# Agent notes — rustypods

## Build env

Host has **no Rust toolchain**. Build inside the `dev` pod — rustypods
dogfoods itself (`dev` runs the `arch-base` image imported from the old
distrobox, `/home/nick` bound rw, autostart on):

```bash
rustypods start dev   # usually already up (autostart)
rustypods exec dev -w ~/Projects/rustypods -- bash -lc \
  'set -o pipefail && \
   RUSTFLAGS="-C link-arg=-fuse-ld=mold" cargo build && cargo test'
# or: bash scripts/build.sh  (release build + tests)
```

`shell` aliases: `exec`; `-w/--workdir` sets the in-container cwd
(absolute path, daemon-side `cd` before exec). `--strict` exports
`SHELLOPTS=pipefail` so `bash -lc 'cargo build | tail'` can't hide a
failure — still keep `set -o pipefail` for non-bash payloads.
`rustypods cp <src> <dst>` copies host↔pod via tar/cat over Exec
(`pod:/abs/path` on exactly one side). If the daemon itself
is broken (bootstrap problem), fall back to the podman distrobox `arch`:
`podman exec -u nick -w /home/nick/Projects/rustypods arch bash -lc …`.

`protoc` is vendored via `protoc-bin-vendored` — no system protobuf needed.

NOTE: always `set -o pipefail` when piping cargo output — a bare
`cargo build | tail` masks build failures (tail's exit code wins).

## Runtime requirements

- `sudo bash scripts/install-daemon.sh --user "$USER"` installs packages
  (apt/dnf/pacman families), the unit, `/etc/rustypods/daemon.env`
  (RUSTYPODS_ALLOWED_UID) and the binaries. `--skip-packages`,
  `--install-polkit` (opt-in; only for raw machinectl), `--dry-run`.
- `rustypods doctor` verifies the host: systemd PID1, cgroup v2, userns,
  nspawn/nsenter option surface, machined, /dev/shm, net sysctls, btrfs.
- Daemon must run as **root** (nspawn, btrfs subvols under /var/lib, machined).
- Btrfs host assumed; off-btrfs falls back to `cp --reflink=auto` (slower, works).
- Port forwarding needs `nft` + `ip` on the host PATH (daemon spawns them).

## Conventions

- Mirrors `~/Projects/computer` workspace style: `crates/`, edition 2021,
  anyhow/clap/tracing. **English** user-facing strings and comments (OSS).
- Never poke Cinnamon/desktop services from an agent (see computer/AGENTS.md).

## Hard-won: never bind /run/user/<uid> read-write into a booting pod

On 2026-09-19 a `--bind=/run/user/1000` (rw) let the pod's logind run
`user-runtime-dir@1000` session cleanup, which `rm -rf`'d the bound dir —
wiping the host's user bus + systemd socket (rootless podman dead until
relogin). rw-binds under `/run` (and /etc, /usr, /boot, /proc, /sys, /dev,
/var/lib/rustypods) are now refused outright by
`rustypods_proto::validate_bind` — they're `:ro` only. Same class of
caution applies to any host dir another init system considers "theirs"
(`/run`, `/var/lib`, `/etc`).

## machined/systemd via zbus (no subprocesses)

The daemon talks machined+systemd through `dbus.rs` proxies on one shared
`zbus::Connection::system()`:

- `KillMachine(name, "leader", SIGRTMIN+3)` = `machinectl poweroff`
  (SIGRTMIN=34 on glibc → signo 37; verified on systemd 257).
- `TerminateMachine(name)` = `machinectl terminate` (hard kill).
- `Machine.leader`/`.unit` properties give the leader pid + authoritative
  scope name — never format `machine-<name>.scope` yourself.
- `SetUnitProperties(unit, runtime=true, a(sv))` = `systemctl
  set-property --runtime`. `CPUQuota` is `CPUQuotaPerSecUSec` on the bus,
  in µs (400% = 4_000_000 = `4s` in `systemctl show`).
- `busctl monitor` as non-root fails (BecomeMonitor denied); under root it
  buffers stdout on timeout-kill — useless for tracing. Prefer direct
  `busctl introspect` + signal experiments.

## Hard-won: nsenter exec + cgroup membership

- `nsenter -p` **always forks**: the spawned pid is a waiter; the real
  payload is its child (`/proc/<pid>/task/<pid>/children`). Cgroup moves and
  metrics must target the CHILD, not the nsenter pid.
- `machine-<pod>.scope` and `payload/` have `subtree_control` on →
  `cgroup.procs` writes fail with EBUSY (no-internal-process). exec.rs
  sidesteps this entirely: `nsenter --cgroup --join-cgroup` joins the
  leader's cgroup atomically at setns time — exec'd processes land in
  `machine-<pod>.scope/payload/init.scope` (verified live, 2026-09) and DO
  fall under the pod's MemoryHigh/CPUQuota. No host-side leaf cgroup is
  created anymore.
- `nsenter --wd=<path>` resolves against the host mountns before setns →
  `getcwd` fails in the container. Don't use it; `cd $HOME` in the login
  shell wrapper instead.
- PTY: `openpty` via libc (`posix_openpt`+`grantpt`+`unlockpt`+`ptsname`),
  slave as stdio + `setsid`/`TIOCSCTTY` in `pre_exec`. `tty(1)` fails on
  path lookup (host devpts), fd semantics work fully.
- util-linux ≤2.42 `nsenter --join-cgroup` **closes fd 0**: its
  `open_cgroup_procs()` declares `int cgroup_fd = 0` (not -1), so
  `open_target_fd` close()s stdin and /proc/<pid>/cgroup lands on it —
  every exec'd payload reads instant EOF and exits 0 with no output.
  exec.rs works around it: `pre_exec` dup2(0→9) + payload wrapper
  `exec 0<&9 9<&-`. Fixed upstream (`= -1`), not yet released.
  The dup fd MUST be single-digit: the wrapper runs under the image's
  /bin/sh and dash (Debian) rejects fd >9 in redirections
  ("Bad fd number" — broke `shell` on every Debian-family image).
- Hard-won: `shell` forwards the host's `LANG` into the pod, but a fresh
  OCI rootfs hasn't generated it → locale-aware tools die
  (`locale.Error: unsupported locale setting`, hit by sphinx-build on a
  fresh debian OCI pod). exec.rs downgrades LANG/LC_ALL to
  `C.UTF-8` when the locale isn't generated in the rootfs; run
  `locale-gen` in the pod for the real locale.

## Port forwarding (net.rs)

nspawn's `--port` needs systemd-networkd **on the host** (its
80-container-ve.network provides DHCP + nft glue). Desktops run
NetworkManager/Netplan → host veth never gets an address → no NAT. So
rustypodsd does it itself:

- Pods with ports or ingress rules → `--network-veth` (private netns, no
  host-net parity).
- Dual-stack pair per pod: host `ve-<name>` = 10.220.<idx>.1 plus
  fd22:220:<idx>::1; pod `host0` = .2 / ::2. `net_index` is persisted.
- The daemon configures both veth ends through the leader's netns before
  start returns, so bare OCI payloads need no in-image `ip` or networkd.
  Boot images also get a matching dual-stack networkd file as persistence.
- NAT = own `ip rustypods` nftables table, rebuilt from state on every
  change: DNAT in prerouting+output, masquerade for pod egress, and
  `fib saddr type local … masquerade` for host-originated traffic (without
  it the pod answers 127.0.0.1 on ITS loopback).
- Required sysctls: `net.ipv4.ip_forward=1`,
  `net.ipv6.conf.all.forwarding=1`, and per-veth IPv4 `route_localnet=1` —
  without the latter, localhost→pod replies are dropped as martians.
- nft scripts use `#` comments — `//` is a syntax error (broke a rebuild).
- `pkexec` strips PATH to sbin-less dirs → always use absolute paths for
  nft/sysctl/tcpdump in scripts and one-off checks.
- Hard-won: `--private-users=pick` is incompatible with
  `--network-namespace-path` (setns to a foreign netns needs CAP_SYS_ADMIN
  in init_user_ns) → stack members run with `private_users: false`;
  standalone `create` pods get userns by default.
- Privileged pod ports (<1024) need `--user root` inside the pod.
- Hard-won: nspawn's host veth name for a >12-char machine name is NOT a
  plain truncation — systemd v257 rewrites it with a hash suffix
  (`ve-rustypod0iFF`). Resolve the host veth by peer ifindex
  (`host0@ifN` in the pod netns ↔ `ifindex` on the host), never by name.
  And `nsenter --net` does NOT enter the mount ns — `/sys/class/net`
  still shows the HOST's interfaces; use `ip link` (netlink) for
  pod-netns reads.
- Hard-won: foreign firewalls (ufw, libvirt's iptables-compat, firewalld)
  install FORWARD base chains with drop policy — pod↔pod and pod egress
  die there, and a RustyPods-owned accept chain can't override a foreign
  drop (each base chain gets its own verdict). `ensure_forward_accepts`
  inserts marker-commented accepts at the TOP of foreign iptables-compat
  chains (`ip`/`ip6`/`inet filter FORWARD`) — the DOCKER-USER pattern.
  Insert whenever the chain exists and lacks the marker, NOT only on
  drop policies: firewalld's filter_FORWARD is policy accept yet still
  rejects via its zone dispatch.
- Hard-won: firewalld's `inet firewalld` table carries the kernel
  `owner` flag — rule inserts from any other netlink socket get EPERM
  (no AVC, not SELinux — the kernel locks the table to firewalld's
  portid). The sanctioned path is `firewall-cmd`: `firewalld_bind`
  adds each pod veth to the built-in `trusted` zone (ACCEPT target) —
  runtime-only, zero config mutation, inert once the veth dies.
  Verified on Fedora 44 / firewalld 2.4.4 / SELinux Enforcing.
- Hard-won: `::1`→pod dnat can NEVER work — the kernel hard-drops
  loopback tuples on non-loopback devices (tcp_v6_rcv; no v6
  `route_localnet` exists — same wall Docker hits). Leaving `::1:80/443`
  unmapped gives instant RST and happy-eyeballs falls back to
  127.0.0.1. Don't re-add an ip6 output dnat for ::1.

## Storage quotas (btrfs qgroups)

- `storage_max` in the pod conf → `btrfs quota enable <data_dir>` +
  `btrfs qgroup limit <bytes> <pod_rootfs>`. Hot-applied on config/reload,
  re-applied at every start (quota state doesn't survive remount).
- Verify: `btrfs qgroup show -re /var/lib/rustypods/pods/<pod>`.

## Rootless podman caveat

`podman` needs the user session bus (`/run/user/1000/bus`). If `podman
exec/start` fails with "Interactive authentication required", the user
session is down — the rustypods daemon itself (root, system bus) is
unaffected. Builds can then run inside a pod: `rustypods shell dev`.
