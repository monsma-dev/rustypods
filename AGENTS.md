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

## Healthchecks & restart (server.rs supervisor)

- Per-second `supervise_once` tick over pods with a restart policy, a
  configured probe, or `ingress_gateway` (managed ⇒ always "always").
- Death-watch keys on the in-memory `stop_intent` set — `PodMeta.started`
  means "was ever started" (drives Created/Stopped display), NOT "should
  be running". stop_pod records intent before engine.stop; start_pod
  clears it; a daemon restart loses intent (Docker-"always"-like).
- Exec probes reuse `exec_argv` — the payload ends with an
  `exec 0<&200` stdin-restore wrapper that ONLY works with
  `pre_exec(exec::preserve_stdin)` on the spawn (util-linux ≤2.42
  --join-cgroup closes fd 0). Spawning the argv without that hook makes
  every probe exit non-zero — probes always "fail" while `rustypods exec`
  works fine (burned an hour on this).
- tcp/http probes dial `10.220.<idx>.2` (pod veth) for ":port"/"/path",
  or a numeric host:port verbatim — the daemon never resolves DNS.
- Backoff: 2^n s per restart attempt, cap 60s, decays after 60s of
  sustained health. "always" restarts on sustained probe failure too;
  "on-failure" only on leader death (exit-code distinction is a machined
  blind spot for now).

## Named volumes + pod env (Wave E)

- `volumes/<name>` are btrfs subvols (fallback: plain dirs) under the
  data dir; registry lives in `conf/volumes/<name>.conf`. Pods mount
  them via `--volume name:/pod/path[:ro]` → daemon-side `--bind` at
  start; `destroy pod` never deletes volumes, `volume rm` refuses
  while any pod conf references one (running OR stopped).
- Volume dirs are mode 0777 on purpose: pod roots under
  --private-users=pick map to arbitrary host UIDs, so a 0755 dir is
  read-only inside the pod. Without idmapped bind mounts there is no
  narrower permission that works for every userns range.
- Missing volumes are auto-created wherever specs resolve (create,
  config, stack apply, start, `volume ls` fs-reconciliation) — hand-
  edited confs can reference volumes that don't exist yet.
- Pod env (`--env KEY=v`, `--env-file`, conf `env`, stack.toml `env`)
  merges OVER the image's OCI env per key and goes to nspawn via
  --setenv. It lands on PID 1's environ — exec'd processes do NOT
  inherit it (nsenter doesn't carry env). Visible via
  /proc/<pid>/environ: config, not a vault.
- `--env-file` parsing: blank lines + `#` comments skipped, no shell
  expansion, `A=$HOME` stays literal; `--env` flags override file
  entries per key.

## REST API surface (Wave G)

`/v1/pods/{name}` GET · `/v1/pods/{name}/stats` GET (live cgroup-v2:
memory.current, cpu.stat usage_usec, pids.current, memory.peak — read
from /sys/fs/cgroup/machine.slice/<machined-unit>/, no agent needed) ·
`/v1/pods/{name}/logs?lines=N` GET (journal for boot pods, console log
otherwise — same probe as stream_logs) · `/v1/pods/{name}/exec` POST
(non-tty, {cmd,user,workdir,env,timeout_secs} → {stdout,stderr,
exit_code,timed_out,truncated}, 4MiB/stream cap, timeout ≤900s).

- exec.rs's `run`/`run_pipe`/`run_tty` are generic over the inbound
  Stream — gRPC passes `tonic::Streaming`, REST `tokio_stream::empty()`.
- Timeout kill is best-effort: dropping the receiver fires tx.closed()
  → the waiter SIGKILLs the host-side nsenter — but `nsenter -p` forks,
  so the in-pod payload is reparented to pod init and can linger until
  it exits or the pod stops. Agents that must not leak should exec a
  `pkill` cleanup or keep payloads self-terminating.

## Rootless podman caveat

`podman` needs the user session bus (`/run/user/1000/bus`). If `podman
exec/start` fails with "Interactive authentication required", the user
session is down — the rustypods daemon itself (root, system bus) is
unaffected. Builds can then run inside a pod: `rustypods shell dev`.
