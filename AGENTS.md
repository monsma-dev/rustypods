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
# gate used locally and by .gitlab-ci.yml (fmt, clippy -D warnings,
# tests, then cargo audit / cargo deny when those tools are installed):
#   bash scripts/check.sh
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

Workspace lints (`[workspace.lints]`, inherited by every member) deny
only what already passes `cargo clippy --workspace --all-targets -- -D warnings`:
`unsafe_op_in_unsafe_fn`. `rustypods-proto`, `rustypods-client`,
`rustypods-agent`, and `rustypods-ingress` also `forbid(unsafe_code)`.
The daemon and CLI still need `unsafe` (libc, pty, ioctl) — do not
forbid it there.

Do not enable these until the hits are gone (one `cargo clippy
--all-targets` pass, lib + tests both counted):

| lint | hits | note |
| --- | ---: | --- |
| `clippy::unwrap_used` | 355 | mostly `Result::unwrap` |
| `clippy::let_underscore_must_use` | 171 | |
| `clippy::indexing_slicing` | 107 | 56 index + 51 slice |
| `clippy::expect_used` | 11 | |
| `clippy::wildcard_imports` | 4 | CLI/GUI/daemon proto globs |
| `clippy::panic` | 2 | |
| `rust_2018_idioms` | 1 | `elided_lifetimes_in_paths` in `dbus.rs`; not enabled so this branch does not edit daemon source |
| `clippy::todo`, `clippy::dbg_macro` | 0 | safe to enable later |

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

Same class, `/tmp`: a desktop (no-userns) pod bind-mounts the host `/tmp`
and then boots the image's systemd, which runs
`systemd-tmpfiles --create --remove --boot`. Vendor `tmp.conf` (`q /tmp`)
and `x11.conf` (`D /tmp/.X11-unix`) then age and delete files on the HOST.
At start of a no-userns pod with any read-write host bind, the daemon
masks those two snippets by symlinking `/etc/tmpfiles.d/tmp.conf` and
`x11.conf` to `/dev/null` inside the rootfs (symlink-safe helpers). The
image's other tmpfiles rules still run.

## machined/systemd via zbus (no subprocesses)

The daemon talks machined+systemd through `dbus.rs` proxies on one shared
`zbus::Connection::system()`:

- `KillMachine(name, "leader", SIGRTMIN+3)` = `machinectl poweroff`
  (SIGRTMIN=34 on glibc → signo 37; verified on systemd 257).
  The wait before `TerminateMachine` is the pod's `stop_timeout`
  (conf + `create`/`config --stop-timeout`, default 8s). The hard-kill
  wait after that stays ~4s.
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
- **Privilege model (security audit 2026-09): no image binary may ever
  run above the target identity.** The old chain nsenter→image
  `setpriv`→image `env`→`/bin/sh` executed three pod-controlled binaries
  as host root in non-userns pods (stack members, `--desktop`,
  `--no-private-users`) — pod root replacing `/usr/bin/setpriv` owned
  the host on the next `shell`/`cp`/REST exec/exec probe. Now
  `exec::exec_plan` → `ExecPlan { argv, env, gid, groups, no_new_privs }`
  and all identity work happens in the daemon's `pre_exec`
  (`pre_exec_identity`, async-signal-safe syscalls only) or inside
  nsenter itself:
  - non-root target, no userns: pre_exec `setgroups`+`setgid` (from the
    image's /etc/group — host ids == pod ids there), then a bare
    `nsenter --setuid=<uid>`. Verified in util-linux 2.41 nsenter.c
    main(): `-S` alone only calls `setuid()` (post-fork, after setns);
    `-G` — and `--user` without `--preserve-credentials` — calls
    `setgroups(0, NULL)` first, which is why gid work is daemon-side.
    setuid root→non-root clears permitted/effective caps.
  - non-root target, userns: `nsenter --user --setuid --setgid` (ids are
    pod-relative, so they must be set after setns(user)). Supplementary
    groups are dropped by nsenter here — accepted trade-off.
  - root target, userns: nsenter's default uid/gid 0 in the pod userns;
    the image's `setpriv --bounding-set` still runs (post-userns, as pod
    root = the target's own trust domain) to restore nspawn's cap set.
    The kernel resets the bounding set to FULL on setns(user)
    (`set_cred_user_ns`), so a daemon-side drop can't do this.
  - root target, no userns: HOST root minus nspawn's bounding set,
    NO_NEW_PRIVS on, no seccomp. Refused unless the user is an explicit
    `root`/`0` (CLI `--user root`, REST `"user":"root"`); `""` errors
    with a hint. `run` logs a warning. Non-userns pods are **trusted
    code only**.
  - pre_exec always PR_CAPBSET_DROPs every cap outside
    `NSPAWN_DEFAULT_CAPS` (nsenter needs only sys_admin/sys_ptrace/
    setuid/setgid/dac_override — all kept) and sets
    `PR_SET_NO_NEW_PRIVS` in non-userns pods (task flag, survives
    setns/setuid/exec). nnp is deliberately NOT set in userns pods so
    `sudo`/`yay` keep working there — a setuid binary only reaches pod
    root, which the same caller may request with `--user root`.
  - `PodMeta::allow_setuid` (conf-only, like `host_access`) lifts nnp for
    exec sessions (`exec::run`, gRPC + REST) in one non-userns pod. Probes
    go through `exec_plan` directly and keep nnp. Untrusted import clears
    it; the ingress gateway's reload drift check refuses it.
  - Payload env goes through `Command::env_clear().envs()` — nsenter
    execvp()s with its environ — no image `env` binary. `nsenter` is
    resolved on the DAEMON's PATH (`host_nsenter`): with env_clear std
    would otherwise search the child's (container!) PATH, and a client
    `PATH=` override could steer the host lookup.
  - Verified host-side (util-linux 2.41.5, unprivileged `unshare -Ur`):
    `-U --preserve-credentials -S 0` keeps the supplementary list and
    only setuid()s; `-U` / `-U -S -G` call setgroups first.
- Every spawn setsid()s in pre_exec (tty: + TIOCSCTTY). Timeout, client
  disconnect and probe timeout kill the whole group (`kill(-pid,
  SIGKILL)`, `exec::kill_pgrp`) — process groups are kernel-global, so
  this reaches nsenter's forked child inside the pod pidns and its
  descendants. Residual: a payload that setsid()s itself (daemons)
  escapes; the pod cgroup can't be used (it's the pod's own init.scope).
- PTY: `openpty` via libc (`posix_openpt`+`grantpt`+`unlockpt`+
  `ptsname_r` — never `ptsname`, its static buffer races between
  concurrent tty execs), master wrapped in `OwnedFd` immediately, then
  O_NONBLOCK + `tokio::io::unix::AsyncFd` for BOTH directions (a
  blocking `write_all` inside tokio::spawn parked a worker per stalled
  session). The reader is a tokio task the waiter aborts after
  DRAIN_GRACE, so a detached grandchild holding the slave can no longer
  leak a thread+fd per session (old "L5"). Slave as stdio +
  `setsid`/`TIOCSCTTY` in `pre_exec`. `tty(1)` fails on path lookup
  (host devpts), fd semantics work fully.
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
- Dual-stack pair per pod: host `ve-<name>` = <v4>.<idx>.1 plus
  <v6>:<idx>::1; pod `host0` = .2 / ::2. Defaults `10.220.0.0/16` and
  `fd22:220::/32` (max 255). Override with `RUSTYPODS_POD_NET4` /
  `RUSTYPODS_POD_NET6` (must be `x.y.0.0/16` and `x:y::/32`). `doctor`
  warns when the v4 pool overlaps a host route. `net_index` is persisted.
- The daemon configures both veth ends through the leader's netns before
  start returns, so bare OCI payloads need no in-image `ip` or networkd.
  Boot images also get a matching dual-stack networkd file as persistence.
- Port spec is `[hostIp:]hostPort:podPort[/tcp|/udp]` (IPv4 literal, or
  IPv6 in brackets). **No host IP means 127.0.0.1 only** — a deliberate
  default so `-p 5432:5432` is not a public listener. `0.0.0.0:hp:pp`
  is every IPv4 address (explicit). `::1` is rejected: it can never work.
- NAT = own `ip rustypods` / `ip6 rustypods6` nftables tables, rebuilt
  from state on every change. DNAT matches `ip daddr <hostIp>` (or
  `fib daddr type local` for an explicit wildcard). A 127.0.0.1 publish
  is **output-hook only**. Masquerade covers pod egress, and
  `fib saddr type local … masquerade` covers host-originated traffic
  (without it the pod answers 127.0.0.1 on ITS loopback).
- Foreign FORWARD accepts (marker `rustypods-forward-v2`, top of the
  chain, DOCKER-USER pattern) are `ct state established,related`,
  `ct status dnat`, and `iifname "ve-*"` (pod egress and pod↔pod).
  Never `ip daddr 10.220.0.0/16 accept` — that let any neighbour routing
  the pod prefix hit unpublished ports. Pod↔pod is allowed only because
  both ends are `ve-*` (Kubernetes-style). `isolated = true` drops
  forwarded traffic whose source or dest is that pod and the other
  address is still inside the pod pool. firewalld still gets the veth
  in the trusted zone for egress; the DNAT match is what limits who
  can open a published port.
- Required sysctls: `net.ipv4.ip_forward=1`,
  `net.ipv6.conf.all.forwarding=1` (after setting `accept_ra=2` on every
  non-pod iface that was at `accept_ra=1`, otherwise the kernel drops
  router advertisements and the IPv6 default route disappears — SLAAC
  / kernel-RA hosts, not NetworkManager), and per-veth IPv4 `route_localnet=1` —
  without the latter, localhost→pod replies are dropped as martians.
  `route_localnet` also lets a pod inject dst 127/8 toward the host
  (CVE-2020-8558). The `inet rustypods` table drops that in raw
  prerouting (`iifname "ve-*" ip daddr 127.0.0.0/8`). Replies of a
  host→pod localhost DNAT arrive with dst = the veth .1 and are
  de-NATed later, so the drop does not break them. A second input
  rule drops NEW flows from pod veths to `fib daddr type local`,
  except established replies, NDP (untracked — without it the host
  can't resolve pod MACs), mesh DNS :53 (UDP+TCP) on `fd00::/8`, and
  pods with `host_access = true`. Gossip :5305 is deliberately NOT
  open to pods: a pod can spoof a peer's `fd<peer>::1` source and the
  gossip socket can't tell which interface a datagram came in on.
- nft scripts use `#` comments — `//` is a syntax error (broke a rebuild).
- `pkexec` strips PATH to sbin-less dirs → always use absolute paths for
  nft/sysctl/tcpdump in scripts and one-off checks.
- Hard-won: `--private-users=pick` is incompatible with
  `--network-namespace-path` (setns to a foreign netns needs CAP_SYS_ADMIN
  in init_user_ns) → stack members run with `private_users: false`;
  standalone `create` pods get userns by default.
- Privileged pod ports (<1024) need `--user root` inside the pod.
- Stack uplinks are `ve-<4-char stem>-<7 hex>` (15 chars). A truncated
  `ve-<first 12>` was reused when it already existed, so two stacks
  sharing a prefix shared one veth and the second had no uplink. An
  existing link is reused only when its peer sits in that stack's netns.
- `rustypodsd teardown-net` (root) deletes the rustypods nft tables,
  marker FORWARD/INPUT inserts (including mesh), and firewalld runtime
  bindings. It does not restore sysctls; it logs what may still be set.
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
  `firewall-cmd --reload` drops those runtime bindings (and a flush
  drops the nft table). `serve()` reconciles every 30s and on
  firewalld's D-Bus `Reloaded` signal: rebuild the nft tables, reinsert
  marker FORWARD/INPUT rules, and re-bind `ve-*` / `rp-mesh*` to trusted.
- Hard-won: `::1`→pod dnat can NEVER work — the kernel hard-drops
  loopback tuples on non-loopback devices (tcp_v6_rcv; no v6
  `route_localnet` exists — same wall Docker hits). Leaving `::1:80/443`
  unmapped gives instant RST and happy-eyeballs falls back to
  127.0.0.1. Don't re-add an ip6 output dnat for ::1.

## Console logs

nspawn's stdout/stderr is an `O_APPEND` fd on `logs/<pod>.log` (mode 0600).
The daemon does not own that fd after spawn — nspawn keeps it across a
daemon restart — so rotation is copytruncate (`runtime/logs.rs`): copy to
`<pod>.log.1`, then `ftruncate` the live inode. Default cap is 10 MiB
(`RUSTYPODS_LOG_MAX_BYTES`). A 30s task rotates every live log; `destroy`
deletes both files; startup deletes logs whose pod conf is gone. A few
lines written during the copy can be lost. `tail -F` follows the same inode
through truncation.

## Storage quotas (btrfs qgroups)

- `storage_max` in the pod conf → `btrfs quota enable <data_dir>` +
  `btrfs qgroup limit <bytes> <pod_rootfs>`. Hot-applied on config/reload,
  re-applied at every start (quota state doesn't survive remount).
- Verify: `btrfs qgroup show -re /var/lib/rustypods/pods/<pod>`.

## Healthchecks & restart (server.rs supervisor)

- Per-second `supervise_once` tick over pods with a restart policy, a
  configured probe, or `ingress_gateway` (managed ⇒ always "always").
  Pods are supervised concurrently (cap 8); the tick awaits them, so
  each pod has at most one in-flight action.
- SIGTERM and SIGINT stop the accept loop and wait up to 30s for
  in-flight mutating RPCs (start/stop/create/destroy/clone/commit/
  rollback/apply/config). Those handlers run on a detached task so a
  client disconnect does not cancel the critical section.
- The gRPC server, HTTP server, and supervisor exiting or panicking
  exits the process non-zero (systemd restarts it; pods survive).
  Ingress reconcile and snapshot GC log and restart with backoff.
- Death-watch keys on `PodMeta.stopped_by_user` (persisted in the pod
  conf, serde default false) plus an in-memory `stop_intent` mirror for
  the tick that races the conf write. `PodMeta.started` means "was ever
  started" (drives Created/Stopped display), NOT "should be running".
  A user stop sets the flag before engine.stop; start clears it before
  the engine runs. Supervisor restarts and autostart both leave a
  user-stopped pod down across daemon restart/upgrade/reboot
  (unless-stopped). A crash with the flag clear still restarts.
  Supervisor-driven halts do not set the flag. Confs written before
  this field existed load as not user-stopped, so the first restart
  after upgrade still brings those pods back once.
- A pod conf that fails to parse, or that breaks the ingress-host or
  gateway invariant, is quarantined (logged, omitted from serving, name
  and net_index reserved) instead of aborting startup or freeing its
  /30. `rustypods ping` lists quarantined confs.
- Exec probes reuse `exec::exec_plan` and spawn ONLY via
  `exec::run_status` — the payload starts with an `exec 0<&9 9<&-`
  stdin-restore wrapper that only works with exec.rs's pre_exec hook
  (util-linux ≤2.42 --join-cgroup closes fd 0). Spawning the argv by
  hand makes every probe exit non-zero — probes always "fail" while
  `rustypods exec` works fine (burned an hour on this). `run_status`
  also group-kills and reaps a probe that outlives its timeout — before,
  a hung probe added one lingering pod-side process per interval.
- Probe identity = `healthcheck.user` in the pod conf (`[healthcheck]
  user = "…"`, image passwd name or numeric uid; conf-only, no
  proto/CLI flag yet, preserved across `config --healthcheck`). Unset:
  pod root in userns pods, but `nobody` (or bare uid 65534 when the
  image has no nobody) in pods WITHOUT a user namespace — root there is
  HOST root. Set `user = "root"` explicitly to accept that.
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
  merges OVER the image's OCI env per key. nspawn is passed
  `--setenv=KEY` with no value (systemd 257 inherits that name from
  the nspawn process environment). Values are NOT on argv —
  `/proc/<pid>/cmdline` is world-readable; `/proc/<pid>/environ` is
  mode 0400. The value still lands on PID 1's environ — exec'd
  processes do NOT inherit it (nsenter doesn't carry env). Config,
  not a vault. Confs that store env are mode 0600 under 0700
  `conf/` directories.
- `images/`, `pods/`, `snapshots/` (and `resolv/`) are forced to 0700
  at every daemon start: rootfs trees carry root-owned setuid binaries
  from images, and a traversable parent makes each one a local-user
  privilege escalation on the host. Nothing outside the daemon walks
  them (nspawn mounts as root, then pivot_roots).
- `--env-file` parsing: blank lines + `#` comments skipped, no shell
  expansion, `A=$HOME` stays literal; `--env` flags override file
  entries per key.

## Pod export/import (Wave H)

`rustypods export <pod> [-o file] [--format tar|btrfs] [--allow-inconsistent]`
writes one archive stream. New archives are version 2:

```
[8B "RPEX0002"][u32 LE manifest_len][manifest JSON]
[payload]
[8B "RPEXEND1"][u64 LE payload_len][32B SHA-256(payload)]
```

The hash covers payload bytes only. `load` stages the payload, checks
the trailer, and only then unpacks and moves the trees into place. A
mismatch or a short file deletes staging and fails; `export -o file`
deletes the partial file when the stream errors (non-zero exit).
`RPEX0001` (no trailer) still loads, and the CLI prints that the
checksum was not verified.

Payload is multi-subvolume `btrfs send` (needs `-r` ro snapshots —
`clone_rootfs` makes rw ones, use `storage::btrfs::snapshot_ro`) on
btrfs hosts, or `tar` elsewhere and whenever `--format tar` is set.
Both name entries `<pod>`/`<vol>`. Tar uses GNU tar
`--numeric-owner --xattrs --xattrs-include='*' --acls` on create.
Trusted extract uses the same flags plus `--no-overwrite-dir` and does
not pass `--absolute-names` (GNU tar strips a leading `/`) or
`--no-same-permissions` (rootfs setuid bits must survive). Untrusted
tar extract is in-process: numeric ownership when root, device/fifo
nodes skipped (nspawn provides `/dev`), `..` and absolute paths
refused. `btrfs receive --chroot` confines receive to the staging dir;
the payload is fed on stdin so the stream is open before the chroot.

`rustypods load <file|-> [--name x] [--trust]` imports. The pod op lock
is held for the whole export stream and the whole import, so
destroy/rollback cannot run mid-transfer. Staging dirs are
`.export-<pid>-<n>-<rand>` / `.import-…`. Daemon start removes leftover
staging dirs older than the process (`transfer::sweep_stale_staging`).

- Running pods are cgroup-frozen for the snapshot window only. A drop
  guard writes `0` back (retried); if that still fails the daemon logs
  an error — the pod may stay frozen. Freeze failure aborts the export
  unless `--allow-inconsistent` (crash-consistent, same as a power cut);
  that warning is also stored in the manifest and printed by the CLI.
- `btrfs receive` lands subvols ro WITH `received_uuid` — `property set
  ro false` is REFUSED on those. The canonical move is an rw `subvolume
  snapshot` into place and deleting the ro staging copy.
- Import always clears started, net_index, stack and ingress_gateway.
  Without `--trust` (REST `?trust=true` to keep them) it also forces
  `private_users`, and strips binds, ports, ingress, host_access,
  allow_setuid, autostart, restart policy, healthchecks and pod env. Image env still
  applies at start. The CLI prints each note. `--trust` keeps the
  exported conf. Image CONF travels; the image tree never does.
- A btrfs-send archive is rejected on a non-btrfs host before the
  payload is unpacked — re-export with `--format tar`.
- Import payload bytes are counted as they arrive, capped by
  `RUSTYPODS_IMPORT_MAX_BYTES` (default 64 GiB).
- Export refuses the managed gateway pod.
- Name/volume collisions refuse before the payload is committed;
  existing volume names fail hard. Volume dirs get 0777 like
  ensure_volume.
- REST: `GET /v1/pods/{name}/export?format=tar&allow_inconsistent=true`
  and `POST /v1/import?name=&trust=true`.
- Import is client-streaming→unary: the CLI uses connect_timeout(1h).
- Known gap: multi-subvolume consistency is freeze-window only, not a
  memory checkpoint. True live migration needs CRIU, out of scope.
- `pull --strip-setuid` clears S_ISUID/S_ISGID on OCI extract. The
  default keeps them (sudo/ping) because user-namespace pods contain
  that. Pods with `private_users=false` are trusted images only.

## Multi-host mesh (Wave I)

`rustypods mesh init|status|add-peer|rm-peer` — userspace WireGuard via
BoringTun (no kernel module), giving every pod a ULA address reachable
from pods on other hosts. L3, end-to-end encrypted, no NAT.

- Identity = addressing: each daemon derives its /48 as
  `fd` + 40 bits of sha256(pubkey). The first byte is `0xfd` (RFC 4193
  fc00::/7 with L already 1). Two bits of the Global ID are then
  forced (`&= 0x3f; |= 0x40`). That is NOT the L bit — changing the
  mask would move every existing host's /48, so the derivation stays.
  A peer's prefix is verified BY its pubkey — config can't claim
  foreign space, and prefix derivation needs zero coordination.
- Key rotation is manual and mesh-wide: `mesh deinit` on every host
  (or, if conf/mesh.conf is corrupt, fix or `rm` it — `mesh init` and
  daemon startup refuse to mint a replacement key), then `mesh init`
  and `mesh add-peer` again with the new pubkeys. There is no
  in-band rekey. A corrupt conf leaves the mesh down; `mesh status`
  prints the parse error in `conf_error`.
- Pod mesh addr = `fd<host>:<net_idx>::2` — a second /128 on host0 next
  to the intra-host fd22:220:<idx>::2. Pods need NO extra route (v6
  default already via host); longest-prefix src selection picks the
  mesh addr when dialing mesh space.
- Datapath: persistent `rp-mesh0` TUN (IFF_NO_PI, created via
  `ip tuntap` so routes survive daemon restarts) + one UDP socket +
  one boringtun `Tunn` per peer. `fd<peer>::/48 dev rp-mesh0` steers
  outbound; `fd<local>:<idx>::2/128 dev ve-<pod>` delivers inbound.
- `conf/mesh.conf` (0600 — holds the WG private key, base64; `conf/` is
  0700) persists
  identity + static peers. Daemon restart re-derives the same /48.
- The pump is one tokio task: TUN reads → dst /48 → peer Tunn → UDP;
  UDP datagrams → peer session (endpoint map, key-scan fallback for
  roaming sources) → decapsulate → TUN — but only when the plaintext
  dst sits inside OUR /48 (peers can't inject routes for foreign
  space). 1s timer tick drives rekey/keepalive (25s keepalive keeps
  NAT mappings warm).
- Firewall: `ensure_mesh_forward` inserts `fd00::/8` accepts in
  ip6/inet FORWARD (ULA is non-routable — safe), `firewalld_bind` puts
  rp-mesh0 in the trusted zone alongside pod veths.
- mesh_init is idempotent and retroactive: running pods get their /128
  immediately, no restart needed. A pod whose mesh addr fails while the
  mesh is up unwinds like a veth failure — never reports "running"
  unreachable cluster-wide.
- Gotcha: inside a service, rpc METHOD names share the symbol table
  with types — `rpc MeshStatus(Empty) returns (MeshStatus)` fails with
  "not a message type" (resolves to the method). Hence `GetMeshStatus`.
- Hard-won: never nest a second `AsyncFd::readable()` inside a select
  arm that already holds the readiness guard — the inner await parked
  forever (guard `r` alive until arm end) freezing the whole pump:
  UDP Recv-Q grew, 0% CPU, `mesh status` still answered. Fix:
  `guard.try_io` directly on the select arm's own guard. The pump runs
  under a supervisor task (a panic would otherwise die silently on a
  dropped JoinHandle); liveness counters pump_ticks/udp_pkts/tun_pkts
  and tun_drops (EAGAIN on the nonblocking TUN write) are in-memory
  atomics surfaced via MeshStatus — no file dumps. Gossip, the
  announcer, and both DNS tasks have the same supervisor shape
  (restart with capped backoff, shutdown awaits them).
- `mesh deinit` (`DELETE /v1/mesh`) is the full teardown: watch-channel
  cancels the pump, the supervisor JoinHandle is awaited (3s bound),
  `ip tuntap del` removes rp-mesh0 (its routes die with it), pod /128s
  are stripped via remove_mesh_addr, and conf/mesh.conf is deleted so
  a restart stays down. Svc.mesh is `Arc<std::sync::RwLock<…>>`, NOT a
  OnceCell — set-once can't express deinit, and the lock must be std
  (to_pod reads it synchronously).
- REST mesh surface: `GET /v1/mesh`, `POST /v1/mesh/init?listen_port=`,
  `DELETE /v1/mesh`, `POST /v1/mesh/peers`, `DELETE /v1/mesh/peers/
  {*pubkey}` (wildcard — raw base64 can contain `/`).
- Hard-won: dual-stack UDP sockets need v4-mapped-v6 endpoints —
  `send_to` to a plain `SocketAddrV4` on a `[::]`-bound socket fails
  silently. `canon_ep` maps both directions (config, roaming srcs) and
  `mesh status` unmaps for display.
- Same-host testing needs real isolation: two mesh endpoints on one
  kernel share the routing table — a connected /128 (fake pod addr on
  `lo`) or A's pod-veth route shortcircuits the tunnel while ping
  still "works". `examples/meshpeer` in its own netns over a veth pair
  gives honest verification; `--fake-pod` uses `noprefixroute` so the
  addr lives only in the local table.
- Scope: standalone pods only (stack members share one netns and are
  skipped); IPv6 ULA only — v4 has no place on the mesh.

### Cluster plane: `--host <peer>` (daemon-to-daemon gRPC)

`rustypods --host s2 ps|start|exec …` runs the full PodControl API on a
peer daemon over the mesh — the placement primitive. Resolution happens
client-side: the CLI asks the LOCAL daemon's GetMeshStatus for the peer
registry (matching `name`, pubkey, or `fd<peer>::1`), then dials
`http://[fd<peer>::1]:5306` over the WG tunnel (h2c — WireGuard already
encrypts).

- The cluster-plane listener lives on `[fd<host>::1]:5306`, spawned by
  `mesh_up`/startup-restore and torn down by `mesh_down` (watch channel
  `svc.mesh_rpc_stop` — Arc-wrapped std Mutex since Svc is Clone).
- Auth: shared `cluster_token` in conf/mesh.conf (0600), sent as
  `x-cluster-token` gRPC metadata, enforced by a server interceptor.
  Generate on the FIRST host (`mesh init` auto-mints when absent);
  `mesh init --token <tok>` on joiners. `mesh status` prints it — UDS
  is uid-gated so that's safe. Debug-redacted in MeshConf.
- Defense in depth: nftables `rustypods-mesh-rpc` input chain drops
  tcp/5306 from anything but the peers' `fd<peer>::1` addrs (rebuilt on
  every add/remove-peer and mesh start). nft alone is NOT sufficient —
  a pod on a peer can spoof `fd<peer>::1` as source (cryptokey routing
  accepts any src inside the peer /48); the token is the real gate.
- `--host` and `--remote` are mutually exclusive; `--remote` stays the
  escape for hosts without mesh.
- `mesh add-peer --name s2` stores the alias in conf (MeshPeerConf.name
  + proto MeshPeer.name / MeshPeerInfo.name).

### Volume streaming: `volume send <name> --to <peer>`

Daemon→daemon dataplane on the same channel: `SendVolume` (unary, to
the LOCAL daemon) resolves the peer, pings it for its storage driver
(`DaemonInfo.storage_driver`), negotiates the format (btrfs send iff
BOTH ends run btrfs — our AlmaLinux/XFS fleet always lands on tar),
then client-streams `VolumeChunk{init,data}` to the peer's
`ReceiveVolume`. Sender rewrites top-level tar entries to the target
name (`--transform`), so `--rename-as` works without receiver logic.
Receiver stages the payload to disk first, only registers the
VolumeMeta after a clean unpack — a mid-stream abort leaves no
half-volume. `--force` overwrites a same-named peer volume, refused
while pods mount it there. This is the primitive the DB backup
pipeline sits on (snapshot → volume → `send --to`).

### Hardening notes (post-review)

- nft guard on :5306 is positive-accept + drop-all: only `iifname
  "rp-mesh*" ip6 saddr {peer ::1s}` passes — `lo`, LAN and any
  non-tunnel ingress are dropped.
- Gossip frames are HMAC-SHA256-signed with the cluster token
  (`{"payload","signature"}` envelope, tag checked with
  `hmac::Mac::verify_slice` before the registry JSON is parsed): a pod
  on a peer can forge the ::1 source but not the tag. Frames without a
  valid tag are dropped, including when this host has no token yet.
- `/v1/mesh` REST never serializes `cluster_token` (cleared in the
  handler) — the ro bearer must not become cluster-admin.
- receive_volume stages to `.vrecv-*` under a byte cap
  (`import_max_bytes`), asserts every tar entry lives under `<name>/`,
  re-checks exists+mounted under the `volume:` op lock, and only then
  deletes the old tree and clones the staged one into place. `.vsend-*`
  /`.vrecv-*` are swept by the boot-time stale-staging pass.
- Mesh listener state holds (stop-signal, JoinHandle): stop awaits the
  task so a following init rebinds cleanly; a dead listener is respawned
  by the next spawn_mesh_rpc. mesh_up/mesh_down hold `mesh_lifecycle`.
- Cluster token = full PodControl on every peer (needed for `--host`);
  it is the cluster-admin credential, same model as kubectl client certs.

### Stack placement: `placement = "<peer>"` in stack.toml

CLI-side fan-out, daemon stays per-host atomic: on `apply` the CLI
light-parses the toml (`split_stack_by_placement` in cmd/cluster.rs),
groups members by placement, resolves each through the local mesh
(via `connect_mesh`), and sends every target a rewritten toml with the
key stripped — `apply_stack_work` REJECTS any toml still carrying it.
Semantics shift per member: same host → shared stack netns + 127.0.0.1
as before; different host → own netns + gossip name
(`<stack>-<member>.rustypods.local`). Ports/ingress publish on the
member's host. `--host` + placement is refused (target is implied).
Partial fan-out failure is per-host reported; `apply` is idempotent —
just re-run.

## Mesh-DNS (Wave K)

Cross-host pod-name resolution: `ping db` from a pod on host A finds
`db` on host B. No external DNS server, no multicast — the registry
rides inside the encrypted tunnel.

- Each daemon also owns `fd<host>::1/128` on rp-mesh0 (`nodad
  noprefixroute` — local-table only, it never re-enters the pump's
  local-space guard). It's the host's control-plane address.
- Two extra UDP sockets bind to it: gossip `:5305` (daemon↔daemon
  registry) and DNS `:53` (pod-facing). Both only reachable after
  WireGuard decap or from local pods — no port-53 conflict with
  systemd-resolved's 127.0.0.53 stub.
- Registry wire format: JSON `{"names": {pod: fd<host>:<idx>::2}}`,
  full-state replace every 30s + Notify-triggered pushes on
  pod/peer lifecycle edges (set_local_names diffs to stay quiet).
- Trust boundary: datagrams must arrive decapsulated AND with src ==
  exactly `fd<peer>::1`; registry values are sanitized to the
  announcer's own /48 AND valid ≤63-char DNS labels, capped at 1024
  entries (sanitize_registry) — a peer can't name our space, a third
  host's, or grow our memory unboundedly. Entries TTL out after 95s
  silent.
- Name conflicts are deterministic: local registry always wins; among
  peers claiming the same name the LOWEST peer /48 wins (HashMap
  iteration is nondeterministic — never first-wins over .values()).
- DNS responder answers single-label names (`db`, `db.rp`, `db.pods`,
  `db.local` suffixes stripped) with AAAA from the merged registry;
  A → NODATA (v6-only mesh); everything else relays verbatim upstream
  over UDP AND TCP (:53 both — RFC 1035 requires TCP for truncation).
  Upstream is re-read per query (net::upstream_resolver prefers
  /run/systemd/resolve/resolv.conf over the 127.0.0.53 stub) — a
  cached resolver goes stale when the host roams networks. canon_ep
  again — the upstream is usually a v4 stub. UDP queries are spawned
  behind a 64-permit semaphore so one 3s upstream wait cannot stall
  every pod; TCP accepts are capped (32), each read idles out at 5s,
  and the length prefix is capped at 4096. Malformed questions return
  no answer — builders never slice past the packet (an 18-byte `db`
  query used to panic the DNS task).
- Pod wiring: at start, networked standalone pods get
  run/resolv.conf (`nameserver fd<host>::1` + real upstream fallback
  + `search rp pods`) ro-bound over /etc/resolv.conf; the target is
  created when missing so --bind can't fail on bare OCI rootfs.
  Failure is warn-not-fatal (pod just loses pod-name resolution).
- Lifecycle: all three tasks subscribe to the pump's shutdown watch
  and are awaited in Mesh::shutdown; remove_peer drops that peer's
  remote registry immediately instead of waiting out the TTL.
- Hard-won: FORWARD accepts are NOT enough — pod→host DNS and
  decapsulated gossip hit INPUT, and an inbound WG handshake on a
  passive host is a NEW conntrack entry that default-drop INPUT
  (ufw ip6 filter policy drop) kills before boringtun sees it.
  Same-host netns tests only worked because the initiating side's
  outbound packets made replies "established". ensure_mesh_input
  inserts `iifname { "ve-*", "rp-mesh*" } ip6 saddr fd00::/8` +
  `udp dport <wg_port>` accepts at the top of ip6/inet/ip INPUT
  chains (marker rustypods-mesh-in). Presence is probed PER RULE
  (iifname wildcard / `udp dport <port>`), not per chain — a changed
  listen_port must still install, and stale old-port accepts are
  deleted by handle. Wildcard iifname values need real quotes in
  nft — pass rule args as explicit argv tokens, not a whitespace-
  split string.
- Hard-won: roaming-endpoint rebinds must also DELETE the old
  endpoint→key map entry — a stale mapping would misattribute future
  datagrams arriving from the old address.

## Ingress CA and gateway

Ingress CAs created from here on are `pathLen=0` and name-constrained to
`rustypods.localhost`. Older unconstrained CAs are kept and warned about
(`doctor`, daemon log). `ingress rotate-ca` replaces one; `ingress uninstall-ca`
removes it from the host trust store. The leaf renews with under 30 days
left; the daemon copies the new pair into the gateway rootfs and restarts
the pod, and the gateway also reloads the files when their mtime changes.
The gateway control socket is opened `O_PATH|O_NOFOLLOW` and must be a
socket owned by the run-directory uid — a pod-planted symlink is refused.

## REST API surface (Wave G)

Tokens persist in `<socket-dir>/http-token` (read-write) and
`http-token-ro` (GET only) across daemon restarts. `RUSTYPODS_HTTP_TOKEN_ROTATE=1`
replaces both. `RUSTYPODS_HTTP_INSECURE=1` allows a non-loopback bind and
warns on every start — the supported remote path is `ssh -L` or gRPC
`--remote`, not plain HTTP on a LAN address. JSON bodies are 1 MiB;
import uses `RUSTYPODS_IMPORT_MAX_BYTES` (default 64 GiB). Non-streaming
handlers have a 60s deadline (exec ≤900s). `/healthz` is open and reports
whether the state lock and machined are reachable. PATCH merges under the
per-pod op lock.

`/v1/pods/{name}` GET · `/v1/pods/{name}/stats` GET (live cgroup-v2:
memory.current, cpu.stat usage_usec, pids.current, memory.peak — read
from /sys/fs/cgroup/machine.slice/<machined-unit>/, no agent needed) ·
`/v1/pods/{name}/logs?lines=N` GET (journal for boot pods, console log
otherwise — same probe as stream_logs) · `/v1/pods/{name}/exec` POST
(non-tty, {cmd,user,workdir,env,timeout_secs} → {stdout,stderr,
exit_code,timed_out,truncated}, 4MiB/stream cap, timeout ≤900s).

- exec.rs's `run`/`run_pipe`/`run_tty` are generic over the inbound
  Stream — gRPC passes `tonic::Streaming`, REST `tokio_stream::empty()`.
- REST `user` follows the same rules as the CLI: `""` = pod root in
  userns pods, REFUSED (400-ish internal error with a hint) in pods
  without a user namespace — pass `"user":"root"` explicitly to run as
  host root there, or an unprivileged image user.
- Timeout kill: dropping the receiver fires tx.closed() → the waiter
  `kill(-pgid, SIGKILL)`s the session's process group (every spawn
  setsid()s), which includes nsenter's forked in-pod child and its
  descendants, then reaps nsenter. Only payloads that setsid()
  themselves survive; agents running such daemons should still `pkill`
  or keep them self-terminating.

## Rootless podman caveat

`podman` needs the user session bus (`/run/user/1000/bus`). If `podman
exec/start` fails with "Interactive authentication required", the user
session is down — the rustypods daemon itself (root, system bus) is
unaffected. Builds can then run inside a pod: `rustypods shell dev`.
