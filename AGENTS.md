# Agent notes — rustypods

## Build env

Host has **no Rust toolchain**. Build inside the `arch` distrobox:

```bash
podman start arch   # if needed
podman exec -u nick -w /home/nick/Projects/rustypods arch bash -lc \
  'RUSTFLAGS="-C link-arg=-fuse-ld=mold" cargo build && cargo test'
# or: bash scripts/build.sh  (release build + tests)
```

`protoc` is vendored via `protoc-bin-vendored` — no system protobuf needed.

## Runtime requirements

- `sudo apt install systemd-container` (nspawn, machinectl, machined)
- `sudo bash scripts/install-daemon.sh` installs the root daemon + polkit rule.
- Daemon must run as **root** (nspawn, btrfs subvols under /var/lib, machined).
- Btrfs host assumed; off-btrfs falls back to `cp --reflink=auto` (slower, works).

## Conventions

- Mirrors `~/Projects/computer` workspace style: `crates/`, edition 2021,
  anyhow/clap/tracing, Dutch user-facing strings.
- Never poke Cinnamon/desktop services from an agent (see computer/AGENTS.md).

## Hard-won: never bind /run/user/<uid> read-write into a booting pod

On 2026-09-19 a `--bind=/run/user/1000` (rw) let the pod's logind run
`user-runtime-dir@1000` session cleanup, which `rm -rf`'d the bound dir —
wiping the host's user bus + systemd socket (rootless podman dead until
relogin). The bind is `--bind-ro=` now; socket connects work fine on ro
mounts. Same class of caution applies to any host dir another init system
considers "theirs" (`/run`, `/var/lib`, `/etc`).

## machined/systemd via zbus (geen subprocessen)

De daemon praat machined+systemd via `dbus.rs` proxies op één gedeelde
`zbus::Connection::system()`:

- `KillMachine(name, "leader", SIGRTMIN+3)` = `machinectl poweroff`
  (SIGRTMIN=34 op glibc → signo 37; empirisch geverifieerd op systemd 257).
- `TerminateMachine(name)` = `machinectl terminate` (hard kill).
- `Machine.leader`/`.unit` properties geven leader-pid + authoritative
  scope-naam — nooit `machine-<name>.scope` zelf formatteren.
- `SetUnitProperties(unit, runtime=true, a(sv))` = `systemctl
  set-property --runtime`. `CPUQuota` heet op de bus `CPUQuotaPerSecUSec`
  in µs (400% = 4_000_000 = `4s` in `systemctl show`).
- `busctl monitor` als non-root faalt (BecomeMonitor denied); onder root
  buffered stdout bij timeout-kill — nutteloos voor tracen. Liever
  direct `busctl introspect` + signaal-experiment.

## Hard-won: nsenter exec + cgroup-lidmaatschap

- `nsenter -p` **fork't altijd**: de gespawnde pid is een wachter; de echte
  payload is zijn kind (`/proc/<pid>/task/<pid>/children`). Cgroup-moves en
  metrics moeten op het KIND, niet op de nsenter-pid.
- `machine-<pod>.scope` én `payload/` hebben `subtree_control` aan →
  `cgroup.procs`-writes geven EBUSY (no-internal-process). Maak een eigen
  leaf `machine-<pod>.scope/rustypods-exec` en schrijf daarheen — dan vallen
  exec'd processen wél onder de pod's MemoryHigh/CPUQuota.
- `nsenter --wd=<pad>` resolved vóór setns tegen de host-mountns → `getcwd`
  faalt in de container. Niet gebruiken; `cd $HOME` in de login-shell-wrap.
- PTY: `openpty` via libc (`posix_openpt`+`grantpt`+`unlockpt`+`ptsname`),
  slave als stdio + `setsid`/`TIOCSCTTY` in `pre_exec`. `tty(1)` faalt op
  path-lookup (host-devpts), fd-semantiek werkt volledig.

## Rootless podman caveat

`podman` needs the user session bus (`/run/user/1000/bus`). If `podman
exec/start` fails with "Interactive authentication required", the user
session is down — the rustypods daemon itself (root, system bus) is
unaffected. Builds can then run inside a pod: `rustypods shell dev`.
