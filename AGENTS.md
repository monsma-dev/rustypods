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

## Rootless podman caveat

`podman` needs the user session bus (`/run/user/1000/bus`). If `podman
exec/start` fails with "Interactive authentication required", the user
session is down — the rustypods daemon itself (root, system bus) is
unaffected. Builds can then run inside a pod: `rustypods shell dev`.
