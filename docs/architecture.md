# RustyPods — Architecture

*A pod engine for Linux built on the primitives the kernel already gives you:
Btrfs subvolumes, systemd-nspawn, cgroup-v2, nftables and tmpfs. No containerd,
no overlayfs chains, no proxy processes — near bare-metal overhead.*

This document is aimed at system administrators and DevOps engineers evaluating
RustyPods, or contributors who want the "why" behind the layout.

## Design goals

1. **Zero-overhead payloads.** A pod's init runs on the host kernel under
   `systemd-nspawn`. There is no shim runtime, no VM, no user-space proxy in the
   data path.
2. **Copy-on-write everything.** Images and pods are Btrfs subvolumes; create,
   clone and destroy are filesystem operations measured in milliseconds.
3. **Real guardrails.** Every pod lives in a machined scope
   (`machine-<pod>.scope`) with cgroup-v2 `MemoryHigh`/`MemoryMax`/`CPUQuota`
   applied through the systemd D-Bus API.
4. **Graceful degradation.** Btrfs is the ultimate experience, but the storage
   layer is a trait — ext4/XFS hosts fall back to reflink copies.
5. **Batteries included.** Telemetry agent, port forwarding, shared-memory
   dataplane, stack orchestration and remote management ship in-tree.

## The three pillars

### 1. Storage — `StorageDriver`

```
trait StorageDriver {
    create_rootfs(path)          // btrfs subvolume create | mkdir
    clone_rootfs(src, dst)       // btrfs snapshot         | cp -a --reflink=auto
    delete_rootfs(path)          // btrfs subvolume delete | rm -rf
    apply_quota(path, bytes)     // btrfs qgroup limit     | unsupported
}
```

At startup the daemon probes the filesystem under `/var/lib/rustypods/pods`:

- **Btrfs** → `BtrfsDriver`. Image→pod and pod→pod clones are `btrfs
  subvolume snapshot` calls — instant and initially free of disk usage.
  Per-pod storage caps are native qgroup limits (`btrfs qgroup limit`):
  writes beyond the cap return ENOSPC inside the pod. Quota accounting does
  not survive a remount, so limits are re-applied at every pod start.

  The same snapshot primitive powers the **time machine**: `rustypods
  commit <pod> [label]` writes an atomic CoW snapshot to
  `snapshots/<pod>/<ts>-<label>` (milliseconds, ~0 bytes), and
  `rustypods rollback <pod>` stops the pod, deletes the live rootfs and
  re-clones the snapshot into place. Git for server state — a failed
  upgrade is a sub-second `rollback` away, not a backup restore.
- **Anything else** → `FallbackDriver`: plain directories cloned with
  `cp -a --reflink=auto`. On XFS and modern ext4 this is still copy-on-write;
  on other filesystems it is a full copy — correct, just not instant.
  `storage_max` then errors clearly instead of silently doing nothing.

The active driver is reported by `rustypods ping` (`storage: btrfs`), so
clients and a future GUI can gate quota UI on real capability.

**Windows/macOS note.** Those platforms cannot run Linux containers at all —
the plan (as with Docker Desktop / Podman Machine) is an invisible micro-VM.
Its virtual disk is formatted Btrfs, so desktop users still get the 10 ms
clones; the CLI talks to the in-VM daemon over the same gRPC socket protocol.

### 2. Orchestration — pods, stacks and networking

**Standalone pods** default to host networking (distrobox parity). A pod
created with `--port` gets a private netns via `--network-veth`; the daemon
owns the addressing (`ve-<pod>` = `10.220.<idx>.1/30` ↔ pod `host0` =
`10.220.<idx>.2/30`) and maintains a dedicated `ip rustypods` nftables table
rebuilt from state after every lifecycle event — self-healing by
construction. Localhost and LAN clients both reach published ports; pod
egress is masqueraded.

We deliberately do **not** use nspawn's `--port`: it silently requires
systemd-networkd managing the host veth, which desktop distros running
NetworkManager/Netplan don't provide.

**Stacks** (`rustypods apply stack.toml`) are the Kubernetes pod model: all
members share ONE named netns (`rustypods-<stack>`) with a single `/30`
uplink (`ve-<stack>` ↔ `vp-<stack>`). Members boot with
`--network-namespace-path=/var/run/netns/rustypods-<stack>` and therefore
share `lo` — a web pod and its database reach each other on `127.0.0.1`
with zero DNS or proxy overhead. Ports publish on the shared stack IP;
duplicate host ports are rejected at apply time. `rustypods stack
start|stop|destroy` fans lifecycle out over `<stack>-<member>` pods, and the
netns is garbage-collected when the last member disappears.

### 3. Dataplane — zero-copy shared memory

For high-throughput IPC (game state, media pipelines, sidecars) pods get an
mmap-able tmpfs segment: host `/dev/shm/rustypods/<pod>/<seg>` is bound into
the pod at `/run/rustypods/shm/<seg>`. Both sides map the *same pages* —
there is no copy and no syscall per message. An in-pod agent
(`rustypods-agent`, injected at image import) streams cgroup-v2/PSI metrics
back over a per-pod Unix socket at `/run/rustypods/run/agent.sock`.

## Control plane

- **API**: gRPC over `/run/rustypods/daemon.sock` (`proto/rustypods.proto` is
  the contract). Peer credentials gate access to root + the configured uid.
- **Remote**: `rustypods --remote user@host …` pipes gRPC through
  `ssh -T host socat - UNIX-CONNECT:<sock>` — SSH supplies auth, encryption
  and host-key verification; the daemon needs no TLS or user database.
- **Config**: per-entity TOML (`conf/pods/<name>.conf`), human-readable
  (`memory_high = "10G"`). `rustypods config` hot-applies to the live scope;
  `rustypods reload` rereads a hand edit.
- **Runtime**: `RuntimeEngine` trait — today `SystemdNspawn` (spawn →
  machined registration via zbus → `SetUnitProperties` limits). The trait
  (`start`/`stop`/`running_pid`/`apply_limits`/`healthy`) is the seam for a
  future OCI engine (`crun`/`youki`) on non-systemd distributions.
- **Exec**: `nsenter` into the machined leader's namespaces + host pty for
  real job control; exec'd processes are moved into the pod's scope so the
  limits keep applying. Exit codes and SIGWINCH propagate over the stream.

## Repository layout

```
crates/
  rustypods-proto/   gRPC contract + shared helpers (validate_name, parse_bytes)
  rustypodsd/        root daemon
    src/storage/     StorageDriver: btrfs.rs + fallback.rs
    src/runtime/     RuntimeEngine: nspawn.rs (argv, spawn, machined ops)
    src/net.rs       veth/netns wiring + the `ip rustypods` nftables table
    src/stack.rs     stack.toml schema + validation
    src/exec.rs      nsenter + pty exec bridge
    src/agent.rs     per-pod telemetry listener + SHM bookkeeping
    src/dbus.rs      zbus proxies: machined, systemd1
  rustypods/         CLI (local UDS or --remote over ssh+socat)
  rustypods-agent/   in-pod metrics publisher
```

## Operational notes

- The daemon runs as root (nspawn, btrfs, netns, machined all require it).
- Required host tools: `systemd-nspawn`, `ip`, `nft`, `btrfs` (optional but
  recommended), `socat` on *remote* hosts for `--remote`.
- `/run/user/<uid>` is only ever bind-mounted **read-only** into pods — a
  writable bind once let container logind delete the host's session bus.
- Pod logs land in `/var/lib/rustypods/logs/<pod>.log` (nspawn console output).
