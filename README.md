# RustyPods

nspawn pods on Btrfs, driven by a Rust daemon over UDS+gRPC.
Podman/distrobox-light without overlayfs, without containerd, without proxy overhead.

## Architecture

```
rustypods (CLI) ──UDS+gRPC──> rustypodsd (root)
                                  │
                                  ├─ btrfs subvolume snapshot   (images → pods, instant CoW)
                                  ├─ btrfs qgroups              (per-pod storage caps)
                                  ├─ systemd-nspawn --boot      (payload on the host kernel)
                                  ├─ machined via zbus          (machine-<pod>.scope, leader lookup, poweroff)
                                  ├─ systemd1 via zbus          (SetUnitProperties: MemoryHigh/Max/CPUQuota)
                                  ├─ nftables DNAT              (port forwarding, own `ip rustypods` table)
                                  └─ <──UDS── rustypods-agent   (in-pod telemetry: cgroup v2 + PSI)

dataplane: /dev/shm/rustypods/<pod>/  ──bind──>  /run/rustypods/shm/  (mmap = real shared pages)
channel:   /var/lib/rustypods/run/<pod>/agent.sock ──bind──> /run/rustypods/run/
network:   pods with --port get a private netns: ve-<pod> (10.220.<idx>.1/30) ↔ host0 (10.220.<idx>.2/30)
stacks:    all members share ONE named netns (rustypods-<stack>) — 127.0.0.1 is shared, K8s-pod style
remote:    rustypods --remote user@host … — gRPC over `ssh … socat - UNIX-CONNECT:` (no extra ports)
```

- `crates/rustypods-proto` — gRPC contract + shared helpers
- `crates/rustypodsd` — root daemon (`/run/rustypods/daemon.sock`, data in `/var/lib/rustypods`)
- `crates/rustypods` — CLI
- `crates/rustypods-agent` — in-pod telemetry (started by `rustypods-agent.service`, dropped into the image at import)

## Build

The host has no Rust toolchain — builds happen inside the `arch` distrobox:

```bash
bash scripts/build.sh
```

## Install (sudo)

```bash
sudo bash scripts/install-daemon.sh   # systemd-container + unit + polkit rule
```

## Usage

```bash
rustypods import --from-distrobox arch      # export your arch box → image arch-base
rustypods images
rustypods create dev --image arch-base      # instant Btrfs snapshot
rustypods start dev --memory-high 10G --memory-max 12G --cpu 400
rustypods ps
rustypods config dev --memory-high 8G       # live hot-reload, no restart
rustypods config dev --storage-max 20G      # btrfs qgroup cap, hot-applied
rustypods reload dev                        # after hand-editing conf/pods/dev.conf
rustypods shell dev                         # native Exec RPC: nsenter + host pty
rustypods shell dev -- cargo build          # or run a command (exit code comes back)
echo hi | rustypods shell dev cat           # pipes work too
rustypods stop dev
rustypods clone dev dev-test              # instant CoW clone (snapshot + fresh net identity)
rustypods destroy dev
rustypods --remote user@server ps         # manage a remote daemon over SSH (needs socat there)
```

Handy flags: `start --ephemeral` (throwaway run, `-x`) and `start --private-users`
(stronger isolation, but breaks the seamless `/home/nick` uid mapping).

## Storage quotas (btrfs qgroups)

```bash
rustypods create web --image arch-base --storage-max 5G
rustypods config dev --storage-max 20G      # hot-applied to the live subvolume
```

The daemon enables quota accounting on the data dir (one-time tree scan) and
sets an exclusive qgroup limit on the pod's subvolume. Writes beyond the cap
fail with ENOSPC inside the pod. Quota state doesn't survive a remount, so
limits are re-applied at every pod start.

## Networking & port forwarding

```bash
rustypods create web --image arch-base --port 18080:80 --port 53:53/udp
```

Any pod with `--port` gets a private network namespace (`--network-veth`):
host side `ve-<pod>` gets `10.220.<idx>.1/30`, the pod's `host0` gets a static
`10.220.<idx>.2/30` (written into the rootfs before boot; index is stable per
pod). The daemon manages its own `ip rustypods` nftables table:

- DNAT `host:port → pod:port` in prerouting + output (external *and*
  localhost clients work)
- SNAT of host-originated traffic to the veth address (otherwise the pod
  would answer 127.0.0.1 on *its* loopback)
- masquerade for pod egress

We do **not** use nspawn's `--port`: it depends on the host side of the veth
being managed by systemd-networkd (its `80-container-ve.network` provides the
DHCP+nft glue), which NetworkManager/Netplan desktops don't run. Required
sysctls (`ip_forward`, `route_localnet` on the veth) are enabled
automatically. Privileged pod ports (<1024) need `--user root` inside the
pod, same as anywhere. Note: pods with ports lose host-net parity — DNS and
outbound go through the NAT, and the pod's own IP replaces `localhost`.

## Stacks (Compose / K8s-pod model)

```toml
# stack.toml
name = "demo"

[pods.web]
image = "arch-base"
ports = ["8081:8080"]        # published on the shared stack IP

[pods.api]
image = "arch-base"
storage_max = "3G"

[pods.api.limits]
memory_max = "1G"
cpu_quota_percent = 100
```

```bash
rustypods apply stack.toml       # creates demo-web + demo-api, wires rustypods-demo netns
rustypods stack start demo       # both pods join the SAME network namespace
rustypods stack stop demo
rustypods stack destroy demo     # members + netns + veth + NAT gone
```

Every stack gets one named netns (`rustypods-<name>`) with a single
`/30` uplink: `ve-<stack>` on the host (`10.220.<idx>.1`) ↔ `vp-<stack>`
inside (`10.220.<idx>.2`). Members start with
`--network-namespace-path=/var/run/netns/rustypods-<stack>` — like
containers in a Kubernetes pod they share `lo`, so `demo-api` reaches a
server in `demo-web` on `127.0.0.1:8080` directly (no DNS, no proxy).
Host port mappings DNAT to the shared stack IP; two members therefore
can't publish the same host port (rejected at apply). Re-applying a
stack.toml is idempotent — confs update, running rootfs stays.

## Exec RPC

`rustypods shell` no longer uses `machinectl`: the daemon runs
`nsenter -t <leader> -m -u -i -n -p` with a host pty (`setsid`+`TIOCSCTTY`
→ real job control), drops to the container user via `setpriv` with passwd
data from the image, and moves the payload into
`machine-<pod>.scope/rustypods-exec` so exec'd processes live under the same
resource limits. SIGWINCH and exit codes are forwarded over the stream;
machined is only used for the leader-pid lookup.

Known limitation: `tty(1)` fails on path resolution (the pty fd lives in the
host devpts); the fd itself works fully.

## Telemetry & shared memory

```bash
rustypods metrics dev                     # live stream: mem/cpu/pids/PSI from the pod
rustypods shm create dev ring --size 64M  # mmap'able segment
rustypods shm ls dev
rustypods shm rm dev ring
```

Host side: `/dev/shm/rustypods/<pod>/<name>`; pod side: `/run/rustypods/shm/<name>`.
Same tmpfs pages — an `mmap` on both sides is literally zero-copy.
Files are owned by uid 1000 so host and pod processes can map them as `nick`.

## Design notes

- **Guardrails via the machined scope**: nspawn registers itself with
  machined; the payload lands in `machine-<pod>.scope`. Limits go on that
  scope via `SetUnitProperties` on the system bus (CPUQuota is called
  `CPUQuotaPerSecUSec` there, 100% = 1_000_000µs) — a `systemd-run` wrapper
  would only cap the supervisor. A pod that can't be capped gets stopped.
- **D-Bus via zbus**: machined calls (`GetMachine`/`KillMachine`/
  `TerminateMachine`/`ListMachines`) and systemd (`SetUnitProperties`,
  `StartUnit`) go natively over one shared `Connection` — no
  `machinectl`/`systemctl` subprocesses in the daemon.
- **Config = TOML per entity**: `conf/pods/<name>.conf` and
  `conf/images/<name>.conf` under `/var/lib/rustypods` (no central
  state.json — it's migrated once). Limits are readable as
  `memory_high = "10.0G"`; `rustypods config` applies live via
  SetUnitProperties, `rustypods reload` rereads a hand edit.
- **Stop semantics**: `stop` = `KillMachine(name, "leader", SIGRTMIN+3)`
  (clean poweroff, empirically verified) → `TerminateMachine` as fallback.
- **UIDs**: identity mapping (no `--private-users` by default) so
  container-`nick` = host uid 1000 and `/home/nick` writes just work —
  distrobox parity.
- **Sanitize on import**: distrobox leftovers (`/etc/hostname`,
  `machine-id`, entrypoint bins, profile.d hooks) are wiped so `--boot`
  starts cleanly.
- **Remaining phase-2 items**: computer-oom worker subgroups/freeze,
  ringbuffer protocol on top of the SHM segments.
