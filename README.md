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
remote:    rustypods --remote user@host … — gRPC over `ssh … rustypods stdio-bridge` (socat fallback)
```

- `crates/rustypods-proto` — gRPC contract + shared helpers
- `crates/rustypodsd` — root daemon (`/run/rustypods/daemon.sock`, data in `/var/lib/rustypods`)
- `crates/rustypods` — CLI
- `crates/rustypods-agent` — in-pod telemetry (started by `rustypods-agent.service`, dropped into the image at import)

## Build

Needs cargo + protoc (vendored via `protoc-bin-vendored` — no system
protobuf needed). `scripts/build.sh` picks a working environment: local
cargo if present, else the `dev` rustypods pod, else the legacy `arch`
distrobox:

```bash
bash scripts/build.sh
```

## Install (sudo)

```bash
sudo bash scripts/install-daemon.sh --user "$USER"
rustypods doctor   # verify the host satisfies all requirements
```

Requires a systemd host (PID 1 + machined) on a cgroup-v2 unified
hierarchy — `rustypods doctor` checks this and more before you install.

Supported distro families — the installer maps each to its package set
(`systemd-container`/`systemd`, `nftables`, `iproute2`/`iproute`,
`util-linux`, `btrfs-progs`, `socat`):

| Family | Distros | Status |
| --- | --- | --- |
| Debian/Ubuntu | Debian, Ubuntu, Mint, Pop!_OS, Neon, Raspbian, Kali | runtime + deployment live-tested on Debian 13 |
| Fedora | Fedora 44 | full runtime + deployment live-tested under KVM with SELinux Enforcing, Btrfs, cgroup v2 |
| RHEL family | RHEL, CentOS, Alma, Rocky, Oracle | required packages mapped; `btrfs-progs` is optional (not in RHEL 8/9 repos — reflink fallback). Runtime/SELinux still unverified |
| Arch | Arch, Manjaro, EndeavourOS, CachyOS | distro detection + installer dry-run validated; runtime unverified |

Release artifacts are currently built from source and should be compiled
on a target-compatible distro/libc — RustyPods does not yet publish
portable static binaries. Package names above have been checked against
the official Fedora/Alma/Arch package sources (name checking, not runtime
testing).

On Arch-family systems the package database and installed packages must
be current before installing (`pacman -Syu`) — the installer deliberately
uses `pacman -S`, never `-Sy`, to avoid partial upgrades.

On the RHEL family the installer does **not** fail the transaction when
`btrfs-progs` is absent (Alma/RHEL/Rocky 8 and 9 do not ship it). It
installs the required set (`systemd-container`, `nftables`, `iproute`,
`util-linux`, `socat`) and warns that the reflink fallback will be used.
If `dnf` cannot see `socat` or `systemd-container`, enable CRB (RHEL 9)
or PowerTools (RHEL 8) and EPEL yourself — the installer does not enable
repos. `--dry-run` prints that decision.

SELinux: `rustypods doctor` reports the mode and the context of
`/var/lib/rustypods`. Fedora 44 was validated enforcing with the default
`var_lib_t`. Other policies are unverified. `--selinux-label` is opt-in:
it runs `semanage fcontext` + `restorecon` (needs
`policycoreutils-python-utils`) and is a no-op when SELinux is off.

Unsupported distro: install the packages manually and re-run with
`--skip-packages`. `--dry-run` prints the detected family, target
user/uid, package commands and every path it would touch, without
changing anything and without root.

Uninstall: `sudo bash scripts/uninstall-daemon.sh` stops and disables the
unit, runs `rustypodsd teardown-net` (or deletes the nft tables and
`rustypods-forward*` / `rustypods-mesh-*` rules), removes binaries, the
unit, the polkit rule, `/etc/rustypods`, and the ingress CA from the host
trust store. It prints `ip_forward`, IPv6 forwarding, and `accept_ra`
and does **not** revert them. `/var/lib/rustypods` is kept unless
`--purge-data` is passed, and `--purge-data` is refused while a pod is
running. `--dry-run` needs no root.

The daemon's allowed non-root uid goes in `/etc/rustypods/daemon.env`
(written by the installer); the unit's `Environment=` default is 1000.
Off-btrfs hosts work via the `cp --reflink=auto` fallback — slower, no
quotas; `doctor` reports which storage driver applies.

The polkit rule (`deploy/49-rustypods.rules`) is **not** installed by
default — the rustypods CLI talks to the daemon over its own socket, so
polkit is only needed if you want raw `machinectl shell` on pods. Opt in
with `--install-polkit`.

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
rustypods exec dev -w ~/Projects/repo -- cargo build   # exec alias + workdir
rustypods exec --strict dev -- bash -lc 'cargo build | tail'  # pipefail on
echo hi | rustypods shell dev cat           # pipes work too
rustypods cp app.conf dev:/etc/app/         # copy host→pod (dirs via tar)
rustypods cp dev:/var/log/app.log ./        # and pod→host
rustypods stop dev
rustypods clone dev dev-test              # instant CoW clone (snapshot + fresh net identity)
rustypods commit dev "pre-upgrade"        # instant rootfs snapshot — the time machine
rustypods snapshots dev
rustypods rollback dev                    # or: --to <id>; swaps rootfs, pod ends stopped
rustypods destroy dev                     # also removes its snapshots
rustypods --remote user@server ps         # SSH; remote rustypods stdio-bridge, or socat if the CLI is old
```

Handy flags: `start --ephemeral` (throwaway run, `-x`) and
`start --no-private-users` (drops the user namespace; persisted to the conf).

## Bind mounts & sandboxing

Pods get no host paths by default. Add explicit binds at create or later —
they're stored in the pod conf and applied at the next start:

```bash
rustypods create dev --image arch-base --bind "$HOME" --bind /data:/mnt/data:ro
rustypods config dev --bind "$HOME" --bind "/run/user/$(id -u):ro"   # replaces the list
rustypods config dev --clear-binds                              # removes them all
```

Spec syntax is `host[:pod][:ro]` (pod path defaults to host). Anything under
`/run`, `/etc`, `/usr`, `/boot`, `/proc`, `/sys`, `/dev` or
`/var/lib/rustypods` is read-only only — a pod's init considers e.g.
`/run/user/<uid>` its own and will `rm -rf` it during session cleanup.

`create --desktop` adds the distrobox-parity preset (your home + /tmp rw,
/run/user/<uid> + /dev/dri + the rootless podman socket, all ro except home)
and disables the user namespace — a shared
home needs host-uid identity. All other new pods run with
`--private-users=pick`: pod root is not host root (the first start chowns
the rootfs once, cheap on btrfs). Exec'd processes additionally get their
capability bounding set dropped to nspawn's default set.

One exception: stack members (`rustypods apply`) run without a user
namespace. They join a pre-made shared netns via
`--network-namespace-path`, and `setns()` to it requires CAP_SYS_ADMIN in
the netns's owning userns (init_user_ns) — a pick-userns child never has
that, so the pod can't even boot. Standalone `create` pods do get userns.

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
# those two bind 127.0.0.1 only. To publish on every host address:
rustypods create web --image arch-base --port 0.0.0.0:18080:80
# or on one address: --port 192.0.2.10:18080:80
# IPv6 host addresses go in brackets: --port [2001:db8::10]:18080:80
```

**Default bind is loopback.** A spec without a host address
(`[hostIp:]hostPort:podPort[/tcp|/udp]`) publishes on **127.0.0.1 only**.
`0.0.0.0:host:pod` is the explicit "every IPv4 address" form. This is
intentional: `-p 5432:5432` must not open Postgres on the public zone
just because the pod exists. The CLI prints a one-line notice when it
creates an implicit loopback publish.

Any pod with `--port` gets a private network namespace (`--network-veth`):
host side `ve-<pod>` gets `<pool>.<idx>.1/30`, the pod's `host0` gets a static
`<pool>.<idx>.2/30` (written into the rootfs before boot; index is stable per
pod). The pool defaults to `10.220.0.0/16` and `fd22:220::/32` (255 pods).
Override it with `RUSTYPODS_POD_NET4` and `RUSTYPODS_POD_NET6` on the
daemon if those ranges collide with a VPN; `doctor` warns when the v4
pool overlaps an existing host route. The daemon manages its own `ip rustypods` nftables table:

- DNAT matches `ip daddr <hostIp>`. Loopback publishes are **output-hook
  only** (a prerouting rule cannot see them and must not exist).
  `0.0.0.0` uses `fib daddr type local` in prerouting and output.
- SNAT of host-originated traffic to the veth address (otherwise the pod
  would answer 127.0.0.1 on *its* loopback)
- masquerade for pod egress
- foreign FORWARD chains get marker accepts for DNATed flows, established
  replies, and packets that arrive on `ve-*` — not a blanket accept of
  the whole pod prefix, so an L2 neighbour cannot reach unpublished ports.
  Pod-to-pod traffic is allowed (both ends are `ve-*`). Set
  `isolated = true` on a pod to drop traffic between it and other pods.

We do **not** use nspawn's `--port`: it depends on the host side of the veth
being managed by systemd-networkd (its `80-container-ve.network` provides the
DHCP+nft glue), which NetworkManager/Netplan desktops don't run. Required
sysctls (`ip_forward`, `route_localnet` on the veth) are enabled
automatically. Before IPv6 forwarding is turned on, interfaces still at
`accept_ra=1` are set to `2` so kernel router advertisements keep
working; NetworkManager hosts already learn RAs in userspace. `doctor`
warns if a non-pod interface is left at `accept_ra=1` while forwarding
is on. These sysctls are not restored on teardown. `route_localnet` is required for localhost→pod replies;
the daemon compensates by dropping pod packets aimed at `127.0.0.0/8`
and by refusing new connections from a pod to host-local addresses.
Set `host_access = true` in the pod conf (or stack.toml) for a pod
that must reach host services. Privileged pod ports (<1024) need `--user root` inside the
pod, same as anywhere. Note: pods with ports lose host-net parity — DNS and
outbound go through the NAT, and the pod's own IP replaces `localhost`.

### Ingress gateway (local HTTPS for `*.rustypods.localhost`)

A managed `rustypods-ingress` pod terminates TLS and reverse-proxies to
pods' `--ingress` rules; the daemon pushes complete route snapshots over
its control socket whenever pods start/stop. Provision it once:

```bash
# --image must be ABI-compatible with the HOST-built rustypods-ingress
# binary that gets copied into the rootfs: Debian host → a Debian-family
# image, Fedora → Fedora-family; on this machine use `arch-base`.
rustypods ingress init --image arch-base          # provisions + starts
rustypods ingress init --image arch-base --install-ca
rustypods ingress status
```

`--install-ca` writes the generated CA (`/var/lib/rustypods/pki/ca.crt`)
into the host's system trust store (`update-ca-certificates` /
`update-ca-trust`) — it **mutates system trust**; skip it and import the
CA into your browser/store yourself if you prefer. Host loopback
`127.0.0.0/8` and `::1` ports 80/443 are redirected to the gateway via
nft OUTPUT rules only — nothing on the LAN can reach it, and init/start
refuses if either port is already bound.

## Stacks (Compose / K8s-pod model)

```toml
# stack.toml
name = "demo"

[pods.web]
image = "arch-base"
ports = ["8081:8080"]        # 127.0.0.1 only; DNAT to the shared stack IP

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
data from the image, and joins the leader's cgroup atomically
(`nsenter --cgroup --join-cgroup`): exec'd processes land in
`machine-<pod>.scope/payload/init.scope` — inside the pod's scope, so the
pod's MemoryHigh/CPUQuota apply to them. SIGWINCH and exit codes are
forwarded over the stream; machined is only used for the leader-pid
lookup.

Known limitation: `tty(1)` fails on path resolution (the pty fd lives in the
host devpts); the fd itself works fully.

## Dev & agent workflows

Always-on dev pods can boot with the daemon — something distrobox never
had:

```bash
rustypods create dev --image arch-base --desktop --autostart
rustypods config dev --autostart off      # back to manual
```

For agents (Devin/Cursor-style exec layers) everything is scriptable — no
tty needed, exit codes come back exactly:

```bash
rustypods shell dev -- cargo test         # non-tty exec; clean stdout/stderr
rustypods logs -f dev                     # plain-text journal, auto-reconnects
```

OCI images without an init exit immediately — use `--cmd sleep infinity`
to keep a dev pod alive:

```bash
rustypods pull debian:trixie
rustypods create deb-dev --image debian-trixie --desktop --cmd sleep infinity
rustypods start deb-dev                 # payload pod; logs via console log
```

The override replaces the image's entrypoint+cmd and forces non-boot mode;
change it later with `rustypods config <pod> --cmd …` / `--clear-cmd`
(applied at the next start). Multi-word commands work — everything after
`--cmd` is command argv, so it must be the **final** rustypods option:

```bash
rustypods create web --image alpine-latest --port 8080:80 \
  --cmd sh -c 'httpd -f -p 80 -h /www'
```

The host's `LANG` is forwarded on exec — a fresh OCI rootfs that hasn't
generated it gets `C.UTF-8` instead, so locale-aware tools don't die; run
`locale-gen` in the pod for the real locale.

Note: non-userns pods (including `--desktop`) require util-linux `setpriv`
inside the image for secure exec — the daemon drops the capability
bounding set through it. Minimal BusyBox images lack a usable `setpriv`,
so `shell`/`exec` there is intentionally refused rather than retaining
host-root's bounding set.

or over REST/JSON with the bearer token in `/run/rustypods/http-token`:

```bash
curl -H "Authorization: Bearer $(cat /run/rustypods/http-token)" \
  http://127.0.0.1:9180/v1/pods
```

Socket passthrough: `--desktop` pods already bind `/run/user/<uid>`
read-only, which covers `$SSH_AUTH_SOCK`, the session bus and PipeWire —
unix-socket `connect()` works fine through a read-only mount. When the
rootless podman socket (`/run/user/<uid>/podman/podman.sock`) exists on the
host it gets its own ro bind, so `podman` inside the pod drives the host's
containers (distrobox parity). Client calls carry a 30s timeout — it bounds
time-to-response only, so `-f` log/metric/exec streams are unaffected.

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

## OCI pulls, logs & snapshot GC

```bash
rustypods pull busybox:latest        # native OCI pull — no podman/docker needed
rustypods pull ghcr.io/org/tool:v1 --name tool
rustypods logs dev                   # journal backlog; non-boot pods → console log
rustypods logs dev -f                # keep following
rustypods config dev --snap-keep 5 --snap-max-age 7d   # snapshot GC; 0 = keep all
```

Pulled images carry their OCI entrypoint/cmd — pods on them run non-boot
(the payload replaces systemd), which is also why their `logs` come from the
console log instead of the journal.

### REST API

The same PodControl surface is exposed as REST/JSON for automation and
agents: `rustypodsd --http-addr 127.0.0.1:9180` (the default; `--http-addr ""`
disables it). Every `/v1/*` request needs
`Authorization: Bearer <token>` — the daemon generates the token at startup
and writes it to `/run/rustypods/http-token` (mode `0400`, owned by the
allowed uid). Requests carrying `Origin`/`Sec-Fetch-Site` headers are
rejected (no browser-driven calls); `/healthz` stays open. The bind is
loopback-only — a non-loopback `--http-addr` is refused unless
`RUSTYPODS_HTTP_INSECURE=1` is set. Request bodies are snake_case;
responses are the proto messages in camelCase JSON:

```
GET    /healthz                      GET    /v1/daemon
GET    /v1/pods                      POST   /v1/pods          {"name","image",…}
PATCH  /v1/pods/:name                {"memory_high_bytes","ports","binds",
                                      "snap_keep_last","autostart",…}
POST   /v1/pods/:name/start|stop     DELETE /v1/pods/:name
GET    /v1/images                    GET    /v1/pods/:name/metrics
POST   /v1/stacks   (raw stack.toml) DELETE /v1/stacks/:name
```

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
- **UIDs**: `--private-users=pick` is the default for new pods (pod root ≠
  host root). `--desktop` pods keep identity mapping so a bound
  `/home/<user>` writes as the real uid — distrobox parity.
- **Sanitize on import**: distrobox leftovers (`/etc/hostname`,
  `machine-id`, entrypoint bins, profile.d hooks) are wiped so `--boot`
  starts cleanly.
- **Remaining phase-2 items**: computer-oom worker subgroups/freeze,
  ringbuffer protocol on top of the SHM segments.

## Desktop GUI (`gui/`)

Tauri v2 + React + TypeScript + Tailwind v4 (dark, Adwaita-flavoured,
frameless window with a custom headerbar). The Rust side is a thin
bridge: Tauri commands call the same gRPC socket via the shared
`rustypods-client` crate — zero duplicated daemon logic. The toolchain
is Rust all the way down: SWC compiles TS/JSX, LightningCSS handles CSS,
and `ts-proto` generates the frontend types straight from
`crates/rustypods-proto/proto/rustypods.proto` — the daemon and the UI
share one contract. Commands return proto messages verbatim (camelCase
JSON), decoded with the generated `fromJSON`.

```bash
cd gui
npm install
npm run gen:proto     # regenerate src/proto/rustypods.ts after .proto changes
npm run tauri dev     # vite + native window, needs the daemon running
npm run build         # frontend only → gui/dist
```

Commands: `get_pods`, `start_pod`, `stop_pod`, `update_pod_config`,
`get_images`, `get_daemon_info`, `watch_logs`. Views: Pods (dense table,
click a row for the detail panel), Stacks (grouped by shared netns),
Images, Settings (daemon info, refresh interval, reduce-motion).
The detail panel has a segmented tab strip: Settings | Logs | Terminal —
Logs renders `StreamLogs` in a read-only xterm, Terminal is a live exec
shell. Snapshot retention (keep-last / max-age) is editable under
Settings → Snapshots.

The pod detail panel edits cgroup limits (memory high/max, CPU quota),
the btrfs disk quota and port forwards via `UpdatePodConfig` — applied
live, no restart. While a pod runs, `watch_metrics` streams the in-pod
agent's samples to the frontend as `pod-metrics` Tauri events: the
panel renders 60-sample SVG sparklines for memory (with high/max limit
lines), CPU vs quota, and PSI stall (mem/io/cpu). Reduce-motion or a
≥5 s refresh interval falls back to text stats. Screenshots in
`docs/screenshots/`.

End-to-end IPC test against a live daemon (uses `tauri::test`
MockRuntime — no webview needed):

```bash
cd gui/src-tauri && cargo test   # stops + starts the `dev` pod for real
```
