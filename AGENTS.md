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
  the pod prefix hit unpublished ports. firewalld still gets the veth
  in the trusted zone for egress; the DNAT match is what limits who
  can open a published port.
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

## Pod export/import (Wave H)

`rustypods export <pod> [-o file]` → one opaque archive stream:
`[8B magic "RPEX0001"][u32 len][manifest JSON][payload]`. Payload =
multi-subvolume `btrfs send` (needs `-r` ro snapshots — `clone_rootfs`
makes rw ones, use `storage::btrfs::snapshot_ro`) on btrfs hosts, `tar`
elsewhere; both name entries `<pod>`/`<vol>` so `btrfs receive`/`tar
-x` recreate the same layout in staging. `rustypods load <file|->
[--name x]` imports.

- Running pods are cgroup-frozen (`cgroup.freeze` on the machined
  scope) for the snapshot window only — point-in-time across rootfs +
  volumes, ms-scale pause. Freeze is inside the SAME blocking closure
  as the snapshots so unfreeze can't be skipped.
- `btrfs receive` lands subvols ro WITH `received_uuid` — `property
  set ro false` is REFUSED on those (the uuid serves incremental
  sends). The canonical move is an rw `subvolume snapshot` into place
  (= clone_rootfs) and deleting the ro staging copy.
- Import sanitizes: started=false, net_index=0 (a /30 can't move
  hosts), stack="", ingress_gateway=false. Image CONF travels (pods
  resolve entrypoint/env from ImageMeta at start) — the image tree
  never does; the pod rootfs is complete.
- Export refuses the managed gateway pod (per-host infrastructure).
- Name/volume collisions refuse before payload lands; existing volume
  names fail hard (never overwrite data). Volume dirs get 0777 like
  ensure_volume.
- REST: `GET /v1/pods/{name}/export` (octet-stream download) and
  `POST /v1/import?name=` (body upload) — same archive, no temp copy.
- Import is client-streaming→unary: the default 30s call timeout
  would cut large uploads — the CLI uses connect_timeout(1h).
- Known gap: multi-subvolume consistency is freeze-window only, not a
  memory checkpoint — apps see a crash-consistent state (like a clean
  power cut). True live migration needs CRIU, out of scope.

## Multi-host mesh (Wave I)

`rustypods mesh init|status|add-peer|rm-peer` — userspace WireGuard via
BoringTun (no kernel module), giving every pod a ULA address reachable
from pods on other hosts. L3, end-to-end encrypted, no NAT.

- Identity = addressing: each daemon derives its /48 as
  `fd<40 bits of sha256(pubkey)>` (RFC 4193 L-bit set). A peer's prefix
  is verified BY its pubkey — config can't claim foreign space, and
  prefix derivation needs zero coordination.
- Pod mesh addr = `fd<host>:<net_idx>::2` — a second /128 on host0 next
  to the intra-host fd22:220:<idx>::2. Pods need NO extra route (v6
  default already via host); longest-prefix src selection picks the
  mesh addr when dialing mesh space.
- Datapath: persistent `rp-mesh0` TUN (IFF_NO_PI, created via
  `ip tuntap` so routes survive daemon restarts) + one UDP socket +
  one boringtun `Tunn` per peer. `fd<peer>::/48 dev rp-mesh0` steers
  outbound; `fd<local>:<idx>::2/128 dev ve-<pod>` delivers inbound.
- `conf/mesh.conf` (0600 — holds the WG private key, base64) persists
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
  are in-memory atomics surfaced via MeshStatus — no file dumps.
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
  again — the upstream is usually a v4 stub.
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
