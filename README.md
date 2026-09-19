# RustyPods

nspawn pods op Btrfs, aangestuurd door een Rust-daemon over UDS+gRPC.
Podman/distrobox-light zonder overlayfs, zonder containerd, zonder proxy-overhead.

## Architectuur

```
rustypods (CLI) ──UDS+gRPC──> rustypodsd (root)
                                  │
                                  ├─ btrfs subvolume snapshot   (images → pods, instant CoW)
                                  ├─ systemd-nspawn --boot      (payload op de host-kernel)
                                  ├─ machined via zbus          (machine-<pod>.scope, leader-lookup, poweroff)
                                  ├─ systemd1 via zbus          (SetUnitProperties: MemoryHigh/Max/CPUQuota)
                                  └─ <──UDS── rustypods-agent   (in-pod telemetrie: cgroup v2 + PSI)

dataplane: /dev/shm/rustypods/<pod>/  ──bind──>  /run/rustypods/shm/  (mmap = echte gedeelde pages)
kanaal:    /var/lib/rustypods/run/<pod>/agent.sock ──bind──> /run/rustypods/run/
```

- `crates/rustypods-proto` — gRPC contract + gedeelde helpers
- `crates/rustypodsd` — root daemon (`/run/rustypods/daemon.sock`, data in `/var/lib/rustypods`)
- `crates/rustypods` — CLI
- `crates/rustypods-agent` — in-pod telemetrie (gestart door `rustypods-agent.service`, gedropt in de image bij import)

## Bouwen

De host heeft geen Rust-toolchain — bouwen gebeurt in de `arch` distrobox:

```bash
bash scripts/build.sh
```

## Installeren (sudo)

```bash
sudo bash scripts/install-daemon.sh   # systemd-container + unit + polkit-regel
```

## Gebruik

```bash
rustypods import --from-distrobox arch      # exporteert je arch box → image arch-base
rustypods images
rustypods create dev --image arch-base      # instant Btrfs-snapshot
rustypods start dev --memory-high 10G --memory-max 12G --cpu 400
rustypods ps
rustypods config dev --memory-high 8G       # live hot-reload, geen restart
rustypods reload dev                        # na hand-edit van conf/pods/dev.conf
rustypods shell dev                         # eigen Exec-RPC: nsenter + host-pty
rustypods shell dev -- cargo build          # of direct een commando (exit-code komt terug)
echo hi | rustypods shell dev cat           # pipes werken ook
rustypods stop dev
rustypods destroy dev
```

Handige vlaggen: `start --ephemeral` (wegwerp-run, `-x`) en `start --private-users`
(sterkere isolatie, maar breekt de naadloze `/home/nick`-uid-mapping).

## Exec-RPC (fase 2b)

`rustypods shell` gebruikt géén `machinectl` meer: de daemon draait
`nsenter -t <leader> -m -u -i -n -p` met een host-pty (`setsid`+`TIOCSCTTY`
→ echte job control), schakelt naar de container-user via `setpriv` met
passwd-data uit de image, en verplaatst de payload naar
`machine-<pod>.scope/rustypods-exec` zodat exec'd processen onder dezelfde
resource-limits vallen. SIGWINCH en exit-codes worden over de stream
doorgestuurd; machined wordt alleen nog gebruikt voor de leader-pid-lookup.

Bekende beperking: `tty(1)` faalt op path-resolutie (de pty-fd leeft in de
host-devpts); de fd zelf werkt volledig.

## Telemetrie & shared memory (fase 2a)

```bash
rustypods metrics dev                     # live stream: mem/cpu/pids/PSI uit de pod
rustypods shm create dev ring --size 64M  # mmap-baar segment
rustypods shm ls dev
rustypods shm rm dev ring
```

Host-side: `/dev/shm/rustypods/<pod>/<naam>`; pod-side: `/run/rustypods/shm/<naam>`.
Zelfde tmpfs-pages — een `mmap` aan beide kanten is letterlijk zero-copy.
Geschreven door uid 1000 zodat host- en pod-processen als `nick` kunnen mappen.

## Design-notities

- **Guardrails via machined-scope**: nspawn registreert zelf bij machined; de
  payload belandt in `machine-<pod>.scope`. Limits gaan daar op via
  `SetUnitProperties` op de system-bus (CPUQuota heet daar
  `CPUQuotaPerSecUSec`, 100% = 1_000_000µs) — een `systemd-run`-wrapper zou
  alleen de supervisor cappen. Pod die niet te cappen is, wordt gestopt.
- **D-Bus via zbus**: machined-calls (`GetMachine`/`KillMachine`/
  `TerminateMachine`/`ListMachines`) en systemd (`SetUnitProperties`,
  `StartUnit`) gaan native over één gedeelde `Connection` — geen
  `machinectl`/`systemctl`-subprocessen meer in de daemon.
- **Config = TOML per entiteit**: `conf/pods/<naam>.conf` en
  `conf/images/<naam>.conf` onder `/var/lib/rustypods` (géén centrale
  state.json — die wordt eenmalig gemigreerd). Limits leesbaar als
  `memory_high = "10.0G"`; `rustypods config` past live toe via
  SetUnitProperties, `rustypods reload` leest een hand-edit opnieuw in.
- **Stop-semantiek**: `stop` = `KillMachine(name, "leader", SIGRTMIN+3)`
  (clean poweroff, empirisch geverifieerd) → `TerminateMachine` als fallback.
- **UID's**: identity mapping (geen `--private-users` default) zodat container-`nick`
  = host-uid 1000 en `/home/nick` writes direct kloppen — distrobox-pariteit.
- **Sanitize bij import**: distrobox-restjes (`/etc/hostname`, `machine-id`,
  entrypoint-bins, profile.d-hooks) worden gewist zodat `--boot` schoon start.
- **Fase 2 restant**: computer-oom worker-subgroups/freeze,
  ringbuffer-protocol bovenop de SHM-segmenten.
