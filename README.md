# RustyPods

nspawn pods op Btrfs, aangestuurd door een Rust-daemon over UDS+gRPC.
Podman/distrobox-light zonder overlayfs, zonder containerd, zonder proxy-overhead.

## Architectuur (M1 — walking skeleton)

```
rustypods (CLI) ──UDS+gRPC──> rustypodsd (root)
                                  │
                                  ├─ btrfs subvolume snapshot   (images → pods, instant CoW)
                                  ├─ systemd-nspawn --boot      (payload op de host-kernel)
                                  ├─ machined                   (machine-<pod>.scope, gratis tooling)
                                  └─ systemctl set-property     (MemoryHigh/MemoryMax/CPUQuota guardrails)
```

- `crates/rustypods-proto` — gRPC contract + gedeelde helpers
- `crates/rustypodsd` — root daemon (`/run/rustypods/daemon.sock`, data in `/var/lib/rustypods`)
- `crates/rustypods` — CLI
- `crates/rustypods-agent` — in-pod telemetry (stub; fase 2)

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
rustypods shell dev                         # machinectl shell nick@dev
rustypods stop dev
rustypods destroy dev
```

Handige vlaggen: `start --ephemeral` (wegwerp-run, `-x`) en `start --private-users`
(sterkere isolatie, maar breekt de naadloze `/home/nick`-uid-mapping).

## Design-notities

- **Guardrails via machined-scope**: nspawn registreert zelf bij machined; de
  payload belandt in `machine-<pod>.scope`. Limits gaan daar op via
  `systemctl set-property` — een `systemd-run`-wrapper zou alleen de supervisor
  cappen. Pod die niet te cappen is, wordt gestopt.
- **UID's**: identity mapping (geen `--private-users` default) zodat container-`nick`
  = host-uid 1000 en `/home/nick` writes direct kloppen — distrobox-pariteit.
- **Sanitize bij import**: distrobox-restjes (`/etc/hostname`, `machine-id`,
  entrypoint-bins, profile.d-hooks) worden gewist zodat `--boot` schoon start.
- **Fase 2**: `zbus` machined-API i.p.v. subprocessen, `rustypods-agent`
  telemetrie via `/run/rustypods` bind, SHM-dataplane (`/dev/shm`), Exec-RPC
  (nsenter+pty), computer-oom worker-subgroups/freeze.
