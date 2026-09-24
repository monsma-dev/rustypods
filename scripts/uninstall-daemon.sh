#!/usr/bin/env bash
# Remove the rustypodsd install. Does not delete pod data unless --purge-data,
# and refuses that while any pod is still running.
#
# Usage: scripts/uninstall-daemon.sh [--dry-run] [--purge-data]
set -euo pipefail

DRY_RUN=0
PURGE_DATA=0

die() { echo "error: $*" >&2; exit 1; }

usage() {
  cat >&2 <<'EOF'
Usage: scripts/uninstall-daemon.sh [--dry-run] [--purge-data]
  --dry-run      print every step, change nothing (no root required)
  --purge-data   also delete /var/lib/rustypods. Refused while a pod is running.
                 Without this flag the data dir is left in place.
Sysctls the daemon may have set (ip_forward, ipv6 forwarding, accept_ra) are
printed and NOT reverted — something else on the host may depend on them.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    --purge-data) PURGE_DATA=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage; die "unknown argument: $1" ;;
  esac
done

if [[ $DRY_RUN -eq 0 && $EUID -ne 0 ]]; then
  die "run as root: sudo bash scripts/uninstall-daemon.sh (or --dry-run)"
fi

run_cmd() {
  printf '    $'
  printf ' %q' "$@"
  printf '\n'
  if [[ $DRY_RUN -eq 0 ]]; then
    "$@"
  fi
}

# A pod counts as running if the CLI says so, or if machined still has a
# machine scope (the daemon's KillMode=process leaves nspawn alive).
pods_running() {
  local ps_bin=/usr/local/bin/rustypods
  if [[ -x $ps_bin ]]; then
    if "$ps_bin" ps 2>/dev/null | awk 'NF >= 3 && $3 == "running" { found=1 } END { exit !found }'; then
      return 0
    fi
  fi
  shopt -s nullglob
  local scopes=(/sys/fs/cgroup/machine.slice/machine-*.scope)
  shopt -u nullglob
  [[ ${#scopes[@]} -gt 0 ]]
}

if [[ $PURGE_DATA -eq 1 ]] && pods_running; then
  die "--purge-data refused: a pod is still running. Stop every pod first (rustypods ps), then re-run."
fi

echo "==> stop and disable rustypodsd"
if [[ $DRY_RUN -eq 1 ]]; then
  echo "    \$ systemctl disable --now rustypodsd"
  echo "    \$ systemctl daemon-reload"
else
  systemctl disable --now rustypodsd || true
  systemctl daemon-reload || true
fi

echo "==> firewall teardown"
DAEMON=/usr/local/bin/rustypodsd
if [[ -x $DAEMON ]] && "$DAEMON" teardown-net --help >/dev/null 2>&1; then
  echo "    rustypodsd supports teardown-net"
  if [[ $DRY_RUN -eq 1 ]]; then
    echo "    \$ $DAEMON teardown-net"
  else
    "$DAEMON" teardown-net || echo "warning: teardown-net failed; falling back to nft" >&2
  fi
else
  echo "    teardown-net not in this binary — deleting nft tables and marker rules"
  # Only RustyPods-owned tables. Never `nft delete table ip filter`.
  run_cmd nft delete table ip rustypods || true
  run_cmd nft delete table ip6 rustypods6 || true
  run_cmd nft delete table inet rustypods || true
  delete_marked() {
    local fam="$1" table="$2" chain="$3" line handle
    command -v nft >/dev/null 2>&1 || return 0
    while IFS= read -r line; do
      case "$line" in
        *rustypods-forward*|*rustypods-mesh-*)
          handle="$(sed -n 's/.*handle \([0-9][0-9]*\).*/\1/p' <<<"$line")"
          [[ -n "$handle" ]] || continue
          run_cmd nft delete rule "$fam" "$table" "$chain" handle "$handle" || true
          ;;
      esac
    done < <(nft -a list chain "$fam" "$table" "$chain" 2>/dev/null || true)
  }
  delete_marked ip filter FORWARD
  delete_marked ip6 filter FORWARD
  delete_marked inet filter FORWARD
  delete_marked ip filter INPUT
  delete_marked ip6 filter INPUT
  delete_marked inet filter INPUT
fi

echo "==> remove unit, binaries, polkit, /etc/rustypods"
run_cmd rm -f /etc/systemd/system/rustypodsd.service
run_cmd rm -f /usr/local/bin/rustypodsd /usr/local/bin/rustypods
run_cmd rm -f /var/lib/rustypods/bin/rustypods-agent /var/lib/rustypods/bin/rustypods-ingress
run_cmd rm -f /etc/polkit-1/rules.d/49-rustypods.rules
run_cmd rm -rf /etc/rustypods
if [[ $DRY_RUN -eq 1 ]]; then
  echo "    \$ systemctl daemon-reload"
else
  systemctl daemon-reload || true
fi

echo "==> ingress CA (host trust store)"
remove_ca() {
  local path="$1" tool="$2"
  if [[ -e $path ]]; then
    run_cmd rm -f "$path"
    if command -v "$tool" >/dev/null 2>&1; then
      run_cmd "$tool"
    else
      echo "    note: removed $path but $tool is not installed"
    fi
  else
    echo "    absent: $path"
  fi
}
remove_ca /usr/local/share/ca-certificates/rustypods-local-ca.crt update-ca-certificates
remove_ca /etc/pki/ca-trust/source/anchors/rustypods-local-ca.crt update-ca-trust
remove_ca /etc/ca-certificates/trust-source/anchors/rustypods-local-ca.crt update-ca-trust

echo "==> sysctls left as the daemon set them (not reverted)"
for key in net.ipv4.ip_forward net.ipv6.conf.all.forwarding; do
  if [[ -r /proc/sys/${key//./\/} ]]; then
    echo "    $key=$(cat "/proc/sys/${key//./\/}")"
  else
    echo "    $key=(unreadable)"
  fi
done
echo "    non-pod interfaces may have accept_ra=2 (was 1). Check:"
echo "      sysctl net.ipv6.conf.all.accept_ra"
echo "    Revert by hand only if nothing else needs forwarding."

if [[ $PURGE_DATA -eq 1 ]]; then
  echo "==> purge /var/lib/rustypods"
  run_cmd rm -rf /var/lib/rustypods
else
  echo "==> keeping /var/lib/rustypods (pass --purge-data to delete images, pods, volumes, PKI)"
fi

echo "Done."
