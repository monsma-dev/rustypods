#!/usr/bin/env bash
# Install rustypodsd as a root systemd service. Run with sudo from the repo root
# after `bash scripts/build.sh` produced release binaries.
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ $EUID -ne 0 ]]; then
  echo "Run with sudo:  sudo bash scripts/install-daemon.sh" >&2
  exit 1
fi

echo "==> [1/5] systemd-container (nspawn + machinectl + machined)"
apt-get install -y systemd-container

echo "==> [2/5] binaries"
install -Dm755 target/release/rustypodsd /usr/local/bin/rustypodsd
install -Dm755 target/release/rustypods /usr/local/bin/rustypods
install -Dm755 target/release/rustypods-agent /var/lib/rustypods/bin/rustypods-agent

echo "==> [3/5] data dirs (btrfs CoW lives here)"
mkdir -p /var/lib/rustypods/{images,pods,logs,shm}

echo "==> [4/5] systemd unit + polkit rule (nick may manage machines)"
install -Dm644 deploy/rustypodsd.service /etc/systemd/system/rustypodsd.service
install -Dm644 deploy/49-rustypods.rules /etc/polkit-1/rules.d/49-rustypods.rules

echo "==> [5/5] enable + start"
systemctl daemon-reload
systemctl enable --now rustypodsd
sleep 1
systemctl status rustypodsd --no-pager | head -5 || true

echo
echo "Klaar. Test:"
echo "  rustypods ping"
echo "  rustypods import --from-distrobox arch"
echo "  rustypods create dev --image arch-base"
echo "  rustypods start dev --memory-high 10G --memory-max 12G"
echo "  rustypods shell dev"
