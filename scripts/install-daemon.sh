#!/usr/bin/env bash
# Install rustypodsd as a root systemd service. Run with sudo from anywhere
# after `bash scripts/build.sh` produced the release binaries.
#
# Usage: scripts/install-daemon.sh [--user NAME] [--skip-packages] [--install-polkit] [--dry-run]
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

USER_NAME=""
SKIP_PACKAGES=0
INSTALL_POLKIT=0
DRY_RUN=0
TMP_FILES=()
BACKUP_DIR=""
MUTATED=0
SUCCESS=0
WAS_ACTIVE=0
WAS_ENABLED=0
declare -a MANAGED=()
declare -a MGMT_BACKUP=()

die() { echo "error: $*" >&2; exit 1; }

# Restore managed files + service state after a failed install. Runs under
# the EXIT trap's original status; best effort, so set +e. Package-manager
# changes and data dirs are never rolled back.
perform_rollback() {
  set +e
  echo "==> install failed — rolling back managed files" >&2
  local i t b
  for i in "${!MANAGED[@]}"; do
    t="${MANAGED[$i]}"
    b="${MGMT_BACKUP[$i]:-}"
    rm -f "$t"
    if [[ -n "$b" && -e "$b" ]]; then
      cp -a "$b" "$t"
    fi
  done
  systemctl daemon-reload
  if [[ $WAS_ACTIVE -eq 1 ]]; then
    systemctl restart rustypodsd
  else
    systemctl stop rustypodsd
  fi
  if [[ $WAS_ENABLED -eq 0 ]]; then
    systemctl disable rustypodsd
  fi
  echo "==> rollback complete — re-run the installer to retry" >&2
}

on_exit() {
  local rc=$?
  if [[ $rc -ne 0 && $MUTATED -eq 1 && $SUCCESS -eq 0 ]]; then
    perform_rollback
  fi
  if [[ ${#TMP_FILES[@]} -gt 0 ]]; then
    rm -f "${TMP_FILES[@]}"
  fi
  if [[ -n "$BACKUP_DIR" ]]; then
    rm -rf "$BACKUP_DIR"
  fi
  exit "$rc"
}
trap on_exit EXIT

usage() {
  cat >&2 <<'EOF'
Usage: scripts/install-daemon.sh [--user NAME] [--skip-packages] [--install-polkit] [--dry-run]
  --user NAME        host user allowed to drive the daemon (default: SUDO_USER,
                     else the single uid 1000-59999 account with a login shell)
  --skip-packages    do not touch the system package manager
  --install-polkit   install the optional polkit rule — only needed for direct
                     machinectl use; normal rustypods RPC does not need it
  --dry-run          print everything that would happen, change nothing
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --user)
      [[ $# -ge 2 ]] || die "--user requires a value"
      USER_NAME="$2"
      shift 2
      ;;
    --skip-packages) SKIP_PACKAGES=1; shift ;;
    --install-polkit) INSTALL_POLKIT=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage; die "unknown argument: $1" ;;
  esac
done

# ── distro family → package install command ──────────────────────────────
# os_value KEY FILE: print the value of literal KEY=... records from an
# os-release-style file. Never source/eval it — it's a root installer and
# the file is data, not code.
os_value() {
  local want="$1" file="$2" k v
  [[ -r "$file" ]] || return 1
  while IFS='=' read -r k v; do
    [[ "$k" == "$want" ]] || continue
    # Strip ONE matching outer quote pair ("..." or '...').
    case "$v" in
      \"*\") v="${v#\"}"; v="${v%\"}" ;;
      \'*\') v="${v#\'}"; v="${v%\'}" ;;
    esac
    printf '%s\n' "$v"
    return 0
  done < "$file"
  return 1
}

# Echoes debian|fedora|arch, or nothing (return 1) when unsupported.
detect_family() {
  local os_release="${RUSTYPODS_OS_RELEASE:-/etc/os-release}"
  local id="" like="" w
  id="$(os_value ID "$os_release" || true)"
  like="$(os_value ID_LIKE "$os_release" || true)"
  case "$id" in
    debian|ubuntu|linuxmint|mint|pop|neon|raspbian|kali) echo debian; return 0 ;;
    fedora|rhel|centos|almalinux|rocky|rockylinux|ol) echo fedora; return 0 ;;
    arch|manjaro|endeavouros|archarm|cachyos) echo arch; return 0 ;;
  esac
  local -a like_words=()
  read -r -a like_words <<< "$like"
  for w in "${like_words[@]}"; do
    case "$w" in
      debian|ubuntu) echo debian; return 0 ;;
      fedora|rhel|centos) echo fedora; return 0 ;;
      arch) echo arch; return 0 ;;
    esac
  done
  return 1
}

# run_cmd: print the exact argv (shell-escaped), then execute it — dry-run
# prints only. One code path for both modes keeps them identical.
run_cmd() {
  printf '    $'
  printf ' %q' "$@"
  printf '\n'
  if [[ $DRY_RUN -eq 0 ]]; then
    "$@"
  fi
}

# The package manager invocations for a detected family.
run_package_steps() {
  case "$FAMILY" in
    debian)
      run_cmd apt-get update
      run_cmd apt-get install -y systemd-container nftables iproute2 util-linux btrfs-progs socat
      ;;
    fedora)
      run_cmd dnf install -y systemd-container nftables iproute util-linux btrfs-progs socat
      ;;
    arch)
      # -S --needed, never -Sy: a bare -Sy refreshes the db without syncing
      # packages → partial-upgrade hazard on a stale system.
      run_cmd pacman -S --needed --noconfirm systemd nftables iproute2 util-linux btrfs-progs socat
      ;;
    *) die "internal: no package steps for family '$FAMILY'" ;;
  esac
}

# ── target user resolution ───────────────────────────────────────────────
resolve_user() {
  if [[ -n "$USER_NAME" ]]; then
    echo "$USER_NAME"
    return 0
  fi
  if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
    echo "$SUDO_USER"
    return 0
  fi
  # Fallback: exactly one human account (uid 1000-59999, real login shell).
  local candidates=()
  local name uid shell
  while IFS=: read -r name _ uid _ _ _ shell; do
    [[ "$uid" =~ ^[0-9]+$ ]] || continue
    (( uid >= 1000 && uid <= 59999 )) || continue
    case "$shell" in
      */nologin|*/false|nologin|false|"") continue ;;
    esac
    candidates+=("$name")
  done < <(getent passwd)
  if [[ ${#candidates[@]} -eq 1 ]]; then
    echo "${candidates[0]}"
    return 0
  fi
  return 1
}

# ── preconditions ────────────────────────────────────────────────────────
if [[ $DRY_RUN -eq 0 && $EUID -ne 0 ]]; then
  die "run as root: sudo bash scripts/install-daemon.sh (or --dry-run)"
fi

USER_NAME="$(resolve_user)" || die \
  "cannot pick a target user automatically — pass --user NAME"
[[ "$USER_NAME" != "root" ]] || die "target user must not be root"
[[ "$USER_NAME" =~ ^[a-z_][a-z0-9_-]*[$]?$ ]] \
  || die "invalid user name: $USER_NAME"
TARGET_UID="$(id -u "$USER_NAME" 2>/dev/null)" \
  || die "user $USER_NAME does not exist"
[[ "$TARGET_UID" =~ ^[0-9]+$ && $TARGET_UID -gt 0 ]] \
  || die "user $USER_NAME has non-positive/invalid uid"

MISSING=()
for b in rustypodsd rustypods rustypods-agent; do
  [[ -x "$REPO_ROOT/target/release/$b" ]] || MISSING+=("$b")
done
if [[ ${#MISSING[@]} -gt 0 ]]; then
  die "missing build artifacts: ${MISSING[*]} — run scripts/build.sh first"
fi

FAMILY=""
if [[ $SKIP_PACKAGES -eq 0 ]]; then
  FAMILY="$(detect_family)" || die \
    "unsupported distro (see /etc/os-release) — install the packages listed \
in the README manually, then re-run with --skip-packages"
fi

UNIT_DST=/etc/systemd/system/rustypodsd.service
ENV_DST=/etc/rustypods/daemon.env
POLKIT_DST=/etc/polkit-1/rules.d/49-rustypods.rules
# Every file the install may overwrite — backed up before first mutation.
MANAGED=(/usr/local/bin/rustypodsd /usr/local/bin/rustypods \
         /var/lib/rustypods/bin/rustypods-agent "$UNIT_DST" "$ENV_DST")
if [[ $INSTALL_POLKIT -eq 1 ]]; then
  MANAGED+=("$POLKIT_DST")
fi
DATA_DIRS=(/var/lib/rustypods/images /var/lib/rustypods/pods \
           /var/lib/rustypods/logs /var/lib/rustypods/bin \
           /var/lib/rustypods/conf /var/lib/rustypods/conf/pods \
           /var/lib/rustypods/conf/images /var/lib/rustypods/snapshots)

# ── dry run ──────────────────────────────────────────────────────────────
if [[ $DRY_RUN -eq 1 ]]; then
  echo "==> dry run — nothing will be changed"
  echo "    repo root:     $REPO_ROOT"
  if [[ $SKIP_PACKAGES -eq 1 ]]; then
    echo "    distro family: (skipped — --skip-packages)"
    echo "    packages:      skipped"
  else
    echo "    distro family: $FAMILY"
    echo "    package steps:"
    run_package_steps
  fi
  echo "    user:          $USER_NAME (uid $TARGET_UID)"
  echo "    binaries:      install -Dm755 target/release/{rustypodsd,rustypods} → /usr/local/bin/"
  echo "                   install -Dm755 target/release/rustypods-agent → /var/lib/rustypods/bin/"
  printf '    data dirs:     %s\n' "${DATA_DIRS[*]}"
  echo "    unit:          deploy/rustypodsd.service → $UNIT_DST"
  echo "    env file:      $ENV_DST → RUSTYPODS_ALLOWED_UID=$TARGET_UID"
  if [[ $INSTALL_POLKIT -eq 1 ]]; then
    echo "    polkit:        deploy/49-rustypods.rules → $POLKIT_DST (user=$USER_NAME)"
  else
    echo "    polkit:        skipped (not needed for rustypods RPC; --install-polkit to install)"
  fi
  echo "    then:          systemctl daemon-reload; enable; restart; rustypods doctor"
  echo "    rollback:      managed files restored if service/doctor verification fails"
  exit 0
fi

# ── packages ─────────────────────────────────────────────────────────────
if [[ $SKIP_PACKAGES -eq 0 ]]; then
  echo "==> [1/6] packages ($FAMILY)"
  run_package_steps
else
  echo "==> [1/6] packages — skipped (--skip-packages)"
fi

# ── binaries ─────────────────────────────────────────────────────────────
echo "==> [2/6] binaries"
# Snapshot managed files + service state BEFORE the first mutation — a
# failed install (e.g. doctor FAILs) restores exactly this state.
BACKUP_DIR="$(mktemp -d)"
chmod 0700 "$BACKUP_DIR"
if systemctl is-active --quiet rustypodsd; then WAS_ACTIVE=1; fi
if systemctl is-enabled --quiet rustypodsd; then WAS_ENABLED=1; fi
for i in "${!MANAGED[@]}"; do
  if [[ -e "${MANAGED[$i]}" || -L "${MANAGED[$i]}" ]]; then
    cp -a "${MANAGED[$i]}" "$BACKUP_DIR/$i"
    MGMT_BACKUP[$i]="$BACKUP_DIR/$i"
  else
    MGMT_BACKUP[$i]=""
  fi
done
MUTATED=1
install -Dm755 "$REPO_ROOT/target/release/rustypodsd" /usr/local/bin/rustypodsd
install -Dm755 "$REPO_ROOT/target/release/rustypods" /usr/local/bin/rustypods
install -Dm755 "$REPO_ROOT/target/release/rustypods-agent" /var/lib/rustypods/bin/rustypods-agent

# ── data dirs ────────────────────────────────────────────────────────────
echo "==> [3/6] data dirs (btrfs CoW lives here)"
install -d -m0755 "${DATA_DIRS[@]}"

# ── unit + env ───────────────────────────────────────────────────────────
echo "==> [4/6] systemd unit + daemon env (allowed uid $TARGET_UID = $USER_NAME)"
install -Dm644 "$REPO_ROOT/deploy/rustypodsd.service" "$UNIT_DST"
env_tmp="$(mktemp)"; TMP_FILES+=("$env_tmp")
printf 'RUSTYPODS_ALLOWED_UID=%s\n' "$TARGET_UID" > "$env_tmp"
install -Dm644 "$env_tmp" "$ENV_DST"

# ── polkit (opt-in) ──────────────────────────────────────────────────────
echo "==> [5/6] polkit"
if [[ $INSTALL_POLKIT -eq 1 ]]; then
  polkit_tmp="$(mktemp)"; TMP_FILES+=("$polkit_tmp")
  sed "s/@RUSTYPODS_USER@/$USER_NAME/g" \
    "$REPO_ROOT/deploy/49-rustypods.rules" > "$polkit_tmp"
  install -Dm644 "$polkit_tmp" "$POLKIT_DST"
  echo "    installed $POLKIT_DST (direct machinectl for $USER_NAME)"
else
  echo "    skipped — not needed for rustypods RPC (use --install-polkit for raw machinectl)"
fi

# ── enable + verify ──────────────────────────────────────────────────────
echo "==> [6/6] enable + start"
systemctl daemon-reload
systemctl enable rustypodsd
systemctl restart rustypodsd
active=0
for _ in $(seq 1 20); do
  if systemctl is-active --quiet rustypodsd; then active=1; break; fi
  sleep 0.5
done
if [[ $active -eq 0 ]]; then
  systemctl status rustypodsd --no-pager || true
  journalctl -u rustypodsd -n 30 --no-pager || true
  die "rustypodsd did not come up — see status/journal above"
fi
echo "    rustypodsd is active"
echo
echo "==> doctor"
/usr/local/bin/rustypods doctor
SUCCESS=1

echo
echo "Done. Next steps:"
echo "  rustypods pull busybox:latest"
echo "  rustypods create test --image busybox-latest"
echo "  rustypods start test"
echo "  rustypods shell test"
