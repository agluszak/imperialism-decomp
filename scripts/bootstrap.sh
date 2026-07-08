#!/usr/bin/env bash
# Remote environment bootstrap for imperialism-decomp.
#
# One-time / from-scratch provisioning of a remote or sandbox host: system
# packages, just/uv/docker/bd, JDK 21, Ghidra 12.1.2 PUBLIC, the original game
# binary, repo-local config, and a first build + reccmp stats run.
#
# Assumes: repo already cloned and this is run from the repo root. Works either
# as root or as a normal user with passwordless sudo (Cursor Cloud runs as the
# unprivileged `ubuntu` user, so privileged steps go through sudo).
#
# NOTE: This is a *one-time bootstrap*, not the per-session update script. The
# lightweight per-session refresh is just `uv sync` (see AGENTS.md "Cursor Cloud
# specific instructions"); heavy/brittle steps (docker image build, Ghidra
# download, first build, bd init) belong here, run once, and persist in the VM
# snapshot.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GHIDRA_VERSION="12.1.2"
GHIDRA_TAG="Ghidra_${GHIDRA_VERSION}_build"
# Extract directly under /opt so the install dir is /opt/ghidra_<ver>_PUBLIC
# (the zip's own top-level dir); this reuses an existing install if present.
GHIDRA_PARENT_DIR="/opt"

# Google Drive file ID for Imperialism.exe.
# Original URL:
# https://drive.google.com/file/d/14UN0ebFHz7mjvkD-73x-kMwo84W3cR5C/view?usp=drive_link
IMPERIALISM_DRIVE_FILE_ID="14UN0ebFHz7mjvkD-73x-kMwo84W3cR5C"
IMPERIALISM_SHA256="6afab8495db715fd9e719cffa74abe5ede4dd763428ff65d73be4edf16c9e691"

log() { printf '\n=== %s ===\n' "$1"; }

# Privileged-command shim: no-op when already root, otherwise sudo.
if [ "$(id -u)" -eq 0 ]; then SUDO=""; else SUDO="sudo"; fi

# Make uv/bd (installed into ~/.local/bin) visible for the rest of this script.
export PATH="$HOME/.local/bin:$PATH"

# ---------------------------------------------------------------------------
# 1. System packages
# ---------------------------------------------------------------------------
log "apt packages"
export DEBIAN_FRONTEND=noninteractive

# Base image ships third-party PPAs whose release Label can change upstream;
# a plain `apt-get update` can hard-fail on that, so allow release-info changes.
$SUDO apt-get update -o Acquire::AllowReleaseInfoChange::Label=true \
                     -o Acquire::AllowReleaseInfoChange::Suite=true \
  || $SUDO apt-get update --allow-releaseinfo-change

$SUDO apt-get install -y --no-install-recommends \
  git git-lfs curl wget ca-certificates unzip p7zip-full \
  build-essential cmake ninja-build \
  python3 python3-pip python3-venv \
  openjdk-21-jdk \
  jq

# Wine is needed both by reccmp (it runs the Windows `cvdump.exe` to parse the
# recompiled PDB during compare/stats/roadmap) and by `just run`/`debug`/
# `screenshot`. 32-bit support is required for the 32-bit cvdump/game binaries.
$SUDO dpkg --add-architecture i386 || true
$SUDO apt-get update || true
$SUDO apt-get install -y --no-install-recommends wine wine32 wine64 \
  || $SUDO apt-get install -y --no-install-recommends wine \
  || echo "WARN: wine install failed; reccmp compare/stats and run/debug/screenshot won't work" >&2

$SUDO git lfs install --system

# If running as root against a repo owned by another user, git refuses to
# operate ("dubious ownership") — allow it explicitly.
git config --global --add safe.directory "$REPO_ROOT" 2>/dev/null || true

# ---------------------------------------------------------------------------
# 2. just
# ---------------------------------------------------------------------------
log "just"
if ! command -v just >/dev/null 2>&1; then
  JUST_VERSION="$(
    curl -sSf https://api.github.com/repos/casey/just/releases/latest \
      | jq -r .tag_name | sed 's/^v//'
  )"
  curl -Lo /tmp/just.tar.gz \
    "https://github.com/casey/just/releases/download/${JUST_VERSION}/just-${JUST_VERSION}-x86_64-unknown-linux-musl.tar.gz"
  $SUDO tar -xzf /tmp/just.tar.gz -C /usr/local/bin just
  $SUDO chmod +x /usr/local/bin/just
  rm -f /tmp/just.tar.gz
fi

# ---------------------------------------------------------------------------
# 3. uv
# ---------------------------------------------------------------------------
log "uv"
if ! command -v uv >/dev/null 2>&1; then
  curl -LsSf https://astral.sh/uv/install.sh | sh
  export PATH="$HOME/.local/bin:$PATH"
fi

# ---------------------------------------------------------------------------
# 4. Docker
# ---------------------------------------------------------------------------
log "docker"
if ! command -v docker >/dev/null 2>&1; then
  curl -fsSL https://get.docker.com | $SUDO sh
fi

# Docker-in-docker inside a Firecracker/microVM sandbox: the guest kernel does
# not support overlay2 or nftables, so use fuse-overlayfs + iptables-legacy.
# Harmless to skip on a normal host; only applied when the tools are present.
if [ ! -f /etc/docker/daemon.json ]; then
  $SUDO apt-get install -y --no-install-recommends fuse-overlayfs iptables 2>/dev/null || true
  $SUDO mkdir -p /etc/docker
  printf '{ "storage-driver": "fuse-overlayfs" }\n' | $SUDO tee /etc/docker/daemon.json >/dev/null
  $SUDO update-alternatives --set iptables /usr/sbin/iptables-legacy 2>/dev/null || true
  $SUDO update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy 2>/dev/null || true
fi

# Start the daemon (systemd may be absent in sandboxes) and wait until it is ready.
if ! docker info >/dev/null 2>&1 && ! $SUDO docker info >/dev/null 2>&1; then
  $SUDO service docker start 2>/dev/null \
    || ($SUDO sh -c 'nohup dockerd >/tmp/dockerd.log 2>&1 &') \
    || true
fi
for _ in $(seq 1 30); do
  if $SUDO docker info >/dev/null 2>&1; then break; fi
  sleep 2
done
$SUDO docker info >/dev/null 2>&1 || { echo "ERROR: docker daemon did not become ready" >&2; exit 1; }

# Let the current (non-root) user run bare `docker` (used by `just build`).
if [ "$(id -u)" -ne 0 ]; then
  $SUDO usermod -aG docker "$USER" 2>/dev/null || true
fi

# Run a docker-dependent `just` target with the docker group active even if the
# current shell predates the group change (no re-login needed).
run_just_docker() {
  if [ "$(id -u)" -eq 0 ] || id -nG | tr ' ' '\n' | grep -qx docker; then
    just "$@"
  else
    sg docker -c "just $*"
  fi
}

# ---------------------------------------------------------------------------
# 5. bd / beads (issue tracking; not required for build/compare)
# ---------------------------------------------------------------------------
log "bd (beads)"
if ! command -v bd >/dev/null 2>&1; then
  curl -sSL https://raw.githubusercontent.com/steveyegge/beads/main/scripts/install.sh | bash \
    || echo "WARN: bd install failed; issue tracking unavailable, build/compare unaffected" >&2
  export PATH="$HOME/.local/bin:$PATH"
fi

# ---------------------------------------------------------------------------
# 6. Ghidra 12.1.2 PUBLIC
# ---------------------------------------------------------------------------
log "Ghidra ${GHIDRA_VERSION} PUBLIC"
$SUDO mkdir -p "$GHIDRA_PARENT_DIR"

if [ -z "$(find "$GHIDRA_PARENT_DIR" -maxdepth 1 -iname "ghidra_${GHIDRA_VERSION}_PUBLIC" 2>/dev/null)" ]; then
  ASSET_URL="$(
    curl -sSf "https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/tags/${GHIDRA_TAG}" \
      | jq -r '.assets[] | select(.name | test("PUBLIC.*\\.zip$")) | .browser_download_url' \
      | head -n1
  )"
  if [ -z "$ASSET_URL" ]; then
    echo "ERROR: could not resolve Ghidra release asset for tag ${GHIDRA_TAG}" >&2
    exit 1
  fi
  curl -Lo /tmp/ghidra.zip "$ASSET_URL"
  $SUDO unzip -q /tmp/ghidra.zip -d "$GHIDRA_PARENT_DIR"
  rm -f /tmp/ghidra.zip
fi

GHIDRA_INSTALL_DIR="$(find "$GHIDRA_PARENT_DIR" -maxdepth 1 -iname "ghidra_${GHIDRA_VERSION}_PUBLIC" | head -n1)"
[ -n "$GHIDRA_INSTALL_DIR" ] || { echo "ERROR: Ghidra install dir not found under ${GHIDRA_PARENT_DIR}" >&2; exit 1; }

# ---------------------------------------------------------------------------
# 7. Original game binary from Google Drive
# ---------------------------------------------------------------------------
log "Imperialism.exe"
mkdir -p "$REPO_ROOT/orig"
ORIGINAL_EXE="$REPO_ROOT/orig/Imperialism.exe"

verify_sha() { [ "$(sha256sum "$1" 2>/dev/null | cut -d' ' -f1)" = "$IMPERIALISM_SHA256" ]; }

if ! verify_sha "$ORIGINAL_EXE"; then
  rm -f "$ORIGINAL_EXE"
  python3 -m pip install --break-system-packages -q --upgrade gdown 2>/dev/null \
    || python3 -m pip install -q --upgrade gdown
  TMP_EXE="$(mktemp)"
  # Passing the Drive file ID directly is supported by gdown's url_or_id argument.
  if ! python3 -m gdown "$IMPERIALISM_DRIVE_FILE_ID" -O "$TMP_EXE"; then
    rm -f "$TMP_EXE"
    echo "ERROR: failed to download Imperialism.exe from Google Drive (not public from here?)." >&2
    exit 1
  fi
  if ! verify_sha "$TMP_EXE"; then
    echo "ERROR: downloaded Imperialism.exe sha256 != ${IMPERIALISM_SHA256}." >&2
    echo "Drive may have returned an HTML error/quota page, or the wrong build." >&2
    rm -f "$TMP_EXE"
    exit 1
  fi
  mv "$TMP_EXE" "$ORIGINAL_EXE"
fi

# ---------------------------------------------------------------------------
# 8. Repo-local config
# ---------------------------------------------------------------------------
log ".env"
cd "$REPO_ROOT"
[ -f .env ] || cp .env.example .env
sed -i "s#^GHIDRA_INSTALL_DIR=.*#GHIDRA_INSTALL_DIR=${GHIDRA_INSTALL_DIR}#" .env
sed -i "s#^ORIGINAL_BINARY=.*#ORIGINAL_BINARY=\"${ORIGINAL_EXE}\"#" .env

# reccmp-user.yml (gitignored, machine-local): points reccmp at the original
# binary. `just bootstrap-reccmp` is ONLY for a machine that has never had a
# reccmp project — it refuses to overwrite the committed reccmp-project.yml this
# repo ships (docs/workflows.md §0), so write the user file directly instead.
log "reccmp-user.yml"
if [ ! -f reccmp-user.yml ]; then
  cat > reccmp-user.yml <<YAML
targets:
  IMPERIALISM:
    path: ${ORIGINAL_EXE}
YAML
fi

log "git lfs pull (vendored Ghidra project export)"
git lfs pull

log "uv sync"
uv sync

# ---------------------------------------------------------------------------
# 9. Project bootstrap
# ---------------------------------------------------------------------------
log "restore-project"
just restore-project

log "docker-build"
run_just_docker docker-build

log "bd init"
bd init || echo "WARN: bd init failed; issue tracking unavailable" >&2

log "tooling-check"
just tooling-check

log "first build + stats"
run_just_docker build
just detect
WINEDEBUG=-all just stats || true

log "done"
echo "Environment ready."
echo "GHIDRA_INSTALL_DIR=${GHIDRA_INSTALL_DIR}"
echo "ORIGINAL_BINARY=${ORIGINAL_EXE}"
