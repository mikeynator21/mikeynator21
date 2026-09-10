#!/usr/bin/env bash
#
# WiFiGuard installer for Linux (Debian, Ubuntu, Raspberry Pi OS, Fedora, Arch).
#
#   curl -fsSL https://raw.githubusercontent.com/mikeynator21/wifiguard/main/install.sh | sudo bash
#
# or, from a clone:  sudo ./install.sh
#
# Installs to /opt/wifiguard, puts a launcher in /usr/local/bin, and sets up a
# systemd unit. It does not start filtering until you say so.

set -euo pipefail

PREFIX="${PREFIX:-/opt/wifiguard}"
BINDIR="${BINDIR:-/usr/local/bin}"
CONFDIR="${CONFDIR:-/etc/wifiguard}"
STATEDIR="${STATEDIR:-/var/lib/wifiguard}"
REPO="${REPO:-https://github.com/mikeynator21/wifiguard}"

info()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn()  { printf '\033[1;33m warning:\033[0m %s\n' "$*" >&2; }
die()   { printf '\033[1;31m error:\033[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run this with sudo: sudo $0"

# --- Python ------------------------------------------------------------------
PYTHON="$(command -v python3 || true)"
[[ -n "$PYTHON" ]] || die "python3 is not installed"
"$PYTHON" - <<'PY' || die "WiFiGuard needs Python 3.11 or newer (it uses tomllib)"
import sys
raise SystemExit(0 if sys.version_info >= (3, 11) else 1)
PY
info "using $("$PYTHON" --version)"

# --- optional system packages -------------------------------------------------
install_packages() {
    local packages=("$@")
    if command -v apt-get >/dev/null; then
        apt-get update -qq && apt-get install -y --no-install-recommends "${packages[@]}"
    elif command -v dnf >/dev/null; then
        dnf install -y "${packages[@]}"
    elif command -v pacman >/dev/null; then
        pacman -Sy --noconfirm "${packages[@]}"
    else
        warn "unknown package manager; install these yourself: ${packages[*]}"
        return 1
    fi
}

MISSING=()
command -v nft      >/dev/null || MISSING+=(nftables)
command -v hostapd  >/dev/null || MISSING+=(hostapd)
command -v wg       >/dev/null || MISSING+=(wireguard-tools)
command -v iw       >/dev/null || MISSING+=(iw)

if [[ ${#MISSING[@]} -gt 0 ]]; then
    info "installing: ${MISSING[*]}"
    install_packages "${MISSING[@]}" || warn "carry on without them; hotspot and VPN features need them"
    # Distributions ship hostapd masked; we start it ourselves, not via systemd.
    systemctl disable --now hostapd 2>/dev/null || true
fi

# --- source -------------------------------------------------------------------
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -d "$SOURCE_DIR/wifiguard" ]]; then
    info "installing from $SOURCE_DIR"
    mkdir -p "$PREFIX"
    cp -r "$SOURCE_DIR/wifiguard" "$PREFIX/"
    [[ -d "$SOURCE_DIR/deploy" ]] && cp -r "$SOURCE_DIR/deploy" "$PREFIX/"
else
    command -v git >/dev/null || die "git is needed to fetch the source"
    info "cloning $REPO"
    rm -rf "$PREFIX.tmp"
    git clone --depth 1 "$REPO" "$PREFIX.tmp"
    rm -rf "$PREFIX"
    mv "$PREFIX.tmp" "$PREFIX"
fi

"$PYTHON" -m compileall -q "$PREFIX/wifiguard"

# --- launcher -----------------------------------------------------------------
cat > "$BINDIR/wifiguard" <<LAUNCHER
#!/bin/sh
# WiFiGuard launcher, written by install.sh
exec ${PYTHON} -m wifiguard.cli "\$@"
LAUNCHER
sed -i "1a PYTHONPATH=\"${PREFIX}:\${PYTHONPATH}\"; export PYTHONPATH" "$BINDIR/wifiguard"
chmod +x "$BINDIR/wifiguard"

# --- directories and config ---------------------------------------------------
mkdir -p "$CONFDIR" "$STATEDIR"
chmod 700 "$STATEDIR"

if [[ ! -f "$CONFDIR/wifiguard.toml" ]]; then
    info "writing a starter config to $CONFDIR/wifiguard.toml"
    "$BINDIR/wifiguard" init-config > "$CONFDIR/wifiguard.toml"
    chmod 600 "$CONFDIR/wifiguard.toml"
else
    info "keeping the existing $CONFDIR/wifiguard.toml"
fi

# --- service ------------------------------------------------------------------
if command -v systemctl >/dev/null && [[ -f "$PREFIX/deploy/wifiguard.service" ]]; then
    install -m 644 "$PREFIX/deploy/wifiguard.service" /etc/systemd/system/wifiguard.service
    systemctl daemon-reload
    info "systemd unit installed (not enabled yet)"
fi

# --- verify -------------------------------------------------------------------
info "running the self-test"
if "$BINDIR/wifiguard" selftest --port 15353 >/tmp/wifiguard-selftest.log 2>&1; then
    tail -3 /tmp/wifiguard-selftest.log
else
    warn "the self-test reported problems; see /tmp/wifiguard-selftest.log"
fi

cat <<'NEXT'

WiFiGuard is installed.

  wifiguard doctor      check this machine is ready
  wifiguard selftest    verify the filtering works (no root needed)

To start filtering for this machine only:
  sudo systemctl enable --now wifiguard

Port 53 is usually held by systemd-resolved. If `doctor` says so:
  sudo systemctl disable --now systemd-resolved
  sudo rm -f /etc/resolv.conf
  echo 'nameserver 127.0.0.1' | sudo tee /etc/resolv.conf

To cover every device on your network, point your router's DHCP
"DNS server" setting at this machine's address.

To share this machine's connection as a filtered hotspot, or to reach
the filter from your phone anywhere, see docs/laptop-gateway.md and
docs/phone.md.
NEXT
