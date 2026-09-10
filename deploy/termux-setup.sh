#!/data/data/com.termux/files/usr/bin/bash
#
# WiFiGuard on Android, under Termux. No root required.
#
#   pkg install git
#   git clone https://github.com/mikeynator21/mikeynator21 wifiguard
#   bash wifiguard/deploy/termux-setup.sh
#
# What this gives you:
#
#   * A filtering resolver running on the phone itself, on port 5353.
#   * A second cluster node, so the network stays filtered when your laptop
#     sleeps -- the phone is always on, and it takes over automatically.
#
# What it cannot give you: port 53 and firewall rules need root on Android, so
# an unrooted phone cannot be a transparent gateway on its own. Point the
# phone's WireGuard profile at it instead -- see docs/phone.md.

set -euo pipefail

info() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m error:\033[0m %s\n' "$*" >&2; exit 1; }

command -v python >/dev/null || { info "installing python"; pkg install -y python; }

python - <<'PY' || die "Termux's Python is older than 3.11; run 'pkg upgrade' first"
import sys
raise SystemExit(0 if sys.version_info >= (3, 11) else 1)
PY

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFIX="$HOME/.wifiguard"
STATEDIR="$PREFIX/state"
mkdir -p "$PREFIX" "$STATEDIR"

info "installing to $PREFIX"
cp -r "$SOURCE_DIR/wifiguard" "$PREFIX/"
python -m compileall -q "$PREFIX/wifiguard"

BINDIR="$PREFIX/bin"
mkdir -p "$BINDIR"
cat > "$BINDIR/wifiguard" <<LAUNCHER
#!/data/data/com.termux/files/usr/bin/bash
export PYTHONPATH="$PREFIX:\${PYTHONPATH:-}"
export WIFIGUARD_STATE="$STATEDIR"
exec python -m wifiguard.cli "\$@"
LAUNCHER
chmod +x "$BINDIR/wifiguard"

if ! grep -q "$BINDIR" "$HOME/.bashrc" 2>/dev/null; then
    echo "export PATH=\"$BINDIR:\$PATH\"" >> "$HOME/.bashrc"
fi

CONFIG="$PREFIX/wifiguard.toml"
if [[ ! -f "$CONFIG" ]]; then
    info "writing $CONFIG"
    cat > "$CONFIG" <<'CONF'
# WiFiGuard on Android (Termux). Unprivileged, so the resolver runs on a high
# port rather than 53.
protection = "strict"
state_dir = "~/.wifiguard/state"

[server]
listen_addresses = ["127.0.0.1"]
port = 5353
workers = 8

[upstream]
servers = [
    "https://dns.quad9.net/dns-query",
    "https://dns.cloudflare.com/dns-query",
]
require_encrypted = true

[cache]
# A phone is bandwidth- and battery-sensitive, so hold answers longer.
min_ttl = 900
max_entries = 20000

[dashboard]
address = "127.0.0.1"
port = 8080

[logging]
# Query logs on a phone are both a privacy risk and a storage cost.
log_queries = false
retention_days = 1

# Uncomment to make this phone a second node that covers for the laptop.
# Use the same secret on both, and give the always-on phone the lower
# priority so it only answers when the laptop is not around.
#
# [cluster]
# enabled = true
# name = "phone"
# address = "10.9.0.3"        # this phone's VPN address
# peers = ["10.9.0.1"]        # the laptop
# priority = 40
# secret = "<wifiguard cluster secret>"
CONF
fi

info "running the self-test"
PYTHONPATH="$PREFIX" WIFIGUARD_STATE="$STATEDIR" python -m wifiguard.cli selftest --port 15353 | tail -4

cat <<NEXT

WiFiGuard is installed on this phone.

  Start it:      wifiguard -c $CONFIG run
  Keep it alive: termux-wake-lock   (before starting)
  Check it:      wifiguard -c $CONFIG status

Open a new Termux session, or run 'source ~/.bashrc', to get the command
on your PATH.

To keep it running after a reboot, install Termux:Boot and add:
  ~/.termux/boot/wifiguard  ->  termux-wake-lock && $BINDIR/wifiguard -c $CONFIG run
NEXT
