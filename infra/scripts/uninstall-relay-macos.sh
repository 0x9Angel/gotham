#!/usr/bin/env bash
# uninstall-relay-macos.sh — remove a Gotham mixnet relay installed by
# install-relay-macos.sh (launchd LaunchDaemon + /usr/local files).
#
#   curl -fsSL https://raw.githubusercontent.com/0x9Angel/gotham-relay/main/infra/scripts/uninstall-relay-macos.sh | sudo bash
#
# Default removes everything, including the identity key (a reinstall gets a
# NEW public key). Keep the key for a same-identity reinstall with:
#   GOTHAM_KEEP_KEYS=1 ... | sudo -E bash
set -euo pipefail

KEEP_KEYS="${GOTHAM_KEEP_KEYS:-0}"
BIN=/usr/local/bin/gotham-relay
STATE_DIR=/usr/local/var/gotham-relay
KEYFILE="$STATE_DIR/relay.key"
PLIST=/Library/LaunchDaemons/org.gotham.relay.plist
LABEL=org.gotham.relay

[[ "$(id -u)" -eq 0 ]] || { echo "Run with sudo: sudo bash $0"; exit 1; }

echo "[1/3] Stopping + unloading the LaunchDaemon ($LABEL)..."
launchctl bootout system "$PLIST" 2>/dev/null || launchctl bootout "system/$LABEL" 2>/dev/null || true
rm -f "$PLIST"

echo "[2/3] Removing the binary..."
rm -f "$BIN"

if [[ "$KEEP_KEYS" == "1" ]]; then
    echo "[3/3] Keeping identity key (GOTHAM_KEEP_KEYS=1): $KEYFILE"
    rm -f "$STATE_DIR/relay.log"
else
    echo "[3/3] Removing identity key + state..."
    rm -rf "$STATE_DIR"
fi

echo
echo "============================================================"
echo " Gotham relay UNINSTALLED (launchd: $LABEL)."
[[ "$KEEP_KEYS" == "1" ]] && echo " Identity key kept at $KEYFILE (a reinstall reuses it)."
echo
echo " If you disabled sleep for the relay, you can re-enable it:"
echo "   sudo pmset -c disablesleep 0 sleep 1"
echo "============================================================"
