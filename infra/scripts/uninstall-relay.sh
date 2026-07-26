#!/usr/bin/env bash
# uninstall-relay.sh — cleanly remove a Gotham mixnet relay installed by
# install-relay.sh on Linux (systemd unit + /opt/gotham + config + firewall
# rule + gotham system user). Reverses exactly what the installer created.
#
# USAGE (run as root):
#   curl -fsSL https://raw.githubusercontent.com/0x9Angel/gotham-relay/main/infra/scripts/uninstall-relay.sh | sudo bash
# or, from a clone:
#   sudo bash infra/scripts/uninstall-relay.sh
#
# By default this removes EVERYTHING, including the relay identity key — so a
# later reinstall gets a NEW public key. To keep the key + system user for a
# later reinstall with the SAME identity, run with:
#   GOTHAM_KEEP_KEYS=1 ... | sudo -E bash
#
# It intentionally does NOT touch your SSH firewall rule, nor disable ufw /
# firewalld itself — only the relay's own UDP rule is removed.
set -euo pipefail

KEEP_KEYS="${GOTHAM_KEEP_KEYS:-0}"

SERVICE=crypto-gotham-relay.service
UNIT=/etc/systemd/system/crypto-gotham-relay.service
INSTALL_DIR=/opt/gotham
STATE_DIR="$INSTALL_DIR/state"
KEYFILE="$STATE_DIR/relay.key"
ENVFILE=/etc/gotham/relay.env
LOG_DIR=/var/log/gotham
RELAY_USER=gotham

[[ "$(id -u)" -eq 0 ]] || { echo "Run as root: sudo bash $0"; exit 1; }

# Learn the advertised UDP port (used only for the firewalld path; the ufw path
# matches our rule's comment tag, not the port). Prefer an explicit override,
# else read relay.env; keep digits only so a quoted value or CRLF cannot corrupt
# it. If it stays empty we cannot know the port, and firewalld removal is skipped
# with a warning rather than deleting a wrong 443/udp rule.
PORT="${GOTHAM_PORT:-}"
if [[ -z "$PORT" && -f "$ENVFILE" ]]; then
    PORT="$(sed -n 's/^GOTHAM_PORT=//p' "$ENVFILE" | head -n1)"
fi
PORT="${PORT//[^0-9]/}"

echo "[1/5] Stopping + disabling the service..."
systemctl disable --now "$SERVICE" 2>/dev/null || true

echo "[2/5] Removing the systemd unit..."
rm -f "$UNIT"
systemctl daemon-reload 2>/dev/null || true
systemctl reset-failed "$SERVICE" 2>/dev/null || true

echo "[3/5] Removing the relay's own firewall rule (SSH + firewall left intact)..."
if command -v ufw &>/dev/null; then
    # Delete ONLY rules carrying our comment tag, addressed by number (highest
    # first so deleting one does not renumber the rest). If the port was already
    # allowed by another service, ufw kept THAT rule (with its own comment) when
    # the installer ran, so matching our tag never removes an unrelated rule.
    removed=0
    while n="$(ufw status numbered 2>/dev/null | grep -F 'Gotham QUIC relay' | grep -oE '^\[ *[0-9]+' | grep -oE '[0-9]+' | sort -rn | head -n1)"; [[ -n "$n" ]]; do
        ufw --force delete "$n" >/dev/null 2>&1 || break
        removed=1
    done
    # Fallback for older installs whose rule carried no comment tag.
    if [[ "$removed" -eq 0 && -n "$PORT" ]]; then ufw delete allow "$PORT"/udp >/dev/null 2>&1 || true; fi
elif command -v firewall-cmd &>/dev/null; then
    if [[ -n "$PORT" ]]; then
        firewall-cmd --permanent --remove-port="$PORT"/udp >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null 2>&1 || true
    else
        echo "    (relay UDP port unknown — leaving firewalld untouched; remove it manually:"
        echo "     firewall-cmd --permanent --remove-port=<PORT>/udp && firewall-cmd --reload)"
    fi
fi

echo "[4/5] Removing binary, config, and logs..."
rm -f "$INSTALL_DIR/bin/gotham-relay"
rmdir "$INSTALL_DIR/bin" 2>/dev/null || true
rm -f "$ENVFILE"
rmdir /etc/gotham 2>/dev/null || true
rm -rf "$LOG_DIR"

if [[ "$KEEP_KEYS" == "1" ]]; then
    echo "[5/5] Keeping identity key + '$RELAY_USER' user (GOTHAM_KEEP_KEYS=1)."
    echo "      Preserved: $KEYFILE"
else
    echo "[5/5] Removing identity key + '$RELAY_USER' system user..."
    rm -rf "$INSTALL_DIR"          # includes state/relay.key
    # The installer ADOPTS a pre-existing '$RELAY_USER' account (it only runs
    # useradd when absent), so deleting unconditionally could destroy an
    # unrelated user (a human login or another service). Only remove it when it
    # looks installer-created: a system UID (<1000) with a nologin shell.
    if id "$RELAY_USER" &>/dev/null; then
        uid="$(id -u "$RELAY_USER" 2>/dev/null || echo 100000)"
        shell="$(getent passwd "$RELAY_USER" | cut -d: -f7)"
        case "$shell" in /usr/sbin/nologin|/sbin/nologin|/usr/bin/nologin|/bin/false) nologin=1 ;; *) nologin=0 ;; esac
        if [[ "$uid" -lt 1000 && "$nologin" -eq 1 ]]; then
            userdel "$RELAY_USER" 2>/dev/null || true
        else
            echo "      Left '$RELAY_USER' intact — not installer-created (uid=$uid shell=$shell)."
        fi
    fi
fi

echo
echo "============================================================"
echo " Gotham relay UNINSTALLED."
if [[ "$KEEP_KEYS" == "1" ]]; then
    echo " Identity key kept at $KEYFILE (a reinstall reuses it)."
else
    echo " Everything removed, including the identity key."
fi
echo " Left intact: your SSH rule and ufw/firewalld itself."
echo "============================================================"
