#!/usr/bin/env bash
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
    removed=0
    while n="$(ufw status numbered 2>/dev/null | grep -F 'Gotham QUIC relay' | grep -oE '^\[ *[0-9]+' | grep -oE '[0-9]+' | sort -rn | head -n1)"; [[ -n "$n" ]]; do
        ufw --force delete "$n" >/dev/null 2>&1 || break
        removed=1
    done
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
    rm -rf "$INSTALL_DIR"
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
