#!/usr/bin/env bash

set -euo pipefail

AUTHORITY_URL="${GOTHAM_AUTHORITY_URL:-http://144.24.205.188:8443}"
EXTRA_AUTHORITY_URLS="${GOTHAM_EXTRA_AUTHORITY_URLS:-http://84.235.232.196:8443 http://84.235.228.107:8443}"
TIER="${GOTHAM_TIER:-mix}"
PORT="${GOTHAM_PORT:-443}"
COUNTRY="${GOTHAM_COUNTRY:-}"
OPERATOR="${GOTHAM_OPERATOR:-}"
ENROLL_TOKEN="${GOTHAM_ENROLL_TOKEN:-}"

REPO="0x9Angel/gotham-relay"
case "$(uname -m)" in
  x86_64|amd64)  ASSET="gotham-relay-linux-x86_64" ;;
  aarch64|arm64) ASSET="gotham-relay-linux-aarch64" ;;
  *) echo "[!] unsupported CPU arch: $(uname -m). Build from source (see docs/gotham/README.md)."; exit 1 ;;
esac
INSTALL_DIR=/opt/gotham
BIN="$INSTALL_DIR/bin/gotham-relay"
STATE_DIR="$INSTALL_DIR/state"
KEYFILE="$STATE_DIR/relay.key"
ENVFILE=/etc/gotham/relay.env
LOG_DIR=/var/log/gotham
RELAY_USER=gotham

[[ "$(id -u)" -eq 0 ]] || { echo "Run as root: sudo bash $0"; exit 1; }
case "$TIER" in entry|mix|exit) ;; *) echo "[!] GOTHAM_TIER must be entry|mix|exit (got '$TIER')"; exit 1;; esac
if [[ -z "$OPERATOR" ]]; then
    echo "[!] GOTHAM_OPERATOR is required and was not set."
    echo
    echo "    Clients refuse to build a path through two relays unless they can"
    echo "    prove the relays belong to DIFFERENT operators, and a relay with no"
    echo "    operator label counts as unproven. An unlabelled relay would run,"
    echo "    report itself healthy, and never carry a single packet."
    echo
    echo "    Re-run with a public nickname, e.g.:"
    echo "      sudo GOTHAM_OPERATOR=your-name bash $0"
    echo
    echo "    Use the SAME value on every relay you run, so the network can tell"
    echo "    your machines apart from everyone else's."
    exit 1
fi
[[ "$OPERATOR" =~ ^[A-Za-z0-9._-]{1,32}$ ]] || {
    echo "[!] GOTHAM_OPERATOR must be 1 to 32 characters from A-Z a-z 0-9 . _ -"
    echo "    (got '$OPERATOR')"
    exit 1
}
echo "[1/7] Installing dependencies..."
if command -v apt-get &>/dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -qq -y --no-install-recommends curl ca-certificates ufw libcap2-bin
elif command -v pacman &>/dev/null; then
    pacman -Sy --needed --noconfirm curl ca-certificates libcap >/dev/null
elif command -v dnf &>/dev/null; then
    dnf install -y -q curl ca-certificates libcap >/dev/null
elif command -v zypper &>/dev/null; then
    zypper --non-interactive install -y curl ca-certificates libcap-progs >/dev/null
else
    echo "[!] No supported package manager (apt/pacman/dnf/zypper). Install curl + libcap"
    echo "    manually, then re-run. (systemd is required for the service.)"
    exit 1
fi

echo "[2/7] Creating $RELAY_USER system user..."
id "$RELAY_USER" &>/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin "$RELAY_USER"

echo "[3/7] Downloading + verifying $ASSET (latest release)..."
mkdir -p "$INSTALL_DIR/bin" "$STATE_DIR" "$(dirname "$ENVFILE")" "$LOG_DIR"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
base="https://github.com/$REPO/releases/latest/download"
curl -fsSL "$base/$ASSET"        -o "$TMP/$ASSET"
curl -fsSL "$base/$ASSET.sha256" -o "$TMP/$ASSET.sha256"
( cd "$TMP" && sha256sum -c "$ASSET.sha256" ) || { echo "[!] Checksum verification FAILED — refusing to install."; exit 1; }
install -m 0755 -o root -g root "$TMP/$ASSET" "$BIN"
if [[ "$PORT" -lt 1024 ]]; then setcap 'cap_net_bind_service=+ep' "$BIN"; fi

echo "[4/7] Generating relay identity (if absent)..."
chown -R "$RELAY_USER:$RELAY_USER" "$STATE_DIR" "$LOG_DIR"
[[ -f "$KEYFILE" ]] || sudo -u "$RELAY_USER" "$BIN" keygen --key-file "$KEYFILE"
PUBKEY="$(sudo -u "$RELAY_USER" "$BIN" pubkey --key-file "$KEYFILE")"

echo "[5/7] Determining reachability (direct vs rendezvous)..."
ADVERTISE_IP="${GOTHAM_ADVERTISE_IP:-$(curl -fsSL --max-time 8 https://api.ipify.org || true)}"

EXTRA=""
[[ -n "$COUNTRY"  ]] && EXTRA+=" --country $COUNTRY"
EXTRA+=" --operator $OPERATOR"
for u in $EXTRA_AUTHORITY_URLS; do
  EXTRA+=" --extra-authority-url $u"
done

MODE="direct"
case "${GOTHAM_RENDEZVOUS:-auto}" in
  on|1|true)   MODE="rendezvous" ;;
  off|0|false) MODE="direct" ;;
  *)
    if [[ -n "${GOTHAM_ADVERTISE_IP:-}" ]]; then
        MODE="direct"
    elif [[ -n "$ADVERTISE_IP" ]] && { ip -o addr show 2>/dev/null || ifconfig 2>/dev/null; } | grep -qw "$ADVERTISE_IP"; then
        MODE="direct"
    else
        MODE="rendezvous"
    fi ;;
esac

pick_rendezvous() {
    DIR_JSON="$(curl -fsSL --max-time 10 "$AUTHORITY_URL/directory" || true)"
    R_LINE="$(printf '%s' "$DIR_JSON" | tr '{' '\n' | grep '"rendezvous_capable":true' | head -1)"
    R_KEM="$(printf '%s'  "$R_LINE" | sed -n 's/.*"kem_pubkey_hex":"\([0-9a-fA-F]\{64\}\)".*/\1/p')"
    R_ADDR="$(printf '%s' "$R_LINE" | sed -n 's/.*"addr":"\([0-9.:]\{7,\}\)".*/\1/p')"
    [[ -n "$R_KEM" && -n "$R_ADDR" ]]
}

if [[ "$MODE" == "rendezvous" ]]; then
    echo "    No reachable public address — enrolling via a RENDEZVOUS point"
    echo "    (RFC B3: works behind CGNAT / mobile 4G-5G / broken UPnP, no port-forward)."
    if ! pick_rendezvous; then
        echo "[!] No rendezvous point is currently available from $AUTHORITY_URL."
        echo "    An operator must run a public relay with --rendezvous-capable, OR"
        echo "    set GOTHAM_ADVERTISE_IP=<reachable.ip> if you CAN port-forward UDP $PORT."
        exit 1
    fi
    echo "    Rendezvous relay: $R_ADDR"
    EXTRA+=" --rendezvous-key $R_KEM --rendezvous-addr $R_ADDR"
    ADVERTISE_ADDR="${ADVERTISE_IP:-127.0.0.1}:$PORT"
else
    [[ -n "$ADVERTISE_IP" ]] || { echo "[!] Could not auto-detect a public IP. Re-run with GOTHAM_ADVERTISE_IP=<your.public.ip>, or GOTHAM_RENDEZVOUS=on to use a rendezvous point."; exit 1; }
    echo "    Directly reachable — advertising $ADVERTISE_IP:$PORT/udp."
    ADVERTISE_ADDR="$ADVERTISE_IP:$PORT"
fi

cat > "$ENVFILE" <<EOF
GOTHAM_ENROLL_TOKEN=$ENROLL_TOKEN
GOTHAM_AUTHORITY_URL=$AUTHORITY_URL
GOTHAM_ADVERTISE_ADDR=$ADVERTISE_ADDR
GOTHAM_PORT=$PORT
GOTHAM_TIER=$TIER
GOTHAM_EXTRA_ARGS=$EXTRA
EOF
chown root:"$RELAY_USER" "$ENVFILE"
chmod 0640 "$ENVFILE"

echo "[6/7] Installing systemd unit + firewall..."
UNIT_SRC=""
for c in "$(dirname "$0")/../systemd/crypto-gotham-relay.service" /tmp/crypto-src/infra/systemd/crypto-gotham-relay.service; do
    [[ -f "$c" ]] && UNIT_SRC="$c" && break
done
if [[ -n "$UNIT_SRC" ]]; then
    install -m 0644 "$UNIT_SRC" /etc/systemd/system/crypto-gotham-relay.service
else
    curl -fsSL "https://raw.githubusercontent.com/$REPO/main/infra/systemd/crypto-gotham-relay.service" \
        -o /etc/systemd/system/crypto-gotham-relay.service
fi
if [[ "$MODE" == "direct" ]]; then
    if command -v ufw &>/dev/null; then
        ufw allow 22/tcp comment 'SSH' >/dev/null 2>&1 || true
        ufw allow "$PORT"/udp comment 'Gotham QUIC relay' >/dev/null 2>&1 || true
        yes | ufw enable >/dev/null 2>&1 || true
    elif command -v firewall-cmd &>/dev/null; then
        firewall-cmd --permanent --add-port="$PORT"/udp >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null 2>&1 || true
    else
        echo "    (no ufw/firewalld detected — make sure UDP $PORT is open in your firewall)"
    fi
else
    echo "    Rendezvous mode: outbound-only, no inbound firewall rule needed."
fi
LR_SRC=""
for c in "$(dirname "$0")/../logrotate/gotham-relay" /tmp/crypto-src/infra/logrotate/gotham-relay; do
    [[ -f "$c" ]] && LR_SRC="$c" && break
done
if [[ -n "$LR_SRC" ]]; then
    install -m 0644 "$LR_SRC" /etc/logrotate.d/gotham-relay
else
    curl -fsSL "https://raw.githubusercontent.com/$REPO/main/infra/logrotate/gotham-relay" \
        -o /etc/logrotate.d/gotham-relay 2>/dev/null || \
        echo "    (could not install logrotate config — rotate /var/log/gotham/relay.log yourself)"
fi

systemctl daemon-reload
systemctl enable --now crypto-gotham-relay.service

echo "[7/7] Waiting for the authority to accept enrollment..."
QUORUM_NEEDED="${GOTHAM_QUORUM_NEEDED:-2}"
ALL_AUTHORITIES="$AUTHORITY_URL $EXTRA_AUTHORITY_URLS"

count_attestations() {
    local n=0
    for a in $ALL_AUTHORITIES; do
        local d
        d="$(curl -fsSL --max-time 8 "$a/directory" 2>/dev/null || true)"
        printf '%s' "$d" | grep -qi "$PUBKEY" && n=$((n + 1))
    done
    printf '%s' "$n"
}

ENROLLED=0
SEEN_BY=0
for _ in $(seq 1 20); do
    sleep 5
    SEEN_BY="$(count_attestations)"
    if [[ "$SEEN_BY" -ge "$QUORUM_NEEDED" ]]; then ENROLLED=1; break; fi
    if grep -qi "invalid possession proof\|401 Unauthorized\|rejected: missing" "$LOG_DIR/relay.log" 2>/dev/null; then
        echo "    Authority refused this relay outright — see the cause below."
        break
    fi
done

if [[ "$ENROLLED" -eq 0 && "$MODE" == "direct" && "${GOTHAM_RENDEZVOUS:-auto}" != "off" ]]; then
    echo
    echo "[!] No authority could reach UDP $PORT on $ADVERTISE_IP."
    echo "    Switching to the rendezvous transport — no port-forward needed."
    if pick_rendezvous; then
        echo "    Rendezvous relay: $R_ADDR"
        MODE="rendezvous"
        EXTRA+=" --rendezvous-key $R_KEM --rendezvous-addr $R_ADDR"
        sed -i "s|^GOTHAM_EXTRA_ARGS=.*|GOTHAM_EXTRA_ARGS=$EXTRA|" "$ENVFILE"
        systemctl restart crypto-gotham-relay.service
        echo "    Re-enrolling…"
        for _ in $(seq 1 20); do
            sleep 5
            SEEN_BY="$(count_attestations)"
            if [[ "$SEEN_BY" -ge "$QUORUM_NEEDED" ]]; then ENROLLED=1; break; fi
        done
    else
        echo "    …but no rendezvous point is available right now, so this relay"
        echo "    cannot join until one comes back. Nothing else to do on your side."
    fi
fi

echo
echo "============================================================"
if [[ "$ENROLLED" -eq 1 ]]; then
    echo " Gotham relay is LIVE and ENROLLED ($SEEN_BY/$QUORUM_NEEDED authorities)"
else
    echo " Gotham relay installed — NOT usable by clients yet"
    echo " Attested by $SEEN_BY of the $QUORUM_NEEDED authorities required."
    if [[ "$SEEN_BY" -gt 0 ]]; then
        echo " It IS running and one authority sees it, but clients need a quorum,"
        echo " so no traffic will be routed through it until the others accept it."
    fi
    if [[ "$MODE" == "direct" ]]; then
        echo " Most common cause: UDP port $PORT is not reachable from the internet"
        echo " (router port-forward missing, or CGNAT). The authority must reach"
        echo " $ADVERTISE_ADDR/udp. If you are behind CGNAT / 4G-5G, re-run with"
        echo " GOTHAM_RENDEZVOUS=on to enrol via a rendezvous point instead."
    else
        echo " In rendezvous mode: check the rendezvous relay ${R_ADDR:-?} is up and"
        echo " that outbound UDP to it is not blocked. Logs: tail -F $LOG_DIR/relay.log"
    fi
fi
echo "============================================================"
echo " Public key : $PUBKEY"
if [[ "$MODE" == "direct" ]]; then
    echo " Advertised : $ADVERTISE_ADDR/udp   (tier: $TIER, direct)"
else
    echo " Reachable  : via rendezvous ${R_ADDR:-?}   (tier: $TIER, CGNAT/B3)"
fi
echo " Authority  : $AUTHORITY_URL"
echo " Also enrolled with: $EXTRA_AUTHORITY_URLS"
echo " Operator   : $OPERATOR   (a relay without a label is never routed)"
echo "------------------------------------------------------------"
echo " Check this relay at any time — it answers in plain language:"
echo "   sudo $BIN doctor --key-file $KEYFILE"
echo
echo " The relay also checks itself every 5 minutes and logs a warning if the"
echo " network stops using it, so a relay that breaks later does not go unnoticed:"
echo "   journalctl -u crypto-gotham-relay -f | grep SELF-CHECK"
echo
echo " Live logs  : tail -F $LOG_DIR/relay.log"
echo " Status     : systemctl status crypto-gotham-relay.service"
echo " Restart    : sudo systemctl restart crypto-gotham-relay.service"
echo " Uninstall  : curl -fsSL https://raw.githubusercontent.com/$REPO/main/infra/scripts/uninstall-relay.sh | sudo bash"
echo "============================================================"
