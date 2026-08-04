#!/usr/bin/env bash
# install-relay.sh — one-command, AUTONOMOUS Gotham mixnet relay installer.
#
# For volunteer relay operators on ANY Ubuntu/Debian host — a public VPS, a home
# box with a port-forward, OR a machine behind CGNAT / mobile 4G-5G / broken UPnP
# (it auto-falls back to RFC B3 rendezvous mode, keeping an OUTBOUND tunnel to a
# public rendezvous relay — no public IP or port-forward needed). No source
# build: it downloads the prebuilt, checksum-verified relay binary and wires up
# auto-enrollment so the relay joins the network on its own.
#
# USAGE (run as root) — no token needed, enrollment is open:
#   curl -fsSL https://raw.githubusercontent.com/0x9Angel/gotham-relay/main/infra/scripts/install-relay.sh | sudo bash
#
# or, after cloning the repo:
#   sudo bash infra/scripts/install-relay.sh
#
# CONFIG (environment variables — ALL OPTIONAL):
#   GOTHAM_ENROLL_TOKEN   Only if the authority runs in closed/token mode.
#                         Enrollment is OPEN by default — you do NOT need one.
#   GOTHAM_AUTHORITY_URL  Directory authority base URL.
#                         Default: http://144.24.205.188:8443
#   GOTHAM_TIER           entry | mix | exit. Default: mix
#                         (a middle hop sees neither sender nor recipient —
#                          the safest role for a volunteer).
#   GOTHAM_PORT           UDP listen + advertise port. Default: 443
#   GOTHAM_ADVERTISE_IP   Public IP peers reach you on. Default: auto-detected.
#                         Set this explicitly if you port-forward UDP behind NAT.
#   GOTHAM_RENDEZVOUS     auto | on | off. Default auto: use a rendezvous point
#                         (RFC B3) when no reachable public address is found —
#                         this is what lets a 4G/5G / CGNAT box be a relay.
#   GOTHAM_COUNTRY        ISO 3166-1 code to publish (e.g. FR). Optional.
#   GOTHAM_OPERATOR       REQUIRED. Public nickname identifying who runs this
#                         relay. Path selection refuses two hops it cannot prove
#                         belong to different operators, so an unlabelled relay
#                         is never selected. Use the SAME value on all yours.
#
# What it does:
#   1. Installs minimal deps (curl, ufw, ca-certificates)
#   2. Creates the `gotham` system user (no shell, no home)
#   3. Downloads + sha256-verifies the latest `gotham-relay-linux-x86_64`
#   4. Generates an X25519 identity key if one doesn't exist
#   5. Writes the relay config + installs a hardened systemd unit
#   6. Opens the firewall (SSH + your UDP port), starts the service
#   7. Waits and reports whether the authority accepted the enrollment

set -euo pipefail

# ─── Config + defaults ──────────────────────────────────────────────────
AUTHORITY_URL="${GOTHAM_AUTHORITY_URL:-http://144.24.205.188:8443}"
# Clients admit a relay only when k of n authorities have attested it (k=2,
# n=3 in the shipped app). Enrolling with the primary alone produced a relay
# that ran, reported itself healthy, and was DROPPED by every client — the
# installer even printed "LIVE and ENROLLED". Enrol with all three.
EXTRA_AUTHORITY_URLS="${GOTHAM_EXTRA_AUTHORITY_URLS:-http://84.235.232.196:8443 http://84.235.228.107:8443}"
TIER="${GOTHAM_TIER:-mix}"
PORT="${GOTHAM_PORT:-443}"
COUNTRY="${GOTHAM_COUNTRY:-}"
# Path selection refuses two hops it cannot PROVE belong to different
# operators, so a relay with no label can never be part of a route. Defaults to
# the hostname, which is at least stable and distinct per machine; operators
# running several relays should set GOTHAM_OPERATOR to the same value on all of
# them so diversity actually reflects who runs what.
OPERATOR="${GOTHAM_OPERATOR:-}"
if [[ -z "$OPERATOR" ]]; then
    echo "[!] GOTHAM_OPERATOR is required and was not set."
    echo
    echo "    It is a public nickname saying who runs this relay. Path selection"
    echo "    fails closed on operator diversity: two relays that cannot be PROVEN"
    echo "    to belong to different operators never share a path."
    echo
    echo "    This used to default to the hostname, which was worse than useless:"
    echo "    two machines run by the same person got two different labels and"
    echo "    counted as two independent operators, which is precisely the"
    echo "    property the rule exists to enforce. Use the SAME value on every"
    echo "    relay you run, and one nobody else is using."
    echo
    echo "    Example:  GOTHAM_OPERATOR=alice GOTHAM_TIER=exit sudo -E $0"
    exit 1
fi
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

# ─── Sanity checks ──────────────────────────────────────────────────────
[[ "$(id -u)" -eq 0 ]] || { echo "Run as root: sudo bash $0"; exit 1; }
case "$TIER" in entry|mix|exit) ;; *) echo "[!] GOTHAM_TIER must be entry|mix|exit (got '$TIER')"; exit 1;; esac
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
# UDP ports < 1024 need CAP_NET_BIND_SERVICE since we run unprivileged.
if [[ "$PORT" -lt 1024 ]]; then setcap 'cap_net_bind_service=+ep' "$BIN"; fi

echo "[4/7] Generating relay identity (if absent)..."
chown -R "$RELAY_USER:$RELAY_USER" "$STATE_DIR" "$LOG_DIR"
[[ -f "$KEYFILE" ]] || sudo -u "$RELAY_USER" "$BIN" keygen --key-file "$KEYFILE"
PUBKEY="$(sudo -u "$RELAY_USER" "$BIN" pubkey --key-file "$KEYFILE")"

echo "[5/7] Determining reachability (direct vs rendezvous)..."
ADVERTISE_IP="${GOTHAM_ADVERTISE_IP:-$(curl -fsSL --max-time 8 https://api.ipify.org || true)}"

EXTRA=""
[[ -n "$COUNTRY"  ]] && EXTRA+=" --country $COUNTRY"
if [[ -z "$OPERATOR" ]]; then
  echo "[!] No operator label could be determined and none was given."
  echo "    A relay without one is never selected for a path. Set GOTHAM_OPERATOR."
  exit 1
fi
EXTRA+=" --operator $OPERATOR"
for u in $EXTRA_AUTHORITY_URLS; do
  EXTRA+=" --extra-authority-url $u"
done

# Decide DIRECT (we have a reachable public address) vs RENDEZVOUS (RFC B3 —
# behind CGNAT / mobile 4G-5G / broken UPnP: keep an OUTBOUND tunnel to a public
# rendezvous relay, no inbound reachability needed). GOTHAM_RENDEZVOUS=on|off|auto.
MODE="direct"
case "${GOTHAM_RENDEZVOUS:-auto}" in
  on|1|true)   MODE="rendezvous" ;;
  off|0|false) MODE="direct" ;;
  *) # auto-detect
    if [[ -n "${GOTHAM_ADVERTISE_IP:-}" ]]; then
        MODE="direct"          # operator asserts a reachable address / port-forward
    elif [[ -n "$ADVERTISE_IP" ]] && { ip -o addr show 2>/dev/null || ifconfig 2>/dev/null; } | grep -qw "$ADVERTISE_IP"; then
        MODE="direct"          # our public IP is bound to a local interface → directly reachable
    else
        MODE="rendezvous"      # no public IP on this host and none asserted → behind NAT/CGNAT
    fi ;;
esac

# Look up a rendezvous point and append the flags that use it. Factored out
# because it is needed twice: once when we already know we are behind a NAT, and
# once as the AUTOMATIC FALLBACK when a "directly reachable" relay turns out not
# to be — which is the common case, and the one that used to require the project
# owner to open a port on the volunteer's router by hand.
pick_rendezvous() {
    DIR_JSON="$(curl -fsSL --max-time 10 "$AUTHORITY_URL/directory" || true)"
    # The directory is compact JSON; split per-relay on '{' and match the flag,
    # then pull its kem + addr.
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
    # The relay auto-fetches the authority PoP key from /pop for the possession
    # proof; nothing to paste. advertise-addr is IGNORED in rendezvous mode but
    # must be non-empty (else systemd swallows the following flag) — placeholder.
    EXTRA+=" --rendezvous-key $R_KEM --rendezvous-addr $R_ADDR"
    ADVERTISE_ADDR="${ADVERTISE_IP:-127.0.0.1}:$PORT"
else
    [[ -n "$ADVERTISE_IP" ]] || { echo "[!] Could not auto-detect a public IP. Re-run with GOTHAM_ADVERTISE_IP=<your.public.ip>, or GOTHAM_RENDEZVOUS=on to use a rendezvous point."; exit 1; }
    echo "    Directly reachable — advertising $ADVERTISE_IP:$PORT/udp."
    ADVERTISE_ADDR="$ADVERTISE_IP:$PORT"
fi

# relay.env holds the token — keep it readable only by root + the relay user.
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
# Rendezvous mode is OUTBOUND-only — no inbound port to open (that is the whole
# point of B3). Only open the UDP port when we advertise a directly-reachable one.
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
# Log rotation. Without it the relay appends forever and a flood of malformed
# packets fills the disk, which stops the relay and often the whole VPS.
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
# Ask the AUTHORITY, not our own log. The directory is ground truth: either our
# public key is in the signed document or it is not. Grepping the log used to
# abort early on "does not host this relay" -- which is a NORMAL transient on a
# rendezvous install, because the authority proves us live by querying our
# rendezvous host and our reverse tunnel may not be registered there yet. Every
# CGNAT volunteer was told the install had failed while it was in fact about to
# succeed. The relay now retries that case within seconds; we just wait for it.
# Count how many authorities list us. Clients admit a relay only when k of n
# have attested it (k=2, n=3 today), so being in the primary's directory alone
# means the relay runs, looks healthy, and is dropped by every client. The
# installer used to print "LIVE and ENROLLED" for exactly that state.
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
    # Only a genuinely terminal failure aborts the wait.
    if grep -qi "invalid possession proof\|401 Unauthorized\|rejected: missing" "$LOG_DIR/relay.log" 2>/dev/null; then
        echo "    Authority refused this relay outright — see the cause below."
        break
    fi
done

# AUTOMATIC FALLBACK. A relay that believed it was directly reachable and was
# not is the single most common failure, and the one that produced "phantom"
# relays: the service runs, the volunteer sees no error, and the network ignores
# them. The heuristic above cannot detect a provider-side firewall or a router
# that silently drops inbound UDP — only the authority's dial-back can, and it
# has just told us by NOT listing us.
#
# Rather than leave the volunteer to diagnose that, switch to the rendezvous
# transport, which needs no inbound reachability at all, and try again.
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
