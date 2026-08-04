#!/usr/bin/env bash
# install-relay-macos.sh — one-command Gotham mixnet relay installer for macOS.
#
# Downloads the checksum-verified prebuilt binary (Apple Silicon or Intel),
# generates an identity key, and installs a launchd LaunchDaemon so the relay
# is boot-persistent and auto-restarts. Run with sudo.
#
#   curl -fsSL https://raw.githubusercontent.com/0x9Angel/gotham-relay/main/infra/scripts/install-relay-macos.sh | sudo GOTHAM_OPERATOR=your-name bash
#
# Env vars (same as the Linux installer):
#   GOTHAM_OPERATOR      REQUIRED. Public nickname identifying who runs this
#                        relay. Path selection refuses two hops it cannot PROVE
#                        belong to different operators, so an unlabelled relay
#                        is never routed. Use the SAME value on every relay you
#                        run, so diversity reflects who actually runs what.
#   GOTHAM_ENROLL_TOKEN  Only if the authority runs in closed/token mode.
#                        Enrollment is OPEN by default — you do NOT need one.
#   GOTHAM_AUTHORITY_URL Directory authority URL. Default http://144.24.205.188:8443
#   GOTHAM_EXTRA_AUTHORITY_URLS
#                        Space-separated ADDITIONAL authorities to enroll with.
#                        Clients need a quorum of attestations, so the default is
#                        the other two authorities of the shipped set.
#   GOTHAM_TIER          entry|mix|exit. Default mix.
#   GOTHAM_PORT          UDP listen+advertise port. Default 443.
#   GOTHAM_ADVERTISE_IP  Public IP peers reach you on. If UNSET, the relay
#                        auto-maps its port and detects its public address via
#                        UPnP-IGD (home routers) — no manual port-forward.
#   GOTHAM_RENDEZVOUS    auto | on | off. Default auto: enrol via a rendezvous
#                        point (RFC B3) when no reachable public address is
#                        found — lets a Mac on 4G/5G / CGNAT be a relay.
set -euo pipefail

AUTHORITY_URL="${GOTHAM_AUTHORITY_URL:-http://144.24.205.188:8443}"
# Clients admit a relay only when k of n authorities have attested it (k=2, n=3
# in the shipped app). A relay enrolled with the primary alone runs, reports
# itself healthy, and is dropped in silence by every client. Enrol with all three.
EXTRA_AUTHORITY_URLS="${GOTHAM_EXTRA_AUTHORITY_URLS:-http://84.235.232.196:8443 http://84.235.228.107:8443}"
TIER="${GOTHAM_TIER:-mix}"
PORT="${GOTHAM_PORT:-443}"
# Fail-closed diversity: path selection never puts two hops together unless it
# can PROVE they belong to different operators, and an unlabelled relay counts
# as unproven. So a relay with no label runs, looks healthy and is never used.
OPERATOR="${GOTHAM_OPERATOR:-}"
ENROLL_TOKEN="${GOTHAM_ENROLL_TOKEN:-}"
REPO="0x9Angel/gotham-relay"

BIN=/usr/local/bin/gotham-relay
STATE_DIR=/usr/local/var/gotham-relay
KEYFILE="$STATE_DIR/relay.key"
LOG="$STATE_DIR/relay.log"
PLIST=/Library/LaunchDaemons/org.gotham.relay.plist

[[ "$(id -u)" -eq 0 ]] || { echo "Run with sudo: sudo bash $0"; exit 1; }
case "$TIER" in entry|mix|exit) ;; *) echo "[!] GOTHAM_TIER must be entry|mix|exit (got '$TIER')"; exit 1;; esac
# Checked BEFORE anything is downloaded: a relay that cannot be routed is worse
# than no relay, because nobody finds out. Better a clean refusal now.
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
# The label is pasted into the launchd plist, so restrict it to characters that
# need no XML escaping and cannot smuggle a second argument.
[[ "$OPERATOR" =~ ^[A-Za-z0-9._-]{1,32}$ ]] || {
    echo "[!] GOTHAM_OPERATOR must be 1 to 32 characters from A-Z a-z 0-9 . _ -"
    echo "    (got '$OPERATOR')"
    exit 1
}

case "$(uname -m)" in
  arm64)  ASSET=gotham-relay-macos-aarch64 ;;
  x86_64)
    # No Intel build is published (the release job only targets
    # aarch64-apple-darwin), and an Apple Silicon binary cannot run on Intel —
    # Rosetta translates the other way. Asking for it produced a bare 404 from
    # curl with no explanation.
    echo "[!] No Intel (x86_64) macOS build is published for the Gotham relay."
    echo "    Apple Silicon binaries do not run on Intel Macs."
    echo "    Options:"
    echo "      - run the relay on a Linux host instead (install-relay.sh), or"
    echo "      - build from source:  cargo build --release -p crypto-gotham-relay"
    exit 1
    ;;
  *) echo "[!] unsupported CPU arch: $(uname -m)"; exit 1 ;;
esac

echo "[1/5] Downloading + verifying $ASSET (latest release)…"
mkdir -p "$(dirname "$BIN")" "$STATE_DIR"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
base="https://github.com/$REPO/releases/latest/download"
curl -fsSL "$base/$ASSET"        -o "$TMP/$ASSET"
curl -fsSL "$base/$ASSET.sha256" -o "$TMP/$ASSET.sha256"
( cd "$TMP" && shasum -a 256 -c "$ASSET.sha256" ) || { echo "[!] Checksum verification FAILED — refusing to install."; exit 1; }
install -m 0755 "$TMP/$ASSET" "$BIN"

echo "[2/5] Generating relay identity (if absent)…"
[[ -f "$KEYFILE" ]] || "$BIN" keygen --key-file "$KEYFILE"
chmod 600 "$KEYFILE"
PUBKEY="$("$BIN" pubkey --key-file "$KEYFILE")"

# Decide DIRECT vs RENDEZVOUS (RFC B3 — behind CGNAT / mobile 4G-5G / broken
# UPnP: keep an OUTBOUND tunnel to a public rendezvous relay, no inbound needed).
PUB_IP="$(curl -fsSL --max-time 8 https://api.ipify.org || true)"
MODE="direct"
case "${GOTHAM_RENDEZVOUS:-auto}" in
  on|1|true)   MODE="rendezvous" ;;
  off|0|false) MODE="direct" ;;
  *) if [[ -n "${GOTHAM_ADVERTISE_IP:-}" ]]; then MODE="direct"          # operator asserts a reachable addr
     elif [[ -n "$PUB_IP" ]] && ifconfig 2>/dev/null | grep -qw "$PUB_IP"; then MODE="direct"  # public IP on an interface
     else MODE="rendezvous"; fi ;;                                        # behind NAT/CGNAT
esac

if [[ "$MODE" == "rendezvous" ]]; then
    echo "    No reachable public address — enrolling via a RENDEZVOUS point (RFC B3, works behind CGNAT/4G-5G)."
    DIR_JSON="$(curl -fsSL --max-time 10 "$AUTHORITY_URL/directory" || true)"
    R_LINE="$(printf '%s' "$DIR_JSON" | tr '{' '\n' | grep '"rendezvous_capable":true' | head -1)"
    R_KEM="$(printf '%s'  "$R_LINE" | sed -n 's/.*"kem_pubkey_hex":"\([0-9a-fA-F]*\)".*/\1/p')"
    R_ADDR="$(printf '%s' "$R_LINE" | sed -n 's/.*"addr":"\([0-9.:]*\)".*/\1/p')"
    if [[ -z "$R_KEM" || -z "$R_ADDR" ]]; then
        echo "[!] No rendezvous point is currently available from $AUTHORITY_URL."
        echo "    An operator must run a public relay with --rendezvous-capable, or set"
        echo "    GOTHAM_ADVERTISE_IP=<reachable.ip> if you CAN port-forward UDP $PORT."
        exit 1
    fi
    echo "    Rendezvous relay: $R_ADDR"
    # rendezvous mode: NO --advertise-addr (a CGNAT relay has no dialable address);
    # the PoP key is auto-fetched from /pop.
    ADVERTISE_XML="    <string>--rendezvous-key</string><string>$R_KEM</string><string>--rendezvous-addr</string><string>$R_ADDR</string>"
    ADVERTISE_MSG="via rendezvous $R_ADDR (CGNAT/B3)"
elif [[ -n "${GOTHAM_ADVERTISE_IP:-}" ]]; then
    ADVERTISE_XML="    <string>--advertise-addr</string><string>${GOTHAM_ADVERTISE_IP}:$PORT</string>"
    ADVERTISE_MSG="${GOTHAM_ADVERTISE_IP}:$PORT (manual)"
else
    ADVERTISE_XML="    <!-- no --advertise-addr: the relay auto-maps its UDP port and detects its public IP via UPnP-IGD -->"
    ADVERTISE_MSG="auto (UPnP-IGD)"
fi
if [[ -n "$ENROLL_TOKEN" ]]; then
    TOKEN_XML="    <string>--enroll-token</string><string>$ENROLL_TOKEN</string>"
else
    TOKEN_XML="    <!-- open enrollment: no --enroll-token needed -->"
fi

# One --extra-authority-url per additional authority; each one's PoP key is
# auto-fetched from its own /pop, so there is nothing to paste here.
AUTHORITIES_XML=""
for u in $EXTRA_AUTHORITY_URLS; do
    AUTHORITIES_XML+="    <string>--extra-authority-url</string><string>$u</string>"$'\n'
done

echo "[3/5] Installing launchd LaunchDaemon…"
cat > "$PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>org.gotham.relay</string>
  <key>ProgramArguments</key><array>
    <string>$BIN</string><string>run</string>
    <string>--key-file</string><string>$KEYFILE</string>
    <string>--listen-host</string><string>0.0.0.0</string>
    <string>--listen-port</string><string>$PORT</string>
    <string>--authority-url</string><string>$AUTHORITY_URL</string>
${AUTHORITIES_XML}    <string>--operator</string><string>$OPERATOR</string>
$ADVERTISE_XML
$TOKEN_XML
    <string>--tier</string><string>$TIER</string>
    <string>--heartbeat-secs</string><string>60</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>$LOG</string>
  <key>StandardErrorPath</key><string>$LOG</string>
</dict></plist>
PLIST
chmod 644 "$PLIST"; chown root:wheel "$PLIST"

echo "[4/5] Loading service…"
launchctl bootout system "$PLIST" 2>/dev/null || true
launchctl bootstrap system "$PLIST"
launchctl enable system/org.gotham.relay

echo "[5/5] Waiting for the authorities to accept enrollment…"
# Ask the AUTHORITIES, not our own log. The directory is ground truth: either
# our public key is in the signed document or it is not. And ask all of them:
# clients admit a relay only once k of n have attested it (k=2 today), so being
# listed by the primary alone means the relay runs and is dropped by every
# client. The log line 'enrolled with directory authority' this installer used
# to point at is printed for that useless state too.
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
done

echo
echo "============================================================"
if [[ "$ENROLLED" -eq 1 ]]; then
    echo " Gotham relay is LIVE and ENROLLED ($SEEN_BY authorities attest it)"
else
    echo " Gotham relay installed - NOT usable by clients yet"
    echo " Attested by $SEEN_BY of the $QUORUM_NEEDED authorities required."
    if [[ "$SEEN_BY" -gt 0 ]]; then
        echo " It IS running and one authority sees it, but clients need a quorum,"
        echo " so no traffic is routed through it until the others accept it."
    elif [[ "$MODE" == "direct" ]]; then
        echo " Most common cause: UDP port $PORT is not reachable from the internet"
        echo " (no router port-forward, or CGNAT). If you are behind CGNAT or on"
        echo " 4G-5G, re-run with GOTHAM_RENDEZVOUS=on to enrol via a rendezvous"
        echo " point instead."
    else
        echo " In rendezvous mode: check the rendezvous relay ${R_ADDR:-?} is up and"
        echo " that outbound UDP to it is not blocked."
    fi
fi
echo "============================================================"
echo " Public key : $PUBKEY"
echo " Advertised : $ADVERTISE_MSG   (tier: $TIER, port $PORT/udp)"
echo " Authority  : $AUTHORITY_URL"
echo " Also enrolled with: $EXTRA_AUTHORITY_URLS"
echo " Operator   : $OPERATOR   (a relay without a label is never routed)"
echo " Live logs  : tail -F $LOG"
echo " Uninstall  : curl -fsSL https://raw.githubusercontent.com/$REPO/main/infra/scripts/uninstall-relay-macos.sh | sudo bash"
echo
echo " Keep this Mac awake on power so the relay stays online:"
echo "   sudo pmset -c sleep 0 disablesleep 1"
echo "============================================================"
