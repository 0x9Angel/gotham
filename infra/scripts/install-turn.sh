#!/usr/bin/env bash
#
# install-turn.sh — install + harden a coturn TURN server on a relay VM so the
# Crypto app can place PRIVATE (relay-only) audio calls: neither peer learns the
# other's IP, and no third-party STUN/TURN (e.g. Google) is contacted.
#
# It runs alongside a Gotham relay on the same host (different ports, no
# conflict). It uses coturn's `use-auth-secret` (TURN REST) mechanism: the app
# never holds a password — the directory authority signs SHORT-LIVED credentials
# with the SAME shared secret this script installs (see `--turn-secret-file` /
# `--turn-url` on gotham-directory-authority).
#
# HONEST NOTE: hosting TURN yourself does NOT make a call "anonymous" — it moves
# the call metadata to THIS server. As the operator you can see both peers' IPs
# and the call timing/duration (never the media, which stays DTLS-SRTP E2E
# encrypted). It removes the third-party (Google) exposure and the peer-to-peer
# IP leak; it is not mixnet-grade anonymity.
#
# Usage (Debian/Ubuntu, as root):
#   TURN_REALM=relay.example.org \
#   TLS_CERT=/etc/letsencrypt/live/relay.example.org/fullchain.pem \
#   TLS_KEY=/etc/letsencrypt/live/relay.example.org/privkey.pem \
#   ./install-turn.sh
#
# IP-only (no domain/cert): omit TURN_REALM/TLS_* — plain TURN on 3478 is used
# (media still E2E encrypted; only the TURN signalling metadata isn't wrapped in
# TLS). Env knobs: TURN_EXTERNAL_IP, TURN_SECRET, MIN_PORT, MAX_PORT,
# SECRET_FILE, AUTHORITY_URL.

set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "error: run as root (sudo)." >&2
  exit 1
fi

# ── Config ───────────────────────────────────────────────────────────────────
EXTERNAL_IP="${TURN_EXTERNAL_IP:-$(curl -fsS https://api.ipify.org 2>/dev/null || true)}"
REALM="${TURN_REALM:-${EXTERNAL_IP:-gotham.local}}"
MIN_PORT="${MIN_PORT:-49160}"
MAX_PORT="${MAX_PORT:-49200}"          # small relay range = fewer open ports
SECRET_FILE="${SECRET_FILE:-/etc/gotham-turn/secret}"
TLS_CERT="${TLS_CERT:-}"
TLS_KEY="${TLS_KEY:-}"

if [[ -z "${EXTERNAL_IP}" ]]; then
  echo "error: could not auto-detect the public IP; set TURN_EXTERNAL_IP." >&2
  exit 1
fi

# ── Shared secret (server-side only; the authority reads the same file) ───────
mkdir -p "$(dirname "${SECRET_FILE}")"
if [[ -n "${TURN_SECRET:-}" ]]; then
  printf '%s' "${TURN_SECRET}" > "${SECRET_FILE}"
elif [[ ! -s "${SECRET_FILE}" ]]; then
  # 32 random bytes, hex. Same string goes into coturn AND the authority.
  head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "${SECRET_FILE}"
fi
chmod 600 "${SECRET_FILE}"
SECRET="$(cat "${SECRET_FILE}")"

# ── Install coturn ───────────────────────────────────────────────────────────
echo "▸ Installing coturn…"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq coturn

# ── Hardened config ──────────────────────────────────────────────────────────
CONF=/etc/turnserver.conf
echo "▸ Writing ${CONF}…"
{
  echo "# Managed by install-turn.sh — Gotham private-call TURN. Do not hand-edit."
  echo "listening-port=3478"
  echo "listening-ip=0.0.0.0"
  echo "relay-ip=${EXTERNAL_IP}"
  echo "external-ip=${EXTERNAL_IP}"
  echo "realm=${REALM}"
  echo "server-name=${REALM}"
  echo
  echo "# Short-lived HMAC credentials only (the directory authority mints them)."
  echo "use-auth-secret"
  echo "static-auth-secret=${SECRET}"
  echo
  echo "# Narrow relay port range (open these UDP ports in the firewall)."
  echo "min-port=${MIN_PORT}"
  echo "max-port=${MAX_PORT}"
  echo
  echo "# Abuse hardening: no relaying to private/loopback/multicast targets,"
  echo "# no TCP relay, per-session quota + bandwidth caps, integrity checks."
  echo "no-tcp-relay"
  echo "no-multicast-peers"
  echo "denied-peer-ip=0.0.0.0-0.255.255.255"
  echo "denied-peer-ip=10.0.0.0-10.255.255.255"
  echo "denied-peer-ip=127.0.0.0-127.255.255.255"
  echo "denied-peer-ip=169.254.0.0-169.254.255.255"
  echo "denied-peer-ip=172.16.0.0-172.31.255.255"
  echo "denied-peer-ip=192.168.0.0-192.168.255.255"
  echo "denied-peer-ip=::1"
  echo "denied-peer-ip=fc00::-fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
  echo "denied-peer-ip=fe80::-fe80::ffff:ffff:ffff:ffff"
  echo "total-quota=100"
  echo "user-quota=6"
  echo "max-bps=256000"
  echo "stale-nonce=600"
  echo "fingerprint"
  echo
  echo "# Drop privileges + no insecure admin surfaces."
  echo "proc-user=turnserver"
  echo "proc-group=turnserver"
  echo "no-cli"
  echo "no-software-attribute"
  echo
  echo "# Privacy: retain NO per-call metadata. Relay allocations are in-memory and"
  echo "# freed when the call ends (no on-disk allocation store is configured), and"
  echo "# here we also DISCARD the session log so client IPs / peer addresses /"
  echo "# timestamps are never written to disk. (This does not stop a live tcpdump —"
  echo "# an operator can always observe traffic in flight; it guarantees nothing is"
  echo "# PERSISTED after the call.) Set TURN_LOG=1 to re-enable logs for debugging."
  if [[ -n "${TURN_LOG:-}" ]]; then
    echo "log-file=/var/log/turnserver/turn.log"
    echo "simple-log"
  else
    echo "log-file=/dev/null"
    echo "no-stdout-log"
  fi
  if [[ -n "${TLS_CERT}" && -n "${TLS_KEY}" ]]; then
    echo
    echo "# TLS (turns://5349) — wraps the TURN control channel; use this when you"
    echo "# have a domain + certificate for the realm."
    echo "tls-listening-port=5349"
    echo "cert=${TLS_CERT}"
    echo "pkey=${TLS_KEY}"
    echo "no-tlsv1"
    echo "no-tlsv1_1"
  fi
} > "${CONF}"
chmod 640 "${CONF}"

# Enable the service (Debian gates it behind this flag).
sed -i 's/^#\?TURNSERVER_ENABLED=.*/TURNSERVER_ENABLED=1/' /etc/default/coturn 2>/dev/null || \
  echo "TURNSERVER_ENABLED=1" > /etc/default/coturn

systemctl enable coturn >/dev/null 2>&1 || true
systemctl restart coturn

# ── Firewall hint (ufw) ──────────────────────────────────────────────────────
if command -v ufw >/dev/null 2>&1; then
  echo "▸ Opening firewall ports (ufw)…"
  ufw allow 3478/udp comment 'gotham-turn' >/dev/null 2>&1 || true
  ufw allow 3478/tcp comment 'gotham-turn' >/dev/null 2>&1 || true
  [[ -n "${TLS_CERT}" ]] && ufw allow 5349/tcp comment 'gotham-turn-tls' >/dev/null 2>&1 || true
  ufw allow "${MIN_PORT}:${MAX_PORT}/udp" comment 'gotham-turn-relay' >/dev/null 2>&1 || true
fi

# ── Report ───────────────────────────────────────────────────────────────────
if [[ -n "${TLS_CERT}" ]]; then
  TURN_URL="turns:${REALM}:5349"
else
  TURN_URL="turn:${EXTERNAL_IP}:3478"
fi

cat <<EOF

────────────────────────────────────────────────────────────────────────────
 coturn is LIVE — private (relay-only) calls can now use it.
────────────────────────────────────────────────────────────────────────────
 TURN URL     : ${TURN_URL}
 Shared secret: ${SECRET_FILE}  (chmod 600 — keep it secret)

 Point the directory authority at it (the authority mints short-lived
 credentials so the app never holds a password):

   gotham-directory-authority \\
     --authority-key <...> --listen 0.0.0.0:8443 \\
     --turn-url ${TURN_URL} \\
     --turn-secret-file ${SECRET_FILE}

 Copy ${SECRET_FILE} to the authority host if coturn and the authority run on
 different machines. Verify:  curl -s http://<authority>:8443/turn
────────────────────────────────────────────────────────────────────────────
EOF
