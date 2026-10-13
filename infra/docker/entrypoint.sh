#!/bin/sh
set -e

KEY=/var/lib/gotham-relay/relay.key
[ -f "$KEY" ] || gotham-relay keygen --key-file "$KEY"

set -- run \
    --key-file "$KEY" \
    --listen-host 0.0.0.0 \
    --listen-port "${GOTHAM_PORT:-443}" \
    --authority-url "${GOTHAM_AUTHORITY_URL:-http://144.24.205.188:8443}" \
    --tier "${GOTHAM_TIER:-mix}" \
    --heartbeat-secs 60

[ -n "${GOTHAM_ADVERTISE_ADDR:-}" ] && set -- "$@" --advertise-addr "$GOTHAM_ADVERTISE_ADDR"
[ -n "${GOTHAM_COUNTRY:-}" ]        && set -- "$@" --country "$GOTHAM_COUNTRY"
[ -n "${GOTHAM_OPERATOR:-}" ]       && set -- "$@" --operator "$GOTHAM_OPERATOR"

exec gotham-relay "$@"
