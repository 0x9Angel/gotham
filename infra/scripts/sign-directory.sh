#!/usr/bin/env bash

set -euo pipefail

show_help() {
    cat <<'EOF'
sign-directory.sh — Build a signed Gotham directory from your relay set.

Run this LOCALLY (not on the VPS) after `install-relay.sh` has produced
a public key on each of your 3 relays.

Usage:
  bash infra/scripts/sign-directory.sh \
      --relay-a "<HEX_PUBKEY_A>:<IP_A>:443" \
      --relay-b "<HEX_PUBKEY_B>:<IP_B>:443" \
      --relay-c "<HEX_PUBKEY_C>:<IP_C>:443" \
      --output  gotham-bootstrap.json

Output: a JSON file the Crypto app reads at boot to learn the relay set.
Copy it to `<data_dir>/gotham/directory.json` on each app instance:
  - Linux:   ~/.crypto/gotham/directory.json
  - macOS:   ~/Library/Application Support/com.crypto.messenger/gotham/directory.json
  - Windows: %APPDATA%/com.crypto.messenger/gotham/directory.json

Signature: the directory is signed by an Ed25519 authority key that
the app already trusts (your release-signing key, or — for personal
testnets — a key you generate once and ship in the source tree).

For Option B (self-operated testnet) the authority IS you; generate it once:
  cargo run -p crypto-gotham-relay --bin gotham-relay -- keygen --key-file ~/.gotham-authority.key
Then export its pubkey hex and hardcode it in
`crypto-tauri/src-tauri/src/gotham.rs:DEFAULT_AUTHORITY_PUBKEY` (TODO).
EOF
    exit 0
}

[[ $# -eq 0 ]] && show_help

OUTPUT=gotham-bootstrap.json
declare -a ENTRIES
AUTHORITY_KEY="${HOME}/.gotham-authority.key"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --relay-a|--relay-b|--relay-c)
            ENTRIES+=("$2")
            shift 2
            ;;
        --output)
            OUTPUT="$2"
            shift 2
            ;;
        --authority-key)
            AUTHORITY_KEY="$2"
            shift 2
            ;;
        --help|-h)
            show_help
            ;;
        *)
            echo "Unknown argument: $1" >&2
            exit 1
            ;;
    esac
done

[[ ${#ENTRIES[@]} -ge 3 ]] || {
    echo "Error: need at least 3 --relay-X entries for a working mixnet" >&2
    exit 1
}

[[ -f "$AUTHORITY_KEY" ]] || {
    echo "Error: authority key not found at $AUTHORITY_KEY" >&2
    echo "Generate with:" >&2
    echo "  cargo run -p crypto-gotham-relay --bin gotham-relay -- keygen --key-file $AUTHORITY_KEY" >&2
    exit 1
}

RELAYS_JSON=$(mktemp)
{
    echo "["
    for i in "${!ENTRIES[@]}"; do
        IFS=':' read -r PUBKEY IP PORT <<< "${ENTRIES[$i]}"
        [[ ${#PUBKEY} -eq 64 ]] || { echo "Bad pubkey length (need 64 hex chars): $PUBKEY" >&2; exit 1; }
        [[ "$IP" =~ ^[0-9.:a-f]+$ ]] || { echo "Bad IP: $IP" >&2; exit 1; }
        [[ "$PORT" =~ ^[0-9]+$ ]] || { echo "Bad port: $PORT" >&2; exit 1; }
        printf '  { "node_id_hex": "%s", "addr": "%s:%s", "capabilities": "all" }' \
            "$PUBKEY" "$IP" "$PORT"
        [[ $i -lt $((${#ENTRIES[@]} - 1)) ]] && printf ',\n' || printf '\n'
    done
    echo "]"
} > "$RELAYS_JSON"

cargo run --quiet --package crypto-gotham-relay --bin gotham-relay -- \
    sign-directory \
    --authority-key "$AUTHORITY_KEY" \
    --relays "$RELAYS_JSON" \
    --output "$OUTPUT" \
    --valid-secs 2592000

rm -f "$RELAYS_JSON"

echo "Signed directory written to: $OUTPUT"
echo
echo "Copy it to your Crypto data dir on each app instance:"
echo "  Linux:   ~/.crypto/gotham/directory.json"
echo "  macOS:   ~/Library/Application Support/com.crypto.messenger/gotham/directory.json"
echo "  Windows: %APPDATA%/com.crypto.messenger/gotham/directory.json"
