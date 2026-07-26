# Private (relay-only) calls — self-hosted TURN

Audio calls in Crypto use WebRTC. In **relay-only** mode (the default) the media
is forced through a **TURN** server so **neither peer learns the other's IP**.
This guide sets up your own TURN on a relay VM, with the directory authority
issuing **short-lived credentials** so the app never holds a TURN password.

## Honest trade-off (read this first)

Hosting TURN yourself does **not** make a call "anonymous" — it **moves the call
metadata to your server**. As the operator you can see **both peers' IPs and the
call timing/duration** (never the media, which stays DTLS-SRTP end-to-end
encrypted, and never the mixnet-routed chat). It removes the third-party (Google)
exposure and the peer-to-peer IP leak; it is **not** mixnet-grade anonymity, and
real-time media never goes through the mixnet. Chosen model = Signal/SimpleX.

## Architecture

```
  caller app ──(GET /turn: fresh short-lived creds)──▶ directory authority
      │                                                     │ signs with the
      │                                                     │ shared secret
      ▼  relay-only WebRTC media (DTLS-SRTP)                ▼ (server-side only)
   coturn on a relay VM  ◀───────────────────────────  same shared secret
```

- **coturn** runs on a relay VM (different ports from the Gotham relay — no
  conflict), in `use-auth-secret` mode: it only accepts **HMAC-signed, expiring**
  credentials.
- The **authority** holds the same shared secret and mints a credential per
  `GET /turn` request (`credential = base64(HMAC-SHA1(secret, expiry))`). The
  secret **never leaves the servers**; the app only ever gets an expiring token.
- The **app** fetches fresh credentials right before each call and merges them
  into its ICE config.

## Deploy

1. **Install coturn on a relay VM** (recommended: the *mix* relay VM, to keep
   call metadata off the authority host):

   ```bash
   # With a domain + TLS cert (best — turns://5349):
   sudo TURN_REALM=relay.example.org \
        TLS_CERT=/etc/letsencrypt/live/relay.example.org/fullchain.pem \
        TLS_KEY=/etc/letsencrypt/live/relay.example.org/privkey.pem \
        infra/scripts/install-turn.sh

   # IP-only (no domain): plain turn:3478 (media still E2E encrypted):
   sudo infra/scripts/install-turn.sh
   ```

   It prints the **TURN URL** and the **shared-secret file** (`/etc/gotham-turn/secret`).

2. **Point the authority at it** (copy the secret file to the authority host if
   they differ):

   ```bash
   gotham-directory-authority \
     --authority-key <...> --listen 0.0.0.0:8443 \
     --turn-url turns:relay.example.org:5349 \
     --turn-secret-file /etc/gotham-turn/secret
   ```

   Verify: `curl -s http://<authority>:8443/turn` → JSON with `ice_servers`.

3. **Point the app at the authority** — Settings → Calls → *Autorité TURN*:
   `https://<authority>:8443`. Leave *Forcer le relais* ON. Calls now work
   privately with no key by hand.

## Firewall (open on the coturn VM)

| Port | Proto | Purpose |
|------|-------|---------|
| 3478 | UDP+TCP | TURN control |
| 5349 | TCP | TURN over TLS (if a cert is set) |
| 49160–49200 | UDP | relay range (`MIN_PORT`/`MAX_PORT` in the script) |

## Two-server metadata split (no single TURN sees both IPs)

Run coturn on **two (or more) relay VMs with the SAME shared secret**, and list
them all on the authority (`--turn-url ... --turn-url ...`). The app then pins
the **caller and callee to DIFFERENT servers** (derived from the shared
`call_id`), so the media relays `caller → TURN_A → TURN_B → callee` and **no
single server sees both real IPs**: TURN_A sees the caller + TURN_B's address;
TURN_B sees the callee + TURN_A's address.

Deploy the second server with the first server's secret:

```bash
# on VM-A: install-turn.sh generates /etc/gotham-turn/secret
# copy that secret to VM-B, then:
sudo TURN_SECRET="$(cat secret-from-vm-a)" infra/scripts/install-turn.sh
# authority lists both:
gotham-directory-authority ... \
  --turn-url turns:vm-a:5349 --turn-url turns:vm-b:5349 \
  --turn-secret-file /etc/gotham-turn/secret
```

**Honest limit:** the split defeats a **single** compromised/subpoenaed server,
or two servers run by **different** operators. If **both** servers are yours, you
can still correlate them and see both IPs — the split doesn't hide anything from
*you*. It also adds a second relay hop (latency) and reduces redundancy (each
peer is pinned to one server; if it's down the call fails — retry).

## No retained metadata

coturn's relay allocations are **in-memory and freed when the call ends** (no
on-disk allocation store is configured), and the install script also sends the
**session log to `/dev/null`** — so client IPs, peer addresses and timestamps are
**never written to disk**. The authority keeps nothing per call (no request log,
ephemeral credentials) and the app stores no call history. Set `TURN_LOG=1`
before running the script to re-enable logs for debugging.

**Honest limit:** this guarantees nothing is **persisted** after the call — it
does **not** stop a live `tcpdump` on the server, which sees IPs in flight
regardless. "Deleted" here means "never gravé sur disque", not "unobservable by
the operator" (that would need the mixnet, which real-time media can't use).

## Notes

- The install script hardens coturn: no TCP relay, denies relaying to
  private/loopback/multicast targets, per-session quota + bandwidth caps,
  privilege drop, no admin CLI, session logging off by default.
- Credentials expire (`--turn-cred-ttl-secs`, default 300s); the app re-fetches
  per call, so a captured credential is short-lived.
- If `--turn-url` / `--turn-secret-file` are unset, `/turn` returns 404 and calls
  fall back to any manual ICE servers set in the app (or fail closed in
  relay-only mode — better than leaking an IP).
