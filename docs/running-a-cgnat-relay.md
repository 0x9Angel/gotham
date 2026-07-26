<!--
SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Gotham-Commercial
Copyright (C) 2026 0x9Angel.
-->

# Running a relay on 4G / 5G / behind CGNAT (RFC B3)

Status: **live since 2026-07-13.** You do **not** need a public IP or a
port-forward to run a Gotham relay. If you are on mobile (4G/5G tethering), a
Freebox with broken UPnP, or double-NAT, you can still contribute — the relay
holds an **outbound tunnel** to a public *rendezvous point* and receives its
mixnet traffic through it (RFC B3 reverse transport). No inbound reachability
required.

## How it works (30 seconds)

Normally the directory authority dials your relay back to prove it is alive —
which fails behind CGNAT. In CGNAT mode your relay instead keeps a persistent
outbound QUIC+Noise tunnel to a public **rendezvous relay `R`**, and the
authority proves your liveness by *asking `R`* (an authenticated Noise-IK query),
never by dialing you. You enrol with **no dialable address**; the path selector
places `R` immediately before you and routes your packets down the tunnel.

## Live rendezvous points

Pick one (both are public relays advertising `rendezvous_capable`):

| Rendezvous `R` | `--rendezvous-addr` | `--rendezvous-key` |
|---|---|---|
| VM-A (entry, /16 144.24) | `144.24.205.188:9101` | `84e2b556431b22d44ff0e8f22204958c4935983808148cefcdac34191d2d3536` |
| VM-B (mix, /16 84.235)   | `84.235.233.41:9102`  | `e7d75909e463b7b080e6cd95c418c3f6d76e9c958dc0d81feba2e40ddd89ba44` |

## Run it

```bash
# 1. one-time: generate your relay identity key
gotham-relay keygen --key-file ~/.gotham/relay.key

# 2. run as a CGNAT relay via a rendezvous point (example: VM-B)
gotham-relay run \
  --key-file      ~/.gotham/relay.key \
  --listen-port   9201 \
  --rendezvous-key  e7d75909e463b7b080e6cd95c418c3f6d76e9c958dc0d81feba2e40ddd89ba44 \
  --rendezvous-addr 84.235.233.41:9102 \
  --authority-url http://144.24.205.188:8443 \
  --tier mix
```

- `--listen-port` binds only locally (for the outbound tunnel); it is **not**
  advertised and does **not** need to be reachable / port-forwarded.
- The authority's PoP key is auto-fetched from `/pop` — no key to paste.
- No `--advertise-addr` (a CGNAT relay has no dialable address).

You should see `rendezvous tunnel up` then `enrolled with directory authority`,
and your relay appears in `GET http://144.24.205.188:8443/directory` with a
`rendezvous` field set and an empty `addr`.

## Honest limits (read before relying on it)

- **A CGNAT relay inherits its rendezvous point's `/16` / operator** for
  diversity accounting (anti-Sybil: all your traffic funnels through `R`, so you
  cannot be counted as more diverse than `R`). So CGNAT relays **add capacity and
  participation**, but they do **not** add an independent `/16` — the diverse
  3-hop backbone still needs public relays on distinct `/16`.
- **The rendezvous point sees your traffic timing/volume** (like a Tor bridge
  sees its clients). A CGNAT relay is therefore **anonymity-weaker** than a
  direct public relay. Good for scale; keep the backbone on direct relays.

## For operators: enabling a public relay as a rendezvous point

Add to the relay's `run` args and restart:

```
--rendezvous-capable --authority-pop-key <the authority's /pop hex>
```

`--authority-pop-key` is REQUIRED so the relay can authenticate the authority's
rendezvous-liveness query (Noise-IK); without it the query is refused
fail-closed. Fetch the value from `GET <authority-url>/pop`.
