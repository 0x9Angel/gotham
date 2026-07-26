# crypto-gotham-relay

Standalone Gotham mixnet relay binary.

## Build

```sh
cargo build --release -p crypto-gotham-relay
# Binary: target/release/gotham-relay
```

## Operator quick start

```sh
# 1. Generate an identity keypair (writes 0600 file with hex secret key)
gotham-relay keygen --key-file /var/lib/gotham-relay/identity.key

# 2. Inspect the public key (publish in the directory)
gotham-relay pubkey --key-file /var/lib/gotham-relay/identity.key

# 3. Run the relay
gotham-relay run \
    --key-file /var/lib/gotham-relay/identity.key \
    --listen-port 443 \
    --delay-micros 20000 \
    --replay-size 1000000 \
    --replay-ttl-secs 300
```

Binding to port 443 requires `CAP_NET_BIND_SERVICE` (granted by the
shipped systemd unit). Otherwise pick a port > 1024.

## Status (v0.1 pre-alpha)

| Component | State |
|---|---|
| Identity keygen + pubkey | Implemented |
| Replay cache (LRU + TTL) | Implemented + tested |
| Poisson delay scheduler | Implemented + tested |
| Stateless `process_packet` | Implemented + tested (forward / deliver / drop) |
| QUIC listener (UDP/443) | ⏳ P2.next |
| Noise XK per-link | ⏳ P2.next |
| Prometheus metrics endpoint | ⏳ P2.next |
| Directory enrolment workflow | ⏳ P3 |

## Deployment

Drop `deploy/gotham-relay.service` into `/etc/systemd/system/`, adapt
paths, then:

```sh
sudo useradd -r -s /usr/sbin/nologin -d /var/lib/gotham-relay gotham
sudo mkdir -p /var/lib/gotham-relay
sudo chown gotham:gotham /var/lib/gotham-relay
sudo systemctl daemon-reload
sudo systemctl enable --now gotham-relay
journalctl -u gotham-relay -f
```

The unit applies strict systemd hardening (`ProtectSystem=strict`,
`MemoryDenyWriteExecute`, `RestrictAddressFamilies`, …). Audit
`systemd-analyze security gotham-relay` after enabling — target score is
≤ 1.5.

## Privacy posture

The relay **does not log per-packet data, peer IPs, or routing decisions**.
Only counter-style metrics (forwards / drops / replay / bad-MAC) are
exposed. Logs at `info` and `warn` levels carry only operational status
(startup, configuration, shutdown).

## License

Dual AGPLv3 + commercial. See `crypto-gotham/LICENSE-AGPL` and
`crypto-gotham/LICENSE-COMMERCIAL` for terms.
