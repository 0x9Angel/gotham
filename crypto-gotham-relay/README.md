# crypto-gotham-relay

Standalone Gotham mixnet relay binary.

## Build

```sh
cargo build --release -p crypto-gotham-relay
# Binary: target/release/gotham-relay
```

## Operator quick start

Most volunteers should use the installer rather than this section: it writes the
unit, the config and the firewall rule, and refuses to produce a relay the
network cannot use. See [`../OPERATOR-GUIDE.md`](../OPERATOR-GUIDE.md) and
[`../infra/scripts/`](../infra/scripts/). By hand:

```sh
# 1. Generate an identity keypair (writes 0600 file with hex secret key)
gotham-relay keygen --key-file /var/lib/gotham-relay/identity.key

# 2. Inspect the public key (publish in the directory)
gotham-relay pubkey --key-file /var/lib/gotham-relay/identity.key

# 3. Run the relay
gotham-relay run \
    --key-file /var/lib/gotham-relay/identity.key \
    --listen-port 443 \
    --operator your-name \
    --replay-size 1000000 \
    --replay-ttl-secs 300 \
    --replay-cache-path /var/lib/gotham-relay/replay.bin
```

Binding to port 443 requires `CAP_NET_BIND_SERVICE` (granted by the
shipped systemd unit). Otherwise pick a port > 1024.

Three flags decide whether the relay is any use rather than merely running.

- **`--operator`** is what path selection uses to tell two hops apart. It fails
  closed: a relay whose operator cannot be shown to differ from another's counts
  as the same operator, and an unlabelled relay is never selected at all. The
  label is self-declared and the authority signs it as it stands — that is one of
  the findings still open in the project's register, and it is the reason the
  live network does not route today.
- **`--replay-cache-path`** keeps the replay set across restarts. Without it a
  restart forgets every packet seen, and a packet captured earlier and replayed
  afterwards is accepted as fresh.
- **Do not pass `--delay-micros`.** The unit in `deploy/` below still pins it to
  20 ms, which sits under the jitter of an ordinary internet path: the hold costs
  latency and buys no mixing at all. The binary's own default — 500 ms per hop —
  is the value that mixes. `infra/systemd/crypto-gotham-relay.service` omits the
  flag on purpose.

To join a network rather than run in isolation, the relay also needs
`--authority-url` and `--advertise-addr`, plus a bearer token
(`GOTHAM_ENROLL_TOKEN`, or `--enroll-token`) wherever the authority runs closed —
which is the case for the authorities this project operates.

A relay that starts, reports `active` and carries nothing looks exactly like a
healthy one from the inside. `gotham-relay doctor --key-file <path>` asks the
authorities whether enough of them list this relay for clients to accept it, and
answers in plain language.

## Status

| Component | State |
|---|---|
| Identity keygen + pubkey | Implemented |
| Replay cache (LRU + TTL, persisted with `--replay-cache-path`) | Implemented + tested |
| Poisson delay scheduler | Implemented + tested |
| Stateless `process_packet` | Implemented + tested (forward / deliver / drop) |
| QUIC listener (UDP/443) | Implemented |
| Noise XK per-link | Implemented |
| Directory enrolment workflow | Implemented |
| Rendezvous transport (RFC B3) | Implemented |
| Prometheus metrics endpoint | Not implemented |

## Deployment

The unit the installers actually use is
`infra/systemd/crypto-gotham-relay.service`: it reads its configuration from
`/etc/gotham/relay.env`, persists the replay cache, and leaves `--delay-micros`
alone. Prefer it.

`deploy/gotham-relay.service` is the minimal hand-editable variant. Drop it into
`/etc/systemd/system/`, adapt the paths, remove the `--delay-micros` line, then:

```sh
sudo useradd -r -s /usr/sbin/nologin -d /var/lib/gotham-relay gotham
sudo mkdir -p /var/lib/gotham-relay
sudo chown gotham:gotham /var/lib/gotham-relay
sudo systemctl daemon-reload
sudo systemctl enable --now gotham-relay
journalctl -u gotham-relay -f
```

Both units apply strict systemd hardening (`ProtectSystem=strict`,
`MemoryDenyWriteExecute`, `RestrictAddressFamilies`, …). Audit
`systemd-analyze security gotham-relay` after enabling — the target score is
≤ 1.5.

## Privacy posture

At the default log level (`info`) the relay records **no user IP addresses and
no message content**. What it emits is operational: counters of packets
forwarded and dropped, the reason for each drop (`bad MAC`, `malformed`,
`rate limited`, `replay`, `self-loop`), and enrollment and connection-limit
events. There is no metrics endpoint: these are log lines, not a scrape target.

Two identifiers do appear, both belonging to *relays* rather than users, and
only in rendezvous mode: the public key of a relay tunnelling through yours, and
the address of the rendezvous relay your own relay dials. Raising `RUST_LOG`
above `info` is not neutral — assume it becomes identifying.

The full inventory, checked against this crate's source, is in
[`../LOGGING-POLICY.md`](../LOGGING-POLICY.md), including what the mailbox holds
on disk and for how long.

## License

Dual AGPLv3 + commercial. See [`../LICENSE`](../LICENSE); for commercial terms,
write to the address in the root README.
