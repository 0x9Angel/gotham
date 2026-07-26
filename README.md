# Gotham

**A Sphinx/Loopix mixnet, in Rust.** Fixed-size packets, per-hop exponential
delays, Poisson cover traffic, sealed sender, store-and-forward mailboxes with a
possession proof, and a signed directory with k-of-n admission.

Gotham is the anonymity network underneath [Crypto](#what-is-not-in-this-repo),
an end-to-end encrypted messenger. **This repository is the network.** It is
usable on its own: nothing here depends on the messenger.

---

## Honest preamble

Read this before anything else.

- The network is **young**. Anonymity in a mixnet comes from the size of the
  anonymity set — the number of independent relays and the volume of unrelated
  traffic your messages hide in. A small deployment protects less than a large
  one. This is a property of the deployment, not a checkbox in the code.
- It has **not been audited by an independent third party**. An internal
  offensive audit was run (72 findings examined, 30 refuted by counter-analysis,
  42 confirmed, 30 fixed with a regression test each, 12 documented as accepted
  residuals). Internal is not independent.
- Some known limitations are structural and written down in
  [`docs/README.md`](docs/README.md) rather than quietly omitted. The routing
  block β is byte-identical at every hop, which makes a packet correlatable
  between two observation points; fixing it needs a wire-format change.

If you are evaluating this for anything where being wrong has consequences,
start with the limitations, not the features.

## What is in this repository

| Crate | Role |
|---|---|
| `crypto-gotham` | Protocol core — Sphinx header, LIONESS payload, path selection, mailboxes, signed directory, enrollment |
| `crypto-gotham-relay` | The relay daemon — QUIC + Noise XK transport, forwarding, cover traffic, rendezvous transport, SURB replies |
| `crypto-gotham-directory` | Directory admission — k-of-n attestation, roster, gossip |
| `crypto-gotham-authority` | Directory authority — signs the relay list, issues TURN credentials |

## Design

- **Sphinx packets**, fixed at 2048 bytes with a 384-byte header, 3 to 5 hops.
  Length, type and destination are indistinguishable to an observer.
- **LIONESS** wide-block payload encryption: flipping one bit destroys the whole
  block, so the payload is non-malleable.
- **Loopix delays** drawn per hop by the sender, plus Poisson cover traffic, so a
  real send is not distinguishable by timing from a decoy.
- **Sealed sender** — the entry relay does not learn who is sending.
- **Enforced path diversity** — entry and exit may not share an operator, an
  IPv4 /16, or an IPv6 /48.
- **Store-and-forward mailboxes** addressed by an opaque id, with a DH-MAC
  possession proof: holding a recipient's *public* key is not enough to read or
  delete their mail.
- **SURBs** — single-use reply blocks, so a recipient can collect mail without
  revealing their IP to the host.
- **Rendezvous transport (RFC B3)** — a relay behind CGNAT (mobile, consumer
  ISP) joins with no inbound port and no public address at all.
- **Signed directory** with anti-rollback, and **k-of-n admission** so no single
  authority key controls the route set.

The protocol notes are in [`docs/`](docs/), including the RFC for the rendezvous
transport and the k-of-n admission design.

## Build

```bash
cargo build --release --workspace
cargo test --workspace
```

Rust stable. No C toolchain beyond what `ring` needs.

## Running a relay

Volunteer relays are what make the network worth anything. If you have a machine
that stays on — a VPS, a home server, a Raspberry Pi — see
[`docs/running-a-cgnat-relay.md`](docs/running-a-cgnat-relay.md) and the
installers in [`infra/scripts/`](infra/scripts/).

A relay behind CGNAT needs **no port forwarding**: it keeps an outbound tunnel to
a public rendezvous relay and is reachable through it.

Bandwidth and packet rate are both capped by flags (`--max-pps`,
`--max-bytes-per-day`), so a relay on a metered connection stays inside a budget
you choose.

## Reporting a vulnerability

Mail **crypto.app.organisation@proton.me**. Reports are handled as a priority and
there will be no legal action against anyone acting in good faith.

Please give us a reasonable window to ship a fix before publishing.

## Licence

**AGPL-3.0-or-later**, or a separate commercial licence.

The AGPL is deliberate: §13 closes the network-service loophole, so anyone who
runs a modified Gotham as a service must offer their changes to its users. An
anonymity network whose operators can quietly fork it into something else is not
an anonymity network.

See [`LICENSE`](LICENSE). For commercial terms, mail the address above.

## What is *not* in this repository

The **Crypto application** — the messenger client, its X3DH and Double Ratchet
implementation, the encrypted store, and the enterprise integrations — is a
separate, proprietary product and is not published here.

That split is deliberate and stated plainly rather than blurred: the network is
open so it can be inspected, extended and run by anyone, because a network
nobody can audit is not one you should route sensitive traffic through. The
application is the commercial product.

Copyright © 2026 0x9Angel.
