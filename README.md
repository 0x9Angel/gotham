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
- It has **not been audited by an independent third party**. The register comes
  from two internal campaigns of early August 2026 — an offensive audit on the
  3rd, a manual code review on the 4th — after deduplication and removal of what
  was already fixed. Every suspected flaw first faced a second analysis whose job
  was to refute it; what did not survive that step is not counted. **71 findings
  recorded**: as of 15 September 2026, **56 are fixed** — with a regression test
  each wherever the attack can be replayed by a program — **13 are reduced**,
  with the surviving risk written down in the register rather than glossed over,
  and **2 are still open**. The findings left open by the general review of July
  2026 have not been folded into this register, so read the open count as a
  floor. Internal is not independent, and a count of findings fixed says nothing
  about the ones nobody has looked for yet.
- **The finding rated critical is reduced, not closed.** The per-hop MAC used to
  authenticate only one slot of the routing block, so two colluding relays could
  tag a packet on the way in and recognise it on the way out. Header **version 3**
  closes that channel: each hop's MAC now covers the rest of the routing block
  after it, so a relay that tags a slot further down the path is caught by the
  first honest hop that follows. Shipped on 13 September 2026, in relay
  **v0.12.0** and application **2.3.0**. Two residuals stay on the record rather
  than being called done: relays still accept the old header until
  `--strict-header-v3` is set across the whole fleet, and two colluding relays
  that sit **immediately next to each other** keep a tagging channel this
  construction cannot close by design.
- **The two findings still open are one defect seen from two sides.** A relay's
  operator label is a string the relay declares about itself, and the authority
  signs it as it stands — while every path-diversity rule rests on that label.
  Nothing checks that two labels belong to two different people, so an adversary
  willing to enrol relays under several labels defeats the diversity rule without
  forging anything. What counts as proof that an operator is one has not been
  settled. If you are considering running a relay, this is the finding to ask
  about.
- Some known limitations are structural and written down in
  [`docs/README.md`](docs/README.md) rather than quietly omitted. One that used
  to be listed here is no longer true and is corrected rather than quietly
  dropped: β is **not** byte-identical between hops — it is re-randomised at
  every hop, and a regression test covers every pair of hops. The defect that
  was real there is narrower and different, and it is the reduced critical
  finding above.
- **All three directory authorities are run by one person**, the author. The
  2-of-3 quorum stops a single key from forging the relay list; it does not stop
  a simultaneous seizure of all three hosts.
- **The network does not route today, and the reason is people, not machines.**
  Path selection refuses two hops on the same path unless it can prove they
  belong to different operators — at every hop, not only at the two ends — so a
  three-hop route needs three independent operators. Every relay in the fleet
  carries the same operator label, so no route can be built at all and traffic
  falls back to the mailbox. More machines, or more address ranges, under that
  one label change nothing. Recruiting independent operators is the network's
  declared first priority.

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
- **Sealed sender** — the entry relay does not learn who is sending. It hides
  *who* is sending, not *that* the peer is the sender: `hop_index` and
  `hop_count` travel in the clear, so the first relay knows its peer is the
  original sender and every relay knows the length of the path it is on.
- **Enforced path diversity** — no two hops anywhere on the path may share an
  operator label, an IPv4 /16 or an IPv6 /48; entry and exit in particular. The
  rule fails closed: a relay whose operator cannot be shown to differ counts as
  the same operator, not as a different one.
- **Store-and-forward mailboxes** addressed by a derived id, with a DH-MAC
  possession proof: holding a recipient's *public* key is not enough to read or
  delete their mail. The id is **not unlinkable**, and it would be wrong to
  imply otherwise: it is a hash of the recipient's public key, and that key
  travels in every invitation and every contact card. Anyone holding someone's
  contact card can compute their mailbox id — and, from a seized relay, show
  that this person received mail there and when. The proof also binds third
  parties rather than the host: whoever runs the relay cannot read the envelopes,
  but can lose or destroy them, which surfaces as a non-delivery rather than as
  a leak.
- **SURBs** — single-use reply blocks, so a recipient can collect mail without
  revealing their IP to the host. Implemented, but **not reachable on the
  current fleet**: the anonymous fetch needs a routable path, and with too few
  relays every fetch falls back to a direct connection in which the host does
  see the recipient's IP. It starts working when the fleet can route.
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

Volunteer relays are what make the network worth anything. **Read these three
before you install anything** — they say what you are agreeing to operate, what
your machine will hold, and what to do if someone comes asking:

- [`OPERATOR-GUIDE.md`](OPERATOR-GUIDE.md) — what a relay does, what each tier
  sees, what we ask of you, and what you are trusting us with today
- [`LOGGING-POLICY.md`](LOGGING-POLICY.md) — an inventory, checked against the
  source, of everything a relay records and keeps
- [`ABUSE-FAQ.md`](ABUSE-FAQ.md) — complaints, legal requests, and a reply
  template for your hosting provider

If you have a machine that stays on — a VPS, a home server, a Raspberry Pi — see
also [`docs/running-a-cgnat-relay.md`](docs/running-a-cgnat-relay.md) and the
installers in [`infra/scripts/`](infra/scripts/).

`GOTHAM_OPERATOR` is required and the installer refuses without it: an
unlabelled relay is never selected by path selection, so it would burn your
bandwidth while looking perfectly healthy.

Enrolment with the authorities this project runs is closed: the relay has to
present a bearer token (`GOTHAM_ENROLL_TOKEN`, or `--enroll-token`). An
authority started with no token list accepts any enrolment — that is a
deployment choice, not a property of the code.

A relay behind CGNAT needs **no port forwarding**: it keeps an outbound tunnel to
a public rendezvous relay and is reachable through it.

Bandwidth and packet rate are both capped by flags (`--max-pps`,
`--max-bytes-per-day`), so a relay on a metered connection stays inside a budget
you choose.

## Reporting a vulnerability

Mail **crypto.app.organisation@proton.me**. Reports are handled as a priority and
there will be no legal action against anyone acting in good faith.

No PGP key is published to date, so treat the mail as you would any other
plaintext mail to a provider-hosted address.

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
