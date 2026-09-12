# Gotham — the mixnet

**Gotham is the anonymity network that carries Crypto's traffic — and could
carry any other application's.** This folder is the single entry point for
understanding it; the code lives in the `crypto-gotham*` crates at the
repository root.

## What it is

A Sphinx/Loopix mixnet:

- **Sphinx-style packets** — every packet is a fixed **2048 bytes**,
  unlinkable hop-to-hop; a relay peels exactly one layer and forwards an
  opaque payload (1-in → 1-out), never inspecting or executing it.
- **X25519 per-hop key agreement.** Per-hop key agreement is **classical, not
  post-quantum.** An earlier version of this page claimed a per-hop X25519 +
  ML-KEM-768 hybrid; that was wrong, and it is the kind of claim this project
  should never make loosely. The ML-KEM-768 hybrid exists
  (`crypto-gotham/src/hybrid.rs`) but is reserved for the **application-layer
  end-to-end session**: per-hop ML-KEM would not fit the 2048-byte packet budget
  (`header.rs`, "X25519-only per-hop key agreement"). So a recorded stream could
  in principle be attacked by a future quantum adversary at the transport layer,
  even where the message content has the hybrid layer.
- **Loopix-style mixing** — per-hop exponential delays plus Poisson cover traffic
  to resist timing correlation. Budget for **seconds, not milliseconds**: the
  default cover mode draws a 500 ms mean delay per hop, so a 3-hop path averages
  about 1.5 s one way and its tail runs to several seconds. This is deliberate —
  mixing *is* delay — and it is why voice does not travel over the mixnet.
- **Directory authority** — relays self-enrol; the authority proves each is
  live and publishes a signed directory that clients pin, admitted by a
  **2-of-3 quorum** so no single authority key controls the route set.

## License — open

Unlike the Crypto app, Gotham is **open**: **AGPL-3.0-or-later**, or a separate
commercial licence. A network of relays nobody may redistribute is not a network
— so anyone may run, study, and fork a relay. See [`../LICENSE`](../LICENSE); for
commercial terms, write to the address in the root README.

## The crates (at the repository root)

| Crate | Role |
|---|---|
| `crypto-gotham` | The protocol library: packet format, hybrid crypto, routing, cover traffic. |
| `crypto-gotham-relay` | The relay daemon — the binary volunteers run. |
| `crypto-gotham-directory` | The directory data model shared by relays and the authority. |
| `crypto-gotham-authority` | The directory authority server (enrolment + signed directory). |

## Run a relay

Any host with a **public IP** can run a relay on Linux, macOS, or Windows. It
starts at boot and runs in the background.

**Behind a home router, do not count on UPnP.** It was tried and abandoned: a
common French ISP box (Freebox) refuses every port mapping with error 718, and
UPnP is unreliable in general. The supported answer for a connection with no
inbound port is the **rendezvous transport (RFC B3)** — your relay keeps an
outbound tunnel to a public relay and is reachable through it, with no port
forwarding at all. See [running-a-cgnat-relay.md](running-a-cgnat-relay.md).

One consequence to know before you invest time in it: a rendezvous-hosted relay
**inherits its rendezvous point's operator label and network position** for
path-diversity purposes. It is reachable, but it does not add diversity against
the relay it tunnels through, so it will rarely be selected. If your goal is to
help the network actually route, a small VPS with its own public IP at a
provider nobody else in the fleet uses is what moves the needle. See
[../OPERATOR-GUIDE.md](../OPERATOR-GUIDE.md).

| OS | Installer |
|---|---|
| Linux | `infra/scripts/install-relay.sh` |
| macOS | `infra/scripts/install-relay-macos.sh` |
| Windows | `infra/scripts/install-relay.ps1` |

Each release binary ships a `.sha256` sidecar; because the relay is AGPL you
can also rebuild it from source and compare.

### Uninstall

| OS | Uninstaller |
|---|---|
| Linux | `infra/scripts/uninstall-relay.sh` |
| macOS | `infra/scripts/uninstall-relay-macos.sh` |
| Windows | `infra/scripts/uninstall-relay.ps1` |

Each uninstaller fully reverses its installer (service, files, firewall rule,
identity key). Set `GOTHAM_KEEP_KEYS=1` to keep the identity key for a later
reinstall with the same public key.

---

## Known structural limitations

The root README points here for these, so here they are rather than nowhere.

- **One critical finding is open.** The per-hop MAC (γ) authenticates only its
  own slot of the routing block, so **two colluding relays can tag a packet on
  the way in and recognise it on the way out**, linking sender to recipient
  deterministically from a single packet. Unexploitable while every relay has the
  same operator — the case today — and it must be closed before third-party
  relays carry real traffic. Closing it requires a wire-format change
  (VERSION 3).
- **`hop_index` and `hop_count` travel in clear** (F-54, reduced not closed).
  One byte tells a relay its position in the path, which means the first relay
  learns its peer is the *original sender* rather than another relay. Sealed
  sender hides *who* is sending; these bytes reveal *that* the peer is the
  sender. Same VERSION 3 change.
- **Per-hop key agreement is classical**, not post-quantum. See "What it is".
- **The mixnet does not carry voice, and will not.** Calls are TURN-relayed
  WebRTC: the relay operator sees both IP addresses, the time and the duration.
  Only the signalling rides the mixnet.
- **Mixing costs latency.** Seconds, not milliseconds. Not a bulk transport.

## Honest status of the live network

> The relay software is hardened and CI-tested across Linux/macOS/Windows. The
> **live network cannot currently route.** As of 12 September 2026 it is five
> relays across two /16s, **all under a single operator label**, and path
> selection fails closed on operator diversity — so no diverse entry→mix→exit
> route can be built at all. The app reports this in its own status line instead
> of claiming otherwise.
>
> All three directory authorities are also run by one person. The 2-of-3 quorum
> stops a single key from forging the relay list; it does not stop a
> simultaneous seizure of all three hosts.
>
> Anonymity from mixing is only ever as strong as the number of **independent**
> relays and operators. Until that number grows, treat this network's anonymity
> guarantees as **theoretical**. Two more independent operators are what changes
> that — not more machines under the same label.

← [Project root](../README.md) · [Operator guide](../OPERATOR-GUIDE.md) ·
[What a relay records](../LOGGING-POLICY.md) · [Abuse and legal requests](../ABUSE-FAQ.md)
