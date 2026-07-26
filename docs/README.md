# Gotham — the mixnet

**Gotham is the anonymity network that carries Crypto's traffic — and could
carry any other application's.** This folder is the single entry point for
understanding it; the code lives in the `crypto-gotham*` crates at the
repository root.

## What it is

A post-quantum-hybrid mixnet:

- **Hybrid crypto per hop** — X25519 **+** ML-KEM-768, so a hop stays
  confidential even against a future quantum adversary.
- **Sphinx-style packets** — every packet is a fixed **2048 bytes**,
  unlinkable hop-to-hop; a relay peels exactly one layer and forwards an
  opaque payload (1-in → 1-out), never inspecting or executing it.
- **Loopix-style mixing** — per-hop Poisson delays + cover traffic to resist
  timing correlation. Built for ~100–300 ms latency, not bulk transfer.
- **Directory authority** — relays self-enrol; the authority proves each is
  live and publishes a signed directory that clients pin.

## License — open

Unlike the Crypto app, Gotham is **open**: dual-licensed
**AGPL-3.0-or-later OR commercial**. A network of relays nobody may
redistribute is not a network — so anyone may run, study, and fork a relay.
See [`../../LICENSE`](../../LICENSE), [`../../LICENSE-AGPL.txt`](../../LICENSE-AGPL.txt),
and [`../../LICENSE-COMMERCIAL.md`](../../LICENSE-COMMERCIAL.md).

## The crates (at the repository root)

| Crate | Role |
|---|---|
| `crypto-gotham` | The protocol library: packet format, hybrid crypto, routing, cover traffic. |
| `crypto-gotham-relay` | The relay daemon — the binary volunteers run. |
| `crypto-gotham-directory` | The directory data model shared by relays and the authority. |
| `crypto-gotham-authority` | The directory authority server (enrolment + signed directory). |

## Run a relay

Any host with a public IP — or a home router that speaks UPnP — can host a
relay on Linux, macOS, or Windows. It starts at boot and runs in the
background.

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

> **Honest status.** The relay software is hardened and CI-tested across
> Linux/macOS/Windows, but the **live network is still small** — anonymity
> from mixing is only as strong as the number of independent relays and
> operators. Until the network is large and diverse, treat its anonymity
> guarantees as **theoretical**.

← [Project root](../../README.md) · the application: [Crypto](../crypto/README.md)
