<!--
SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Gotham-Commercial
Copyright (C) 2026 0x9Angel.
-->

# k-of-n decentralised directory admission

Status: **implemented (2026-07-12), gated OFF by default** — turns on when an
operator stands up ≥ 2 authorities and points the app at them. Supersedes the
single-authority trust anchor for admission.

## The problem it fixes

The v0.1/v0.8 directory has **one** Ed25519 authority key that signs the whole
roster. Whoever compromises that one key can forge the entire network —
including straddling entry+exit to deanonymise users. That is `k = 1, n = 1`.

## The model: federated attestation, fetched directory

Trust moves from "one authority signs everything" to "a **quorum** vouches for
each relay independently". A relay is admitted only if **k of n** pinned
authorities have each signed its identity.

```
relay ──enroll(same epoch)──▶ authority A₁ ─┐  each Aᵢ signs (kem, epoch, operator)
      ──enroll(same epoch)──▶ authority A₂ ─┼─▶ serves its attestation at GET /admissions
      ──enroll(same epoch)──▶ authority A₃ ─┘
                                              app pins {A₁,A₂,A₃}, k=2
app ──GET /directory (primary)──────────────▶ descriptor roster (addr/tier)
    ──GET /admissions (ALL Aᵢ)──────────────▶ per-relay attestations
    admit relay ⇔ ≥ k distinct authorities attested (kem, epoch, operator) AND fresh
```

Key property: **forging a relay IDENTITY the attacker cannot run now costs k
authority compromises, not one.** The authorities never need to be online
together or agree on a global snapshot — each signs a relay's tuple
independently, and the attestations travel with that relay.

### What the quorum does NOT do by itself (read this)

k-of-n removes the **single-key forgery** risk (one compromised authority can no
longer invent relays) and the **victim-key spoof** risk (the possession proof
blocks enrolling a key you don't hold). It does **not**, on its own, stop an
attacker who simply **runs their own relays** and passes each authority's
automated admission test (possession proof + liveness dial-back + per-IP rate
limit + diversity caps). Because every authority runs the *same* automated test,
passing it once ≈ passing it `n` times: `k` attestations then cost `k` HTTP
enrollments, not `k` compromises.

So the classic mixnet Sybil flood (register many attacker-run relays to raise
path-compromise probability) is bounded by the **caps + PoP + the authorities'
policy**, not by the quorum count. The quorum's real contribution to Sybil
resistance is that it gives `n` *independent* operators a place to apply
**divergent vetting** (manual review, out-of-band operator verification,
jurisdiction-specific limits) — and one honest authority declining is enough to
deny a Sybil. **Real Sybil resistance therefore lives in the authorities'
admission policy; the code provides the mechanism and a floor (caps + PoP), not
a ceiling.** Do not deploy all `n` authorities with an identical open policy and
expect the quorum alone to stop a determined Sybil.

### Why one shared epoch

For several authorities' signatures to *combine* into one certificate they must
sign the **same message** `(kem, epoch, operator)`. So the relay picks **one**
`attest_epoch` — `now` floored to a 1-day bucket (`current_attest_epoch`) — and
sends that identical integer to every authority. Bucketing keeps the value
stable across the relay's ~60 s heartbeats (the signed message doesn't churn)
while advancing daily. Daily advance bounds **revocation latency**: an authority
revokes a relay by simply declining to re-sign a newer epoch, and consumers stop
admitting it once the last attestation ages past `MAX_ADMISSION_AGE_SECS`
(30 days). The authority only signs an epoch inside a ±window of its own clock
(`epoch_acceptable`), so a relay cannot bank a pre-dated attestation.

## Trust split (honest scope)

| Property | Protected by | Residual |
|---|---|---|
| **Admission** (which identities are real relays) | k-of-n quorum — no single authority suffices | none — a rogue authority < k cannot inject relays |
| **Descriptor metadata** (a relay's addr/tier) | the ONE primary authority's blanket `/directory` signature (same as today) | a rogue *pinned* authority can mis-describe an *already-admitted* relay's address |

The residual is a **blackhole/DoS, never a deanonymization**: Sphinx layers are
sealed to the relay's KEM key, which a wrong address does not hold, so a
redirected packet is undecryptable, not readable. Removing even that residual
needs per-descriptor attestation (future); the gossip roster in
`crypto-gotham-directory` already binds `addr` in each relay's self-signed
advertisement, which is the longer-term transport.

## Recommended deployment: 2-of-3

Three authorities in **distinct jurisdictions / hosting providers**, threshold
`k = 2`:

- tolerates the loss of **one** authority without blocking admission;
- forging a relay requires **two** independent compromises;
- one honest authority is enough to *deny* a Sybil (it just won't attest).

`2-of-2` has no fault tolerance (one down ⇒ no admission); `3-of-5` is more
robust but four extra hosts to run. 2-of-3 is the sweet spot.

## Configuration

**Authority** — no new required flags. Every authority attests automatically
when a relay proposes an epoch, and serves `GET /admissions`. Run three separate
authority instances, each with its own `--authority-key`.

**Relay** — enroll with all of them:

```
gotham-relay run … \
  --authority-url        https://a1.example \
  --extra-authority-url  https://a2.example \
  --extra-authority-url  https://a3.example \
  --advertise-addr <ip:port>
```

Each authority's PoP key is auto-fetched from its own `/pop` (no key by hand).

**App** — pin the set (env, opt-in). Unset ⇒ the single-authority path runs
unchanged (this is the A2-before-A1 transition guard: the app keeps working on
the current single-signed directory until the set is live):

```
GOTHAM_AUTHORITY_SET="https://a1.example@<ed25519_pubkey_hex>,https://a2.example@<hex>,https://a3.example@<hex>"
GOTHAM_AUTHORITY_THRESHOLD=2
```

The first entry is the *primary* (its `/directory` supplies the descriptor
roster); `/admissions` is collected from all three.

**Fail closed, never downgrade.** Once a set is pinned, if fewer than `k`
authorities' `/admissions` are reachable — or the quorum otherwise can't be met —
the app uses the empty fail-safe directory (routes nothing) and does **NOT** fall
back to trusting a single authority's unfiltered roster. Otherwise an on-path
attacker who merely blocks `k−1` of the `/admissions` endpoints could force the
app back to 1-of-1 trust with an unfiltered roster — dissolving the whole feature
from a network position. Refusing to send is safer than sending over
attacker-forced single-authority trust.

## Rollout order (must not break the live app)

**A2 before A1.** Stand up ≥ k authorities FIRST, *then* flip the app to require
quorum. Shipping an app that *requires* k-of-n while only one authority exists
would make it reject the current single-signed directory and break the live
deployment. The env-gate + fail-closed fallback are exactly what let the app
traverse the transition without a cutover.

## Wire additions (all additive / backward-compatible)

- `RelayEnrollment.attest_epoch: Option<u64>` — absent on legacy relays; a legacy
  authority ignores it (serde default), a new authority then issues no
  attestation for that relay (still enrolls, still routable via the blanket
  directory).
- `POST /enroll` response body → `EnrollResponse { attestation, epoch }` (JSON).
  Old relays only check the 2xx status, so the body change is invisible to them.
- `GET /admissions` → `Vec<AdmissionEntry>` (new endpoint).

Shared wire types live in `crypto-gotham-directory::wire` so the authority
(producer) and app (consumer) cannot drift.

## Hardening (from the adversarial review)

- **No silent downgrade** — a pinned quorum that can't be met fails closed (see
  above); it never reverts to single-authority trust.
- **`/admissions` DoS bounds** — the authority attests only the diversity-capped
  roster (not the whole registry) and caches the signed payload for a few
  seconds, so an unauthenticated GET flood can't amplify Ed25519 signing. The app
  caps the `/admissions` response body (16 MiB) and skips attestation groups too
  small to reach quorum, so a hostile response can't amplify its verify work.
- **Operator projected** — the quorum-attested operator label is written onto the
  admitted descriptor, so operator-diversity runs on a quorum-signed value, not
  the single primary's unverified claim.
- **Tighter revocation** — the app drops an admission whose epoch is older than
  3 days (vs the certificate's 30-day freshness), so a network-revoked relay
  falls out of admission in days, not a month.

## Tests

- `crypto-gotham/src/enroll.rs` — epoch bucketing + additive wire.
- `crypto-gotham-relay/src/enroll_client.rs` — one shared epoch, per-authority proof.
- `crypto-gotham-authority/src/main.rs` (`kofn_tests`) — **3 simulated
  authorities** over the real axum handlers via `oneshot`: each attests on
  `/enroll`, serves it on `/admissions`, a 2-of-3 quorum verifies, sub-quorum /
  far-future-epoch / legacy-no-epoch are all rejected.
- The client-side admission core (`kof_*`), in the Crypto application — not
  published in this repository; described here so the protocol side is complete:
  quorum admits, sub-quorum/forged/unknown-authority/stale/wrong-identity/
  operator-mismatch all dropped; `parse_authority_set` shapes.
