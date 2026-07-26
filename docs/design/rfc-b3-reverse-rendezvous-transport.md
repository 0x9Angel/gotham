# RFC B3 — Reverse / rendezvous transport for NAT'd relays

Status: **DRAFT / for review** · Author: 0x9Angel · Supersedes the "roadmap B3"
placeholders in `crypto-gotham-relay/src/nat.rs:20,38,89`.

## 1. Problem

A relay behind **CGNAT** (mobile, many home ISPs incl. Freebox with broken
UPnP) has no reachable inbound `ip:port`. Today that is fatal for enrollment and
routing:

- **Enrollment** — the authority proves possession *and reachability* by dialing
  the relay back over QUIC+Noise-XK (`probe_relay_liveness`,
  `crypto-gotham-relay/src/transport.rs:564`, called at
  `crypto-gotham-authority/src/main.rs:199`). A NAT'd relay can't be dialed →
  rejected (`enroll.rs:125` rejects loopback; `advertisement.rs:233` rejects
  unspecified/port-0).
- **Routing** — the next hop's `ip:port` is baked into the Sphinx header by the
  *sender* (`RoutingRecord { next_ipv4, next_port, next_node_id }`,
  `crypto-gotham/src/header.rs:124-128`; dialed directly at
  `crypto-gotham-relay/src/pool.rs:189`). A NAT'd relay has no dialable address
  to bake.

`nat.rs` already detects this (`NatMapping.cgnat`, warn-only) and names the fix.
This RFC is that fix.

## 2. What we can lean on (from the code map)

- **The transport is already full-duplex.** QUIC `open_bi`/`accept_bi` + a
  *bidirectional* Noise `TransportState`. The reverse channel physically exists
  but is unused on the mixnet path: `serve_connection` only reads
  (`transport.rs:865`) and `PooledConnection.recv` is never read (`pool.rs`,
  marked dead-code). **We wire that reverse reader; we do not invent a transport.**
- **Connection reuse exists.** `ConnectionPool` keyed by `(SocketAddr, peer_pk)`
  (`pool.rs:127/184`) — the seam for a long-lived tunnel, but it needs a
  **pubkey-only, non-evictable, keep-alive'd** variant for a rendezvous tunnel.
- **Noise-XK authenticates the responder to the initiator.** The dialer pins the
  server's static key. (`noise_initiator_handshake` transport.rs:517 /
  `noise_responder_handshake` transport.rs:482.)
- **Descriptor fields are additive.** `#[serde(default, skip_serializing_if=…)]`
  is the established pattern (`directory.rs:102` `mailbox`); but a new field must
  also enter the **signed** `canonical_bytes` set (`advertisement.rs:126-146`)
  and bump `WIRE_VERSION` (`crypto-gotham-directory/src/lib.rs:62`), else it is
  forgeable.
- **Selection lives in `directory.rs`** (`PathSelector::pick`,
  `path_diverse`, `apply_diversity_caps`). `route.rs` is a dead stub — ignore it.
  `pick_to_exit` already forces a specific last hop — the mechanism to force a
  hop is present.

## 3. Core design — "the rendezvous is an explicit mix hop"

Let **N** = a NAT'd relay, **R** = a public relay that opts in to serve as N's
**rendezvous**. 

**Tunnel.** N keeps a **persistent outbound QUIC connection to R**, established
with **Noise IK** (not XK) so that **N's static key is authenticated to R**. R
registers the live, authenticated tunnel keyed by N's identity. (IK because the
*initiator* N must be authenticated to R; XK only authenticates the responder.)

**Routing.** When a path needs N, the path selector places **R immediately
before N**: `[ … , h, R, N, … ]`.

- Hop `h → R` is an ordinary forward: R's real `ip:port` + R's identity are baked
  in, R is a normal Sphinx hop and **peels a layer**.
- R's peeled `RoutingRecord` for the next hop carries a **new `VIA_RENDEZVOUS`
  flag** (one spare bit in `header.rs:134`), `next_node_id = N`, and a **sentinel
  `next_addr`** (`0.0.0.0:0`, unused).
- R sees the flag → does **not** dial N. It looks N up in its rendezvous table by
  `next_node_id` and **pushes the opaque, N-encrypted Sphinx packet down N's
  tunnel** (the reverse direction of the connection N opened).
- N's tunnel reader feeds the packet to `Relay::process` as if it arrived inbound;
  N peels its layer and forwards onward over its **own** outbound (N *can* dial
  out — only inbound is blocked).

Why this shape:

- **No inline rendezvous address needed.** The header only has room for a flag,
  not a variable locator — and here it doesn't need one. The N→R binding is used
  only at **path-selection time** (sender reads it from N's descriptor and orders
  the path). Over the wire, R resolves N by the identity it already learns as a
  normal successor.
- **Minimal Sphinx change:** exactly one flag bit; `next_addr` becomes a sentinel
  for that hop. γ still MAC-covers the record, so the indirection can't be
  injected in flight.
- **No new information leak beyond a normal hop:** R learning "my successor is N"
  is what every mix hop knows about its next hop. R cannot read the packet (it's
  Sphinx-encrypted for N).
- **Reuses the whole forwarding machinery;** the only genuinely new send action is
  "push down an existing tunnel" instead of "dial `next_addr`".

## 4. Enrollment / proof-of-possession for N

The IK handshake **already proves to R** that the tunnel holder owns N's static
key. So:

- N enrolls (`POST /enroll`) with `addr` = sentinel and a new
  `rendezvous = { rendezvous_id: R }` field.
- The authority does **not** dial N. It accepts N iff **R attests** — freshness-
  bound (nonce/timestamp) — that "N's IK tunnel is live and authenticated as N".
  R can only attest N's that actually completed IK with it, so R cannot fabricate
  a relay whose key it does not hold (it can only *withhold* service —
  availability, not forgery).
- "Liveness" for N is redefined: **maintains a live tunnel to R** (R heartbeats
  it), not "dialable at addr".

Decision (open to change): rendezvous binding is **authority/R-attested**, not
self-asserted, so a relay cannot claim an arbitrary R or fake liveness. In the
decentralized directory this rides the existing `AdmissionCert` mechanism
(`attestation.rs:138-149`).

> **SECURITY — R-attestation is NOT a possession proof; RESOLVED with an
> end-to-end DH-MAC (adversarial review found the original design exploitable).**
> The IK handshake proves N's possession *to R*, but if the authority merely
> asks R "do you host N?", a **malicious rendezvous relay** (or anyone, in
> open-enrollment mode) can answer "yes" for a key it does not control —
> enrolling arbitrary identities (Sybil) or **overwriting/locking out an existing
> relay's entry** (with a high `seq`).
>
> **Fix (implemented):** N proves possession **directly to the authority**, R
> untrusted. N's `POST /enroll` carries `pop_proof =`
> MAC(`DH(N_sk, authority_pop_pk)`, `kem_pubkey ‖ seq`), where the MAC key is
> `blake3::derive_key("gotham-rendezvous-pop-v1", DH(...))`
> (`RelayEnrollment::pop_tag`). N reaches the authority *outbound* (it already
> does, to enroll) so no inbound is needed; only the holder of `N_sk` can compute
> the DH, so R cannot forge it. The authority derives a **stable** X25519 PoP key
> from its Ed25519 identity (`derive_authority_pop_sk`) and prints its public
> half at startup; a CGNAT relay pins it as `--authority-pop-key`. Binding the
> MAC to `seq` also kills the seq-overwrite/lockout (a captured proof can't be
> replayed for a higher seq). The R-query is kept only as a **liveness** hint
> (is N's tunnel up), which is availability-only, not possession.
>
> **Extended (2026-07-12 audit):** the same possession gap existed for
> **directly-reachable** relays — their only check was the dial-back probe,
> which authenticates *whoever answers at the public `addr`*, not the enroller,
> so an off-path attacker who reads a victim's `(addr, kem)` from the signed
> directory could overwrite/lock-out its entry with a higher `seq`. The DH-MAC
> is therefore now **mandatory on every enrollment path**, verified *before* the
> branch-specific (liveness-only) dial-back or R-query. See §9.

The presence query (`serve_rendezvous_query`, ALPN `gotham-rdvq/1`) is now
**authenticated (2026-07-12)**: it runs Noise-IK and R answers only a querier
whose static key equals the pinned authority PoP key (fail-closed without a
pin), so it is no longer an open presence oracle — see §9.

## 5. Directory / descriptor changes

- `Advertisement` (`advertisement.rs:53-89`): add signed
  `rendezvous: Option<RendezvousBinding>` **and** a `RendezvousCapable` capability
  so an R advertises willingness. Add both to `canonical_bytes`
  (`advertisement.rs:126-146`). Bump `WIRE_VERSION`.
- `RelayDescriptor` (`crypto-gotham/src/directory.rs:77-103`): mirror
  `rendezvous: Option<…>` after `mailbox` (line 102), same additive serde; carry
  it through `Advertisement::to_relay_descriptor` and
  `Roster::to_relay_descriptors`.
- `Advertisement::verify` (`advertisement.rs:241-249`) and the enroll validity
  gate must **branch**: a rendezvous-only relay legitimately has no dialable
  `address`; accept an empty/sentinel addr **iff** `rendezvous` is present.

## 6. Path selection & diversity (anti-Sybil — load-bearing)

- In `PathSelector::pick` (`directory.rs:439-465`): a `ViaRendezvous` candidate N
  is admissible only if its R is **Direct**, present, and inserted immediately
  before N. Add a `rendezvous_reachable` predicate beside the existing
  `path_diverse` check.
- **Diversity inheritance (critical):** N sits behind R's network position, so N
  must **inherit R's /16, /48 and operator** in `pair_diverse` / `network_diverse`
  / `apply_diversity_caps` (`directory.rs:570/601/647`). Otherwise an adversary
  runs many N's behind one R and defeats subnet/operator diversity — the network's
  load-bearing guarantee.

## 7. Threat model (honest)

- **A rendezvous sees its NAT'd relay's inbound traffic** (volume/timing), like a
  Tor bridge sees its client. It cannot read content (Sphinx). Mitigation: cover
  traffic on the N↔R tunnel + keepalive; **multiple rendezvous per N** to spread;
  N's traffic mixed among R's. **Anonymity for a NAT'd relay is therefore weaker
  than for a direct relay** — we state this plainly and do not overclaim.
- **Malicious/unreliable R** — can drop (availability) but not forge N (IK auth).
  N holds ≥2 rendezvous points.
- **Sybil via rendezvous** — bounded by §6 diversity inheritance + caps counted
  against R.
- **PoP replay** — attestation is nonce/timestamp-bound (the current per-key
  monotonic `seq`, `enroll.rs:195`, is *not* possession-bound, so the proof must
  carry its own freshness).
- **Tunnel reaping** — QUIC sets no `keep_alive_interval` today; the tunnel needs
  keepalive/cover and must be **pinned/exempt from pool eviction** (`pool.rs:166`).

## 8. Phased plan

- **Phase 0 — data-model + selection (no live transport; fully unit-testable).**
  `VIA_RENDEZVOUS` flag + sentinel handling in `header.rs`/`process.rs`;
  `rendezvous` field + `RendezvousCapable` on `Advertisement`/`RelayDescriptor`
  (+ canonical bytes, WIRE_VERSION, verify branch); selection predicate + diversity
  inheritance in `directory.rs`. Ships behind selection so nothing routes to a
  rendezvous relay until Phase 2 exists.
- **Phase 1 — the N↔R tunnel.** Noise **IK** primitives; new ALPN `gotham-rdv/1`;
  R-side `RendezvousTable` (pubkey-keyed, non-evictable, keepalive); N-side
  persistent dialer + **reverse reader loop** (wire the dead `recv` half).
- **Phase 2 — rendezvous forwarding.** `ProcessOutcome::ForwardViaRendezvous`;
  R pushes down the tunnel; N's reader feeds `Relay::process`.
- **Phase 3 — enroll/PoP.** `rendezvous`-carrying enrollment; authority accepts on
  R's freshness-bound attestation; liveness redefined.
- **Phase 4 — hardening + adversarial review.** Cover traffic on the tunnel,
  multi-rendezvous, diversity-cap tests, replay tests, traffic-analysis notes.

## 9. Implementation status (2026-07-11)

**Built + tested (unit + in-process end-to-end), `cargo test`/`clippy` green:**
- Data model: `VIA_RENDEZVOUS` flag (`header.rs`), `rendezvous`/`rendezvous_capable`
  on the descriptor, signed `Advertisement` (WIRE_VERSION→3) and enrollment.
- Selection: hosted relays spliced (R immediately before N) with the R→N
  adjacency exempt; **diversity inheritance** (N counts as R's /16 + operator);
  fail-closed on an absent R (dropped from the caps, non-diverse in selection).
- Transport: Noise-IK tunnel (ALPN `gotham-rdv/1`), `RendezvousTable`
  (size-capped), N-side persistent client + reverse reader (bounded, back-
  pressured), R-side accept.
- Forwarding: `Forward { via_rendezvous }` → R pushes down the tunnel; N's drain
  processes + forwards onward. **End-to-end test**: R peels a `VIA_RENDEZVOUS`
  layer → pushes → N (reachable by no one directly) receives + delivers.
- Binary glue: `--rendezvous-key/-addr/-capable`, `--authority-pop-key`; a CGNAT
  relay runs the tunnel client instead of the (unreachable) listener.
- **Enrollment / PoP (secure, enabled by default):** the DH-MAC possession proof
  (`pop_tag`/`verify_pop`, `derive_authority_pop_sk`). **As of the 2026-07-12
  audit the proof is MANDATORY for _every_ enrollment — direct relays too, not
  just CGNAT ones.** Previously a direct relay's only possession check was the
  dial-back probe, which authenticates *whoever answers at `addr`*, not the POST
  originator; since `addr`+`kem` are public directory data, an off-path attacker
  could POST a victim's `(addr, kem)` with a higher `seq` and hijack/lock-out its
  entry. The authority now verifies the DH-MAC (bound to `kem‖seq`) *before* the
  branch-specific liveness check on both paths, so possession is proven by the
  key holder and the dial-back / R-query are liveness-only. Round-trip +
  key/seq-binding unit-tested. **The PoP public key is AUTO-PROVISIONED:** a relay
  not given `--authority-pop-key` fetches it from `GET <authority-url>/pop` on
  startup (it's a public key — a wrong one only fails this relay's own proof,
  never a hijack), so volunteers run the same install one-liner with no key to
  hand-carry. `--authority-pop-key` stays an optional pin that also rules out the
  self-inflicted enroll failure a MITM on the fetch could otherwise cause. A
  transient MITM that poisons the first `/pop` with a well-formed-but-wrong key
  self-heals: on a possession-proof rejection the relay drops the auto-fetched
  key and re-fetches next tick (a pinned key is never dropped). An adversarial
  review confirmed auto-fetch does NOT reintroduce the hijack (forging still
  needs the relay secret) — the only residual was that persistent-DoS, now fixed.

**Hardening landed in the 2026-07-12 audit pass (all tested):**
- Handshake slowloris: every responder handshake read is bounded by
  `HANDSHAKE_READ_TIMEOUT` (10 s) and the accept loop caps concurrent handlers
  (`MAX_INFLIGHT_CONNS`, fail-closed).
- Memory amplification: the sender-chosen per-hop delay is clamped to
  `MAX_HOP_DELAY` (30 s) — a u32 `delay_micros` otherwise permits ~71 min holds.
- Authority DoS: the per-IP rate map is hard-bounded within a window (IPv6
  rotation can't grow it), and outbound liveness probes are concurrency-capped
  (`MAX_INFLIGHT_PROBES`, fail-closed) so `/enroll` can't be a reflection amp.
- Mailbox metadata: the outer (host-facing) seal on a mixnet deposit AND on a
  SURB fetch now uses a throwaway **ephemeral** sender key, not the user's
  identity — the mailbox host no longer learns the depositor/poller identity
  (the recipient still recovers the true sender from the inner seal).
- **`gotham-rdvq/1` presence oracle authenticated (was MEDIUM, now fixed).** The
  query is now **Noise-IK**: the querier presents its static key and R answers
  only if it equals the pinned authority PoP key (`--authority-pop-key`, which
  every relay already holds); no pin ⇒ R answers nothing (fail-closed). The
  authority authenticates with its stable PoP secret. An arbitrary party can no
  longer probe which CGNAT relays are live. Unit test
  `rdvq_presence_query_requires_authority_auth` (authority served, impostor
  rejected).

**Known residuals (tracked):**
- **Rendezvous-table squat (LOW).** Disposable self-generated identities can fill
  `MAX_TUNNELS` (512) and deny hosting to legitimate CGNAT relays. Needs a
  per-source bound or directory-gated admission — degrades availability only, no
  anonymity/integrity impact.

The full B3 path — a CGNAT relay enrolls (DH-MAC), is selected (spliced behind
its R, diversity-inherited), and receives mixnet packets over its reverse tunnel
— is now implemented end to end.

## 10. Non-goals

- Not a general NAT hole-punch (STUN/ICE). Rendezvous is simpler and fits the
  mixnet (R is already a hop).
- Does not make a NAT'd relay as strong as a direct one (see §7).
- No change to the Sphinx crypto beyond one flag bit + a sentinel address.
