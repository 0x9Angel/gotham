# Running a Gotham relay

Read this before you install anything. It tells you what you are agreeing to
operate, what it does and does not do, and what it costs you.

If anything here turns out to be inaccurate, that is a bug in this document and
we want to hear about it.

---

## What a relay actually does

A Gotham relay forwards fixed-size, layered-encrypted packets between other
Gotham nodes. Each packet is 2048 bytes, always, whatever it carries. Your relay
peels exactly one layer of encryption, learns the address of the next hop, and
forwards it.

**Your relay cannot read any message.** Message content is encrypted end to end
between the two people talking, under keys your relay never sees. Peeling your
layer reveals routing information, not content.

**Your relay does not connect to the open internet on anyone's behalf.** This is
the single most important difference from a Tor exit node, and it is the reason
the legal exposure is not comparable. Even the tier named `exit` is the last hop
*inside Gotham*: it delivers to another Gotham participant's mailbox. It never
fetches a web page, never sends mail, never opens a connection to a third-party
service. Your IP address will not appear in someone else's abuse logs as the
apparent source of their traffic, because your relay never talks to them.

## What each tier sees

| Tier | Sees | Does not see |
|---|---|---|
| `entry` | The IP of a Gotham user connecting to it | Who they are talking to, or what they said |
| `mix` | Only the previous and next relay | Any user IP, any content |
| `exit` | The recipient's address inside Gotham | The sender's IP, or any content |

No single relay sees both ends **when a path can be built**. That is the point
of the design, and it is also why one operator running several relays weakens
it: path selection refuses to build a path through two relays it cannot prove
belong to different operators.

**What the table above does not describe is the network as it stands today.**
Building a path needs at least three relays, all three tiers populated, and two
distinct *attested* operators. The current fleet does not meet that, so the
client falls back to depositing into, and collecting from, a mailbox host over
a **direct** connection. In that mode one relay — the mailbox host — sees the
sender's IP and the recipient's IP filed against the same mailbox identifier.
The client logs this fallback loudly, and the code calls it the largest
remaining anonymity leak in the send path.

Message *contents* stay end-to-end encrypted throughout: the host handles
sealed envelopes it cannot open. What is not protected in this mode is the
metadata — who contacted whom, and when. Running one more relay, under an
operator label distinct from the existing ones, is what changes it. That is the
single most useful thing a volunteer can do right now, and it is why this guide
exists.

## Requirements

- A host with a **public IP address**. This is the requirement that matters most,
  so it is worth being blunt about why.

  Behind CGNAT (most home fibre, all mobile 4G/5G), your relay can still join in
  rendezvous mode — and it needs **no inbound port and no port forwarding**, which
  is the whole point of RFC B3. But it then **inherits the operator label and the
  network position of its rendezvous point** for diversity purposes
  (`directory.rs`, `effective operator`). If that rendezvous point is one of the
  relays you are trying to add diversity against, your relay counts as the *same*
  operator and path selection will rarely if ever pick it.

  So rendezvous solves reachability. It does **not** make a home connection a
  source of diversity. If you want to genuinely help the network route, a small
  VPS with its own public IP — at a hosting provider nobody else in the fleet
  uses — is the practical answer, and a free tier is enough.

  Rendezvous mode is also **not automatic**: it requires both `--rendezvous-key`
  (the rendezvous relay's X25519 key) and `--rendezvous-addr`. Without them a
  relay behind a box tries to be directly reachable, fails, and never appears in
  the directory at all.
- One open UDP port. **The default is 443**, not 9101 — the installers use it
  and the relay binary defaults to it. Open the port you actually run on, or the
  relay never appears in the directory.
- Negligible CPU, and **RAM depends on what you host**: around 100 MB for a
  plain relay, but a mailbox host holds its stored envelopes in memory up to a
  512 MB ceiling, so size that machine for ~600 MB rather than 100. A free-tier
  VPS picked against the smaller figure will be OOM-killed while holding other
  people's mail. Bandwidth is what matters most: a relay that carries traffic
  uses it continuously, including cover traffic that exists precisely so idle
  periods are not distinguishable from busy ones.
- Disk, **only if you host a mailbox**: a snapshot of that same set, so up to
  512 MB again, held up to 30 days in the worst case. Read
  [LOGGING-POLICY.md](LOGGING-POLICY.md) before deciding — it says exactly what
  that means for a seized machine, and how to run with nothing at rest.
- A machine you control and can keep patched.

## What you must provide

`GOTHAM_OPERATOR` is **required**. It is a public nickname that says who runs
this relay. The installer refuses to continue without it.

This is not bureaucracy. Path selection fails closed on operator diversity: two
relays that cannot be *proven* to belong to different operators will never share
a path. An unlabelled relay is therefore never selected, and would sit there
consuming your bandwidth for nothing while appearing healthy. A clear failure at
install time beats a silent one forever after.

Pick a name you are willing to have published in the directory, and use the same
one for every relay you run. Do not use someone else's.

## Install

```sh
GOTHAM_OPERATOR=<your public nickname> \
GOTHAM_TIER=<entry|mix|exit> \
sudo -E ./infra/scripts/install-relay.sh
```

The installer enrolls with all three directory authorities. This is required:
clients admit a relay only once **two of three** authorities have vouched for
it. A relay enrolled with one authority looks perfectly healthy to you and is
silently ignored by every client.

## What you are trusting us with

Be clear-eyed about this. Today, all three directory authorities are operated by
the same person (the project author). That means:

- The people who decide which relays exist are not independent of each other.
- If those three hosts were seized or compromised together, the attacker would
  control which relays clients use.

This is a real, current limitation of the network, not a theoretical one. It is
being worked on, and it is written here rather than buried because you deserve
to know what you are joining before you join it.

**And the same is true of the relays.** As of 12 September 2026 the fleet is five
relays across two /16s, **all under one operator label** — the author's. Path
selection fails closed on operator diversity, so it cannot currently build a
diverse entry→mix→exit route at all. The network is therefore running in
mailbox-only mode: the app says so in its own status line rather than claiming an
anonymity it does not have.

Concretely, what your relay changes: **you would be the second independent
operator, and the network needs three.** That is not a reason to stay away — it
is the reason the project needs you — but you should know that anonymity does
not switch on the day you join. It switches on the day the third operator joins.

**There is also one open finding you should hear about before deciding.** The
per-hop MAC authenticates only part of the routing block, so two *colluding*
relays can tag a packet on the way in and recognise it on the way out. Today
that is unexploitable — every relay is ours, and a collusion of one party with
itself reveals nothing new. It stops being harmless the moment the fleet is
genuinely mixed, which is precisely what you would be helping bring about. It is
rated critical, it needs a wire-format change, and closing it before third-party
relays carry real traffic is the project's own commitment to you.

## What we ask of you

- Do not run relays under more than one operator label. Doing so defeats the
  diversity rule and actively harms the anonymity of every user.
- Do not log traffic beyond what the relay logs by default. See
  [LOGGING-POLICY.md](LOGGING-POLICY.md).
- Do not modify the relay to inspect, record, delay, or drop traffic
  selectively. If you want to study the network, say so and we will help you do
  it in a way that does not endanger users.
- Tell us if you are compelled to do any of the above and are permitted to say
  so. See [ABUSE-FAQ.md](ABUSE-FAQ.md).

## Stopping

There is no commitment. Run `uninstall-relay.sh`, or just stop the service. The
directory drops relays that stop sending heartbeats. Please do not disappear
mid-flight if you can help it, but no one will chase you.

---

*This document describes the software as it is, not as we would like it to be.
If you find a claim here that the code does not support, open an issue.*
