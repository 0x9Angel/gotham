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

No single relay sees both ends. That is the entire point of the design, and it
is also why one operator running several relays weakens it: path selection
refuses to build a path through two relays it cannot prove belong to different
operators.

## Requirements

- A host with a **public IP address**. Behind CGNAT (most home fibre, all mobile
  4G/5G), your relay can still run in rendezvous mode, but it will inherit the
  operator and network of its rendezvous point for diversity purposes, which
  means it will rarely if ever be selected. If you want to genuinely help, a
  small VPS is the practical answer.
- One open UDP port (9101 by default).
- Roughly 100 MB of RAM and negligible CPU. Bandwidth is what matters: a relay
  that carries traffic will use it continuously, including cover traffic that
  exists precisely so idle periods are not distinguishable from busy ones.
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
