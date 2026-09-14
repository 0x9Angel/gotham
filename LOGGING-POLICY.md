# What a Gotham relay records

This document is an inventory, not a promise. Every claim below was checked
against the source in `crypto-gotham-relay/`. If you find a divergence, that is
a bug and we want the issue.

The point of writing it down is simple: an operator who does not know what their
machine stores cannot answer honestly when someone asks, and cannot judge what a
seizure of that machine would expose.

---

## The short version

At the default log level, a relay records **no user IP addresses** and **no
message content**. What it holds that matters is the mailbox: sealed envelopes
waiting to be collected, on disk, for up to 7 days by default — and up to 30 if
the sender asks for it. It also keeps its replay-protection set on disk — opaque
per-packet MACs with timestamps, the last few minutes only, owner-readable —
so a restart does not reopen the replay window. See "Replay protection" below
for exactly what that file does and does not say.

## Logs

Default verbosity is `info` (`RUST_LOG`, `crypto-gotham-relay/src/main.rs:67`).

At that level the relay emits operational lines: counters of packets forwarded
and dropped, and the reason for each drop (`bad MAC`, `malformed`,
`rate limited`, `replay`, `self-loop`), plus enrollment and connection-limit
events. None of these carry a user identity or an IP address.

**Two identifiers do appear**, both belonging to *relays* rather than users, and
only if you run in rendezvous mode:

- `peer = <hex public key>` in the rendezvous subsystem (`rendezvous.rs:176`,
  `:188`) — the long-term public key of a relay keeping a tunnel open through
  yours. A third occurrence at `:198` is `debug!` and is not emitted by default.
- `r = <ip:port>` (`rendezvous.rs:219`, `:220`, `:241`) — the address of the
  rendezvous relay **your** relay dials when it is itself behind CGNAT. This is
  an IP address, at `info` level. It is the address of a public relay, not of any
  user, and it is already in the signed directory for anyone to read. We correct
  it here because an earlier version of this document said "no IP addresses"
  without qualification, and that was not exactly true.

**Raising the level is not neutral.** `RUST_LOG=debug` or `trace` will emit
substantially more, and you should assume it becomes identifying. Do not run a
production relay above `info` unless you are debugging, and lower it again
afterwards.

**Logs go to the systemd journal**, so their retention is whatever your host is
configured for. Check `journalctl --disk-usage` and your `journald.conf`. If you
want them gone quickly, set `MaxRetentionSec` there. We do not manage this for
you and cannot.

## Mailbox contents

If your relay runs with the mailbox enabled, it stores **sealed envelopes** for
recipients who are not currently online.

- The envelopes are encrypted. Your relay cannot read them.
- Default retention is **7 days**, but the sender sets the lifetime per deposit
  and the relay clamps it to a **30-day maximum**
  (`default_ttl_secs` / `max_ttl_secs`, `crypto-gotham/src/mailbox.rs`). So the
  honest worst case is 30 days, not 7. Judge your exposure on 30.
- The mailbox is **persisted to disk** so a restart does not lose messages
  (`main.rs:394`, "loaded mailbox snapshot from disk"). It survives reboots. It
  is on your filesystem.
- Fetching requires a possession proof; a bad proof is refused and logged.

What this means concretely: a machine seized today holds **up to 30 days** of
encrypted envelopes in the worst case — a week for a typical deposit — plus the
mailbox identifiers they are filed under. The content is not readable. The
identifiers and the timing are metadata, and we do not pretend otherwise.

Be concrete about what that metadata is worth to whoever holds the disk,
because "identifier" sounds more anonymous than it is. A mailbox id is derived
from the recipient's public key, and that key travels in every invitation and
every contact card. So an investigator who already has a person's contact card
can compute their mailbox id and show that this person received mail on this
relay, and when. It does not reveal who wrote to them, or what was said. It
does place a named individual on your machine at given times.

**There is no flag to shorten this.** The 7-day default and the 30-day ceiling
are compiled in (`MailboxPolicy::default()`); the relay exposes `--mailbox`,
`--mailbox-store` and `--allow-unauthenticated-mailbox-fetch`, and nothing that
tunes the lifetime. We would rather say so than let you search for an option
that is not there.

Your two real levers are:

- **Omit `--mailbox-store`.** The mailbox then lives in memory only. It still
  works, and a reboot wipes it — nothing survives on your filesystem. The
  trade-off is stated in the flag's own help: messages held for offline peers
  are lost on restart.
- **Omit `--mailbox` entirely.** See the last section.

## Replay protection

The relay keeps a bounded, time-limited set of recently seen packet identifiers
to reject replays (`replay.rs`). Each entry is the packet's 16-byte per-hop MAC
and the second it was seen. Nothing else: no address, no size, no next hop, no
content. Entries expire after `--replay-ttl-secs` (300 by default).

**As of this version the installers keep that set on disk**, at
`--replay-cache-path` (`/opt/gotham/state/replay.bin` on Linux). This is a
security change, not a logging one, and it is worth being precise about both
halves.

Why it exists: the set used to live only in memory, so every restart — an
upgrade, a reboot, a crash — forgot every packet the relay had seen. A packet
captured before the restart and replayed after it was accepted as new. Replay
detection that stops working across restarts is not replay detection, and the
restarts are not something an attacker has to cause; they happen on their own.

What the file is, and is not: it is a list of opaque 16-byte values with
timestamps, covering at most the last few minutes, owner-only (`0600`), written
atomically, and read once at start. It does record that *some* packet passed
through this relay at a given second. It does not record whose, from where, or
to where — the MAC is not linkable to a sender, a recipient or a message by
anyone who does not already hold the packet. On a seized machine it says "this
relay carried traffic at these seconds", which the fact of running a relay
already says.

If you would rather hold nothing at all at rest, drop `--replay-cache-path`
from the service definition. The relay then logs, once at start, that its
replay protection will not survive a restart. That is the trade you are
making, and it is yours to make.

## What we deliberately do not do

- No per-user records, accounts, or persistent identifiers of people.
- No connection log with source addresses.
- No content storage in readable form, anywhere, at any point.

## If you want less

You can run a relay with the mailbox disabled. It will still forward traffic and
still be useful, and it will hold nothing at rest beyond its own keys and the
replay set described above — drop `--replay-cache-path` too and it is the keys
alone. If storing other people's encrypted mail on your disk is not something
you are comfortable with, this is the honest option and nobody will think less
of you for it.

A middle path, if you do want to help offline delivery: keep `--mailbox` and
drop `--mailbox-store`. The mailbox is then memory-only — useful while your
relay is up, gone on reboot, never written to your disk.

---

*Checked against the source on 2026-09-12. The previous review was 2026-08-03;
re-checking it corrected two understatements — the mailbox ceiling is 30 days
and not 7, and `info` does log one relay IP address in rendezvous mode. Both are
described above. If you find another divergence, that is a bug and we want the
issue.*
