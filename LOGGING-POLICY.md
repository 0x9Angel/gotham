# What a Gotham relay records

This document is an inventory, not a promise. Every claim below was checked
against the source in `crypto-gotham-relay/`. If you find a divergence, that is
a bug and we want the issue.

The point of writing it down is simple: an operator who does not know what their
machine stores cannot answer honestly when someone asks, and cannot judge what a
seizure of that machine would expose.

---

## The short version

At the default log level, a relay records **no IP addresses** and **no message
content**. What it holds that matters is the mailbox: sealed envelopes waiting
to be collected, on disk, for up to 7 days.

## Logs

Default verbosity is `info` (`RUST_LOG`, `crypto-gotham-relay/src/main.rs:67`).

At that level the relay emits operational lines: counters of packets forwarded
and dropped, and the reason for each drop (`bad MAC`, `malformed`,
`rate limited`, `replay`, `self-loop`), plus enrollment and connection-limit
events. None of these carry a user identity or an IP address.

**The one identifier that appears** is `peer = <hex public key>`, in the
rendezvous subsystem (`rendezvous.rs:176`, `:188`). It is the long-term public
key of a *relay* keeping a tunnel open through yours, not a user. A third
occurrence at `:198` is `debug!` and is not emitted at the default level.

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
- Default retention is **7 days** (`crypto-gotham/src/mailbox.rs:226`),
  clamped per-deposit between 1 second and the configured maximum.
- The mailbox is **persisted to disk** so a restart does not lose messages
  (`main.rs:394`, "loaded mailbox snapshot from disk"). It survives reboots. It
  is on your filesystem.
- Fetching requires a possession proof; a bad proof is refused and logged.

What this means concretely: a machine seized today holds up to a week of
encrypted envelopes, plus the mailbox identifiers they are filed under. The
content is not readable. The identifiers and the timing are metadata, and we do
not pretend otherwise.

## Replay protection

The relay keeps a bounded, time-limited set of recently seen packet identifiers
to reject replays (`replay.rs`). It is in memory, bounded in both size and time.
It is not a traffic log and is not written to disk.

## What we deliberately do not do

- No per-user records, accounts, or persistent identifiers of people.
- No connection log with source addresses.
- No content storage in readable form, anywhere, at any point.

## If you want less

You can run a relay with the mailbox disabled. It will still forward traffic and
still be useful, and it will hold nothing at rest beyond its own keys. If
storing other people's encrypted mail on your disk is not something you are
comfortable with, this is the honest option and nobody will think less of you
for it.

---

*Checked against the source on 2026-08-03.*
