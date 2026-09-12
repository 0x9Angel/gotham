# Abuse, complaints and legal requests

For people running a Gotham relay who have been contacted by a hosting provider,
a police force, or anyone else.

**This is not legal advice.** It is a description of how the software works, so
that you can answer accurately. For advice about your own situation in your own
country, talk to a lawyer. Links to organisations that help relay operators are
at the end.

---

## First, the thing most complaints get wrong

Gotham relays do **not** connect to the open internet on behalf of users. Not
even the tier called `exit`.

A Tor exit node fetches web pages, sends mail, and opens connections to
third-party services, which is why its IP shows up in other people's abuse logs.
A Gotham `exit` relay is the last hop *inside the Gotham network*: it hands the
packet to another Gotham participant's mailbox and stops there.

So if you receive a complaint saying your server attacked a host, scanned a
network, sent spam, or downloaded something, **your relay did not do that**. Either
the complaint is misattributed, or something else on your machine is
compromised. Check the second possibility seriously before replying.

## What you can truthfully say

- The service forwards fixed-size encrypted packets between nodes of a privacy
  network. It does not originate connections to third-party services.
- You cannot read the traffic. It is end-to-end encrypted between users under
  keys the relay never holds.
- You do not keep a log of source addresses. See
  [LOGGING-POLICY.md](LOGGING-POLICY.md) for exactly what is and is not recorded.
- You cannot identify a user from a packet, and neither can we.

Do not overstate this. If your relay runs a mailbox, it does hold encrypted
envelopes on disk — **7 days by default and up to 30 in the worst case**, since
the sender sets the lifetime and the relay only clamps it — and it does hold the
mailbox identifiers they are filed under. Say so if asked, and say 30 rather than
7 if you are asked for a maximum. A claim that turns out to be false is far worse
for you than an inconvenient truth.

## Template: reply to a hosting provider

> Hello,
>
> The server at <IP> runs a relay for Gotham, a privacy-preserving messaging
> network. The service forwards fixed-size encrypted packets between nodes of
> that network.
>
> It does not open connections to third-party services on behalf of users, and
> it does not act as a proxy or VPN exit to the public internet. It therefore
> cannot be the origin of the activity described in your notice. I would be glad
> to see the timestamps and destination addresses you have, so I can check
> whether my host has been compromised by something unrelated.
>
> The relay software is open source (AGPL-3.0) and its logging behaviour is
> documented here: <link to LOGGING-POLICY.md>. I do not retain source IP
> addresses and cannot identify individual users.
>
> I am happy to answer further questions.

Adapt it. Do not send it if it is not true of your setup.

## If you receive a legal order

1. **Do not panic and do not wipe anything.** Destroying data you have been
   ordered to preserve can be a far more serious offence than anything the order
   is about.
2. **Get a lawyer** before responding, if you can at all.
3. **Read what is actually being asked.** An order to hand over data you do not
   have is answerable by saying that you do not have it.
4. **Tell us, if you are allowed to.** Some orders forbid disclosure; respect
   that. If you are permitted to say something, open an issue or contact us. If
   you are not, you are not.

We ask you not to modify your relay to start recording traffic, but we recognise
that a court can order you to do things we cannot override. If that happens and
you are permitted to say so, tell us so we can warn users. If you are compelled
into silence, stopping the relay is always a legitimate choice, and one nobody
will question.

## Warrant canary

The project does not currently publish a warrant canary. Saying so plainly is
better than the alternative: a canary that has never been meaningfully
maintained gives users false confidence. If this changes it will be announced.

## Reducing your own exposure

- Run the relay on a machine that does nothing else.
- Run it without the mailbox if you would rather hold nothing at rest.
- Keep the default log level. Do not run at `debug` in production.
- Set journal retention to something short in `journald.conf`.
- Use a hosting provider whose terms actually permit privacy infrastructure, and
  read those terms before you start rather than after a complaint.

## Reporting abuse of the network itself

If you believe Gotham is being used to harm someone, we want to know, and we
will be honest about what we can do. The design means we cannot read messages or
identify users. We can act on the parts we do control: the software, the
directory, and relay admission. Open an issue or contact the address in
`SECURITY.md`.

We would rather say "here is precisely what we can and cannot do" than promise a
moderation capability that the architecture does not permit.

**What has changed since this document was first written.** Because the publisher
cannot read anything, the useful controls are the ones in the hands of the person
being harmed — and those did not exist in August. They do now:

- **Blocking.** A user can block a contact. Inbound envelopes from that peer are
  refused *before* decryption, presence stops being broadcast to them, and a live
  call is torn down. Blocking is a local decision; no relay is involved and the
  blocked peer is not told.
- **Reporting.** A user can record a report locally: a hash-chained journal
  inside the encrypted database, signed **with the user's own key**. Be precise
  about what that buys, because the distinction matters to anyone who takes it
  to a lawyer: it is an *integrity* control, not proof of authorship. It shows
  that an entry has not been altered after the fact relative to the rest of the
  chain. It does **not** prove the peer wrote the quoted text, and it cannot
  prove the owner did not compose the entry themselves — a signature made with
  your own key is one you can always remake. Nothing is transmitted to the
  publisher. It is a record the user controls, not a moderation queue and not a
  forensic attestation.
- **A written notice-and-action procedure**, as Article 16 of the EU Digital
  Services Act requires, with response deadlines and a route to appeal. It also
  states plainly what we cannot do, and points to the authorities that can act —
  in France, PHAROS, plus 119 for a child at risk and 3018 for online harassment.

None of this asks a relay operator to do anything, and none of it lets anyone —
including us — read a message. It is here so that you can answer accurately if
someone asks what recourse a victim has: the answer is no longer "nothing".

## Organisations that help relay operators

- **Electronic Frontier Foundation** (US) — has long-standing guidance for Tor
  relay operators, much of which transfers.
- **La Quadrature du Net** (France) — digital rights, familiar with these
  questions.
- **European Digital Rights (EDRi)** — network of European organisations.
- Your national digital rights organisation, if you have one.

---

*Last reviewed 2026-09-12. If a claim here no longer matches the code, open an
issue: an inaccurate FAQ is worse than none. This review corrected the mailbox
retention figure — the ceiling is 30 days, not 7 — and added the recourse now
available to users.*
