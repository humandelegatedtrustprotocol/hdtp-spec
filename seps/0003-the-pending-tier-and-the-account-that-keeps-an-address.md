# SEP-0003: The pending tier's refusal, and the account that keeps a left address

| | |
|---|---|
| Status | Accepted (2026-10-07) |
| Author | Sumit Agrawal <security@hdtp.io> |
| Created | 2026-10-07 |
| Target | 1.0, amending 1.0.0 in place, as SEP-0002 did |

## Summary

Two sentences of 1.0.0 disagree with the rule they sit beside or with the hosts that hold them. A
caller at the pending tier that calls anything but `contact_accepted` or `contact_rejected` is refused
`pending_approval`, as §6.1 requires; §6.2 and §12 say `permission_denied`, and the node's plain door answers it.
A host keeps a left address for 24 hours for the account that held it, which a host may give to
several people, not for the person alone.

## Motivation

§6.1: every other call from a caller at the pending tier **MUST** answer `pending_approval`. §6.2's
*Results* and §12's `permission_denied` row give that tier `permission_denied` for a tool it cannot
see. The seed (`vectors/lib/envelope.mjs`) and the intrusion scenario "a contact still pending_out
cannot message before accepting" follow §6.1, and so does BatonDeck on the wire, where its core answers
a pending caller's other calls before dispatch; the node's plain door follows §6.2.
A caller that is told `pending_approval` knows its request still waits; `permission_denied` tells it
nothing it can act on.

§9.#4 forbids assigning a held address to another person's identity. BatonDeck keeps a left address
for the workspace that held it, and on a workspace of several people a colleague's identity may take
it inside the 24 hours, which the sentence forbids. A host knows its accounts; it need not know
which identities of a shared one are one person's.

## Specification changes

In `docs/specification/1.0/` and identically in `draft/`:

§6.2 *Results*: "`blocked_or_unknown` at the guest tier, `permission_denied` at the pending and
contact tiers" becomes "`blocked_or_unknown` at the guest tier, `pending_approval` at the pending
tier (§6.1), `permission_denied` at the contact tier".

§12, the `permission_denied` row: "At the pending or contact tier" becomes "At the contact tier".

§9 *Hosting*, "What a host must do when the person leaves". The MUST

> Whenever an identity leaves an address, deleted or moved, the host keeps the address for the
> person for 24 hours: in that time it **MUST NOT** be assigned to another person's identity, and the
> person may take it for any identity of theirs; after them the host frees it.

becomes

> Whenever an identity leaves an address, deleted or moved, the host keeps the address for 24 hours
> for the account that held it — the person's, or one the person shares at the host: in that time it
> **MUST NOT** be assigned to an identity of another account, and any identity of that account may
> take it; after them the host frees it.

One MUST changes (9.#4, which keeps its place); none is added or removed. §6.1's MUST is unchanged.

## Wire

The `code` a pending-tier caller reads changes from `permission_denied` to `pending_approval`. A host
that answered `permission_denied` there did not conform to §6.1 and does not conform to this text. A
host that kept an address for the person conforms where all of the person's identities at it are in
one account.

## Security

`pending_approval` tells a caller at the pending tier only what it knows: it sent the request. A
guest still gets `blocked_or_unknown` for everything it cannot call. A colleague who takes a held
address answers under another root, so §5's *An address that belongs to someone* applies to every
contact of the identity that left, as it does after the 24 hours.

## Alternatives

- **Make §6.1 say `permission_denied`.** The seed, its intrusion scenario and the repair a caller
  makes on `pending_approval` all rest on §6.1; the hosts are the side that is wrong.
- **Keep the hold for the person.** On a shared account a host would have to tell which identities
  are one person's, which nothing else in the protocol asks of it.

## Evidence

The seed answers `pending_approval` at the pending tier today. The node gains a test of a pending-tier
call to a contact-tier tool on the plain door, and BatonDeck one of its dispatcher's refusal, which
the wire does not reach. hdtp-identity's MUST registry moves
9.#4's hash and names the host; BatonDeck's `docs/must-holders.json` names `address-hold.test.ts`.
