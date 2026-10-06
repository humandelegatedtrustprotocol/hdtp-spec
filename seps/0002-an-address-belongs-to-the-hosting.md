# SEP-0002: An address belongs to the hosting

| | |
|---|---|
| Status | Accepted (2026-10-06) |
| Author | Sumit Agrawal <mr.sumitagrawal.17@gmail.com> |
| Created | 2026-10-06 |
| Target | 1.0, amending 1.0.0 in place, as SEP-0001 did |

## Summary

§9 holds every address an identity has vacated until the last leaf issued for it expires, up to
398 days. This SEP makes an address the hosting's, not the identity's: whenever an identity leaves
an address, deleted or moved, the host keeps it for the person for 24 hours, for any identity of
theirs, and then frees it. The identity is its root, which stays the person's, to issue a later leaf
from at any host and address, or not.

## Motivation

Observed on 2026-10-06 on BatonDeck's staging: an identity was deleted, its leaf had a year to run,
and its name was refused to everybody, the person who deleted it included, until 2027-10-05. The
leaf's key was destroyed with the identity (§9), so nothing answered under it; the hold kept a name
from people who wanted it. A contact pins a root, not an address, so a later holder of the address
is a stranger to every contact of the first (§5) whether the address was held or not. The 24 hours
let a person who deleted or moved by mistake take the address back.

## Specification changes

§9 *Hosting*, "What a host must do when the person leaves", in `docs/specification/1.0/` and
identically in `draft/`. The MUST

> An address an identity has vacated **MUST NOT** be assigned to another identity until the last
> leaf issued for it has expired, so a contact that missed the move never reaches a stranger where
> it expects a friend.

becomes

> Being left — the person deleting the identity at this host — ends the hosting and nothing else. An
> address belongs to the hosting, not to the identity, which is its root: the leaf, its key and the
> records go, and the root stays the person's, to issue a later leaf from at this host or another,
> or not. Whenever an identity leaves an address, deleted or moved, the host keeps the address for
> the person for 24 hours: in that time it **MUST NOT** be assigned to another person's identity,
> and the person may take it for any identity of theirs; after them the host frees it. A later
> holder of an address is another root, which a contact that pinned this one treats as a stranger
> (§5).

§14.5, the row *A former host's leaf*: "the address is not reassigned until the leaf expires"
becomes "a later holder of the old address, which a host frees 24 hours after the identity leaves
it, is another root, never auto-accepted by a contact that pinned the address for this one (§5)".

One MUST is narrowed; none is added or removed, and it keeps its place in §9 (9.#4).

## Wire

Nothing on the wire changes. The MUST only relaxes: a host that holds an address until its last
leaf expires conforms to both texts.

## Security

A later holder of a freed address answers under another root, so §5's *An address that belongs to
someone* applies: it is never auto-accepted and is shown beside the contact who held the address.
The intrusion battery's case "former host squats the vacated address with its own root and Alina's
name" is that rule and is unchanged. What is given up: a contact that missed a move or a deletion
and dials the old address after the 24 hours reaches the later holder's server, which a WebPKI
server certificate does not tell apart (§2, server side); a call it seals is sealed to a leaf key
the later holder does not have.

## Alternatives

- **Keep the hold until the last leaf expires.** It protects what the root pin already protects, and
  keeps the name from its own person.
- **Free a deleted identity's address at once.** A person who deleted by mistake would lose the
  address to the next claimant; a deletion and a move leave an address the same way.

## Evidence

A host's allocation policy is no library's to hold, so hdtp-identity's MUST registry names the host.
BatonDeck's tests run the same cases after a deletion and after a move: inside 24 hours the address
is taken by an identity of the same workspace and refused, with the time it frees, to another
workspace; after them another workspace takes it.
