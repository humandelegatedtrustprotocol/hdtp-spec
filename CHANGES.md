# HDTP — revision history

What each released version of the specification changed. The text of a version is
`docs/specification/<X.Y>/`; its index page's version line is the version and the date, and its
body reads as the specification as it stands and names no version of its own history.

The wire carries the major alone: `X-HDTP-VERSION`, an envelope's `v`, `hdtp_export`. A version
within a major can still change what an implementation writes or accepts; each entry says whether
it does.

The versions published before the rename, 1.0.0 of 2026-08-23 to 2.2.5 of 2026-09-30, are recorded
as they were written in `docs/release/changes-before-hdtp.md`, a dated record kept byte for byte.

## 1.1.0-draft

An export carries the conversations a person had with former contacts (§9.2, SEP-0004). A new
optional member, `removed.csv` (`root,name,display_name`), names each root that was ever active and
is no longer a contact, by its root and the two names last known for it; a thread's and a message's
`contact` may be one of its roots. A removed row is not a contact: an importer never writes it as one
and never calls it. `counts.removed` and `files`' `removed.csv` are present with the member and only
with it, so a file without one is a 1.0 file; a 1.0 importer refuses a file that has one. This
changes what an implementation writes and accepts. §3's stripping of `FN` reaches a row's
`display_name`, and §14.5's planted row names the removed conversation as its residual.

In §14.5, the row for a stolen leaf key said the key "speaks only from its one address". It is
*reached* only there: a receiver verifies a chain against the endpoint it pinned, never against where
a call came from, so until the renewal reaches a contact the thief calls that contact as the person
from anywhere, in either form of §13.2, and opens what the contact still seals to the key. The row now
says so, in both columns; no requirement changes. `vectors/intrude.mjs` gained the six scenarios that
measure it: the stolen key in the small form, before and after the renewal is learned; an envelope
sealed to the superseded key opening at the host (§2) and for whoever holds that key; and what a
contact seals to once the renewal has reached it, with the thief replaying the superseded chain.

## 1.0.0 · 2026-10-03

The first release. An identity is the fingerprint of a self-signed root certificate the person
holds, derived from a passkey or kept in a wallet (§2); a host serves it under a leaf the root
issued for one address, valid for at most 398 days (§14). Contacts are vCards carrying the leaf
(`X-HDTP-VERSION:1`, `X-HDTP-CERT`, `X-HDTP-SEAL`, §3), added by invite and human approval (§4, §5);
everything a contact may do is an MCP tool behind per-contact permissions (§6, §8). Calls may be
sealed end to end, HPKE Base with `info` `HDTP-SEAL-v1` and a detached signature, in an envelope
whose header has `v` 1 (§13). A person can move between hosts, taking an export of their contacts and
conversations, and a host that is left deletes what it held (§9).
Appendix B carries the vectors, generated from the seeds `hdtp-1.0-vectors/{label}`.

Amended on 2026-10-04, before HDTP went live, in this version rather than a new one: a root may
carry an end date its person chooses, and has none by default (§14.1). Chain validation refuses a
chain whose root is past its end date, and a leaf whose `notAfter` is after its root's (§14.2 rule 4);
a wallet signs nothing under such a root and ends a leaf no later than its root (§2.2). Appendix B
gained a root with an end date, three leaves under it and five chain cases. An implementation of
this version from before the amendment refuses, by rule 1, every chain whose root has an end date.

Amended again on 2026-10-05, before HDTP went live, in this version: a reader takes every line after
`X-HDTP-CERT` that starts no property into its value, blank lines included, and removes every space,
tab, CR and LF from it (§3, *Reading a card*; SEP-0001), so a card whose folding a chat or a mail
client damaged reads. Writers do not change. An implementation of this version from before the
amendment refuses such a card, and a certificate with a space or a tab inside it.

Amended on 2026-10-06, in this version: an address belongs to the hosting, not to the identity
(§9; SEP-0002). Whenever an identity leaves an address, deleted or moved, the host keeps the address
for the person for 24 hours, for any identity of theirs, and then frees it; it was held until the
last leaf issued for it expired. The root is the person's and is not touched. The MUST only
relaxes: a host of this version from before the amendment conforms to it.

Amended on 2026-10-07, in this version (SEP-0003): a caller at the pending tier is refused
`pending_approval` for a tool it cannot call, as §6.1 required; §6.2 and §12 had said
`permission_denied`. A host keeps a left address for the account that held it, which may be one the
person shares at the host, rather than for the person (§9). A host of this version from before the
amendment that answered `permission_denied` there does not conform to it; one that kept an address
for the person conforms where all of the person's identities at it are in one account.
