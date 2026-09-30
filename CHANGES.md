# PACT — revision history

The internal record of what each version string of `SPEC.md` said about itself. `SPEC.md` carries no history: its header line is the version and the date, and its body reads as the specification as it stands. What changed from one version to the next is here — one entry per version string, newest first, dated by that version's own header line (the date the whitepaper cover reads) and naming the commits that carried it, so the full text of any version is `git show <commit>:SPEC.md`. Where a commit date differs from the header date, both are given.

The wire carries the major alone: `X-PACT-VERSION`, an envelope's `v`, `pact_export`. A revision within a major can still change what an implementation writes or accepts (2.1.3 left an envelope's members one spelling; 2.2.4 renamed `get_card`'s `limits` members). The one tag is `v1.2.0`; no 2.x version has been tagged. Two texts have carried the label 2.1.3.

## 2.2.4 · 2026-09-28 · `5662841`

Sizes the call budgets by the contacts an identity may hold: each budget is a token bucket, a contact may make 1 call a second with a burst of 10, the identity takes its contacts together at their number times that rate, a guest's budget is unchanged and an address alone has one of its own, and `get_card`'s `limits` names the new figures in place of `contact_calls_per_hour` (§12).

## 2.2.3 · 2026-09-28 · `c669db6`

Nothing on the wire: the notice that an export is unencrypted names what the file holds, and a book holds only the contact list (§9.2).

## 2.2.2 · 2026-09-28 · `e444773`, `3d3bd63`, `1ee0306`

Nothing on the wire: an export's manifest lists only its three text members, so the number of files an export can carry is no longer bounded by the manifest's size; the key-material rule reaches the manifest's own strings and the media files; and every time in an export is an RFC 3339 instant in UTC (§9.2). Under the same number: the manifest holds the sha256 of each text member, not of every member (`3d3bd63`); a signing request's `expires` is an RFC 3339 instant in UTC ending in `Z`, with `.` the only fraction separator (§9.1, `1ee0306`).

## 2.2.1 · 2026-09-28 · `2eeda10`

Nothing on the wire: a signing request's fields are held to exact shapes (§9.1); what a contact controls can no longer stop the owner's export — the writer nulls, drops, truncates or leaves out and lists what the reader would refuse — a host's own import ceilings never refuse an export, and an import ends with a request for a new leaf that the host mints and the person completes (§9.2).

## 2.2.0 · 2026-09-27 · `4648358`, `a24d64d`, `2df17f7`

Two things a host and a wallet do between them and nothing to the wire between contacts: a host asks a web wallet for a leaf with a form, and receives the chain in the fragment of its own address (§9.1); and the person's contacts, conversations and files move between hosts as one unencrypted zip that holds no key, whose every member an importer checks before it writes one row (§9.2). A planted row in §14.5. Under the same number: `update_contact` only where the leaf is held, and an attachment has an empty body (§9.2, `a24d64d`); `get_card` carries the chain at the contact tier, as §6.1 and §6.2 say (§14.3, `2df17f7`).

## 2.1.3 · 2026-09-21 · `ccc26d6`; re-dated 2026-09-26 · `2d6770e`, `ff46e42`

Nothing an honest sender writes: an envelope's members have one spelling (§13.1), an issuer key identifier is held to its 32 bytes at card intake as in a chain (§3), a card's writer puts no control character into it (§3), and the address guard judges an IPv6 literal by the IPv4 address inside it (§3). The text then changed twice under the same number: a pending contact lists its tier, and `update_contact` names its refusal (`2d6770e`, 2026-09-24); the wallet's file is the root only, the record holds the ledger, and a lost credential is re-bound (`ff46e42`, committed 2026-09-27 with the header re-dated 2026-09-26).

## 2.1.2 · 2026-09-20 (committed 2026-09-21) · `b347750`

An extension's value is the type it names, and the reference library reads a path length in full.

## 2.1.1 · 2026-09-20 · `5adad82`

A certificate's ECDSA signature is the low-S twin, and a validity field is a date. The header's account of 2.1 from here on: no wire change; the span of a leaf is the person's to choose beneath §14.2's ceiling; a verifier that confirms a pin may not turn an unanswered confirmation into a revocation (§14.3); the host that makes an archive is bound as the host that imports one already was — no key goes into it, and what travels is the person's contacts and conversations and nothing of the host's — and a leaf's key is destroyed when the leaf expires (§9).

## 2.1.0 · 2026-09-19 · `4d954ae`, and eight more commits under the same number the same day

One rule and no wire change: a verifier bounds how long a pin may go unconfirmed (§14.3), which narrows a stolen leaf's reach without a revocation list. Then, under the same number: §14.3's bound is the requirement, not the mechanism (`5c677ee`); §12 points at the record of what holds each rule (`ac21f0a`); who chooses how long a leaf lasts, and who does not (`39295d2`); a newer leaf arrives on use and needs no poll (§14.3, `503a846`); §9 binds the host that makes an archive, not only the one that imports it (`02021c8`); a leaf's key does not outlive its leaf (§9, `649d856`); what moves between hosts is a person's contacts and conversations, and nothing of the host's (§9, `1e60b57`); no tracked file carries a PACT 1.x name, and `npm run vectors:check` fails if one comes back (`b730729`).

## 2.0.0 · 2026-09-17 · `95af027`, `d2fc6eb`

The identity generation: the person is the certificate authority, the host holds a leaf (§2, §3, §5.3, §9, §13, §14), and that root may be derived from a passkey rather than stored (§2.1, §2.2). PACT 1.x is not supported and there is no coexistence mode: `X-PACT-VERSION` is `2`, envelopes are `v: 2`, and a key-pinned identity is refused. The release removed PACT 1.x from the text — Appendix C and its coexistence mode, the `v: 1` envelope, the key-pinned card, the relay role. `d2fc6eb` (2026-09-19): §13.5 no longer cites vectors the removal deleted.

## 2.0.0-draft · 2026-09-12 to 2026-09-17 · `eb6746e` … `582e279`, eighteen commits

First headed "the identity generation: a person-held root, hosting by grant, and a self-certifying identity log (§2, §3, §13, §14, Appendix C)", and re-dated daily. In order: the end-to-end review's corrections (`60fc784`); the person is the certificate authority (`de98f3d`); the review's corrections (`5e7565c`); compromise cases, and the validations that answer them (`b1dc36d`); two sentences the header change had left behind (`1059920`); the certificate and `v: 2` envelope vectors, generated and proven (`8cee1ff`); intrusion scenarios replayed, four rules they found (`188858f`); post-quantum sealing, an exact profile, newest-leaf absolute (`77fd7ed`) — the post-quantum sealing was set aside the same day in the final draft for review (`7bfd8f2`), and §13.5 records the path back; the chain travels once, a fingerprint names it after (`b6a8fd5`); the small form checks the held leaf's validity, guesses are budgeted (`ce9a1bc`); the normal form is checked as written, a result's plaintext is named (`7ab0aa0`); the algorithm identifier inside and outside a certificate are one (`85d0185`); the seed is as strict as the ports, and three rules the prose left to luck (`8567874`); a root may be derived from a passkey, and must be proven before use (§2.1, §2.2, `da0909e`); the wallet is served, not installed, and §9 says so (`aab3daf`); Appendix C's coexistence with 1.x becomes optional and deprecated (`582e279`).

## 1.2.0 · 2026-08-30 · `d130444`, tag `v1.2.0`

Adopts the deployed wire contracts — invite landing (§4), thread ownership (§7), relay verbs (§9), SPKI distribution (§2), rotation grace (§2), preset defaults (§8), tunable limits (§12). The last text of PACT 1: one keypair per person, per agent installation, whose TLS client certificate was the identity; a relay carried mail for an agent that was offline. Every 2.x implementation refuses it.

## 1.2.0-draft · 2026-08-30 · `9e9e92b`

The same note as 1.2.0, released the same day.

## 1.1.0-draft · 2026-08-24 (committed 2026-08-27) · `f4f8fce`, `595dcba`

Adds sealed envelopes (§13), generalized caller identity (§2), relay-mode wording (§9). Then: `FN` is the sender's own claim and carries no authority (`595dcba`). Never released; 1.2.0-draft followed.

## 1.0.0 · 2026-08-23 · `379fbf4`, `58379dc`

First public version: an MCP server per person, mTLS with a pinned key fingerprint, vCard cards, invites, a relay mode. `58379dc` published the text as a GitHub Pages site, retired on 2026-08-28 (`f2e8bb0`).
