# HDTP — revision history

What each released version of the specification changed. The text of a version is
`docs/specification/<X.Y>/`; its index page's version line is the version and the date, and its
body reads as the specification as it stands and names no version of its own history.

The wire carries the major alone: `X-HDTP-VERSION`, an envelope's `v`, `hdtp_export`. A version
within a major can still change what an implementation writes or accepts; each entry says whether
it does.

The versions published before the rename, 1.0.0 of 2026-08-23 to 2.2.5 of 2026-09-30, are recorded
as they were written in `docs/release/changes-before-hdtp.md`, a dated record kept byte for byte.

## 1.1.0 · not yet released

The lines the draft carries for its release. A reader takes every line after `X-HDTP-CERT` that
starts no property into its value, blank lines included, and removes every space, tab, CR and LF from
it (§3, *Reading a card*; SEP-0001), so a card whose folding a chat or a mail client damaged reads.
Writers do not change. A reader of this version accepts every card a reader of 1.0 accepts, read the
same, and also a certificate with a space or a tab inside it, which 1.0 refuses.

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
