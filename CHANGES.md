# HDTP — revision history

What each released version of the specification changed. The text of a version is
`docs/specification/<X.Y>/`; its index page's version line is the version and the date, and its
body reads as the specification as it stands and names no version of its own history.

The wire carries the major alone: `X-HDTP-VERSION`, an envelope's `v`, `hdtp_export`. A version
within a major can still change what an implementation writes or accepts; each entry says whether
it does.

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
