# Security policy

PACT carries private messages between people's agents under long-lived identity keys. If you
find a weakness in the specification — a way to forge, replay or misattribute a sealed envelope,
to impersonate an identity or a host, to reach a tool the permission tiers should hide, or a
certificate the §14.1 profile should refuse and does not — report it privately.

**Do not open a public issue for security reports.**

Email: security@pact-protocol.com with subject `[pact-protocol security]`. Say which section
you read against and include a reproduction if you can; a scenario in the shape of those in
`vectors/intrude.mjs` is the most useful form, because it runs against the in-memory node in
`vectors/lib` as it stands. You will get an acknowledgment within 72 hours and a status update
at least every 14 days until resolution.

Please give us reasonable time to ship a fix before public disclosure. Credit is given in
`CHANGES.md` unless you prefer otherwise.

## Scope notes

- The protocol's accepted trade-offs — no forward secrecy at the envelope layer, metadata
  visible to an edge or a tunnel, a lost root is a new identity — are stated in `SPEC.md`'s
  non-goals paragraph and in §13.5, and are not vulnerabilities by themselves.
- `vectors/intrude.mjs` is the list of compromise cases the specification already answers; the
  ones it reports as residual by decision are named as such. A scenario that reproduces against
  `vectors/lib` is a specification finding, not a test to relax.
- Reports about the implementations — the self-hosted node and PACT Cloud, neither public yet —
  go to the same address.
