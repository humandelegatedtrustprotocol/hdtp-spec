# SEP-NNNN: Title

| | |
|---|---|
| Status | Draft |
| Author | Name <email> |
| Created | YYYY-MM-DD |
| Target | the version this aims at, e.g. 1.1 |

## Summary

One paragraph: what changes, for whom.

## Motivation

The problem, shown: what an implementation or a person cannot do today, or does wrongly, and how
that was observed.

## Specification changes

Each section of `docs/specification/draft/` this touches, and each MUST it adds, changes or
removes, quoted.

## Wire

Whether an implementation of this SEP still interoperates with one that does not. If it does not,
which of `X-HDTP-VERSION`, an envelope's `v` or an export's `hdtp_export` moves, and why the break
is worth it.

## Security

What this changes for the cases of §14.5 and the trade-offs of §11 and §13.5. A new compromise case
is written as a scenario of `vectors/intrude.mjs`.

## Alternatives

What else was considered, and why not.

## Evidence

How the change is held: vectors, intrusion scenarios, identity-library tests. A SEP that cannot be
held by any says so.
