## 12. Errors, limits, conformance

**Errors.** Each code below is the `code` of a refusal: a tool result with `isError: true` whose text is a JSON object (§6.2). A refusal carries `code` and, for the two codes that say so, one more member.

| Code | Meaning |
|---|---|
| `unknown_contact` | The call needs a contact or a request the receiver does not hold for the caller — for example, `contact_accepted` from a caller the receiver sent no request to |
| `pending_approval` | The caller is at the pending tier and the call is not one of its tools (§6.1); a `request_contact` repeated while the first still waits; a contact at a new address under `ask` (§5.3) |
| `permission_denied` | At the pending or contact tier, a tool the caller may not use, or one that does not exist (§6.2, §8) |
| `invite_invalid` | An invite token that is unknown, expired, revoked or used up (§4) |
| `blocked_or_unknown` | At the guest tier, a tool the caller may not use, or one that does not exist: one answer for every case, so that a guest cannot tell them apart |
| `too_large` | A string or a decoded `data` past its bound (§6.2) |
| `rate_limited` | A call budget is spent (below). It carries `retry_after`: whole seconds, at least 1, until the budget holds a call again |
| `unavailable` | The host cannot serve the call now: a tool it is temporarily withholding, a capability it does not have, or a bound on the contacts or requests an identity holds (below) |
| `bad_request` | An argument that is absent, of the wrong type or not among the values allowed (§6.2), or a card refused at intake (§3) |
| `seal_required` | An identified caller's unsealed substantive call to a recipient whose card says `X-HDTP-SEAL: required` (§13.3) |
| `identity_required` | No usable identity proof where one is needed (§13.3) |
| `envelope_invalid` | An envelope that is malformed, misdirected, mis-signed, expired or fingerprint-mismatched, or whose chain fails §14.2 |
| `seal_not_accepted` | A sealed call to a recipient whose card says `X-HDTP-SEAL: none`: the sender was told not to seal (§13.4) |
| `certificate_renewed` | An envelope sealed to a leaf key this endpoint once held and holds no longer. It carries `data`, `{"chain": [leaf, root]}`: the current chain, which the caller validates against its pin before it seals again (§14.4) |
| `chain_required` | An envelope that named its sender's leaf by fingerprint and could not be verified against a leaf the receiver holds; it carries nothing more, and the sender sends again with its chain (§13.2) |

**Limits are defaults — operator-tunable, and discoverable:** the numbers below are what an untuned host enforces; an operator may raise or lower them, and the values in force are advertised as the `limits` object of the `get_card` result. Every byte count is of UTF-8, or of decoded bytes for media.

| `limits` member | What it bounds | Default |
|---|---|---|
| `text_bytes` | a `send_message` `text` | 16384 |
| `note_bytes` | a `request_contact` `note`, and a `contact_rejected` `reason` | 1024 |
| `media_inline_bytes` | a `send_media` `data`, decoded; larger media go by `url` | 5242880 |
| `availability_slots` | the slots one `check_availability` answer holds (§6.2) | 5 |
| `invite_ttl_days` | the longest lifetime, in days, an invite may be given (§4) | 90 |
| `contact_calls_per_second` | the per-contact budget's rate (below) | 1 |
| `contact_burst` | the per-contact budget's burst | 10 |
| `identity_calls_per_second` | the per-identity budget's rate | the number of contacts the identity may hold, times `contact_calls_per_second`, or less where the host cannot sustain that |
| `guest_calls_per_hour` | the guest budget, per address and root | 10 |
| `guest_source_calls_per_hour` | the budget of a source address alone | 60 |

A certificate is at most 4 KiB, and a chain is exactly two certificates (§14.2). A host MAY bound the contacts an identity holds — its active contacts and the requests it has sent — and the requests waiting for its owner; a `redeem_invite` or `request_contact` past either bound is answered `unavailable`, and neither bound is advertised.

**Call budgets are sized by the contacts an identity may hold,** so that the people it knows are not throttled for talking to it at once. Every budget is a token bucket — a sustained rate and a burst: a bucket holds at most its burst in calls, refills at its rate, and a call it has no whole call for is answered `rate_limited` with `retry_after` the seconds, rounded up and at least 1, until it holds one again. Defaults: **per contact** 1 call/second with a burst of 10, keyed by the identity called and the contact's pinned root; **per identity**, every contact together, the number of contacts the identity may hold times the per-contact rate, with one second of that as its burst — so that each of its contacts may call at its own rate at the same moment and none is refused — unless the host cannot sustain that rate, in which case it enforces and advertises the rate it can; **guest tier** 10/hour per IP+key, the key being the root fingerprint of the chain presented, with a burst of 10; and a small-form envelope answered `chain_required` counts against the budget of its source address alone, 60/hour with a burst of 60, since an unverified sender is a guest until proven — many callers share an address behind a NAT or a hosting provider's egress — and a source over budget is answered `rate_limited` before anything is opened. A caller at pending tier spends the guest budget, and when one guest dimension is missing (no client address behind an edge, no key on a bare probe), the remaining dimension still budgets alone; neither absence buys an unmetered path. Every call that reaches dispatch spends — `tools/list`, and a tool the caller may not see or that does not exist, as much as any other — and a replayed envelope answered from its record (§13.3) spends nothing. The per-identity budget is spent only by contacts; a guest's call spends its guest budget and nothing a contact needs.

**Conformance checklist — an implementation is an HDTP agent server if it:** exposes an MCP server over HTTPS accepting TLS client certificates, or, behind an edge that terminates TLS, requiring sealed calls (§10, §13.4); identifies callers by fingerprint against a contact list — the root of a validated chain — with guest/pending/contact tiers; implements the guest + pending tools and `send_message`, `update_contact`, `remove_contact`, `get_card`; filters `tools/list` per caller; enforces manual approval for unsolicited requests; supports invite issuance with expiry/uses/revocation; emits and imports vCards with the `X-HDTP-*` properties; treats inbound strings as untrusted; honors idempotent `msg_id`. An implementation advertising `X-HDTP-SEAL: optional|required` additionally implements §13: `sealed_call` at every tier, the open order, and sealed results for sealed requests. **Because identity is a certificate chain**, it additionally: validates every chain by §14.2 and passes the shared vectors; carries its chain in its first envelope to each contact and in the first after each renewal, names its leaf by fingerprint otherwise, and answers `chain_required` uniformly to any small-form envelope it cannot verify (§13.2); keeps one pin per root — endpoint and latest leaf — treats an older leaf as no proof (§14.3), and learns a newer leaf at the pinned endpoint from any exchange; runs the new-address flow of §5.3 under `accept_new_hosts`; holds a superseded leaf's key until its `notAfter` and answers a former key with `certificate_renewed` (§14.4); deletes everything it held for an identity that has left (§9); and refuses any envelope whose `v` is not `1`, and any card whose `X-HDTP-VERSION` is not `1`, as `envelope_invalid` and `bad_request` respectively. A wallet is an HDTP wallet if it holds a root and nothing a host holds, signs a certificate only from an explicit user action, and shows the endpoint before signing while letting the person set the validity — any span up to the 398-day ceiling of §14.1, which is the receiver's rule and not a preference a wallet may offer past (§14.2).

**The record.** Each sentence of this document that states an absolute requirement or prohibition, in the obligatory keywords of BCP 14, has an identifier: its section's number and its place among those sentences of that section, as in `14.3#1`. `PROOFS.md` in the hdtp-identity repository lists every one beside the test, intrusion scenario or named external artefact that holds it.

---
