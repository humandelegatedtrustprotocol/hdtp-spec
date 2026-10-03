## 11. Security notes and what was left out

What this spec relies on, and what it consciously gave up relative to the earlier hardened draft:

| Property | This spec's answer | Given up vs the hardened draft |
|---|---|---|
| Who am I talking to | A root pinned from a vCard/invite exchanged human-to-human; every call proves the leaf key of a chain that validates to it and names the address in use | Directory + SAS ceremonies. Nothing is re-invented here: X.509 chain validation with the person as the authority, and one rule about which leaf is newest |
| Consent | Manual approval on both sides, always; invites = pre-approval by the issuer; a contact's new address is accepted on the strength of their own root's signature, or on the owner's say-so (§5.3) | Same property, much less machinery |
| Wire privacy | TLS 1.3 between the two endpoints; sealed envelopes past terminating edges (§13) | Forward secrecy at the envelope layer: **none** — and carriers always see metadata (§13.5) |
| Harvest now, decrypt later | Nothing yet, by decision. The path is set (§13.5): sealing first, as a hybrid key the leaf carries and one suite; the card as a pointer and the chain sent once, so the change touches neither card nor wire | Post-quantum today — deferred on 2026-09-13 |
| Impersonation of a link | Invite redemption anchored to the issuer-distributed URL; card signature by the issuer's leaf key; the card's certificate names its issuer | Commit-reveal SAS (residual: whoever controls the sharing channel can swap the card/URL — same trust as sharing a phone number) |
| Impersonation by name | Nothing at the protocol layer: `FN` is the sender's claim (§3). Attribution is cryptographic — a chain validates to the pinned root or it is refused — so a contact can never *send as* another. What it can do is call itself what another calls itself | Petnames are a UI answer, not a wire one (residual: on first contact, before the owner has named anyone, the only name on screen is the one the peer chose) |
| Revocation | Delete contact/invite server-side — instant, local, nothing cryptographic outstanding. A host's authority ends at its leaf's `notAfter`, or the moment a newer leaf reaches a contact — no CRL, no OCSP | Delegation expiry machinery; this spec has one, the one X.509 always had |
| Renewal | A new leaf from the wallet, learned on the next exchange; the root is never rotated | Root rotation: a compromised root's holder could rotate too, so rotation would not tell the person from the thief; a lost root is a new identity |
| Replay/dup | Idempotent `msg_id` per call; TLS prevents third-party replay | Sequence windows |
| Spam | Guest tier is two tools; invites carry expiry/uses; per-contact and per-identity call budgets (§12) | Admission tokens |
| Prompt injection | Unchanged and still required: every inbound string (`text`, `note`, `topic`, filenames) is untrusted data — length-capped, never concatenated into the agent's instructions, rendered to humans as quoted content | — |
| Custodial hosting | The host holds the leaf key and can act as you while the leaf is valid — as every hosted service can — but never the root: its authority is written on a certificate you signed, for an address you saw, until a date you chose, and is outranked by the next leaf you sign (§9) | A platform-run transparency log; this spec keeps no log anywhere — the certificate is the record |

Also dropped: DIDs, SAS wordlists, per-contact route/gateway keys, the verb registry and negotiation state machine (threads + two calendar tools instead), sequence/window replay machinery (idempotency keys suffice at this trust level), conformance classes (checklist below instead). One drop was reversed, for a reason stated where it lives: the sealed envelope returns in reduced form as §13. An identity hierarchy is adopted in the smallest form that lets a person leave a host — a root that issues, a leaf that serves, and nothing else, expressed as the certificates every TLS stack already validates — and there is no relay role, because hosting under a leaf serves the same need without a third party reading everyone's metadata.

---

