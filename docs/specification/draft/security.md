## 11. Security considerations

What HDTP relies on for each property, and the risk that remains:

| Property | What HDTP relies on | What remains |
|---|---|---|
| Who am I talking to | A root pinned from a vCard/invite exchanged human-to-human; every call proves the leaf key of a chain that validates to it and names the address in use: X.509 chain validation with the person as the authority, and one rule about which leaf is newest (§14) | Trust in a card equals trust in the channel that carried it (§3) |
| Consent | Manual approval on both sides, always; invites = pre-approval by the issuer; a contact's new address is accepted on the strength of their own root's signature, or on the owner's say-so (§5.3) | Under `accept_new_hosts: auto`, a stolen root moves contacts to a new address without asking them; the owner is shown the event (§5.3) |
| Wire privacy | TLS 1.3 between the two endpoints; sealed envelopes past terminating edges (§13) | No forward secrecy at the envelope layer, and carriers see metadata (§13.5) |
| Harvest now, decrypt later | Nothing: HDTP has no post-quantum cryptography. The path is set (§13.5): sealing first, as a hybrid key the leaf carries and one suite; the card as a pointer and the chain sent once, so the change touches neither card nor wire | Sealed traffic recorded today can be decrypted by an adversary that later has a quantum computer |
| Impersonation of a link | Invite redemption anchored to the issuer-distributed URL; card signature by the issuer's leaf key; the card's certificate names its issuer | Whoever controls the sharing channel can swap the card or the URL: the same trust as sharing a phone number |
| Impersonation by name | Nothing at the protocol layer: `FN` is the sender's claim (§3). Attribution is cryptographic — a chain validates to the pinned root or it is refused — so a contact can never *send as* another. What it can do is call itself what another calls itself; an owner's own name for a contact is a local answer, not a wire one | On first contact, before the owner has named anyone, the only name on screen is the one the peer chose |
| Revocation | Delete contact/invite server-side — instant, local, nothing cryptographic outstanding. A host's authority ends at its leaf's `notAfter`, or the moment a newer leaf reaches a contact — no CRL, no OCSP | A contact that has not seen a newer leaf accepts the older one until its `notAfter` (§14.3) |
| Renewal | A new leaf from the wallet, learned on the next exchange; the root is never rotated, because a compromised root's holder could rotate it too, and rotation would not tell the person from the thief | A lost or compromised root is a new identity (§2) |
| Replay/dup | Idempotent `msg_id` per call; TLS between the endpoints; for a sealed call, the envelope's `msg_id` record and its 300-second window (§13.3) | — |
| Spam | The guest tier has two tools, and `sealed_call` when sealing is on; invites carry expiry/uses; per-contact and per-identity call budgets (§12) | A flood still costs the receiver the work of refusing it (§14.5) |
| Prompt injection | Every inbound string (`text`, `note`, `topic`, filenames) is untrusted data — length-capped, never concatenated into the agent's instructions, rendered to humans as quoted content | — |
| Custodial hosting | The host holds the leaf key and can act as you while the leaf is valid — as every hosted service can — but never the root: its authority is written on a certificate you signed, for an address you saw, until a date you chose, and is outranked by the next leaf you sign (§9); HDTP keeps no log, and the certificate is the record | While its leaf is valid, a host can act as the person at its address (§14.5) |


---

