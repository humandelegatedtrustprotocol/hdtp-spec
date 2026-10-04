## 3. Contact cards (vCard)

An HDTP contact card is a standard **vCard 4.0** (RFC 6350) with three extension properties, so it saves into phone contact books, syncs like every other contact, and travels over WhatsApp/email/AirDrop/QR unchanged:

```
BEGIN:VCARD
VERSION:4.0
FN:Alina Rao
TEL:+91 98x xx xx xxx
EMAIL:alina@example.com
X-HDTP-VERSION:1
X-HDTP-CERT:MIIBkTCCAUOgAwIBAgIUX7…(the leaf certificate, base64url DER, folded per RFC 6350)…
X-HDTP-SEAL:required
END:VCARD
```

| Property | Required | Meaning |
|---|---|---|
| `X-HDTP-VERSION` | yes | Protocol major version: `1`, and nothing else. A card naming another major is refused `bad_request` |
| `X-HDTP-CERT` | yes | The identity's current leaf certificate, base64url DER (§14.1). It carries the endpoint, the leaf key, the issuing root's fingerprint and the validity dates — everything a card must say about identity and reachability, and the signature that binds them, in one |
| `X-HDTP-SEAL` | no | Inbound sealing policy: `none`\|`optional`\|`required` (§13). Absent = `none` |

A leaf is 400–500 bytes of DER, so a card stays under a kilobyte: a QR a phone reads from a screen, and for print the invite URL (§4) is the lighter carrier. A root is never in a card: the leaf names it by fingerprint (its issuer key identifier, §14.1), and the root itself arrives with the first exchange. An implementation **MUST NOT** write any other `X-HDTP-*` property, and **MUST** ignore any it reads — an endpoint, a key, a gateway: the address and the key are the leaf's, and there is no gateway.

What a card anchors is the **root fingerprint** and the **endpoint** — both read from the leaf, and both outliving it. A card whose leaf has expired is still a valid bootstrap for that root at that address: the first exchange brings the current leaf (§2, §14.4). *Pinning* a card means recording those two things; trust in them equals trust in the channel that carried the card, and the first chain that validates to that root at that endpoint is the proof of possession. A sender **MAY** seal its first call to the leaf key of a card whose leaf has expired — as a bootstrap only, pinning nothing until a chain validates — and expects either a result carrying the current chain or `certificate_renewed` (§14.4).

**A signed card.** Wherever a card is served — by `get_card`, by `redeem_invite`, and on the invite landing (§4) — it comes with `card_sig` and the identity's chain (§2). `card_sig` is the current leaf key's signature over the UTF-8 bytes of the card text exactly as sent, line breaks included: pure Ed25519 (RFC 8032), 64 bytes, for an Ed25519 leaf, or ECDSA with SHA-256 in ASN.1 DER for a P-256 leaf, written as base64url without padding (RFC 4648, Section 5). A receiver validates the chain (§14.2), checks that the card's `X-HDTP-CERT` is the chain's leaf, and verifies `card_sig` under that leaf's key over the card text it received. Appendix B carries a signed card.

**`FN` is the sender's own claim, and carries no authority.** The identity is the
root's fingerprint; the name beside it is whatever the card's author typed, and so
is the `commonName` inside the certificate. Two contacts may therefore carry the
same `FN` — usually because two people really are called the same thing,
occasionally because one of them chose it. A receiving implementation **MUST NOT**
treat `FN` as identifying, and **SHOULD NOT** present it as a contact's whole
identity: where two pinned contacts render alike, show the fingerprint alongside.
Implementations **SHOULD** also let the owner assign their own local name for a
contact, which is the only name no peer can influence.

`FN` is untrusted display input: a receiver **MUST** strip control and bidirectional-format characters from it before rendering it, **SHOULD** cap its length, and **SHOULD** fold confusable scripts when deciding whether two names collide. None of this is wire-visible — a card is accepted or rejected on its certificate, never on its name.

Intake is strict exactly where identity or reachability is at stake. A receiver **MUST** reject a card without `X-HDTP-CERT`, one whose certificate does not parse as §14.1 describes — no issuer key identifier or one that is not the 32 bytes a key identifier is, no endpoint or several, a validity longer than 398 days — and a card whose `X-HDTP-VERSION` names a major version it does not implement, each with `bad_request`. There is no root to pin, no address to reach, or no version in common; accepting such a card only defers the failure to a worse moment. An *expired* leaf is not a reason to reject: the root and the endpoint are what the card is for. A receiver **MUST** also refuse, at intake and again before every dial, an endpoint whose host resolves to a loopback, link-local or private address — the resolve-and-vet guard §6.2 applies to media URLs — unless the owner has configured that network on purpose, and a guest's endpoint that names the receiver's own address, which no honest card carries. An IPv6 literal that embeds an IPv4 address — IPv4-mapped, IPv4-compatible, NAT64 (`64:ff9b::/96`) or 6to4 (`2002::/16`) — is judged by the address inside it, which is the one a translator dials: `[64:ff9b::7f00:1]` is loopback on any NAT64 network, and for a literal there is no name to resolve, so this is the whole guard. NAT64's local-use prefix (`64:ff9b:1::/48`) and site-local addresses are never public. A writer **MUST NOT** put a control character into a card — in `FN`, in `X-HDTP-SEAL`, or in a property it adds: a card is lines, a line break writes a property of the writer's choosing, and a reader takes the first of a name, so a name of `x`, a line break and `X-HDTP-SEAL:none` made a card that requires sealing into one that does not. Unknown `X-HDTP-*` properties are preserved and ignored, which is how minor versions stay compatible.

The card a phone shares natively as "contact QR" is therefore already an HDTP identity. An agent watches the phone book (or an import action): any contact carrying `X-HDTP-*` fields is offerable as "connect our agents?" — which triggers the manual flow of §5.2. Ordinary contacts apps preserve unknown `X-` properties, so vCard needs no new sharing channel.

---

