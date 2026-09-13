# PACT — Personal Agent Communication & Trust Protocol

**Version 2.0.0-draft · 2026-09-13 · the identity generation: the person is the certificate authority, the host holds a leaf (§2, §3, §5.3, §9, §13, §14, Appendix C); post-quantum sealing, an exact certificate profile, compromise cases in §14.5**

PACT is a deliberate exercise in simplicity. An earlier hardened draft of this protocol (kept on file) was cryptographically thorough but heavy: sealed envelopes, key hierarchies, SAS ceremonies, DIDs, route pseudonyms. This spec keeps the parts that deliver the cause and removes the rest. 1.1 re-adopted exactly one of the removed pieces — a narrow sealed envelope, §13 — because terminating edges need identity and confidentiality that survive them. 2.0 changes one thing more, and it is older than any of the dropped machinery: an identity that belongs to a person rather than to whoever hosts it needs the key that *controls* it separated from the key that *serves* it, and X.509 has expressed exactly that separation since 1988. In 2.0 **the person is a certificate authority**. The root certificate in their wallet is the identity; the host they choose holds a leaf certificate the root issued, naming the address it serves and the date its authority ends. Still no DIDs, no SAS, no prekeys, no ceremonies, no directory — and no log, no sequence numbers, no relay. And because a certificate can carry a large key where a card could not, sealing is post-quantum from the first 2.0 envelope.

- **The identity is the person's; the host serves it.** An identity is the fingerprint of a self-signed root certificate whose private key lives in the person's wallet and signs nothing but certificates. The host — their own machine, or a provider — holds a leaf the root issued for one address, valid for at most a year, and that leaf carries the keys that speak: a signing key that is the TLS certificate and signs every call, and a post-quantum sealing key that contacts seal to. Contacts pin the root, learn the current leaf from every exchange, and never have to be told when it is renewed. Moving is a new leaf for a new address, and a contact request from there (§5.3, §9).
- **Your agent is a publicly exposed MCP server.** Sending a message *is* calling the other party's `send_message` tool. Everything a contact may do — messages, media, status, availability, calendar booking — is an MCP tool that is visible and callable only per your permission settings for that contact.
- **Contacts are vCards in your phone book.** A contact card is a standard vCard with two extra `X-PACT-*` fields, one of them the leaf certificate. Share it over WhatsApp, email, AirDrop, or as a QR — the channels people already use. Adding a contact is always a manual, human approval.
- **Invites are short URLs.** All settings (expiry, max uses, auto-accept, permission preset) live on the *sender's* server, so a link is revocable at the protocol level by deleting it. A QR of the link invites a room full of people.
- **Threads like a messenger.** Conversations carry a `thread_id` and optional `topic`, shared by both sides. Agents talk to agents; a human can type into the same thread manually. WhatsApp, but the participants are agents, and each one is reachable because it is hosted, not because a server in the middle holds its mail.

**Non-goals (accepted trade-offs, stated honestly):** no forward secrecy at the envelope layer (§13) — a later key compromise decrypts recorded sealed traffic, bounded in 2.0 by a leaf's lifetime; edges always see metadata (the recipient's key, timing, sizes — the sender rides inside the ciphertext in 2.0, §13.1), and an unsealed call is readable by whatever carries it; no anonymity or traffic-analysis resistance; no directory — a bare fingerprint resolves to nothing, every relationship starts from a card or an invite; no store-and-forward — a person who must be reachable while their own machine is off is hosted (§9), and 2.0 has no relay role; no recovery and no rotation of a lost or compromised root — the person's backups are the only copy; no post-quantum signatures yet — sealing is what 2.0 makes post-quantum, because recorded ciphertext is exposed today while a forger would need the computer today. §11 records what was dropped from the hardened draft and what each drop costs.

---

## Table of contents

1. Architecture
2. Identity, certificates and mTLS
3. Contact cards (vCard)
4. Invites
5. Adding contacts (flows)
6. The agent MCP server and its tools
7. Messaging and threads
8. Permissions
9. Hosting
10. Deployment
11. Security notes and what was left out
12. Errors, limits, conformance
13. Sealed envelopes
14. Certificates
Appendix A: worked examples
Appendix B: sealed-envelope test vectors
Appendix C: coexistence with 1.x

---

## 1. Architecture

```mermaid
flowchart LR
    subgraph SA["Person A"]
        HA["Human A<br/>(phone app + contact book + wallet)"]
        AA["Agent A<br/>(LLM + policies)"]
        MA["MCP server A<br/>https://a.example/mcp"]
        TA["A's private tools<br/>calendar, mail (MCP)"]
        HA --- AA
        AA --- MA
        AA --- TA
    end

    subgraph SB["Person B"]
        HB["Human B<br/>(phone app + contact book + wallet)"]
        AB["Agent B<br/>(LLM + policies)"]
        MB["MCP server B<br/>https://b.example/mcp"]
        TB["B's private tools<br/>calendar, mail (MCP)"]
        HB --- AB
        AB --- MB
        AB --- TB
    end

    AA -- "mTLS · calls B's tools<br/>send_message, book_slot…" --> MB
    AB -- "mTLS · calls A's tools" --> MA
```

Both sides are symmetric: every participant runs (or is hosted with) an **agent** and exposes an **MCP server** over HTTPS. "A messages B" = A's agent makes one mTLS-authenticated MCP tool call to B's server. B's server identifies the caller by the certificate chain it proves — as the client certificate, or inside a sealed envelope's signature (§2, §13) — validates that chain to a root pinned in B's contact list, and shows/allows exactly the tools B's permission settings grant that contact. Humans sit above their agents: they approve contacts, set permissions, hold the wallet that issues their host its certificate, and can type messages that travel the same rails.

---

## 2. Identity, certificates and mTLS

An identity is a **root certificate**: self-signed X.509, its private key held by the person in a wallet and used for one thing, issuing certificates. The root's fingerprint is the identity's name everywhere — in pins, in envelopes, on screen — and keeps the 1.x form, applied to the root's key:

```
fingerprint = "sha256:" + base64url( SHA-256( SubjectPublicKeyInfo ) )
```

A **host** — the person's own machine, or a provider — serves the identity under a **leaf certificate** the root issued. The leaf carries the host's own keys, the one address the identity answers at, and the dates between which the host's authority runs. Its **signing key** does two of the three jobs the 1.x identity key did — it is the TLS certificate, and it signs every envelope — and its **sealing key**, an X-Wing key carried in an extension, does the third: contacts seal to it, and a quantum computer does not open what they sealed (§13). What 1.x pinned was one key; 2.0 pins the root above both and learns the leaf. §14 gives both certificates' profile and the validation rules; this section is what they mean.

| Certificate | Key held by | Algorithm | Names | Lives |
|---|---|---|---|---|
| root | the person, in a wallet | Ed25519; P-256 permitted | the identity, by fingerprint | as long as the identity; never rotated |
| leaf | the host, one per identity | a signing key, Ed25519 or ECDSA P-256; a sealing key, X-Wing (X25519 and ML-KEM-768) | the endpoint, as its subject alternative name | at most 398 days, RECOMMENDED one year; renewed by the wallet with fresh keys |

A **chain** is exactly two certificates, leaf then root. It travels wherever a key had to travel in 1.x: as the TLS client certificate chain, inside every sealed envelope (§13.2), in the `redeem_invite` and `get_card` results, and on the invite landing (§4). A card carries the leaf alone (§3); the root arrives with the first exchange, and nothing about it needs to be trusted in advance, because it must hash to the fingerprint the leaf names as its issuer.

**Verification**, in full in §14.2: the root is self-signed and hashes to the fingerprint the verifier holds or is about to pin; the leaf is signed by that root, within its validity now, no longer than 398 days, and names exactly one endpoint; that endpoint equals the address in question, byte for byte. Then the leaf's keys are the identity's voice at that address — until a newer leaf says otherwise, which it does the instant it is seen (§14.3).

**Client side (who is calling):** a caller proves possession of its leaf key in either of two ways — by presenting the chain as its TLS client certificate, or by the detached signature on a sealed envelope (§13), which survives pipes that strip client certificates. The receiver validates the chain, takes the root's fingerprint as the caller's identity, and resolves it through its pins (§6.1). A pin records the root, the endpoint and the leaf last accepted: the caller's leaf must name the pinned endpoint and be no older than the pinned leaf. An older leaf proves nothing (§14.3); a different endpoint is a request to change it (§5.3). When both proofs are present their leaf keys MUST match, else `envelope_invalid`. **The root is the identity; the leaf is how it speaks today, and from where.** A chain whose root resolves to no pin gets the *guest* tier only (§6.1).

**Server side (who am I calling):** the endpoint is the pinned leaf's subject alternative name — a card carries no separate address, and a wallet signs no leaf without one. The endpoint's TLS server certificate is validated as either (a) normal WebPKI for the URL's hostname — the default, works with Let's Encrypt and behind terminating edges — or (b) the contact's own chain, which a self-hosted node MAY present as its server certificate and which the caller validates to the pinned root. Either way the name in the certificate equals the host dialed, and the *authorization* anchor is the root pinned at add-contact time, which no leaf moves.

**Renewal.** A leaf is renewed by the wallet issuing a new one for the same endpoint — with fresh keys, signing and sealing — before the old expires; a host SHOULD ask thirty days ahead, at a moment the person is already present. Nothing is announced: every request and every result carries its author's chain, so a contact learns the new leaf on the next exchange in either direction, and because the endpoint is unchanged it needs no one's approval to accept it. A host keeps a superseded leaf's private keys until that leaf's `notAfter`, so an envelope sealed to it by a contact that has not yet heard still opens; an envelope sealed to a key the host once held and holds no longer is answered `certificate_renewed` with the current chain (§14.4). A contact that sealed to an expired leaf learns the current one the same way — which is what keeps a card printed a year ago usable, as long as the address on it still stands. An expired leaf is refused everywhere, not demoted to guest, until the wallet renews it; a host's reminders are part of serving the identity.

**Moving** is a new leaf for a new endpoint, a contact request from there, and the old host forgetting: §5.3 and §9.

**Losing keys.** A lost or compromised leaf key is a renewal with a new key. A lost **root** is the end of the identity: re-share a new card from a new identity. A compromised root is the same, because whoever holds it can issue leaves, and no rotation ceremony could tell the two holders apart. There is deliberately no recovery and no rotation; the person's own backups of the wallet are the only copy, and the wallet says so once, when the root is made.

---

## 3. Contact cards (vCard)

A PACT contact card is a standard **vCard 4.0** (RFC 6350) with two extension properties, so it saves into phone contact books, syncs like every other contact, and travels over WhatsApp/email/AirDrop/QR unchanged:

```
BEGIN:VCARD
VERSION:4.0
FN:Alina Rao
TEL:+91 98x xx xx xxx
EMAIL:alina@example.com
X-PACT-VERSION:2
X-PACT-CERT:MIIBkTCCAUOgAwIBAgIUX7…(the leaf certificate, base64url DER, folded per RFC 6350)…
X-PACT-SEAL:required
END:VCARD
```

| Property | Required | Meaning |
|---|---|---|
| `X-PACT-VERSION` | yes | Protocol major version: `2`. A 2.0 receiver also accepts `1` (Appendix C) |
| `X-PACT-CERT` | yes in 2.0 | The identity's current leaf certificate, base64url DER (§14.1). It carries the endpoint, the signing and sealing keys, the issuing root's fingerprint and the validity dates — everything a 1.x card spelled out in separate properties, and the signature that binds them, in one |
| `X-PACT-SEAL` | no | Inbound sealing policy: `none`\|`optional`\|`required` (§13). Absent = `none` |

A leaf is about 1.7 KB of DER, most of it the post-quantum sealing key, so a card is about 2.4 KB: within a QR code's 2,953 bytes and readable from a screen, while the invite URL (§4) is the carrier for print. A root is never in a card: the leaf names it by fingerprint (its issuer key identifier, §14.1), and the root itself arrives with the first exchange. `X-PACT-ENDPOINT`, `X-PACT-KEY` and `X-PACT-GATEWAY` are 1.x properties; a 2.0 implementation writes the first two only on a compatibility card toward a peer it knows to be 1.x (Appendix C), and the third never.

What a card anchors is the **root fingerprint** and the **endpoint** — both read from the leaf, and both outliving it. A card whose leaf has expired is still a valid bootstrap for that root at that address: the first exchange brings the current leaf (§2, §14.4). *Pinning* a card means recording those two things; trust in them equals trust in the channel that carried the card, exactly as in 1.x, and the first chain that validates to that root at that endpoint is the proof of possession. A sender MAY seal its first call to the sealing key of a card whose leaf has expired — as a bootstrap only, pinning nothing until a chain validates — and expects either a result carrying the current chain or `certificate_renewed` (§14.4).

**`FN` is the sender's own claim, and carries no authority.** The identity is the
root's fingerprint; the name beside it is whatever the card's author typed, and so
is the `commonName` inside the certificate. Two contacts may therefore carry the
same `FN` — usually because two people really are called the same thing,
occasionally because one of them chose it. A receiving implementation MUST NOT
treat `FN` as identifying, and SHOULD NOT present it as a contact's whole
identity: where two pinned contacts render alike, show the fingerprint alongside.
Implementations SHOULD also let the owner assign their own local name for a
contact, which is the only name no peer can influence.

Treat `FN` as untrusted display input: cap its length, strip control and
bidirectional-format characters before rendering it, and fold confusable scripts
when deciding whether two names collide. None of this is wire-visible — a card is
accepted or rejected on its certificate, never on its name.

Intake is strict exactly where identity or reachability is at stake. A receiver MUST reject a card without `X-PACT-CERT`, one whose certificate does not parse as §14.1 describes — no issuer key identifier, no endpoint or several, a validity longer than 398 days — and a card whose `X-PACT-VERSION` names a major version it does not implement, each with `bad_request`. There is no root to pin, no address to reach, or no version in common; accepting such a card only defers the failure to a worse moment. An *expired* leaf is not a reason to reject: the root and the endpoint are what the card is for. A receiver MUST also refuse, at intake and again before every dial, an endpoint whose host resolves to a loopback, link-local or private address — the resolve-and-vet guard §6.2 applies to media URLs — unless the owner has configured that network on purpose, and a guest's endpoint that names the receiver's own address, which no honest card carries. Unknown `X-PACT-*` properties are preserved and ignored, which is how minor versions stay compatible — and how a 2.0 identity's card reaches a 1.x phone book intact (Appendix C).

The card a phone shares natively as "contact QR" is therefore already a PACT identity. An agent watches the phone book (or an import action): any contact carrying `X-PACT-*` fields is offerable as "connect our agents?" — which triggers the manual flow of §5.2. Ordinary contacts apps preserve unknown `X-` properties, which is exactly why vCard is the carrier: **no new sharing channel is invented**.

---

## 4. Invites

An invite is a short URL whose entire state lives server-side with the issuer:

```
https://agent.alina.example/i/inv_8Qq1xZk3
```

(The token is a path segment on the issuer's host — `/i/<token>` — because the landing below is served by the issuer, and a URL *fragment* never reaches a server. A QR of this URL is the shareable form. A `pact://` deep-link wrapper MAY carry the same two values for app routing.)

Issuer-side settings per invite — because state is server-side, all of this is enforceable and changeable *after* the link is shared:

| Setting | Default | Notes |
|---|---|---|
| `expires_at` | 14 days | Redeems after this fail |
| `max_uses` | 1 | Set high for a QR shown to a room; each redeem becomes its own contact |
| `auto_accept` | false | `true` = redeeming immediately creates the contact (conference-badge mode); `false` = each redeem lands as a pending request for manual approval |
| `preset` | "basic" | Permission preset granted on accept (§8) |
| `label` | — | "Pune conference 2026" — shows on incoming requests |
| revoked | — | Deleting the token invalidates the link at the protocol level; nothing cryptographic to chase |

The invite URL itself contains no personal data and no key — only the bearer token. The URL resolves (over TLS, to the endpoint the issuer personally handed over as QR/link) to a landing page serving the issuer's **signed card**: the vCard plus a signature over it by the issuer's leaf key. The same URL serves two audiences by content negotiation: a browser gets the human landing page; a client sending `Accept: application/pact-invite+json` (or appending `?format=json`) gets `{"card","card_sig","chain"}` — the signed card and the issuer's chain (§2), whose leaf MUST byte-equal the card's `X-PACT-CERT` and which the redeemer MUST validate (§14.2) before use, so it can seal its very first call. An unknown, revoked, expired, or used-up token answers with one indistinguishable not-found on both views. The redeemer therefore holds the issuer's card *before* redeeming — which is also what lets a guest seal `redeem_invite` toward a `required` issuer (§13) — and redemption re-returns the same signed card in-band, so the redeemer pins a root whose chain reached it over the URL the issuer personally handed out.

---

## 5. Adding contacts

Contacts are always mutual and always human-approved (an invite's `auto_accept` is the issuer *pre-approving* at share time). Contact state on each side:

```mermaid
stateDiagram-v2
    [*] --> none
    none --> pending_out : I redeemed an invite /<br/>sent a request
    none --> pending_in : someone requested me
    pending_in --> active : I approve
    pending_in --> blocked : I reject
    pending_in --> none : request expires
    pending_out --> active : they approve<br/>(contact_accepted call)
    pending_out --> blocked : rejected<br/>(contact_rejected call)
    pending_out --> none : expired
    active --> blocked : I block
    blocked --> active : I unblock
    active --> none : remove_contact<br/>(either side)
```

### 5.1 Invite flow (QR / link)

```mermaid
sequenceDiagram
    autonumber
    actor A as Alina (human)
    participant AS as Alina's MCP server
    actor B as Bharat (human)
    participant BA as Bharat's agent

    A->>A: create invite (expiry, uses, preset)
    A-->>B: QR / link via any channel
    B->>BA: scan QR
    BA->>AS: redeem_invite(token, card_B)  [mTLS: B's chain]
    Note over AS: chain valid (§14.2)? leaf = card_B's X-PACT-CERT?<br/>token valid? not expired / revoked / uses left?
    alt auto_accept invite
        AS-->>BA: accepted + signed card_A + chain_A + granted permissions
        Note over BA: validate chain_A · pin A's root and endpoint · save vCard to phone book
    else manual approval
        AS-->>BA: pending + signed card_A + chain_A
        AS->>A: notify: contact request (Bharat, via "Pune conference" invite)
        A->>AS: approve
        AS->>BA: contact_accepted(card_A, permissions)  [mTLS: A's chain]
        Note over BA: caller's root = pinned root · endpoint = pinned endpoint
    end
    Note over AS,BA: both sides active · both phone books updated
```

Key exchange is complete with zero extra ceremony: **B proved possession of B's leaf key** in step 4 — by presenting the chain as the client certificate, or by the signature on a sealed `redeem_invite` (§13); either way the server validates the chain and checks its leaf is the one in the submitted card — and **A's chain reached B signed, over the endpoint A personally handed out** in the QR. Mutual mTLS (or sealed calls) from here on.

### 5.2 Manual flow (vCard shared over existing channels)

```mermaid
sequenceDiagram
    autonumber
    actor A as Alina (human)
    actor B as Bharat (human)
    participant BA as Bharat's agent
    participant AS as Alina's MCP server

    A-->>B: vCard via WhatsApp / email / AirDrop / contact QR
    B->>B: saved to phone contact book
    BA->>B: "This contact has a PACT agent - connect?"
    B->>BA: yes
    BA->>AS: request_contact(card_B, note)  [mTLS: B's chain]
    AS-->>BA: pending
    AS->>A: notify: request from Bharat (unsolicited - always manual)
    A->>AS: approve + choose permission preset
    AS->>BA: contact_accepted(card_A, permissions)  [mTLS: A's chain]
    Note over BA: caller's root = the issuer of the certificate<br/>in the vCard B already holds · endpoint = the card's
```

The vCard B received out-of-band is the trust anchor: the `contact_accepted` caller must present a chain that validates to the root the card's certificate names, at the endpoint it names. Trust in the card equals trust in the channel that carried it — which is the same trust people already place in a shared phone number.

**What "pin" means in 2.0.** In both flows the thing pinned is the **root fingerprint** the card's leaf names as its issuer, together with the **endpoint** the leaf names, and the leaf itself as the latest one seen. The chain a caller proves — as a client certificate or inside an envelope — is validated to that root and checked against that endpoint, and "the same key" in the notes above means the leaf key of a chain that passes, not merely the key the card shows. A card whose chain never validates is not a contact; it is a piece of paper.

**Rejection:** declining a request is a demotion, not a deletion. The requester's row moves to `blocked`, so a rejected stranger cannot simply knock again — their next `request_contact` receives the same `{"status": "pending"}` any stranger gets, while nothing is recorded and the owner is never bothered: blocked MUST be indistinguishable from never-met (§12). The rejecting side MAY tell the peer by calling the pending-tier `contact_rejected` tool (§6.2), the mirror of `contact_accepted`; the default is silence. A requester that receives `contact_rejected` moves its own `pending_out` row to `blocked` — its record that the approach was declined and is not to be repeated.

**Removal / blocking:** `remove_contact` notifies the peer and deletes the pin on both sides (effective locally regardless — enforcement is "your root is no longer in my list"). Blocking is local-only: the contact silently drops to guest tier; no notification is sent.

**An address that belongs to someone.** A stranger whose leaf names an endpoint the receiver has pinned for another root, or had pinned for another root within the last 30 days, is never auto-accepted — an invite's `auto_accept` does not apply — and is shown to the owner beside the name of the contact who holds or held that address. The honest case exists: a person who lost their root starts a new identity at the same address, and their contacts must see that it is a new identity. The dishonest one is a former provider re-using an address it was asked to vacate, wearing the departed person's name.

### 5.3 A contact at a new address

When a person moves to another host, the new host holds a fresh leaf naming its own endpoint and a copy of the person's contact book (§9), and nothing of the old host's. It reaches each contact from the new address by calling `update_contact` with the new card, over a client certificate or a sealed envelope carrying the new chain. The receiver validates the chain to the root it has pinned — so this is provably the same person — and finds an endpoint different from the one it pinned and a leaf newer than the one it holds. What happens next is the owner's setting, **`accept_new_hosts`**:

- `auto`, the default: the pin's endpoint and leaf are replaced, the call answers `ok`, and the next message flows to the new address; the change is recorded in the owner's audit and shown to the owner as an event — "Alina now writes from a new address" — because a stolen root re-homes contacts in exactly this way, and a person who is told can ask. The default is `auto` because the root's signature on the new leaf is the person's own authorisation of the new host, and asking their contact to confirm what they already signed adds a human step to a question the cryptography has settled.
- `ask`: the call answers `{"status": "pending"}`; the request appears beside contact requests, naming the contact, the old address and the new one; until the owner decides, every other call from the new address answers `pending_approval`, and messages to the contact keep going to the old address, where they may fail. Approving re-pins as `auto` would have; rejecting leaves the pin as it was, and the new address is a stranger the owner MAY block.

**After a removal.** A host that is being left, and still holds a valid leaf, could call `remove_contact` at every contact before the new host arrives, and the person would find their contacts gone. A receiver therefore keeps, for 30 days after a `remove_contact`, the removed root and the leaf that removed it; a chain from that root with a newer leaf inside that window is handled as a new address under `ask`, whatever the setting says, since a host that removed a contact and a host that returns cannot both have been the person's wish. A person who removes a contact and returns meets the same question, which is the right one.

The rule applies to a pinned root in any state but `blocked` — a peer may move between my request and their `contact_accepted`: under `auto` the endpoint is re-pinned and the call proceeds in the tier its state earns; under `ask` it waits as above.

Either way the old host's leaf — still within its validity, and still in the old host's hands unless it has done what §9 requires — is now *older* than the one pinned, so a call from the old address proves nothing (§14.3). A contact the new host could not reach — asleep for the whole validity of the old leaf, or absent from the contact book — needs the card again over a human channel, as a contact that missed a rotation always did: the person re-shares it, or publishes the QR where people find them, and the next exchange carries the current leaf.

---

## 6. The agent MCP server and its tools

Every participant exposes one MCP server (Streamable HTTP, current MCP spec) over HTTPS with the mTLS rules of §2. **Authorization is the proven chain, resolved to a pinned root** (§2) — client certificate or envelope signature, never OAuth on this surface; that identity selects a tier and a permission profile, and MCP `tools/list` returns only what that caller may use. (Consumer MCP clients such as hosted chat apps cannot present client certificates; that is fine — callers here are agents. A separate OAuth-protected façade for third-party assistants can be added later without touching this protocol.)

### 6.1 Tiers

```mermaid
flowchart TD
    C["Incoming call<br/>chain: leaf + root<br/>(client cert or envelope sig, §2)"] --> V{"chain valid?<br/>(§14.2)"}
    V -- no --> R["refused<br/>envelope_invalid · handshake"]
    V -- yes --> F{"root pinned?"}
    F -- no --> G["GUEST tier<br/>redeem_invite · request_contact"]
    F -- "blocked, or the leaf is older<br/>than the pinned one (§14.3)" --> G
    F -- "other endpoint,<br/>any state but blocked" --> N["NEW ADDRESS (§5.3)<br/>auto: re-pin, continue · ask: pending"]
    F -- "pending_out,<br/>pinned endpoint" --> P["PENDING tier<br/>contact_accepted · contact_rejected"]
    F -- "active,<br/>pinned endpoint" --> A["CONTACT tier<br/>tools filtered by this contact's<br/>permission profile (§8)"]
```

A leaf newer than the pinned one, at the pinned endpoint, replaces it on the way through: that is a renewal, learned (§2). A guest whose endpoint belongs to a pinned contact, or did within 30 days, reaches the owner with that contact's name beside it and is never auto-accepted (§5).

### 6.2 Core tools

All tools return MCP tool results; errors use the codes of §12. `msg_id`-bearing calls are idempotent: the same `msg_id` re-sent is acknowledged, not re-executed. A `msg_id` MUST be a non-empty string — idempotency keyed on nothing protects nothing.

**Guest tier**

| Tool | Arguments | Returns |
|---|---|---|
| `redeem_invite` | `token`, `card` (vCard text) | `status: accepted\|pending`, `card` (signed issuer vCard), `card_sig`, `chain` (§2), `permissions?` |
| `request_contact` | `card`, `note?` (≤1 KiB) | `status: pending` |
| `sealed_call` | `protected`, `enc`, `ct`, `sig` (§13) | the sealed result — present at every tier when `X-PACT-SEAL` ≠ `none` |

**Pending tier** (caller is someone I asked to be my contact)

| Tool | Arguments | Returns |
|---|---|---|
| `contact_accepted` | `card`, `permissions` (list granted to me) | `ok` |
| `contact_rejected` | `reason?` | `ok` |

**Contact tier** (each item present only if permitted for this caller — §8)

| Tool | Permission | Arguments | Returns |
|---|---|---|---|
| `send_message` | `message.text` | `msg_id`, `thread_id?`, `topic?`, `text` (≤16 KiB), `reply_to?`, `sender: agent\|human` | `thread_id`, `status: delivered\|queued_for_human` |
| `send_media` | `message.media` | `msg_id`, `thread_id`, `filename`, `mime`, `data` (base64, ≤5 MiB) or `url`, `sender: agent\|human` | `thread_id`, `status` |
| `get_status` | `status.view` | — | `status: available\|busy\|dnd\|offline`, `note?` |
| `check_availability` | `calendar.availability` | `window {from,to,tz}`, `duration_min` | `slots: [≤5 of {start,end,tz}]` |
| `book_slot` | `calendar.book` | `msg_id`, `slot`, `subject`, `thread_id?` | `booking_id`, `ics` |
| `cancel_booking` | `calendar.book` | `booking_id`, `reason?` | `ok` |
| `update_contact` | (always) | `card` (new); `sig` only in a 1.x exchange (Appendix C) | `ok` — a card refresh, or `status: pending` from a new address under `ask` (§5.3). The caller's chain is the authority: the card's certificate MUST equal the chain's leaf |
| `remove_contact` | (always) | — | `ok` |
| `get_card` | (always) | — | `card` (current signed vCard), `card_sig` (by the leaf key), `chain` (§2), `limits` (§12) |

Small print that keeps the table honest: `sender` on `send_media` labels exactly as on `send_message`, and on both it defaults to `agent` when absent — the safe direction; a node never invents a `human` claim. `get_status` answers from that fixed four-value vocabulary; an implementation whose upstream presence source knows richer states MUST map any state not listed to `busy`. `url` media is recorded, never fetched on receipt: fetching is an explicit owner action, made with resolve-and-vet address guards (private ranges refused), not a side effect a sender can trigger.

This table is the v2 core. Anything else a person wants to expose to contacts — a document dropbox, a task intake, a payment request — is just **another MCP tool on the same server behind the same permission switchboard**. That is the point of building on MCP: the protocol never needs a new verb registry; integrations are tools.

---

## 7. Messaging and threads

A conversation is a `thread_id` (UUID, minted by whoever sends first) plus an optional human-readable `topic`, stored by both sides. Either agent — or either human, typing manually — continues a thread by calling the peer's `send_message` with that `thread_id`. `sender: human|agent` is honest labeling shown in the peer's UI; an agent replying autonomously identifies as the assistant, never as its owner.

```mermaid
sequenceDiagram
    autonumber
    actor HA as Human A
    participant AA as Agent A
    participant MB as B's MCP server
    participant AB as Agent B
    actor HB as Human B

    HA->>AA: "ask Bharat's agent to find 45 min next week"
    AA->>MB: send_message(thread T1, topic "Coffee catch-up",<br/>text: proposal, sender: agent)
    MB->>AB: deliver into thread T1
    AB->>MB: policy check - allowed to negotiate?
    AB->>AA: send_message on A's server (thread T1):<br/>"Tue 10:00 or Thu 09:30?"  [reverse direction, same thread]
    AA->>MB: book via check_availability + book_slot
    MB-->>AA: booking_id + ics
    AA->>HA: "Booked: Tue 10:00 - added to your calendar"
    AB->>HB: digest: "Booked coffee with Alina, Tue 10:00"
    HB->>AB: (optionally types into T1 manually - sender: human)
```

Notes that keep this simple and sane: negotiation is *conversation* between agents inside a thread (no negotiation state machine on the wire) plus two structured calendar tools where structure matters — `check_availability` never returns raw free/busy, only ≤5 policy-filtered candidate slots, and `book_slot` returns the ICS both sides file via their private calendar MCP tools. A `thread_id` belongs to the contact that first used it: a `send_message` from any other contact carrying that `thread_id` is refused `bad_request` — without this rule, thread placement is an impersonation vector, one contact writing into the middle of another's conversation. Multi-party coordination (several employees' agents negotiating) is therefore parallel per-contact threads sharing a `topic` string — still like a CC line, no group crypto, but each line is its own thread. Delivery when the peer is unreachable: retry with backoff until `expires` (sender-chosen, default 24 h), then report failure to the sender's human. 2.0 has no store-and-forward role: a peer that must be reachable while its own machine is off is hosted (§9).

---

## 8. Permissions

Per-contact switchboard, controlled by the owner, enforced at the owner's server on every call — changes apply instantly, no wire protocol needed (flip a switch → the tool disappears from that caller's `tools/list` and calls return `permission_denied`).

| Permission | Gates | In "basic" preset |
|---|---|---|
| `message.text` | `send_message` | ✔ |
| `message.media` | `send_media` | ✖ |
| `status.view` | `get_status` (status visibility) | ✖ |
| `calendar.availability` | `check_availability` | ✖ |
| `calendar.book` | `book_slot`, `cancel_booking` | ✖ |
| `integration.<name>` | any additional exposed tool | ✖ |

`integration.<name>` is one switch per integration, not per tool: it gates **every** tool that integration exposes, and those tools appear in a contact's `tools/list` under passthrough names of the form `<slug>_<tool>`. Integration grants sit outside preset bundles in both directions — no bundle names them, so applying a preset never grants one and never revokes one; they are always an explicit per-contact decision.

Presets are owner-editable bundles assigned at approval time and adjustable per contact afterwards; four ship as documented defaults:

| Preset | Grants |
|---|---|
| `basic` | `message.text` |
| `work` | `message.text` · `calendar.availability` · `calendar.book` |
| `friend` | `message.text` · `message.media` · `status.view` · `calendar.availability` · `calendar.book` |
| `family` | the same bundle as `friend` — the distinction is the owner's to draw, not the protocol's |

A preset is a label for a bundle, not a lock: hand-toggle one switch and the grant is bespoke. Beyond visibility, the owner's agent applies its own policy on top (auto-reply vs. surface-to-human, auto-book windows, quiet hours) — that is local behavior, not protocol.

```mermaid
flowchart LR
    subgraph B["B's server - per-contact profiles"]
        P1["Alina: text+media+availability+book"]
        P2["Vendor X: text only"]
        P3["Unknown callers: guest tier"]
    end
    A1["Alina's agent"] -->|"tools/list shows 6 tools"| B
    A2["Vendor X agent"] -->|"tools/list shows 1 tool"| B
    A3["Stranger"] -->|"tools/list shows 2 guest tools"| B
```

---

## 9. Hosting

Direct calls need the recipient's server reachable. 1.x answered the hours it is not with a relay the recipient chose — a store-and-forward gateway that verified sealed traffic without reading it, and saw every sender, recipient and timestamp for its trouble. 2.0 removes that role, because the same need is met more simply by the thing 2.0 makes safe: **being hosted**. A host runs the identity's server all the time, under a leaf the person issued, and can be replaced without the person losing anything. This section is what a host holds, what it must do when the person leaves, and how the wallet on the other side behaves.

**What a host holds.** The leaf certificate for the identity at its endpoint and that leaf's two private keys, signing and sealing; a superseded leaf's keys until its `notAfter` (§2); the identity's data — contacts, threads, media, invites, settings, audit chain. Never the root. A host obtains a leaf by sending the wallet a certificate signing request (PKCS #10, RFC 2986) carrying the host's signing key, its sealing key as a requested extension, and the endpoint it will serve; the wallet shows the person the endpoint and the validity, and signs or does not. A provider's sign-up page for a person who has no wallet runs the same ceremony in the browser: the root is generated there, the first leaf is issued there, the wallet is downloaded before anything else happens, and no server sees a root. The ceremony runs in a document the provider's page cannot read — the extension when one is installed, otherwise a frame served from an origin that is not the provider's and pinned by integrity hash — and hands the page back only the leaf; a page that could read the root would be the provider seeing it.

**Renewal** is §2: a CSR again, for the same endpoint, before the old leaf expires. A renewal SHOULD carry fresh keys, so that a key compromised without anyone noticing dies with its leaf; a suspected compromise is the same act done at once, and the new leaf outranks the stolen one with every contact it reaches (§14.3). **Moving** is the person issuing a leaf to the new host, the data carried across as an archive — contacts, messages, media, invites, settings; the archive's format is each host's own, and a host that imports one MUST refuse any key material in it — and the new host reaching every contact by §5.3, *before* the person tells the old host to leave, so that no contact meets a gap. The wallet's own copy of the contact book is the authority for that campaign: a host imports the archive's contacts against it and shows the person every difference, so a former host can neither plant a contact nor drop one unseen.

```mermaid
sequenceDiagram
    autonumber
    actor P as Person (wallet)
    participant O as Old host
    participant N as New host
    participant C as A contact
    N->>P: CSR (new host key, new endpoint)
    P->>N: leaf, signed by the root
    O-->>N: archive (data, never keys)
    P->>O: leave
    O->>O: delete the leaf key and every record
    N->>C: update_contact(new card)  [chain: new leaf + root]
    C->>C: chain valid · root pinned · endpoint differs · leaf newer
    alt accept_new_hosts = auto
        C-->>N: ok (re-pinned)
    else ask
        C-->>N: pending
        C->>C: owner approves
    end
    C->>N: send_message  [sealed to the new leaf]
```

**What a host must do when the person leaves.** Destroy the leaf's private key and delete every record of the identity — data, keys, the fingerprints of former leaves — at once, keep nothing beyond what law compels, and answer calls at the old address exactly as it answers calls for an address it never served. The protocol's backstop against a host that does not is the leaf's own expiry, and the fact that a newer leaf outranks it with every contact it reaches (§14.3). The person's backstop is the regime the provider is audited under: a provider that hosts other people's identities is their data processor, and certifications such as SOC 2 together with the obligations of the GDPR are what make "deleted" a checkable claim rather than a promise. An address an identity has vacated MUST NOT be assigned to another identity until the last leaf issued for it has expired, so a contact that missed the move never reaches a stranger where it expects a friend.

**The wallet** holds the root and nothing a host holds. It signs certificates only from an explicit user action, in a window of its own that no page can draw over, and before signing it shows the endpoint the leaf will name, the origin of the page that asked (a difference between the two is shown, not hidden — a provider's portal and the addresses it serves are often different hosts), whether that endpoint's host is one it has issued to before, and the validity. It verifies the CSR's own signature, so the key it certifies is one the host proved it holds, and refuses a CSR whose key is a root. Issuing a leaf to a *new* endpoint requires the passphrase, or the hardware key, again, even in an unlocked session; a renewal for the same endpoint needs the click alone. It issues one live leaf per identity at a time — a second endpoint is a move, not a second home, because contacts keep one pin and the newest leaf wins — and MUST NOT issue a second while one is live except as its replacement. At rest the root is under a key derived from a passphrase with a memory-hard function, optionally wrapped by a hardware key — and better, the root itself lives in a hardware key or a passkey, where copying the vault copies nothing, which is the one defence against a root fought over by two holders (§14.3); unlocked, it lives in the extension's memory for the session and nowhere a page can reach. It keeps its own copy of the person's contact book, so the book outlives any host and any identity, and it is backed up as a file, to a drive, or to a hardware key, at the person's choice. Losing every copy ends the identity; the wallet says so once, when the root is made.

---

## 10. Deployment

```mermaid
flowchart TB
    subgraph SH["Self-hosted at home"]
        N1["Agent + MCP server<br/>on home machine<br/>leaf issued by the owner's wallet"]
    end
    subgraph TU["Reachability options"]
        T1["Port forward / static IP<br/>full mTLS end-to-end<br/>the chain is the server certificate"]
        T2["TCP/TLS passthrough tunnel<br/>Tailscale Funnel · ngrok TLS · frp<br/>rathole · Pangolin raw-TCP<br/>full mTLS end-to-end"]
        T3["Edge-terminating tunnel<br/>Cloudflare Tunnel · ngrok HTTPS<br/>identity + confidentiality ride<br/>the sealed envelope (§13)"]
    end
    subgraph PF["Provider-hosted"]
        H1["Provider runs MCP servers,<br/>contact stores, invite pages<br/>under leaves its customers issued"]
    end
    N1 --> T1
    N1 --> T2
    N1 --> T3
```

**Self-hosting:** anything that passes raw TLS through to your machine preserves true end-to-end mTLS — verified as of 2026-08: port forward; **Tailscale Funnel** (relays without decrypting; client certificates reach your server); ngrok **TLS** endpoints (unterminated by default; paid); frp's SNI-routed vhost; rathole; Pangolin raw-TCP resources. Cloudflare Tunnel and ngrok's HTTPS endpoints terminate TLS at the edge and strip client certificates — behind such an edge, caller identity and confidentiality ride the sealed envelope instead (`X-PACT-SEAL: required`, §13), and the edge sees ciphertext plus metadata only. A custom domain + Let's Encrypt on the tunnel/host gives contacts a clean endpoint; a self-hosted node on its own domain MAY instead present its chain as the server certificate (§2). A machine that is not always on is not a PACT host; the answer to that is a provider, not a mailbox.

**Provider mode:** the operator hosts each customer's MCP server (per-tenant paths or hostnames) and renders invite links/QRs. It holds one leaf per identity, issued by the customer's own root for the address the operator serves it at, and never the root: a customer who leaves issues a leaf to the next host, that host reaches every contact from its own address (§5.3), and the operator deletes what it held (§9). Every change of address — a custom domain, a rename, a move between the operator's environments — is a leaf the person signs and a new address at every contact (§5.3); an operator gates such changes behind that ceremony rather than performing them alone, which in 1.x it could. A person arriving with nothing makes their first identity in the browser on the operator's sign-up page: the root is generated there, the first leaf issued there, the wallet downloaded before anything else happens. The same front-door machinery scales down to one person: an *ingress* — a pact node on a VPS routing per-subdomain, either passing TLS through untouched or terminating public TLS and re-originating over mutually pinned mTLS to the home node — is the self-hosted form of provider mode, and a provider is that ingress run for many tenants.

---

## 11. Security notes and what was left out

What this spec relies on, and what it consciously gave up relative to the earlier hardened draft:

| Property | This spec's answer | Given up vs the hardened draft |
|---|---|---|
| Who am I talking to | A root pinned from a vCard/invite exchanged human-to-human; every call proves the leaf key of a chain that validates to it and names the address in use | Directory + SAS ceremonies. 2.0 re-invented nothing here: X.509 chain validation with the person as the authority, and one rule about which leaf is newest |
| Consent | Manual approval on both sides, always; invites = pre-approval by the issuer; a contact's new address is accepted on the strength of their own root's signature, or on the owner's say-so (§5.3) | Same property, much less machinery |
| Wire privacy | TLS 1.3 between the two endpoints; sealed envelopes past terminating edges (§13, added in 1.1) | Forward secrecy at the envelope layer: **none** — and carriers always see metadata (§13.5) |
| Harvest now, decrypt later | Every 2.0 envelope is sealed with a hybrid post-quantum KEM, X25519 and ML-KEM-768 together, to a sealing key the leaf carries (§13.1) | Post-quantum signatures: not yet — a forger needs the computer today, and they would triple every certificate and envelope |
| Impersonation of a link | Invite redemption anchored to the issuer-distributed URL; card signature by the issuer's leaf key; the card's certificate names its issuer | Commit-reveal SAS (residual: whoever controls the sharing channel can swap the card/URL — same trust as sharing a phone number) |
| Impersonation by name | Nothing at the protocol layer: `FN` is the sender's claim (§3). Attribution is cryptographic — a chain validates to the pinned root or it is refused — so a contact can never *send as* another. What it can do is call itself what another calls itself | Petnames are a UI answer, not a wire one (residual: on first contact, before the owner has named anyone, the only name on screen is the one the peer chose) |
| Revocation | Delete contact/invite server-side — instant, local, nothing cryptographic outstanding. A host's authority ends at its leaf's `notAfter`, or the moment a newer leaf reaches a contact — no CRL, no OCSP | Delegation expiry machinery; 2.0 has one, the one X.509 always had |
| Renewal | A new leaf from the wallet, learned on the next exchange; the root is never rotated | Root rotation: a compromised root's holder could rotate too, so rotation would not tell the person from the thief; a lost root is a new identity |
| Replay/dup | Idempotent `msg_id` per call; TLS prevents third-party replay | Sequence windows |
| Spam | Guest tier is two tools; invites carry expiry/uses; per-contact rate limits (§12) | Admission tokens |
| Prompt injection | Unchanged and still required: every inbound string (`text`, `note`, `topic`, filenames) is untrusted data — length-capped, never concatenated into the agent's instructions, rendered to humans as quoted content | — |
| Custodial hosting | The host holds the leaf key and can act as you while the leaf is valid — as every hosted service can — but never the root: its authority is written on a certificate you signed, for an address you saw, until a date you chose, and is outranked by the next leaf you sign (§9) | A platform-run transparency log; 2.0 keeps no log anywhere — the certificate is the record |

Also dropped: DIDs, SAS wordlists, per-pact route/gateway keys, the verb registry and negotiation state machine (threads + two calendar tools instead), sequence/window replay machinery (idempotency keys suffice at this trust level), conformance classes (checklist below instead). One drop was reversed, for a reason stated where it lives: 1.1 re-adopted the sealed envelope in reduced form as §13. 2.0 adopted an identity hierarchy in the smallest form that lets a person leave a host — a root that issues, a leaf that serves, and nothing else, expressed as the certificates every TLS stack already validates — and removed the relay role, because hosting under a leaf serves the same need without a third party reading everyone's metadata.

---

## 12. Errors, limits, conformance

**Errors** (MCP tool errors with `code`): `unknown_contact`, `pending_approval`, `permission_denied`, `invite_invalid` (expired/revoked/used-up), `blocked_or_unknown` (guest-tier catch-all — indistinguishable by design), `too_large`, `rate_limited` (+`retry_after`, integer seconds), `unavailable` (also returned for a tool an implementation is temporarily withholding), `bad_request`; from 1.1 (§13): `seal_required` (unsealed call to a sealing-required recipient), `identity_required` (no usable identity proof where one is needed), `envelope_invalid` (malformed, misdirected, mis-signed, expired, or fingerprint-mismatched envelope — in 2.0 also one whose chain fails §14.2); from 1.2: `seal_not_accepted` (a sealed call to a recipient whose card says `X-PACT-SEAL: none` — the sender was told not to seal, §13.4); from 2.0: `certificate_renewed` (an envelope sealed to a leaf key this endpoint once held and holds no longer; the error's data carries `chain`, the current one, which the caller validates against its pin before re-sealing, §14.4). A contact at a new address under `ask` receives `pending_approval` (§5.3), which 1.0 already had.

**Limits are defaults — operator-tunable, and discoverable:** the numbers below are what an untuned node enforces; an operator may raise or lower them, and the values in force are advertised as a `limits` object in the `get_card` result with members `text_bytes`, `note_bytes`, `media_inline_bytes`, `availability_slots`, `invite_ttl_days`, `contact_calls_per_hour`, `guest_calls_per_hour`. Defaults: text ≤16 KiB; media ≤5 MiB inline (larger by `url`); ≤5 slots per availability response; invite `expires_at` ≤90 days; a certificate ≤4 KiB and a chain of exactly two (§14.2); per-contact rate 60 calls/hour; guest tier 10/hour per IP+key, the key being the root fingerprint of the chain presented (a 1.x key fingerprint for a 1.x caller) — and when one dimension is missing (no client address behind an edge, no key on a bare probe), the remaining dimension still budgets alone; neither absence buys an unmetered path.

**Conformance checklist — an implementation is a PACT agent server if it:** exposes an MCP server over HTTPS accepting TLS client certificates; identifies callers by fingerprint against a contact list — of the identity key in 1.x, of the root of a validated chain in 2.0 — with guest/pending/contact tiers; implements the guest + pending tools and `send_message`, `update_contact`, `remove_contact`, `get_card`; filters `tools/list` per caller; enforces manual approval for unsolicited requests; supports invite issuance with expiry/uses/revocation; emits and imports vCards with the `X-PACT-*` properties; treats inbound strings as untrusted; honors idempotent `msg_id`. An implementation advertising `X-PACT-SEAL: optional|required` additionally implements §13: `sealed_call` at every tier, the open order, and sealed results for sealed requests. **A 2.0 implementation** additionally: validates every chain by §14.2 and passes the shared vectors; carries its chain in every envelope it emits, request and result, and seals every 2.0 envelope with `PACT-SEAL-XWING`; keeps one pin per root — endpoint and latest leaf — treats an older leaf as no proof (§14.3), and learns a newer leaf at the pinned endpoint from any exchange; runs the new-address flow of §5.3 under `accept_new_hosts`; holds a superseded leaf's key until its `notAfter` and answers a former key with `certificate_renewed` (§14.4); deletes everything it held for an identity that has left (§9); continues to accept `v: 1` envelopes and `1` cards from contacts pinned as 1.x, per Appendix C. A wallet is a 2.0 implementation if it holds a root and nothing a host holds, signs a certificate only from an explicit user action, and shows the endpoint and the validity before signing.

---

## 13. Sealed envelopes

*Added in 1.1. Optional at the protocol level, negotiated per §3's `X-PACT-SEAL`; an implementation that never seals remains a conforming 1.0 peer toward `none` recipients.*

Plain mTLS ends where TLS ends. A terminating tunnel edge reads whatever crosses it and sees no client certificate — so behind such a pipe, both confidentiality and caller identity need a carrier that survives termination. The sealed envelope is that carrier: HPKE encryption to the sealing key the recipient's leaf carries, plus a detached signature by the sender's leaf signing key. In 1.x one key did all three jobs; in 2.0 the leaf carries two, because a post-quantum KEM key can neither sign nor terminate TLS, and every 2.0 envelope is sealed with the hybrid suite so that traffic recorded today stays closed to a quantum computer tomorrow. The sender's chain rides inside every envelope, which is how a renewed leaf travels.

### 13.1 Format

An envelope is a JSON object of four members:

| Member | Content |
|---|---|
| `protected` | base64url of the canonical-JSON header bytes (the HPKE AAD): `v` (=2), `suite`, `kid` (the fingerprint of the recipient leaf's signing key — it names the leaf whose sealing key this is sealed to), `msg_id`, `ts`, `exp` (integer Unix seconds; `exp − ts` ≤ 30 days), `cty` (`application/pact-call+json` for requests, `application/pact-result+json` for results). There is no `from` and no `to`: the sender is the chain inside the ciphertext, the recipient is the key. A `v: 1` header additionally carries `from` and `to`, 1.x key fingerprints, and is accepted from a pinned 1.x contact (Appendix C) |
| `enc` | base64url HPKE encapsulated key |
| `ct` | base64url ciphertext of the plaintext payload |
| `sig` | base64url detached signature by the sender's leaf key over `protected ‖ enc ‖ ct` (the raw byte concatenation of the three decoded members) |

`kid` is what lets a superseded key be refused before anything is opened, and refused usefully — with `certificate_renewed` and the current chain (§14.4). The header names one key and nothing else; the sender's certificates travel inside the ciphertext (§13.2), so a carrier sees which key a message is for, when, and how large — never who sent it, a name, or an address. The recipient's key id is stable for a leaf's life, and that linkage is the metadata that remains (§13.5).

Canonical JSON is the JSON Canonicalization Scheme of RFC 8785: UTF-8, keys sorted by code point, no insignificant whitespace, no HTML escaping, numbers in their shortest form. Suites (HPKE is RFC 9180, Base mode):

| Suite id | KEM | KDF | AEAD | For |
|---|---|---|---|---|
| `PACT-SEAL-XWING` | X-Wing: X25519 and ML-KEM-768 combined (draft-connolly-cfrg-xwing-kem; HPKE KEM id 0x647a) | HKDF-SHA256 | ChaCha20-Poly1305 | every 2.0 recipient, to the sealing key its leaf carries |
| `PACT-SEAL-P256` | DHKEM(P-256, HKDF-SHA256) | HKDF-SHA256 | AES-128-GCM | 1.x recipients with P-256 identity keys |
| `PACT-SEAL-X25519` | DHKEM(X25519, HKDF-SHA256) | HKDF-SHA256 | ChaCha20-Poly1305 | 1.x recipients with Ed25519 identity keys, birationally converted |

X-Wing's shared secret is the KEM shared secret directly, as its specification says; the DH KEMs derive theirs through ExtractAndExpand, as RFC 9180 says. A 2.0 sender MUST seal with `PACT-SEAL-XWING` toward a 2.0 recipient, and a 2.0 receiver MUST refuse a classical suite sealed to a 2.0 leaf (`envelope_invalid`): the hybrid is not a preference but the suite, so that no downgrade by omission exists. The signature uses the sender's own algorithm regardless of the recipient's suite — which is what lets any two identities interoperate; HPKE **Auth** mode was rejected precisely because a cross-curve pair cannot share an authentication DH. Pinned encodings: ECDSA P-256/SHA-256 signatures are ASN.1 DER; Ed25519 signatures are pure Ed25519 per RFC 8032. The HPKE `info` parameter is the ASCII string `PACT-SEAL-v2` for a `v: 2` header and `PACT-SEAL-v1` for a `v: 1` header, so an envelope of one generation can never open as the other. Ed25519 keys convert to X25519 per the standard maps: the public key by the birational map of RFC 7748 §4.1, the private scalar from the SHA-512-derived, clamped scalar of RFC 8032 §5.1.5. The HPKE ephemeral MUST be fresh for every envelope — a reused one repeats the key and the nonce, and two ciphertexts under them leak the XOR of their plaintexts — and both sides MUST refuse an all-zero DH output, which a low-order X25519 point produces (RFC 9180 §7.1.4).

`msg_id` is REQUIRED and MUST be non-empty — replay protection keyed on an empty string protects nothing. A protected header carrying a member not listed for its `v` MUST be rejected (`envelope_invalid`): the header is the AAD, and two implementations that disagree about what was signed cannot interoperate.

### 13.2 The `sealed_call` tool

Sealing is carried MCP-natively by one wrapper tool, `sealed_call`, present at **every** tier. Its tool arguments are the four envelope members of §13.1 at top level — `{"protected": …, "enc": …, "ct": …, "sig": …}` — and its result is an envelope of the same shape. The plaintext of a request envelope is one bare JSON object `{"method": …, "params": …, "chain": […]}` (no JSON-RPC framing) whose method MUST be `tools/call` or `tools/list`; `chain` is the sender's leaf and root, base64url DER, leaf first — the key that verifies `sig`, and the way a renewal reaches a contact — and is REQUIRED in every 2.0 envelope, request and result (a `v: 1` plaintext carries `spk`, the sender's SubjectPublicKeyInfo, as 1.2 defined it); the inner call is dispatched exactly as if it had arrived directly from the proven identity — same tiers, same permission switchboard (§8). **The result of a sealed request MUST be sealed back to the caller** (same format, `kid` naming the caller's leaf key, the request's `msg_id` for correlation, `cty: application/pact-result+json`, and the responder's own `chain` in the plaintext beside the result); result envelopes are never dispatched — the receiving caller decodes, opens, validates the chain, verifies the signature and correlates — and the request-side steps of §13.3 (idempotency, tiering) do not apply to them. A plaintext request gets a plaintext result. A guest's sealed `redeem_invite`/`request_contact` is bound three ways inside the opened payload: `chain` MUST validate (§14.2), `sig` MUST verify under its leaf key, and its leaf MUST byte-equal the `card` argument's `X-PACT-CERT` (in a `v: 1` exchange, `SHA-256(spk)` MUST equal `from` and the card's `X-PACT-KEY`). A sealed `tools/list` from an unknown sender has no card to bind and is rejected `envelope_invalid` (guests use plain `tools/list`, which always answers). Error results follow the sealing rule too: once a request envelope has been successfully opened, an error result MUST be sealed back like any other result — a plaintext error is only for an envelope that could not be opened at all, where there is no proven key to seal toward. `certificate_renewed` (§14.4) is always of that second kind: it answers an envelope sealed to a key the recipient no longer holds, which was never opened, so it travels in plaintext and carries nothing a caller trusts before validating the chain. `cty` is what binds direction: `application/pact-call+json` envelopes are dispatched, `application/pact-result+json` envelopes are only ever correlated, and an envelope whose `cty` does not match its position is rejected `envelope_invalid`.

### 13.3 Opening

Receivers MUST validate in this order, rejecting at the first failure: decode `protected`; check `v` and `suite` supported; resolve `kid` to a leaf key this endpoint holds for the identity served at the path the envelope arrived at — the current one, or a superseded one not yet past its `notAfter` — and otherwise answer `certificate_renewed` with the current chain when `kid` names a key this endpoint once held for that identity, `envelope_invalid` when it never did or holds it for another identity (§14.4); check that `suite` is the one that leaf takes (§13.1); HPKE-open to that leaf's sealing key; require the plaintext to carry exactly `method`, `params` and `chain`; validate the payload's `chain` (§14.2); verify `sig` under the chain's leaf key; resolve the tier (§6.1) — when the chain's root is pinned, a leaf older than the pinned one is a guest, a different endpoint is §5.3, a newer leaf at the pinned endpoint replaces it; when it is not pinned, apply the guest binding of §13.2; enforce time — `now < exp`, and `|now − ts| ≤ 300 s`, since every 2.0 envelope is delivered directly; enforce `msg_id` idempotency (a replayed envelope is acknowledged with its original result, never re-executed); then dispatch. Failures map to `envelope_invalid`. A `v: 1` envelope is a 1.x proof: its `from` resolves against contacts pinned as 1.x only, an unpinned `from` is a guest bound by the 1.x rule of §13.2, and a 2.0 contact's root fingerprint never resolves through it (Appendix C). A *substantive call* is any unsealed `tools/call` other than `sealed_call` itself; from an identified caller to a `required` recipient it fails `seal_required`, and a call carrying no usable identity proof where one is needed fails `identity_required` first (§12). Idempotency records for seen `msg_id`s MUST be retained at least until the envelope's `exp`. Envelope `msg_id`s and the inner call's `msg_id`s are separate namespaces; implementations SHOULD prefix envelope idempotency keys (`env:`) so one store serves both without collision. A **blocked** sender's envelopes MUST be processed exactly as an unknown sender's — the guest card-binding rules of §13.2 apply and a sealed `tools/list` is rejected `envelope_invalid` — so sealing never becomes an oracle distinguishing blocked from unknown (§12); a guest envelope whose inner call carries no `card` argument is likewise rejected `envelope_invalid`.

### 13.4 Negotiation

`X-PACT-SEAL` on the card (§3): `none` — the recipient does not accept envelopes (`sealed_call` absent; senders MUST NOT seal); `optional` — both accepted; senders MAY seal; `required` — unsealed substantive calls are refused (plain `tools/list` still answers with whatever the transport identity earns), and senders MUST seal. A node MAY additionally require transport client certificates (a `client_cert` posture knob) and refuse a certificate-less `sealed_call` with `identity_required`. That is an owner's hardening choice about their own front door, not a protocol contradiction: the envelope still proves who is calling; the certificate requirement decides who may knock at all. Such a node is unreachable through terminating edges by construction — which is sometimes exactly the point.

### 13.5 Stated trade-offs

Unchanged in spirit from §11, extended by sealing, and documented rather than papered over: **no forward secrecy** — HPKE Base mode to a long-lived key means a later compromise of a leaf's sealing key decrypts ciphertext recorded while it was current; mitigations are the 300-second window and the leaf's lifetime — a sealing key lives at most 398 days, and a renewal with fresh keys retires it — which bound the exposure, not fix it. **Post-quantum:** the hybrid KEM keeps recorded traffic closed to a quantum computer; the signature is still classical, so a quantum computer present *today* could forge, which is a threat on another clock and the next generation's change. **Metadata is less than 1.x showed, and not nothing:** a carrier sees `kid`, timing and sizes, and can tie every message to one recipient key for that leaf's life; it no longer sees who sent it. **The leaf's signing key does TLS and signatures; its sealing key does sealing**; `kid` names the leaf. The signing key signs exactly four structures — a TLS handshake, a certificate signing request, a card, an envelope — each distinguishable by its first bytes, and an implementation MUST NOT sign anything else with it. The `v: 1` vectors for both suites live in Appendix B, and the `v: 2` and certificate vectors beside them; an implementation that opens and verifies all of them is envelope-interoperable.

---

## 14. Certificates

*Added in 2.0.* Two X.509 certificates, one rule about which leaf is newest, and one answer for a caller holding an old key. Everything a verifier needs is in the chain it is handed; nothing is fetched, and there is no directory.

### 14.1 Profile

Both certificates are X.509 v3 (RFC 5280). Signing keys are Ed25519 (RFC 8410) or ECDSA P-256; signatures are Ed25519 or ECDSA with SHA-256, in the encodings §13.1 pins. A leaf's sealing key is X-Wing (draft-connolly-cfrg-xwing-kem): 1216 bytes of public key — ML-KEM-768 then X25519 — derived from a 32-byte seed the host keeps, carried in the `pactSealKey` extension under the registration-free UUID arc of ITU-T X.667. A certificate's `signatureAlgorithm` MUST be its issuer key's own algorithm; a verifier takes the algorithm from the key, never from the certificate, so a mismatch is simply a certificate the key did not sign. A **key identifier** is the 32-byte SHA-256 of the SubjectPublicKeyInfo — the bytes a fingerprint (§2) encodes — used for `subjectKeyIdentifier` and `authorityKeyIdentifier` alike, so the leaf's issuer key identifier *is* the root's fingerprint.

| | Root | Leaf |
|---|---|---|
| issued by | itself | the root |
| `subject` | one `commonName`, untrusted (§3) — the wallet fills it with the person's chosen name | one `commonName`, untrusted |
| `serialNumber` | random, at least 64 bits | random, at least 64 bits |
| validity | `notBefore` at creation; `notAfter` `99991231235959Z`, RFC 5280's "no well-defined expiration" — a root is never rotated | `notBefore` the later of one hour before issuance and one second after the previous leaf's `notBefore` — the wallet knows every leaf it issued, so a verifier whose clock runs a little behind still accepts, and no leaf is superseded by its own predecessor; `notAfter` at most 398 days after `notBefore`, RECOMMENDED one year |
| `basicConstraints` | critical; `cA` true; `pathLenConstraint` 0 | critical; `cA` false |
| `keyUsage` | critical; `keyCertSign` only | critical; `digitalSignature`, plus `keyAgreement` for a P-256 key |
| `extendedKeyUsage` | — | `serverAuth`, `clientAuth` |
| `subjectAltName` | — | exactly one `uniformResourceIdentifier`: the endpoint, an `https` URL in RFC 3986 normal form — lowercase scheme and host, no default port, dot segments removed, percent-encoding uppercase and minimal, a non-empty path, no userinfo, query, fragment or trailing slash — the one string the host advertises and callers dial. MAY add the `dNSName` of that URL's host, for TLS stacks that match names; a `dNSName` that differs from the URI's host is a refusal |
| `subjectKeyIdentifier` | its key identifier | its key identifier |
| `authorityKeyIdentifier` | — | the root's key identifier, and nothing else |
| `pactSealKey` — 2.25.165898202536361518156571913262952224823 | — | non-critical; OCTET STRING holding the X-Wing public key, 1216 bytes |

A **chain** is the leaf followed by the root and nothing else; a verifier refuses any other length. The profile is exact: a certificate that carries an extension not listed here, critical or not, a duplicated extension, a name of another shape, a signature algorithm other than its issuer key's own, a non-minimal DER length, or a byte after its end is not a PACT certificate. An exact profile closes the whole class of things one parser sees and another does not, rather than one instance at a time. There is no CRL, no OCSP and no policy: revocation is the next leaf (§14.3), and expiry is expiry.

### 14.2 Chain validation

A verifier handed a chain applies these in order and refuses at the first failure — `envelope_invalid` in an envelope, a refused handshake for a client certificate, `bad_request` for a card:

1. The chain has exactly two certificates, and each matches §14.1 exactly — the first as a leaf, the second as a root: the fields, the algorithms, the extensions and their criticality, nothing more, in strict DER with nothing after the end. A single self-signed certificate is not a chain: it is a 1.x proof, resolved by its key's fingerprint against contacts pinned as 1.x (Appendix C) and otherwise a guest's.
2. The second is a root: self-signed, its signature verifying under its own key, `cA` true, `keyCertSign` set. Its key identifier is computed from its key as §14.1 defines, never read from the certificate, and its fingerprint is the identity. When the verifier already holds a fingerprint for the identity in question — from a pin, or from the issuer key identifier of a card's certificate — the two MUST be equal.
3. The first is a leaf: its signature verifies under the root's key, its `authorityKeyIdentifier` equals the root's computed key identifier, `cA` false, `digitalSignature` set.
4. The verifier's clock is within the leaf's `notBefore` and `notAfter`, and `notAfter − notBefore` is at most 398 days.
5. The leaf's `subjectAltName` holds exactly one URI, an `https` URL: the endpoint. When the verifier knows which address is in question — the URL it dialed, the endpoint it pinned, the endpoint in the card — the URI MUST equal it byte for byte — both are the normal form of §14.1, so nothing is normalised at comparison time. A mismatch is a refusal, never a warning. A `dNSName` beside the URI MUST equal its host, and the address guard of §3 — no loopback, link-local or private host; never the verifier's own endpoint from a guest — applies before any dial.
6. The leaf's key is then the proven key: what `sig` must verify under (§13), what a client certificate must present, what to seal to.

A verifier never trusts a host, a card, or a provider. It trusts the fingerprint it pinned and the rules above. The rules govern a chain the verifier validates; the key a sender seals its first call to is read from a card, needs no validation, and may belong to an expired leaf (§3).

### 14.3 The newest leaf wins

For each pinned identity a verifier keeps the endpoint and the latest leaf it accepted. A leaf whose `notBefore` is earlier than the pinned leaf's is **superseded**: a caller presenting it resolves to no pin and gets the guest tier (§6.1), a result carrying it is `envelope_invalid`, and nothing is sealed to it. A leaf with a later `notBefore` at the pinned endpoint replaces the pinned one as it passes — a renewal; at another endpoint it is a new address (§5.3). Equal `notBefore` and equal bytes is the pinned leaf; equal `notBefore` and different bytes is refused.

The rule is absolute. A newer leaf from the root takes priority the instant it is seen, whatever the validity of the older one: at that contact the older leaf's cycle is over — retired, rogue, or stolen — and nothing it does afterwards is the identity's. There is no dampener and no grace, because any delay would be time a compromised leaf keeps speaking. Only the root can produce a leaf with a later `notBefore`, so no host can outrank the person, and a host that has been replaced can outrank nobody who has seen its replacement. What the rule cannot do is reach a contact that has seen nothing new: that contact goes on accepting the old leaf until its `notAfter` — the reason a leaf's validity is short, and the reason a host that has been left must delete the key (§9). A sequence number would add nothing that `notBefore` does not already carry, signed by the root; the wallet keeps it monotonic across the leaves it issues (§14.1).

### 14.4 `certificate_renewed`

An endpoint keeps the key identifiers of every leaf it has held for an identity it still serves — fingerprints, never keys past their `notAfter`. An envelope whose `kid` names one of them and no key it still holds is answered, in plaintext, with `certificate_renewed` and data `{"chain": [leaf, root]}`: the identity's current chain at this endpoint. The caller validates it (§14.2) against the root it holds and the address it dialed, updates its pin, and re-seals. A `kid` the endpoint never held is `envelope_invalid` with nothing attached — which is also what an identity that has left gets at its old address, because a host that has been left keeps nothing (§9). The answer proves nothing by itself; only the chain's validation does, and a forged one fails rule 2. A caller follows `certificate_renewed` at most once per call, and only when the chain it carries is newer than or equal to its pin (§14.3): an older chain, a chain to another root, or a chain naming another address is discarded and the call fails as it would have. A `kid` this endpoint holds for a *different* identity is `envelope_invalid`, never opened and never answered with a chain — a provider serving many identities on one origin must not let one identity's key answer at another's path.

### 14.5 Compromise cases

What an attacker can hold, what stops each, and what each still costs. Every row names rules that live elsewhere in this document; the table is the checklist, not a new mechanism. `vectors/intrude.mjs` in the repository replays each row, and the corner cases around it, against the seed implementation, and reports which attacks are blocked and which succeed by decision.

| The attacker holds | What stops it | What remains |
|---|---|---|
| **The root**, from a stolen and opened vault | Nothing cryptographic, by decision: whoever holds the root is the person. What makes the theft hard is the passphrase and memory-hard derivation, the hardware wrap, the extension's own window, and the passphrase asked again for a new endpoint (§9). What lets contacts notice a move the person never made is `ask` and the event shown under `auto` (§5.3). What ends a war between two holders is nothing a rule can do — the newest leaf wins for whoever minted last (§14.3), so a fought-over root is abandoned — and what prevents one is a root in a hardware key (§9) | a new identity, re-shared over human channels; the wallet's contact book is the list to call |
| **A leaf key**, from a host | The key speaks only from its one address and can neither issue nor move; a renewal with a fresh key outranks it with every contact it reaches (§14.3); leaves expire within 398 days | contacts that exchange nothing until then; ciphertext recorded to that key (§13.5) |
| **The current host** itself, rogue | As every hosted service: bounded to one address and one date by the leaf, unable to change either, and answerable to the wallet's contact book and the export the person can take anywhere | what it does while it serves — reads, sends, refuses to renew — shows only in its audit chain and in silence |
| **A former host's leaf**, still valid after a move | Newest leaf wins with every contact reached; the campaign runs before the old host is told; the removal tombstone defeats a scorched-earth `remove_contact` (§5.3); the address is not reassigned until the leaf expires; the duty to delete, audited (§9) | contacts the campaign never reached, until the leaf expires |
| **The sign-up page**, keeping the root it made | The ceremony runs where the page cannot read, open-source and integrity-pinned (§9); a person who will not trust it brings a wallet | the same trust as any web wallet |
| **A CSR** for an address of the attacker's choosing | The wallet shows the endpoint, the asking origin, and whether the host is new; verifies proof of possession; demands the passphrase for a new endpoint (§9) | a person who signs what they did not read |
| **The wire**, as a carrier or edge | Sealing with the hybrid post-quantum suite; the sender inside the ciphertext (§13.1) | messages tied to one recipient leaf for its life; no forward secrecy |
| **A quantum computer**, later, and today's recordings | Every 2.0 envelope is sealed with X-Wing, X25519 and ML-KEM-768 together (§13.1) | forging with one *today* against classical signatures — a threat on another clock |
| **A certificate** that reads one way to one parser and another to the next | The exact profile and strict DER of §14.1: nothing unlisted, nothing duplicated, nothing trailing, the declared algorithm the issuer key's own | nothing |
| **A forged or replayed `certificate_renewed`** | Validation to the caller's own pin, the newest-leaf rule, the dialed address, one follow per call (§14.4) | nothing |
| **A card** naming a hostile, internal, or borrowed address | The address guard at intake and before every dial (§3, §14.2); a guest's endpoint never equals the receiver's own; a guest at an address that belongs or lately belonged to a pinned contact is never auto-accepted and is shown beside that contact's name (§5) | a person who approves a stranger whose card wears a friend's name at a fresh address — the 1.x residual |
| **A leaf key**, used for a 1.x rotation toward 1.x peers | Nothing: a 1.x pin follows the key that signed the rotation (Appendix C) | 1.x contacts taken until they upgrade or re-add |
| **Free roots**, flooding `request_contact` | Two guest tools, rate-limited by address and root (§12); human approval; invites with expiry and uses | as in 1.x |
| **A poisoned archive**, from a former host | No key enters (§9); the wallet's contact book is the authority and every difference is shown | contacts the person never kept in the wallet |
| **An unlocked extension**, driven by a page | Signing only from the extension's window after a click; the passphrase again for a new endpoint (§9); the leaf key signs nothing but its four structures (§13.5) | a renewal for the same endpoint, which changes nothing a contact sees |

---

## Appendix A: worked examples

The examples below are 1.x wire shapes, kept because a 2.0 implementation still exchanges them with pinned 1.x contacts (Appendix C). The 2.0 shape of the first one differs in the card and the response only:

```json
{ "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
    "name": "redeem_invite",
    "arguments": {
      "token": "inv_8Qq1xZk3",
      "card": "BEGIN:VCARD\nVERSION:4.0\nFN:Bharat Mehta\nX-PACT-VERSION:2\nX-PACT-CERT:MIIBkTCCAUOgAwIBAgIUX7…\nX-PACT-SEAL:required\nEND:VCARD"
    } } }
```

Response: `{ "status": "pending", "card": "<Alina's 2.0 vCard>", "card_sig": "<b64 sig by Alina's leaf key over the vCard bytes>", "chain": ["<b64url DER of Alina's leaf>", "<b64url DER of Alina's root>"] }` — and before pinning, Bharat's agent validates the chain (§14.2): the root's fingerprint equals the issuer key identifier in the card's certificate, the leaf byte-equals the card's `X-PACT-CERT`, and the leaf names the endpoint Bharat's agent will call from now on.

**Invite redeem, 1.x (MCP tool call, B → A's server):**

```json
{ "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
    "name": "redeem_invite",
    "arguments": {
      "token": "inv_8Qq1xZk3",
      "card": "BEGIN:VCARD\nVERSION:4.0\nFN:Bharat Mehta\nX-PACT-VERSION:1\nX-PACT-ENDPOINT:https://agent.bharat.example/mcp\nX-PACT-KEY:sha256:Xf7dO2vUf2-ijuFdlp1bsOpTd01Ii9r53xxuASSz7yI\nEND:VCARD"
    } } }
```

Response: `{ "status": "pending", "card": "<Alina's vCard>", "card_sig": "<b64 sig by Alina's key over the vCard bytes>", "spki": "<b64url DER SubjectPublicKeyInfo of Alina's key>" }`

**Message (A's agent → B's server):**

```json
{ "jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {
    "name": "send_message",
    "arguments": {
      "msg_id": "b2f6b7f0-3f0a-4d55-9f6e-2a1c9d4e8a11",
      "thread_id": "T-coffee-2026-08",
      "topic": "Coffee catch-up",
      "text": "Alina's assistant here - Alina would like 45 min with Bharat next week, mornings, Koregaon Park. What works?",
      "sender": "agent"
    } } }
```

Response: `{ "thread_id": "T-coffee-2026-08", "status": "delivered" }`

**Booking:** `check_availability {window:{from:"2026-08-24T00:00:00+05:30", to:"2026-08-29T23:59:59+05:30", tz:"Asia/Kolkata"}, duration_min:45}` → `{slots:[{start:"2026-08-25T10:00:00+05:30", end:"2026-08-25T10:45:00+05:30", tz:"Asia/Kolkata"}, …]}` → `book_slot {msg_id, slot, subject:"Coffee catch-up", thread_id:"T-coffee-2026-08"}` → `{booking_id:"bk_91h2", ics:"<base64>"}`.

## Appendix B: sealed-envelope test vectors

Four `v: 1` vectors, one per sender/recipient curve pairing, which a 2.0 implementation must still open from pinned 1.x contacts (Appendix C). Keys are PKCS#8 DER (hex); `protected`, `enc`, `ct`, `sig` are the wire members (unpadded base64url). To pass: decrypt `ct` with the recipient key and the §13 parameters (AAD = decoded `protected`, info = `PACT-SEAL-v1`), compare against `plaintext_hex`, and verify `sig` with the sender key over the decoded `protected‖enc‖ct`. The `v: 1` vectors were generated by the reference implementation's deterministic generator (`internal/envelope/cmd/genvectors`); ECDSA signatures are one valid signature (ECDSA is randomized), everything else is reproducible byte for byte.

```json
[
  {
    "name": "p256-to-p256",
    "suite": "PACT-SEAL-P256",
    "sender_key_pkcs8_hex": "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b020101042061b166252295c65954e0dfb828b3b9abb0fc8ca2055508661077edb4a0ba7ae1a144034200049bfa9cd35edc77da581131b4bc2c0310cd144eb8627d2279bfd15460fd7b0363fa9f3769844a137eabb53030d2c5492836ff51f671331cc32e139ed3afaeb496",
    "recipient_key_pkcs8_hex": "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420d866a28733d07c5c4f587c8d1d3264ec9b793dfc97cb0311fea40d47095496a2a14403420004577951164a653fb35931e80ce8b3db6ce2828f947f9ee7898f59549f4163e3679a81aa362a26910f4ba4c9e937db6432a18819dde3f0d651cb8fb7d856f78764",
    "plaintext_hex": "7b226d6574686f64223a22746f6f6c732f63616c6c222c22706172616d73223a7b226e616d65223a2273656e645f6d657373616765222c22617267756d656e7473223a7b226d73675f6964223a227665632d31222c2274657874223a2268656c6c6f2066726f6d207468652050414354207465737420766563746f7273227d7d7d",
    "protected": "eyJjdHkiOiJhcHBsaWNhdGlvbi9wYWN0LWNhbGwranNvbiIsImV4cCI6MTc1NjAwMDYwMCwiZnJvbSI6InNoYTI1NjpjWFIyYWdiZnFKb1VlNDZVeHgtOVRoSG1wb2lnSklYZTJ2bktTRzZPdUhFIiwia2lkIjoic2hhMjU2Om11VmVlbFpQeDg2d0FMQUhJVUo2VURGS2lmZkN3Z3RVd21lWHBoNDNzYU0iLCJtc2dfaWQiOiJ2ZWMtcDI1Ni10by1wMjU2Iiwic3VpdGUiOiJQQUNULVNFQUwtUDI1NiIsInRvIjoic2hhMjU2Om11VmVlbFpQeDg2d0FMQUhJVUo2VURGS2lmZkN3Z3RVd21lWHBoNDNzYU0iLCJ0cyI6MTc1NjAwMDAwMCwidiI6MX0",
    "enc": "BN0cRaGNSlhqPW-BM4YSFGyyJu5G3qaTT4IJ64LaAHWmRbuw9ZChCDZ1cVESgkrYeJZG7VflwiBb17JYSihPwvM",
    "ct": "s86vY-5CXEzrEnGgfBnQgR3EvZ5Dk5JUOz8FAYrlx78T6Hzdyuv6-y0fO22tTqdv2j0-sQxDFUz0h8tLWJA1171YA_WIIyMZUY6rn5NjSR1Yl_FIz8f97WXvVerhlgqB7GsPGkRtl70e33jmYXWwqEGAiG0rpc-LnS2URSRwuGYOQ9gaNtvl44cCslZHCbay8A",
    "sig": "MEUCIBgckxmyYKDG0I5HxoyI8tHe0PCe4Fap2KBxVLSdojR0AiEA9P6r9cm0DH4kA_DrOJEU1uNcLMF5jJ2DszfoSmiGVh8"
  },
  {
    "name": "p256-to-ed25519",
    "suite": "PACT-SEAL-X25519",
    "sender_key_pkcs8_hex": "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420bbbf2eac3d953b44479e70ad2103cff1baac7fe8bb43d9a0b0ba654a540c7646a14403420004e59ea0e956518497dd1b4b5d0a94c80190d4b239b22b04fbbef43c1be5725e759d2d3d86e5cb90e5efea543c87baa3cb57c104b01da42a2f7bf0cbf4983095e0",
    "recipient_key_pkcs8_hex": "302e020100300506032b6570042204203c86992285a1d54b7b6ac42f7aeed88e4a41020b13edc20529fef6c19a79012c",
    "plaintext_hex": "7b226d6574686f64223a22746f6f6c732f63616c6c222c22706172616d73223a7b226e616d65223a2273656e645f6d657373616765222c22617267756d656e7473223a7b226d73675f6964223a227665632d31222c2274657874223a2268656c6c6f2066726f6d207468652050414354207465737420766563746f7273227d7d7d",
    "protected": "eyJjdHkiOiJhcHBsaWNhdGlvbi9wYWN0LWNhbGwranNvbiIsImV4cCI6MTc1NjAwMDYwMCwiZnJvbSI6InNoYTI1NjpBZV9VY292MUw4SEJ6SHdZVHZ5S09MOGlicFdsT1pFbENlWTBmamE0ZUc4Iiwia2lkIjoic2hhMjU2OmRjQldWOTZOV3QyMzl6cDBvbm00REp1bTZ1RlBZR3NrYVBzbnU3RUMyT0EiLCJtc2dfaWQiOiJ2ZWMtcDI1Ni10by1lZDI1NTE5Iiwic3VpdGUiOiJQQUNULVNFQUwtWDI1NTE5IiwidG8iOiJzaGEyNTY6ZGNCV1Y5Nk5XdDIzOXpwMG9ubTRESnVtNnVGUFlHc2thUHNudTdFQzJPQSIsInRzIjoxNzU2MDAwMDAwLCJ2IjoxfQ",
    "enc": "NhMd2t8iCmE2mLOWTEH1tIAEFs8kU3IpU4BaIKTevmo",
    "ct": "RRWCOb0Lc4j00RovWFGacFJERV_q2ZRyJS6e7L7Bj_p3ZnQfBkmARuB6ycRL6aWWJsvjt_6WSoZmpTsnEglAvp2SpBlItgNJQ8V8rPVQmPP774FfWMV4nC1w1yl6rGrmkIpyUaHaPH4O_fT8grTfoiKj3gYz9MUcFjPGU-auoFmLBABe3c0k8peHpBZmkCnLrA",
    "sig": "MEQCIAEH8mwCYubrCSQ04Ur4W2en36a0Ktq1UvP6HivPks1QAiBN0Dez4anJitNgvr5GLnXNUrgXA4dBWlSsnwNbbWNIyQ"
  },
  {
    "name": "ed25519-to-p256",
    "suite": "PACT-SEAL-P256",
    "sender_key_pkcs8_hex": "302e020100300506032b657004220420dded58571510c5d3905ba4204f12610820f8dacafa279629d1dfd2397c6bc306",
    "recipient_key_pkcs8_hex": "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420042e2e259509c4031cfdd0776123925a0c8c127cc5407673b31082a7557d96a5a14403420004e6ca8deed080dd33d4564fcad397c80fdb30337fae655189ac73d769342067ff20e3456f864a79739d99b94a40ec3a8db461fcb4ba796b43df8ddd643e62d39d",
    "plaintext_hex": "7b226d6574686f64223a22746f6f6c732f63616c6c222c22706172616d73223a7b226e616d65223a2273656e645f6d657373616765222c22617267756d656e7473223a7b226d73675f6964223a227665632d31222c2274657874223a2268656c6c6f2066726f6d207468652050414354207465737420766563746f7273227d7d7d",
    "protected": "eyJjdHkiOiJhcHBsaWNhdGlvbi9wYWN0LWNhbGwranNvbiIsImV4cCI6MTc1NjAwMDYwMCwiZnJvbSI6InNoYTI1NjpXMjNOYlRaanJrNjEzcnpNRlUwVEZUTUxEaVJCcDZkRFlBRlRWS3FPMzhvIiwia2lkIjoic2hhMjU2OnBlTEstTnp4SFBZbEo4LXFOMkh1N0ZURnhXMmxqX1NxeldiUHdjNFhLclEiLCJtc2dfaWQiOiJ2ZWMtZWQyNTUxOS10by1wMjU2Iiwic3VpdGUiOiJQQUNULVNFQUwtUDI1NiIsInRvIjoic2hhMjU2OnBlTEstTnp4SFBZbEo4LXFOMkh1N0ZURnhXMmxqX1NxeldiUHdjNFhLclEiLCJ0cyI6MTc1NjAwMDAwMCwidiI6MX0",
    "enc": "BPMaVDxwpReY1Mva9jURDxm1_QXRQR6mklh7bMtzi2kYHohwuDtD-UyFiAo40EJ51_1XHnyYU6FFCpACNGCZdQA",
    "ct": "5otl61qtp0U59GnHjjPTuWAlFYexOpKmLjrsU7mh1ADVFSbEvpPEkqM3RMobw1o_blyWQYz4EWQDa0dKeAK-B-emYRbymFghUEjTgB5ew5iF8RkYWvmWufdd0dbZN-ZMecssmJLzGI8QVtA7TJRQ2_5SrXBn_zXzsZ9NY0eWQ_PUUpBIk8Vf6RIyphDL0_Kpzg",
    "sig": "Qm0AMcKuTmFhRy3t8EQPVn66phvkqna9ScU_xQGqZdK987KlB7Sfd1lvbX1V2sQbdCLS3hDOcNNdxGH1ElGzBw"
  },
  {
    "name": "ed25519-to-ed25519",
    "suite": "PACT-SEAL-X25519",
    "sender_key_pkcs8_hex": "302e020100300506032b6570042204201082593d1ed0548c80d9d1647754bc3e10a16e718e19497e763ee5981350de40",
    "recipient_key_pkcs8_hex": "302e020100300506032b6570042204208c4cf5dd038d748d9b710a79c818ebd2b80fa27976a507ca050bf81f10f1c5b1",
    "plaintext_hex": "7b226d6574686f64223a22746f6f6c732f63616c6c222c22706172616d73223a7b226e616d65223a2273656e645f6d657373616765222c22617267756d656e7473223a7b226d73675f6964223a227665632d31222c2274657874223a2268656c6c6f2066726f6d207468652050414354207465737420766563746f7273227d7d7d",
    "protected": "eyJjdHkiOiJhcHBsaWNhdGlvbi9wYWN0LWNhbGwranNvbiIsImV4cCI6MTc1NjAwMDYwMCwiZnJvbSI6InNoYTI1NjpydXRKaUNSTkpiVWFjVHA0M0xnakVsZjFlV1poX1l2TGZNZlBvZVpJRk9VIiwia2lkIjoic2hhMjU2OnZmOFBuTDYwYUdLUmx1TVFXbUo5aWtUeUljTHh1Yk9EWHpEOExsdmlFQnMiLCJtc2dfaWQiOiJ2ZWMtZWQyNTUxOS10by1lZDI1NTE5Iiwic3VpdGUiOiJQQUNULVNFQUwtWDI1NTE5IiwidG8iOiJzaGEyNTY6dmY4UG5MNjBhR0tSbHVNUVdtSjlpa1R5SWNMeHViT0RYekQ4TGx2aUVCcyIsInRzIjoxNzU2MDAwMDAwLCJ2IjoxfQ",
    "enc": "dGH3Zm64Ur_VKqlrCX2mtRaSd1fOjy6GuuAOlduklFw",
    "ct": "B2MIdlrfx82bnSHrNisCkYbuGm3TPhjXly-kfF1i3B4Mthjqg7a1KCbyM3SEwqEDe_QFVBRTFhD9isg3Y7neflVCTw3oxmt5hhpuHW74_ImSi5bVAlLbTcNkVxWJxsJOFfIVbnhczLCV_EF8aM_kfDts-wiesq0cBbj4dUdQVYgIugRwbpAigJnT836c4_t4Cg",
    "sig": "pH9HMbtRYn7_IEz_NuSPYaOBQ3JgyvbBYjkBZKjyv9PEog2LIDyEvVSdwSsgQ-zShoCuq_zHZBPEovEbKH2FCw"
  }
]
```

**The 2.0 vectors.** Generated by `vectors/gen.mjs` in this repository — every key derives from a label, so the certificates and the Ed25519 signatures reproduce byte for byte; ML-KEM encapsulations and ECDSA signatures are one valid instance — and proven against this document by `vectors/check.mjs`, which opens the four `v: 1` vectors above with the same code before it touches these. Eight certificates to the §14.1 profile (two roots; two valid leaves, each carrying an X-Wing sealing key; an expired leaf; a 404-day leaf; a successor leaf under fresh keys; and a leaf without a sealing key, which is not a 2.0 leaf); thirteen chain cases, each refusal naming the §14.2 rule it fails; four §14.3 comparisons; three `certificate_renewed` answers, two of them discarded; and two `v: 2` envelopes, one each way, sealed with `PACT-SEAL-XWING` to the recipient leaf's sealing key, with the sender's chain inside the plaintext and a header of `v`, `suite`, `kid`, `msg_id`, `ts`, `exp` and `cty`. To pass the envelopes: derive the recipient's X-Wing key from its `sealing_key_seed_hex`, open `ct` with the §13 parameters (AAD = decoded `protected`, info = `PACT-SEAL-v2`), compare against `plaintext_hex`, validate the `chain` in the plaintext, and verify `sig` under its leaf key over the decoded `protected‖enc‖ct`. `seal_key_extension_oid` is the extension's OID. The root private keys are not in the vectors, because a verifier never needs one; the leaf keys are, so the envelopes open.

```json
{
  "generated_by": "vectors/gen.mjs (every key derives from a label; certificates and Ed25519 signatures reproduce byte for byte; ML-KEM encapsulations and ECDSA signatures are one valid instance)",
  "now": "2026-09-13T12:00:00Z",
  "seal_key_extension_oid": "2.25.165898202536361518156571913262952224823",
  "certificates": {
    "root_a": {
      "der_hex": "308201313081e4a0030201020209009902956916dc1741300506032b657030143112301006035504030c09416c696e612052616f3020170d3236303930313030303030305a180f39393939313233313233353935395a30143112301006035504030c09416c696e612052616f302a300506032b65700321000cb85b79f8e09ac5e8264d833c151113b1002f17dcc1bf5c4497d24b7cffd3b0a351304f30120603551d130101ff040830060101ff020100300e0603551d0f0101ff04040302020430290603551d0e04220420633cfd0fb6be62a0e97c519bafa4abf363a5f8b4f37f3db26bffc320abad9bec300506032b65700341006af142b4666634fcdd49896354d52a763bae899b3f42f7c059070078078d993435bd09ab85c9c8f60e0721a85280b10e8169fbaee2ba52feca3bf9c8460b6501",
      "note": "Ed25519 root, self-signed, CN \"Alina Rao\", notAfter 9999-12-31"
    },
    "root_b": {
      "der_hex": "308201783082011ea003020102020900e51123c1ee85d6e0300a06082a8648ce3d04030230173115301306035504030c0c426861726174204d656874613020170d3236303930313030303030305a180f39393939313233313233353935395a30173115301306035504030c0c426861726174204d656874613059301306072a8648ce3d020106082a8648ce3d0301070342000400b37ef8a33dc093cc42687c60aef3f73ab71289ef82625e1482531d848714e35f3c490ba6e9a3a028c023815fba8209f0f511a4b78b420ca45fac122bdbce27a351304f30120603551d130101ff040830060101ff020100300e0603551d0f0101ff04040302020430290603551d0e04220420f53e3a50e4c41653c2db3189679a867339db836d79c5b0ba6f1704d13e50a2b3300a06082a8648ce3d040302034800304502202021fc5c4bb6e483b84d97172eec8306df9033b303ad563fc493b687cf4d981c02210086472d10ee2ec7871f30ccb7488112a9b0ebe7499dcbb17eed5ece42efc56d66",
      "note": "P-256 root, self-signed, CN \"Bharat Mehta\""
    },
    "leaf_a": {
      "der_hex": "3082069d3082064fa003020102020900ea540e3161472cf5300506032b657030143112301006035504030c09416c696e612052616f301e170d3236303930313030303030305a170d3237303930313030303030305a30143112301006035504030c09416c696e612052616f302a300506032b65700321004eeb9d16157a525df7081d67dd25af338526e6b6cec2fa43e4536a0c4213cff4a38205bc308205b8300c0603551d130101ff04023000300e0603551d0f0101ff040403020780301d0603551d250416301406082b0601050507030106082b06010505070302303f0603551d1104383036861f68747470733a2f2f6167656e742e616c696e612e6578616d706c652f6d637082136167656e742e616c696e612e6578616d706c6530290603551d0e042204203579fc22b8c43dd0ffb01278a0e62b4d5507e487c10830d9cd4a25af989f0252302b0603551d23042430228020633cfd0fb6be62a0e97c519bafa4abf363a5f8b4f37f3db26bffc320abad9bec308204de06146981f9ceeab8f4b58e94c4e4b1b7f8fe92a8b037048204c4048204c001b97c6395ae691cab0eea5ab462a58534ac99e559759c919ecc7884e69a61a5cca4399246a401ca39226033266053c7f5080a3f2b0474b47a238023ebe8429ae3294138b02feb7be9c6427e5580e71331b9098a5763117f60735a5b25bc670629da6e69d8a8aae04994f1c9fb18453d1a44faf21b5ec767715479a5d27fcee86c0d4a211aaa0642568dac632fec214bebb6a3ef0010cdba7dd6957338b31200ed3fc353af075a2344f15e11a3161afa55abe15aebd363ca6c3bccd79bcf407cf4490b49998b7b51be0e624c0573ac67fb1c22761cf9372a449b0b441160cf94548e3073e2d74e9993270f00330d0b1499793ae702b2c0f32d3743993450672868a80f614c62e79277e7c55a39cbb3a4b830a381df0a0c6a08ad9c590695c93b6c9ca8d2a82b7040c8c24a3889128ba65516c1a99c4b2b0fc37329570245294764ff2ab1a3e86c3209c889f347b755663c1c75f7d6c809c37933e38feb038ea5300899d3699889a29961a0b5c8cb1bb66df2b62c4a7c0b93e66168611cc8e214dab6156470c930a702bc8b4f307587a43596a5057008d6401389894b2b428be116a7eaa2736704855061629616d409076adb872153b0bcd9028b51910bf518dde7b480b83376711b5831996837b43e409952158f0448293e34ad73706c746ca81ceab2f6972076f88b2df737de1a432d8c5709d7cb0fc67c5fe1c38012b2389748154bc492acbc2830b417da1ba85a5f8478914e25c6f178a63e751e8893c6fae48fb05b24dce10abb3773de691a2262a96521636c43306dc52318599d5f336ae063c124f46d6cd9856172cd11476fa6f81392121bbf3aba7eb1cdc70100f42076219c0c4c393b8e656cbb133a2ce728cd41413fd210b2a5c285eacb7ddb74a42902a2ba09108ca8c82911bd473b8700ae51b75a00058fc8e643def475dd180a84033500102180fa5bceec18518b6a0ae91ffeb3b679d37e059a9ba39a445b401939a87c4a4c222285384b668ba8f24c35db45ab3026e0e0c1425b2b51acb41cc26e2cb316ad63b253736691f62ff681b0941b808cdba3e5d36514e384b0e7bb20f6b6dfe54e79422f69f68066b30aecf3b066e03b086ca4daf6981486b98af48c68463616e979c1800f0cd90cede2270757cfcb2a6cd2a7533d546d6bf80d70eb465b0954a9985551c75e1cfb42ef452a6e8a4bcb569a0c388180b3a8fc5906dbfa7bda76191d7727a8ab9183a1778f0b429cc181afb48182db6b902cab21f859a245590aea4d32222f3a44a72bab0b53758f8536b983d9caf7e3363b5c3f3ee2125d53a932d3b570665869501bc2baa26d1b5fda178c3f23acff765c33470a9881cf6ca7a71327300d53cc3a59c137c28e59332cac992884260eb284505c360c1fa44f3b0831c462aebeb497eaa38db53b7b47a35be1b32a289c077219cfc3d47f91571c1fd561e4db71a5b8a5ef57cc13ec9214e01673a00ea474610f7b3dcc98bfdefa5b7ec276cce91f8728071a385e9d6b263c76b3a1d15f18b189dd644f38acacb2c32ffd6405236134851b2fa62b594817986b9c356b364b34a66746d3763462ca51556298ba1c794130703c5de78324e4840050e151a6a88ad6605e83b3f115465f10ae006db51f23e58717f6bd0f4f2ad9e31a15026b2f3f7f2dd5ebf15b08348ea20a3d6153136e0371b23e02d36003ce951b36a449e3f1aaff6e300506032b657003410012126f7a0a31d19a730da3e067395d82e0e3cffc54bc9d815ab7a41cbac17eb664ada7fa01ab2dc2bb073a7ecfe145e94b2b021a33787a42c994296a31c3a200",
      "note": "Ed25519 leaf under root_a for https://agent.alina.example/mcp, 2026-09-01 to 2027-09-01, a dNSName beside the URI, an X-Wing sealing key"
    },
    "leaf_b": {
      "der_hex": "308206cf30820674a003020102020862cf0a32fd882130300a06082a8648ce3d04030230173115301306035504030c0c426861726174204d65687461301e170d3236303930313030303030305a170d3237303930313030303030305a30173115301306035504030c0c426861726174204d656874613059301306072a8648ce3d020106082a8648ce3d03010703420004d6e652937ca86505559bc84e4936573de2d110833c4718cef004a203c054a92dcdfb5e5765ebc267dc3d241783447ba3b58cec954ea8ca5f24fdb8963dca1897a38205a8308205a4300c0603551d130101ff04023000300e0603551d0f0101ff040403020388301d0603551d250416301406082b0601050507030106082b06010505070302302b0603551d1104243022862068747470733a2f2f6167656e742e6268617261742e6578616d706c652f6d637030290603551d0e04220420aeecb55b2b35908f453ec115bda1f469a90d0b45336ca53451212c95313db25f302b0603551d23042430228020f53e3a50e4c41653c2db3189679a867339db836d79c5b0ba6f1704d13e50a2b3308204de06146981f9ceeab8f4b58e94c4e4b1b7f8fe92a8b037048204c4048204c0d692a33f381e8213449b0a049ba774adcb5db82410681a3d77c51821ca68b59c62388287bf43a2fd20ae129426a953c3c241cbe0627f3ad90397125fea86cd8ff133d360a2a0ab4b0ce3684a0246b1492a93294ca7d00425dcc9efe1cf9b1a58a035cc3691940b7599b221953fc17742587673d1340228a82a3009214a8808ea1820d7b94802b908da920169a251245606472b1880462a13694a44b711da65ba791e0e312f03834c427908206ba07d6a39bae8cd31f141932acde804cac21ca669f30263339f7bda114ef705cfe380dac4c4a000ac30c914a27a01355650802364f5343a9953965dd90ec980570695b9997a3a095416d2ba9e5cba7f6225a091644606da69a8b2a1df9aadc1a78718383762c239f9057aade130c10884c09710d0c97480231997dc3b27b22383510ef0e3aa6f1cb468548afa47115b99b33d556f0344408f72a7c06577cb4b12bb063e2aa09f05e7bc1459a2f66bac70870543fc8b779bbadf560d6c953e9945866198240cfb626a666b1a8093f7168edd5c6944e010b10098740043d936589ad4ca849791f0dc2c175010b11b4e8bda624ac89e36318a8318c25dbc6b16c813cc7220fd89b785b3565bf2c15933b2a10c6e3af35c4f225246459330d441ecb767f49ca54092b7857b37832c7c834c5da19633b34ccd6ed289f15a4b44e6860dfaca2ef334772777f56ac274cba8aa710073666acae92d6827a684537dd5da38ceb366cc54cb6860c8be331382c2bbe278ac5e623d36a43e519545fd5c5eee289aa206345e12bd90130f09702339933e1210a3ccfc9bdaa67cda05cce731be28538b96981f71cc06c098c2e840c7f16bbdd76c49a03c52dbfa5745cb51309b627a5a651b32533e545836c46c5dc61930eb3f35b03f8af3c262a4b5a4d24ce4a586b58a17f55b9f7db40dc368709c28a334b84a48440d078822b256af41d754f4766d5ae69ecf429f830101e820718a23470d1c9b25aa93511cc87f8270b61bbb3a6a6ad019a6b2a47f93ba9fa6e2b96523391464c7b3261c17741c819417947c7dd88649727ca163a14220a03a6a4a7949e1af907a9db696851cd219201b2e7927c3176758ceabcb1ae633dbc49dde848a69818c157235329538cc52240a7c1d8a23a6aee42500d426ff6a08be8b0465e28b4d6a6ad41cc127a16e8e77797a00737cdba9347b091a83ac6fb76e3edbb7fbe0c22bc2b5b3277edf912fc20cb659f8354f613721850953b7bd3ea05ab1c719b1c63f0644acef9295c283cd623991e4b00ed44819f812112575b5c5264580e10ce050c6723ab4ccc85e343616dc2b500f954c280acb0be1cd7f805e73ca5a60f154ed39991fd60069296055ab88f59b22efd0368398484ca6b5d1181e447c5ae8a183a087c58933387e083cafd36a66e666a1015234a40989b279587112c7f79bb974a09274c10cd9266afcb4001a75fcb1bda085a5f7ccaf5f5b400e259557531b6d04cca2362da72c4d7d7a899b883b7cb9236267ae95aa891be26b2c701b3dda08e0a94a0fe68532f21a5eb89aa4c23a7cb3a82876549336ba02a46962c4bd08ec7fee661dba64c5a46755e990b96558165788013c9ab9fa983874c260335b5fc5f7472b2ce76436683125e8d7b7852b89f6542f0e327ae6de923eee5628b28722f6ef85b2b7efed22e11f02d2b79a5b673561a987af35d1738a6df8b172843c300a06082a8648ce3d0403020349003046022100a5d3589c4651315bce43eeea465a068f4e866fc17a37aa526952b8fe5a06f979022100e0a012fc77ef28a74bf0ffd771cb84c7473bd778dc27fcb25cb3220d22d9d002",
      "note": "P-256 leaf under root_b for https://agent.bharat.example/mcp, 2026-09-01 to 2027-09-01, keyUsage digitalSignature+keyAgreement, an X-Wing sealing key"
    },
    "leaf_a_expired": {
      "der_hex": "3082068730820639a00302010202080c2ba902f1b494b2300506032b657030143112301006035504030c09416c696e612052616f301e170d3235303630313030303030305a170d3236303630313030303030305a30143112301006035504030c09416c696e612052616f302a300506032b65700321004eeb9d16157a525df7081d67dd25af338526e6b6cec2fa43e4536a0c4213cff4a38205a7308205a3300c0603551d130101ff04023000300e0603551d0f0101ff040403020780301d0603551d250416301406082b0601050507030106082b06010505070302302a0603551d1104233021861f68747470733a2f2f6167656e742e616c696e612e6578616d706c652f6d637030290603551d0e042204203579fc22b8c43dd0ffb01278a0e62b4d5507e487c10830d9cd4a25af989f0252302b0603551d23042430228020633cfd0fb6be62a0e97c519bafa4abf363a5f8b4f37f3db26bffc320abad9bec308204de06146981f9ceeab8f4b58e94c4e4b1b7f8fe92a8b037048204c4048204c001b97c6395ae691cab0eea5ab462a58534ac99e559759c919ecc7884e69a61a5cca4399246a401ca39226033266053c7f5080a3f2b0474b47a238023ebe8429ae3294138b02feb7be9c6427e5580e71331b9098a5763117f60735a5b25bc670629da6e69d8a8aae04994f1c9fb18453d1a44faf21b5ec767715479a5d27fcee86c0d4a211aaa0642568dac632fec214bebb6a3ef0010cdba7dd6957338b31200ed3fc353af075a2344f15e11a3161afa55abe15aebd363ca6c3bccd79bcf407cf4490b49998b7b51be0e624c0573ac67fb1c22761cf9372a449b0b441160cf94548e3073e2d74e9993270f00330d0b1499793ae702b2c0f32d3743993450672868a80f614c62e79277e7c55a39cbb3a4b830a381df0a0c6a08ad9c590695c93b6c9ca8d2a82b7040c8c24a3889128ba65516c1a99c4b2b0fc37329570245294764ff2ab1a3e86c3209c889f347b755663c1c75f7d6c809c37933e38feb038ea5300899d3699889a29961a0b5c8cb1bb66df2b62c4a7c0b93e66168611cc8e214dab6156470c930a702bc8b4f307587a43596a5057008d6401389894b2b428be116a7eaa2736704855061629616d409076adb872153b0bcd9028b51910bf518dde7b480b83376711b5831996837b43e409952158f0448293e34ad73706c746ca81ceab2f6972076f88b2df737de1a432d8c5709d7cb0fc67c5fe1c38012b2389748154bc492acbc2830b417da1ba85a5f8478914e25c6f178a63e751e8893c6fae48fb05b24dce10abb3773de691a2262a96521636c43306dc52318599d5f336ae063c124f46d6cd9856172cd11476fa6f81392121bbf3aba7eb1cdc70100f42076219c0c4c393b8e656cbb133a2ce728cd41413fd210b2a5c285eacb7ddb74a42902a2ba09108ca8c82911bd473b8700ae51b75a00058fc8e643def475dd180a84033500102180fa5bceec18518b6a0ae91ffeb3b679d37e059a9ba39a445b401939a87c4a4c222285384b668ba8f24c35db45ab3026e0e0c1425b2b51acb41cc26e2cb316ad63b253736691f62ff681b0941b808cdba3e5d36514e384b0e7bb20f6b6dfe54e79422f69f68066b30aecf3b066e03b086ca4daf6981486b98af48c68463616e979c1800f0cd90cede2270757cfcb2a6cd2a7533d546d6bf80d70eb465b0954a9985551c75e1cfb42ef452a6e8a4bcb569a0c388180b3a8fc5906dbfa7bda76191d7727a8ab9183a1778f0b429cc181afb48182db6b902cab21f859a245590aea4d32222f3a44a72bab0b53758f8536b983d9caf7e3363b5c3f3ee2125d53a932d3b570665869501bc2baa26d1b5fda178c3f23acff765c33470a9881cf6ca7a71327300d53cc3a59c137c28e59332cac992884260eb284505c360c1fa44f3b0831c462aebeb497eaa38db53b7b47a35be1b32a289c077219cfc3d47f91571c1fd561e4db71a5b8a5ef57cc13ec9214e01673a00ea474610f7b3dcc98bfdefa5b7ec276cce91f8728071a385e9d6b263c76b3a1d15f18b189dd644f38acacb2c32ffd6405236134851b2fa62b594817986b9c356b364b34a66746d3763462ca51556298ba1c794130703c5de78324e4840050e151a6a88ad6605e83b3f115465f10ae006db51f23e58717f6bd0f4f2ad9e31a15026b2f3f7f2dd5ebf15b08348ea20a3d6153136e0371b23e02d36003ce951b36a449e3f1aaff6e300506032b65700341001e7ff0e07abcedc1384afd96eb33ebe30675569e29966262cb2b7104e0bcb8fdac582b092638f2951e2bfd1daa28a078d840802c128a133fbd8faa57d94d8308",
      "note": "leaf_a's keys and endpoint, 2025-06-01 to 2026-06-01: expired at NOW"
    },
    "leaf_a_long": {
      "der_hex": "308206883082063aa003020102020900bca80aa75de7cf1e300506032b657030143112301006035504030c09416c696e612052616f301e170d3236303930313030303030305a170d3237313031303030303030305a30143112301006035504030c09416c696e612052616f302a300506032b65700321004eeb9d16157a525df7081d67dd25af338526e6b6cec2fa43e4536a0c4213cff4a38205a7308205a3300c0603551d130101ff04023000300e0603551d0f0101ff040403020780301d0603551d250416301406082b0601050507030106082b06010505070302302a0603551d1104233021861f68747470733a2f2f6167656e742e616c696e612e6578616d706c652f6d637030290603551d0e042204203579fc22b8c43dd0ffb01278a0e62b4d5507e487c10830d9cd4a25af989f0252302b0603551d23042430228020633cfd0fb6be62a0e97c519bafa4abf363a5f8b4f37f3db26bffc320abad9bec308204de06146981f9ceeab8f4b58e94c4e4b1b7f8fe92a8b037048204c4048204c001b97c6395ae691cab0eea5ab462a58534ac99e559759c919ecc7884e69a61a5cca4399246a401ca39226033266053c7f5080a3f2b0474b47a238023ebe8429ae3294138b02feb7be9c6427e5580e71331b9098a5763117f60735a5b25bc670629da6e69d8a8aae04994f1c9fb18453d1a44faf21b5ec767715479a5d27fcee86c0d4a211aaa0642568dac632fec214bebb6a3ef0010cdba7dd6957338b31200ed3fc353af075a2344f15e11a3161afa55abe15aebd363ca6c3bccd79bcf407cf4490b49998b7b51be0e624c0573ac67fb1c22761cf9372a449b0b441160cf94548e3073e2d74e9993270f00330d0b1499793ae702b2c0f32d3743993450672868a80f614c62e79277e7c55a39cbb3a4b830a381df0a0c6a08ad9c590695c93b6c9ca8d2a82b7040c8c24a3889128ba65516c1a99c4b2b0fc37329570245294764ff2ab1a3e86c3209c889f347b755663c1c75f7d6c809c37933e38feb038ea5300899d3699889a29961a0b5c8cb1bb66df2b62c4a7c0b93e66168611cc8e214dab6156470c930a702bc8b4f307587a43596a5057008d6401389894b2b428be116a7eaa2736704855061629616d409076adb872153b0bcd9028b51910bf518dde7b480b83376711b5831996837b43e409952158f0448293e34ad73706c746ca81ceab2f6972076f88b2df737de1a432d8c5709d7cb0fc67c5fe1c38012b2389748154bc492acbc2830b417da1ba85a5f8478914e25c6f178a63e751e8893c6fae48fb05b24dce10abb3773de691a2262a96521636c43306dc52318599d5f336ae063c124f46d6cd9856172cd11476fa6f81392121bbf3aba7eb1cdc70100f42076219c0c4c393b8e656cbb133a2ce728cd41413fd210b2a5c285eacb7ddb74a42902a2ba09108ca8c82911bd473b8700ae51b75a00058fc8e643def475dd180a84033500102180fa5bceec18518b6a0ae91ffeb3b679d37e059a9ba39a445b401939a87c4a4c222285384b668ba8f24c35db45ab3026e0e0c1425b2b51acb41cc26e2cb316ad63b253736691f62ff681b0941b808cdba3e5d36514e384b0e7bb20f6b6dfe54e79422f69f68066b30aecf3b066e03b086ca4daf6981486b98af48c68463616e979c1800f0cd90cede2270757cfcb2a6cd2a7533d546d6bf80d70eb465b0954a9985551c75e1cfb42ef452a6e8a4bcb569a0c388180b3a8fc5906dbfa7bda76191d7727a8ab9183a1778f0b429cc181afb48182db6b902cab21f859a245590aea4d32222f3a44a72bab0b53758f8536b983d9caf7e3363b5c3f3ee2125d53a932d3b570665869501bc2baa26d1b5fda178c3f23acff765c33470a9881cf6ca7a71327300d53cc3a59c137c28e59332cac992884260eb284505c360c1fa44f3b0831c462aebeb497eaa38db53b7b47a35be1b32a289c077219cfc3d47f91571c1fd561e4db71a5b8a5ef57cc13ec9214e01673a00ea474610f7b3dcc98bfdefa5b7ec276cce91f8728071a385e9d6b263c76b3a1d15f18b189dd644f38acacb2c32ffd6405236134851b2fa62b594817986b9c356b364b34a66746d3763462ca51556298ba1c794130703c5de78324e4840050e151a6a88ad6605e83b3f115465f10ae006db51f23e58717f6bd0f4f2ad9e31a15026b2f3f7f2dd5ebf15b08348ea20a3d6153136e0371b23e02d36003ce951b36a449e3f1aaff6e300506032b65700341004ce05ce5c1f02a9df75a2f180e6056442075c92abe27cac4f45669c1aeb21c980307ed1383a686e7e6738ec0d6f1d5585f7a0c0f73aedf2f7914dd74a4b41002",
      "note": "leaf_a's keys and endpoint, 2026-09-01 to 2027-10-10: 404 days"
    },
    "leaf_a_next": {
      "der_hex": "3082068730820639a0030201020208184ebda4c22a39ae300506032b657030143112301006035504030c09416c696e612052616f301e170d3237303830323030303030305a170d3238303830313030303030305a30143112301006035504030c09416c696e612052616f302a300506032b6570032100eaea799849559930c97b850037b8c8eca3a623a1c96d8f9d3a4ee9ef3c4b4b9fa38205a7308205a3300c0603551d130101ff04023000300e0603551d0f0101ff040403020780301d0603551d250416301406082b0601050507030106082b06010505070302302a0603551d1104233021861f68747470733a2f2f6167656e742e616c696e612e6578616d706c652f6d637030290603551d0e042204204046e58de3045443592671cdddbc9b1826cc1429527e4c61a7bedafa6a6c24cf302b0603551d23042430228020633cfd0fb6be62a0e97c519bafa4abf363a5f8b4f37f3db26bffc320abad9bec308204de06146981f9ceeab8f4b58e94c4e4b1b7f8fe92a8b037048204c4048204c01656bb265a6b12228c5de05f3f1c49753a8a9f62a47d178b0906cfe9b6bfcffc31b7c99cf1c0961f551a49057b86eb84fbc121ad29b76789a1ae15b68c4bc3e0342320230ca868b3a52836dc099e84c81433fc0049fcce9161af37561938d9710535247f3c1100fa679d3815d95661378767dbc79f44808d197b5825376b1b29bda33a6f605897aca1471fc2c1cb4598a62772e67241b496cdba507f1e44822d8839c2002dae23454f9b7760a9351dbccb4ee39055c6b41be575cdc157626c301ae65f9b9112fa415ee8452a632503e7c9724150183db22a8ed16cc77039ecd344094ba74d2328d8e8c80fe566b7db9a14a8a3ef38cbc4c081ac979dd54229a0a4921cbcae2292165ee29a4578840e39c506f3a81f820ccbd0205c2c0ba499bd7496acff63a8aefc3b6f8c00ffc81879679ec959ccf2c2089983381de1aac451608ef7c5329b1c91eab14e837220065579a2231101679761bdfa36945d9339ec1b4e1d636bd863a0a6d67efc1a8658ab2edddc9abf616050759801fa2758e7b09cd255b2f394f6d3c336f7b4f0a3bd1eb1a0ba74b571b13817f8cde901160ca8b91b90c36748874f0a10ea37794bf2c408b52c533447dfc561dc889363e74360d48bbdc79db233b227ec9afc8834431b8d30ec290121590f5aa5953a0429309a922c78ce969e74d9b978543d73e72c1b517a5af18896ac4a0c2b6d46032008d43324f00b166997e5894304940cf22047c950815a55a38af5aac7081e556150d8f60c22905c6c9a1125f116dae3aaeddac073c59adbd809337749382b483ddb2923107a61e10e91e90b04739816da093ca4472f42891ee78ab03c8cb469cd907122c11239adc70745d4676cca3ecaa01165b3c1cf814c00877c7ac1221e76c06f52cf6615b3595b8c75712e0a615e13e73b22cb5d247c7912b5875c6166e5700ec2996b48010d1c303889e0250fe821905a9f202c5741382c271b90d9550cc1a161f16624673b774ebbb7e782a240aa9fe838ade96849f7c31b5efaa50296627fa17f6e6c93f302acd6445fdecc8a72bc1e1c2906fb56bcfbcb3448a9215716c8881c765e064472ac680fd8991a251b934036eb95a0d9d5b2b01768f89258ae8324172503a2da508e6bcc004dc931764a10b74c6807c39f3292bb8c27b567b7f765516ce21d7044bcd619367676102df3704b7a2b964488da82714ea5255e9b373a4ccd6781c50f143b19eb2745fc57e0347906194c881313a17278f8f181a3146e02182cd966642f522b2ea317bec666140bafb900acdd56af9a11a8ee5b886f06cb8d6001149466d83894ba284b130aa47c861b9b28216fb1a879d44a0b0a75feec3035e3bfd5342ddfe32eb820001b4aae7fdb34fadb40e3697c4a2699dd1705c49825b9c665be215a55ca5858525519d355aef628ee2a7b67db930db45cd6c646f9e3814324c4edf05ec3f748eb4269f2c47221392f0aa17ce5e61cbe09152a84819eab57620a179b0c4448d9b41a120c1f101706f77a5845226a70b903a6b28b856bcbdac12b857bbcdc971d025219c65af37a0c1b697f7925b11e5126c742b32df97858583517e5076c3bac3272422c641802ab2b8ec028143c699513c3ce0a42002d181a6611cace68f3375001bd22bf10c487e97a04ff717b2fad91b44e96e876eac8dedb7e508d7f7433d06d8457304bf5db9e58e85af9b214365369300506032b6570034100cb9e9e577461dd37f2476f4b9d6ab799cfc2f4ed19b38bad3fc8724ec385a2bb66e1e9d666de368ce9468bef11a1a2f6df98bd95bb6e55593a814431ccb60e0e",
      "note": "fresh signing and sealing keys for the same endpoint, 2027-08-02 to 2028-08-01: the renewal that supersedes leaf_a"
    },
    "leaf_a_unsealed": {
      "der_hex": "308201a430820156a003020102020900e17b86ffae383660300506032b657030143112301006035504030c09416c696e612052616f301e170d3236303930313030303030305a170d3237303930313030303030305a30143112301006035504030c09416c696e612052616f302a300506032b65700321004eeb9d16157a525df7081d67dd25af338526e6b6cec2fa43e4536a0c4213cff4a381c43081c1300c0603551d130101ff04023000300e0603551d0f0101ff040403020780301d0603551d250416301406082b0601050507030106082b06010505070302302a0603551d1104233021861f68747470733a2f2f6167656e742e616c696e612e6578616d706c652f6d637030290603551d0e042204203579fc22b8c43dd0ffb01278a0e62b4d5507e487c10830d9cd4a25af989f0252302b0603551d23042430228020633cfd0fb6be62a0e97c519bafa4abf363a5f8b4f37f3db26bffc320abad9bec300506032b6570034100d73ffc61a6cd2092a010b25b809c7cf7f92a064a041eb53b60d47d4e75687ed61244b9c9c3164ca79a65d26351549eb15842d96280d9de8d1932c21bbab39309",
      "note": "leaf_a without the sealing-key extension: not a 2.0 leaf"
    }
  },
  "leaf_keys": {
    "leaf_a": {
      "signing_key_pkcs8_hex": "302e020100300506032b6570042204204896ed640768ccb301df47585afe0488dd5095d2c325c68c3b08d66c085b4272",
      "sealing_key_seed_hex": "4ebae05b985a4738fb7369a7d64ee51c454c8a60ff3a57f92828d7f843b3b158"
    },
    "leaf_a_next": {
      "signing_key_pkcs8_hex": "302e020100300506032b657004220420595eb444aaa52fea62576f1d2e89e82af0b6d111582b6b371008e4a8ff072633",
      "sealing_key_seed_hex": "a6c01dea239b1f821babe349622e28b983b277a17965bba00a111e0c8c28da8f"
    },
    "leaf_b": {
      "signing_key_pkcs8_hex": "3041020100301306072a8648ce3d020106082a8648ce3d0301070427302502010104206a261bbb098c126fe60dcc26a72045d97db5079d52cd59826220705150ad60d7",
      "sealing_key_seed_hex": "9235b0005f5f30aaa370b175724fece907ac76000f3aaa7f087276080ac90227"
    }
  },
  "chain_cases": [
    {
      "name": "alina valid",
      "chain": [
        "leaf_a",
        "root_a"
      ],
      "expected_root": "sha256:Yzz9D7a-YqDpfFGbr6Sr82Ol-LTzfz2ya__DIKutm-w",
      "expected_endpoint": "https://agent.alina.example/mcp",
      "now": "2026-09-13T12:00:00Z",
      "expect": "accept"
    },
    {
      "name": "bharat valid",
      "chain": [
        "leaf_b",
        "root_b"
      ],
      "expected_root": "sha256:9T46UOTEFlPC2zGJZ5qGcznbg215xbC6bxcE0T5QorM",
      "expected_endpoint": "https://agent.bharat.example/mcp",
      "now": "2026-09-13T12:00:00Z",
      "expect": "accept"
    },
    {
      "name": "first contact, no expectation",
      "chain": [
        "leaf_a",
        "root_a"
      ],
      "now": "2026-09-13T12:00:00Z",
      "expect": "accept"
    },
    {
      "name": "chain of three",
      "chain": [
        "leaf_a",
        "root_a",
        "root_a"
      ],
      "now": "2026-09-13T12:00:00Z",
      "expect": "refuse",
      "rule": 1
    },
    {
      "name": "single certificate is not a chain",
      "chain": [
        "root_a"
      ],
      "now": "2026-09-13T12:00:00Z",
      "expect": "refuse",
      "rule": 1
    },
    {
      "name": "leaf presented as root",
      "chain": [
        "leaf_a",
        "leaf_a"
      ],
      "now": "2026-09-13T12:00:00Z",
      "expect": "refuse",
      "rule": 1
    },
    {
      "name": "leaf without a sealing key",
      "chain": [
        "leaf_a_unsealed",
        "root_a"
      ],
      "now": "2026-09-13T12:00:00Z",
      "expect": "refuse",
      "rule": 1
    },
    {
      "name": "root is not the one pinned",
      "chain": [
        "leaf_a",
        "root_a"
      ],
      "expected_root": "sha256:9T46UOTEFlPC2zGJZ5qGcznbg215xbC6bxcE0T5QorM",
      "now": "2026-09-13T12:00:00Z",
      "expect": "refuse",
      "rule": 2
    },
    {
      "name": "leaf under the wrong root",
      "chain": [
        "leaf_a",
        "root_b"
      ],
      "now": "2026-09-13T12:00:00Z",
      "expect": "refuse",
      "rule": 3
    },
    {
      "name": "expired leaf",
      "chain": [
        "leaf_a_expired",
        "root_a"
      ],
      "now": "2026-09-13T12:00:00Z",
      "expect": "refuse",
      "rule": 4
    },
    {
      "name": "leaf not yet valid",
      "chain": [
        "leaf_a_next",
        "root_a"
      ],
      "now": "2026-09-13T12:00:00Z",
      "expect": "refuse",
      "rule": 4
    },
    {
      "name": "leaf longer than 398 days",
      "chain": [
        "leaf_a_long",
        "root_a"
      ],
      "now": "2026-09-13T12:00:00Z",
      "expect": "refuse",
      "rule": 4
    },
    {
      "name": "endpoint mismatch",
      "chain": [
        "leaf_a",
        "root_a"
      ],
      "expected_endpoint": "https://agent.alina.example/mcp/",
      "now": "2026-09-13T12:00:00Z",
      "expect": "refuse",
      "rule": 5
    }
  ],
  "newest_leaf_cases": [
    {
      "pinned": "leaf_a",
      "presented": "leaf_a",
      "expect": "same"
    },
    {
      "pinned": "leaf_a",
      "presented": "leaf_a_next",
      "expect": "newer"
    },
    {
      "pinned": "leaf_a_next",
      "presented": "leaf_a",
      "expect": "superseded"
    },
    {
      "pinned": "leaf_a",
      "presented": "leaf_a_long",
      "expect": "conflict"
    }
  ],
  "certificate_renewed_cases": [
    {
      "name": "renewal followed",
      "pinned_leaf": "leaf_a",
      "dialed": "https://agent.alina.example/mcp",
      "now": "2027-08-15T12:00:00Z",
      "answer": {
        "code": "certificate_renewed",
        "data": {
          "chain": [
            "MIIGhzCCBjmgAwIBAgIIGE69pMIqOa4wBQYDK2VwMBQxEjAQBgNVBAMMCUFsaW5hIFJhbzAeFw0yNzA4MDIwMDAwMDBaFw0yODA4MDEwMDAwMDBaMBQxEjAQBgNVBAMMCUFsaW5hIFJhbzAqMAUGAytlcAMhAOrqeZhJVZkwyXuFADe4yOyjpiOhyW2PnTpO6e88S0ufo4IFpzCCBaMwDAYDVR0TAQH_BAIwADAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMCoGA1UdEQQjMCGGH2h0dHBzOi8vYWdlbnQuYWxpbmEuZXhhbXBsZS9tY3AwKQYDVR0OBCIEIEBG5Y3jBFRDWSZxzd28mxgmzBQpUn5MYae-2vpqbCTPMCsGA1UdIwQkMCKAIGM8_Q-2vmKg6XxRm6-kq_Njpfi08389smv_wyCrrZvsMIIE3gYUaYH5zuq49LWOlMTksbf4_pKosDcEggTEBIIEwBZWuyZaaxIijF3gXz8cSXU6ip9ipH0XiwkGz-m2v8_8MbfJnPHAlh9VGkkFe4brhPvBIa0pt2eJoa4VtoxLw-A0IyAjDKhos6UoNtwJnoTIFDP8AEn8zpFhrzdWGTjZcQU1JH88EQD6Z504FdlWYTeHZ9vHn0SAjRl7WCU3axspvaM6b2BYl6yhRx_CwctFmKYncuZyQbSWzbpQfx5Egi2IOcIALa4jRU-bd2CpNR28y07jkFXGtBvldc3BV2JsMBrmX5uREvpBXuhFKmMlA-fJckFQGD2yKo7RbMdwOezTRAlLp00jKNjoyA_lZrfbmhSoo-84y8TAgayXndVCKaCkkhy8riKSFl7imkV4hA45xQbzqB-CDMvQIFwsC6SZvXSWrP9jqK78O2-MAP_IGHlnnslZzPLCCJmDOB3hqsRRYI73xTKbHJHqsU6DciAGVXmiIxEBZ5dhvfo2lF2TOewbTh1ja9hjoKbWfvwahlirLt3cmr9hYFB1mAH6J1jnsJzSVbLzlPbTwzb3tPCjvR6xoLp0tXGxOBf4zekBFgyouRuQw2dIh08KEOo3eUvyxAi1LFM0R9_FYdyIk2PnQ2DUi73HnbIzsifsmvyINEMbjTDsKQEhWQ9apZU6BCkwmpIseM6WnnTZuXhUPXPnLBtRelrxiJasSgwrbUYDIAjUMyTwCxZpl-WJQwSUDPIgR8lQgVpVo4r1qscIHlVhUNj2DCKQXGyaESXxFtrjqu3awHPFmtvYCTN3STgrSD3bKSMQemHhDpHpCwRzmBbaCTykRy9CiR7nirA8jLRpzZBxIsESOa3HB0XUZ2zKPsqgEWWzwc-BTACHfHrBIh52wG9Sz2YVs1lbjHVxLgphXhPnOyLLXSR8eRK1h1xhZuVwDsKZa0gBDRwwOIngJQ_oIZBanyAsV0E4LCcbkNlVDMGhYfFmJGc7d067t-eCokCqn-g4reloSffDG176pQKWYn-hf25sk_MCrNZEX97MinK8HhwpBvtWvPvLNEipIVcWyIgcdl4GRHKsaA_YmRolG5NANuuVoNnVsrAXaPiSWK6DJBclA6LaUI5rzABNyTF2ShC3TGgHw58ykruMJ7Vnt_dlUWziHXBEvNYZNnZ2EC3zcEt6K5ZEiNqCcU6lJV6bNzpMzWeBxQ8UOxnrJ0X8V-A0eQYZTIgTE6FyePjxgaMUbgIYLNlmZC9SKy6jF77GZhQLr7kArN1Wr5oRqO5biG8Gy41gARSUZtg4lLooSxMKpHyGG5soIW-xqHnUSgsKdf7sMDXjv9U0Ld_jLrggABtKrn_bNPrbQONpfEommd0XBcSYJbnGZb4hWlXKWFhSVRnTVa72KO4qe2fbkw20XNbGRvnjgUMkxO3wXsP3SOtCafLEciE5LwqhfOXmHL4JFSqEgZ6rV2IKF5sMREjZtBoSDB8QFwb3elhFImpwuQOmsouFa8vawSuFe7zclx0CUhnGWvN6DBtpf3klsR5RJsdCsy35eFhYNRflB2w7rDJyQixkGAKrK47AKBQ8aZUTw84KQgAtGBpmEcrOaPM3UAG9Ir8QxIfpegT_cXsvrZG0TpbodurI3tt-UI1_dDPQbYRXMEv1255Y6Fr5shQ2U2kwBQYDK2VwA0EAy56eV3Rh3TfyR29LnWq3mc_C9O0Zs4utP8hyTsOFortm4enWZt42jOlGi-8RoaL235i9lbtuVVk6gUQxzLYODg",
            "MIIBMTCB5KADAgECAgkAmQKVaRbcF0EwBQYDK2VwMBQxEjAQBgNVBAMMCUFsaW5hIFJhbzAgFw0yNjA5MDEwMDAwMDBaGA85OTk5MTIzMTIzNTk1OVowFDESMBAGA1UEAwwJQWxpbmEgUmFvMCowBQYDK2VwAyEADLhbefjgmsXoJk2DPBURE7EALxfcwb9cRJfSS3z_07CjUTBPMBIGA1UdEwEB_wQIMAYBAf8CAQAwDgYDVR0PAQH_BAQDAgIEMCkGA1UdDgQiBCBjPP0Ptr5ioOl8UZuvpKvzY6X4tPN_PbJr_8Mgq62b7DAFBgMrZXADQQBq8UK0ZmY0_N1JiWNU1Sp2O66Jmz9C98BZBwB4B42ZNDW9CauFycj2DgchqFKAsQ6Bafuu4rpS_so7-chGC2UB"
          ]
        }
      },
      "expect": "follow"
    },
    {
      "name": "older chain discarded",
      "pinned_leaf": "leaf_a_next",
      "dialed": "https://agent.alina.example/mcp",
      "now": "2027-08-15T12:00:00Z",
      "answer": {
        "code": "certificate_renewed",
        "data": {
          "chain": [
            "MIIGnTCCBk-gAwIBAgIJAOpUDjFhRyz1MAUGAytlcDAUMRIwEAYDVQQDDAlBbGluYSBSYW8wHhcNMjYwOTAxMDAwMDAwWhcNMjcwOTAxMDAwMDAwWjAUMRIwEAYDVQQDDAlBbGluYSBSYW8wKjAFBgMrZXADIQBO650WFXpSXfcIHWfdJa8zhSbmts7C-kPkU2oMQhPP9KOCBbwwggW4MAwGA1UdEwEB_wQCMAAwDgYDVR0PAQH_BAQDAgeAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjA_BgNVHREEODA2hh9odHRwczovL2FnZW50LmFsaW5hLmV4YW1wbGUvbWNwghNhZ2VudC5hbGluYS5leGFtcGxlMCkGA1UdDgQiBCA1efwiuMQ90P-wEnig5itNVQfkh8EIMNnNSiWvmJ8CUjArBgNVHSMEJDAigCBjPP0Ptr5ioOl8UZuvpKvzY6X4tPN_PbJr_8Mgq62b7DCCBN4GFGmB-c7quPS1jpTE5LG3-P6SqLA3BIIExASCBMABuXxjla5pHKsO6lq0YqWFNKyZ5Vl1nJGezHiE5pphpcykOZJGpAHKOSJgMyZgU8f1CAo_KwR0tHojgCPr6EKa4ylBOLAv63vpxkJ-VYDnEzG5CYpXYxF_YHNaWyW8ZwYp2m5p2Kiq4EmU8cn7GEU9GkT68htex2dxVHml0n_O6GwNSiEaqgZCVo2sYy_sIUvrtqPvABDNun3WlXM4sxIA7T_DU68HWiNE8V4RoxYa-lWr4Vrr02PKbDvM15vPQHz0SQtJmYt7Ub4OYkwFc6xn-xwidhz5NypEmwtEEWDPlFSOMHPi106ZkycPADMNCxSZeTrnArLA8y03Q5k0UGcoaKgPYUxi55J358VaOcuzpLgwo4HfCgxqCK2cWQaVyTtsnKjSqCtwQMjCSjiJEoumVRbBqZxLKw_DcylXAkUpR2T_KrGj6GwyCciJ80e3VWY8HHX31sgJw3kz44_rA46lMAiZ02mYiaKZYaC1yMsbtm3ytixKfAuT5mFoYRzI4hTathVkcMkwpwK8i08wdYekNZalBXAI1kATiYlLK0KL4Ran6qJzZwSFUGFilhbUCQdq24chU7C82QKLUZEL9Rjd57SAuDN2cRtYMZloN7Q-QJlSFY8ESCk-NK1zcGx0bKgc6rL2lyB2-Ist9zfeGkMtjFcJ18sPxnxf4cOAErI4l0gVS8SSrLwoMLQX2huoWl-EeJFOJcbxeKY-dR6Ik8b65I-wWyTc4Qq7N3PeaRoiYqllIWNsQzBtxSMYWZ1fM2rgY8Ek9G1s2YVhcs0RR2-m-BOSEhu_Orp-sc3HAQD0IHYhnAxMOTuOZWy7Ezos5yjNQUE_0hCypcKF6st923SkKQKiugkQjKjIKRG9RzuHAK5Rt1oABY_I5kPe9HXdGAqEAzUAECGA-lvO7BhRi2oK6R_-s7Z5034FmpujmkRbQBk5qHxKTCIihThLZouo8kw120WrMCbg4MFCWytRrLQcwm4ssxatY7JTc2aR9i_2gbCUG4CM26Pl02UU44Sw57sg9rbf5U55Qi9p9oBmswrs87Bm4DsIbKTa9pgUhrmK9IxoRjYW6XnBgA8M2Qzt4icHV8_LKmzSp1M9VG1r-A1w60ZbCVSpmFVRx14c-0LvRSpuikvLVpoMOIGAs6j8WQbb-nvadhkddyeoq5GDoXePC0KcwYGvtIGC22uQLKsh-FmiRVkK6k0yIi86RKcrqwtTdY-FNrmD2cr34zY7XD8-4hJdU6ky07VwZlhpUBvCuqJtG1_aF4w_I6z_dlwzRwqYgc9sp6cTJzANU8w6WcE3wo5ZMyysmSiEJg6yhFBcNgwfpE87CDHEYq6-tJfqo421O3tHo1vhsyoonAdyGc_D1H-RVxwf1WHk23GluKXvV8wT7JIU4BZzoA6kdGEPez3MmL_e-lt-wnbM6R-HKAcaOF6dayY8drOh0V8YsYndZE84rKyywy_9ZAUjYTSFGy-mK1lIF5hrnDVrNks0pmdG03Y0YspRVWKYuhx5QTBwPF3ngyTkhABQ4VGmqIrWYF6Ds_EVRl8QrgBttR8j5YcX9r0PTyrZ4xoVAmsvP38t1evxWwg0jqIKPWFTE24DcbI-AtNgA86VGzakSePxqv9uMAUGAytlcANBABISb3oKMdGacw2j4Gc5XYLg48_8VLydgVq3pBy6wX62ZK2n-gGrLcK7Bzp-z-FF6UsrAhozeHpCyZQpajHDogA",
            "MIIBMTCB5KADAgECAgkAmQKVaRbcF0EwBQYDK2VwMBQxEjAQBgNVBAMMCUFsaW5hIFJhbzAgFw0yNjA5MDEwMDAwMDBaGA85OTk5MTIzMTIzNTk1OVowFDESMBAGA1UEAwwJQWxpbmEgUmFvMCowBQYDK2VwAyEADLhbefjgmsXoJk2DPBURE7EALxfcwb9cRJfSS3z_07CjUTBPMBIGA1UdEwEB_wQIMAYBAf8CAQAwDgYDVR0PAQH_BAQDAgIEMCkGA1UdDgQiBCBjPP0Ptr5ioOl8UZuvpKvzY6X4tPN_PbJr_8Mgq62b7DAFBgMrZXADQQBq8UK0ZmY0_N1JiWNU1Sp2O66Jmz9C98BZBwB4B42ZNDW9CauFycj2DgchqFKAsQ6Bafuu4rpS_so7-chGC2UB"
          ]
        }
      },
      "expect": "discard"
    },
    {
      "name": "another root discarded",
      "pinned_leaf": "leaf_a",
      "dialed": "https://agent.alina.example/mcp",
      "now": "2026-09-13T12:00:00Z",
      "answer": {
        "code": "certificate_renewed",
        "data": {
          "chain": [
            "MIIGzzCCBnSgAwIBAgIIYs8KMv2IITAwCgYIKoZIzj0EAwIwFzEVMBMGA1UEAwwMQmhhcmF0IE1laHRhMB4XDTI2MDkwMTAwMDAwMFoXDTI3MDkwMTAwMDAwMFowFzEVMBMGA1UEAwwMQmhhcmF0IE1laHRhMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1uZSk3yoZQVVm8hOSTZXPeLREIM8RxjO8ASiA8BUqS3N-15XZevCZ9w9JBeDRHujtYzslU6oyl8k_biWPcoYl6OCBagwggWkMAwGA1UdEwEB_wQCMAAwDgYDVR0PAQH_BAQDAgOIMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjArBgNVHREEJDAihiBodHRwczovL2FnZW50LmJoYXJhdC5leGFtcGxlL21jcDApBgNVHQ4EIgQgruy1Wys1kI9FPsEVvaH0aakNC0UzbKU0USEslTE9sl8wKwYDVR0jBCQwIoAg9T46UOTEFlPC2zGJZ5qGcznbg215xbC6bxcE0T5QorMwggTeBhRpgfnO6rj0tY6UxOSxt_j-kqiwNwSCBMQEggTA1pKjPzgeghNEmwoEm6d0rctduCQQaBo9d8UYIcpotZxiOIKHv0Oi_SCuEpQmqVPDwkHL4GJ_OtkDlxJf6obNj_Ez02CioKtLDONoSgJGsUkqkylMp9AEJdzJ7-HPmxpYoDXMNpGUC3WZsiGVP8F3Qlh2c9E0AiioKjAJIUqICOoYINe5SAK5CNqSAWmiUSRWBkcrGIBGKhNpSkS3EdplunkeDjEvA4NMQnkIIGugfWo5uujNMfFBkyrN6ATKwhymafMCYzOfe9oRTvcFz-OA2sTEoACsMMkUonoBNVZQgCNk9TQ6mVOWXdkOyYBXBpW5mXo6CVQW0rqeXLp_YiWgkWRGBtppqLKh35qtwaeHGDg3YsI5-QV6reEwwQiEwJcQ0Ml0gCMZl9w7J7Ijg1EO8OOqbxy0aFSK-kcRW5mzPVVvA0RAj3KnwGV3y0sSuwY-KqCfBee8FFmi9muscIcFQ_yLd5u631YNbJU-mUWGYZgkDPtiamZrGoCT9xaO3VxpROAQsQCYdABD2TZYmtTKhJeR8NwsF1AQsRtOi9piSsieNjGKgxjCXbxrFsgTzHIg_Ym3hbNWW_LBWTOyoQxuOvNcTyJSRkWTMNRB7Ldn9JylQJK3hXs3gyx8g0xdoZYzs0zNbtKJ8VpLROaGDfrKLvM0dyd39WrCdMuoqnEAc2ZqyuktaCemhFN91do4zrNmzFTLaGDIvjMTgsK74nisXmI9NqQ-UZVF_Vxe7iiaogY0XhK9kBMPCXAjOZM-EhCjzPyb2qZ82gXM5zG-KFOLlpgfccwGwJjC6EDH8Wu912xJoDxS2_pXRctRMJtielplGzJTPlRYNsRsXcYZMOs_NbA_ivPCYqS1pNJM5KWGtYoX9VuffbQNw2hwnCijNLhKSEQNB4gislavQddU9HZtWuaez0KfgwEB6CBxiiNHDRybJaqTURzIf4Jwthu7Ompq0BmmsqR_k7qfpuK5ZSM5FGTHsyYcF3QcgZQXlHx92IZJcnyhY6FCIKA6akp5SeGvkHqdtpaFHNIZIBsueSfDF2dYzqvLGuYz28Sd3oSKaYGMFXI1MpU4zFIkCnwdiiOmruQlANQm_2oIvosEZeKLTWpq1BzBJ6Fujnd5egBzfNupNHsJGoOsb7duPtu3--DCK8K1syd-35Evwgy2Wfg1T2E3IYUJU7e9PqBasccZscY_BkSs75KVwoPNYjmR5LAO1EgZ-BIRJXW1xSZFgOEM4FDGcjq0zMheNDYW3CtQD5VMKArLC-HNf4Bec8paYPFU7TmZH9YAaSlgVauI9Zsi79A2g5hITKa10RgeRHxa6KGDoIfFiTM4fgg8r9NqZuZmoQFSNKQJibJ5WHESx_ebuXSgknTBDNkmavy0ABp1_LG9oIWl98yvX1tADiWVV1MbbQTMojYtpyxNfXqJm4g7fLkjYmeulaqJG-JrLHAbPdoI4KlKD-aFMvIaXriapMI6fLOoKHZUkza6AqRpYsS9COx_7mYdumTFpGdV6ZC5ZVgWV4gBPJq5-pg4dMJgM1tfxfdHKyznZDZoMSXo17eFK4n2VC8OMnrm3pI-7lYosoci9u-Fsrfv7SLhHwLSt5pbZzVhqYevNdFzim34sXKEPDAKBggqhkjOPQQDAgNJADBGAiEApdNYnEZRMVvOQ-7qRloGj06Gb8F6N6pSaVK4_loG-XkCIQDgoBL8d-8op0vw_9dxy4THRzvXeNwn_LJcsyINItnQAg",
            "MIIBeDCCAR6gAwIBAgIJAOURI8HuhdbgMAoGCCqGSM49BAMCMBcxFTATBgNVBAMMDEJoYXJhdCBNZWh0YTAgFw0yNjA5MDEwMDAwMDBaGA85OTk5MTIzMTIzNTk1OVowFzEVMBMGA1UEAwwMQmhhcmF0IE1laHRhMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEALN--KM9wJPMQmh8YK7z9zq3EonvgmJeFIJTHYSHFONfPEkLpumjoCjAI4FfuoIJ8PURpLeLQgykX6wSK9vOJ6NRME8wEgYDVR0TAQH_BAgwBgEB_wIBADAOBgNVHQ8BAf8EBAMCAgQwKQYDVR0OBCIEIPU-OlDkxBZTwtsxiWeahnM524NtecWwum8XBNE-UKKzMAoGCCqGSM49BAMCA0gAMEUCICAh_FxLtuSDuE2XFy7sgwbfkDOzA61WP8STtofPTZgcAiEAhkctEO4ux4cfMMy3SIESqbDr50mdy7F-7V7OQu_FbWY"
          ]
        }
      },
      "expect": "discard"
    }
  ],
  "envelopes": [
    {
      "name": "alina-to-bharat",
      "suite": "PACT-SEAL-XWING",
      "sender_chain": [
        "leaf_a",
        "root_a"
      ],
      "sender_leaf_key_pkcs8_hex": "302e020100300506032b6570042204204896ed640768ccb301df47585afe0488dd5095d2c325c68c3b08d66c085b4272",
      "recipient_chain": [
        "leaf_b",
        "root_b"
      ],
      "plaintext_hex": "7b226d6574686f64223a22746f6f6c732f63616c6c222c22706172616d73223a7b226e616d65223a2273656e645f6d657373616765222c22617267756d656e7473223a7b226d73675f6964223a227665632d31222c2274657874223a2268656c6c6f2066726f6d207468652050414354207465737420766563746f7273227d7d2c22636861696e223a5b224d4949476e544343426b2d67417749424167494a414f7055446a466852797a314d4155474179746c634441554d524977454159445651514444416c4262476c7559534253595738774868634e4d6a59774f5441784d4441774d4441775768634e4d6a63774f5441784d4441774d444177576a41554d524977454159445651514444416c4262476c7559534253595738774b6a414642674d725a5841444951424f363530574658705358666349485766644a61387a6853626d747337432d6b506b55326f4d51685050394b4f4342627777676757344d41774741315564457745425f7751434d41417744675944565230504151485f42415144416765414d423047413155644a5151574d425147434373474151554642774d42426767724267454642516344416a415f42674e56485245454f4441326868396f64485277637a6f764c32466e5a5735304c6d4673615735684c6d5634595731776247557662574e7767684e685a3256756443356862476c755953356c654746746347786c4d436b4741315564446751694243413165667769754d513930502d77456e69673569744e5651666b683845494d4e6e4e536957766d4a3843556a417242674e5648534d454a4441696743426a50503050747235696f4f6c38555a7576704b767a5936583474504e5f50624a725f384d677136326237444343424e344746476d422d633771755053316a705445354c47332d503653714c41334249494578415343424d41427558786a6c613570484b734f366c7130597157464e4b795a35566c316e4a47657a486945357070687063796b4f5a4a477041484b4f534a674d795a675538663143416f5f4b77523074486f6a6743507236454b6134796c424f4c417636337670786b4a2d5659446e457a4735435970585978465f59484e61577957385a775970326d3570324b697134456d5538636e3747455539476b5436386874657832647856486d6c306e5f4f3647774e5369456171675a43566f327359795f7349557672747150764142444e756e33576c584d347378494137545f445536384857694e45385634526f7859612d6c5772345672723032504b6244764d3135765051487a305351744a6d5974375562344f596b77466336786e2d78776964687a354e7970456d777445455744506c46534f4d4850693130365a6b79635041444d4e4378535a6554726e41724c413879303351356b305547636f614b67505955786935354a33353856614f63757a704c67776f34486643677871434b326357516156795474736e4b6a5371437477514d6a43536a694a456f756d56526242715a784c4b775f4463796c58416b55705232545f4b72476a364777794363694a3830653356575938484858333173674a77336b7a34345f724134366c4d41695a30326d5969614b5a59614331794d7362746d33797469784b66417554356d466f59527a49346854617468566b634d6b7770774b38693038776459656b4e5a616c42584149316b415469596c4c4b304b4c3452616e36714a7a5a775346554746696c68625543516471323463685537433832514b4c555a454c39526a643537534175444e32635274594d5a6c6f4e37512d514a6c534659384553436b2d4e4b317a63477830624b676336724c326c7942322d497374397a6665476b4d746a46634a31387350786e786634634f41457249346c30675653385353724c776f4d4c51583268756f576c2d45654a464f4a636278654b592d645236496b38623635492d7757795463345171374e33506561526f6959716c6c49574e73517a427478534d59575a31664d3272675938456b39473173325956686373305252322d6d2d424f534568755f4f72702d7363334841514430494859686e41784d4f54754f5a577937457a6f7335796a4e5155455f3068437970634b46367374393233536b4b514b6975676b516a4b6a494b524739527a7548414b355274316f4142595f49356b50653948586447417145417a5541454347412d6c764f3742685269326f4b36525f2d73375a35303334466d70756a6d6b526251426b357148784b544349696854684c5a6f756f386b7731323057724d436267344d464357797452724c5163776d34737378617459374a546332615239695f32676243554734434d3236506c303255553434537735377367397262663555353551693970396f426d737772733837426d34447349624b54613970675568726d4b3949786f526a595736586e426741384d32517a743469634856385f4c4b6d7a5370314d39564731722d41317736305a62435653706d465652783134632d304c7652537075696b764c56706f4d4f49474173366a38575162622d6e766164686b646479656f713547446f58655043304b637759477674494743323275514c4b73682d466d6952566b4b366b307949693836524b63727177745464592d464e726d4432637233347a59375844382d34684a6455366b79303756775a6c68705542764375714a7447315f614634775f49367a5f646c777a5277715967633973703663544a7a414e5538773657634533776f355a4d7979736d5369454a673679684642634e67776670453837434448455971362d744a66716f3432314f3374486f31766873796f6f6e41647947635f4431482d52567877663157486b3233476c754b587656387754374a495534425a7a6f41366b64474550657a334d6d4c5f652d6c742d776e624d36522d484b4163614f4636646179593864724f683056385973596e645a453834724b797977795f395a41556a5954534647792d6d4b316c49463568726e4456724e6b7330706d6447303359305973705256574b5975687835515442775046336e6779546b684142513456476d7149725759463644735f4556526c3851726742747452386a35596358397230505479725a34786f56416d73765033387431657678577767306a71494b50574654453234446362492d41744e6741383656477a616b53655078717639754d4155474179746c63414e424142495362336f4b4d6447616377326a3447633558594c6734385f38564c79646756713370427936775836325a4b326e2d6747724c634b37427a702d7a2d46463655737241686f7a65487043795a5170616a48446f6741222c224d4949424d544342354b41444167454341676b416d514b566152626346304577425159444b3256774d425178456a415142674e5642414d4d435546736157356849464a68627a4167467730794e6a41354d4445774d4441774d444261474138354f546b354d54497a4d54497a4e546b314f566f77464445534d424147413155454177774a51577870626d4567556d46764d436f77425159444b32567741794541444c686265666a676d73586f4a6b324450425552453745414c78666377623963524a665353337a5f3037436a555442504d42494741315564457745425f7751494d415942416638434151417744675944565230504151485f42415144416749454d436b4741315564446751694243426a50503050747235696f4f6c38555a7576704b767a5936583474504e5f50624a725f384d67713632623744414642674d725a5841445151427138554b305a6d59305f4e314a69574e55315370324f36364a6d7a39433938425a427742344234325a4e4457394361754679636a324467636871464b417351364261667575347270535f736f372d63684743325542225d7d",
      "protected": "eyJjdHkiOiJhcHBsaWNhdGlvbi9wYWN0LWNhbGwranNvbiIsImV4cCI6MTc4OTMwMTQwMCwia2lkIjoic2hhMjU2OnJ1eTFXeXMxa0k5RlBzRVZ2YUgwYWFrTkMwVXpiS1UwVVNFc2xURTlzbDgiLCJtc2dfaWQiOiJ2ZWMtdjItYWxpbmEtdG8tYmhhcmF0Iiwic3VpdGUiOiJQQUNULVNFQUwtWFdJTkciLCJ0cyI6MTc4OTMwMDgwMCwidiI6Mn0",
      "enc": "EI0bD1u71v0iiDDGNwSFI4DWqBFOV6W-hPaHx5F6R2jDmDH46Zx6mjBMLtC3JNwU28gbffrH9_M8vcdFRWRjwWkhBVAUaRQdo3P59tQyfOu4b4SrAwweNIX3eRJ8mqzSPrBwdHbOTEbJo-JiL4DoFyK-_RXtr_7EUsW3sw55HO7qvx1tiGFz40cb4Fdb0shloTegXdaV9piBfO8JzFJqL-TVZL4xA-9DrDMjWrH6i53GX4U_PkYZIAyxYw2zB4ZyEgdV9RC2XXGi7_Swm56SoaR6UHGszNW2HZqX6Jl7GKn4LzppGG6YCGuOOfvwhzkgYujbrRxL329X85mYcMrocyXvzY7A9tyAMCD16jT_xy2ZSwzJdlbBp8VHbUAdA3PTegQgJLwFU7Fgqtrh-IQyIS_Q0HmMqhwIbf9SS4VfvRFamdNMjckIgzBOgDjs0F4OSU4rXvyi50Bf5mRDN7Y6QT9m1bzPvX6DRnUrE6LlQcYBuBUW4qZD-4M148TB77lTVR0f_vNzlssdDf0ytaFD-2LgqN2jNxmtf4sKMG9aCp4GEyqS7jVsd_FTg7dS9-GBt2VVzp1nL1QDKT-op7HRv09etfyzUja_Tao7mTQRb-GDJXY9tPIWLEIlCclAWtQr5_A1R4AnF4eSGabTnhJXfVEUcDhhpSD1Fal5XNHlnako_5fJtlDKoQ9hyrFCLM1c6NoBYOLNVO6dhtZvgJulZ1xTD1HVs2eDCxPLfw3Mo60oaz86be3kOfIBJmJwltt8W5qqpVB9ltQHiOjxtsyDGskcADrVRj-PPgjIiAlSrB1oNf75R3K9QDLxXFYAreuP4faabshza8x6lDDSJx7dXJ8TJivCtLMLI9jfeER8JTwyL4CsEWyYiyiSE2RV13i3pie3hxyJ57r2GRhioBID0EHv_yFpuuBLTElK7PKoh2FqbGa3VUoYSkHEw-o8OkkYiSIxTySLq8iztadhScQVfS16wAWkALautF3V8zie0F07jeUiXEqsE9VlRNcRnEAK5_eKKf7ZOLfDePb0lhjM7EtFWqJ26B5GfcvSvyokrnhJ8CqhYsrIWbqF9HnQ7MSAlZs4X3C--bCJO6ETApunhSc1voGKW_oTIP4bUxWH3H4bYIcdjaOnaNkl6UwKVJbo3hndrMIIgiggZeAItxjn0zNHIXOcQLI-9eJYtpNe7La1Ne-n9GOEqx6amAsnKEY0AwDjYJSyLdf3JgGc611TNW_1Pg02zrnA4mOXJ8Q0aG_aV-GOjBOripJVI9UYlEFan75JjTZ5gjLwP6FUszKPKhF5_-ygQujzAVWEZqXIVj-geruWzDb_CbVAt8ugYEYQXDnS8McU2qf7gsUUNHuODWiTX4kA-ou7byyjxQhBimT02XqwfojqWJ7wxyqh6rkTAc_QBrCKCjELM1ZfszCJEAGdkm58jrTv6YoB7JGSaimGCGF8gGD-SwWKlt5H21xhuD4elo9lCI5jWfkQNdwaJg",
      "ct": "jIyJP3gEyVhZwjGw5zfgQ1bxOCYS7kZw9BK5yp0VdJy54SQM-DopyYm-eeF3mnmj5Wp1iUSPGJzKWivqr8EwvdLZHkTDrD41C6W4A2BwagT_2ySWH0-e_HYiFObEwuA-FFfiSDwy62oK0N31aDyKn5AWOv2ZE2ScAScLd_aa6Bw0Lz0XD3FRI1Fi415KRGZNaWO9jyZ3tEUEsL9LW8tSt0tqkDV9mFJ0UivQFntYOs-hJkV6ApRlrXP5UdL3LqYVHO1Ecw6JBRu1Gs1vWRibbqCBAHwW0c3FzsxnTyomhkZAJXegddO7ZHdsCl16lXLkCps0pmNPbh06kJhXcRHUjXvC0iAMUyORpvQUV0KPH79YA52OsIX9y9dhxRxoEmsN2BvwTpCiLFfvYTRu6B5IZPJ2QcK_nOVyXYkwYv-I4iWFmRw4y9Jt2OAqw7qtDG8mY_FfwwgS39ZbJVdx7nKMX5ym68kWK_bDy71odY1qdPrD4CxuNxbGO0EWcuXiXAPAO8vsZ5gYvfMDgopj0p669KNAJzhdzfyBo1S5pubecaQSfb_qeqKBNgS2Oqvw1kvQQFQeKGGX7bMZNuymVaeq43xZUxdsTxdFL8b5Cn3q2smQv851HlyXmorrl6WaDQr_TY9OV_EDJMNAzK477PuYUoSJJOdHJDaxH5xhnRRrBbLIEu42yK908KbTUlzBKFFB8pUwoELJUE-IvQmY1BvBc_X36hzjIxWntyhkKzrl4NNA4Axm3t6ll_pzCSwsk_LVIAjRogkTJ1wpb9GDwzfJvuYQB2C63L6AGY8IxATNwCNrlmjDqWfO9q1M1v5eQdGmPfHE12qviqdAtimmcfRBPkxjsMItGlJUwME9dCnqVK2T2quE9-9xru71R63xkDne6osGDzvgB8eDKdINePCpzQJjY7GwJF8Dm28axSLFe1enb_NTwQwD4RtYwG5BYyGcGFEstgH6vSQR_dZckdUKFSD5ydsP6_8F7GCW9zGvake_0rAB1K6iZ6ygbkoTzQsUReGZzttyAeteX6_512AcdWBqKF-hF52ilfueGHFblFczqeBJuGKu4WCQqtYDOaviVczjCWjiTlsKgBZRneMQniOjFaNLekCk_D32leNrpG7Nc-1lY_b3_NrW67zmf-u4ICSf-LAKOgkoHCav9ZCwLZBfRWza2topi1TL2PM-U0txxjsqhCHu5T9A5ESpRJEUSgkWkK5KZMqwOPUwnzQ-ab9goM-WMmjBFr4UFZNNKEzHqGWbHI3xDTQLWyUIOOias5WfrKXX84g2OBeXwYxgrV_wACdG6cXMg4yvnNXkpDbCAo4cmfncDOAa1SeUl19BYDB04ZcoNvPidTaKSqSfETTrJfs0CwETW1-GOkxm5fSZlJX-KEAOzApjk2UXSrNoQMF0_Z3hPhOdlF6ygRTXYzpZxt0IXCMXSEYJzw64GZz04ckGq1yZu62hPLA4EwqM0lgIKOG_9aK7WrN6kriL3OEF8PldwyR3KDVV-2opv5Xzd1qtCgs0KN-6evT-xjXZxEd97Pg0bpfrLBYc9HKzw0HwewgbRKd5V7QRGPYFAqcUwW2SNXOvvtA-JZzK-KolH2a5E9agkbVjyQsqQhuwuaDtFoncqwm18sEwsily1Ti5CbKF8cBiACgVc4CChAtpBT_cozmaVpmfA3BNMpqOz-eSR0AA7yDQQwJvebMdMFKW9kJPXIyFyZa0oJMrtZxolD4RsMGePKwaJDE26iAkp0iC7kkhkE5aeQx-rvt49z9qGYsPJWYgyedUfZup16LCCFu9k8fcqyyshdP5lECIO_xQ7m0kHUXuc_cUaYxgTbawb36hvC4R-DX_YyLQEf1RPufaIxrS6X25AyXBJkS5048G69TwN2mhtu_YwfgQXEMcR8Dj0jLOi--aAHSU9WNFV7dLrNNGhUFI5FuAd1pI_f0BLcl2Mulcd_ygNRmSoXpDENel7ZSywzEalnOfJboq1-wnkRdPQoQI_RIyAI8RAzlReaXhemtCElLN6mIXFcJ0UVBb7igsfLDa0e5XdaLmxcvRptshO2ebtfgu-R1Gd5cW9YcHD8E27cSqda46_PYDfuF_ouS8R9srW6xDEaBdAK_AByHAjz_2uMgJUeg118r54yrw41Fv_UbsKG00FP1-tQV0dtP7uZ-9tYNcU5IoZx2Xt7nmtT0SqfzwDL1aqzMy_Eh5EJwzL9yqEe56dZDvM-Z_9V8UF0v_GknM_QFrWM0fN9P8jgVLjtKcX0xeOoHptLkZg3_4-1eNvPNe-H0DBZ4_LNizqQj3tvRq-L77aClY2fgrWwDOPKtdaSRylfyqQDcZYxALOIiVy5ZzqOBTUvD-vlXfO2urAItECeUufmALujlIP6Py7_yI2FE935mMX-KuyBitLBuwsTzuK9JIfOBormlIBcbn1Ao0AtbERskxIOmyns5rIG7tJb2tVfYSdNeHQAt7-UbFgxfichL6A1vnCuEuPUAd0gefMAOgoxu_oQA5MWOtXF2zeJQl8DwebfUgqarr2IJ1g5GEADQ6kBc5QE98O-ILcvC1zhrWDE_CiDhL8T8fVvvSx4ITtOU4hZVEn0aRszgjtn630hBV50ff9VXduBMVC55b5uItLaXwGlMZaHPhHQkcFNJo0Et209N-VuKuu70tdwESRjOBPJTWpYjssUhAPzi7zO7BNM3bVbvJzUJQXlizACWb7LbVF6PZe7FBdios0tb8UqdJfgXZGaAFoqNCY9bGnX7JWEG_mVt307eCLEo1UOO3kPjKp04AbR1EyWEt_se4daIkpZmWwjIaqwhtEgL9vIv_0arZa1vVZFynzqRrJliqWXHiYrhZMVk2lAHpKsfY__B1-t8OrnEkBx_l-B_bYck45IKnZzymy_jwQTCGNCYkFO4rmSi9AGBikjTUFeSMRI9d2mA6MIwxegxwPerlMELSx6EIKD2-fVgxs1zfElGphs7gbSuQ5vKRv1oV4h7GlLg_EUmdMC_03w8597cUdkBGnvZyVC9sLiHiCgJ_20xghh6TEF2g1ClID2WrczhmqQgD2LtVFDWjCjFkAwhOXdcKsI_TcmErpcpx25D1OIPfmQu2QChoyua5EHDf6rh-t5_FpD3mferMfBpp--drEU8Y_21gdwHZ4eAqAMyecPZOTDCszVac9pnPr3kRVLyumxp3vGz4GVSoNoe5-oNW0i7pQu83FuUQRD8XwjFceLxVWI6QbSMSXnXUuTik9eNRrxiR50JwQl-jgmCTAZzKmKxiXOXXlK5nSnGsLle83E5S4Lixhes3VndWPmxHywSomItuD0qkqwIEvJnyP3mulVJKIYoW5_yb-U6JP-TYQasMt4RCndoxrcLThwhfEJRG7JIVrQo-lhBxpyPnvnL-OaQPb_qQC1Xtttz2AedS2Nk4H5DF68jukP12ZKSdKjBI99LZ0UGXpn5rgfT8r1bdrweggHSB5bEsA9U1c0W4v0Ab3y6xdbPQgM2lfgz0-3jNvGTnGQWGnyba6dqyltXYbbIpRmiry6vl9V0yb7KRmwdTeRvKPNsbFRnWu4qZw-svFJZt0zEGV8W0bgAyLlUvxsp0RgXrhVJifSNx8fhAQPfXvh1RPCj-L9q_PVI1Z1rEuceAGf8oIou9sabs4dO5aVajYPW4NJ2cAogpQhCnBIXmfztGC_xOAW4gKp9MUnuYxPDOS0as2akvZiEMQEXoJJKNThb48jp3jyHlMmuCag6Eae_Um98wPy7tcuOJQIakxuA80AS-_h9GQrZ1i0X3gt4vMQM6fw",
      "sig": "PQNLXRF_TmJPTx5pf7H_1rGu_UM2k_3vZxgpD6ez9kq6GN1ZBGJv50m4u2ALYdwIojAQPcXxRWYUOEgV07NQBA"
    },
    {
      "name": "bharat-to-alina",
      "suite": "PACT-SEAL-XWING",
      "sender_chain": [
        "leaf_b",
        "root_b"
      ],
      "sender_leaf_key_pkcs8_hex": "3041020100301306072a8648ce3d020106082a8648ce3d0301070427302502010104206a261bbb098c126fe60dcc26a72045d97db5079d52cd59826220705150ad60d7",
      "recipient_chain": [
        "leaf_a",
        "root_a"
      ],
      "plaintext_hex": "7b226d6574686f64223a22746f6f6c732f63616c6c222c22706172616d73223a7b226e616d65223a2273656e645f6d657373616765222c22617267756d656e7473223a7b226d73675f6964223a227665632d31222c2274657874223a2268656c6c6f2066726f6d207468652050414354207465737420766563746f7273227d7d2c22636861696e223a5b224d4949477a7a4343426e536741774942416749495973384b4d76324949544177436759494b6f5a497a6a304541774977467a45564d424d47413155454177774d516d6868636d46304945316c614852684d423458445449324d446b774d5441774d4441774d466f58445449334d446b774d5441774d4441774d466f77467a45564d424d47413155454177774d516d6868636d46304945316c614852684d466b77457759484b6f5a497a6a3043415159494b6f5a497a6a3044415163445167414531755a536b33796f5a5156566d38684f53545a5850654c5245494d3852786a4f38415369413842557153334e2d3135585a6576435a3977394a4265445248756a74597a736c55366f796c386b5f62695750636f596c364f43426167776767576b4d41774741315564457745425f7751434d41417744675944565230504151485f4241514441674f494d423047413155644a5151574d425147434373474151554642774d42426767724267454642516344416a417242674e56485245454a4441696869426f64485277637a6f764c32466e5a5735304c6d4a6f59584a686443356c654746746347786c4c32316a6344417042674e56485134454967516772757931577973316b493946507345567661483061616b4e4330557a624b5530555345736c544539736c38774b7759445652306a42435177496f416739543436554f5445466c5043327a474a5a357147637a6e62673231357862433662786345305435516f724d77676754654268527067666e4f36726a3074593655784f5378745f6a2d6b7169774e775343424d51456767544131704b6a507a676567684e456d776f456d366430726374647543515161426f39643855594963706f745a78694f494b4876304f695f5343754570516d71565044776b484c34474a5f4f746b446c784a66366f624e6a5f457a303243696f4b744c444f4e6f53674a4773556b716b796c4d703941454a647a4a372d48506d7870596f44584d4e7047554333575a7369475650384633516c6832633945304169696f4b6a414a49557149434f6f59494e653553414b35434e715341576d6955535257426b6372474942474b684e70536b53334564706c756e6b65446a457641344e4d516e6b494947756766576f3575756a4e4d6646426b79724e3641544b7768796d61664d43597a4f6665396f52547663467a2d4f41327354456f4143734d4d6b556f6e6f424e565a5167434e6b395451366d564f5758646b4f79594258427057356d586f364356515730727165584c705f596957676b57524742747070714c4b68333571747761654847446733597349352d5156367265457777516945774a6351304d6c3067434d5a6c3977374a37496a6731454f384f4f71627879306146534b2d6b635257356d7a50565676413052416a334b6e77475633793073537577592d4b7143664265653846466d69396d757363496346515f794c643575363331594e624a552d6d555747595a676b44507469616d5a72476f43543978614f33567870524f4151735143596441424432545a596d74544b684a6552384e7773463141517352744f69397069537369654e6a474b67786a4358627872467367547a4849675f596d3368624e57575f4c4257544f796f5178754f764e6354794a53526b57544d4e5242374c646e394a796c514a4b336858733367797838673078646f5a597a73307a4e62744b4a3856704c524f61474466724b4c764d306479643339577243644d756f716e454163325a7179756b746143656d68464e3931646f347a724e6d7a46544c61474449766a4d5467734b37346e6973586d49394e71512d555a56465f567865376969616f67593058684b396b424d504358416a4f5a4d2d4568436a7a50796232715a383267584d357a472d4b464f4c6c70676663637747774a6a4336454448385775393132784a6f447853325f7058526374524d4a7469656c706c477a4a54506c52594e7352735863595a4d4f735f4e62415f6976504359715331704e4a4d354b574774596f58395675666662514e773268776e43696a4e4c684b5345514e42346769736c61765164645539485a74577561657a304b66677745423643427869694e48445279624a61715455527a4966344a77746875374f6d707130426d6d7371525f6b37716670754b355a534d35464754487379596346335163675a51586c48783932495a4a636e796859364643494b4136616b7035536547766b48716474706146484e495a4942737565536644463264597a71764c4775597a32385364336f534b6159474d465849314d7055347a46496b436e776469694f6d7275516c414e516d5f326f49766f73455a654b4c5457707131427a424a3646756a6e64356567427a664e75704e48734a476f4f7362376475507475332d2d44434b384b317379642d333545767767793257666731543245334959554a55376539507142617363635a7363595f426b537337354b56776f504e596a6d52354c414f3145675a2d4249524a58573178535a46674f454d34464447636a71307a4d68654e445957334374514435564d4b41724c432d484e66344265633870615950465537546d5a4839594161536c6756617549395a73693739413267356849544b61313052676552487861364b47446f49664669544d346667673872394e715a755a6d6f5146534e4b514a69624a3557484553785f6562755853676b6e5442444e6b6d61767930414270315f4c47396f49576c39387976583174414469575656314d626251544d6f6a59747079784e6658714a6d346737664c6b6a596d65756c61714a472d4a724c48416250646f49344b6c4b442d61464d76496158726961704d4936664c4f6f4b485a556b7a61364171527059735339434f785f376d5964756d544670476456365a43355a56675756346742504a71352d706734644d4a674d317466786664484b797a6e5a445a6f4d53586f313765464b346e325643384f4d6e726d3370492d376c596f736f636939752d467372667637534c6848774c53743570625a7a5668715965764e64467a696d333473584b455044414b42676771686b6a4f5051514441674e4a414442474169454170644e596e455a524d56764f512d3771526c6f476a303647623846364e36705361564b345f6c6f472d586b43495144676f424c38642d386f703076775f39647879345448527a7658654e776e5f4c4a637379494e49746e514167222c224d4949426544434341523667417749424167494a414f555249384875686462674d416f4743437147534d343942414d434d4263784654415442674e5642414d4d44454a6f59584a686443424e5a57683059544167467730794e6a41354d4445774d4441774d444261474138354f546b354d54497a4d54497a4e546b314f566f77467a45564d424d47413155454177774d516d6868636d46304945316c614852684d466b77457759484b6f5a497a6a3043415159494b6f5a497a6a30444151634451674145414c4e2d2d4b4d39774a504d516d6838594b377a397a7133456f6e76676d4a6546494a5448595348464f4e6650456b4c70756d6a6f436a4149344666756f494a38505552704c654c5167796b583677534b39764f4a364e524d45387745675944565230544151485f42416777426745425f7749424144414f42674e56485138424166384542414d43416751774b5159445652304f424349454950552d4f6c446b78425a547774737869576561686e4d3532344e7465635777756d3858424e452d554b4b7a4d416f4743437147534d343942414d43413067414d455543494341685f46784c747553447545325846793773677762666b444f7a4136315750385354746f6650545a676341694541686b6374454f3475783463664d4d7933534945537162447235306d647937462d3756374f51755f46625759225d7d",
      "protected": "eyJjdHkiOiJhcHBsaWNhdGlvbi9wYWN0LWNhbGwranNvbiIsImV4cCI6MTc4OTMwMTQwMCwia2lkIjoic2hhMjU2Ok5YbjhJcmpFUGREX3NCSjRvT1lyVFZVSDVJZkJDRERaelVvbHI1aWZBbEkiLCJtc2dfaWQiOiJ2ZWMtdjItYmhhcmF0LXRvLWFsaW5hIiwic3VpdGUiOiJQQUNULVNFQUwtWFdJTkciLCJ0cyI6MTc4OTMwMDgwMCwidiI6Mn0",
      "enc": "mnVUBXmUeHbb0s_c6qnZp36DRKgtCsWkNDAzmC2Fxce8bUFxMARKizbYt_iBH2efH93ETf58W-pIYkUziPt3J705KWs9NDVVsKLN6GnjfF9mtj6SBJi5VcTkEfMKyrQH7HfPqultKvrAJQc8EFhun9Ej2jRbPDqTN40ICd6QfYttlbUhdc-iRXWioqk1c1MMeVtotT8jMyBmmniTuM1ghV1glwzRk3qSY3Ri2vzcspuUH_ilTiJFTjJhNBepnPGkEsGAZuy-vOWNtbKPp_N0I7SmSnvwuI3E6aC-qGOofIPeQ8Tq8dUvYk3IK12RNe_zpMq6__a6P10bNIXah12y7afhQnO0kPj54tJzVCBOxqTQDKp6DYmkHqjZ4HkttKqEEIGADeCEId2L3TWV_bKIbTQl43ROQdhce9_F6Xixu-mAXXRHUi-bXRKOGKsXwqDX7F03zyKNRjA5oP2oKUVpr90WxTT3uxHtZoZJKyzg8Syv5FvYSyJdYCNhn_IDx6Gs3v8DOXz0Dy8xrSkSewkKqIcRHybClfrfuQHAhdpJ9PeTKgBVu2lB7UENhPEp7xAgTqZ00DKV9MwV0xmfk4SUq7xmYx-op-2yBrpm9xRjqvzSxKS_jz8gAu3Md7HFohk2afwE_2wGflaKGKXuO8jQcZVCMDTos4Wtbc4LfTRIUa9oq2MuSLlibZ5zPIAdPsPAh_-IuToawcZ9LKUF140E-HzepjLVSkKK3-noEyWEV6oCB6cohGgrTgLQRDSCsbNjFHL1r-JLgV5xRRmZ4J1spzorah3E-TNzWdQyOgpHDjhUTSCCHtPT_0ivDAlRxgPZzw3uCraTFwK5WxpogFEQhv9AMhg4AggKhi8EF_bhx83ZRZxn-QldUtEzB4f2rSTeeJ-Fnzcu6WcNwYEoJ4rvS5Io401Zz6H5Wj8D38uuz1lLZG5vcTWFsJQ2EPXM8kMf34hAocald3ae3ZEKBH5metYfoUQqPT1YjEpaBq84V-e9Z2NdKfZdSTtHDKbU5vfYDzXKky14PdNl-1lKypF97aJfetRG7sc8f9azxOUaXVYETCzBzzT00iBPlX9c7MFMZXyBdUX4OdpCb34Y6D9KMT2qVHLbzzdkLcb-VnNzML10NgfoUbL5B5sd4te11Wo5URcHmIUz_jVBb-sqNPVFQKiLj6oNyfp8A9aKXyfcM7psPm4vXQM5tb1WRy9IH7GvLQbW18WMLB_loFqKJHn59GI4kzVTkH57NfJZFOLQ__i7BZ39Q-eZULxXpBiGQLIRQ8Q97PN5fgCuanlkyfmCClciq8a3EOS-j-df6ldWTQl0zSFArOBZQq64csTwoTOgdozUdvOxQ3G_b3LvpOcy8anpA-6d6964U52RndWGvMDyUgm-TuUF8rMWa4mpVkbnioD8snQVrGOSJqCoADl-YOq8_UgwNGtE0eQvMtrtPNo40OWJgP9W_sYhGkjYkxuz6mBczcuOCa31JP_skU2HZw",
      "ct": "CSVOHehuaskM528pqDfozDqZncIBzjEPbUWKB-MxC9HwfZXZEbjYrA5YwQEyv4PhYtdCpB77wwHNSK_mvl_BoqAMT2Nta5Kaw9zlH6RHADV27Vy-u5JtR6fZ_U8_fstrAwoNhKw-HWWgEZwym1TlpmwnhNKXRCn5E8CyR3_lfdvkKoRcKz3Aq_XzMu4ANDaiGsGsn6CIsKd9WmBEL2s0rf6-sF49Fq6STPfPZSV482lL5X0dT8aHtZcqozyRmZGzm2slTdVwMVum5TtLp1dC2tYlXpAW7jBGxHiCshJ0pZ_PAViaqzslyWYuLUBWqXJtQvFnP8k7c4eM56b9BtfA1dNb1VDh63-ch8ErKdC63psculzvODDtwg5mGM3gAIlyZYCgc25um7tXXSiWLkAVQP3LZrXqANhfuxq51ISzBLGsGHYsCD7bxQbeu8TqcsPQ2BtEIcDe1q0lIhbTpfVscg0Z7vZpn5udrwPnG7iI_yYllulDflCSBSgUwvgBSkwAO8InYa2lcll0xCxpcKz7ZoJO2hec9_py_XmZgdvFARaDvw_K19iSc234cKqkcWDQqXLqmq5uAGzgfcax1ktb4alLie0dPqB3VS-I6aTbuktldCcTr8V2BhFGG3sgWr9HOf1i2YHL0UiQAYsJy_zm8eJnPtj9Ex7__NMwZCvkjVCkXWAhNoQi8c1jxiKi7FZR2Nr0p-SAq9uhHYIlzuExjWykBt_ALH4l8Ual2MtPdkl3fjbRVHxd7Y29t7yARmEhNB_1KbXBMiqdfC32Y0h0UBl8eseWH_qTdOAYXC40mBan79IOZTBRl-yjqqmRWqqYe-wiuRE1Rtc7J3RSbFf2y5nJeQrlOPMvQ8ulmtHVRQ6h4RYQOps-YxmqvhlEcGsz9HOUXz_u94xoRLiskZNQfzfhb13sal7BglHCDPRurXsZaezdlgSHIo53tJFrVKWMmEuyAT2H7B84olmL4IIanY7BDHvxDtDaQbrwYc4-p-4Rw8gMRVhy27OBTidbDwpidnwDzXXhhoUpk0B-rYGE4jP3aEluCx4_c6mdiuY6OYPRefQEOiiu4sR6m_-T_eStuSBVciVvzr_PuQ0xeMNNuHb68svFrRMLXRt1wKcYMkhEXj-2dkrWY8LMPD9tANzffJTLNZ-PeGXKdt9CB9u5s3FjDZ0FkyixlqhTlFAedlAzr-sotmznoW7ldjHpBVpfvA2dcp1pLFlMkM2nXcFv7o9meUKiBNn3ciHQYj7xmWd-pI3MSxTm4d3wMpYQCLdPf7OIYvi5uwSjqPLSg7OOmTH_WVmM28pC28ESMEVyXlDAl31aay0g7ZdzFd440RwmJuXnnBIiPGjHtDGffOmsQcgt1quaFfPnWRgsB9dbPg2KRMuyhGk8iLOO13GS8If7kvz38UBOPe_YasNatfPwrpoSVmJmverjKggwFEqCFXU4MuiKoYzACUgD_Gm4X1PpREFNziwzqGQRfWajOoODynhTn33VIZShRM5OwOaxFuFbR5teez0m1-r5E7OqFfzIiZrFSJPbbRlseonpEmqsZiDdP1i9N6XsS5TYwub6iqRXrbifJIW2F97WWWvKLm4Kfkdj1W45n0fpwZ0IJ0BLfunmWEpHay3Z3Z3frXUu4cfIHKnYnI6XFJYD3hhvzWazS4bHlQBdXC2dte9ONmYHa0Ac9GnH3gC-D4d8qDQhkxyTzPTg8EFym4VoDsW8pGg3NVn2L2SxX8SaaQyzDZqjP2s-0XOiO5OH6C77tUhYd7fMP1d1x2wRaN5V2M7nCRwJ131bbqrvhz6u0zQ0xMedaW8tVb-xqODqIQ3TdIQ7cYzO4Ohcp9rdr_DEDWqety7rUWYK6pDUxpNw8BZMqbAQHDDByCdLalggoLLrUCp94TxMo65DE-yl9Vk3w0By2DlLJAnPRaCK_dIH_Ftexfvh-zLbZ94myaIQ4kebl9PmJENcct4Q0_DFy_pt0FMG5tfd5Wbk1L0C2nRO8IUVL54NJsFXkzTI7SnON5s3vwUjV5zly-Tu4zwCx-k0oyntpRlpxafBQz6H2z4NXdDVXQ77TdFjIVdxhzZbQXr3_nu02ScVUA0Cm5i-pkAlTJIK3tGv9jIsux7RMY56ttqDzQ5NEkYqVZZxtpGJKDOLX8hUeQZZRTeR4nH3_cpATQQvo_IILTkSl5M_HXqAjFMm0ViujzGKHSSEOM6bcV5K85OAoxcFtP5JbxDHXAL2b4c41BAjxTbA2Ru_GTdDbjC3EsGkwxMTzmhtjgovbIL6bT3p4XLPI_BF4K_5IYMwOo4P69lupzyg4KCevb5n3cjakGL99yeG0Hnzd062ErT7i_ctOD2u9foKAWC8QsfHdo4DKQwX3mVJQNlmDHwUjLQbkpGqSf7IAo4KzztmHQI8D-E8-GrDjpXhn9MHKawWdFsP1JzAJLo_d8rWetRocdbQ3Re412yD5XGEsaRBJBYTxZmKDLgdVh1iSEBTFv0zZVVYzG1xnuDK7UGDkIspGqQpiohlV9k20azEdSIMyiyeH1LOGErHlrhYeXAIQGkHy0DIeS0jTjjq3K4Um3S9Y5i3WAqBeA9kRK9-5-F5fe6wfrLM6NLvQBYlEWRq8AeeYiu3VQ4fyBmlcTn6UbVE2enQPvicpDi1JbIaNLkMsTENVy6cFDN7c7xVGy5rbkNqHgWBVbHPrUWRuCjzHBUsLEj5nLcVE6fwpEHBc_k8qRziDaCvH7h89sBoD7Vw5z9yT0bmsbnYJJ85RbuoUmp1XB7zbUBBw4E1C8IuWV7GF2R0nJMyGQv7GncapZX80Ys4mO8WS3meZ_jsAUsdszFIiMY2bv4lqj4FBzjJrBPajWYriBlEjOo3Be29jiq_q2KWHmiMOGExCbyENR_xAQrf_qTU-1jeRZQRGMQTlOf0NcJ9Vuly3chPo83eK7SRD7NQv-PwyBa3gDw0Mn7PLwjcxyipmHNiCiMEmOKxiFmo-DeuasbiSV8o67gMYp79KAEBF30Tr43w1aZsmdn6CFukz2j6T3sQsJN1CTy8e38l2ysrP90qv6ew-g17a8h1Kt3-xj25BTU5p4FarAa5qt3TjXiODAnyk4yu8a_mLhFiZ_zJzxrVoQmXXmje-4rMKcIhgunbMXu1M2NigO_C8xRkzTaBF6OxUNTe12sUHI384FrzIm_mIMzV4OHAqTHqDx3Tn_zAni-tTLVnRNVIPWk2vzYGF4Xj_g03FUCSC0ilwDkroYE_CmXoqrtr4NnDWn2uM3sXqlrg101RYov9QLQfVhLqSg4CRqsDv7UUAyukAFPAVIXTmmzlFDXyx02esJWSQnhTvbYKSayvdWwLmp3uBvI4uutjb7TdOUVWrmxrxJo-fTFSMIwGNQS941uG7Z0XjHIoGs53JtptAf5Z4kbQXDQ4aXozgXIeFM661Bpyh-A-qPCQiY7BxSTjG7JZtKuadQQ-VhIsU9IlDV3RYH_00mykWaW2sdOdPrarg-PGi8gNXRI6kP6i6hiD_vy0TAB5gXTkIQpwX7TcaIdfIC8i9I_IzKMjt7UyCAhIwq6CHws1M52drFeBooywhmj-UxPvZgwRaDdXVKedlQMGA4aKCuvnzHTyj0oojOu0adQ8C9IxLtMehej9vhectGEWxoI81pOTbRgWqzajdql0sGYb0qNCENKbahw8x6CJ7_ajrZ_xCP3BJvZAHS7mtWh74_BG_DiQqnfBLHGOKvP6T7w4HzzeiozsxpgJu_syvNfOFb7WF2VZS7jGeGHu30kOI6uu-gZaLe5-4wNvN5F3fGGwe5dfQIPMtOXSAHNiX_6mBpNOxnqVM-nnkyK3pZ-PLC0StT222E9ytSlSSWUwX3ItDefzPgQ2MmaoUdbDbWJed8b4n0vzB3tgignhsXgOECTHgGKy3rNNeMMiQESYcC3WPHUmmecbjdp5h8s3l6yi-WfD6oxJHjO_dxy2KA4RcWrNvu6gn6AdBep7BlxS_wWe3jc-w9iIll3YiO8I-w",
      "sig": "MEUCIQCYb8DQp0hDjv5vb9Su_qjaTztj-UK4AjEyFMFRj6bA_AIgBEtON4RXkmd8JVrYjZx6IXS1PWeyx0i5rOK_gMFkbeg"
    }
  ]
}
```

---

## Appendix C: coexistence with 1.x

A 2.0 identity and a 1.x peer must keep talking, because a contact book full of 1.x pins is exactly what a person brings to 2.0. The rules, each the smallest that works:

| Situation | Rule |
|---|---|
| A 2.0 identity's card reaches a 1.x phone book or agent | 1.x rejects any `X-PACT-VERSION` other than `1` and preserves unknown `X-` properties. A 2.0 host therefore MAY emit a **compatibility card** toward known 1.x peers: `X-PACT-VERSION:1`, `X-PACT-ENDPOINT` = the leaf's endpoint, `X-PACT-KEY` = the leaf key's fingerprint, and `X-PACT-CERT` carried as an extra. The 1.x peer pins the leaf key as it always has; a 2.0 peer receiving the same card recognises `X-PACT-CERT` and pins the root |
| A 1.x contact holds a fingerprint pin of a 2.0 identity's leaf key | It is a valid pin for as long as that leaf's key is current. On a renewal with a new key, the 2.0 host sends the 1.x rotation — `update_contact` with the compatibility card and the old key's signature over the new fingerprint — to every pinned 1.x contact, exactly as 1.2 §2 specifies, and presents the old key as its client certificate toward that peer until it re-pins, as 1.2 §2 requires; it can, because it holds the old key until the old leaf's `notAfter`. A move puts the old key in a host that has deleted it, so a 1.x contact learns of a move the way 1.2 §2 already required of a contact that missed a rotation: from the card again, over a human channel |
| A 1.x contact calls the 2.0 identity | Its client certificate — a single self-signed certificate, which §14.2 rule 1 routes here — or its `v: 1` envelope proves a key fingerprint; the 2.0 receiver resolves it as a pinned 1.x contact (§6.1) and opens `v: 1` envelopes with info `PACT-SEAL-v1`. An owner MAY stop accepting 1.x from a date of their choosing, after which such contacts are refused `envelope_invalid` and must be re-added from a 2.0 card |
| A 2.0 identity calls a 1.x contact | It presents its chain as the client certificate — 1.2 §2 ignores the chain and reads the leaf's key — seals `v: 1` to the contact's pinned identity key with the suite that key needs, with `from` the leaf key's fingerprint, and signs with the leaf key. The 1.x peer sees a 1.x call |
| A 1.x contact's card names a gateway | 2.0 has no relay role (§9). A 2.0 node delivers directly and, when the peer is unreachable until `expires`, reports failure (§7); it never calls `relay_call`, and a 2.0 identity never writes `X-PACT-GATEWAY` |
| A 2.0 peer holds a 1.x pin of a node that has since upgraded | The node's 1.x identity key became the key of its first leaf, so its first `v: 2` envelope carries a chain whose leaf key equals the pin. A 2.0 receiver holding a 1.x pin of key K that validates a chain with leaf key K re-pins as 2.0 — root, endpoint, leaf — with no human step. Nothing is re-shared |
| A 1.x node that upgrades to 2.0 with an existing identity | The person makes a root and issues a leaf for the node's endpoint carrying the node's existing key, so every 1.x pin of that key stays valid and every 2.0 contact learns the root on its next exchange, per the row above |
| A 2.0 identity moves to a host that speaks only 1.x | The host cannot carry a chain, and its `update_contact` is signed by a key that cannot authorise an address in 2.0, so to every 2.0 contact the identity is a stranger at a new address: it must be re-added from a card over a human channel, and to 1.x contacts it is a rotation at best. A 2.0 host that exports an identity toward a 1.x destination MUST say so before the export; the remedy is a destination that speaks 2.0 |

The `X-PACT-VERSION` major moves to `2` with this generation because the card's shape and the meaning of the envelope header's names changed; the compatibility card is the one place a 2.0 implementation writes `1`, and only toward a peer it knows to be 1.x.

---

*End of PACT 2.0.0-draft.*
