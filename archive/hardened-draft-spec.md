> **ARCHIVED — superseded.** This is the earlier *hardened* draft (message-layer E2E envelopes, key hierarchies, SAS ceremonies). The current protocol is `SPEC.md` at the repo root, which deliberately replaced this design with plain mTLS + vCard + MCP tools. Kept for reference: its sealed envelope can return as an optional layer if gateway-proof privacy is ever needed.

# PACT 1.0 — Personal Agent Communication & Trust Protocol

**Version:** 1.0.0
**Date:** 2026-08-23
**Status of this document:** Proposed Specification, first public release. This document has completed an internal multi-lens review (protocol completeness, security/cryptography, editorial); dispositions of all review findings are recorded in the informative companion document, *PACT: Landscape, Comparison & Roadmap*. Feedback is invited via the project issue tracker (see Release Checklist, Appendix H, item RB-2). Wire-format artifacts defined here are frozen for the 1.x series except where a section is explicitly marked provisional.
**Editors:** PACT project editors.
**License:** Specification text is licensed under CC BY 4.0. Example code, schemas, and test vectors are additionally licensed under MIT.
**Naming note:** "PACT" is a working project name. A trademark/collision search (note: the name collides with the Pact contract-testing framework, pact.io, and others) is a release blocker tracked as RB-1 in Appendix H. The protocol identifiers in this document use the provisional authority `pactprotocol.org` and MUST be re-issued under the project's final domain before wire freeze is declared complete.

---

## Abstract

PACT is a protocol that lets the personal assistant agent of one person communicate with the personal assistant agent of another person over the internet — to book appointments, negotiate meeting times, and relay messages — only after both people have consented to be connected. Consent is established by a *pairing* handshake (a "friend request") during which the two sides exchange and pin each other's public keys, in the manner of mutual TLS trust. All subsequent traffic is carried in end-to-end encrypted, sender-authenticated envelopes that are opaque to every intermediary, which allows the same protocol to run peer-to-peer between self-hosted agents, through operated gateways, through tunnels such as Cloudflare Tunnel, and on multi-tenant hosted platforms, interchangeably. PACT is layered on the A2A (Agent2Agent) protocol as a formal extension and uses MCP (Model Context Protocol) as each agent's private tool layer.

---

## Table of contents

- Front matter, Abstract
- 1. Introduction *(informative)*
- 2. Terminology and conventions *(normative)*
- 3. Conformance *(normative)*
- 4. Architecture overview *(informative)*
- 5. Identity *(normative)*
- 6. Pairing *(normative)*
- 7. Envelope and transport profiles *(normative)*
- 8. Message layer: A2A profile *(normative)*
- 9. Verbs *(normative)*
- 10. Authorization and scopes *(normative)*
- 11. Discovery and the directory *(normative)*
- 12. Errors *(normative)*
- 13. Versioning and extensibility *(normative)*
- 14. Registries *(normative)*
- 15. Security considerations *(normative and informative, as marked)*
- 16. Privacy considerations *(normative and informative, as marked)*
- 17. Internationalization considerations *(normative)*
- 18. Accessibility considerations *(informative)*
- 19. References
- Appendix A. Complete message examples *(informative)*
- Appendix B. Schemas *(normative pointer)*
- Appendix C. Test vectors *(normative)*
- Appendix D. Public MCP façade profile *(optional feature; normative when implemented)*
- Appendix E. Design rationale *(informative)*
- Appendix F. Deployment guidance *(informative)*
- Appendix G. Changelog and review disposition *(informative)*
- Appendix H. Release checklist *(informative)*
- Acknowledgements

---

## 1. Introduction *(informative)*

### 1.1 Motivating scenario

Every person has a personal assistant agent — an AI agent acting on their behalf. When person B wants something from person A (an appointment, a meeting time, a message passed along), B tells B's own agent, which contacts A's agent over the internet. A's agent applies A's policies — calendar rules, approval rules, privacy rules — negotiates with B's agent, and involves A only when a decision needs a human. Neither person exposes a calendar to the other, and neither agent will talk to the other before the two humans have agreed to be connected.

### 1.2 Design goals

The protocol was designed against the following goals. These are stated informatively; the binding requirements derived from them appear throughout the normative sections.

Personal ownership: an agent's identity chains to a human owner, not merely to a service. Consent-gated communication: a friend request is sent and accepted before agents may exchange anything beyond the request itself. Mutual key exchange: on acceptance each side receives and pins the other's keys, and all later traffic is mutually authenticated against exactly that pinned material. Deployment symmetry: the same pact works peer-to-peer between self-hosted agents, through gateways, through tunnels from behind NAT, and between tenants of a hosted platform — and any mix of these. Untrusted middle: gateways, tunnel edges, mailboxes, and relays carry ciphertext they can neither read nor forge. Untrusted directory: a name-to-key directory is verifiable (signed records, key transparency) rather than trusted. Offline delivery: messages to a sleeping agent are queued without weakening end-to-end security. Human-in-the-loop: "waiting for my human" is a first-class protocol state. Openness: PACT composes with the A2A and MCP ecosystems rather than replacing them.

### 1.3 Relationship to A2A, MCP, and prior work

PACT is defined as an extension profile of **A2A version 1.0** [A2A]: PACT payloads are A2A messages and tasks, discovery uses the A2A Agent Card, and long-running negotiations use the A2A task lifecycle. A2A supplies interoperable message/task semantics; PACT supplies what A2A deliberately leaves out — a pairing/consent handshake, key exchange and pinning, end-to-end encryption across intermediaries, and a typed vocabulary for scheduling and person-to-person messaging.

**MCP** [MCP] is each agent's *inward* tool interface (calendar, mail, contacts); it is inside the trust boundary and out of scope here except for the optional public façade in Appendix D.

The pairing ceremony adapts the out-of-band invitation pattern of DIDComm v2 [DIDCOMM] and the trust-domain federation model of SPIFFE [SPIFFE]; the human verification ceremony adapts Signal safety numbers and Matrix SAS; directory hardening adapts deployed key-transparency designs (WhatsApp AKD, Apple CKV, Signal AKV). The informative companion document surveys this landscape and records why each design was chosen.

### 1.4 How to read this document

Sections marked *(normative)* bind implementations; sections marked *(informative)* do not. Within normative sections, requirements use BCP 14 keywords (§2.1). JSON examples are informative renderings of the normative field tables unless a section states otherwise; test vectors (Appendix C) are normative. §3 defines which sections apply to each conformance class.

---

## 2. Terminology and conventions *(normative)*

### 2.1 Requirement keywords

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC2119] [RFC8174] when, and only when, they appear in all capitals, as shown here.

### 2.2 Terms

**Person / owner** — the human on whose behalf a personal agent acts.
**Personal Agent (PA)** — the assistant runtime acting for one owner: model, policies, memory, and the owner's tools reached via MCP.
**PACT endpoint** — a PA's internet-facing surface: an A2A server implementing this specification.
**Pact** — the mutual, consented relationship between two owners' agents, created by the pairing handshake (§6) and recorded on each side as a *pact record*.
**Pact record** — the local durable record of one pact: peer identity and pinned keys, scopes in each direction, transports, counters, and state.
**Initiator / responder** — the side that sent, respectively received, the `pact.pair.request` that created a pact. The roles are fixed for the life of the pact and name the two directions of traffic (`i2r`, `r2i`).
**Tier** — the exposure class of a skill or verb: *public* (reachable without a pact) or *paired* (requires an active pact and a covering scope).
**Transport profile** — one of the defined ways envelope bytes move: Profile D (direct), Profile G (gateway), Profile M (mailbox). See §7.
**Envelope** — the sealed (end-to-end encrypted, sender-authenticated) unit of transfer defined in §7.1.
**Owner key (OK)** — a person's long-term Ed25519 signing key; the root of their agent identity.
**Agent signing key (IK)**, **agent KEM key (EK)**, **transport key (TK)**, **gateway auth key (GAK)** — operational keys defined in §5.1.
**Delegation** — an owner-signed statement certifying an agent's operational keys (§5.2).
**Identity record** — the signed, published document mapping a handle to an owner key, delegations, prekey commitment, and endpoints (§11.2).
**Handle** — the human-readable name of an agent identity, `name@domain` (§11.1).
**Invitation** — an out-of-band artifact (link/QR) that authorizes one pairing request toward its issuer (§6.2).
**Gateway** — infrastructure that accepts envelopes over HTTPS and routes them toward a PACT endpoint it fronts (§7.3).
**Mailbox** — infrastructure that queues envelopes for later pickup by an offline endpoint (§7.4).
**Directory** — infrastructure that serves identity records for handles, optionally backed by a key-transparency log (§11).
**Directory Operator / Platform Operator** — the party operating a directory, or a hosted multi-tenant deployment, respectively.
**Managed / Sovereign custody** — hosting arrangements in which the owner key is held by a Platform Operator, respectively by the owner's own device (§15.4, Appendix F).
**Route (routeId)** — an opaque, recipient-minted identifier that addresses one pact's inbound queue at the recipient's infrastructure (§7.2).

### 2.3 Notational conventions

Byte strings shown as `b64u(x)` are base64url without padding [RFC4648]. `SHA-256` is [RFC6234]; `HKDF` is [RFC5869]; `Ed25519` is [RFC8032]; `X25519` is [RFC7748]; HPKE is [RFC9180]; JWS is [RFC7515]; HTTP Message Signatures is [RFC9421]; JCS canonical JSON is [RFC8785].

**Timestamps.** Fields in security artifacts (`ts`, `exp`, `nbf`, delegation validity, invitation expiry) are integer Unix seconds (UTC). Fields describing human schedules (windows, slots, events) are RFC 3339 [RFC3339] strings with UTC offset, accompanied by an IANA time-zone name where §9.2 requires one. No other timestamp forms are permitted.

**Identifiers.** `pactId`, `msgId`, `routeId`, `bookingRef`, and nonces are 128-bit values generated from a cryptographically secure random source (CSPRNG), encoded `b64u` (22 characters). Time-ordered UUIDs MUST NOT be used for these identifiers (they embed timestamps; see §16).

**JSON.** All JSON is UTF-8 [RFC8259]. Where this document requires a hash or signature "over the transmitted bytes", the exact byte sequence sent on the wire is the input; where it requires canonical form, JCS [RFC8785] is used. Every signed or hashed JSON artifact in this specification states which of the two applies.

**Unknown fields.** A receiver MUST ignore unknown members in any PACT-defined JSON object (envelope headers, verb bodies, records) unless a section states otherwise. This is the extensibility rule for minor revisions (§13).

---

## 3. Conformance *(normative)*

### 3.1 Conformance classes

**PACT Endpoint** — implements: identity (§5), pairing (§6), the envelope (§7.1), Profile G client and server behavior (§7.3), the A2A profile (§8), the `pact.*` verb set (§9.1), scopes (§10), resolution of identity records (§11.3), and errors (§12).
**Gateway** — implements §7.1 (outer handling only), §7.3, the control API (§7.5), and §12.
**Mailbox** — implements §7.1 (outer handling only), §7.4, the control API (§7.5), and §12.
**Directory** — implements §11.1–11.3 and §12. Key transparency (§11.4) is a labeled feature.

One deployment may implement several classes.

### 3.2 Feature matrix for PACT Endpoints

| Feature | Requirement level |
|---|---|
| Envelope sealing/opening, suite `PACT-HPKE-1` (§7.1) | REQUIRED |
| Profile G (client and server) (§7.3) | REQUIRED |
| Profile M client (pickup from a mailbox) (§7.4) | REQUIRED |
| Profile D (§7.2) | RECOMMENDED |
| Profile M server (operating a mailbox) | OPTIONAL |
| `pact.*` verbs (§9.1) | REQUIRED (except `pact.reverify`: RECOMMENDED) |
| `scheduling.*` verbs (§9.2) | RECOMMENDED (REQUIRED to claim the *Scheduling* feature) |
| `messaging.*` verbs (§9.3) | RECOMMENDED (REQUIRED to claim the *Messaging* feature) |
| `presence.*` verbs (§9.4) | OPTIONAL |
| SAS ceremony (§6.4) | REQUIRED (UI); commit-reveal fields REQUIRED (wire) |
| Key transparency verification (§11.4) | RECOMMENDED |
| On-the-record signing (§7.1.5) | OPTIONAL |
| Public MCP façade (Appendix D) | OPTIONAL |

### 3.3 Conformance claims and testing

An implementation claims conformance by class and feature list (e.g., "PACT Endpoint 1.0 with Scheduling, Profile D"). It MUST produce matching outputs for the applicable test vectors in Appendix C. A public conformance suite is a stated deliverable of the project (Appendix H, RB-4); until it exists, vector conformance plus interoperation with the reference implementation constitutes the claim basis.

---

## 4. Architecture overview *(informative)*

```
        Person A (owner)                                Person B (owner)
           │ approves                                       │ approves
   ┌───────┴────────┐                               ┌───────┴────────┐
   │ Personal Agent │                               │ Personal Agent │
   │  policies, LLM │                               │  policies, LLM │
   └───┬────────┬───┘                               └───┬────────┬───┘
       │ MCP    │ PACT endpoint               PACT      │ MCP    │
       ▼        │ (A2A + PACT ext)            endpoint  ▼        │
  [calendar]    │                                  [calendar]    │
  [tools…]      │                                  [tools…]      │
                │  Profile D: direct P2P (QUIC, keys = addresses)│
                ├────────────────────────────────────────────────┤
                │  Profile G: via gateway(s) — ciphertext only   │
                ├──────────► [Gateway]  ◄────────────────────────┤
                │  Profile M: mailbox store-and-forward          │
                └──────────► [Mailbox] ── pickup ───────────────►│

   Supporting planes (operated, federatable, or self-hosted):
   [Directory: handle → signed identity record]  [Key-transparency log]
   [Tunnel ingress for NATed self-hosted endpoints]
```

The unit of security is the envelope, not the connection: every application message is sealed end-to-end between the two paired agents, so gateways, tunnels, and mailboxes are interchangeable ciphertext movers. A pact between a platform-hosted agent and a self-hosted agent behind a home NAT is symmetric — neither side needs to know how the other is deployed. Deployment recipes (platform-hosted multi-tenant, self-hosted behind Cloudflare Tunnel or Pangolin-style ingress, hybrid) are collected in Appendix F.
---

## 5. Identity *(normative)*

### 5.1 Keys

| Key | Algorithm | Held by | Lifetime | Purpose |
|---|---|---|---|---|
| **Owner key `OK`** | Ed25519 | The person (device keystore / hardware token; or platform custody in Managed arrangements — see §15.4) | Years; replaced only by continuity rotation (§6.5.2) | Root of identity. Signs delegations, identity records, pairing messages, scope changes, suspensions, revocations, identity migrations. |
| **Agent signing key `IK`** | Ed25519 | PA runtime | Delegation-bound: default 7 days, maximum 30 days, renewed automatically | Signs control-verb payloads that require agent (not owner) signature, and on-the-record payloads (§7.1.5). |
| **Agent KEM key `EK`** | X25519 | PA runtime | Delegation-bound: default 7 days, maximum 30 days | HPKE sender/recipient key for envelope sealing (§7.1). |
| **Transport key `TK`** | Ed25519 | PA runtime | Long-lived (months–years); rotated only deliberately via `pact.transport.update` (§9.1) | Channel identity for Profile D: the Iroh endpoint key or raw-public-key TLS identity. Deliberately decoupled from `IK`/`EK` rotation so a peer's dial address does not change when routine keys roll. |
| **Gateway auth key `GAK`** | Ed25519 | PA runtime, **one per pact per direction** | Pact-lifetime; rotatable via `pact.key.update` | Signs RFC 9421 requests toward the *peer's* gateway/mailbox (§7.3.2, §7.4.2). Per-pact keys prevent a relay from linking one sender's traffic across different peers (§16). |
| **Prekeys** | X25519 | Private halves at the PA; public halves published per §5.4 | One-time prekeys: single use. Signed prekey: maximum 30 days | Allow sealing a first envelope to a peer that is offline (§6.3.1, §7.1.4). |

Key-usage domain separation: `OK` and `IK` signatures always carry a distinguishing JWS `typ` (this document defines `pact-delegation+jws`, `pact-pair+jws`, `pact-record+jws`, `pact-otr+jws`); `TK` is used only inside TLS/QUIC handshakes (which impose their own signature context); `GAK` is used only in RFC 9421 signature bases with the `tag` parameter set to `pact-infra` (§7.3.2). A key generated for one row of the table MUST NOT be used in another row's role.

### 5.2 Delegation

A delegation is a JWS in compact serialization, signed by `OK`, protected header `{"alg":"EdDSA","typ":"pact-delegation+jws"}`, whose payload is the following object (signature is over the transmitted compact-serialization bytes):

| Field | Type | Req | Description |
|---|---|---|---|
| `did` | string | ✔ | The owner's DID this delegation belongs to. Verifiers MUST compare this against the pact's pinned identity, not trust it in isolation. |
| `kid` | string | ✔ | Identifier of this delegation/key set; referenced by envelope `skid`/`kid` and record entries. |
| `ik` | string | ✔ | `b64u` Ed25519 public key (agent signing). |
| `ek` | string | ✔ | `b64u` X25519 public key (agent KEM). |
| `tk` | string | ✖ | `b64u` Ed25519 public key (transport), present when the deployment uses Profile D. |
| `caps` | array of string | ✔ | Capability names from the delegation-capability registry (§14.4): what this agent may do *on behalf of its owner* (e.g., `pair`, `scheduling`, `messaging`). Distinct from per-pact scopes (§10); a delegation is identity attestation, not a peer-facing capability token. |
| `nbf`, `exp` | int | ✔ | Validity window, Unix seconds. `exp − nbf` MUST NOT exceed 30 days (SHOULD be ≤ 7 days). |

Verification rule (applies to every signed artifact and every envelope): signature by `IK` (or seal by `EK`) → locate an unexpired delegation carrying that key → the delegation's `OK` signature verifies → that `OK` equals the pact's pinned owner key. Delegation validity is evaluated at the message's authenticated `ts` (§7.1.3), not at pickup time, provided pickup occurs within the mailbox retention bound (§7.4.4).

Compromise containment: a stolen `IK`/`EK` is bounded by delegation expiry; the owner additionally revokes with `pact.key.revoke` (§9.1) and by publishing an identity record that omits the delegation. Verifiers MUST NOT accept a delegation on the basis of a cached identity record older than the freshness bound in §11.3.3.

### 5.3 DID representation

An owner's agent identity is expressed as a DID [DID-CORE]. Conforming endpoints MUST support resolving and comparing the following methods:

- **`did:web`** [DID-WEB] for identities anchored to a domain. Resolution follows the did:web method exactly: `did:web:example.com` resolves to `https://example.com/.well-known/did.json`; the path form `did:web:example.com:u:alina` resolves to `https://example.com/u/alina/did.json`. (Note the path form does **not** use `/.well-known/`.)
- **`did:key`** [DID-KEY] for infrastructure-free identities: the DID encodes `OK` directly and is self-certifying. Reachability information then travels in invitations and pact records rather than a published document.

Support for pairwise **`did:peer`** (privacy: unlinkable identities per relationship) and **`did:wba`** is OPTIONAL and interop-negotiated via the identity record's `didMethods` field.

The **identity record** (§11.2) is the authoritative PACT description of an identity. Where a DID document exists it MUST be generated from the same source of truth as the identity record and carry the same `updated` value; on any disagreement the identity record governs PACT processing.

### 5.4 Prekey publication

An identity publishes a **prekey bundle**: one *signed prekey* (X25519 public key + Ed25519 signature by `OK`, `typ` context string `"PACT-1.0 spk"` prepended to the signed bytes) and zero or more *one-time prekeys* (each individually `OK`-signed the same way). The identity record carries `prekeys.hash` = SHA-256 over the JCS form of the current bundle *manifest* (the signed prekey plus the set of one-time prekey ids), so a key-transparency-verified identity record commits to the bundle a fetcher receives; a bundle that fails this check MUST be rejected. Servers hosting bundles MUST consume one-time prekeys atomically (each returned at most once), MUST fall back to the signed prekey when the pool is empty, SHOULD rate-limit unauthenticated fetches, and MUST retain the private halves of consumed one-time prekeys for the retention bound in §14.6 so that sender retries remain decryptable. The PA replenishes one-time prekeys below a locally chosen threshold and republishes `prekeys.hash` on every manifest change.

### 5.5 Agent Card binding

The public A2A Agent Card served at `/.well-known/agent-card.json` MUST be an A2A **signed Agent Card** whose signing key is verifiable through the identity record (the record's `agentCardKey` field), and MUST declare the PACT extension:

```json
{
  "name": "Alina's assistant",
  "url": "https://agents.pact.example/u/alina/a2a",
  "capabilities": { "extensions": [ {
      "uri": "https://pactprotocol.org/ext/v1",
      "required": false,
      "params": {
        "did": "did:web:agents.pact.example:u:alina",
        "identityRecord": "https://agents.pact.example/.well-known/pact/alina",
        "pairing": "https://agents.pact.example/u/alina/pact/pair",
        "versions": [1],
        "tiers": { "public": ["pact.pair.request"] }
      } } ] }
}
```

The extension URI `https://pactprotocol.org/ext/v1` is provisional (RB-1). On the public card the extension is declared `required: false` (vanilla A2A clients may still use public-tier skills). The A2A *extended Agent Card*, served only to authenticated paired peers, MUST declare it `required: true` and MAY reveal paired-tier skills and transport detail. PACT's message security is not an HTTP-layer scheme; implementations MUST NOT represent the envelope as a `securitySchemes` entry of type `mutualTLS` or any other transport-layer type.

---

## 6. Pairing *(normative)*

Pairing turns two strangers' agents into mutually keyed peers. It is deliberately human-gated: **agents transport the request; people approve it.** An endpoint MUST NOT establish an active pact without an explicit approval action by its owner for that specific request (standing policy MAY auto-*reject*; it MUST NOT auto-accept).

### 6.1 Pact states and lifecycle

```
                    ┌────────────────────────────────────────────┐
 none ──request──► pending-out            pending-in ◄──request──┤ (peer side)
                    │   ▲                     │ approve           │
                    │   └──error/expiry───────┤                   │
                    │                     accept-sent             │
                    │◄──accept────────────────┘                   │
                 finish-sent ──finish──► active ◄── ping-ok ──────┘
                                          │  ▲
                              suspend     │  │ resume (by suspender)
                                          ▼  │
                                       suspended ──revoke──► revoked (terminal)
                                        active  ──revoke──► revoked (terminal)
```

State rules:

1. **Relationship key.** Each endpoint keys pact state on the unordered pair of owner DIDs. At most one pact per relationship key may be in a non-terminal state at a time.
2. **Simultaneous open (glare).** If an endpoint holding `pending-out` toward a peer receives that peer's `pact.pair.request`, the request whose sender's DID is lexicographically lower (byte-wise comparison of the UTF-8 DID strings) survives; the other side's endpoint MUST answer the losing request with error `PACT_ALREADY_PENDING`, referencing the surviving `pactId`, and both endpoints continue the surviving handshake only.
3. **Duplicate requests.** A `pact.pair.request` naming a relationship that already has an `active` pact MUST be answered with `PACT_EXISTS` (scope changes use `pact.scopes.update`, not re-pairing). A `pactId` equal to any pactId previously seen for a *different* relationship MUST be rejected as `MALFORMED`.
4. **Timeouts.** `pending-out`/`pending-in` end at the request's `exp` (default 7 days from issue; both sides then discard). An accept received after the requester discarded state is answered `REQUEST_EXPIRED`. `accept-sent` endpoints retransmit the accept envelope per §7.6 and revert to `pending-in` (notifying their owner) if no `pact.pair.finish` arrives within 48 hours.
5. **Activation.** A pact becomes `active` on each side only after that side has both processed the peer's final handshake message *and* completed a successful `pact.ping` round trip (§6.3.5). Until then only `pact.*` handshake verbs are valid on the pact.
6. **Withdrawal and decline.** The initiator may send `pact.pair.cancel` while `pending-out`; the responder declines with `pact.pair.reject` (optional human note). Both end the handshake; state returns to `none`.
7. **Suspension.** Either side may suspend (`pact.suspend`). Suspension is per-suspender: a pact is usable only when neither side holds it suspended, and only the side that suspended may `pact.resume` its own suspension. Inbound application envelopes on a suspended pact are answered `PACT_SUSPENDED` (retryable); `pact.*` control verbs remain valid. In-flight tasks freeze; scheduling holds are released. Continuity-failure and account-recovery events force suspension pending `pact.reverify` (§6.5.2, §15.5).
8. **Revocation.** `pact.revoke` (owner-signed) ends the pact permanently (§6.6). `revoked` is terminal for that `pactId`. Re-pairing after revocation is permitted and runs a fresh full handshake with a new `pactId`; no state, keys, or counters carry over.
9. **In-flight tasks on revoke** transition to A2A state `canceled` with reason `pact-revoked`.

### 6.2 Invitations

An invitation authorizes exactly one `pact.pair.request` toward its issuer and carries the issuer's key material so the requester can verify and seal to the issuer from the first message.

**Invite URI.** ABNF (parameters MUST appear in exactly this order; values are percent-encoded per RFC 3986):

```
invite-uri  = "pact:invite?" "v=1"
              "&did=" did
              "&ok="  b64u32          ; issuer owner public key
              "&ek="  b64u32          ; invitation KEM public key (X25519)
              "&hint=" 1*hint         ; comma-separated transport hints
              "&sk="  b64u16          ; single-use invitation secret (128-bit CSPRNG)
              "&exp=" 1*10DIGIT       ; Unix seconds
              "&sig=" b64u64          ; Ed25519 by OK over sign-input
hint        = ("iroh:" nodeid [";" relay-url]) / https-URI
sign-input  = the exact ASCII query string from "v=1" through "&exp=…" inclusive
              (i.e., everything between "?" and "&sig="), UTF-8 bytes
```

An equivalent `https://` carrier link MAY wrap the same query string (fragment part) for clients without scheme handlers; the `pact:` form is authoritative. Issuers MAY invalidate an outstanding `sk` at any time; a request using an invalidated, expired, or already-consumed `sk` is rejected `INVITATION_INVALID`. Consumption of `sk` MUST be atomic and bound to the single resulting `pactId` (two racing requests: at most one proceeds). `exp` SHOULD be ≤ 14 days from issue.

The invitation is handed over any existing human channel (chat, email, printed QR, in person). Because it travels outside PACT, its confidentiality equals that channel's; §15.2 describes the resulting trust properties.

### 6.3 Handshake

All pairing messages are carried as A2A messages containing a single `pact.pair.*` data part (§8.3), and are **sealed** (§7.1) — including the initial request:

- *Invitation path:* the request is sealed to the invitation's `ek`.
- *Directory path:* the requester resolves the responder's identity record (§11.3), verifies it (including key transparency where available), fetches a prekey, and seals the request to it (§7.1.4).

Only the outer routing fields of §7.1 are visible to infrastructure; `displayName`, `humanNote`, and all key material are inside the ciphertext. Pairing payloads are additionally **owner-signed**: the data part's `body` is a JWS compact serialization (`typ: "pact-pair+jws"`) signed by the sender's `OK`; hashes over pairing messages are computed over these exact JWS bytes.

#### 6.3.1 `pact.pair.request` (initiator → responder)

JWS payload fields:

| Field | Type | Req | Description |
|---|---|---|---|
| `type` | string | ✔ | `"pact.pair.request"` |
| `pactId` | string | ✔ | 128-bit `b64u`, minted by the initiator (subject to §6.1 rules 2–3) |
| `from` / `to` | string | ✔ | Initiator / responder DIDs |
| `identityRecord` | object | ✔ | The initiator's complete signed identity record (§11.2) |
| `routes` | object | ✔ | Initiator's inbound provisioning for this pact: `{ "routeId", "gateway", "mailbox", "gak" }` — where the responder should send envelopes and which GAK the responder will use toward the initiator's infrastructure is *its own* choice; `gak` here is the **initiator's** per-pact GAK public key that the initiator will use toward the *responder's* infrastructure |
| `transports` | array | ✔ | Ordered transport descriptors (§7.7) for reaching the initiator |
| `requestedScopes` | array | ✔ | Scopes the initiator asks to exercise against the responder (§10.2) |
| `offeredScopes` | array | ✔ | Scopes the initiator grants the responder in return |
| `sasCommit` | string | ✔ | `b64u(SHA-256(nI))` where `nI` is the initiator's 128-bit SAS nonce (revealed in `finish`) |
| `suiteFloor` | string | ✔ | Minimum envelope suite the initiator will ever accept on this pact (§7.1.6) |
| `invitationSk` | string | ✖ | The `sk` when on the invitation path |
| `displayName` | string | ✖ | ≤ 120 bytes; untrusted, §17 rules apply |
| `humanNote` | string | ✖ | ≤ 4 KiB; untrusted free text shown to the responder's human |
| `iat`, `exp` | int | ✔ | Issue and expiry (≤ 7 days apart) |

Responder processing: unseal → verify the JWS against the *included* identity record → cross-check per §6.3.6 → apply §6.1 rules → surface to the human with handle, verification status, scopes, and untrusted-content framing (§17). The A2A task enters `input-required` until the human acts.

#### 6.3.2 `pact.pair.accept` (responder → initiator; sealed to the request's `skid` keys)

| Field | Type | Req | Description |
|---|---|---|---|
| `type` | string | ✔ | `"pact.pair.accept"` |
| `pactId` | string | ✔ | Echo |
| `reqHash` | string | ✔ | `b64u(SHA-256(request JWS bytes))` — binds this accept to exactly that request |
| `identityRecord` | object | ✔ | Responder's signed identity record |
| `routes` | object | ✔ | Responder's inbound provisioning (as in 6.3.1, roles swapped) |
| `transports` | array | ✔ | Ordered descriptors for reaching the responder |
| `grantedScopes` | array | ✔ | ⊆ `requestedScopes`: what the initiator may exercise |
| `acceptedScopes` | array | ✔ | ⊆ `offeredScopes`: what the responder will exercise |
| `nR` | string | ✔ | Responder's 128-bit SAS nonce, revealed plain (the initiator is still committed via `sasCommit`) |
| `suiteFloor` | string | ✔ | Responder's minimum suite; the pact floor is the higher of the two |
| `iat`, `exp` | int | ✔ | |

#### 6.3.3 `pact.pair.finish` (initiator → responder)

| Field | Type | Req |
|---|---|---|
| `type` = `"pact.pair.finish"`, `pactId` | | ✔ |
| `acceptHash` — `b64u(SHA-256(accept JWS bytes))` | string | ✔ |
| `nI` — reveals the nonce committed in `sasCommit`; responder MUST verify `SHA-256(nI)` equals the commitment and abort (`BAD_SIGNATURE`) otherwise | string | ✔ |
| `iat` | int | ✔ |

#### 6.3.4 Pact record contents

On completing the handshake each side stores, at minimum: `pactId`; role (initiator/responder); peer DID and handle; **pinned peer `OK`**; peer's current delegations (`kid` → `ik`/`ek`/`tk`); peer transports and their update counter; own and peer route provisioning (routeIds, GAKs); scopes in each direction; suite floor; SAS transcript values; send/receive `seq` state; pact state.

#### 6.3.5 Channel confirmation

Each side sends `pact.ping` and answers with `pact.ping` (`echo` field) over the pact. Success in both directions completes activation (§6.1 rule 5). `pact.ping` MAY be sent at any later time as a liveness/transport probe.

#### 6.3.6 Directory cross-check

When processing a `pair.request`/`accept`, if a directory record for the peer's claimed handle/DID is resolvable: the record's `ownerKey` MUST equal the included identity record's; on mismatch the endpoint MUST reject (`BAD_SIGNATURE`) — this is the anti-MITM anchor. Differences in delegations, transports, or prekeys are tolerated (the in-band record may be fresher). If the directory is unreachable or the identity is did:key/unlisted, processing continues but the pact MUST be marked *unverified* and §6.4's SAS requirement applies.

### 6.4 Human verification (SAS)

The SAS ceremony gives the two humans a short string to compare over any existing channel, detecting key substitution that the directory path could not.

**Derivation** (test vectors: C.2):

```
ikm  = concat(sort_bytewise(OK_A_raw32, OK_B_raw32))       ; smaller key first
salt = pactId (16 raw bytes)
info = "PACT-1.0 sas" || nI || nR
okm  = HKDF-SHA256(ikm, salt, info, L = 9 bytes)           ; 72 bits
words   = first 66 bits → six 11-bit indexes into the BIP-39 English wordlist (0-based)
numeric = first 6 bytes as big-endian integer mod 10^12, zero-padded to 12 digits
          (grouped 4-4-4 for display; modulo bias < 2^-27, accepted)
```

Because `nI` is committed before `nR` is revealed (§6.3.1–6.3.3), an active MITM gets exactly one guess per pairing (success 2⁻⁶⁶ for words); offline grinding is not possible. Both values MUST be computed and displayable; the numeric form is the accessibility and cross-locale fallback (§18). Comparison failure MUST abort the pact (revoke) and SHOULD be reportable (§15.7).

**When required:** after an invitation-path pairing, the ceremony is REQUIRED for the *inviter's* direction of trust (the invitation authenticated inviter→invitee only; the invitee's keys arrived unanchored — §15.2) unless the invitee's identity was independently verified via key transparency. After a directory-plus-KT-verified pairing it is RECOMMENDED and may be deferred. After any continuity failure, account recovery, or KT anomaly it is REQUIRED (`pact.reverify` carries fresh commit/reveal nonces and re-runs this ceremony over the *current* owner keys).

### 6.5 Key rotation

**6.5.1 Operational keys.** New delegations (fresh `kid`/`ik`/`ek`, optionally `tk`) are announced to every active pact via `pact.key.update` and published in the identity record. Peers MUST accept any key with a valid delegation chaining to the pinned `OK`, subject to the freshness bound (§11.3.3). Recipients MUST retain superseded `EK` private keys, and accept envelopes addressed to them, for ≥ 35 days after supersession (covering the 30-day mailbox retention bound); an envelope for a key older than that is answered `UNKNOWN_KID`, instructing the sender to refresh and re-seal. Senders MUST re-seal any still-queued envelopes they control after processing a peer's `pact.key.update`. `GAK` rotation rides the same verb.

**6.5.2 Owner key.** A replacement `OK'` MUST carry a continuity statement signed by the predecessor: the JCS bytes of `{"typ":"pact-okc","did":…,"handle":…,"prev":b64u(OK),"next":b64u(OK'),"epoch":n,"ts":…}` signed by `OK`. Continuity chains MUST NOT exceed 16 links; verifiers walk from their pinned key. Where the identity is directory-listed, the rotation MUST also appear in the (KT-logged) identity record, and peers MUST require *both* a valid continuity chain *and* KT consistency when KT is available — a valid chain with a KT fork is treated as compromise (suspend + `pact.reverify`). A rotation *without* continuity (lost key) demotes every pact to `suspended` pending SAS re-verification; this is deliberate — it is the only honest outcome after total key loss. Account-recovery flows are equivalent to lost-key rotation (§15.5).

### 6.6 Revocation (unfriending)

`pact.revoke` (owner-signed, sealed) moves the pact to `revoked` on both sides. The revoker MUST also: de-provision the pact's route at its own gateway/mailbox (§7.5) so the peer's infrastructure access ends even if the notice is never processed; delete peer transport hints; release scheduling holds. Because every inbound message is checked against the local pact record (never against a bearer artifact), revocation is effective locally the moment it is recorded. For did:key identities with no published record, `pact.key.revoke`/`pact.revoke` notices are the *only* revocation channel: they MUST be queued via Profile M to every active pact until acknowledged, and such deployments SHOULD use the short end of the delegation-lifetime range (§14.6).
---

## 7. Envelope and transport profiles *(normative)*

One sealed envelope; three ways to move it. The envelope is identical across profiles; profiles differ only in how bytes travel and how infrastructure authenticates the depositor.

### 7.1 The sealed envelope

#### 7.1.1 Structure

Media type `application/pact-envelope+json` (§14.7):

```json
{
  "route": "<b64u 128-bit routeId>",
  "protected": "<b64u of the protected-header JSON bytes>",
  "enc": "<b64u HPKE encapsulated key>",
  "ct": "<b64u ciphertext>"
}
```

Protected header fields (the decoded bytes are the HPKE AAD; all fields are REQUIRED):

| Field | Type | Description |
|---|---|---|
| `v` | int | Wire version, `1` |
| `suite` | string | Envelope suite id (§7.1.6) |
| `pactId` | string | The pact this envelope belongs to |
| `from`, `to` | string | Sender and recipient DIDs |
| `dir` | string | `"i2r"` or `"r2i"` (§2.2) |
| `seq` | int | Per-pact, per-direction monotonic counter (§7.1.3) |
| `msgId` | string | 128-bit `b64u`, unique per message; **reused unchanged on every retry across every profile** |
| `ts`, `exp` | int | Seal time and expiry, Unix seconds; `exp − ts` ≤ 604 800 (7 days) |
| `cty` | string | Content type of the plaintext (§14.7): `application/pact-msg+json` (A2A request) or `application/pact-rsp+json` (A2A response/status) |
| `kid` | string | Recipient key id: a delegation `kid`, a one-time prekey id (`opk-…`), the signed-prekey id (`spk-…`), or an invitation (`inv-…`) |
| `skid` | string | Sender's delegation `kid` (identifies the sender EK used for HPKE Auth) |

The `route` value is the only field infrastructure needs; everything security-relevant is in `protected`, which is authenticated by the AEAD. Receivers MUST base every decision on protected-header values, never on transport metadata.

#### 7.1.2 Sealing and opening

Sealing uses **HPKE Auth mode** [RFC9180]:

```
info = "PACT-1.0 env" || b64u(pactId)                 ; ASCII concatenation
enc, ctx = SetupAuthS(pkR = recipient EK, skS = sender EK, info)
ct       = ctx.Seal(aad = protected-header bytes, pt = payload bytes)
```

Auth mode mixes the sender's static `EK` into the key schedule: the recipient — and only the recipient — is convinced the envelope came from the holder of the sender's `EK`, while neither party can prove authorship to a third party (deniable authentication; see §15.3 for the KCI caveat and §7.1.5 for the non-repudiable option). There is no per-envelope signature.

Opening and validation MUST proceed in this order:

1. Look up `route` (infrastructure) / deliver to endpoint.
2. Decode `protected`; check `v` supported, `suite` ≥ the pact's floor (§7.1.6) — unknown or below-floor suite ⇒ `UNSUPPORTED_VERSION`.
3. Resolve `kid` to a held private key (including retained superseded keys and prekeys) ⇒ else `UNKNOWN_KID`.
4. Resolve `pactId` to a pact record; require `from` = peer DID, `to` = own DID, `dir` consistent with the peer's role ⇒ else `UNKNOWN_PACT` (this check also defeats reflection and cross-pact forwarding). For `pact.pair.*` bootstrap envelopes no pact exists yet; they are accepted only on pairing routes (§7.5.2).
5. Resolve `skid` to a currently-valid delegation of the pinned peer `OK` (per §5.2) and its `ek`; open HPKE with that sender key ⇒ AEAD failure is `DECRYPT_FAILED`; delegation failure is `DELEGATION_EXPIRED`.
6. Enforce replay rules on (`pactId`, `dir`, `seq`) and `msgId` (§7.1.3) ⇒ `REPLAY`.
7. Enforce time: `|now − ts| ≤ 300 s`, OR the envelope arrived via Profile M within retention and `ts` is not in the future by more than 300 s; require `now < exp`. Expired application envelopes are discarded (optionally reported via `pact.error`); expired handshake artifacts are answered `REQUEST_EXPIRED` (§12).
8. Parse the plaintext per `cty` ⇒ `UNSUPPORTED_MEDIA` / `MALFORMED`; then apply tier, scope (§10), and verb schema checks.

Errors detected at steps 4–8 are reported with `pact.error` (§9.1.9) where a pact exists, else dropped with the transport-level mapping of §12.

#### 7.1.3 Sequencing, replay, and deduplication

`seq` is per-pact, per-direction, starts at 1, increments by 1 per *distinct* message, MUST be durably persisted by the sender, and MUST NOT reset for the life of the pact — across restarts, key rotations, and transport changes. Exactly one agent key set per direction may be actively sending at a time (multi-runtime deployments MUST serialize through one sender state; relaxation is future work, §13.3). Receivers maintain, per direction: a high-water mark and a sliding window of `W = 1024` below it; they MUST accept gaps and out-of-order arrivals within the window, MUST reject duplicates (same `seq` seen) and anything below the window, and MUST treat a repeated `msgId` anywhere within the retention bound as the *same* message (idempotent re-delivery, acknowledged but not re-processed — the cross-profile dedupe rule, §7.6). Replay state MUST be shared across all profiles.

#### 7.1.4 First contact while offline (prekeys)

The first envelope(s) of a pairing may be sealed before the peer has any delegation of the sender: `kid` names the responder's one-time or signed prekey (§5.4) or the invitation key; `skid` names the *sender's* delegation, whose `ek` provides the Auth-mode sender key and which the recipient verifies against the identity record *inside* the request (full verification completes at step 5 using the included record, then §6.3.6). Senders MUST prefer one-time prekeys, MUST fall back to the signed prekey on exhaustion, and MUST re-use the same prekey-sealed bytes on retry (never re-fetch a fresh one-time key for a retry of the same `msgId`).

#### 7.1.5 On-the-record mode (optional)

Deniable authentication is the default and is correct for personal messaging. Where a verb's semantics warrant a portable proof (e.g., a booking confirmation both sides may need to show later), a sender MAY include, inside the payload, `otr: <JWS>` — compact serialization by its `IK`, `typ: "pact-otr+jws"`, payload = `{ "msgId", "pactId", "bodyHash": b64u(SHA-256(JCS(verb body))) }`. Receivers supporting the feature verify and store it; the envelope remains valid without it. A pact MAY negotiate (via scope-style agreement, §10.4) that specific verbs — typically `scheduling.confirm` — are always on-the-record. This is also the evidentiary mechanism for abuse reporting (§15.7).

#### 7.1.6 Suites and downgrade protection

| Suite id | KEM | KDF | AEAD | Status |
|---|---|---|---|---|
| `PACT-HPKE-1` | DHKEM(X25519, HKDF-SHA256) | HKDF-SHA256 | ChaCha20-Poly1305 | REQUIRED (MTI) |
| `PACT-HPKE-2` | X25519 + ML-KEM-768 hybrid | HKDF-SHA256 | ChaCha20-Poly1305 | RESERVED for 1.1 (PQ) |

The suite id is inside the AAD (authenticated) and each side declared a `suiteFloor` in the owner-signed pairing messages; receivers MUST reject envelopes below the pact floor. When `PACT-HPKE-2` ships, endpoints raise their floor via `pact.key.update`'s `suiteFloor` field; an attacker cannot strip a floor that was fixed in the signed pairing transcript. Forward secrecy in 1.0 is bounded by `EK` lifetime (≤ 30 days, default 7); see §15.3 for the honest statement and the 1.1 ratchet plan.

### 7.2 Profile D — direct peer-to-peer

Reference transport: an **Iroh** endpoint whose node key is the pact peer's pinned `TK`. Dialing a friend is dialing that key; the QUIC handshake yields mutual channel authentication against exactly the pinned material, with NAT hole-punching and automatic fallback through relays that carry only ciphertext. Binding: ALPN `pact/1`; each envelope is sent on its own bidirectional QUIC stream as a 4-byte big-endian length prefix followed by the envelope bytes; a response envelope (if any is immediately available) returns on the same stream, else the stream closes and the response travels later as a normal reverse envelope. Envelopes remain fully sealed on Profile D (the channel is defense-in-depth, and captured relay traffic stays useless). Alternative binding: raw-public-key TLS 1.3 [RFC7250] (or pinned self-signed certificate whose SPKI equals `TK`) carrying the Profile G HTTP contract — permitted only where the TLS session terminates at the peer's endpoint (direct or SNI/TCP-passthrough tunnel), never behind a TLS-terminating edge. A channel whose authenticated key does not equal the pinned `TK` MUST be aborted before any application data.

### 7.3 Profile G — gateway

#### 7.3.1 HTTP contract

```
POST /pact/v1/inbox/{routeId}
Content-Type: application/pact-envelope+json
```

| Status | Meaning | Sender behavior |
|---|---|---|
| `200` | Delivered to a live endpoint; body MAY contain a response envelope | Done |
| `202` | Accepted for relay/queue (not yet delivered) | Done; response arrives as a reverse envelope |
| `400` | Malformed envelope | Fatal for this message |
| `401` | RFC 9421 verification failed | Refresh GAK/clock; fatal after retry |
| `404` | Unknown `routeId` | Refresh transports (§7.7); try next transport |
| `409` | Duplicate `msgId` already accepted | Treat as success |
| `413` | Exceeds size limits (§14.6) | Fatal |
| `429` + `Retry-After` | Rate/quota | Retry after delay |
| `503` | Backpressure/unavailable | Retry with backoff |

Gateways MUST dedupe accepted deposits on `msgId` for at least the envelope's `exp`, making POST idempotent. A gateway routes on `routeId` alone; it MUST NOT require access to any protected field.

#### 7.3.2 Depositor authentication

Every deposit MUST carry an HTTP Message Signature [RFC9421] by the sender's per-pact `GAK` covering at minimum `@method`, `@authority`, `@path`, `content-digest` [RFC9530] (SHA-256 of the exact body bytes), `created`, `expires`, `nonce`, with signature parameters including `keyid` = the GAK id provisioned at pairing and `tag="pact-infra"`. Verifiers enforce `expires − created ≤ 300 s`, clock skew ≤ 300 s, and single-use nonces within the window. This authenticates the depositor *to infrastructure* for admission control and quotas without revealing content and without linking the sender across pacts (per-pact keys, §16.2). The identical scheme authenticates mailbox pickup calls, with the recipient's GAK.

### 7.4 Profile M — mailbox

#### 7.4.1 Model

A mailbox queues envelopes per `routeId` for a recipient that is offline. Semantics follow the DIDComm Message Pickup pattern, concretized here.

#### 7.4.2 HTTP contract (all calls RFC 9421-authenticated per §7.3.2)

```
GET  /pact/v1/mbx/{routeId}                    → 200 { "count": n, "bytes": m, "oldest": ts }
POST /pact/v1/mbx/{routeId}/delivery {"limit":k} → 200 { "envelopes": [ … ] }   ; k ≤ 100
POST /pact/v1/mbx/{routeId}/ack {"msgIds":[…]}   → 200                          ; deletes
POST /pact/v1/mbx/{routeId}/push {"kind":"webhook"|"apns"|"fcm"|"ntfy", "target":…} → 204
GET  /pact/v1/mbx/{routeId}/live               → WebSocket upgrade; server pushes
                                                  envelope frames; client sends ack frames
```

Delivered-but-unacked envelopes are redelivered on later calls. Push notifications MUST be content-free ("you have mail"). Deposit into a mailbox is the Profile G contract (§7.3.1) served by the mailbox host.

#### 7.4.3 Cross-profile acknowledgement

A recipient MUST ack (thereby delete) any mailbox copy whose `msgId` it has already processed via another profile.

#### 7.4.4 Retention and quotas

A mailbox MUST enforce retention = `min(envelope exp, 30 days)` and the per-pact quotas of §14.6, and SHOULD advertise its limits in the status response. Expired envelopes are deleted, not delivered.

### 7.5 Infrastructure control API

The interface by which an endpoint provisions *its own* gateway/mailbox (both roles MAY be one service). All calls RFC 9421-signed by the endpoint's operator credential (deployment-defined) — this API is within one party's trust domain, but its shape is normative so endpoints and infrastructure from different vendors compose.

```
PUT    /pact/v1/routes/{routeId}
       { "senderGak": "<b64u peer GAK>", "mode": "active"|"pairing"|"suspended",
         "quota": {…override…}, "expiresAt": ts? }
PATCH  /pact/v1/routes/{routeId}    ; rotate senderGak, change mode
DELETE /pact/v1/routes/{routeId}    ; revocation: peer deposits now answered 404
```

#### 7.5.1 Lifecycle coupling

On sending a `pair.request` the initiator provisions the offered `routeId` in `pairing` mode (accepts only `pact.pair.*`-sized envelopes from the expected responder's GAK, bounded count, TTL = request `exp`) — this is how a sealed `accept` reaches an initiator that has gone offline. On activation both sides move their route to `active` with the peer's GAK. On revocation/suspension the owner side deletes or suspends the route (§6.6, §6.1 rule 7).

#### 7.5.2 Pairing routes for listed identities

An identity that accepts directory-path contact publishes a *pairing route* in its identity record (§11.2 `pairing`): a route in `pairing` mode with relaxed depositor authentication (no pre-shared GAK exists yet). Operators MUST bound these by rate, count, and size, and SHOULD apply anti-abuse admission (e.g., proof-of-work stamps or anonymous-token schemes; §15.6).

### 7.6 Delivery, retries, and responses

PACT is asynchronous at the protocol level: every response, status update, or error travels as a new sealed envelope in the reverse direction (`cty: application/pact-rsp+json`), correlated by the JSON-RPC `id`, which MUST be unique per (pact, direction) within the replay window; a synchronous body on Profile D/G `200` is an optimization, not a guarantee. Senders retry undelivered envelopes with exponential backoff (initial 30 s, factor 2, cap 1 h, jitter; give up at `exp`), reusing `msgId` and the identical sealed bytes; after exhausting one transport they fall down the preference list (§7.7) and finally queue to the peer's mailbox. Retransmission of the same bytes is what makes the dedupe rules of §7.1.3/§7.3.1 sufficient for at-least-once delivery with exactly-once processing.

### 7.7 Transport descriptors, selection, and updates

A transport descriptor is one of:

```json
{ "profile": "D", "iroh": "<nodeid>", "relays": ["https://relay.pact.example"] }
{ "profile": "D", "tls": "https://a.pact.example/pact", "tk": "<b64u>" }
{ "profile": "G", "url": "https://gw.pact.example", "routeId": "<b64u>" }
{ "profile": "M", "url": "https://mbx.pact.example", "routeId": "<b64u>" }
```

Ordered lists are exchanged at pairing and updated any time with `pact.transport.update` (§9.1.5), which carries a per-sender monotonic `rev`; receivers apply the highest `rev` and ignore stale updates. The pact record's transport list is authoritative between updates; the peer's identity record is bootstrap/fallback, consulted only when every pact-record transport fails. Senders MUST attempt descriptors in order, SHOULD prefer Profile D when present, and MUST treat forced fallback (D persistently failing while G succeeds) as a loggable signal (§15.6, downgrade forcing).

---

## 8. Message layer: A2A profile *(normative)*

### 8.1 Conformance to A2A

Envelope plaintext (`cty: application/pact-msg+json` / `application/pact-rsp+json`) is an A2A v1.0 JSON-RPC request, respectively response/stream event. Endpoints MUST implement `message/send`, `tasks/get`, `tasks/cancel`, and `tasks/list`; A2A streaming and push notifications are OPTIONAL (Profile M plus reverse envelopes provides equivalent function). gRPC/REST bindings of A2A are not used inside envelopes.

### 8.2 Tiering

Every skill/verb is tagged `public` or `paired` (Agent Card `tiers`). The public tier of the core protocol is exactly `pact.pair.request`; deployments MAY additionally expose `scheduling.inquire` (§9.2.10) and Appendix D façade tools, and MUST treat all public-tier input under the untrusted-content rules (§17) with the anti-abuse bounds of §7.5.2. Paired-tier verbs MUST arrive as sealed envelopes under an `active` pact with a covering scope (§10.3).

### 8.3 Verb envelope

Every PACT data part is:

```json
{ "kind": "data", "data": { "verb": "<namespace.action>", "v": 1, "body": { … } } }
```

Receivers MUST schema-validate `body` (`MALFORMED` on failure), MUST reject unknown verbs with `UNSUPPORTED_VERB` listing supported verbs, and MUST NOT fall back to interpreting free text in place of a failed structured verb. Accompanying `text` parts are permitted for human nuance and are always untrusted data (§17). One message carries at most one verb part.

### 8.4 Tasks and the human loop

Long-running interactions are A2A tasks. `input-required` = a human decision is pending on the receiving side; `auth-required` = the verb needs a scope the pact lacks (the human may grant via `pact.scopes.update`, §10.4, unblocking the task); `rejected` = policy refusal; `completed` carries final artifacts. Task ids are scoped per pact; an endpoint MUST NOT reference one pact's task from another pact.

---

## 9. Verbs *(normative)*

Registry summary (tier, direction, required scope) in §14.1; field tables here. All bodies are subject to the size limits of §14.6. "Owner-signed" marks verbs whose body is a JWS by `OK` (as in §6.3); "agent-signed" marks JWS by `IK`; all others rely on envelope authentication alone.

### 9.1 `pact.*` — pact lifecycle

**9.1.1 – 9.1.4** `pact.pair.request` / `accept` / `finish` / `reject` — defined in §6.3 (owner-signed). `pact.pair.reject` body: `{ "pactId", "reason": "declined"|"expired"|"policy", "humanNote"? }` (owner-signed). `pact.pair.cancel` body: `{ "pactId" }` (owner-signed).

**9.1.5 `pact.transport.update`** (agent-signed): `{ "rev": n, "transports": [descriptor…], "routes"?: {...replacement route/GAK provisioning...} }`. Highest `rev` wins (§7.7).

**9.1.6 `pact.key.update`** (owner-signed): `{ "delegations": [<delegation JWS>…], "retiredKids": […], "suiteFloor"?: "...", "prekeysHash"?: "..." }`. Announces new operational keys/floor; peers update the pact record and MUST re-seal queued traffic (§6.5.1).

**9.1.7 `pact.key.revoke`** (owner-signed): `{ "kids": […], "reason": "compromise"|"routine" }`. Peers MUST stop accepting the named kids immediately, overriding delegation `exp`. Distinct from `pact.revoke` (relationship termination).

**9.1.8 `pact.scopes.update`** (owner-signed): `{ "grant": [scope…], "retract": [scope…], "otrVerbs"?: [verb…] }`. Applies to what the *sender* permits the receiver to exercise. Retraction is effective on receipt; the sender enforces locally regardless.

**9.1.9 `pact.error`**: `{ "code": <registry §14.5>, "refMsgId"?, "refTaskId"?, "retryable": bool, "detail"? (≤1 KiB, untrusted) }`. The sealed error channel for failures discovered after unsealing.

**9.1.10 `pact.ping`**: `{ "echo": <b64u ≤32 bytes> }` — respond with the same body.

**9.1.11 `pact.suspend` / `pact.resume`** (owner-signed): `{ "reason"?: "user"|"security"|"recovery" }` / `{}` (§6.1 rule 7).

**9.1.12 `pact.reverify`** (owner-signed): `{ "sasCommit" | "n" }` — two-message commit/reveal re-running §6.4 over current owner keys; on success both sides clear `suspended` state that required re-verification.

**9.1.13 `pact.revoke`** (owner-signed): `{ "reason"? }` (§6.6).

**9.1.14 `pact.identity.update`** (owner-signed): `{ "did": "<new>", "handle": "<new>", "identityRecord": {…}, "continuity": <chain if OK changed> }` — provider migration and handle changes. Same `OK` ⇒ peers re-pin DID/handle and continue (pactId, seq, scopes unchanged). Changed `OK` ⇒ §6.5.2 rules apply first.

### 9.2 `scheduling.*` — negotiation

Verbs marked *(task)* run inside one A2A task per negotiation. The privacy rules of §9.2.9 are normative.

**9.2.1 `scheduling.request`** *(task-opening)*:

| Field | Type | Req | Notes |
|---|---|---|---|
| `intent` | `"meet"`\|`"call"`\|`"visit"` | ✔ | |
| `subject` | string ≤ 512 B | ✔ | Untrusted (§17) |
| `durationMin` | int 5–1440 | ✔ | |
| `window` | `{ "earliest", "latest": RFC3339-with-offset, "tz": IANA }` | ✔ | Constraints interpreted in `tz` |
| `constraints` | `{ "daysOfWeek"?: ["Mon"…], "timeOfDay"?: ["morning"|"afternoon"|"evening"], "mode"?: "in-person"|"video"|"phone", "area"?: string ≤256 B }` | ✖ | `morning`=06:00–12:00, `afternoon`=12:00–17:00, `evening`=17:00–21:00 local in `window.tz` |
| `priority` | `"normal"`\|`"high"` | ✖ | default normal |
| `expiresAt` | RFC3339 | ✔ | Negotiation deadline |

**9.2.2 `scheduling.propose`** *(task)*: `{ "slots": [1–5 of { "start", "end": RFC3339-with-offset, "tz": IANA, "mode", "location"? ≤256 B }], "holdUntil"?: RFC3339, "note"? ≤1 KiB }`. `tz` is authoritative; receivers MUST recompute wall-clock from the zone (DST safety), treating the offset as advisory.

**9.2.3 `scheduling.counter`** *(task)*: same shape as propose plus `inReplyTo: <msgId>`. The total number of `scheduling.counter` messages on a task (both directions combined) MUST NOT exceed 4; the next divergence escalates to humans (`input-required`) or declines.

**9.2.4 `scheduling.accept`** *(task)*: `{ "slot": {…exactly one proposed slot…}, "inReplyTo": <msgId> }`.

**9.2.5 `scheduling.confirm`** *(task-terminal)* — always sent by the **responder of the negotiation task** (the side whose calendar is being booked), whichever side sent the accept: `{ "bookingRef": <b64u128, minted by that responder, unique per pact>, "event": { "title" ≤512 B, "start", "end", "tz", "mode", "location"?|"url"? }, "ics": <b64 iCalendar>, "otr"?: <§7.1.5> }`. The ICS MUST set `ORGANIZER` to the confirming side (or its owner-approved address), `UID = "pact-" + pactId + "-" + bookingRef + "@pact.invalid"`, and `SEQUENCE = 0`; attendee addresses appear only with owner approval, else are omitted. Confirm is idempotent on `bookingRef`: a duplicate confirm with the same ref is an acknowledgement; a different ref for the same task is `MALFORMED`.

**9.2.6 `scheduling.decline`** *(task-terminal)*: `{ "reason": "no-availability"|"declined-by-user"|"out-of-scope"|"slot-unavailable"|"hold-expired"|"expired", "retryAfter"?: RFC3339 }`.

**9.2.7 `scheduling.cancel`**: `{ "bookingRef", "reason"? ≤512 B }`. Cancels a confirmed booking; the ICS METHOD:CANCEL carries the same UID with incremented SEQUENCE. A cancelled `bookingRef` is terminal; subsequent verbs naming it are rejected `MALFORMED` — a new meeting is a new `scheduling.request`.

**9.2.8 `scheduling.reschedule`**: `{ "bookingRef", "request": {…9.2.1 body…} }` — opens a new negotiation task bound to an existing *non-cancelled* booking; its confirm reuses the UID with incremented SEQUENCE and a fresh `bookingRef`.

**9.2.9 Privacy and state rules.** A responder MUST NOT disclose free/busy data; it returns only concrete candidate slots already filtered by its owner's policy, at most 5 per message. `holdUntil` soft-reserves offered slots; holds expire automatically and MUST be released on task end or suspension. If an accepted slot is no longer available (hold expired, concurrent booking), the responder answers the accept with `scheduling.decline (slot-unavailable | hold-expired)` **or** a fresh `scheduling.propose` — the task state machine is:

```
request ─► propose ─►(accept ─► confirm | decline | propose′)
   │           │ ▲        ▲
   │           ▼ │        │ counter ≤ 4 total
   │         counter ─────┘
   └─► decline                     confirm ─► [cancel | reschedule]*
```

Any step may surface as `input-required` per the receiving owner's policy.

**9.2.10 `scheduling.inquire`** *(public tier, OPTIONAL)*: body = 9.2.1 minus `window`/`constraints` granularity — `{ "intent", "subject", "durationMin", "roughWindow": "text ≤256 B" }`. The only permitted responses are task `rejected` or `input-required` resolving to a `pact.pair.request` suggestion; candidate slots MUST NOT be returned to unpaired callers.

### 9.3 `messaging.*`

**9.3.1 `messaging.deliver`**: `{ "text"?: ≤16 KiB | "parts"?: [A2A parts], "urgency": "normal"|"priority", "replyRequested": bool }`. `priority` requires scope `messaging.priority`. The receiving agent renders, digests, or answers per its owner's policy; when it answers autonomously it MUST self-identify as the assistant (never as the owner).

**9.3.2 `messaging.receipt`**: `{ "refMsgId", "state": "delivered"|"read"|"answered", "ts" }`. Emission is policy-gated per pact; receivers MUST NOT infer meaning from absence (§16.4).

### 9.4 `presence.*` *(optional feature)*

`presence.query`: `{}` → response `presence.state`: `{ "state": "available"|"busy"|"away"|"do-not-disturb", "asOf": ts }`. Response-only in 1.0 (no unsolicited pushes); coarse states only; per-pact opt-in; servers SHOULD fuzz timing and rate-limit queries (§16.4).
---

## 10. Authorization and scopes *(normative)*

### 10.1 Model

Scopes are directional permissions attached to a pact: what one owner permits the *peer* to exercise. They are established at pairing (§6.3) and changed with `pact.scopes.update` (§9.1.8). Scopes are distinct from delegation capabilities (§5.2 `caps`), which bind an owner's *own* agent; an inbound verb is authorized only when the sender's delegation carries the matching capability **and** the receiver's pact record grants the matching scope.

### 10.2 Pairing-field semantics

In `pact.pair.request`: `requestedScopes` = scopes the initiator asks to exercise against the responder; `offeredScopes` = scopes the initiator grants the responder. In `pact.pair.accept`: `grantedScopes` ⊆ `requestedScopes` = what the initiator may now exercise; `acceptedScopes` ⊆ `offeredScopes` = what the responder will exercise. The resulting pact records two independent grant sets, one per direction; either owner may later grow or shrink only the set *it* grants.

### 10.3 Grammar and verb mapping

Scope names are `namespace.action` from the registry (§14.2); the wildcard form `namespace.*` matches every action in that namespace and is valid in grants and delegation caps alike (no other patterns). Verb→scope mapping:

| Verb(s) | Scope required of the sender |
|---|---|
| `pact.*` | none (lifecycle; gated by pact state and signature rules) |
| `scheduling.request`, `scheduling.reschedule` | `scheduling.request` |
| `scheduling.propose/counter/accept/confirm/decline/cancel` within a task | the scope that authorized the task's opening verb (in-task rule) |
| completion of a negotiation without per-event human approval | `scheduling.autobook` (receiver-side policy gate, not a wire check) |
| `messaging.deliver` | `messaging.deliver` |
| `messaging.deliver` with `urgency: priority` | `messaging.priority` |
| `messaging.receipt` | in-task rule (rides the delivered message's scope) |
| `presence.query` | `presence.read` |
| `tasks.delegate` (reserved namespace) | `tasks.delegate` |

A verb without its scope is rejected `SCOPE_MISSING`; the receiver MAY instead park the task in `auth-required`, surface the request to its owner, and proceed if the owner grants (§10.4).

### 10.4 Step-up

On `auth-required`, the would-be grantor's endpoint surfaces the missing scope to its owner; approval emits `pact.scopes.update` with the grant, after which the parked task resumes. Denial resolves the task `rejected`.

### 10.5 Policy engine *(informative)*

How an endpoint decides allow-auto / ask / deny within granted scopes is local policy, invisible to the wire except as task states. Recommended defaults: pairing always asks (normative anyway, §6); the first negotiation with a new pact asks; subsequent in-scope traffic automates; anything touching money, third parties, `tasks.delegate`, or on-the-record commitments asks. Owners see an audit log of every cross-pact action (§15.6).

---

## 11. Discovery and the directory *(normative)*

### 11.1 Handles

```
handle = name "@" domain
name   = 1*64( %x61-7A / DIGIT / "." / "_" / "-" )   ; lowercase a–z, 0–9, ".", "_", "-"
domain = <domain per RFC 5890 (A-label or U-label)>
```

Names are stored and transmitted in lowercase NFC; comparison is exact byte equality after NFC normalization and lowercasing. Internationalized domains use IDNA 2008 [RFC5890]; displayed handles apply the confusable-script protections of §17. Registrars (directory operators) MUST reject names that are confusable-equivalent (UTS #39 skeleton match) to an existing name in the same domain.

### 11.2 Identity record

Served at `https://{domain}/.well-known/pact/{name}` (path registration: §14.8), media type `application/pact-record+json`. The record is a JWS (compact, `typ: "pact-record+jws"`) signed by `OK`; payload:

| Field | Type | Req | Description |
|---|---|---|---|
| `handle`, `did` | string | ✔ | Subject identity |
| `ownerKey` | string | ✔ | `b64u` Ed25519 `OK` |
| `continuity` | array | cond | Owner-key continuity chain (§6.5.2), oldest→newest, ≤ 16 |
| `delegations` | array | ✔ | Current delegation JWSs (§5.2) |
| `prekeys` | object | ✔* | `{ "url", "hash" }` (§5.4); *required for identities accepting directory-path pairing |
| `pairing` | string | ✔* | Pairing-route deposit URL (§7.5.2); *same condition |
| `transports` | array | ✔ | Bootstrap transport descriptors (§7.7) |
| `agentCard` | string | ✔ | URL of the A2A Agent Card |
| `agentCardKey` | string | ✔ | Key the card's JWS must verify under |
| `didMethods` | array | ✖ | Additional supported methods (`did:peer`, `did:wba`) |
| `visibility` | `"listed"`\|`"unlisted"` | ✔ | Unlisted records resolve only with an invitation secret presented as `?sk=` (constant-time compared) |
| `updated` | int | ✔ | Unix seconds; monotonic per identity |
| `kt` | object | ✖ | `{ "log", "leaf", "sth", "inclusion" }` inclusion proof (§11.4) |

### 11.3 Resolution

**11.3.1** Resolvers fetch over HTTPS (WebPKI), verify the record JWS against `ownerKey`, walk `continuity` if their pinned key is older, and verify `kt` when present and when the resolver knows the log.
**11.3.2** Federation: a directory serves its own domain authoritatively and MAY proxy/cache foreign lookups by fetching the foreign well-known record (with its KT proof). There is no global root; the handle's domain is the authority pointer, as with email.
**11.3.3 Freshness.** Before accepting a *new* delegation `kid` from a peer, and at least every 24 hours for pacts in active use, an endpoint MUST refresh the peer's identity record (or receive an equivalent `pact.key.update`); an endpoint MUST NOT honor a delegation absent from the freshest record it can obtain, and MUST treat sustained inability to refresh (> 7 days) for a directory-listed peer as a degraded-trust signal surfaced to policy. did:key peers are exempt (no record exists; §6.6 rules apply).

### 11.4 Key transparency *(Directory feature)*

A directory claiming the *Key Transparency* feature MUST append every record state change — `(VRF(handle), SHA-256(JCS(record payload)))` — to an append-only Merkle log with signed tree heads, following the deployed AKD/CONIKS construction: handles blinded by VRF so the log does not enumerate the user base; plaintext PII lives only in the mutable directory (supporting erasure, §16.5); auditors mirror and verify consistency; clients verify inclusion on lookup and SHOULD monitor their *own* entry (a published state you did not create is compromise evidence; §6.5.2). Signed tree heads SHOULD be gossiped across unrelated channels. KT converts the directory from a trusted party into an auditable one; §16.3 states what it does *not* protect (live query privacy).

---

## 12. Errors *(normative)*

Failures visible before unsealing map to transport status (§7.3.1); failures after unsealing are reported in-band with `pact.error` (§9.1.9) when a usable pact exists, else silently dropped (dropping is intentional: unpaired probes learn nothing). Registry:

| Code | Meaning | Retryable | Typical transport mapping |
|---|---|---|---|
| `MALFORMED` | Envelope/verb fails schema | no | 400 |
| `UNKNOWN_ROUTE` | routeId not provisioned | after transport refresh | 404 |
| `UNKNOWN_PACT` | pactId/from/to/dir don't resolve | no | — (sealed) |
| `PACT_EXISTS` | Pairing against an active pact | no | — |
| `PACT_ALREADY_PENDING` | Glare loser (§6.1 rule 2) | no; use surviving pactId | — |
| `PACT_SUSPENDED` | Pact suspended | yes, after resume | — |
| `PACT_REVOKED` | Pact revoked | no | — |
| `REQUEST_EXPIRED` | Handshake artifact past `exp` | no | — |
| `INVITATION_INVALID` | sk unknown/consumed/revoked/expired | no | — |
| `UNKNOWN_KID` | No held key for `kid` | yes, after key refresh + re-seal | — |
| `DECRYPT_FAILED` | AEAD/KEM failure | no | — |
| `BAD_SIGNATURE` | JWS/commitment/cross-check failure | no | — |
| `DELEGATION_EXPIRED` | skid delegation invalid at `ts` | yes, after peer re-keys | — |
| `SCOPE_MISSING` | Verb lacks covering scope | after grant (§10.4) | — |
| `REPLAY` | seq/msgId rejected | no (already processed) | 409 |
| `TOO_LARGE` | Exceeds §14.6 | no | 413 |
| `RATE_LIMITED` | Admission control | yes (Retry-After) | 429 |
| `QUOTA_EXCEEDED` | Storage/queue quota | yes, later | 429/503 |
| `UNSUPPORTED_VERSION` | v/suite unsupported or below floor | no | — |
| `UNSUPPORTED_MEDIA` | Unknown `cty` | no | — |
| `UNSUPPORTED_VERB` | Unknown verb (lists supported) | no | — |
| `INTERNAL` | Receiver fault | yes | 500/503 |

`pact.error` referencing a task also moves that task to `failed` unless the code is retryable.

---

## 13. Versioning and extensibility *(normative)*

### 13.1 What 1.0 freezes

Frozen for the 1.x series: the envelope structure and validation order (§7.1), suite `PACT-HPKE-1`, the pairing message sequence and SAS derivation (§6), the transport contracts (§7.3–7.5), the verb bodies of §9 at `v:1`, the identity-record shape (§11.2), the error registry semantics (§12), and the handle/invite ABNFs. Additive change happens through: new optional fields (must-ignore, §2.3), new verbs and scopes (registries, §14), new suites (floor-negotiated, §7.1.6), new transport-descriptor profiles, and A2A-level extensions.

### 13.2 Wire versioning

`protected.v` and verb `v` are independent: `v` (envelope) bumps only on incompatible envelope changes; verb `v` bumps per-verb on incompatible body changes. Endpoints advertise `versions` (Agent Card, §5.5) and per-pact effective versions are implied by what both advertise at pairing time and thereafter via `pact.key.update` announcements; a sender MUST use the highest mutually supported versions and MUST NOT exceed what the peer advertised. Unknown envelope `v` ⇒ `UNSUPPORTED_VERSION`; unknown verb `v` ⇒ `UNSUPPORTED_VERB` with the supported list.

### 13.3 Known 1.1 work items *(informative)*

Post-quantum hybrid suite (`PACT-HPKE-2`) and floor raise; per-conversation ratchet or MLS for forward secrecy; group pacts (household/team, MLS-based); multi-runtime senders (per-kid sequence spaces); anonymous deposit tokens (Privacy Pass) for pairing routes and metadata-reduced relaying; `did:peer` pairwise identities by default; delegation to third-party specialist agents; payments via the A2A AP2 extension.

### 13.4 Change control

Registries in §14 are maintained in the project repository; additions require a published specification and do not require a new protocol version. Incompatible changes require a major version and a new extension URI.

---

## 14. Registries *(normative)*

### 14.1 Verbs

| Verb | Tier | Direction | Scope | Defined |
|---|---|---|---|---|
| `pact.pair.request` | public | init→resp | — | §6.3.1 |
| `pact.pair.accept` / `finish` / `reject` / `cancel` | pairing | as defined | — | §6.3, §9.1 |
| `pact.ping` | paired* | either | — | §9.1.10 |
| `pact.key.update` / `key.revoke` | paired* | either | — | §9.1.6–7 |
| `pact.transport.update` | paired* | either | — | §9.1.5 |
| `pact.scopes.update` | paired* | either | — | §9.1.8 |
| `pact.suspend` / `resume` / `reverify` | paired* | either | — | §9.1.11–12 |
| `pact.revoke` | paired* | either | — | §9.1.13 |
| `pact.identity.update` | paired* | either | — | §9.1.14 |
| `pact.error` | paired* | either | — | §9.1.9 |
| `scheduling.request` | paired | either | `scheduling.request` | §9.2.1 |
| `scheduling.propose` / `counter` / `accept` / `confirm` / `decline` | paired | in-task | in-task | §9.2.2–6 |
| `scheduling.cancel` / `reschedule` | paired | either | `scheduling.request` | §9.2.7–8 |
| `scheduling.inquire` | public (opt) | any→resp | — | §9.2.10 |
| `messaging.deliver` | paired | either | `messaging.deliver` | §9.3.1 |
| `messaging.receipt` | paired | in-task | in-task | §9.3.2 |
| `presence.query` / `state` | paired (opt) | either / reply | `presence.read` | §9.4 |

\* "paired\*" = valid on a pact in any non-terminal state (lifecycle verbs must work while suspended or mid-handshake as defined).

### 14.2 Scopes

`scheduling.request`, `scheduling.autobook`, `messaging.deliver`, `messaging.priority`, `presence.read`, `tasks.delegate` (reserved in 1.0: MUST be declinable, semantics deferred). Wildcard: `namespace.*`.

### 14.3 Transport profiles

`D` (direct QUIC/Iroh or raw-key TLS), `G` (gateway HTTPS), `M` (mailbox). Descriptor shapes: §7.7.

### 14.4 Delegation capabilities

`pair`, `scheduling`, `messaging`, `presence`, `transport`, `infra` (control-API operation). Wildcard permitted.

### 14.5 Error codes

The table of §12.

### 14.6 Security and operational parameters

| Parameter | Value |
|---|---|
| Envelope maximum size | 262 144 bytes (256 KiB) |
| Free-text field maxima | per field tables; default 4 KiB (`humanNote`), 512 B (subjects/reasons), 16 KiB (`messaging.deliver.text`) |
| Identity record maximum | 65 536 bytes |
| Mailbox delivery batch | ≤ 100 envelopes and ≤ 1 MiB |
| Mailbox retention | min(envelope `exp`, 30 days) |
| Default per-pact mailbox quota | ≥ 200 envelopes or 16 MiB (operator-adjustable; advertised) |
| Replay window `W` | 1024 per direction |
| Clock skew tolerance | ± 300 s |
| Envelope maximum TTL (`exp − ts`) | 7 days |
| Delegation lifetime | default 7 days; maximum 30 days |
| Superseded-EK retention | ≥ 35 days |
| Consumed one-time-prekey private-half retention | ≥ 7 days |
| Signed-prekey lifetime | ≤ 30 days |
| Invitation `sk` | 128-bit CSPRNG; `exp` ≤ 14 days |
| Pairing request lifetime | ≤ 7 days; `accept-sent` reversion 48 h |
| Continuity chain depth | ≤ 16 |
| SAS | 6 BIP-39 words (66 bits) + 12-digit numeric fallback; nonces 128-bit |
| Counter depth per negotiation | ≤ 4 total |
| Proposal slots per message | ≤ 5 |
| RFC 9421 `expires − created` | ≤ 300 s |
| Directory record freshness for new kids | ≤ 24 h (§11.3.3) |

### 14.7 Media types

`application/pact-envelope+json`, `application/pact-msg+json`, `application/pact-rsp+json`, `application/pact-record+json`. Registration with IANA is release work (RB-3).

### 14.8 URIs and well-known paths

`pact:` URI scheme (invitations, §6.2) — provisional registration RB-3. Well-known suffix `pact` (`/.well-known/pact/{name}`) — RFC 8615 registration RB-3. Extension URI `https://pactprotocol.org/ext/v1` — provisional, RB-1. HTTP path prefixes `/pact/v1/…` as defined in §7.
---

## 15. Security considerations

### 15.1 Threat model *(informative)*

Adversaries considered: (a) network attackers on any path; (b) curious-or-malicious infrastructure — gateways, mailboxes, tunnel edges, relays; (c) a malicious or compromised directory/platform operator; (d) a malicious *paired* peer; (e) an unpaired stranger; (f) a compromised agent runtime; (g) an attacker holding a stolen operational key; (h) content-level attackers targeting the receiving agent's model (prompt injection) or its human (social engineering). Out of scope: compromise of the owner's own device *and* platform simultaneously, and traffic-analysis-resistant anonymity (see §16).

### 15.2 Pairing trust outcomes *(normative)*

The protocol yields different guarantees per pairing path, and implementations MUST surface these states to owners rather than presenting all pacts as equal:

| Path | Key of the party contacted (inviter / listed identity) | Key of the contacting party | Residual until SAS |
|---|---|---|---|
| Invitation (§6.2) | Authenticated by the OOB channel that carried the invitation | **Unanchored (TOFU)** — the inviter has no prior anchor for the invitee | MITM on the return path; hence §6.4 REQUIRES the inviter-side SAS |
| Directory with KT (§11.4) | KT-verified | KT-verified | Active malicious log (detectable post-hoc via monitoring/audit; SAS closes the window) |
| Directory without KT | Trusted directory | Trusted directory | Directory operator MITM; SAS RECOMMENDED |
| Neither (did:key, no invitation `ek`) | TOFU | TOFU | Full MITM; SAS REQUIRED before granting scopes beyond defaults |

The commit-reveal SAS (§6.4) gives an active MITM a single 2⁻⁶⁶ guess; a failed comparison is treated as compromise, not inconvenience.

### 15.3 Cryptographic properties and limits *(normative where stated)*

**Authentication & deniability.** Envelope authentication is HPKE Auth mode: peer-convincing, third-party-deniable. Known limit (KCI): an attacker holding a recipient's `EK` *private* key can forge envelopes *to that recipient* from any of its peers. Containment: `EK` lifetime ≤ 30 days; every pact-lifecycle decision (pairing, scopes, keys, revocation) additionally requires `OK`/`IK` signatures, which KCI cannot forge; high-stakes verbs can demand on-the-record mode (§7.1.5). Implementations MUST NOT treat an envelope alone as evidence of authorship toward third parties.
**Confidentiality & forward secrecy.** Compromise of an `EK` private key exposes envelopes sealed to it during its lifetime (≤ 30 days; default 7). 1.0 accepts this bound honestly; 1.1 plans a per-conversation ratchet (§13.3). Harvest-now-decrypt-later against classical X25519 is acknowledged; the PQ-hybrid suite and floor-raise path (§7.1.6) is the mitigation.
**Bindings.** The AAD/`info` bindings of §7.1.2 and the checks of §7.1.2 step 4 defeat cross-pact re-sealing (surreptitious forwarding), reflection, and metadata malleability; `reqHash`/`acceptHash` bind the pairing transcript; suite floors in the owner-signed transcript defeat downgrade.
**Canonicalization.** Every signed/hashed JSON artifact states its byte-input rule (§2.3); implementations MUST NOT re-serialize before verifying.

### 15.4 Custody tiers *(normative)*

**Sovereign:** `OK` on the owner's device; hosted components hold only delegations. This is the RECOMMENDED default whenever a device is available.
**Managed:** the Platform Operator holds `OK`. Operators offering Managed custody MUST: (1) disclose plainly that the operator can technically act as the owner; (2) maintain a per-user, append-only, user-visible **pact log** of every owner-key operation (pair accept/reject, scope change, key event, revocation) — silent pairing then leaves tamper-evident tracks the owner's app monitors, the same pattern KT applies to the directory; (3) send out-of-band notification on every owner-key operation; (4) support one-way upgrade to Sovereign. Device co-signature (2-of-2: platform + device) for owner-key operations is RECOMMENDED where any device exists.

### 15.5 Recovery *(normative)*

Any recovery mechanism (social recovery, operator escrow, seed restore onto a new device) that re-establishes control without the old `OK` MUST be treated as a lost-key rotation: all pacts suspend pending `pact.reverify` (§6.5.2). Recovery designs are otherwise out of scope, but operators MUST document theirs, and escrow-based recovery inherits every Managed-custody obligation of §15.4.

### 15.6 Abuse resistance *(normative where stated)*

The consent gate confines strangers to pairing routes and optional public verbs, which MUST be bounded (rate, count, size — §7.5.2) and SHOULD require admission cost (PoW stamp or anonymous token) for directory-path requests to listed identities. Paired-channel abuse (flooding within a pact) is bounded by §14.6 quotas and answered with suspension/revocation. Endpoints MUST maintain an owner-visible audit log of cross-pact actions. Forced transport downgrade (Profile D persistently blocked) MUST be logged and SHOULD be surfaced. Glare, invitation, and prekey endpoints MUST use constant-time comparison for secrets (`sk`, commitments, SAS checks).

### 15.7 Abuse reporting *(informative)*

Deniable-by-default messaging removes cryptographic proof of misbehavior; that is a feature for privacy and a cost for moderation. The on-the-record mechanism (§7.1.5) is the balance: a reporting owner can share received `otr`-signed content with an operator as portable evidence, and owners can require `otr` on verbs they consider contractual. Operators SHOULD provide a reporting channel accepting an exported envelope + pact context; protocol-level blocking is `pact.suspend`/`pact.revoke` plus route de-provisioning.

### 15.8 Implementation security *(normative)*

Private keys MUST be stored in platform keystores/HSMs where available and be zeroized on release; `OK` operations SHOULD require local user presence in Sovereign custody. All secret comparisons constant-time. CSPRNG for every identifier and nonce in §2.3. Implementations MUST bound resource use per peer and per route (parsing limits, decompression bans, queue caps) and SHOULD isolate envelope parsing from the agent runtime. The model-facing injection rules of §17.2 are security requirements, not UX guidance.

---

## 16. Privacy considerations

### 16.1 What each party learns *(informative)*

| Party | Learns | Never learns |
|---|---|---|
| Peer (paired) | Everything you send it; your policy's outputs (slots, receipts) | Raw calendar/free-busy (§9.2.9) |
| Gateway/tunnel edge | routeId, envelope sizes/timing, depositor GAK (per-pact pseudonym) | Content, DIDs, handles, cross-pact linkage of a sender (per-pact GAKs/routeIds) |
| Mailbox | Queue depth/timing per routeId; same as gateway | Content |
| Directory | Which records are fetched, by which IP/when (live queries) | Content of pacts; with KT it cannot *undetectably* substitute keys |
| Platform (Managed) | Operationally: whatever the hosted runtime processes | — (this is the custody tradeoff, §15.4) |

### 16.2 Metadata minimization *(normative where stated)*

Per-pact `routeId`s and `GAK`s are REQUIRED precisely so infrastructure sees pairwise pseudonyms rather than a linkable global identity. Identifiers MUST be random (no embedded timestamps). Envelope padding to size buckets is RECOMMENDED for sensitive deployments. Residual, stated honestly: infrastructure still observes per-pact traffic existence, timing, and volume; IP-level linkage is out of scope (use onion routing or shared relays where that matters).

### 16.3 Directory query privacy *(informative)*

KT protects key *integrity*, not query privacy: the directory still sees live lookups (who is about to contact whom) and self-monitoring reveals interest in one's own entry. Mitigations for future work: cache-and-batch resolution, oblivious lookups, third-party mirrors. Unlisted visibility (§11.2) keeps an identity out of enumeration entirely.

### 16.4 Presence, receipts, and interpersonal risk *(normative)*

Presence and read receipts are stalking and intimate-partner-surveillance vectors. They are OFF by default, per-pact opt-in, coarse, response-only (presence), SHOULD be time-fuzzed and rate-limited, and MUST be retractable per pact without notice to the peer. Implementations MUST NOT signal to a peer that receipts were disabled.

### 16.5 Data protection *(informative)*

The KT log stores only VRF-blinded identifiers and hashes; plaintext handles/records live in the mutable directory, so erasure requests can be honored by deleting the mutable record and keys (crypto-shredding) while the log's blinded leaves retain no usable PII. Mailboxes hold ciphertext with bounded retention (§14.6). Pact records, task history, and audit logs are personal data held by each endpoint for its own owner; retention is owner policy.

---

## 17. Internationalization considerations *(normative)*

### 17.1 Text handling

All strings are UTF-8, normalized to NFC at trust boundaries. Length limits are byte limits (§14.6). Handles follow §11.1; internationalized domains display in U-label form only when the script is unmixed and non-confusable (UTS #39), else in A-label form.

### 17.2 Untrusted-content rules

Every free-text field arriving from a peer or stranger (`displayName`, `humanNote`, `subject`, `note`, `reason`, `area`, `location`, `event.title`, `messaging.deliver.text`, `pact.error.detail`, and any A2A text part) is untrusted input. Receivers MUST: enforce field byte limits; strip or refuse control characters, bidirectional-override characters (U+202A–202E, U+2066–2069), and zero-width characters (U+200B–200D, U+2060, U+FEFF); render such content to humans only inside visually framed untrusted-content regions with the *verified handle* displayed more prominently than any `displayName`; and pass such content to a model only within a delimited untrusted-data channel — never concatenated into instructions and never able to authorize tool use by itself. Agents processing an inbound verb SHOULD run with tool access confined to that verb's needs.

### 17.3 SAS localization

The SAS wordlist is the BIP-39 **English** list regardless of locale (it is an index namespace, not prose); implementations MAY display localized wordlists *alongside* indexes but cross-locale comparison uses the numeric fallback (§6.4), which MUST always be available.

---

## 18. Accessibility considerations *(informative)*

The two human ceremonies must not assume sight or a camera. Invitations: the `pact:` URI is copyable text wherever a QR is shown; QR scanning always has a paste-the-link equivalent. SAS: words are displayed as selectable text with the 12-digit numeric fallback (screen-reader friendly, speakable over a phone call, groupable 4-4-4); comparison UIs offer "read aloud" and do not time out in under two minutes. Approval prompts (pairing, scope grants) follow platform accessibility guidelines and never rely on color alone to convey verification status.

---

## 19. References

### 19.1 Normative

[RFC2119]/[RFC8174] BCP 14 · [RFC3339] Timestamps · [RFC3986] URI · [RFC4648] Base64url · [RFC5869] HKDF · [RFC5890] IDNA · [RFC6234] SHA · [RFC7515] JWS · [RFC7748] X25519 · [RFC8032] Ed25519 · [RFC8259] JSON · [RFC8615] Well-known URIs · [RFC8785] JCS · [RFC9180] HPKE · [RFC9421] HTTP Message Signatures · [RFC9530] Content-Digest · [RFC7250] Raw public keys in TLS · [A2A] A2A Protocol Specification v1.0 (a2a-protocol.org, pinned v1.0.x) · [DID-CORE] W3C Decentralized Identifiers v1.0 · [DID-WEB]/[DID-KEY] respective method specifications · [BIP39-EN] BIP-39 English wordlist (2048 words) · [UTS39] Unicode Technical Standard #39, Security Mechanisms.

### 19.2 Informative

[MCP] Model Context Protocol (spec 2026-07-28) · [DIDCOMM] DIDComm Messaging v2.1 · [SPIFFE] SPIFFE/SPIRE federation · Signal PQXDH and Automatic Key Verification · WhatsApp Auditable Key Directory · Apple iMessage Contact Key Verification · Matrix cross-signing and SAS · Tailscale Tailnet Lock · Iroh 1.0 · Cloudflare Tunnel and Web Bot Auth · Pangolin · DIDComm Message Pickup 3.0 · MLS RFC 9420 · Privacy Pass RFC 9576/9578 · ANEX · Agent Network Protocol (ANP) · the companion document *PACT: Landscape, Comparison & Roadmap* (full market/citation detail).

---

## Appendix A. Complete message examples *(informative)*

Values are consistent with the Appendix C key material (owners "Alina" = A, "Bharat" = B; Bharat initiates). JWS strings are abbreviated *only* in this appendix by showing payloads pre-signing; Appendix C carries a fully signed vector.

### A.1 `pact.pair.request` payload (JWS payload, signed by Bharat's OK)

```json
{
  "type": "pact.pair.request",
  "pactId": "ABEiM0RVZneImaq7zN3u_w",
  "from": "did:web:agents.pact.example:u:bharat",
  "to": "did:web:agents.pact.example:u:alina",
  "identityRecord": {
    "handle": "bharat@agents.pact.example",
    "did": "did:web:agents.pact.example:u:bharat",
    "ownerKey": "gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q",
    "delegations": ["<delegation JWS for kid ag-b-1>"],
    "prekeys": { "url": "https://mbx.pact.example/pact/v1/prekeys/bharat",
                 "hash": "2N7f0S1zXhKPBhcOM4jC2VYtW9J0f3n8mWq1sVd8Yxs" },
    "pairing": "https://gw.pact.example/pact/v1/inbox/IiIiIiIiIiIiIiIiIiIiIg",
    "transports": [ { "profile": "G", "url": "https://gw.pact.example",
                      "routeId": "IiIiIiIiIiIiIiIiIiIiIg" } ],
    "agentCard": "https://agents.pact.example/u/bharat/.well-known/agent-card.json",
    "agentCardKey": "gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q",
    "visibility": "listed",
    "updated": 1755950000
  },
  "routes": { "routeId": "EREREREREREREREREREREQ",
              "gateway": "https://gw.pact.example",
              "mailbox": "https://mbx.pact.example",
              "gak": "oaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaE" },
  "transports": [ { "profile": "G", "url": "https://gw.pact.example",
                    "routeId": "EREREREREREREREREREREQ" } ],
  "requestedScopes": ["scheduling.request", "messaging.deliver"],
  "offeredScopes": ["scheduling.request", "messaging.deliver"],
  "sasCommit": "292GIeNLEm-sycKZxyEUGCZgqGHOnDUlR2pgcY76PY4",
  "suiteFloor": "PACT-HPKE-1",
  "displayName": "Bharat Mehta",
  "humanNote": "We met at the Pune conference - connecting our assistants.",
  "iat": 1755960000,
  "exp": 1756564800
}
```

### A.2 `pact.pair.accept` payload (signed by Alina's OK; sealed to Bharat)

```json
{
  "type": "pact.pair.accept",
  "pactId": "ABEiM0RVZneImaq7zN3u_w",
  "reqHash": "liopgoxJLupY2-fGoacSm-ybedNY4nJFL5RxL5tJA2w",
  "identityRecord": { "handle": "alina@agents.pact.example",
    "did": "did:web:agents.pact.example:u:alina",
    "ownerKey": "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w",
    "delegations": ["<delegation JWS for kid ag-a-1>"],
    "prekeys": { "url": "https://mbx.pact.example/pact/v1/prekeys/alina",
                 "hash": "Vt6R3l0P9wFhZk2uNqYbC8sD4eG7jH1mK5oQxTzWnAI" },
    "pairing": "https://gw.pact.example/pact/v1/inbox/MzMzMzMzMzMzMzMzMzMzMw",
    "transports": [ { "profile": "G", "url": "https://gw.pact.example",
                      "routeId": "MzMzMzMzMzMzMzMzMzMzMw" } ],
    "agentCard": "https://agents.pact.example/u/alina/.well-known/agent-card.json",
    "agentCardKey": "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w",
    "visibility": "listed",
    "updated": 1755950000 },
  "routes": { "routeId": "IiIiIiIiIiIiIiIiIiIiIg",
              "gateway": "https://gw.pact.example",
              "mailbox": "https://mbx.pact.example",
              "gak": "srKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrI" },
  "transports": [ { "profile": "G", "url": "https://gw.pact.example",
                    "routeId": "IiIiIiIiIiIiIiIiIiIiIg" } ],
  "grantedScopes": ["scheduling.request", "messaging.deliver"],
  "acceptedScopes": ["scheduling.request"],
  "nR": "sLCwsLCwsLCwsLCwsLCwsA",
  "suiteFloor": "PACT-HPKE-1",
  "iat": 1756000000,
  "exp": 1756604800
}
```

### A.3 `pact.pair.finish` payload (signed by Bharat's OK)

```json
{ "type": "pact.pair.finish",
  "pactId": "ABEiM0RVZneImaq7zN3u_w",
  "acceptHash": "0Wn3v9pC1kQx8sZbYfTeH5uJ2mA7rL4dN6gK9iM3oPs",
  "nI": "oKCgoKCgoKCgoKCgoKCgoA",
  "iat": 1756001000 }
```

Both apps now display SAS words for BIP-39 indexes `[1613, 996, 201, 690, 31, 1039]`, numeric `7558 7897 6288` (Appendix C.2).

### A.4 A sealed envelope (Appendix C.4 vector, decryptable)

```json
{ "route": "IiIiIiIiIiIiIiIiIiIiIg",
  "protected": "eyJ2IjoxLCJzdWl0ZSI6IlBBQ1QtSFBLRS0xIiwicGFjdElkIjoiQUJFaU0wUlZabmVJbWFxN3pOM3VfdyIsImZyb20iOiJkaWQ6a2V5OnpBIiwidG8iOiJkaWQ6a2V5OnpCIiwiZGlyIjoicjJpIiwic2VxIjo3LCJtc2dJZCI6IkFBRUNBd1FGQmdjSUNRb0xEQTBPRHciLCJ0cyI6MTc1NjAwMDAwMCwiZXhwIjoxNzU2MDAzNjAwLCJjdHkiOiJhcHBsaWNhdGlvbi9wYWN0LW1zZytqc29uIiwia2lkIjoiZWstci0xIiwic2tpZCI6ImVrLXMtMSJ9",
  "enc": "KXEneb6c7QquKEgSOVhhaMeQDME9I4aGlr8IZDBe92Y",
  "ct": "hqjuKip9UHpLjl3zPFxxgg9hJ6qH7DOXqxUbMzQRVJqXkTJImdwzbXYXcmPXmjV5P4MWNzcAD398wGobhsmN2b5sLzz8mw-Fcdt-cYSeAfKExIWKC1d77lsgHC6G3ZxQh-k_WXq1kVM6nLbiLpxQnRpX96rquUf2uhs7QHHATux-whFCOqe2QA3QT6uMnbhl" }
```

### A.5 Scheduling flow (plaintext payloads, pre-sealing)

`scheduling.request` (Bharat → Alina), opening a task:

```json
{ "jsonrpc": "2.0", "id": "r-1", "method": "message/send",
  "params": { "message": { "role": "user",
    "parts": [ { "kind": "data", "data": { "verb": "scheduling.request", "v": 1, "body": {
        "intent": "meet", "subject": "Catch-up over coffee", "durationMin": 45,
        "window": { "earliest": "2026-08-24T00:00:00+05:30",
                    "latest": "2026-08-29T23:59:59+05:30", "tz": "Asia/Kolkata" },
        "constraints": { "daysOfWeek": ["Tue","Wed","Thu"],
                         "timeOfDay": ["morning"], "mode": "in-person",
                         "area": "Koregaon Park, Pune" },
        "priority": "normal", "expiresAt": "2026-08-24T18:00:00+05:30" } } },
      { "kind": "text", "text": "Bharat says: long overdue, keen to catch up." } ],
    "messageId": "w8PDw8PDw8PDw8PDw8PDww" } } }
```

`scheduling.propose` (Alina → Bharat, reverse envelope, same task):

```json
{ "verb": "scheduling.propose", "v": 1, "body": {
    "slots": [
      { "start": "2026-08-25T10:00:00+05:30", "end": "2026-08-25T10:45:00+05:30",
        "tz": "Asia/Kolkata", "mode": "in-person", "location": "Koregaon Park" },
      { "start": "2026-08-27T09:30:00+05:30", "end": "2026-08-27T10:15:00+05:30",
        "tz": "Asia/Kolkata", "mode": "in-person", "location": "Koregaon Park" } ],
    "holdUntil": "2026-08-24T12:00:00+05:30" } }
```

`scheduling.accept` (Bharat): `{ "verb": "scheduling.accept", "v": 1, "body": { "slot": { "start": "2026-08-25T10:00:00+05:30", "end": "2026-08-25T10:45:00+05:30", "tz": "Asia/Kolkata", "mode": "in-person", "location": "Koregaon Park" }, "inReplyTo": "3vHfQ9sK1mYcW7pLtR5DZg" } }`

`scheduling.confirm` (Alina, task-terminal):

```json
{ "verb": "scheduling.confirm", "v": 1, "body": {
    "bookingRef": "kJ2mQx4vTfWbY8pLnA3c6g",
    "event": { "title": "Catch-up over coffee",
               "start": "2026-08-25T10:00:00+05:30", "end": "2026-08-25T10:45:00+05:30",
               "tz": "Asia/Kolkata", "mode": "in-person", "location": "Koregaon Park" },
    "ics": "QkVHSU46VkNBTEVOREFSDQpWRVJTSU9OOjIuMA0KUFJPRElEOi0vL1BBQ1QvL0VODQpNRVRIT0Q6UkVRVUVTVA0KQkVHSU46VkVWRU5UDQpVSUQ6cGFjdC1BQkVpTTBSVlpuZUltYXE3ek4zdV93LWtKMm1ReDR2VGZXYlk4cExuQTNjNmdAcGFjdC5pbnZhbGlkDQpTRVFVRU5DRTowDQpEVFNUQU1QOjIwMjYwODIzVDEyMDAwMFoNCkRUU1RBUlQ7VFpJRD1Bc2lhL0tvbGthdGE6MjAyNjA4MjVUMTAwMDAwDQpEVEVORDtUWklEPUFzaWEvS29sa2F0YToyMDI2MDgyNVQxMDQ1MDANClNVTU1BUlk6Q2F0Y2gtdXAgb3ZlciBjb2ZmZWUNCkxPQ0FUSU9OOktvcmVnYW9uIFBhcmtcLCBQdW5lDQpPUkdBTklaRVI7Q049QmhhcmF0J3MgYXNzaXN0YW50Om1haWx0bzpuby1yZXBseUBwYWN0LmludmFsaWQNCkVORDpWRVZFTlQNCkVORDpWQ0FMRU5EQVINCg==" } }
```

### A.6 `pact.error`

```json
{ "verb": "pact.error", "v": 1, "body": {
    "code": "SCOPE_MISSING", "refMsgId": "w8PDw8PDw8PDw8PDw8PDww",
    "retryable": true, "detail": "scheduling.request not granted on this pact" } }
```

### A.7 End-to-end narrative *(informative)*

Sumit is self-hosted (Profile D via Iroh, plus a rented mailbox); Dr. Rao is platform-hosted with Sovereign custody. (1) Rao's clinic QR is a PACT invitation; Sumit scans; his agent seals `pact.pair.request` to the invitation key; Rao approves on her phone, which signs the accept; finish and pings complete; her app prompts the inviter-side SAS at the next visit (invitation path, §15.2). (2) Weeks later Sumit says "book a consultation next week, mornings"; his agent opens a task with `scheduling.request` via her gateway. (3) Her agent applies policy (patients: Tue/Thu 9–12, 15-minute buffers) and proposes three held slots; his agent auto-accepts Tuesday 09:30 under his standing healthcare policy. (4) Her policy requires her nod for new patients — `input-required`; she approves in her digest; `scheduling.confirm` with ICS lands both calendars via each side's MCP tools. (5) She falls ill; her agent sends `scheduling.reschedule`; his home node is asleep, so the envelope waits in his mailbox and his phone gets a contentless push. Nobody saw a calendar; nothing readable crossed any intermediary.

---

## Appendix B. Schemas *(normative pointer)*

The field tables of §§5–11 are the normative schema definitions. Machine-readable JSON Schema files generated from them ship in the project repository (`/schemas/1.0/*.json`) and are release-gated by RB-4; on any divergence the field tables govern.

---

## Appendix C. Test vectors *(normative)*

All secrets are fixed test seeds — never use them outside tests. Ed25519/X25519 private keys are given as 32-byte seeds, hex.

### C.1 Key material

```
OK_A seed  = 0101…01 (32×0x01)   OK_A pub = iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w
OK_B seed  = 0202…02             OK_B pub = gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q
EK_S seed  = 0303…03 (X25519)    EK_S pub = Xf7dO2vUf2-ijuFdlp1bsOpTd01Ii9r53xxuASSz7yI
EK_R seed  = 0404…04 (X25519)    EK_R pub = rAGyIJ6GNU-4UyN7XeD0-rE8f8v0M6YcAZNpYX_s8Qs
pactId     = hex 00112233445566778899aabbccddeeff  (b64u ABEiM0RVZneImaq7zN3u_w)
nI         = hex a0×16            nR = hex b0×16
```

### C.2 SAS (§6.4)

```
ikm (sorted OK_B‖OK_A here, B sorts first) =
  8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394
  8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c
salt = pactId bytes; info = "PACT-1.0 sas" || nI || nR
okm(9) = c9af9064ab203f03eb
word indexes (11-bit, 0-based) = 1613, 996, 201, 690, 31, 1039
numeric = 755878976288  → displayed 7558 7897 6288
```

### C.3 Request hash (§6.3.2)

For the minimal JWS (protected `{"alg":"EdDSA","typ":"pact-pair+jws"}`, payload `{"type":"pact.pair.request","pactId":"ABEiM0RVZneImaq7zN3u_w","sasCommit":"292GIeNLEm-sycKZxyEUGCZgqGHOnDUlR2pgcY76PY4"}`, key OK_B):

```
sasCommit = b64u(SHA-256(nI)) = 292GIeNLEm-sycKZxyEUGCZgqGHOnDUlR2pgcY76PY4
JWS = eyJhbGciOiJFZERTQSIsInR5cCI6InBhY3QtcGFpcitqd3MifQ.eyJ0eXBlIjoicGFjdC5wYWlyLnJl
      cXVlc3QiLCJwYWN0SWQiOiJBQkVpTTBSVlpuZUltYXE3ek4zdV93Iiwic2FzQ29tbWl0IjoiMjkyR0ll
      TkxFbS1zeWNLWnh5RVVHQ1pncUdIT25EVWxSMnBnY1k3NlBZNCJ9.yDxXgTi95cwv7EFslor__8Nw8aj
      3cwSGyMTByTjw76Fg3X_1pnPSbtKXIRLeg3r0QO8wkOOJVd0qZ0jr65FlCw   (line breaks editorial)
reqHash = sha256(JWS bytes) = b88dfebdd5ad6d034cf26f1716743eccb2ca1ab00ed393c13286776b62cb9a02
```

### C.4 Envelope seal/open (§7.1)

Suite `PACT-HPKE-1`; sender key EK_S, recipient EK_R; `info = "PACT-1.0 env" || "ABEiM0RVZneImaq7zN3u_w"` (hex `504143542d312e3020656e76…`); AAD = the decoded bytes of the `protected` value in A.4; plaintext = the JSON-RPC body shown in C.4-pt below. Because HPKE encapsulation is randomized, this is a **decryption** vector: opening A.4's `enc`/`ct` with EK_R's private key and EK_S's public key MUST yield exactly:

```
pt = {"jsonrpc":"2.0","id":"1","method":"message/send","params":{"message":{"role":"user","parts":[{"kind":"text","text":"hello"}]}}}
```

Sealing implementations are verified by round-trip (seal then open) plus AAD-tamper rejection (flipping any protected byte MUST fail).

### C.5 Content digest (§7.3.2)

For the exact envelope JSON of A.4 serialized as `{"protected":…,"enc":…,"ct":…}` with the shown values and no whitespace: `Content-Digest: sha-256=:A+1+7z86l46Stc0IMn+fhPB5TQnkiddTUL4K0MgNIRM=:`

### C.6 Handle normalization (§11.1, §17.1)

`Alina@Agents.PACT.example` → `alina@agents.pact.example` (valid). `аlina@agents.pact.example` (Cyrillic а, U+0430) → REJECT at registration (UTS #39 confusable with existing `alina`); resolvers treat it as a distinct, unrelated handle.

---

## Appendix D. Public MCP façade profile *(optional; normative when implemented)*

An endpoint MAY additionally expose a remote MCP server presenting public-tier capability as tools — `request_contact(handle, note)`, `request_meeting(…)` mapping to `pact.pair.request` / `scheduling.inquire` — for third-party assistants that speak MCP but not A2A/PACT. It MUST be secured per the current MCP authorization spec (OAuth 2.1; client identity via Client ID Metadata Documents), MUST apply the same tier rules, untrusted-content rules, and admission bounds as the native public tier (§7.5.2, §8.2, §17.2), and MUST NOT expose paired-tier capability, accept scope grants, or return candidate slots. Client certificates are not expected on this surface (hosted MCP clients cannot present them); it is an untrusted-tier front door whose purpose is to convert strangers into pairing requests. MCP is otherwise the endpoint's private, inward tool layer and out of scope.

---

## Appendix E. Design rationale *(informative)*

Condensed from the v0.1 design decisions; full landscape argument in the companion document. **A2A profile, not a rival protocol** — adoption gravity, maintained task lifecycle, extension mechanism built for this. **Message security over channel security** — mTLS dies at every TLS-terminating edge, gateway, and queue; sealing at the message layer is what lets one pact span P2P, tunnels, and platforms (mTLS's *trust model* — pinned peer keys, mutual proof — is kept and enforced where TLS can't reach; Profile D adds real channel auth as defense-in-depth). **Owner key over account** — rotation without re-friending, portability across deployments, and honest custody tiers. **The friend request is the key ceremony** — the one high-quality out-of-band moment two humans share is used to move keys (DIDComm OOB + SPIFFE bundle-exchange + Signal safety-number lineage), with commit-reveal SAS closing the MITM window. **Deniable by default, on-the-record by choice** — personal messaging should not mint court-grade transcripts as a side effect; contracts (confirmations) can opt in. **Typed verbs over prose** — narrow, schema-validated negotiation is simultaneously the privacy mechanism (no free/busy dumps) and the prompt-injection firewall. **Convenience without required trust** — signed records, key transparency, ciphertext-only relays, and per-pact pseudonymous routing let an operator run everything while being able to prove it can read nothing and swap no keys undetected.

---

## Appendix F. Deployment guidance *(informative)*

**Platform-hosted (multi-tenant).** Endpoints as stateless HTTPS workloads; per-tenant routes are the §7.5 control plane; gateway and mailbox are shared services enforcing §14.6 quotas; directory + KT log operated per §11.4; custody per §15.4 (offer Sovereign; default Managed only with its obligations). Existing gateway data planes (agentgateway, ContextForge-style registries) fit the Gateway/Mailbox classes.
**Self-hosted behind NAT.** Preferred: Profile D (Iroh — no domain, no inbound ports; relays see ciphertext) plus a rented or self-run mailbox for sleep coverage. HTTPS alternative: own domain behind Cloudflare Tunnel or a Pangolin-style WireGuard ingress — acceptable *because* only sealed envelopes traverse the edge (the edge reads nothing; §7.1); raw-key TLS variants require SNI/TCP passthrough (§7.2). Register the identity did:web on the owned domain, or stay did:key with invitation-only pairing.
**Hybrid.** Hosted directory/mailbox/handle with local execution and Sovereign keys is expected to be the most common shape; nothing on the wire distinguishes the modes, and `pact.identity.update` (§9.1.14) migrates an identity between them without re-friending.

---

## Appendix G. Changelog and review disposition *(informative)*

**v1.0.0 (2026-08-23).** First public release. Produced from draft v0.1 after a three-lens adversarial review (protocol completeness: 37 findings; security/cryptography: 32; editorial/release-readiness: 25+structure). Every finding is dispositioned in the companion document; headline changes: envelope re-based on HPKE Auth mode with full AAD/context binding (was Base+JWS; fixes surreptitious forwarding, metadata malleability, and default non-repudiation); commit-reveal SAS with specified wordlist and vectors (was grindable and unimplementable); pairing request now sealed (was cleartext); transport key split from rotating agent keys (Profile D addresses no longer break on rotation); per-pact routeIds and gateway auth keys (infrastructure unlinkability); complete error model, HTTP/pickup/control-API contracts, lifecycle state machine with glare/timeout/suspend semantics, key/EK-grace/prekey lifecycles, freshness bounds, size/parameter registry, versioning policy; conformance classes; normative security, privacy, i18n, accessibility sections; custody-tier obligations incl. the pact transparency log; test vectors. Deferred to 1.1 (§13.3): PQ suite, ratchet FS, groups, multi-runtime senders, anonymous deposit tokens.
**v0.1 (2026-08-23).** Internal design study (superseded; its landscape/comparison content now lives in the companion document).

---

## Appendix H. Release checklist *(informative)*

| # | Blocker before announcing 1.0 final | Status |
|---|---|---|
| RB-1 | Name/trademark decision ("PACT" collides with pact.io contract testing); register final project domain; re-issue extension URI | Open |
| RB-2 | Public repository + issue tracker + spec home URL | Open |
| RB-3 | IANA registrations: media types (§14.7), `pact:` scheme, `/.well-known/pact` (RFC 8615) | Open |
| RB-4 | Publish JSON Schemas + conformance suite; reference implementation passes Appendix C | Open |
| RB-5 | Independent cryptographic review of §6.4, §7.1 (external to this project) | Open |
| RB-6 | Legal review of §16.5 data-protection statements per launch jurisdictions | Open |

---

## Acknowledgements

This design knowingly stands on: DIDComm v2 (out-of-band invitations, mediator/pickup store-and-forward), Signal (X3DH/PQXDH prekeys, safety numbers, key transparency), SPIFFE/SPIRE (trust-domain federation as consent), Matrix (cross-signing, SAS ceremonies), Tailscale (Tailnet Lock key continuity, node-sharing UX), WhatsApp AKD and Apple CKV (deployed key transparency), Iroh (keys as dialable addresses), the A2A and MCP projects and the AAIF, RFC 9421 deployments (Cloudflare Web Bot Auth), Pangolin and the self-hosted tunnel community, and ANEX as direct prior art for personal-agent scheduling negotiation. Errors are the editors' own.

*End of PACT 1.0.0.*
