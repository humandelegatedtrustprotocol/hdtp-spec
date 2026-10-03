> **ARCHIVED — historical, never released.** The first design study (v0.1): requirements, landscape research and the initial protocol sketch that led to the hardened draft and then to the current `SPEC.md`. Not a PACT version; nothing in it binds an implementation.

# PACT — Personal Agent Communication & Trust Protocol

**Specification draft v0.1 — August 2026**
*A protocol for person-to-person communication mediated by personal assistant agents, with friend-request key exchange, end-to-end security, and dual P2P / gateway deployment.*

> "PACT" is a working name (a pact = a mutual agreement between two parties, which is exactly what the pairing handshake creates). Rename freely.

---

## Table of contents

1. [Vision and requirements](#1-vision-and-requirements)
2. [Landscape: what already exists (Aug 2026)](#2-landscape-what-already-exists-aug-2026)
3. [Gap analysis: what I need vs what they have](#3-gap-analysis-what-i-need-vs-what-they-have)
4. [Design decisions and rationale](#4-design-decisions-and-rationale)
5. [Architecture overview](#5-architecture-overview)
6. [Identity model](#6-identity-model)
7. [Pairing: the friend-request handshake](#7-pairing-the-friend-request-handshake)
8. [Transport profiles (P2P, gateway, mailbox)](#8-transport-profiles)
9. [Message and task layer (A2A profile)](#9-message-and-task-layer-a2a-profile)
10. [Scheduling and messaging semantics](#10-scheduling-and-messaging-semantics)
11. [Authorization: per-friend scopes and human-in-the-loop](#11-authorization-per-friend-scopes-and-human-in-the-loop)
12. [Discovery and the directory](#12-discovery-and-the-directory)
13. [Deployment modes](#13-deployment-modes)
14. [MCP integration](#14-mcp-integration)
15. [Threat model and security considerations](#15-threat-model-and-security-considerations)
16. [Wire format examples](#16-wire-format-examples)
17. [End-to-end example: booking an appointment](#17-end-to-end-example-booking-an-appointment)
18. [Build vs reuse, and implementation roadmap](#18-build-vs-reuse-and-implementation-roadmap)
19. [References](#19-references)

---

## 1. Vision and requirements

### 1.1 The scenario

Every person has a **personal assistant agent** (an AI agent acting on their behalf). When Person B wants something from Person A — book an appointment, propose a meeting, pass a message, ask a question — B tells **B's own agent**, which contacts **A's agent** over the internet. A's agent applies A's policies (calendar rules, approval rules, privacy rules), negotiates with B's agent, and only involves A when a decision needs a human. The people never have to exchange raw availability, and neither agent talks to the other before the two humans have consented to be connected.

### 1.2 Hard requirements (from the brief)

| # | Requirement | Notes |
|---|-------------|-------|
| R1 | **Agent represents a person** | Identity must chain to a human owner, not just to a service. |
| R2 | **Consent-gated communication** | A "friend request" is sent and accepted before agents may talk. |
| R3 | **Mutual key exchange on acceptance** | mTLS-like: each side gives the other its key and pins the peer's key. All later traffic is mutually authenticated with those keys. |
| R4 | **P2P mode** | Two self-hosted agents can talk directly, no platform in the path. |
| R5 | **Gateway mode** | Agents can also talk through operated gateways (ours or others'). |
| R6 | **Self-hosting behind NAT** | A locally-run agent can be exposed via tunnels (e.g., Cloudflare Tunnel + custom domain) with generated keys. |
| R7 | **Platform-hosted mode** | We run the MCP/agent servers for customers, plus the directory of people/agents, the gateway, and the security layer beneath. |
| R8 | **Open, internet-scale protocol** | Should interoperate with the emerging agent ecosystem (A2A, MCP), not be a walled garden. |
| R9 | **Appointment booking as the flagship use case** | Plus generic person-to-person message relay through the two assistants. |

### 1.3 Derived requirements (implied by the hard ones)

- **D1 — Offline delivery.** A self-hosted agent may be off or unreachable; messages need store-and-forward without breaking E2E security.
- **D2 — Key rotation and revocation.** Keys leak, devices die, friendships end. Rotation must not require re-friending; unfriending must actually cut access.
- **D3 — Gateway must be untrusted for content.** If a gateway/tunnel/CDN sits in the path, it must not be able to read or forge messages (channel-level mTLS dies at TLS-terminating intermediaries — this forces message-level crypto; see §4.2).
- **D4 — Directory must be untrusted for keys.** A platform directory that maps names→keys can MITM silently unless key transparency and/or out-of-band verification exists.
- **D5 — Human approval loop.** The protocol needs first-class "waiting for my human" states, not just request/response.
- **D6 — Spam and abuse resistance.** Anyone-can-contact-anyone is email; the consent gate plus rate/reputation controls are load-bearing.
- **D7 — Prompt-injection containment.** Peer messages are adversarial input to an LLM. The protocol should favor structured, schema-validated payloads over free text wherever possible.

---

## 2. Landscape: what already exists (Aug 2026)

### 2.1 Agent-to-agent protocols

**A2A (Agent2Agent)** — the adoption winner. Originally Google, donated to the Linux Foundation (June 2025), **v1.0.0 released March 2026** (v1.0.1 May 2026), now moving under the Agentic AI Foundation (AAIF) alongside MCP. 150+ member orgs (AWS, Microsoft, Cisco, IBM, Salesforce, SAP, ServiceNow), shipped in Azure AI Foundry, Copilot Studio, Amazon Bedrock AgentCore, Google Cloud; 5 official SDKs (Python, JS, Java, Go, .NET).
Key mechanics relevant to PACT:

- **Agent Card** at `/.well-known/agent-card.json` (IANA-registered) describing skills, endpoints, and `securitySchemes` — which include an explicit **`MutualTlsSecurityScheme`**, plus OAuth2/OIDC/API-key/HTTP schemes.
- **Signed Agent Cards** (v1.0): JWS over the canonicalized card — cryptographic authenticity for the card itself.
- **Extended (authenticated) Agent Card**: a richer card revealed only after authentication — a natural "reveal more after friending" hook.
- **Task lifecycle**: `working`, `input-required`, `auth-required`, `completed`, `failed`, `canceled`, `rejected` — `input-required` and `auth-required` map directly onto human-approval and step-up-auth moments.
- **Transports**: JSON-RPC 2.0/HTTP, gRPC, REST; updates via polling, SSE streaming, and **push notifications to client-registered webhooks**.
- **Formal extension mechanism**: extension URIs declared in the Agent Card, `required: true` supported; ecosystem extensions already exist (AP2 payments, a2a-x402).

What A2A does **not** have: any pairing/consent handshake, any key-exchange primitive (mTLS provisioning is out of scope), any end-to-end encryption (TLS is hop-by-hop; gateways read plaintext), and no NAT-traversal/P2P story — it assumes agents are reachable HTTPS servers.

**MCP (Model Context Protocol)** — agent↔tool, not agent↔agent, and institutionally converging with A2A under AAIF. Current spec **2026-07-28**: stateless HTTP core (no session handshake; per-request `_meta`; `Mcp-Method`/`Mcp-Name` headers designed for gateway routing), Tasks as an extension, OAuth 2.1 authorization (RFC 9728 protected-resource metadata, RFC 8707 resource indicators mandatory, **Client ID Metadata Documents** replacing dynamic client registration — client identity is an HTTPS URL). SSE legacy transport deprecated. No mTLS story in the spec, no E2EE, and mainstream hosted MCP clients (claude.ai, ChatGPT, Cursor) cannot present client certificates — mTLS on an MCP endpoint only works when you control both ends. MCP matters to PACT as (a) the *inward* tool layer of each personal agent (calendar, email), and (b) an optional public façade for third-party assistants (§14).

**ANP (Agent Network Protocol)** — philosophically the closest match: `did:wba` DID-based identity (did:web extended for agents, single-request HTTP-signature auth, self-certifying key-thumbprint variant), **real end-to-end encryption** (ECDHE from DID keys; ANP 1.1 adds an X3DH-like prekey setup with Double-Ratchet-style protection for DMs and moves group E2EE toward IETF MLS bound to DIDs), JSON-LD Agent Description documents, `.well-known/agent-descriptions` discovery. Seeded the **W3C AI Agent Protocol Community Group** (267 participants). But: earliest-stage maturity, community implementations only (AgentConnect), spec churn, adoption thin outside its home community, third-party assessments put production viability at "late 2026 at best." **Verdict: mine it for design patterns; do not take it as a dependency.**

**AGNTCY (Cisco → Linux Foundation, July 2025)** — infrastructure for an "Internet of Agents", explicitly a carrier for A2A/MCP payloads. Components: OASF agent schemas + federated **Agent Directory Service**; **SLIM** messaging (now an IETF Internet-Draft) — gRPC/HTTP2 transport, point-to-point and group channels, **E2EE via MLS (RFC 9420)** so relay nodes cannot read content, SPIFFE/SPIRE identity federation; **Agent Badges** (W3C Verifiable Credentials bound to agent cards). Production use inside Webex. Heavy, enterprise-shaped, no consumer pairing story — but SLIM is the most production-grade E2EE agent relay design in existence and validates PACT's gateway profile.

**Dead / niche:** IBM **ACP** merged into A2A (Aug 2025) — do not build on it. NEAR **AITP** (personal-assistant↔service commerce, crypto-centric, ~no traction). **Agora** (academic meta-protocol negotiation — influential idea only). **Coral Protocol** (MCP-native thread runtime + Solana token — crypto-flavored, centralized). **Eclipse LMOS** (W3C Web-of-Things-based, DID identity, WIP). **ANEX** (ammonhaggerty) deserves special mention: a draft spec for *exactly* this vision — personal-agent handshake, FIPA contract-net negotiation, meeting scheduling as the flagship use case — but 14 commits, 3 stars, dormant. It is prior art for the verb design, and proof the idea is in the air but unbuilt.

### 2.2 Identity and key-exchange building blocks

- **mTLS with per-peer trust**: two workable shapes — (a) a tiny **private CA per user** (friend = exchange CA certs; rotation = reissue leaves under the same CA; tooling: smallstep `step-ca`, Vault PKI); (b) **pinned self-signed keys** with a key-continuity rule (new key signed by old — the Tailscale *Tailnet Lock* pattern). Pin the CA or the key, never the leaf cert. The fundamental problem: **mTLS dies at any TLS-terminating intermediary** (gateway, CDN, LB). Workarounds (SNI passthrough, terminate-and-forward-header, double mTLS) each lose something. IETF **WIMSE** reached the same conclusion and is standardizing app-level Workload Proof Tokens precisely because channel identity doesn't survive middleboxes.
- **SPIFFE/SPIRE federation** is architecturally a "friending" system for infrastructure: trust domain per party, one-time bundle exchange (the accept ceremony), auto-refreshed bundles, short-lived auto-rotated SVIDs, unfriend = drop the `federates_with` entry. Too heavy to run per consumer, but the *model* (trust-domain-per-person, bundle exchange on consent, short-lived leaf creds) is exactly right and PACT adopts it in spirit.
- **DIDComm v2** (DIF spec v2.1) is the closest complete blueprint for PACT's security layer: pairwise **did:peer** identities, **out-of-band invitation** (the friend request), sender-authenticated encryption (**ECDH-1PU authcrypt**), DID rotation, **mediators** with store-and-forward pickup protocols for offline/NATed agents, trust-ping. Weakness: library ecosystem is thin and unevenly maintained in 2026 (reference Rust/Python libs low-activity; credo-ts still v1-centric; Veramo usable for Node). Adopt the *shapes*; be prepared to implement the envelope yourself on modern primitives (HPKE).
- **Signal-family**: X3DH→**PQXDH** (post-quantum prekey agreement) for asynchronous first contact; safety numbers/QR for human mutual verification; and — new in **Aug 2026** — Signal's **Automatic Key Verification**: a key-transparency log (VRF-blinded identifiers, append-only Merkle trees, third-party auditors Cloudflare + Trail of Bits) that removes blind trust in the central key directory. WhatsApp (AKD, open-source `akd` Rust crate) and Apple (Contact Key Verification) shipped the same pattern earlier. **Key transparency is the 2026-consensus answer to D4** (directory MITM).
- **Matrix**: cross-signing (master key signs device keys; verify the human once, devices inherit trust) and SAS emoji/QR ceremonies are the best-studied human verification UX; Olm/Megolm E2EE is battle-tested but complex (2022 protocol vulns; Feb 2026 vodozemac findings). Running Matrix itself is a heavyweight but complete fallback option (friending = DM invite, federation = gateways, store-and-forward built in).
- **OAuth 2.1 / CIMD / Entra Agent ID / Okta for GenAI / Cloudflare Web Bot Auth**: the OAuth family models *user→client authorization*, not symmetric peer trust — usable as the façade for third-party clients (§14) but wrong as the friendship primitive. Cloudflare's Web Bot Auth (RFC 9421 HTTP Message Signatures + published Ed25519 key directories, adopted by AWS WAF) is the lightest-weight "authenticate an HTTP request from a keyholder" pattern and PACT reuses RFC 9421 for gateway-visible request signing.

### 2.3 Products: who does assistant-to-assistant today?

**Headline: nobody ships true assistant↔assistant negotiation between two different people's agents as their core loop.**

| Product / project | What it actually does | A2A between two people's agents? | Open / self-host | Status 2026 |
|---|---|---|---|---|
| x.ai (Amy) | Email-CC scheduling assistant | Same-platform shortcut claimed (unverified) | No | Dead (2021) |
| Clara Labs | Human-in-loop email scheduling | No — emails the human | No | Alive, niche |
| Reclaim.ai | Calendar optimization, booking links | No | No | Alive (absorbed Clockwise, sunset Mar 2026) |
| Motion | AI calendar + PM | No | No | Alive |
| **Cal.com** | Open-source scheduling infra; "Cal.com Agents" book *via API* | No — agent→booking-API, slots exposed, no negotiation | **Yes (AGPL)** | Alive; best OSS substrate for one side |
| Skej / Howie | Email/Slack assistant personas (~$15–25/mo) | No; two of them on one email thread would negotiate *emergently, unauthenticated* | No | Alive |
| Ohai.ai | SMS household assistant | Cross-household sync marketed, unverified | No | Alive |
| Google Gemini "Help me schedule" | Inserts your slots into Gmail; human clicks | No recipient-side agent | No | Alive |
| Microsoft Copilot Studio | **First-party A2A support** for org agents | Enterprise maker-configured, not personal | No | Alive |
| Lindy / Zapier Agents / Dust | Multi-agent within one account/org | No cross-user | No | Alive |
| Personal AI | Others DM your persona; your AI replies | Human→your-AI, one platform | No | Alive (enterprise pivot) |
| Alexa+ | Orchestrates *business* partner agents | Consumer→business, proprietary | No | Alive |
| **OpenClaw** (ex-Moltbot) | THE self-hosted personal agent of 2026 (MIT, huge installed base); `sessions_send` agent-to-agent **within one instance** only | No native cross-instance protocol, no identity/keys | **Yes (MIT)** | Very alive |
| **Moltbook** | Social network of OpenClaw agents; API-key auth, security holes; acquired by **Meta, Mar 2026** | Broadcast/social, not tasked negotiation | Partially | Absorbed |
| claw.events | Pub/sub (WebSocket) for cross-instance OpenClaw agents | Coordination yes; no E2E, no friend model | Yes (MIT) | Young |
| MindRoom | Agents as first-class **Matrix** users → federation gives cross-server agent rooms | Transport solved; no negotiation semantics | Yes | Young, real users |
| NANDA (MIT) | Index ("DNS for agents") + signed **AgentFacts** + registry federation | Discovery/trust layer only | Yes | Academic momentum |
| ERC-8004 | On-chain agent identity/reputation registries, composable with A2A | Identity layer only, crypto-adjacent | Yes | Real deployments |
| AgentMail | Inbox-per-agent; agent↔agent **over email** ($6M seed) | Yes, but unstructured, no E2E, no consent model | No | Alive |
| ANEX | Draft spec: personal-agent handshake + scheduling negotiation | On paper, exactly this | Yes | Dormant |

Independent confirmation of the gap (K. Heinrich, "Scheduling for agents"): current "agent-ready" scheduling tools are REST endpoints with AI wrappers; nobody implements agent↔agent negotiation; the missing verb set is request/propose/counter/accept/decline/reschedule/cancel with **privacy-preserving narrow queries** instead of exposed booking pages. PACT §10 adopts exactly this.

### 2.4 Deployment infrastructure

- **Remote MCP hosting**: the 2026-07-28 stateless spec makes agent endpoints plain stateless HTTPS workloads behind any LB — ideal for multi-tenant hosting. Dominant multi-tenant pattern: shared deployment + cryptographically random per-tenant URLs + audience-bound tokens (RFC 8707) + per-tenant tool filtering. Cloudflare's stack (Workers, `createMcpHandler`, Durable Objects when stateful, `workers-oauth-provider`, `mcp-remote` shim) is the reference SaaS implementation.
- **Gateways**: **agentgateway** (Rust, Linux Foundation, MCP+A2A+LLM routing, JWT/OAuth authn, CEL RBAC — best-in-class data plane), **IBM ContextForge** (gateway + registry + virtual servers + federation — closest prior art to "our gateway + directory"), Lasso (security plugins), Docker MCP Gateway (local packaging), LiteLLM, Kong/Azure APIM (enterprise API→MCP).
- **Tunnels** (self-hosting behind NAT):
  - **Cloudflare Tunnel**: free, custom domains, but **the edge terminates TLS and sees plaintext**; client certs (API Shield / Access mTLS) are verified *at the edge*, not your origin. Usable for PACT only because Profile G's message-level E2EE makes the edge blind (D3). Notably, **Anthropic's own "MCP tunnels" preview (Aug 2026) rides cloudflared with an inner TLS layer terminated inside your network so Cloudflare sees only metadata** — direct prior art for tunnel + inner-crypto layering.
  - **ngrok**: paid custom domains; TLS endpoints support true passthrough (`terminate_at: agent`) — E2E-capable; mTLS termination with BYO CA on higher tiers.
  - **Tailscale Funnel**: E2E (relay can't decrypt) but no custom domains, port-limited — hobby only. **Tailscale node sharing** is however a shipped, real "friend request" primitive (email/link invite, quarantined-by-default shared nodes) worth copying UX from.
  - **Pangolin** (21k+ stars, AGPL+commercial): identity-aware reverse proxy + WireGuard connectors (`newt`, outbound-only) — the self-hosted Cloudflare-Tunnel-alternative where *your* VPS terminates TLS. The exact shape for PACT's platform-run tunnel ingress. frp/rathole are the minimal DIY equivalents; boringproxy is dead.
- **True P2P**: **Iroh 1.0 (June 2026)** is the standout — "dial keys, not IPs": **ed25519 node IDs used directly as mTLS-style identity in the QUIC handshake**, NAT hole-punching that gets the large majority of traffic flowing directly (n0 reports ~95% of connection data passing peer-to-peer), transparent fallback to open-source, self-hostable relays that **cannot decrypt traffic**, wire-protocol stability guarantee, Rust/Python/Node/Swift/Kotlin bindings. This is literally requirement R3+R4 as a library. libp2p is the heavier alternative (DHT discovery, lower hole-punch rates); WebRTC only matters for browser-resident agents; WireGuard meshes (Tailscale/NetBird/Headscale) require shared-network membership — wrong shape for a friend graph.
- **Offline delivery**: DIDComm mediator + Message Pickup 3.0 is the purpose-built pattern (queue per recipient, poll or live WebSocket delivery, explicit acks, mediator sees only envelopes); pragmatic equivalents: NATS JetStream / MQTT persistent sessions with payloads sealed to the recipient key. MCP/A2A Tasks give the protocol-level async surface; email is a last-resort *notification* channel, never the data path.

---

## 3. Gap analysis: what I need vs what they have

Scoring the serious candidates against the requirements (✅ has it, 🟡 partial, ❌ missing):

| Requirement | A2A v1.0 | MCP 2026-07 | ANP 1.1 | DIDComm v2 | AGNTCY/SLIM | Matrix | Iroh (transport) | OpenClaw eco | Cal.com | Schedulers (Howie et al.) |
|---|---|---|---|---|---|---|---|---|---|---|
| R1 person-owned agent identity | 🟡 signed cards, no human chain | ❌ | ✅ DID | ✅ DID | 🟡 VC badges | ✅ MXID + cross-signing | 🟡 node key only | ❌ API keys | ❌ accounts | ❌ |
| R2 consent gate (friend request) | ❌ | ❌ | 🟡 DID auth ≈ | ✅ OOB invitation | ❌ | ✅ room invite | ❌ | ❌ | ❌ | ❌ |
| R3 mutual key exchange + pinning | 🟡 mTLS scheme declared, provisioning out of scope | ❌ | ✅ ECDHE/X3DH-like | ✅ authcrypt | ✅ MLS | ✅ Olm | ✅ key = address | ❌ | ❌ | ❌ |
| R4 P2P | ❌ | ❌ | 🟡 | ✅ via mediators | 🟡 relay mesh | 🟡 federation | ✅ ~90% direct | ❌ | ❌ | ❌ |
| R5 gateway mode | ✅ | ✅ | ✅ | ✅ mediators | ✅ | ✅ homeservers | ✅ relays | 🟡 central | ✅ SaaS | ✅ SaaS |
| R6 self-host behind NAT | 🟡 BYO | 🟡 BYO | 🟡 | ✅ | 🟡 | ✅ | ✅ | ✅ | ✅ | ❌ |
| R7 platform-hostable multi-tenant | ✅ | ✅ | 🟡 | 🟡 | ✅ | ✅ | ✅ | 🟡 | ✅ | ✅ |
| R8 open + ecosystem adoption | ✅✅ | ✅✅ | 🟡 W3C CG | 🟡 DIF | 🟡 LF/IETF | ✅ | ✅ OSS | ✅ OSS | ✅ | ❌ |
| R9 scheduling/negotiation semantics | ❌ generic tasks | ❌ tools | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | 🟡 slots API, no negotiation | 🟡 email NL |
| D1 offline store-and-forward | 🟡 push webhooks | 🟡 tasks | 🟡 | ✅ pickup protocol | 🟡 | ✅ | 🟡 needs mailbox | ❌ | n/a | n/a |
| D3 E2EE past gateways | ❌ | ❌ | ✅ | ✅ | ✅ MLS | ✅ | ✅ | ❌ | ❌ | ❌ |
| D4 directory key transparency | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | n/a | ❌ | n/a | n/a |
| Maturity / production adoption | ✅✅ | ✅✅ | ❌ | 🟡 | 🟡 | ✅ | ✅ new but solid | ✅ users, no protocol | ✅ | ✅ |

**Conclusions.**

1. **No single system covers the loop.** Every row-winner is missing either consent+keys (A2A, MCP), adoption (ANP, DIDComm), semantics (everything), or openness (all commercial schedulers). Every existing player has at most two of: open negotiation semantics, key-based friend pairing, P2P with gateway fallback, self-hostable agent, directory.
2. **The consent/pairing gap is universal** — nobody specifies "friend request → mutual credential exchange." Nearest primitives: DIDComm OOB invitations, SPIFFE bundle exchange, Tailscale node sharing, A2A `auth-required` + extended card. This is PACT's genuinely novel contribution (§7).
3. **The mainstream stack (A2A+MCP) is hop-by-hop TLS only.** Any gateway-hosted deployment exposes plaintext to the gateway. E2EE must be added at the message layer — which ANP, DIDComm, SLIM, and Matrix all independently concluded.
4. **Adoption gravity says: be an A2A profile, not a rival protocol.** A2A has the ecosystem, the task lifecycle, the discovery convention, and a formal extension mechanism designed for exactly this kind of layering.
5. **Iroh solves R3+R4 at the transport level for free** (key = address = mTLS identity, relay fallback, E2E through relays) — the P2P mode should not be built from scratch.
6. **Key transparency (Signal/WhatsApp/Apple pattern)** is how a platform directory earns "security key managed" without becoming a silent MITM — none of the agent protocols have it yet; PACT should (§12.3).
7. **The OpenClaw ecosystem is the proof of demand**: a huge installed base of self-hosted personal agents with *no* native cross-instance identity or protocol, improvising over Moltbook/claw.events with API keys. The whitespace is real and currently being filled badly.

---

## 4. Design decisions and rationale

**DD1 — Layer PACT on A2A v1.0 as a formal extension, not a new message protocol.**
PACT defines the extension URI `https://pact.dev/ext/pact/v1` (placeholder), declared `required: true` in the Agent Card for friend-scoped endpoints. Messages, tasks, artifacts, streaming, and push notifications are plain A2A; PACT adds (a) the pairing handshake methods, (b) the E2E envelope, (c) scheduling/messaging verb schemas, (d) per-friend scope semantics. Rationale: R8/gap-conclusion 4 — interop with Copilot Studio, Bedrock, Azure agents comes for free at the unpaired tier, and the spec inherits a maintained task lifecycle instead of inventing one. (ANEX died partly because it was an island.)

**DD2 — Message-level security is primary; channel mTLS is transport hygiene.**
The unit of security is the **sealed PACT envelope** (§8.4): HPKE (RFC 9180) encryption to the recipient's current agent key + Ed25519 signature by the sender's agent key, with DIDComm v2 authcrypt (ECDH-1PU) as the specified interop-compatible alternative. Rationale: D3 — mTLS cannot survive Cloudflare Tunnel edges, platform gateways, or store-and-forward mailboxes, and the brief explicitly wants all three. Direct P2P connections *additionally* get channel-level mutual auth (Iroh QUIC / raw-key TLS §8.2), giving true defense-in-depth in P2P mode — this is the honest version of "mTLS-like": the *trust model* of mTLS (pinned peer keys, mutual proof of possession) enforced at the message layer where TLS can't reach.

**DD3 — Identity = per-person keypair, expressed as a DID, with agent keys delegated under it.**
An **Owner Key** (Ed25519, held by the person/their device or, custodially, by the platform tier they chose) is the root of the person's agent identity. **Agent Keys** are certified by the Owner Key with scoped, expiring delegation certificates (Matrix cross-signing / SPIFFE short-lived-SVID pattern). Published as a DID document: `did:web` (hosted or own-domain), self-certifying `did:key` (pure P2P), pairwise `did:peer` (privacy option). Rationale: R1, D2 — rotation of agent keys never requires re-friending; owner-key rotation uses key-continuity (new signed by old) plus directory/KT re-attestation; DIDs keep the identity portable across our platform, self-hosting, and other vendors, and align with where ANP/W3C CG, AGNTCY badges, and NANDA AgentFacts are all heading.

**DD4 — The friend request IS the key ceremony.**
Modeled on DIDComm out-of-band invitations + SPIFFE bundle exchange + Signal safety numbers (§7): the request carries the requester's full key material and desired scopes; acceptance returns the accepter's; both sides pin. The one high-quality out-of-band moment (two humans who already know each other) is used to move keys, so TOFU is avoided at pairing time; an optional SAS "safety phrase" ceremony covers directory-MITM paranoia and re-verification after owner-key rotation. Rationale: R2, R3, D4.

**DD5 — Three transport profiles, one envelope.**
Profile **D** (direct P2P over Iroh/QUIC or raw-key TLS), Profile **G** (gateway-relayed HTTPS), Profile **M** (mailbox store-and-forward for offline peers). The sealed envelope is identical across all three; profiles differ only in how bytes move. Every pact records the peer's transport preferences ordered by priority; senders try D, fall back G, queue M. Rationale: R4, R5, D1 — and it means a self-hosted agent and a platform-hosted agent interoperate without either caring how the other is deployed.

**DD6 — Scheduling is a typed verb vocabulary, not free text.**
`scheduling.*` DataPart schemas (§10) implementing request/propose/counter/accept/confirm/decline/cancel/reschedule with narrow, policy-filtered candidate slots — never raw free/busy dumps. Free-text parts ride along for nuance but are never load-bearing. Rationale: R9, D7 — schema-validated structure is both the privacy answer (Heinrich's "narrow queries") and the prompt-injection answer (the receiving agent acts on validated fields, not on persuasive prose).

**DD7 — The platform is convenience, not a trust requirement.**
Directory lookups are verifiable (signed records + key-transparency log §12.3), gateways relay ciphertext, mailboxes queue ciphertext, and any component can be self-hosted or federated. The platform's honest value: hosting agents, running reliable relays/mailboxes/tunnel ingress, operating the directory + KT log, and UX. Rationale: R7+R8 without building a walled garden — and it is the only architecture where "we maintain the security layer beneath" and "users can leave" are simultaneously true.

**DD8 — Unpaired contact is allowed but quarantined.**
A stranger's agent (or any vanilla A2A/MCP client) may reach the **public tier** of an agent: discovery card, `pact.pair.request`, and whatever low-risk skills the owner exposes publicly (e.g., "request a meeting; my human will see it as a contact request"). Everything else requires a pact. Rationale: D6 — the consent gate is the spam firewall, but a hard-closed system would kill the "anyone can send a friend request" bootstrap, and A2A-ecosystem interop (DD1) demands a public surface.

---

## 5. Architecture overview

```
        Person A                                            Person B
           │ owns/approves                                     │
   ┌───────┴────────┐                                 ┌────────┴───────┐
   │ Personal Agent │                                 │ Personal Agent │
   │  (A's policies,│                                 │  (B's policies,│
   │   LLM, memory) │                                 │   LLM, memory) │
   └───┬────────┬───┘                                 └───┬────────┬───┘
       │ MCP    │ PACT endpoint                 PACT      │ MCP    │
       ▼        │ (A2A + PACT ext)              endpoint  ▼        │
  [calendar]    │                                    [calendar]    │
  [email]       │                                    [email]       │
  [tools...]    │                                    [tools...]    │
                │                                                  │
                │   Profile D: direct P2P (Iroh QUIC, keys=addrs)  │
                ├──────────────────────────────────────────────────┤
                │                                                  │
                │   Profile G: via gateway(s) — ciphertext only    │
                ├──────────► [Gateway/Relay] ◄─────────────────────┤
                │                                                  │
                │   Profile M: mailbox store-and-forward           │
                └──────────► [Mailbox svc] ─── pickup ────────────►│

   Supporting planes (platform-run, federatable, or self-hosted):
   [Directory: handle → signed identity record + agent card]
   [Key Transparency log: append-only, audited]
   [Tunnel ingress: for NATed self-hosters (CF Tunnel / Pangolin-style)]
```

**Components.**

- **Personal Agent (PA)** — the assistant runtime: LLM + policies + memory + the person's tools via MCP. Runs anywhere (our platform, home server, VPS).
- **PACT Endpoint** — the PA's internet-facing surface: an A2A v1.0 server with the PACT extension. Serves the public Agent Card; enforces tiering (public vs paired).
- **Pact Store** — the local database of pacts (friend records): peer identity, pinned keys, scopes granted/received, transport hints, state.
- **Gateway/Relay** — routes sealed envelopes between endpoints it fronts; terminates public TLS; never holds plaintext or long-term keys. May be ours, a peer's, or absent.
- **Mailbox** — per-recipient ciphertext queue with a pickup protocol (DIDComm Message Pickup 3.0 semantics) for offline peers.
- **Directory** — maps handles to signed identity records + agent cards; backed by the **KT log**. Federatable (§12.4).
- **Tunnel connector** — outbound-only process on a self-hosted node (cloudflared, Pangolin `newt`, or Iroh's built-in relay dialing) making it reachable.

---

## 6. Identity model

### 6.1 Keys

| Key | Alg | Held by | Lifetime | Purpose |
|---|---|---|---|---|
| **Owner Key** `IK_owner` | Ed25519 | The person (device keychain / hardware key / platform custody for the managed tier) | Years; rotated by continuity | Root of identity. Signs delegations, pact acceptances, identity record updates, revocations. |
| **Agent Key** `IK_agent` | Ed25519 | The PA runtime | 30–90 days, auto-rotated | Signs every envelope; authenticates transports. Certified by `IK_owner` via a **Delegation**. |
| **Agent KEM Key** `EK_agent` | X25519 | The PA runtime | Rotated with `IK_agent` | HPKE recipient key for sealed envelopes. |
| **Prekeys** | X25519, signed | Published to mailbox/directory | One-time / short-lived | Allow first sealed message to an offline peer (Signal X3DH pattern; PQ-hybrid upgrade path §15.6). |

**Delegation** (owner→agent), a JWS by `IK_owner`:

```json
{
  "typ": "pact-delegation+jws",
  "sub": "did:key:z6Mk...agent",
  "iss": "did:web:agents.example.com:alice",
  "scopes": ["pact:*", "scheduling:*", "messaging:*"],
  "nbf": 1755900000, "exp": 1763676000,
  "continuity": null
}
```

Verifiers MUST check: envelope signature by `IK_agent` → valid unexpired delegation → chains to the pinned `IK_owner` of that pact. Compromise of an agent key is bounded by delegation expiry; the owner revokes by publishing a new identity record without it (and, for paired peers, a `pact.key.revoke` notice §7.6).

### 6.2 DID representation

The person's agent identity is a DID document containing `IK_owner` (as the authoritative `verificationMethod`), current agent keys/delegations, and `service` entries for PACT endpoints, mailbox, and transport hints.

- **Hosted / own domain:** `did:web:agents.pact.example:alice` or `did:web:alice.dev` — resolvable at `https://…/.well-known/did.json`. Human handle `alice@agents.pact.example` maps to it (§12.1). did:web's known weakness — the server can swap keys silently — is exactly what the KT log (§12.3) and pact-time pinning neutralize.
- **Pure P2P / no domain:** `did:key:z6Mk…` derived from `IK_owner` — self-certifying, no infrastructure. Reachability data then travels inside invitations and pact records (Iroh node ID + relay hints).
- **Privacy option:** pairwise `did:peer` per relationship, so pacts are unlinkable across a person's relationships. Optional in v0.1.

### 6.3 Agent Card binding

The public A2A Agent Card at `/.well-known/agent-card.json` MUST be a **Signed Agent Card** (A2A v1.0 JWS) whose signing key is verifiable via the DID document, and MUST declare the PACT extension with the DID:

```json
{
  "name": "Alice's assistant",
  "url": "https://alice.agents.pact.example/a2a",
  "capabilities": { "extensions": [ {
      "uri": "https://pact.dev/ext/pact/v1",
      "required": false,
      "params": { "did": "did:web:agents.pact.example:alice",
                  "pairing": "https://alice.agents.pact.example/pact/pair",
                  "tiers": { "public": ["pact.pair.request", "scheduling.request"] } } } ] },
  "securitySchemes": { "pact-envelope": { "type": "mutualTLS", "description": "see PACT §8" } },
  "signatures": [ { "protected": "...", "signature": "..." } ]
}
```

The **extended Agent Card** (A2A authenticated-card mechanism) is served only to paired peers and reveals paired-tier skills and transport details.

---

## 7. Pairing: the friend-request handshake

Pairing turns two strangers' agents into mutually-keyed peers. It is deliberately human-gated on both ends: **agents transport the request; people approve it.**

### 7.1 Pact states

`none → requested → active ⇄ suspended → revoked` (terminal). Either side may suspend (pause without deleting keys) or revoke (unfriend).

### 7.2 Initiation paths

1. **Directory path:** B searches the directory for `alice@agents.pact.example` (or scans Alice's profile QR), fetches her signed identity record + agent card, verifies the KT-log inclusion proof, then sends `pact.pair.request` to her public pairing endpoint.
2. **Out-of-band invitation path (no directory needed):** Alice generates an invitation — URL or QR:

```
pact://invite?v=1
  &did=did:key:z6MkAlice...
  &ik=ed25519:base64url(IK_owner)
  &hint=iroh:nodeid+relay | https://alice.dev/pact
  &sk=base64url(single-use invitation secret)
  &exp=1756000000
  &sig=base64url(Ed25519 sig by IK_owner over all fields)
```

She hands it to Bob over any existing channel (chat, email, in person). Possession of `sk` authorizes exactly one `pair.request`, which MUST include `sk` — this rate-limits strangers and binds the request to the out-of-band moment. Invitation-path requests MAY be auto-surfaced with higher trust ("you invited this person").

### 7.3 Handshake messages

All pairing messages are JWS objects signed by the sender's `IK_owner` (the one moment where the human-root key signs directly), carried as A2A messages with a `pact.pair.*` DataPart. The request is sent to the public tier in the clear (it contains only public material); the accept is sealed to the requester's keys.

**`pact.pair.request`** (Bob → Alice):

```json
{
  "type": "pact.pair.request", "pactId": "uuid-v7", "nonce": "…",
  "from": { "did": "did:web:agents.pact.example:bob",
            "identityRecord": { "…full signed record: IK_owner, agent keys, delegations, endpoints, prekeys…" } },
  "to":   { "did": "did:web:agents.pact.example:alice" },
  "invitation": "sk-if-invitation-path",
  "requestedScopes": ["scheduling.request", "messaging.deliver"],
  "offeredScopes":   ["scheduling.request", "messaging.deliver"],
  "displayName": "Bob Mehta",
  "humanNote": "We met at the Pune conference — let's let our assistants coordinate.",
  "exp": 1756100000
}
```

**Processing at Alice's agent:** verify JWS against the *included* identity record; cross-check the record against directory + KT proof when available (mismatch ⇒ warn or reject); create task in `input-required`; surface to Alice with `displayName`, `humanNote`, verification status, and requested scopes. **The agent never auto-accepts a pact** (policy MAY auto-*reject*, e.g., block-lists).

**`pact.pair.accept`** (Alice → Bob, sealed to Bob's keys):

```json
{
  "type": "pact.pair.accept", "pactId": "…", "nonce": "…", "reqHash": "sha256:…",
  "from": { "did": "…alice", "identityRecord": { "…" } },
  "grantedScopes": ["scheduling.request", "messaging.deliver"],
  "acceptedScopes": ["scheduling.request"],
  "transports": [
    { "profile": "D", "iroh": "nodeid…", "relays": ["relay.pact.example"] },
    { "profile": "G", "url": "https://alice.agents.pact.example/a2a" },
    { "profile": "M", "mailbox": "https://mbx.pact.example/alice" } ],
  "sas": "commitment:sha256:…"
}
```

`reqHash` binds accept to the exact request (no substitution). Both sides now write the **pact record**: peer DID, **pinned `IK_owner`**, current agent keys, scopes in each direction, transports, state `active`. Bob's agent completes with **`pact.pair.finish`** (sealed, echoes `reqHash`, confirms his transports), then a sealed **`pact.ping`** in each direction proves both envelope directions work (DIDComm trust-ping analog). A `pact.pair.reject` (optionally with a human note) is the decline path; unanswered requests expire.

### 7.4 Human verification (SAS) — optional but recommended

Both agents derive `SAS = wordlist(HKDF(sort(IK_owner_A ‖ IK_owner_B) ‖ pactId, "pact-sas-v1"))` → e.g., 4 words. The apps show them; the humans compare via any existing channel. Matches Signal safety numbers / Matrix SAS. UX policy: invitation-path pacts may skip it (the OOB link already carried the keys); directory-path pacts SHOULD prompt once; a KT-verified directory lookup downgrades this to "verify if paranoid."

### 7.5 Rotation

- **Agent keys:** rotate freely; new delegations signed by `IK_owner` are pushed to active peers via sealed `pact.key.update` and published in the identity record. Peers accept any key with a valid delegation chain to the pinned owner key — no ceremony.
- **Owner key:** new `IK_owner'` must carry a **continuity statement** signed by the old key (`{"continuity": {"prev": "ed25519:…", "sig": "…"}}`), be re-published to the directory/KT log, and be announced via `pact.key.update`. Peers verify continuity OR re-run SAS. A rotation *without* continuity (lost key) demotes the pact to `suspended` pending human re-verification — this is deliberate: it is the only honest option after total key loss.

### 7.6 Revocation / unfriending

`pact.revoke` (signed by `IK_owner`, sealed) → both sides mark `revoked`, delete transport hints, drop the peer from mailbox ACLs, and gateways/mailboxes operated by either side stop accepting envelopes for that pair. Because authorization is checked per-message against the pact store (never against a bearer artifact), revocation is immediate on the revoker's side even if the peer never acks. Suspension is the reversible variant.

---

## 8. Transport profiles

One sealed envelope (§8.4); three ways to move it. Senders MUST try the peer's transports in the pact record's priority order; a delivery is the same protocol event regardless of profile.

### 8.2 Profile D — Direct P2P

- **Reference transport: Iroh 1.0.** Each PACT endpoint runs an Iroh endpoint whose ed25519 node key **is** `IK_agent` (or a key delegated from it). Dialing a friend = dialing their pinned key; the QUIC handshake gives mutual channel authentication against exactly the pinned material ("mTLS-like" fulfilled at the channel layer), with NAT hole-punching carrying most traffic directly and automatic fallback through self-hostable relays that carry only ciphertext. A2A JSON-RPC runs over the QUIC stream; envelopes are still sealed (defense-in-depth, and so a captured relay stream is useless).
- **Alternative: raw-key TLS.** For HTTPS-native stacks: TLS 1.3 where each side presents a self-signed cert whose SPKI MUST equal the pact's pinned agent key (RFC 7250 raw-public-key mode where stacks allow). Only sound end-to-end — i.e., direct connection or SNI/TCP-passthrough tunnels (ngrok `terminate_at: agent`, rathole, Tailscale Funnel); NEVER behind a TLS-terminating edge.

### 8.3 Profile G — Gateway

Envelope POSTed over ordinary WebPKI HTTPS to the peer's gateway URL (`/pact/inbox`), which routes on the **outer header only** (recipient DID hash, msg id, size, expiry) to the destination agent (direct connection, tunnel, or its own queue). Sender authenticity to the *gateway* (for rate-limiting/abuse control, since the gateway can't read the envelope) uses **RFC 9421 HTTP Message Signatures** keyed by the sender's agent key — the Cloudflare Web Bot Auth pattern. Gateways are interchangeable and see: who-to-whom (DID-hash level), when, how big. They never see content, and cannot forge (no keys). This is the profile that makes Cloudflare Tunnel acceptable despite edge TLS termination (D3): the edge relays ciphertext.

### 8.4 The sealed envelope

```json
{
  "pact": "v1",
  "outer": { "to": "sha256(did+pactId)", "id": "uuid-v7", "cty": "a2a-message+json",
             "exp": 1756000600, "profileHint": "G" },
  "sealed": {
    "alg": "HPKE-Base-X25519-SHA256-ChaCha20Poly1305",
    "enc": "base64url(encapsulated key)",
    "kid": "recipient EK_agent id (or prekey id)",
    "ct":  "base64url(ciphertext of { payload, sig })"
  }
}
```

The plaintext is `{ "payload": <A2A message/task JSON>, "sig": JWS(payload, IK_agent_sender), "seq": n, "ts": … }`. Recipient verifies: HPKE opens with its current key → signature chains via a valid delegation to the pinned peer `IK_owner` → `seq`/`id` unseen (replay) → `ts`/`exp` sane. **Interop note:** a conforming implementation MAY instead use DIDComm v2 authcrypt (ECDH-1PU+A256KW) as the sealing layer — semantically equivalent (sender-authenticated encryption); the mandatory-to-implement is the HPKE+JWS form above because 2026 library support (HPKE, JOSE) is broader and better maintained than the DIDComm stacks. First-contact-while-offline uses the peer's published signed prekeys (X3DH-style) so even the initial sealed message never waits for the peer to come online.

### 8.5 Profile M — Mailbox (offline delivery)

Same envelope, queued. Semantics lifted from DIDComm Message Pickup 3.0: per-recipient ciphertext queue; recipient authenticates with its agent key (RFC 9421) and either polls (`status → delivery(batch) → ack`) or holds a WebSocket/long-poll for live handoff; explicit acks delete; TTL from `outer.exp`; mailbox ACL = active pacts only (revocation removes the sender's write access). A mailbox is run by the platform, by a self-hoster for themselves, or by any third party — it holds ciphertext and metadata only. Push notification to wake a sleeping self-hosted node MAY use A2A push-notification webhooks or plain APNs/FCM/ntfy with zero content ("you have mail").

---

## 9. Message and task layer (A2A profile)

PACT payloads are standard **A2A v1.0** messages and tasks; this section only profiles A2A and registers the extension's verbs.

- **Conformance:** endpoints MUST implement A2A JSON-RPC binding; gRPC/REST optional. `message/send`, `tasks/get`, `tasks/cancel`, `tasks/list` required; streaming (SSE) and push notifications recommended.
- **Tiering:** every skill in the Agent Card is tagged `tier: public` or `tier: paired`. Paired-tier calls MUST arrive as sealed envelopes under an active pact with a scope covering the verb; public-tier calls follow vanilla A2A auth (or none) — see DD8.
- **Task lifecycle mapping:** long negotiations are A2A tasks. `input-required` = "waiting for a human" (either side); `auth-required` = step-up (e.g., the verb needs a scope this pact lacks — the human can grant it inline); `rejected` = policy refusal; `completed` carries the final artifact (e.g., the confirmed event).
- **Verb envelope:** every PACT DataPart is `{ "verb": "<namespace.action>", "v": 1, "body": { …schema-valid… } }`. Unknown verbs ⇒ A2A error `UnsupportedOperationError`, never silent free-text fallback (D7).
- **Idempotency & ordering:** message ids are UUIDv7; `seq` is per-pact monotonic per direction; receivers de-duplicate on id and MAY reorder on `seq`. Retries reuse ids (ANP 1.1's idempotency lesson).

Namespaces in v0.1: `pact.*` (pairing/keys/lifecycle — §7), `scheduling.*`, `messaging.*` (§10), `presence.*` (optional). Everything else is future extension space (payments via A2A's AP2 slot in in an obvious candidate).

---

## 10. Scheduling and messaging semantics

### 10.1 Scheduling verbs

The negotiation vocabulary (aligned with the verb set the market analysis says is missing — request/propose/counter/accept/decline/reschedule/cancel — and with privacy-preserving narrow queries):

| Verb | Direction | Body (core fields) |
|---|---|---|
| `scheduling.request` | initiator → | `intent` (meet/call/visit), `durationMin`, `window` (earliest/latest ISO-8601, TZ), `constraints` (times-of-day, days, location/mode), `subject`, `priority`, `expiresAt` |
| `scheduling.propose` | responder → | `slots[]` (≤5 of `{start, end, mode, location?}`), `holdUntil?` (soft holds), `note?` |
| `scheduling.counter` | either → | same shape as propose; references `inReplyTo` |
| `scheduling.accept` | either → | `slot`, `inReplyTo` |
| `scheduling.confirm` | responder → | `event` (title, start/end, TZ, mode, location/URL, attendees), `ics` (base64 iCalendar, both agents write it to their calendars via MCP), `bookingRef` |
| `scheduling.decline` | either → | `reason?` (enum: no-availability, declined-by-user, out-of-scope), `retryAfter?` |
| `scheduling.cancel` / `scheduling.reschedule` | either → | `bookingRef`, `reason?`; reschedule embeds a fresh `request` |

**Privacy rules (normative):** a responder MUST NOT return raw free/busy data; it returns only concrete candidate slots already filtered through its owner's policy (working hours, buffers, per-friend visibility class — e.g., family sees evenings, business contacts don't). Proposals are capped (≤5 slots) so iterative narrowing, not calendar disclosure, is the mechanism. `holdUntil` lets an agent soft-reserve offered slots to prevent double-booking across concurrent negotiations; holds auto-expire.

**State machine per negotiation task:** `request → (propose|decline) → (accept|counter)* → confirm → [cancel|reschedule]*`, with any human-gated step surfacing as A2A `input-required`. Both agents SHOULD enforce a counter-depth limit (default 4) then escalate to their humans — two LLMs politely countering forever is a real failure mode.

### 10.2 Messaging verbs (person-to-person relay)

- `messaging.deliver` — body: `{ "text" | "parts": [A2A parts], "urgency": normal|priority, "replyRequested": bool }`. The receiving agent decides per policy: show to the human, summarize into a digest, or answer autonomously on the person's *stated* behalf (never impersonating — see §15.5).
- `messaging.receipt` — delivered/read/answered signals, policy-gated (owners choose whether receipts are shared).
- `presence.query` / `presence.state` (optional scope) — coarse states only (`available | busy | away | do-not-disturb`), never location.

---

## 11. Authorization: per-friend scopes and human-in-the-loop

### 11.1 Scopes

Granted at pairing, adjustable anytime via sealed `pact.scopes.update` (either grant or retract; retraction is immediate locally, as with revocation).

```
scheduling.request      may open scheduling negotiations with me
scheduling.autobook     negotiations may complete WITHOUT my per-event approval,
                        inside my policy limits (durations, hours, count/week)
messaging.deliver       may deliver messages to me
messaging.priority      may mark messages priority (can breach DND)
presence.read           may query coarse presence
tasks.delegate          may ask my agent to do things beyond the above (dangerous; off by default)
```

Scopes are directional and asymmetric (Alice may grant Bob `scheduling.autobook` while holding only `scheduling.request` from him).

### 11.2 Policy engine (informative)

Each PA evaluates every inbound verb against owner policy: **allow-auto** (act within limits, notify after), **ask** (surface as `input-required`), **deny** (reject with reason). Recommended defaults: pairing = always ask (normative, §7.3); first negotiation with a new pact = ask; subsequent within granted scopes = auto; anything touching money, third parties, or `tasks.delegate` = ask. Policies are local implementation detail — the *protocol* only sees their outcomes as task states, which keeps policy innovation out of the interop surface.

---

## 12. Discovery and the directory

### 12.1 Handles

`name@domain` (deliberately email-shaped — humans already know how to share these). Resolution: `https://domain/.well-known/pact/{name}` → **signed identity record**; the same domain serves the A2A agent card. A person on our platform is `sumit@agents.pact.example`; a self-hoster is `sumit@sumit.dev`; both are first-class (R8). WebFinger-style aliasing MAY map existing emails to handles.

### 12.2 Identity record

```json
{
  "handle": "alice@agents.pact.example",
  "did": "did:web:agents.pact.example:alice",
  "ownerKey": "ed25519:…",
  "continuityChain": ["…prev keys w/ sigs…"],
  "agentKeys": [ { "kid": "…", "key": "ed25519:…", "kem": "x25519:…", "delegation": "…jws…" } ],
  "prekeys": { "url": "https://mbx.pact.example/alice/prekeys" },
  "agentCard": "https://alice.agents.pact.example/.well-known/agent-card.json",
  "transports": [ …as in §7.3 accept… ],
  "visibility": "listed | unlisted",
  "proof": { "jws": "…sig by ownerKey…", "kt": { "log": "https://kt.pact.example", "leaf": "…", "sth": "…", "inclusion": "…" } }
}
```

`unlisted` records resolve only with an invitation secret — invite-only people stay discoverable to their invitees and nobody else (D6).

### 12.3 Key transparency (platform mode, normative for our directory)

The directory appends every (handle, ownerKey, agentKeys-hash) state change to an append-only Merkle log (VRF-blinded handles — WhatsApp AKD / Signal AKV construction; Meta's open-source `akd` crate is the reference implementation). Clients: verify inclusion proofs on lookup; **monitor their own entry** (your agent alarms if the platform ever publishes a key for you that you didn't create); gossip signed tree heads. Third-party auditors watch for forks. Result: the platform operates the directory but **cannot silently substitute keys** — the property that makes "we manage the security layer" compatible with "you don't have to trust us" (D4, DD7). Self-hosted did:web users get the same benefit by having their record mirrored into (any) KT log; SAS (§7.4) remains the belt-and-suspenders for the paranoid.

### 12.4 Federation

Directories peer the way registries are converging generally (NANDA "registry quilt" model): a PACT directory serves its own domain's records authoritatively and proxies/caches lookups for foreign domains by fetching their well-known records + KT proofs. No global root; the domain in the handle is the authority pointer, exactly like email/Matrix/XMPP.

---

## 13. Deployment modes

### 13.1 Mode 1 — Platform-hosted ("we run it")

- **PA runtime:** stateless A2A/MCP workloads (2026-07-28-style), multi-tenant: shared deployment, per-tenant cryptographically-random endpoint paths, per-tenant encrypted credential store for MCP tool creds (calendar OAuth etc.), per-tenant tool filtering. Prior art: Cloudflare `createMcpHandler` pattern, Truto-style multi-tenant architecture; gateway data plane per agentgateway, registry/virtual-server ideas per IBM ContextForge.
- **Keys:** two custody tiers, chosen per user. **Managed:** platform HSM/KMS holds `IK_owner`, envelope sealing happens server-side — E2E to the *platform boundary*, honest marketing required ("we hold your keys"). **Sovereign:** `IK_owner` lives in the user's device app/passkey-style; the hosted PA holds only its delegated agent keys; owner-key operations (pairing accepts, revocations, rotations) are signed on the device. Sovereign is the differentiator — offer it from day one, default Managed for frictionless onboarding, one-tap upgrade.
- **Platform services:** directory + KT log, gateways, mailboxes, tunnel ingress for hybrid users, abuse control (invitation quotas, RFC 9421-verified rate limits, pair-request reputation), billing.

### 13.2 Mode 2 — Self-hosted behind NAT (tunnels)

The PA runs at home (the OpenClaw-shaped audience). Reachability options, best first:

1. **Iroh-native (recommended default):** no domain, no tunnel config — the node dials out to relays; friends dial its key. Works behind any NAT; relays (ours or public) see ciphertext only. Handle can still be platform-hosted (`user@agents.pact.example`) pointing at Profile D/M transports.
2. **Own domain + Cloudflare Tunnel:** `cloudflared` + custom domain gives a stable HTTPS Profile-G endpoint and did:web identity. The CF edge sees TLS-plaintext of the *transport*, but only sealed envelopes traverse it — acceptable by construction (D3). This matches the layering Anthropic's MCP-tunnels preview uses (outer tunnel, inner crypto). Access service tokens optionally shield the endpoint from scanning noise.
3. **Pangolin-style / own VPS (frp, rathole):** for users who want no third party at all in the path; VPS terminates TLS, envelopes keep it blind. Platform can also *operate* Pangolin-like ingress as a service for self-hosters (tunnel ingress above).

Offline coverage: self-hosted nodes SHOULD register a mailbox (ours or self-run) so peers get Profile M when the home node sleeps.

### 13.3 Mode 3 — Hybrid

Hosted directory/mailbox/gateway + local execution and keys. Likely the most popular real-world shape: the platform gives 24/7 reachability and the handle; the agent and keys stay home. Nothing in the protocol distinguishes the modes — a pact between a Mode-1 user and a Mode-2 user is symmetric.

---

## 14. MCP integration

- **Inward (private):** the PA consumes the owner's tools via MCP — calendar, mail, contacts, task managers. This is standard MCP (2026-07-28), entirely inside the trust boundary; per-tenant credential injection in Mode 1. The scheduling verbs (§10) are *implemented* against these tools (freebusy computation, event creation from `scheduling.confirm.ics`).
- **Outward (public MCP façade, optional):** the PACT endpoint MAY additionally expose a remote MCP server presenting public-tier capability as tools — `request_meeting(...)`, `leave_message(...)`, `request_contact(...)` — secured with vanilla OAuth 2.1 (CIMD client identity). Purpose: the long tail of third-party assistants that speak MCP but not A2A/PACT can still *initiate* contact; everything lands in the same quarantined public tier (DD8) and can be upsold into a real pact ("this agent's owner wants to connect — approve?"). Do not attempt mTLS on this façade: hosted MCP clients cannot present client certs; the façade is untrusted-tier by design.
- **Positioning:** MCP = agent→tool (vertical), A2A+PACT = agent↔agent (horizontal). This mirrors the ecosystem's own layering and keeps us aligned with where AAIF is taking both specs.

---

## 15. Threat model and security considerations

| # | Threat | Mitigation |
|---|---|---|
| T1 | Impersonation at pairing ("I'm Alice") | Keys travel inside the signed request/accept; directory + KT proof cross-check; SAS ceremony; invitation path binds to an existing human channel. Residual: social engineering of the *human* — display names are labeled unverified; show handle + verification status prominently. |
| T2 | Directory/platform key substitution (MITM) | KT log + self-monitoring agents + auditors (§12.3); pinning at pact time means post-pairing substitution is detected as an invalid delegation chain. |
| T3 | Malicious/curious gateway, tunnel edge, mailbox | They carry sealed envelopes only; sender authenticity is inside the envelope; RFC 9421 outer signatures stop them forging even *valid-looking* traffic for rate-limit fraud. Metadata (who-to-whom, timing, size) remains visible — documented honestly; pairwise did:peer + padding are the v2 metadata-privacy path. |
| T4 | Stolen agent key | Delegations expire in ≤90 days; owner revokes instantly via identity record + `pact.key.revoke`; per-message verification means no lingering bearer artifacts. |
| T5 | Lost owner key | Continuity chain impossible ⇒ pacts auto-suspend pending human re-verification (§7.5). Recovery UX (social recovery, platform escrow for Managed tier) is product-layer. |
| T6 | Replay / reorder / duplication | UUIDv7 ids + per-pact `seq` + `exp`; receivers de-dupe; idempotent verb handling (§9). |
| T7 | Spam / unsolicited contact flood | Consent gate (nothing but `pair.request` reaches an unpaired inbox); invitation secrets; per-sender pairing quotas at gateways; directory `unlisted`; pair-request reputation signals in platform mode. |
| T8 | **Prompt injection via peer content** | The most agent-specific threat: a peer's `humanNote` or message text is adversarial LLM input. Normative: verbs/schemas are the only load-bearing surface (D7); free text MUST be treated as untrusted data (rendered to humans, summarized defensively, never executed as instructions); the PA's tool access while processing inbound content SHOULD be confined to the verb's needs (e.g., processing `scheduling.request` can read freebusy policy, not send email). |
| T9 | Over-delegation / runaway agents | Scopes are minimal-by-default, directional, human-granted; `autobook` bounded by owner limits; counter-depth limits; audit log of every cross-pact action shown to the owner. |
| T10 | Compromised PA runtime (Mode 1) | Sovereign key tier keeps `IK_owner` off the platform; per-tenant isolation; tenant credentials encrypted at rest, decrypted only in call path. The Managed tier's weaker story is disclosed, not hidden. |

**15.6 Cryptographic agility & PQ.** v0.1 suites: Ed25519 / X25519-HPKE (ChaCha20-Poly1305) / SHA-256; every artifact carries `alg`/`v` fields. Planned v0.2: hybrid X25519+ML-KEM-768 HPKE for sealing and PQXDH-style prekey bundles — tracking Signal's deployed design, since sealed envelopes are the harvest-now-decrypt-later surface.

---

## 16. Wire format examples

**A `scheduling.request` as a full A2A message (plaintext form, pre-sealing):**

```json
{
  "jsonrpc": "2.0", "id": 42, "method": "message/send",
  "params": { "message": {
    "role": "user",
    "parts": [
      { "kind": "data", "data": { "verb": "scheduling.request", "v": 1, "body": {
          "intent": "meet", "subject": "Catch-up over coffee",
          "durationMin": 45,
          "window": { "earliest": "2026-08-25T00:00:00+05:30", "latest": "2026-08-29T23:59:59+05:30", "tz": "Asia/Kolkata" },
          "constraints": { "daysOfWeek": ["Tue","Wed","Thu"], "timeOfDay": ["morning","afternoon"], "mode": "in-person", "area": "Koregaon Park, Pune" },
          "priority": "normal", "expiresAt": "2026-08-24T18:00:00+05:30" } } },
      { "kind": "text", "text": "Bob says: long overdue, keen to catch up before month-end." }
    ],
    "messageId": "0198f6a2-…", "taskId": null,
    "metadata": { "pact": { "pactId": "…", "seq": 17 } }
  } }
}
```

This JSON is what gets signed (JWS by Bob's agent key), sealed (HPKE to Alice's agent KEM key), wrapped in the outer envelope (§8.4), and moved by whichever profile is live. Alice's agent replies on the created task with `scheduling.propose` (≤5 slots), and so on to `scheduling.confirm` carrying the ICS both sides write to their calendars via MCP.

---

## 17. End-to-end example: booking an appointment

Sumit (self-hosted, Mode 2, Iroh + Cloudflare Tunnel) ↔ Dr. Rao (platform-hosted, Mode 1, sovereign keys).

1. **Connect.** Dr. Rao's clinic profile QR is a PACT invitation. Sumit scans it; his agent sends `pact.pair.request` (invitation path) with `requestedScopes: [scheduling.request]`. Rao's assistant surfaces it; Rao taps accept on her phone (sovereign tier: her device signs `pact.pair.accept`). Both sides pin keys; sealed pings confirm. Elapsed: seconds; humans involved: two taps.
2. **Request.** Weeks later: "book me a consultation with Dr. Rao next week, mornings." Sumit's agent opens a task with `scheduling.request` (30 min, next-week window, mornings, Asia/Kolkata), sealed, Profile D attempt → Rao's platform gateway (Profile G) since no direct path exists.
3. **Negotiate.** Rao's agent checks her calendar via MCP + her policy (patients get Tue/Thu 9–12 only, 15-min buffers, max 8/week) → `scheduling.propose` with 3 slots, `holdUntil` +24h. Sumit's agent cross-checks his calendar, auto-accepts the Tuesday 09:30 (within his standing auto-book policy for healthcare) → `scheduling.accept`.
4. **Confirm.** Rao's policy says new-patient bookings need her nod → task `input-required`; she approves in her morning digest → `scheduling.confirm` with event + ICS + `bookingRef`. Both agents write calendars via MCP. Sumit gets a notification card; nobody saw anybody's calendar; no phone tag, no booking page.
5. **Change.** Rao gets sick: her agent emits `scheduling.reschedule` referencing `bookingRef` with a fresh window; the loop re-runs; Sumit's Mode-2 node happens to be asleep, so the envelope waits in his mailbox (Profile M) and his phone gets a contentless push.

---

## 18. Build vs reuse, and implementation roadmap

### 18.1 Build-vs-reuse decisions

| Layer | Decision | Source |
|---|---|---|
| Task/message semantics, discovery card | **Reuse** A2A v1.0 + extension mechanism | a2aproject SDKs |
| Sealed envelope | **Build (thin)** on HPKE (RFC 9180) + JOSE libs; DIDComm-compat optional | hpke-js/rust, jose |
| Pairing handshake | **Build** — this is the novel part; shapes from DIDComm OOB + SPIFFE federation + Signal SAS | — |
| P2P transport | **Reuse** Iroh 1.0 (keys-as-addresses, relays) | n0-computer/iroh |
| Gateway data plane | **Reuse/extend** agentgateway (Rust, LF) or ContextForge patterns | agentgateway, IBM |
| Tunnel ingress for self-hosters | **Reuse** cloudflared for BYO-domain; Pangolin-style (Traefik+WG) for platform ingress | cloudflared, fosrl/pangolin |
| Mailbox | **Build (small)** with DIDComm Pickup-3.0 semantics over NATS JetStream/Postgres | — |
| Directory + KT | **Build** directory (simple signed records); **reuse** Meta `akd` for the transparency log | facebook/akd |
| Scheduling verbs | **Build** schemas (§10); calendar execution via existing MCP servers; Cal.com API as an optional backend | Cal.com OSS |
| Agent runtime | **Integrate**, don't build first: ship the PACT endpoint as (a) our hosted PA, (b) an **OpenClaw plugin/skill** — instant self-hosted install base | openclaw |

### 18.2 Roadmap

- **Phase 1 — Hosted MVP (one mode, full loop).** Platform-hosted PAs (Managed keys), directory (no KT yet, but records signed from day one), gateway, mailbox, pairing handshake, sealed envelopes, `scheduling.*` + `messaging.deliver`, calendar MCP (Google/Microsoft/Cal.com). Success = two customers' assistants book a real meeting with zero calendar disclosure.
- **Phase 2 — Self-hosting + sovereignty.** Open-source reference node (Docker single-container: PA-adapter + PACT endpoint + Iroh), OpenClaw plugin, cloudflared/Pangolin recipes, sovereign key tier (device-held owner keys), mailbox for sleeping nodes, `pact.key.*` rotation flows. Success = a self-hosted node pairs and books against a hosted one with the platform unable to read any of it.
- **Phase 3 — Trust at scale.** KT log + self-monitoring + auditors, directory federation, `unlisted`/invitation quotas/reputation, SAS UX polish, `scheduling.autobook` + policy engine maturity, public MCP façade.
- **Phase 4 — Ecosystem.** Publish the extension spec + test suite; propose the pairing/E2EE extension upstream (A2A extensions registry / AAIF, W3C AI Agent Protocol CG as venue); PQ-hybrid suites; payments via AP2 slot; group pacts (household/team — MLS becomes relevant only here).

### 18.3 What to watch (could change decisions)

- **A2A↔MCP convergence under AAIF** (joint interop work reported for late 2026) — keep the extension surface small so a merged spec is an easy retarget.
- **IETF WIMSE** Workload Proof Tokens — if standardized, a candidate replacement for our RFC 9421 outer-auth layer.
- **Signal AKV / `akd` maturation** — ride their auditor ecosystem rather than bootstrapping our own.
- **Meta × Moltbook** — a proprietary consumer agent network is likely coming; PACT's counter-position is *open + E2E + self-hostable*, so keep those non-negotiable.
- **ANP/W3C CG** — if did:wba gains real adoption, add it as a supported DID method (cheap: it's did:web-shaped).

---

## 19. References

**Protocols & specs:** A2A v1.0 spec & extensions (a2a-protocol.org; github.com/a2aproject/A2A) · MCP 2026-07-28 & 2025-11-25 specs (modelcontextprotocol.io; blog.modelcontextprotocol.io) · ANP & did:wba (agent-network-protocol.com) · W3C AI Agent Protocol CG (w3.org/community/agentprotocol) · DIDComm v2.1 (identity.foundation/didcomm-messaging) · did:peer (identity.foundation/peer-did-method-spec) · AGNTCY & SLIM I-D (agntcy.org; draft-mpsb-agntcy-slim) · SPIFFE federation (spiffe.io) · WIMSE drafts (draft-ietf-wimse-arch, -s2s-protocol) · HPKE RFC 9180 · MLS RFC 9420 · HTTP Message Signatures RFC 9421 · GNAP RFC 9635 · OAuth resource indicators RFC 8707 · Protected resource metadata RFC 9728.

**Key management & transparency:** Signal PQXDH & Automatic Key Verification (signal.org/blog/automatic-key-verification) · WhatsApp AKD (engineering.fb.com; github.com/facebook/akd) · Apple Contact Key Verification (security.apple.com) · Matrix cross-signing (matrix.org) · Tailscale Tailnet Lock whitepaper · Cloudflare Web Bot Auth / signed agents (blog.cloudflare.com/signed-agents).

**Infrastructure:** Iroh 1.0 (iroh.computer/blog/v1) · agentgateway (agentgateway.dev) · IBM ContextForge (github.com/IBM/mcp-context-forge) · Cloudflare Tunnel & API Shield mTLS docs (developers.cloudflare.com) · Anthropic MCP tunnels (platform.claude.com/docs — research preview) · Pangolin (github.com/fosrl/pangolin) · DIDComm Message Pickup 3.0 (didcomm.org/messagepickup/3.0) · Truto multi-tenant MCP architecture (truto.one/blog).

**Market:** LF A2A press (linuxfoundation.org) · ACP→A2A merge (lfaidata.foundation) · agent-registry survey (arxiv.org/html/2508.03095) · NANDA index & AgentFacts (media.mit.edu; github.com/projnanda) · ERC-8004 (ethereum-magicians.org) · K. Heinrich, "Scheduling for agents" (kurtheinrich.com/blog/scheduling-for-agents) · ANEX (github.com/ammonhaggerty/ANEX) · OpenClaw (github.com/openclaw/openclaw) · Meta–Moltbook acquisition (fortune.com, Mar 2026) · Cal.com agents docs (cal.com/docs/agents) · Clockwise sunset→Reclaim (reclaim.ai/blog) · AgentMail (agentmail.to).

---

*End of PACT v0.1 draft. Known open questions for v0.2: group pacts (MLS), metadata privacy (pairwise DIDs, padding, sealed-sender), payments (AP2), delegation to third-party agents ("my agent asks your agent's *lawyer* agent"), and PQ-hybrid suites.*
