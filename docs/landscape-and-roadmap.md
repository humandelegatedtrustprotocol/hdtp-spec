# PACT: Landscape, Comparison & Roadmap

**Companion document to the PACT 1.0 specification — informative throughout.**
**Date:** 2026-08-23. Research current as of August 2026.

This document carries the material that informed the design but does not bind implementers: the survey of existing protocols, products, and infrastructure; the requirements-versus-existing-systems comparison; the design rationale in full; build-vs-reuse guidance and roadmap for an operator; and the disposition of every finding from the pre-release review of draft v0.1. The normative protocol is defined solely by *PACT 1.0 — Specification*.

---

## 1. The requirement

Each person has a personal assistant agent. Person B's agent contacts Person A's agent over the internet — to book an appointment or pass a message — only after a friend request has been sent and accepted, at which point the two sides exchange keys and pin them, mTLS-style. The system must work peer-to-peer between self-hosted agents (including home machines exposed via tunnels such as Cloudflare Tunnel with a public domain), through operated gateways, and as a hosted platform where an operator runs the agents/MCP servers, the directory of people and their agents, the gateway, and the security layer beneath — with all modes interoperating.

Derived needs: offline store-and-forward; key rotation and revocation without re-friending; gateways untrusted for content; directories untrusted for keys (verifiable, not believed); first-class human-approval states; spam resistance via the consent gate; prompt-injection containment via structured payloads.

---

## 2. Landscape (August 2026)

### 2.1 Agent-to-agent protocols

**A2A (Agent2Agent)** — the adoption winner. Google → Linux Foundation (June 2025), v1.0.0 released March 2026 (v1.0.1 May 2026), moving under the Agentic AI Foundation (AAIF) alongside MCP. 150+ member organizations (AWS, Microsoft, Cisco, IBM, Salesforce, SAP, ServiceNow); shipped in Azure AI Foundry, Copilot Studio, Amazon Bedrock AgentCore, Google Cloud; five official SDKs. Mechanics PACT builds on: Agent Card at an IANA-registered well-known URI with declared security schemes (including a first-class mutual-TLS scheme); signed Agent Cards (JWS); an extended card revealed only after authentication; task lifecycle with `input-required` and `auth-required` interrupted states; JSON-RPC/gRPC/REST bindings, SSE streaming, push-notification webhooks; a formal extension mechanism already used by ecosystem extensions (AP2 payments, x402). What A2A lacks — and why PACT exists as its extension: no pairing/consent handshake, no key-exchange primitive, no end-to-end encryption (TLS is hop-by-hop; gateways read plaintext), no NAT/P2P story.

**MCP** — agent↔tool, not agent↔agent; converging institutionally with A2A under AAIF. Spec 2026-07-28: stateless HTTP core, per-request metadata, routing headers designed for gateways, tasks as an extension, OAuth 2.1 authorization with protected-resource metadata, resource indicators, and Client ID Metadata Documents; legacy SSE transport deprecated. Mainstream hosted MCP clients cannot present client certificates, so mTLS on a public MCP endpoint only works between parties who control both ends. In PACT, MCP is each agent's private tool layer (calendar, mail), plus the optional public façade of Appendix D.

**ANP (Agent Network Protocol)** — philosophically the closest prior art: `did:wba` identity (did:web extended for agents; single-request HTTP-signature auth; a self-certifying key-thumbprint variant), true end-to-end encryption from DID keys (ANP 1.1 adds an X3DH-like prekey setup with Double-Ratchet-style protection and moves group E2EE toward MLS bound to DIDs), JSON-LD agent descriptions, well-known discovery manifests. Seeded the W3C AI Agent Protocol Community Group (~267 participants). Maturity is the problem: community implementations only, spec churn, thin adoption outside its home community; third-party assessments put production viability at late 2026 at the earliest. PACT mines the design patterns without taking the dependency.

**AGNTCY (Cisco → Linux Foundation, July 2025)** — "Internet of Agents" infrastructure, explicitly a carrier for A2A/MCP payloads: OASF agent schemas and a federated Agent Directory Service; SLIM messaging (an IETF Internet-Draft) with gRPC/HTTP2 transport, point-to-point and group channels, and end-to-end encryption via MLS so relay nodes cannot read content; SPIFFE/SPIRE identity federation; Agent Badges as W3C Verifiable Credentials. Production use inside Webex. Enterprise-shaped, no consumer pairing story — but SLIM is the most production-grade E2EE agent relay design in the field and independently validates PACT's gateway profile (encrypted payloads through untrusted relays).

**Dead or niche:** IBM ACP merged into A2A (August 2025). NEAR AITP (personal-assistant↔service commerce, crypto-centric, negligible traction). Agora (academic meta-protocol negotiation — influential idea only). Coral Protocol (MCP-native thread runtime plus a Solana token; centralized, niche). Eclipse LMOS (Web-of-Things-based, DID identity, work in progress). **ANEX** deserves special mention: a draft spec for exactly this vision — personal-agent handshake, contract-net negotiation, meeting scheduling as the flagship use case — dormant at a handful of commits and stars. It is direct prior art for the verb design and proof that the idea was in the air but unbuilt.

### 2.2 Identity and key-exchange building blocks

**mTLS with per-peer trust** works in two shapes: a tiny private CA per user (friend = exchange CA certs; rotate leaves freely; smallstep/Vault tooling) or pinned self-signed keys with a key-continuity rule (new key signed by old — the Tailscale Tailnet Lock pattern). Either way, the fundamental limit is that channel-level mTLS dies at any TLS-terminating intermediary — gateway, CDN, load balancer — and the workarounds (SNI passthrough, terminate-and-forward-identity headers, double mTLS) each lose something. IETF WIMSE reached the same conclusion and is standardizing application-level workload proof tokens for exactly this reason. This is why PACT enforces the mTLS *trust model* (pinned peer keys, mutual proof of possession) at the message layer, and keeps channel-level key-pinned QUIC/TLS for the direct profile only.

**SPIFFE/SPIRE federation** is architecturally a friending system for infrastructure: a trust domain per party, a one-time bundle exchange as the accept ceremony, auto-refreshed bundles, short-lived auto-rotated credentials, and unfriending by dropping the federation entry. Too heavy to run per consumer; the model (trust-root per person, consent-time exchange, short-lived operational credentials) is exactly right and PACT adopts it in spirit — including, after review, SPIFFE-style short delegation lifetimes (days, not months).

**DIDComm v2** is the closest complete blueprint for the security layer: pairwise DIDs, out-of-band invitations (the friend-request analog), sender-authenticated encryption (ECDH-1PU authcrypt — deniable, like PACT's HPKE Auth choice), DID rotation, and mediators with store-and-forward pickup protocols that directly inspired Profile M. Its weakness in 2026 is the library ecosystem: reference implementations are low-activity, the major frameworks remain v1-centric, and momentum in the SSI world shifted toward credential presentation rather than messaging. PACT adopts the shapes on modern primitives (HPKE, JOSE) rather than depending on DIDComm stacks.

**Signal-family machinery** supplied three pieces: PQXDH-style prekey bundles for first contact while offline; safety numbers evolved into PACT's commit-reveal SAS; and — as of Signal's August 2026 launch of Automatic Key Verification, with Cloudflare and Trail of Bits as third-party auditors — deployed proof that key transparency logs (VRF-blinded identifiers, append-only Merkle trees, self-monitoring clients, external auditors) are the consensus answer to "run a key directory nobody has to trust." WhatsApp's Auditable Key Directory (open-source `akd` library) and Apple's Contact Key Verification shipped the same construction earlier. Matrix contributed the cross-signing idea (verify the human once; devices inherit) and the SAS ceremony UX.

**OAuth 2.1 / GNAP / vendor agent-identity work** (Entra Agent ID, Auth0 for GenAI, Cloudflare Web Bot Auth) model user→client authorization or agent→website identification, not symmetric peer trust; PACT uses the OAuth stack only on the optional public MCP façade, and reuses the RFC 9421 signed-request pattern (as deployed by Cloudflare Web Bot Auth and adopted by AWS WAF) for infrastructure admission control.

### 2.3 Products: who does assistant-to-assistant today?

Headline: **no shipping product does true assistant-to-assistant negotiation between two different people's agents as its core loop.** Independent confirmation of the same gap and of the missing verb set (request/propose/counter/accept/decline/reschedule/cancel with privacy-preserving narrow queries): K. Heinrich, "Scheduling for agents."

| Product / project | What it actually does | Agents of two people talk? | Open / self-host | Status 2026 |
|---|---|---|---|---|
| x.ai (Amy) | Email-CC scheduling assistant | Same-platform shortcut claimed (unverified) | No | Dead (2021) |
| Clara Labs | Human-in-loop email scheduling | No — emails the human | No | Alive, niche |
| Reclaim.ai | Calendar optimization, booking links | No | No | Alive; absorbed Clockwise (sunset Mar 2026) |
| Motion | AI calendar + project management | No | No | Alive |
| Cal.com | Open-source scheduling infra; agents book via API | No — agent→booking API, slots exposed, no negotiation | Yes (AGPL) | Alive; best OSS substrate for one side |
| Skej / Howie | Email/Slack assistant personas | No; two on one thread would negotiate emergently, unauthenticated | No | Alive |
| Ohai.ai | SMS household assistant | Cross-household sync marketed, unverified | No | Alive |
| Google Gemini scheduling | Inserts your slots into Gmail; human clicks | No recipient-side agent | No | Alive |
| Microsoft Copilot Studio | First-party A2A support | Enterprise maker-configured agents, not personal | No | Alive |
| Lindy / Zapier Agents / Dust | Multi-agent within one account/org | No cross-user | No | Alive |
| Personal AI | Humans DM your persona; your AI replies | Human→your-AI, one platform | No | Alive (enterprise pivot) |
| Amazon Alexa+ | Orchestrates business partner agents | Consumer→business, proprietary | No | Alive |
| OpenClaw | Leading self-hosted personal agent (MIT); agent-to-agent within one instance | No cross-instance protocol, no identity/keys | Yes (MIT) | Very alive |
| Moltbook | Social network of OpenClaw agents; API-key auth; acquired by Meta (Mar 2026) | Broadcast/social, not tasked negotiation | Partially | Absorbed |
| claw.events | Pub/sub for cross-instance OpenClaw agents | Coordination, no E2EE, no friend model | Yes (MIT) | Young |
| MindRoom | Agents as first-class Matrix users (federation!) | Transport solved; no negotiation semantics | Yes | Young, real users |
| NANDA (MIT) | Index ("DNS for agents"), signed AgentFacts, registry federation | Discovery/trust layer only | Yes | Academic momentum |
| ERC-8004 | On-chain agent identity/reputation registries | Identity layer only, crypto-adjacent | Yes | Real deployments |
| AgentMail | Inbox-per-agent; agent↔agent over email | Yes, but unstructured, no E2EE, no consent model | No | Alive ($6M seed) |
| ANEX | Draft spec: personal-agent handshake + scheduling | On paper, exactly this | Yes | Dormant |

The OpenClaw ecosystem is the clearest proof of demand: a large installed base of self-hosted personal agents with no native cross-instance identity or protocol, improvising over Moltbook and claw.events with API keys — the whitespace PACT's self-hosted profile targets directly.

### 2.4 Deployment infrastructure

**Remote MCP/agent hosting:** the stateless 2026 direction makes agent endpoints plain HTTPS workloads behind any load balancer; the dominant multi-tenant pattern is a shared deployment with cryptographically random per-tenant paths, audience-bound tokens, and per-tenant tool filtering — the shape PACT's per-pact routeIds generalize.
**Gateways:** agentgateway (Rust, Linux Foundation; MCP+A2A routing, authn, RBAC) and IBM ContextForge (gateway + registry + virtual servers + federation) are the closest prior art for the Gateway/Mailbox conformance classes; Lasso, Docker MCP Gateway, LiteLLM, Kong and Azure APIM fill adjacent niches.
**Tunnels:** Cloudflare Tunnel is free with custom domains but terminates TLS at the edge (client certificates, where used, are verified at the edge, not the origin) — acceptable for PACT only because sealed envelopes make the edge blind; notably Anthropic's own MCP-tunnels preview (August 2026) layers inner encryption over cloudflared for the same reason. ngrok offers true TLS passthrough on paid tiers; Tailscale Funnel is end-to-end but domain- and port-limited; Pangolin (21k+ stars) is the leading self-hosted identity-aware ingress (WireGuard connectors, your VPS terminates TLS); frp/rathole are the minimal DIY relays; boringproxy is dead. Tailscale node sharing remains the best shipped "friend request" UX precedent.
**True P2P:** Iroh 1.0 (June 2026) is the standout — node identifiers are ed25519 public keys used directly as the QUIC handshake identity ("dial keys, not IPs"), with NAT hole-punching carrying the large majority of traffic directly (the project reports ~95% of connection data flowing peer-to-peer) and automatic fallback through open-source, self-hostable relays that cannot decrypt; wire-protocol stability guarantee; Rust/Python/Node/Swift/Kotlin bindings. libp2p is the heavier alternative; WebRTC matters only for browser-resident agents; WireGuard meshes require shared-network membership — the wrong shape for a friend graph.
**Offline delivery:** DIDComm mediator + Message Pickup semantics (adopted, concretized, in Profile M); pragmatic backends include NATS JetStream or MQTT persistent sessions holding sealed envelopes; content-free push (APNs/FCM/ntfy) wakes sleeping nodes.

---

## 3. Comparison: requirements versus existing systems

Legend: ✅ has it · 🟡 partial · ❌ missing. (A2A and MCP columns reflect the base protocols without PACT.)

| Requirement | A2A v1.0 | MCP 2026-07 | ANP 1.1 | DIDComm v2 | AGNTCY/SLIM | Matrix | Iroh (transport) | OpenClaw eco | Cal.com | Schedulers |
|---|---|---|---|---|---|---|---|---|---|---|
| Person-owned agent identity | 🟡 signed cards | ❌ | ✅ DID | ✅ DID | 🟡 VC badges | ✅ MXID+cross-sign | 🟡 node key | ❌ API keys | ❌ accounts | ❌ |
| Consent gate (friend request) | ❌ | ❌ | 🟡 DID auth | ✅ OOB invitation | ❌ | ✅ room invite | ❌ | ❌ | ❌ | ❌ |
| Mutual key exchange + pinning | 🟡 mTLS declared, unprovisioned | ❌ | ✅ | ✅ | ✅ MLS | ✅ | ✅ key=address | ❌ | ❌ | ❌ |
| P2P | ❌ | ❌ | 🟡 | ✅ via mediators | 🟡 relay mesh | 🟡 federation | ✅ | ❌ | ❌ | ❌ |
| Gateway mode | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ relays | 🟡 central | ✅ SaaS | ✅ SaaS |
| Self-host behind NAT | 🟡 BYO | 🟡 BYO | 🟡 | ✅ | 🟡 | ✅ | ✅ | ✅ | ✅ | ❌ |
| Platform-hostable multi-tenant | ✅ | ✅ | 🟡 | 🟡 | ✅ | ✅ | ✅ | 🟡 | ✅ | ✅ |
| Open + ecosystem adoption | ✅ strong | ✅ strong | 🟡 W3C CG | 🟡 DIF | 🟡 LF/IETF | ✅ | ✅ OSS | ✅ OSS | ✅ | ❌ |
| Scheduling/negotiation semantics | ❌ generic tasks | ❌ tools | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | 🟡 slots, no negotiation | 🟡 email NL |
| Offline store-and-forward | 🟡 push hooks | 🟡 tasks | 🟡 | ✅ pickup | 🟡 | ✅ | 🟡 needs mailbox | ❌ | n/a | n/a |
| E2EE past gateways | ❌ | ❌ | ✅ | ✅ | ✅ MLS | ✅ | ✅ | ❌ | ❌ | ❌ |
| Directory key transparency | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | n/a | ❌ | n/a | n/a |
| Maturity / production adoption | ✅ strong | ✅ strong | ❌ | 🟡 | 🟡 | ✅ | ✅ new, solid | ✅ users, no protocol | ✅ | ✅ |

Conclusions that shaped PACT: (1) no single system covers the loop — each candidate misses consent+keys, adoption, semantics, or openness; (2) the consent/pairing gap is universal — nobody specifies friend-request → mutual key exchange, making §6 of the specification the genuinely novel contribution; (3) the mainstream A2A+MCP stack is hop-by-hop TLS, so gateway deployments require message-layer E2EE — the same conclusion ANP, DIDComm, SLIM, and Matrix reached independently; (4) adoption gravity says be an A2A profile, not a rival; (5) Iroh solves keys-as-addresses P2P as a library; (6) key transparency is how a hosted directory earns "security-key-managed" without becoming a silent MITM; (7) the OpenClaw ecosystem proves the demand and currently fills it badly.
---

## 4. Design decisions in full

**DD1 — Layer on A2A v1.0 as a formal extension.** Messages, tasks, artifacts, streaming, and discovery are plain A2A; PACT adds pairing, the sealed envelope, verb schemas, and per-pact scopes. Interop with the A2A ecosystem comes free at the public tier, and the spec inherits a maintained task lifecycle. (ANEX died partly by being an island.)

**DD2 — Message-level security is primary; channel security is hygiene.** The unit of security is the sealed envelope: HPKE **Auth mode** — sender-authenticated at the KEM layer, deniable toward third parties, with the protected header as AAD and pact context bound into the key schedule. (Draft v0.1 used HPKE Base + a detached signature on every message; the security review showed that construction enabled cross-pact re-sealing, left replay fields unauthenticated, and made every chat message court-admissible by default — v1.0's Auth-mode envelope with `otr` opt-in fixes all three.) Direct P2P connections additionally pin the peer's transport key in the QUIC/TLS handshake: the mTLS trust model enforced end-to-end, where TLS itself cannot reach.

**DD3 — Identity is a per-person keypair expressed as a DID, with short-lived delegated agent keys.** Owner key as root; agent signing/KEM keys under 7–30-day delegations (rotation never touches friendships); a separate long-lived transport key so P2P dial addresses survive routine rotation; per-pact gateway auth keys so infrastructure sees pairwise pseudonyms. did:web for hosted/own-domain identities, did:key for infrastructure-free ones; migration between them via `pact.identity.update` without re-friending.

**DD4 — The friend request is the key ceremony.** The request carries full key material and desired scopes sealed to the responder; acceptance returns the responder's; both pin. Commit-reveal nonces make the human SAS check one-shot (no offline grinding); the trust outcome of each pairing path (invitation / directory+KT / bare) is stated honestly and surfaced in UX.

**DD5 — Three transport profiles, one envelope.** Direct (Iroh/QUIC, keys as addresses), Gateway (plain HTTPS carrying ciphertext), Mailbox (store-and-forward with pickup). Profiles differ only in how bytes move; a self-hosted node and a platform tenant pair symmetrically.

**DD6 — Scheduling is a typed verb vocabulary, not prose.** Request/propose/counter/accept/confirm/decline/cancel/reschedule with at most five policy-filtered candidate slots per message and no free/busy disclosure — simultaneously the privacy mechanism and the prompt-injection firewall. Free text rides along but is never load-bearing.

**DD7 — The platform is convenience, not a trust requirement.** Signed identity records, a key-transparency log, ciphertext-only relays, per-pact pseudonymous routing, and (for Managed custody) a user-visible pact log make the operator auditable rather than trusted — the only architecture in which "the operator maintains the security layer" and "users can verify and can leave" are simultaneously true.

**DD8 — Unpaired contact is allowed but quarantined.** The public tier is the pairing request (plus, optionally, a slot-free `scheduling.inquire` and an OAuth-fronted MCP façade), bounded by admission control. The consent gate is the spam firewall; the public surface is the bootstrap.

---

## 5. Build vs reuse (operator guidance)

| Layer | Decision | Basis |
|---|---|---|
| Task/message semantics, discovery card | Reuse A2A v1.0 + extension mechanism | a2aproject SDKs (5 languages) |
| Sealed envelope | Build thin on HPKE (RFC 9180) + JOSE libraries | hpke-rs/pyhpke/hpke-js; mature JOSE stacks |
| Pairing handshake, SAS | Build — the novel part; shapes from DIDComm OOB, SPIFFE federation, Signal/Matrix ceremonies | Spec §6 |
| P2P transport | Reuse Iroh 1.0 (keys as addresses, E2E relays) | n0-computer/iroh |
| Gateway data plane | Reuse/extend agentgateway; registry ideas from ContextForge | Linux Foundation projects |
| Tunnel ingress for self-hosters | Reuse cloudflared (BYO domain) or Pangolin-style WireGuard ingress operated as a service | Appendix F of the spec |
| Mailbox | Build small: Profile M contract over NATS JetStream/Postgres | Spec §7.4 |
| Directory + key transparency | Build the directory (signed records are simple); reuse Meta's `akd` for the log | facebook/akd |
| Scheduling execution | Verbs from spec §9.2; calendar writes via existing MCP servers; Cal.com API as an optional backend | Cal.com OSS |
| Agent runtime | Integrate, don't build first: ship the PACT endpoint as the hosted PA *and* as an OpenClaw plugin for the self-hosted install base | openclaw |

## 6. Roadmap

**Phase 1 — Hosted MVP (full loop, one mode).** Hosted PAs (Managed custody with its §15.4 obligations), directory with signed records (KT log can follow, records are log-ready from day one), gateway + mailbox, pairing, envelopes, `scheduling.*` + `messaging.deliver`, calendar MCP (Google/Microsoft/Cal.com). Success: two customers' assistants book a real meeting with zero calendar disclosure.
**Phase 2 — Self-hosting + sovereignty.** Reference node (single container: PA adapter + PACT endpoint + Iroh), OpenClaw plugin, cloudflared/Pangolin recipes, Sovereign custody (device-held owner keys signing pairing/scopes), mailbox coverage for sleeping nodes, rotation flows. Success: a self-hosted node pairs and books against a hosted one and the operator can read none of it.
**Phase 3 — Trust at scale.** KT log + self-monitoring + third-party auditors, directory federation, unlisted identities + admission control + `scheduling.autobook` maturity, SAS UX polish, public MCP façade.
**Phase 4 — Ecosystem.** Publish spec + schemas + conformance suite (RB-3/4), propose the pairing/E2EE extension upstream (A2A extension registry / AAIF; W3C AI Agent Protocol CG as a venue), PQ-hybrid suite + floor raise, group pacts (MLS), payments via AP2.

## 7. What to watch

A2A↔MCP convergence under AAIF (a joint interop effort is reported for late 2026 — keep the extension surface small so a merged spec is an easy retarget). IETF WIMSE workload proof tokens (candidate replacement for the RFC 9421 infra-auth layer). Signal AKV / `akd` auditor ecosystem (ride it rather than bootstrapping auditors). Meta × Moltbook (a proprietary consumer agent network is likely; PACT's counter-position — open, E2EE, self-hostable — must stay non-negotiable). ANP / W3C CG (if did:wba gains adoption, adding it as a supported method is cheap). Privacy Pass deployments (anonymous admission tokens for pairing routes, spec §13.3).

---

## 8. Review disposition (v0.1 → v1.0)

Draft v0.1 underwent a three-lens adversarial review: protocol completeness (P1–P37), security/cryptography (S1–S32), editorial/release-readiness (E1–E25 plus a structural recommendation). Disposition codes: **F** fixed in 1.0 (with locus), **D** deferred to 1.1 with rationale recorded in spec §13.3, **A** accepted-with-statement (residual documented honestly), **R** rejected/overtaken.

**Protocol findings.**
P1 error model → F §12, §9.1.9 · P2 unauthenticated seq/ts/outer → F §7.1 (protected header = AAD; all decisions on authenticated fields) · P3 Iroh key rotation breaks dialing → F §5.1 transport key split, §7.7 · P4 no EK grace → F §6.5.1 (35-day retention, UNKNOWN_KID) · P5 seq lifecycle/dedupe key → F §7.1.3 (persistent seq, window 1024, msgId dedupe, retry = same bytes) · P6 outer.to uncomputable → F recipient-minted routeIds (§7.1.1, §7.5) · P7 Profile G HTTP contract → F §7.3.1 · P8 async responses → F §7.6 (reverse envelopes, `application/pact-rsp+json`) · P9 glare/duplicates/re-pair → F §6.1 rules 1–3, 8 · P10 handshake timeouts/half-open → F §6.1 rule 4, `pact.pair.cancel` · P11 suspension protocol → F §6.1 rule 7, §9.1.11–12 · P12 scope-model incoherence → F §10 (four fields defined, one grammar, verb table, caps renamed) · P13 version negotiation → F §13 · P14 pickup unspecified → F §7.4 · P15 Profile D binding → F §7.2 (ALPN, framing, sealed even on D) · P16 transport updates → F §9.1.5, §7.7 precedence · P17 prekey lifecycle → F §5.4, §7.1.4 · P18 multi-device/seq → F §7.1.3 single-sender rule; multi-runtime deferred (D §13.3) · P19 cross-check underdefined → F §6.3.6 · P20 SAS unimplementable → F §6.4 + vectors C.2 · P21 clock skew → F §7.1.2 step 7, §5.2, §14.6 · P22 size limits → F §14.6 · P23 did:web resolution error → F §5.3 (correct method rules; identity record authoritative) · P24 handle ABNF/migration → F §11.1, §9.1.14 · P25 public scheduling contradiction → F §8.2, §9.2.10 (inquire, no slots) · P26 timezone/DST → F §2.3, §9.2 (IANA zone authoritative) · P27 negotiation failure paths → F §9.2.6/9.2.9 (slot-unavailable, hold-expired, machine redrawn, confirm idempotent, cancelled ref terminal) · P28 ICS semantics → F §9.2.5/9.2.7 (organizer, UID, SEQUENCE, address withholding) · P29 infra provisioning/ACL bootstrap → F §7.5 (control API, pairing routes) · P30 signature byte-inputs → F §2.3, §6.2, §6.3 (exact-bytes rule) · P31 numbering/dangling refs → F (restructure) · P32 extension required-flag / mutualTLS misuse → F §5.5 · P33 accept-exits-loop, counter depth → F §9.2.3/9.2.9 · P34 receipt/presence schemas → F §9.3.2/9.4 · P35 invitation lifecycle/hint grammar → F §6.2 · P36 mailbox TTL ceiling → F §7.4.4/§14.6 · P37 did:key revocation → F §6.6.

**Security findings.**
S1 surreptitious forwarding / unauthenticated metadata → F §7.1 (Auth mode, AAD, step-4 binding checks) · S2 grindable SAS → F §6.4 commit-reveal, 66 bits · S3 asymmetric invitation trust → F §15.2 + §6.4 requirement placement · S4 custodial silent pairing → F §15.4 (pact log, notifications, co-sign RECOMMENDED); residual stated (A) · S5 cleartext pair.request → F §6.3 (sealed to prekey/invitation key) · S6 no forward secrecy → A/D: EK ≤ 30 days documented §15.3; ratchet deferred §13.3 · S7 suite downgrade → F §7.1.6 (suite in AAD, signed floors) · S8 revocation latency → F §5.2 (7-day default delegations), §11.3.3 freshness · S9 cross-protocol key reuse → F §5.1 (key-per-role, typ contexts, 9421 tag) · S10 prekeys not committed → F §5.4 (bundle hash in KT-covered record, atomic consume) · S11 injection via schema fields → F §17.2 normative rules · S12 homoglyph spoofing → F §11.1, §17.1–17.2 · S13 9421 coverage → F §7.3.2 · S14 relay ACL vs metadata → F per-pact GAK/routeId (§16.2); anonymous tokens deferred (D) · S15 non-repudiation default → F Auth mode + `otr` opt-in (§7.1.5) · S16 canonicalization → F §2.3 exact-bytes/JCS rules · S17 KT query privacy + uuidv7 leak → F random ids (§2.3); query privacy documented §16.3 (A) · S18 presence/receipt stalking → F §16.4 · S19 continuity chain risks → F §6.5.2 (depth 16, AND-KT rule, bound fields) · S20 paired-channel flooding → F §14.6 quotas + backpressure · S21 replay/reflection cross-profile → F §7.1.2 step 4, §7.1.3 shared state · S22 recovery attack surface → F §15.5 (recovery = suspend + reverify) · S23 parameter/suite tables → F §14.6, §7.1.6 · S24 invitation sk weaknesses → F §6.2 (128-bit, atomic, sealed request, inviter SAS) · S25 glare → F §6.1 rule 2 · S26 pairing-route Sybil DoS → F §7.5.2/§15.6 (bounds, admission cost SHOULD) · S27 profile downgrade forcing → F §7.7/§15.6 logging (A residual: metadata) · S28 public scheduling surface → F §9.2.10 · S29 implementation security → F §15.8 · S30 GDPR vs KT → F §11.4/§16.5 (blinded log, mutable PII) · S31 delegation semantics → F §5.2 (identity-only, caps split, iss-vs-pinned rule) · S32 abuse reporting vs deniability → F §15.7 (`otr` as evidence channel).

**Editorial findings.**
E1 research/vendor voice in spec → F: split into this companion + neutral-voice spec · E2 conformance classes → F §3 · E3 BCP 14 → F §2.1 + keyword audit · E4 versioning policy → F §13 · E5 numbering/dangling refs → F restructure (verified by automated xref pass) · E6 schemas/field tables/ellipsis-free examples → F §§5–11 tables + Appendix A/B · E7 placeholder identifiers/name collision → A: provisional URIs marked, reserved example domains used, RB-1 release blocker · E8 pact.key.revoke undefined / verb registry → F §9.1.7, §14.1 · E9 public-tier contradiction → F §8.2 · E10 registries → F §14 · E11 envelope-before-profiles ordering → F §7 order · E12 error registry → F §12 · E13 front matter → F (status, editors, license, changelog) · E14 terminology → F §2.2 · E15 ABNFs → F §6.2, §11.1 · E16 dual sealing layers unnegotiated → F: single MTI sealing (DIDComm-authcrypt option removed; interop note only in this companion) · E17 i18n → F §17 · E18 accessibility → F §18 · E19 test vectors + conformance statement → F Appendix C, §3.3 (suite itself RB-4) · E20 references split/pinned → F §19 · E21 privacy considerations section → F §16 · E22 typo → F · E23 stat/legend drift → F (this document, §2.4/§3) · E24 timestamp policy → F §2.3 · E25 cosmetics (uuid casing, mutualTLS example, headings) → F.

Every CRITICAL and MAJOR finding is fixed in 1.0 except the two explicitly deferred capability items (forward-secrecy ratchet, anonymous relay tokens) and the accepted-residual items (custodial capability, KT query privacy, relay metadata), each of which the specification now states honestly rather than papering over.

---

## 9. Sources

Protocols and specs: a2a-protocol.org (spec v1.0, releases, extensions) · Linux Foundation A2A announcements · AAIF formation and project proposals · modelcontextprotocol.io + blog (2025-11-25, 2026-07-28) · agent-network-protocol.com (ANP, did:wba) · W3C AI Agent Protocol CG · identity.foundation (DIDComm v2.1, did:peer, trusted-agents WGs) · agntcy.org + draft-mpsb-agntcy-slim · spiffe.io (federation) · IETF WIMSE drafts · RFCs cited in the specification's §19.
Security machinery: signal.org (PQXDH; Automatic Key Verification, Aug 2026) · engineering.fb.com + github.com/facebook/akd (WhatsApp AKD) · security.apple.com (CKV) · matrix.org (cross-signing; vodozemac analyses) · tailscale.com (Tailnet Lock, sharing) · blog.cloudflare.com (signed agents / Web Bot Auth, key transparency auditing).
Infrastructure: iroh.computer/blog/v1 · github.com/agentgateway/agentgateway · github.com/IBM/mcp-context-forge · developers.cloudflare.com (Tunnel, client certificates, remote MCP) · platform.claude.com docs (MCP tunnels preview) · github.com/fosrl/pangolin · didcomm.org/messagepickup/3.0 · ngrok, Tailscale Funnel, frp/rathole docs.
Market: linuxfoundation.org press (A2A 150+ orgs; AGNTCY) · lfaidata.foundation (ACP merge) · arxiv.org/html/2508.03095 (registry survey) · MIT NANDA (media.mit.edu, github.com/projnanda) · ERC-8004 (ethereum-magicians.org) · kurtheinrich.com/blog/scheduling-for-agents · github.com/ammonhaggerty/ANEX · github.com/openclaw/openclaw · Meta–Moltbook acquisition coverage (Fortune/TIME/Forbes, Q1 2026) · cal.com/docs/agents · reclaim.ai (Clockwise sunset) · agentmail.to · vendor pages for Skej, Howie, Ohai.ai, Clara Labs, Personal AI, Lindy, Zapier, Dust, Alexa+.

*End of companion document.*
