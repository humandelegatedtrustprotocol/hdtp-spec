# PACT — Personal Agent Communication & Trust

Agent-to-agent messaging over **MCP + mTLS**. Your assistant talks to your friends' and colleagues' assistants across the open internet: contacts live in your phone book as vCards, identity is one TLS keypair, and sending a message is calling a `send_message` tool on the other person's publicly exposed MCP server. Think *WhatsApp, but the participants are AI agents* — with humans manually approving every contact and controlling per-contact permissions.

**Status: v1.2.0 released 2026-08-30 and implemented by the reference gateway; v2.0.0-draft in progress (2026-09-13) — the identity generation: the person is a certificate authority, the host holds a leaf the person issued, so an identity can move between providers.**

## Repository map

| Path | What it is |
|---|---|
| `SPEC.md` | **The protocol.** PACT 1.0 — identity & mTLS, vCard contact cards, invites, contact flows, the MCP tool surface, permissions, threads, gateway mode, deployment, security notes, errors & conformance checklist. Mermaid diagrams throughout. |
| `explainer/pact-explainer.html` | Self-contained visual explainer (open in any browser). Also published privately at claude.ai/code/artifact/6410d04a-ec41-45b5-bb97-fbc3801c4da1. |
| `docs/landscape-and-roadmap.md` | Informative companion: survey of existing protocols/products (A2A, ANP, DIDComm, AGNTCY, Iroh, OpenClaw ecosystem, schedulers…), requirements-vs-systems comparison matrix, build-vs-reuse guidance, roadmap, and the full review-disposition history. |
| `archive/hardened-draft-spec.md` | Superseded hardened draft (E2E sealed envelopes, key hierarchies, SAS, key transparency). Kept because its envelope can return as an optional layer if gateway-proof privacy is ever required. |
| `archive/design-study-v0.1.md` | The original design study that started the project. |
| `archive/test-vectors/` | Crypto test-vector generator + output for the *hardened draft* (HPKE/SAS) — not applicable to current `SPEC.md`. |

## The protocol in five lines

1. **Identity** — in 2.0, a self-signed root certificate you hold, pinned by its fingerprint; the host you choose serves you under a leaf your root issued for its address, valid for at most a year, and contacts learn each renewed leaf from the chain every call carries. In 1.x, one keypair whose SPKI fingerprint is you. Every call is mTLS with the leaf key.
2. **Contacts** — standard vCards with `X-PACT-CERT` (2.0) or `X-PACT-ENDPOINT` / `X-PACT-KEY` (1.x); shared over channels people already use; always mutual, always human-approved.
3. **Invites** — short URLs/QRs whose settings (expiry, max uses, auto-accept, preset) live server-side, so they're revocable at the protocol level.
4. **Capabilities** — everything a contact may do is an MCP tool, filtered per caller via `tools/list`; new integrations are just new tools.
5. **Delivery** — direct HTTPS, always. A person who must be reachable while their own machine is off is hosted by a provider under a leaf they issued and can leave (2.0 §9); 1.x's recipient-chosen gateway is gone from 2.0.

## Building the whitepaper

`npm ci && npm run build` renders `SPEC.md` into `dist/pact-whitepaper.pdf` — an A4 whitepaper with a cover, a table of contents with page numbers, running headers, PDF bookmarks, and every mermaid diagram as vector art. The build is also the verification gate: it fails on a heading over 120 characters (the sign of an accidental setext heading) and on a diagram that does not render. It needs Node 22 and a Chrome that `puppeteer` downloads on install; set `PUPPETEER_EXECUTABLE_PATH` to use one already on the machine. `.github/workflows/whitepaper.yml` builds the PDF on every push to `main`, keeps it as a workflow artifact, and publishes it to the private R2 bucket when the Cloudflare secrets are set (`npm run publish` does the same from a local build).

## Suggested next steps

- Reference implementation: a single-binary/container **agent server** (MCP over Streamable HTTP, TLS client-cert auth, contact store, invite issuance, the §6.2 core tools) + a thin client for calling peers.
- vCard import/export against a real phone contact book.
- Two-node demo: pair via QR, negotiate, `book_slot`, exchange ICS.
- Conformance checks from `SPEC.md` §12 as a test suite.

License for the spec text: CC BY 4.0 (recommended; not yet stamped). "PACT" is a working name — note the collision with pact.io (contract testing) before publishing publicly.
