# PACT — Personal Agent Communication & Trust

Agent-to-agent messaging over **MCP + mTLS**. Your assistant talks to your friends' and colleagues' assistants across the open internet: contacts live in your phone book as vCards, identity is one TLS keypair, and sending a message is calling a `send_message` tool on the other person's publicly exposed MCP server. Think *WhatsApp, but the participants are AI agents* — with humans manually approving every contact and controlling per-contact permissions.

**Status: 2.2.4 (2026-09-28), released — the identity generation: the person is a certificate authority, the host holds a leaf the person issued, so an identity can move between providers. PACT 1.x (last released as 1.2.0, 2026-08-30) is not supported. `CHANGES.md` is the revision history.**

## Repository map

| Path | What it is |
|---|---|
| `SPEC.md` | **The protocol.** Architecture; identity, certificates and mTLS; vCard contact cards; invites; contact flows; the MCP tool surface; messaging and threads; permissions; hosting; deployment; security notes; errors, limits and conformance; sealed envelopes; certificates; worked examples and the test vectors. Mermaid diagrams throughout. |
| `CHANGES.md` | The revision history: one entry per version string `SPEC.md` has carried, dated by its header line, with the commits that carried it. `SPEC.md` itself names no version of its own history. |
| `explainer/pact-explainer.html` | Self-contained visual explainer (open in any browser). Also published privately at claude.ai/artifact/7txRRL4VBVXyMhsNUcuLJX. |
| `docs/landscape-and-roadmap.md` | Informative companion: survey of existing protocols/products (A2A, ANP, DIDComm, AGNTCY, Iroh, OpenClaw ecosystem, schedulers…), requirements-vs-systems comparison matrix, build-vs-reuse guidance, roadmap, and the full review-disposition history. |
| `archive/hardened-draft-spec.md` | Superseded hardened draft (E2E sealed envelopes, key hierarchies, SAS, key transparency). Kept because its envelope can return as an optional layer if gateway-proof privacy is ever required. |
| `archive/design-study-v0.1.md` | The original design study that started the project. |
| `archive/test-vectors/` | Crypto test-vector generator + output for the *hardened draft* (HPKE/SAS) — not applicable to current `SPEC.md`. |
| `vectors/` | The 2.0 vectors of Appendix B: `gen.mjs` derives every secret from a label and writes the certificates, chain cases and `v: 2` envelopes; `check.mjs` reads them back *from `SPEC.md`*, opens the Go-generated `v: 1` vectors with the same code, cross-checks each certificate with OpenSSL, and asserts every case's outcome. `npm run vectors:check`. `intrude.mjs` replays the §14.5 compromise cases against an in-memory node: `npm run vectors:intrude`. |
| *the library* | Not here: `pact-identity/` in the umbrella repository is the 2.0 library the vectors specify — a Rust core compiled to WebAssembly, an independent Go port, and the `pact` CLI (`pact vectors check --spec SPEC.md` proves Appendix B natively); both ports answer every vector and every intrusion scenario exactly as `vectors/lib` does. |

## The protocol in five lines

1. **Identity** — in 2.0, a self-signed root certificate you hold, pinned by its fingerprint; the host you choose serves you under a leaf your root issued for its address, valid for at most a year, and contacts learn each renewed leaf from the chain, carried once and named by fingerprint after. In 1.x, one keypair whose SPKI fingerprint is you. Every call is mTLS with the leaf key.
2. **Contacts** — standard vCards with `X-PACT-CERT`; shared over channels people already use; always mutual, always human-approved.
3. **Invites** — short URLs/QRs whose settings (expiry, max uses, auto-accept, preset) live server-side, so they're revocable at the protocol level.
4. **Capabilities** — everything a contact may do is an MCP tool, filtered per caller via `tools/list`; new integrations are just new tools.
5. **Delivery** — direct HTTPS, always. A person who must be reachable while their own machine is off is hosted by a provider under a leaf they issued and can leave (2.0 §9); 1.x's recipient-chosen gateway is gone from 2.0.

## Building the whitepaper

`npm ci && npm run build` renders `SPEC.md` into `dist/pact-whitepaper.pdf` — an A4 whitepaper with a cover, a table of contents with page numbers, running headers, PDF bookmarks, and every mermaid diagram as vector art. The build is also the verification gate: it fails on a heading over 120 characters (the sign of an accidental setext heading) and on a diagram that does not render. It needs Node 22 and a Chrome that `puppeteer` downloads on install; set `PUPPETEER_EXECUTABLE_PATH` to use one already on the machine. `.github/workflows/whitepaper.yml` builds the PDF on every push to `main` and keeps it as a workflow artifact; it holds no Cloudflare credential. Publishing is local: `make publish` (the credentials from the umbrella's `.env`) runs the gates and the build and puts the PDF and its meta into the private R2 bucket that [pact-protocol.com](https://pact-protocol.com) serves, refusing a pair from different builds.

## Rendering the specification for the web

`make spec-html REF=<commit> OUT=<dir>` (`site/spec-html.mjs`) renders one *committed* SPEC.md — `git show <commit>:SPEC.md`, never the working tree — into fragments the protocol site vendors: `spec.html`, the whole text as one fragment with stable ids from the section numbers (`#s2-1` is §2.1), every MUST marked, and every mermaid block replaced by an inline SVG inside `<figure class="diagram">` that carries only the classes of pact-web-kit's diagram contract — `site/diagram-classes.json`, a copy of the kit's `kit/diagram-classes.json` — so the kit's `docs.css` owns its colours and fonts; `toc.json`, the heading tree; `musts.json`, every normative sentence with its heading and pact-identity's registry id; `meta.json`, the version and date from the header line, the commit and the counts; and `vectors/`, the Appendix B file and a fragment indexing it. It shares the markdown and mermaid pipeline with the whitepaper build. The output directory must be gitignored or outside the repository: the superseded PACT 1.2.0 text (`d130444`) renders the same way and names things the 1.x guard refuses. Every build audits its own drawings against the contract — every primitive carries one of its classes, on a tag it lists; the text was laid out at the size and weight it records — and refuses to write otherwise. `npm run spec:check` proves the renderer on both texts — same commit, same bytes; one id per heading; no `style=`, no `<style>`, nothing but the contract's classes in a drawing, every class of the contract drawn; as many MUSTs marked as the text has — and holds its MUST extractor to pact-identity's and its copy of the contract to the kit's, so it wants both sibling checkouts beside this one (`PACT_IDENTITY_DIR` and `PACT_WEB_KIT_DIR` otherwise); without pact-identity it fails, without the kit it says so and holds to the committed copy.

## Suggested next steps

- Reference implementation: a single-binary/container **agent server** (MCP over Streamable HTTP, TLS client-cert auth, contact store, invite issuance, the §6.2 core tools) + a thin client for calling peers.
- vCard import/export against a real phone contact book.
- Two-node demo: pair via QR, negotiate, `book_slot`, exchange ICS.
- Conformance checks from `SPEC.md` §12 as a test suite.

License for the spec text: CC BY 4.0 (recommended; not yet stamped). "PACT" is a working name — note the collision with pact.io (contract testing) before publishing publicly.
