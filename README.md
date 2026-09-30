# PACT — Personal Agent Communication & Trust

Agent-to-agent messaging over **MCP + mTLS**. Your assistant talks to your friends' and colleagues' assistants across the open internet: contacts live in your phone book as vCards, your identity is a certificate you hold, and sending a message is calling a `send_message` tool on the other person's publicly exposed MCP server. Think *WhatsApp, but the participants are AI agents* — with humans approving every contact and controlling per-contact permissions.

**Status: 2.2.5 (2026-09-30), released — the identity generation: the person is a certificate authority, the host holds a leaf the person issued, so an identity can move between providers. PACT 1.x (last released as 1.2.0, 2026-08-30) is not supported. `CHANGES.md` is the revision history.**

## Repository map

| Path | What it is |
|---|---|
| `SPEC.md` | **The protocol.** Architecture; identity, certificates and mTLS; vCard contact cards; invites; contact flows; the MCP tool surface; messaging and threads; permissions; hosting; deployment; security notes; errors, limits and conformance; sealed envelopes; certificates; worked examples and the test vectors. Mermaid diagrams throughout. |
| `CHANGES.md` | The revision history: one entry per version string `SPEC.md` has carried, dated by its header line, with the commits that carried it. `SPEC.md` itself names no version of its own history. |
| `explainer/pact-explainer.html` | A visual explainer of the protocol with hand-drawn inline SVG diagrams. It is an HTML fragment written to be embedded in a page — it starts at `<title>`, with no doctype or `<html>` wrapper — and it loads its typefaces from Google Fonts. |
| `docs/landscape-and-roadmap.md` | Informative companion, written against 2.1.3: a survey of existing protocols and products (A2A, ANP, DIDComm, AGNTCY, Iroh, OpenClaw ecosystem, schedulers…), a requirements-vs-systems comparison matrix, build-vs-reuse guidance, a roadmap, and the review-disposition history. It binds nothing. |
| `archive/hardened-draft-spec.md` | A historical draft that was never released (message-layer envelopes with key hierarchies, SAS ceremonies, key transparency). Not a PACT version; the current sealed envelope, `SPEC.md` §13, is a different design. |
| `archive/design-study-v0.1.md` | The design study that started the project. Historical. |
| `archive/test-vectors/` | The historical draft's test-vector generator and output (HPKE/SAS). Not applicable to `SPEC.md`. |
| `vectors/` | The test vectors of Appendix B. `gen.mjs` derives every secret from a label and writes the certificates, chain cases and sealed envelopes to `pact-2.0-vectors.json`; `check.mjs` reads them back *from `SPEC.md`*, cross-checks each certificate with OpenSSL (Node's `X509Certificate`) and asserts every case's outcome; `check-no-1x.mjs` holds that no name PACT 1.x had and 2.x does not has come back into the tree. `npm run vectors:check` runs `check.mjs`, then the guard's self-test, then the guard. `intrude.mjs` replays the §14.5 compromise cases and the corner cases around them against an in-memory node and reports each as blocked, residual by decision, or reproduced: `npm run vectors:intrude`. `lib/` is the smallest implementation of §3, §13 and §14 that makes that possible. |

## The protocol in five lines

1. **Identity** — a self-signed root certificate you hold, pinned by its fingerprint. The host you choose serves you under a leaf your root issued for its address, valid for as long as you choose up to 398 days; contacts learn each renewed leaf from the chain, carried once and named by fingerprint after. Every call is mTLS with the leaf key.
2. **Contacts** — standard vCards with `X-PACT-CERT`; shared over channels people already use; always mutual, always human-approved.
3. **Invites** — short URLs/QRs whose settings (expiry, max uses, auto-accept, preset) live server-side, so they're revocable at the protocol level.
4. **Capabilities** — everything a contact may do is an MCP tool, filtered per caller via `tools/list`; new integrations are just new tools.
5. **Delivery** — direct HTTPS, always; there is no relay. A person who must be reachable while their own machine is off is hosted by a provider under a leaf they issued and can leave (§9).

## Implementations

Two exist, both by this project and neither public yet: a self-hosted node ([pact-gateway.com](https://pact-gateway.com)) and a hosted platform ([pact-cloud.com](https://pact-cloud.com)). Both are built on one identity library, `pact-identity` (a Rust core compiled to WebAssembly, an independent Go port and a `pact` CLI), which runs the vectors of Appendix B and the scenarios of `vectors/intrude.mjs` through both of its ports. There is no independent implementation yet.

## Building the whitepaper

`npm ci && npm run build` renders `SPEC.md` into `dist/pact-whitepaper.pdf` — an A4 whitepaper with a cover, a table of contents with page numbers, running headers, PDF bookmarks, and every mermaid diagram as vector art. The build is also a verification gate: it fails on a heading over 120 characters (the sign of an accidental setext heading) and on a diagram that does not render. It needs Node 22 (what the workflow uses) and a Chrome that `puppeteer` downloads on install; set `PUPPETEER_EXECUTABLE_PATH` to use one already on the machine. `.github/workflows/whitepaper.yml` runs `npm run vectors:check` and the build on every push to `main` and on every pull request; it holds no credential, publishes nothing and keeps no artifact.

Publishing is the maintainer's and local: `make publish` runs the gates and the build, refuses a PDF and meta from different builds, and puts both into the private bucket that [pact-protocol.com](https://pact-protocol.com) serves to registered readers. It needs `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` in the file `ENV_FILE` names (`../.env` by default).

## Rendering the specification for the web

`make spec-html REF=<commit> OUT=<dir>` (`site/spec-html.mjs`) renders one *committed* SPEC.md — `git show <commit>:SPEC.md`, never the working tree — into fragments the protocol site vendors: `spec.html`, the whole text as one fragment with stable ids from the section numbers (`#s2-1` is §2.1), every MUST marked, and every mermaid block replaced by an inline SVG inside `<figure class="diagram">` that carries only the classes of pact-web-kit's diagram contract — `site/diagram-classes.json`, a copy of the kit's `kit/diagram-classes.json` — so the kit's `docs.css` owns its colours and fonts; `toc.json`, the heading tree; `musts.json`, every normative sentence with its heading and pact-identity's registry id; `meta.json`, the version and date from the header line, the commit and the counts; and `vectors/`, the Appendix B file and a fragment indexing it. It shares the markdown and mermaid pipeline with the whitepaper build. The output directory must be gitignored or outside the repository: the superseded PACT 1.2.0 text (`d130444`) renders the same way and names things the 1.x guard refuses. Every build audits its own drawings against the contract — every primitive carries one of its classes, on a tag it lists; the text was laid out at the size and weight it records — and refuses to write otherwise. `npm run spec:check` proves the renderer on both texts — same commit, same bytes; one id per heading; no `style=`, no `<style>`, nothing but the contract's classes in a drawing, every class of the contract drawn; as many MUSTs marked as the text has — and holds its MUST extractor to pact-identity's and its copy of the contract to the kit's, so it wants both sibling checkouts beside this one (`PACT_IDENTITY_DIR` and `PACT_WEB_KIT_DIR` otherwise); without pact-identity it fails, without the kit it says so and holds to the committed copy.


## Open work

- Conformance checks from `SPEC.md` §12 as a runnable suite.
- An independent implementation.
- An external review of the sealed envelope (§13) and the certificate profile (§14).

## Licensing

| Files | Licence |
|---|---|
| The specification text, `SPEC.md` | [CC BY 4.0](LICENSE-docs) |
| The other prose: `README.md`, `CHANGES.md`, `CLAUDE.md`, `CONTRIBUTING.md`, `SECURITY.md`, `docs/`, `archive/*.md`, `explainer/pact-explainer.html` (its text and inline SVG) | [CC BY 4.0](LICENSE-docs) |
| Code: `vectors/**/*.mjs`, `site/*.mjs`, `site/whitepaper.css`, `archive/test-vectors/gen_vectors.py`, `Makefile`, `package.json`, `.github/workflows/whitepaper.yml` | [Apache-2.0](LICENSE) |
| Data: `vectors/pact-2.0-vectors.json`, `vectors/appendix-b-reader.json`, `vectors/pact1x-markers.txt`, `site/diagram-classes.json`, `archive/test-vectors/vectors.json` | [Apache-2.0](LICENSE), with the code |
| The mark, `site/brand/mark.svg` | the project's mark; not covered by either licence above |
| Fonts: `site/brand/inter-*.woff2`, `site/brand/jbmono-*.woff2` | SIL Open Font License 1.1: `site/brand/OFL-inter.txt`, `site/brand/OFL-jetbrains-mono.txt`. The `latin` files are byte-identical to the ones fontsource 5.3.0 packages from the Google Fonts builds; the two `*-symbols-wght.woff2` are subsets cut for this build (‖ → ≠ ≤ ≥). Neither family reserves a font name, so the subsets keep the family names. |

`archive/hardened-draft-spec.md` carries a licence line of its own ("CC BY 4.0 … additionally licensed under MIT"). It is the draft's own text, part of the dated record; the draft was never issued.

"PACT" is unrelated to Pact ([pact.io](https://pact.io)), the contract-testing framework.
