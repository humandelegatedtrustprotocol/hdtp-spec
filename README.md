# HDTP — Human Delegated Trust Protocol

Agent-to-agent messaging over **MCP + mTLS**. Your assistant talks to your friends' and colleagues' assistants across the open internet: contacts live in your phone book as vCards, your identity is a certificate you hold, and sending a message is calling a `send_message` tool on the other person's publicly exposed MCP server. Humans approve every contact and control what each contact may do.

**Status: 1.0.0 (2026-10-03), released. `CHANGES.md` is the revision history. This repository is private.**

## Repository map

| Path | What it is |
|---|---|
| `docs/specification/1.0/` | **The protocol**, version 1.0: `index.md` (the title, the version line, the introduction and the contents) and one page per section — architecture; identity, certificates and mTLS; contact cards; invites; adding contacts; the MCP tool surface; messaging and threads; permissions; hosting; deployment; security notes; errors, limits and conformance; sealed envelopes; certificates; worked examples; the test vectors. Mermaid diagrams throughout. |
| `docs/specification/draft/` | Where the next version is written. It starts as a copy of 1.0 under the version line `1.1.0-draft`; `seps/README.md` says how a change gets there. |
| `schema/1.0/`, `schema/draft/` | `schema.json`, the JSON Schema of the JSON objects on the wire, generated from hdtp-identity's contract by `schema/gen.mjs`; `schema/README.md` says what it covers and what it leaves out. |
| `seps/` | HDTP Enhancement Proposals: the process (`seps/README.md`) and the template. |
| `CHANGES.md` | The revision history: one entry per released version. The text itself names no version of its own history. |
| `blog/` | Posts about the protocol. |
| `explainer/hdtp-explainer.html` | A visual explainer of the protocol with hand-drawn inline SVG diagrams. It is an HTML fragment written to be embedded in a page — it starts at `<title>`, with no doctype or `<html>` wrapper — and it loads its typefaces from Google Fonts. |
| `vectors/` | The test vectors of Appendix B. `gen.mjs` derives every secret from a label and writes the certificates, chain cases and sealed envelopes to `hdtp-1.0-vectors.json`, and splices them into the appendix of the released version and of the draft; `check.mjs` reads them back *from the specification*, cross-checks each certificate with OpenSSL (Node's `X509Certificate`), asserts every case's outcome, and holds every sentence of the text that states a wire version, or says what the appendix holds, to those bytes (`lib/stated.mjs`). `intrude.mjs` replays the §14.5 compromise cases and the corner cases around them against an in-memory node and reports each as blocked, residual by decision, or reproduced: `npm run vectors:intrude`. `lib/` is the smallest implementation of §3, §13 and §14 that makes that possible. |
| `scripts/` | The name guard: `check-names.mjs` and its list `hdtp-names.txt`, the canonical copies of what every HDTP repository's gate runs. |
| `site/` | The two renderings of the specification — the whitepaper and the web fragments — and `spec-source.mjs`, the one reader of the text, which every other reader goes through. |

## The protocol in five lines

1. **Identity** — a self-signed root certificate you hold, pinned by its fingerprint. The host you choose serves you under a leaf your root issued for its address, valid for as long as you choose up to 398 days; contacts learn each renewed leaf from the chain, carried once and named by fingerprint after. Every call is mTLS with the leaf key.
2. **Contacts** — standard vCards with `X-HDTP-CERT`; shared over channels people already use; always mutual, always human-approved.
3. **Invites** — short URLs/QRs whose settings (expiry, max uses, auto-accept, preset) live server-side, so they're revocable at the protocol level.
4. **Capabilities** — everything a contact may do is an MCP tool, filtered per caller via `tools/list`; new integrations are just new tools.
5. **Delivery** — direct HTTPS, always; there is no relay. A person who must be reachable while their own machine is off is hosted by a provider under a leaf they issued and can leave (§9).

## Implementations

Two exist, both by this project and neither public yet: a self-hosted node, HDTP Gateway ([hdtp.dev](https://hdtp.dev)), and a hosted platform, BatonDeck ([batondeck.com](https://batondeck.com)). Both are built on one identity library, `hdtp-identity` (a Rust core compiled to WebAssembly, an independent Go port and the `hdtp` CLI), which runs the vectors of Appendix B and the scenarios of `vectors/intrude.mjs` through both of its ports. There is no independent implementation yet.

## Gates

```
npm ci
npm run vectors:check     # the vectors against the specification, then the name guard (its self-test first)
npm run spec:check        # the web renderer and the open-fonts rule; needs hdtp-identity beside this checkout
npm run schema:check      # schema/*/schema.json is what hdtp-identity's contract generates
npm run build             # the whitepaper; the build is also a gate
```

`make check` runs the first three, `make build` the fourth. The name guard (`scripts/check-names.mjs`) fails on any tracked path or text carrying a name `scripts/hdtp-names.txt` forbids: the name its `name` line gives, in any case, anywhere except right after `im` or `com`, and the names of behaviours HDTP does not have. The file also lists what is allowed, one exact text in one file of one repository per line: this repository's one entry is the sentence that says what HDTP was called, and the others are the sites' redirect configs and the specification site's vendored copies of that sentence.

## Building the whitepaper

`npm ci && npm run build` renders the newest released version into `dist/hdtp-whitepaper.pdf` — an A4 whitepaper with a cover, a table of contents with page numbers, running headers, PDF bookmarks, every mermaid diagram as vector art, and a last page, "Licence and attribution", that the cover points to. The build is also a verification gate: it fails on a heading over 120 characters (the sign of an accidental setext heading), on a diagram that does not render, and on a PDF that does not carry its licence — it reads the printed PDF back (`site/pdf.mjs`) and refuses to write one whose text lacks the copyright line, the attribution line with the version line's version and date, or the licence's address, or whose document information lacks the author and CC BY 4.0. The wording of that page, of the cover's licence line, of the metadata and of the web fragment's licence block is `site/licence.mjs`'s, read from `NOTICE`, `CITATION.cff`, the version line, `site/whitepaper.css` and `site/fonts.json`. It needs Node 22 (what the workflow uses) and a Chrome that `puppeteer` downloads on install; set `PUPPETEER_EXECUTABLE_PATH` to use one already on the machine. `.github/workflows/whitepaper.yml` runs `npm run vectors:check` and the build on every push to `main` and on every pull request; it holds no credential, publishes nothing and keeps no artifact.

Publishing is the maintainer's and local: `make publish` runs the gates and the build, refuses a PDF and meta from different builds, and puts both into the private bucket `hdtp-private`, which [hdtp.io](https://hdtp.io) serves to registered readers. It needs `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` in the file `ENV_FILE` names (`../.env` by default).

## Rendering the specification for the web

`make spec-html REF=<commit> OUT=<dir> [VERSION=<X.Y>|draft]` (`site/spec-html.mjs`) renders one *committed* version — `docs/specification/<version>/` at that commit, read through `site/spec-source.mjs`, never the working tree; the newest released version when `VERSION` is not given — into fragments the protocol site vendors: `spec.html`, the whole text as one fragment with stable ids from the section numbers (`#s2-1` is §2.1), every MUST marked, and every mermaid block replaced by an inline SVG inside `<figure class="diagram">` that carries only the classes of hdtp-web-kit's diagram contract — `site/diagram-classes.json`, a copy of the kit's `kit/diagram-classes.json` — so the kit's `docs.css` owns its colours and fonts; flowcharts and state diagrams are laid out by ELK (`@mermaid-js/layout-elk`), and a flowchart wider than the text column is drawn the other way round when that reads larger. Beside it: `diagrams.json`, the mermaid each drawing was rendered from; `toc.json`, the heading tree; `musts.json`, every normative sentence with its heading and hdtp-identity's registry id (the registry is `--musts <path>`, else `js/musts.json` in `HDTP_IDENTITY_DIR`, else in the sibling `../hdtp-identity`, one lookup in `site/siblings.mjs`); `meta.json`, the version and date from the version line, the directory it was read from (`dir`), the commit and the counts; and `vectors/`, the Appendix B file and a fragment indexing it. When the rendered commit carries `LICENSE-docs`, `spec.html` ends in `<div class="licence">`: the copyright line and the attribution line for that commit's version. The output directory must be gitignored or outside the repository. Every build audits its own drawings against the contract and refuses to write otherwise. `npm run spec:check` proves the renderer on the current text and on a fixture committed into a scratch repository (a MUST inside a fence and one inside a diagram, and no `LICENSE-docs`), holds its MUST extractor to hdtp-identity's and its copy of the contract to the kit's — so it wants both sibling checkouts beside this one (`HDTP_IDENTITY_DIR` and `HDTP_WEB_KIT_DIR` otherwise); without hdtp-identity it fails, without the kit it says so and holds to the committed copy — and builds the whitepaper into a scratch directory to read its licence back. The same run holds every font a file of this repository names to open fonts and CSS generic families (`site/fonts.test.mjs`, against `site/fonts.json`).

## Open work

- Conformance checks from §12 as a runnable suite.
- An independent implementation.
- An external review of the sealed envelope (§13) and the certificate profile (§14).

## How to cite / attribute

CC BY 4.0 requires attribution when the specification text is shared, as it is or adapted. Use this
line, with the version you used, read from the version line of the specification's index page:

> *HDTP — Human Delegated Trust Protocol*, by Sumit Agrawal, version 1.0.0 (2026-10-03), https://hdtp.io/spec/, licensed under CC BY 4.0 (https://creativecommons.org/licenses/by/4.0/).

State whether you changed the text. `CITATION.cff` carries the same fields for citation tools, and
`npm run vectors:check` fails when its version or date differs from the version line, or when this
line differs from the one `site/licence.mjs` words for the whitepaper and the web. Redistributions
of the code and data carry `NOTICE`, as section 4(d) of the Apache License 2.0 requires.

## Licensing

| Files | Licence |
|---|---|
| The specification text, `docs/specification/` | [CC BY 4.0](LICENSE-docs); patents: the OWFa 1.0 (Patent Only) declaration in [`PATENTS.md`](PATENTS.md), made by Sumit Agrawal as an individual and for Shailka Systems Private Limited as a Bound Entity |
| The other prose: `README.md`, `CHANGES.md`, `CONTRIBUTING.md`, `GOVERNANCE.md`, `MAINTAINERS.md`, `SECURITY.md`, `CLAUDE.md`, `seps/`, `schema/README.md`, `blog/`, `explainer/hdtp-explainer.html` (its text and inline SVG), and the project's own prose in `PATENTS.md` (the text outside its fenced agreement) | [CC BY 4.0](LICENSE-docs) |
| `CODE_OF_CONDUCT.md` | the Contributor Covenant 2.1, by its authors, under CC BY 4.0 |
| Code: `vectors/**/*.mjs`, `site/*.mjs`, `site/whitepaper.css`, `scripts/check-names.mjs`, `schema/gen.mjs`, `Makefile`, `package.json`, `package-lock.json`, `.gitignore`, `.github/workflows/whitepaper.yml` | [Apache-2.0](LICENSE), with [`NOTICE`](NOTICE) |
| Data: `vectors/hdtp-1.0-vectors.json`, `vectors/appendix-b-reader.json`, `scripts/hdtp-names.txt`, `schema/*/schema.json`, `site/diagram-classes.json`, `site/fonts.json`, `CITATION.cff`, `NOTICE` | [Apache-2.0](LICENSE) |
| Licence and agreement texts: `LICENSE` (the Apache License 2.0), `LICENSE-docs` (the CC BY 4.0 legal code), the fenced agreement in `PATENTS.md` (OWFa 1.0, Patent Only), `site/brand/OFL-*.txt` | their authors' texts (the Apache Software Foundation, Creative Commons, the Open Web Foundation, the font authors); not licensed by this project |
| The mark, `site/brand/mark.svg` | the project's mark; not covered by any licence above |
| Fonts: `site/brand/inter-*.woff2`, `site/brand/jbmono-*.woff2` | SIL Open Font License 1.1: `site/brand/OFL-inter.txt`, `site/brand/OFL-jetbrains-mono.txt`. The `latin` files are byte-identical to the ones fontsource 5.3.0 packages from the Google Fonts builds; the two `*-symbols-wght.woff2` are subsets cut for this build (‖ → ≠ ≤ ≥). Neither family reserves a font name, so the subsets keep the family names. The explainer loads Bricolage Grotesque, Schibsted Grotesk and Spline Sans Mono from Google Fonts, each under the SIL Open Font License 1.1; none of their files is in this repository. Fonts named in stacks are only open fonts and CSS generic families: Inter and JetBrains Mono (shipped here), the explainer's three, and `system-ui`, `ui-sans-serif`, `ui-monospace`, `sans-serif` and `monospace`, which resolve to the reader's own system font and name none; `npm run spec:check` holds every file to that (`site/fonts.test.mjs`). The whitepaper PDF embeds Inter and JetBrains Mono only. |

No licence stops a third party from filing a patent application. What this project does about
patents is in `PATENTS.md`: the OWFa pledge, by Sumit Agrawal and binding Shailka Systems Private
Limited, not to assert their own claims, and the dated publication of the specification.
