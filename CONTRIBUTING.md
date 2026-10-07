# Contributing

This repository holds the HDTP specification (`docs/specification/`), its revision history
(`CHANGES.md`), the JSON Schema of its wire objects (`schema/`), the enhancement-proposal process
(`seps/`), the test vectors of its Appendix B and the build of its whitepaper. Changes come as pull
requests and are reviewed by the maintainers (`MAINTAINERS.md`). How decisions are made is
`GOVERNANCE.md`.

## Where to start

- **A defect in the text** — a contradiction, an ambiguity, a MUST no implementation could meet, a
  vector that disagrees with its prose: open an issue ("Specification defect"), naming the version
  and section (`1.0 §14.2`).
- **A question or an idea:** open an issue ("Question or idea").
- **A change to what an implementation must do:** write a SEP. Copy `seps/TEMPLATE.md` to
  `seps/NNNN-short-title.md` with the next free number, fill in every section, and open a pull
  request with the SEP alone, status `Draft`. `seps/README.md` is the whole process, from review
  to text.
- **A correction that changes no requirement** (a typo, a broken reference, a clearer sentence): a
  pull request against the text, with its `CHANGES.md` line.
- **A security weakness:** never an issue. `SECURITY.md` says how to report it privately.

## Ground rules

- A released version's text (`docs/specification/1.0/`) changes only by a correction that changes
  no requirement, and that is a Z bump of its version line. Anything that changes what an
  implementation must do is written in `docs/specification/draft/`, by the process in
  `seps/README.md`.
- The text reads as the specification as it stands: it names no version of its own history. What
  a change altered goes in `CHANGES.md` under the version that carries it. The index page's line
  `**Version X.Y.Z · date**` is the version — the whitepaper cover parses it and the identity
  library's tests hold their `SPEC_VERSION` to its first token.
- A wire-visible change is a specification edit first. Then `npm run vectors` regenerates
  `vectors/hdtp-1.0-vectors.json` from the labels in `gen.mjs` and splices the JSON back into
  Appendix B, and `npm run vectors:check` proves that the text carries the generated vectors
  unchanged and that every case does what the text says.
- Every MUST sentence is hashed in the identity library's `js/musts.json` (the `hdtp-identity`
  repository), each entry naming the test or scenario that holds it. Editing a MUST changes its
  hash and fails that library's gate until the entry is re-verified in both of its ports, so say in
  the pull request which MUSTs you touched.
- `schema/*/schema.json` is generated from hdtp-identity's contract (`npm run schema`), never
  edited by hand; `npm run schema:check` fails when it differs. The same command writes
  `schema/*/reference.md` from it; `npm run docs:check` fails when that page differs from what
  `schema.json` generates, or when an example in `schema/*/examples/` does not validate against it.
- The name guard (`scripts/check-names.mjs`, run by `npm run vectors:check`) fails on any tracked
  path or text carrying a name `scripts/hdtp-names.txt` forbids.
- Mermaid blocks must render, and a heading stays under 120 characters. The whitepaper build fails
  on either, which is how an accidental setext heading (a paragraph followed directly by `---`)
  gets caught.
- A sentence about behaviour is written after measuring it: a count, a limit or a schedule quoted
  in prose is read from the text or the code it describes, never from memory.

## Getting set up

Node 22 and `npm ci`. The whitepaper build needs a Chrome, which
`puppeteer` downloads on install; `PUPPETEER_EXECUTABLE_PATH` points it at one already on the
machine. `npm run spec:check` and `npm run schema:check` need the `hdtp-identity` checkout beside
this one (or `HDTP_IDENTITY_DIR`).

```
npm run vectors:check     # the vectors against the specification, then the name guard (its self-test first)
npm run docs:check        # every section reference and link resolves; the schema's reference page and examples
npm run spec:check        # the web renderer and the open-fonts rule
npm run schema:check      # the schema is what hdtp-identity's contract generates
npm run build             # the newest released version -> dist/hdtp-whitepaper.pdf; the build is also a gate
npm run vectors:intrude   # the compromise cases against the in-memory node; a REPRODUCES is a finding
npm run vectors           # regenerate the vectors (only after a wire-visible edit)
```

`make check` runs the first four and `make build` the build. `make publish` is the maintainer's:
it puts the built PDF and its meta into the private bucket that hdtp.io serves, with credentials
read from a local file and from nowhere else.

## Gates and where they run

Every gate runs locally. Nothing runs on GitHub: there is no CI and no CI credential, and there
will be none. This repository has no git hooks.

| Gate | Needs |
|---|---|
| `npm run vectors:check`, `npm run docs:check`, `npm run build` | this checkout |
| `npm run spec:check`, `npm run schema:check` | the `hdtp-identity` checkout beside this one, or `HDTP_IDENTITY_DIR`; hdtp-identity is not public |

Without hdtp-identity, `schema:check` stops at once and `spec:check` fails its three tests of the
MUST registry. They fail rather than skip, so that `make check` cannot pass with the sibling
missing. Run the first three before opening a pull request and say in it that you did; the
maintainer runs all five before merging.

## Sending a change

- One logical change per commit. The message says what changed and why; if it fixes a defect,
  say how the defect was shown.
- A change to the text comes with its `CHANGES.md` entry in the same commit, and with regenerated
  vectors when it touched the wire.
- Inbound is outbound. A contribution is accepted only under the terms the repository gives out:
  - prose, the specification text included, under CC BY 4.0 (`LICENSE-docs`);
  - code and data under the Apache License 2.0 (`LICENSE`);
  - and, for the specification, the patent commitment of `PATENTS.md`: you make the Open Web
    Foundation Final Specification Agreement (OWFa 1.0, Patent Only) for the specification that
    includes your contribution, as an individual or, when you contribute for an employer or other
    organisation, for it as a Bound Entity, on the terms and with the scope the declaration there
    states.

  The README's "Licensing" section says which file falls under which licence.
- Every commit carries a sign-off: a `Signed-off-by: Your Name <you@example.com>` line, which
  `git commit -s` adds. It certifies the Developer Certificate of Origin 1.1
  (<https://developercertificate.org/>): that you wrote the contribution or otherwise have the
  right to submit it under the terms above. A pull request with a commit that has no sign-off is
  not merged.
- Conduct is `CODE_OF_CONDUCT.md`, the Contributor Covenant 2.1.
