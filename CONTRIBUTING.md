# Contributing

This repository holds the PACT specification (`SPEC.md`), its revision history (`CHANGES.md`),
the test vectors of its Appendix B and the build of its whitepaper. Changes come as pull requests
and are reviewed by the maintainer; the required status check is `build`, the workflow in
`.github/workflows/whitepaper.yml`.

## Ground rules

- `SPEC.md` is the single source of truth, and its body reads as the specification as it stands:
  it names no version of its own history. What a change altered goes in `CHANGES.md` under the
  version that carries it. The header line `**Version X.Y.Z · date**` is the version — the
  whitepaper cover parses it and the identity library's tests hold their `SPEC_VERSION` to its
  first token — and an edited text is a Z bump.
- A wire-visible change is a specification edit first. Then `npm run vectors` regenerates
  `vectors/pact-2.0-vectors.json` from the labels in `gen.mjs`, the JSON is spliced back into
  Appendix B, and `npm run vectors:check` proves that the document carries the generated vectors
  unchanged and that every case does what the text says.
- Every MUST sentence in `SPEC.md` is hashed in the identity library's `js/musts.json` (the
  `pact-identity` repository, not yet public), each entry naming the test or scenario that holds
  it. Editing a MUST changes its hash and fails that library's gate until the entry is re-verified
  in both of its ports, so say in the pull request which MUSTs you touched.
- No PACT 1.x name comes back. `vectors/check-no-1x.mjs` fails the gate on any name 1.x had and
  2.x does not, outside `archive/`, `docs/landscape-and-roadmap.md` and the two files it lists
  with a reason.
- Mermaid blocks live in `SPEC.md` and must render; a heading stays under 120 characters. The
  whitepaper build fails on either, which is how an accidental setext heading (a paragraph
  followed directly by `---`) gets caught.
- A sentence about behaviour is written after measuring it: a count, a limit or a schedule quoted
  in prose is read from the text or the code it describes, never from memory.

## Getting set up

Node 22 (what the workflow uses) and `npm ci`. The whitepaper build needs a Chrome, which
`puppeteer` downloads on install; `PUPPETEER_EXECUTABLE_PATH` points it at one already on the
machine.

```
npm run vectors:check     # the vectors against SPEC.md, then the 1.x guard (its self-test first)
npm run build             # SPEC.md -> dist/pact-whitepaper.pdf; the build is also a gate
npm run vectors:intrude   # the compromise cases against the in-memory node; a REPRODUCES is a finding
npm run vectors           # regenerate the vectors (only after a wire-visible edit)
```

`make check` and `make build` are the same two gates. `make publish` is the maintainer's: it puts
the built PDF and its meta into the private bucket that pact-protocol.com serves, with credentials
read from a local file and from nowhere else.

## Gates and where they run

There is no CI credential and there will be none. The workflow runs `npm run vectors:check` and
`npm run build` on every push to `main` and on every pull request, with `permissions: contents:
read`; it publishes nothing and keeps no artifact. This repository has no git hooks. Run both
gates locally before opening a pull request; the workflow runs them again on it.

## Sending a change

- One logical change per commit. The message says what changed and why; if it fixes a defect,
  say how the defect was shown.
- A change to `SPEC.md` comes with its `CHANGES.md` entry in the same commit, and with
  regenerated vectors when it touched the wire.
- No tests, linters or runtime code beyond `vectors/` without saying why: the repository is
  deliberately small.
- Inbound is outbound. A contribution is accepted only under the terms the repository gives out:
  - prose, the specification text included, under CC BY 4.0 (`LICENSE-docs`);
  - code and data under the Apache License 2.0 (`LICENSE`);
  - and, for `SPEC.md`, the patent commitment of `PATENTS.md`: you make the Open Web Foundation
    Final Specification Agreement (OWFa 1.0, Patent Only) for the specification that includes your
    contribution, as an individual or, when you contribute for an employer or other organisation, for
    it as a Bound Entity, on the terms and with the scope the declaration there states.

  The README's "Licensing" section says which file falls under which licence.
- Every commit carries a sign-off: a `Signed-off-by: Your Name <you@example.com>` line, which
  `git commit -s` adds. It certifies the Developer Certificate of Origin 1.1
  (<https://developercertificate.org/>): that you wrote the contribution or otherwise have the
  right to submit it under the terms above. A pull request with a commit that has no sign-off is
  not merged.
