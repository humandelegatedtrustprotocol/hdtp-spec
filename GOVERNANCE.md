# Governance

HDTP has one maintainer. This file is how decisions about the specification are made today, and what
changes when more people take part.

## Who decides

The maintainers listed in `MAINTAINERS.md` decide what the specification says. There is one, Sumit
Agrawal, for Shailka Systems Private Limited, and so one decision-maker: a change lands when he
merges it. There is no steering committee, working group or foundation, and none is implied by
anything in this repository.

A decision is made in the open where it can be — in a pull request, an issue or an enhancement
proposal (`seps/`) — and a decision that changes what an implementation must do is always written
down as a SEP before it becomes text.

## How the specification changes

- **The text.** A released version lives in `docs/specification/<X.Y>/`; the next one is written
  in `docs/specification/draft/`. `CHANGES.md` records what each released version changed.
- **Versions** are `X.Y.Z`, written once, in the version line of the index page:
  - Z is the usual increment: a correction or clarification that changes no requirement. It may be
    made in a released version's directory.
  - Y is a deliberate release of accumulated work, judged ready to stand as one. It is written in
    `draft/` and released as a new `X.Y` directory.
  - X is a new protocol generation that breaks the wire, and the only bump that moves the card's
    `X-HDTP-VERSION`, an envelope's `v` and an export's `hdtp_export`.
  - While a version is being written its line carries `-draft` (`1.1.0-draft`); releasing drops the
    suffix and tags `vX.Y.Z`.
- **Enhancement proposals.** A change to what an implementation must do — a new tool, a new rule, a
  change on the wire — starts as a SEP. `seps/README.md` is the process: how a SEP is written,
  reviewed, accepted or rejected, and how an accepted one becomes text in `draft/`.
- **Evidence.** The text is held by gates, all run locally; nothing runs on GitHub
  (`CONTRIBUTING.md`, "Gates and where they run"):
  - in this repository, `make check` runs `npm run vectors:check` (the vectors of Appendix B
    against the text, then the name guard), `npm run docs:check` (every section reference and link
    resolves, and the schema's reference page and examples hold to `schema.json`), the web
    renderer's tests (`npm run spec:check`) and the schema held to the identity library's contract
    (`npm run schema:check`); the last two read the sibling `hdtp-identity` (public since 2026-10-08).
    The whitepaper build (`npm run build`) is a gate too. The intrusion battery (`npm run vectors:intrude`) is run by hand here:
    no gate of this repository runs it;
  - locally, in `hdtp-identity`, that library's gate (`sh gate.sh`, its pre-push hook) runs this
    repository's vector check and intrusion battery again, and holds the MUST registry: every
    normative sentence of the text names the test or scenario that holds it.

  A change that the gates cannot hold says so in its pull request.

## Licences and patents

The text is CC BY 4.0 and the code and data Apache-2.0 (`README.md`, "Licensing"). Sumit Agrawal,
as an individual and for Shailka Systems Private Limited as a Bound Entity, has made the Open Web
Foundation Final Specification Agreement (OWFa 1.0, Patent Only) for the specification
(`PATENTS.md`), and every contributor makes the same commitment for the specification that includes
their contribution (`CONTRIBUTING.md`).

## When more people take part

Maintainers are added by the existing maintainers, by a change to `MAINTAINERS.md` that says what
each new maintainer is responsible for. If the project gains maintainers from outside Shailka
Systems Private Limited, this file will be rewritten to say how they decide together, before that
change is merged.

## Conduct

`CODE_OF_CONDUCT.md`, the Contributor Covenant 2.1, applies in every space of the project.
