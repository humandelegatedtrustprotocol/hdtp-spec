# Specification Enhancement Proposals (SEPs)

A SEP proposes a change to what an implementation of HDTP must do: a new tool, a new or changed
rule, a change on the wire. It is where the reasoning is written down before the text changes, so
that the specification never carries a requirement nobody argued for. A correction that changes
no requirement does not need one; `GOVERNANCE.md` says which changes are which.

## Writing one

1. Copy `TEMPLATE.md` to `seps/NNNN-short-title.md`, where `NNNN` is the next free number, four
   digits.
2. Fill in every section. "Specification changes" names each section of `docs/specification/draft/`
   the SEP touches and each MUST it adds, changes or removes. "Wire" says whether a version that
   implements the SEP still interoperates with one that does not, and if not, which version number
   moves.
3. Open a pull request with the SEP alone, status `Draft`.

## Statuses

| Status | Meaning |
|---|---|
| `Draft` | Open for discussion in its pull request. The author may change anything. |
| `In review` | The author asks for a decision; the text stops changing except to answer review. |
| `Accepted` | The maintainers merged it. It may now be written into `docs/specification/draft/`. |
| `Rejected` | The maintainers declined it; the SEP is merged with this status and its reasons, so the question has an answer on record. |
| `Withdrawn` | The author stopped it. Merged like a rejection, with the reason. |
| `Final` | Its text is in a released version. The SEP names that version. |

## From SEP to text

An accepted SEP becomes text by a second pull request, against `docs/specification/draft/`, that
also:

- adds the `CHANGES.md` lines it will carry when the draft is released;
- regenerates the vectors (`npm run vectors`) if it touched the wire, and the schema
  (`npm run schema`) if hdtp-identity's contract changed with it;
- names the SEP in its description.

When the draft is released as a new `docs/specification/<X.Y>/`, every SEP it carries moves to
`Final`, naming that version.

## Index

| SEP | Title | Status |
|---|---|---|
| [0001](0001-reading-a-pasted-card.md) | Reading a card whose folding was damaged in transit | Accepted; written into 1.0.0 in place |
