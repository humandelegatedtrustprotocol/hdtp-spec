# SEP-0005: A closed envelope

| | |
|---|---|
| Status | Accepted (by the owner, 2026-10-12) |
| Author | Sumit Agrawal <security@hdtp.io> |
| Created | 2026-10-11 |
| Target | 1.1 |

## Summary

An envelope (§13.1) is a JSON object of exactly four members, `protected`, `enc`, `ct` and `sig`,
each present and each a JSON string. A receiver refuses any other object with `envelope_invalid`,
before step 2 of the open order (§13.3): a fifth member, a member spelled another way, a member
absent, or a member that is not a string. A member that occurs more than once is read at its last
occurrence. The rule holds for a request envelope and for a result envelope alike.

## Motivation

§13.1 says an envelope "is a JSON object of four members" and closes the header and the plaintext,
but not the object itself. Nothing says what a receiver does with a fifth member, with `SIG`, or
with `sig` absent, so readers differed:

| Input to `sealed_call` | The node, before its fix | The node, 2026-10-11 | The cloud's reader, 2026-10-11 |
|---|---|---|---|
| a fifth member, `note` | dropped unread | `envelope_invalid` | `envelope_invalid` |
| `SIG` in place of `sig` | read as `sig` (Go matches names without regard to case) | `envelope_invalid` | `envelope_invalid` |
| `sig` absent, or `null`, small form | | `chain_required` | `envelope_invalid` |
| `sig` not base64url, small form | | `chain_required` | `envelope_invalid` |
| `sig` twice, the last one valid | | opened | read: the last |
| `sig` twice, a number then a valid string | | `envelope_invalid` | read: the last |

Measured 2026-10-11: the node through its `sealed_call` handler (`internal/public/sealed.go`), the
cloud at the envelope reader its `sealed_call` calls first. The "before" column is what the node's
own regression test records of the code it replaced. Both had closed the request side: the node holds the member names before Go's
decoder reads them, and the cloud refuses any key other than the four. Neither closed a result
envelope: the node reads a result into a Go struct, which drops a fifth member and matches names
without regard to case (`internal/outbound/seal.go`), and the cloud hands the result to
hdtp-identity's `open_result`, which requires the four and ignores any other.

Two rows are not about the object. A `sig` that is not canonical base64url is already refused by
§13.1 ("a receiver **MUST** refuse (`envelope_invalid`) a member written any other way"). The node
answered `chain_required` to it in the small form because hdtp-identity's `decide` (both ports) read
`sig` leniently and let the failure surface at the signature check, which answers the small form's
words. The cloud decodes all four members before it calls `decide`, and answers `envelope_invalid`.
The text was right and the node was wrong. This SEP puts the decoding in step 1, where it is visible.

Since 2026-10-11, two things in that row changed. hdtp-identity 0.8.1 (#59) reads `sig` strictly
before the form decides, in both ports, and refuses a `sig` not in its canonical base64url with
`envelope_invalid`; the node requires 0.8.1 or later since hdtp-gateway d0e917e, so its code answers
`envelope_invalid` to that row (read from the code, not re-run). The seed does the same since
hdtp-spec #61. The absent and `null` rows did not change in the node: Go's decoder leaves an absent or
`null` member as the empty string, which is the canonical spelling of zero bytes, so it reaches the
signature check and the small form answers `chain_required` (hdtp-identity v0.8.2,
`go/envelope.go`, the port the node runs). Since hdtp-gateway v0.1.4 (#122, which requires
hdtp-identity 0.8.3), the node refuses an absent or `null` `sig` with `envelope_invalid` before the
open.

## Specification changes

Sections touched: §13.1, §13.2 and §13.3 (`sealed-envelopes.md`), and the draft's Appendix B.

**§13.1, Format.** "An envelope is a JSON object of four members:" becomes:

> An envelope is a JSON object of exactly four members, each present and each a JSON string:

After the table's paragraph on base64url, a new paragraph:

> A receiver **MUST** refuse (`envelope_invalid`) an envelope that is not a JSON object, that lacks
> one of these four members or has any other, or one of whose members is not a JSON string. Member
> names are compared byte for byte: `SIG` is not `sig`. A member that occurs more than once is read at
> its last occurrence, and a receiver **MUST NOT** read or judge an earlier one. Both rules hold for a
> result envelope as for a request.

The rule is the receiver's so that it does not depend on whether an MCP library holds a call to the
tool's input schema; the node's go-sdk does not hold a raw tool to it.

**§13.2, Results.** "the receiving caller decodes, opens, …" becomes "the receiving caller reads the
envelope as step 1 of §13.3 does, opens, …".

**§13.3, Opening.** Step 1, "Decode `protected`.", becomes:

> 1. Read the envelope (§13.1): exactly the four members, each a JSON string in its canonical
>    base64url. Decode `protected`.

A failure at step 1 is `envelope_invalid`, as before ("A failure at a step that names no other
answer"). Step 1 reads all four members' spellings before step 3 resolves `kid`, so a misspelled
member sealed to a key the receiver once held is `envelope_invalid`, where a receiver that resolved
`kid` first answered `certificate_renewed`.

### The MUSTs this adds

1. §13.1: a receiver refuses an envelope that is not an object of exactly the four members, each a
   string.
2. §13.1: a member that occurs more than once is read at its last occurrence, and an earlier one is
   not read or judged.

### Duplicate members

The two readers agreed on 2026-10-11 on every case where each occurrence is a string: both read the last.
The cloud parses the request body once with `JSON.parse`, which keeps the last occurrence and leaves
no trace of the earlier ones. The node's go-sdk passes the arguments as raw bytes, and Go's
`encoding/json` keeps the last occurrence in a map and in a struct. The two differ only when an
earlier occurrence is not a string: Go's struct decoder reports the type error even though a later
occurrence overwrites it, and `JSON.parse` never sees it.

MUST 2 takes what the node and the cloud both do. The node was the side that changed: since v0.1.4
(#122) it decodes the arguments with hdtp-identity's reader, which reads each member at its last
occurrence. The cloud cannot see an earlier occurrence without replacing its body parser. The alternative,
refusing duplicates, is under Alternatives.

hdtp-identity 0.8.3 and the seed differ in a third case. The library holds the whole arguments text to
its argument boundary (its CONTRACT §0), including an earlier occurrence of a repeated member. A lone
UTF-16 surrogate, a number outside the range of a double, or nesting deeper than 127 inside an earlier
occurrence makes `decide` fail the call `bad_request` (`args: …`). The same text makes the Go port's
`Envelope` decoder return an error. The seed's `receiveText` keeps only the last occurrence and
answers `ok`. hdtp-identity's CONTRACT states this as a divergence from MUST 2 (measured for 0.8.3,
hdtp-identity f4984e1). The node decodes the arguments with that decoder, so it answers such text
`envelope_invalid`. This is read from the code, not re-run.

Duplicate members inside `protected` are not addressed here.

## Wire

A sender that follows 1.0 writes the four members and nothing else, so it interoperates with a
receiver that implements this SEP. A sender that adds a member is refused, where some 1.0 receivers
ignored the member. No version moves: 1.0 already defines the envelope as four members, and no
conforming sender writes anything else.

## Security

The envelope authenticates itself: whatever member a reader picks, `sig` must verify over
`protected ‖ enc ‖ ct`. An open object does not let an attacker forge an envelope. It lets two
readers disagree about which envelope arrived, and it gives a member nobody defined a place to
carry data past every check. A reader that ignores members accepts an envelope that a strict reader
refuses, the same split §13.1 closes for base64url spellings.

Reading the last occurrence of a repeated member gives a sender a second spelling of one envelope:
the same four values, written with a repeat. This adds nothing an attacker could use. The envelope
read is a real envelope that passes every later step, and §13.3 step 9 keys replay on `msg_id`,
inside `protected`, not on the text.

## Alternatives

- **Refuse duplicate members** (I-JSON, RFC 7493 §2.3). This is one spelling per envelope, and it
  is what Go's `encoding/json/v2` does by default (measured with Go 1.26.9 under
  `GOEXPERIMENT=jsonv2`). Neither implementation can detect a duplicate today
  without a new parser over the raw body. In the cloud that parser replaces `JSON.parse` for the
  whole JSON-RPC request. Today no reader in either implementation, and neither port of the core
  reading `protected`, refuses a duplicate. Declined for now because it costs both implementations
  a parser and closes no attack.
- **"Reject or lexically last"** (RFC 7515 §4). This leaves the choice to each receiver, which is
  the latitude §13.1 removes everywhere else.
- **Leave the object open, as 1.0 is.** This is the split the table above measured.

## Evidence

**Vectors.** Until this SEP, Appendix B's block was shared by 1.0 and the draft, and
`vectors/check.mjs` asserted that the two carried the same bytes. The draft's block is now the 1.0
block plus one member, `invalid_envelopes`, and 1.0's Appendix B does not move.

The plan said `vectors/gen.mjs` would rewrite 1.0's block unchanged. It cannot: every run signs the
P-256 vectors afresh, and a run on 2026-10-12 changed 8 lines of 1.0's Appendix B. So the draft's
block was spliced from the committed `vectors/hdtp-1.0-vectors.json`, and gen was not run.
`vectors/lib/invalid-envelopes.mjs` builds the entries from the envelopes, and `gen.mjs` splices the
draft through it, so the next regeneration keeps the draft and 1.0 in step. `check.mjs` holds the
draft's block to the 1.0 file plus the entries derived from it.

Each entry of `invalid_envelopes` is `{name, envelope, arguments_text, answer}`. `envelope` names one
of `envelopes`. `arguments_text` is the raw JSON text of the `sealed_call` arguments. `answer` is the
code that a receiver at `now`, holding that envelope's recipient key and Alina as a contact, gives.
The vector is text, not parsed JSON, because a parsed fixture cannot hold a duplicate. The eleven
entries are on `alina-to-bharat` unless named:

- a fifth member (`"note":"x"`), `envelope_invalid`;
- `SIG` in place of `sig`, `envelope_invalid`;
- `Protected` beside `protected`, `envelope_invalid`;
- `sig` absent, on `alina-to-bharat-by-reference` (the small form), `envelope_invalid`;
- `sig` `null`, on the same, `envelope_invalid`;
- `sig` a number, `envelope_invalid`;
- `sig` not base64url (`!!!!`), on the same small-form envelope, `envelope_invalid`;
- an array in place of the object, `envelope_invalid`;
- `sig` twice, `AAAA` then the real one, `ok`: the control for MUST 2;
- `sig` twice, the real one then `AAAA`, `envelope_invalid`. `AAAA` is canonical base64url, so this
  one is refused at the signature check (step 7), not at step 1;
- `sig` twice, `5` then the real one, `ok`.

Every entry except the controls is the unmodified text of a vector that opens, with one change, so
each refusal is due to that change. The seed reads the text with `receiveText` in
`vectors/lib/envelope.mjs`, which applies step 1 before the existing steps. `check.mjs` checks that
each entry answers its `answer`, and that each referenced envelope, written with each member once,
answers `ok`. The draft's Appendix B states the count of entries, and `check.mjs` holds that count to
the block.

**Intrusion scenarios.** `vectors/intrude.mjs` gained twelve scenarios in the category `envelope`.
They send the same cases as `sealed_call` text against the seed's receiver, plus one for the order of
step 1: a `sig` that is not base64url, sealed to a key the receiver once held, is refused and not
answered `certificate_renewed`. The two duplicate controls run last. Each refusal was shown red with
step 1 removed from the seed, or with `sig` read leniently or after `kid`. Each duplicate scenario
was shown red under a reader that keeps the first occurrence.

**Battery.** This part is planned and not built. The cloud's conformance battery, in its `envelope` group, gains
one subtest. The subtest posts each refusal above as raw `sealed_call` arguments, as the pinned
contact, and wants `envelope_invalid` for each. The group's existing control, a well-formed envelope
that opens, runs first and changes no state (`get_card`). The duplicate control, with the real `sig`
last, runs after the refusals and wants an opened envelope. The subtest needs a raw-text post beside
the battery's struct-encoding one, because the struct encoder cannot write a duplicate, a fifth
member or an absent one. The node's live harness gains the same cases in its `envelope` scenarios.

**Implementations.**

| Holder | Change | State |
|---|---|---|
| the seed | step 1 refuses another object and reads the four spellings before `kid`; `receiveText` reads the text | done (hdtp-spec #63) |
| hdtp-identity, both ports | `decide` refuses a `sig` that is not canonical base64url as `envelope_invalid` before any form-specific answer | done in 0.8.1 (#59) |
| hdtp-identity, both ports | one reader for `decide` and `open_result` refuses another object (`envelope members`, `envelope member types`); `decide` reads the spellings of `enc`, `ct` and `sig` before it resolves `kid`; its intrusion suite runs the twelve scenarios by name | done in 0.8.3 (#66) |
| the node, requests | `envelopeOf` decodes the arguments with hdtp-identity's `Envelope` decoder, which refuses another object, an absent member or one that is not a string (`null` included), and keeps the last occurrence of a repeated member | done in v0.1.4 (#122) |
| the node, results | a peer's result is decoded with the same decoder before `OpenResult`; a refusal is `envelope_invalid`, and no `get_card` is asked | done in v0.1.4 (#122) |
| the cloud, requests | `decodeEnvelope` refuses another member, an absent member and one that is not a string before `decide` | done (batondeck #278, 2026-10-11) |
| the cloud, results | re-vendors hdtp-identity 0.8.3, whose `open_result` refuses another object; the client answers that refusal `envelope_invalid`, with no `get_card` and no re-pin | done (batondeck #291) |

The node's `TestAnEnvelopeOfOtherMembersIsRefused` has the absent, `null` and duplicate cases; its
commit records them red on hdtp-identity 0.8.2 for the absent and `null` ones. The cloud's envelope
reader tests have the absent case and not the `null` or duplicate ones: those are to do.
