# SEP-0005: A closed envelope

| | |
|---|---|
| Status | Draft |
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
with `sig` absent, so readers differ:

| Input to `sealed_call` | The node, before its fix | The node, today | The cloud's reader, today |
|---|---|---|---|
| a fifth member, `note` | dropped unread | `envelope_invalid` | `envelope_invalid` |
| `SIG` in place of `sig` | read as `sig` (Go matches names without regard to case) | `envelope_invalid` | `envelope_invalid` |
| `sig` absent, or `null`, small form | | `chain_required` | `envelope_invalid` |
| `sig` not base64url, small form | | `chain_required` | `envelope_invalid` |
| `sig` twice, the last one valid | | opened | read: the last |
| `sig` twice, a number then a valid string | | `envelope_invalid` | read: the last |

Measured 2026-10-11: the node through its `sealed_call` handler (`internal/public/sealed.go`), the
cloud at the envelope reader its `sealed_call` calls first. The "before" column is what the node's
own regression test records of the code it replaced. Both closed the request side recently: the node holds the member names before Go's
decoder reads them, and the cloud refuses any key other than the four. Neither closes a result
envelope: the node reads a result into a Go struct, which drops a fifth member and matches names
without regard to case (`internal/outbound/seal.go`), and the cloud hands the result to
hdtp-identity's `open_result`, which requires the four and ignores any other.

Two rows are not about the object. A `sig` that is not canonical base64url is already refused by
§13.1 ("a receiver **MUST** refuse (`envelope_invalid`) a member written any other way"). The node
answers `chain_required` to it in the small form because hdtp-identity's `decide` (both ports) reads
`sig` leniently and lets the failure surface at the signature check, which answers the small form's
words. The cloud decodes all four members before it calls `decide`, and answers `envelope_invalid`.
The text is right and the node is wrong. This SEP puts the decoding in step 1, where it is visible.

## Specification changes

Sections touched: §13.1, §13.2 and §13.3 (`sealed-envelopes.md`).

**§13.1, Format.** "An envelope is a JSON object of four members:" becomes:

> An envelope is a JSON object of exactly four members, each present and each a JSON string:

After the table's paragraph on base64url, a new paragraph:

> A receiver **MUST** refuse (`envelope_invalid`) an envelope that is not a JSON object, that has a
> member other than these four, or that lacks one of them, or one of whose members is not a JSON
> string. Member names are compared byte for byte: `SIG` is not `sig`. A member that occurs more than
> once is read at its last occurrence, and a receiver **MUST NOT** read or judge an earlier one.

The rule is the receiver's so that it does not depend on whether an MCP library holds a call to the
tool's input schema; the node's go-sdk does not hold a raw tool to it.

**§13.2, Results.** "the receiving caller decodes, opens, …" becomes "the receiving caller reads the
envelope as step 1 of §13.3 does, opens, …".

**§13.3, Opening.** Step 1, "Decode `protected`.", becomes:

> 1. Read the envelope (§13.1): exactly the four members, each a JSON string in its canonical
>    base64url. Decode `protected`.

A failure at step 1 is `envelope_invalid`, as today ("A failure at a step that names no other
answer").

### The MUSTs this adds

1. §13.1: a receiver refuses an envelope that is not an object of exactly the four members, each a
   string.
2. §13.1: a member that occurs more than once is read at its last occurrence, and an earlier one is
   not read or judged.

### Duplicate members

The two readers agree today on every case where each occurrence is a string: both read the last.
The cloud parses the request body once with `JSON.parse`, which keeps the last occurrence and leaves
no trace of the earlier ones. The node's go-sdk passes the arguments as raw bytes, and Go's
`encoding/json` keeps the last occurrence in a map and in a struct. The two differ only when an
earlier occurrence is not a string: Go's struct decoder reports the type error even though a later
occurrence overwrites it, and `JSON.parse` never sees it.

MUST 2 takes what both do. The node is the side that changes: it reads each member from the map it
already builds, whose values are the last occurrences, and not by decoding the whole object a second
time. The cloud cannot see an earlier occurrence without replacing its body parser. The alternative,
refusing duplicates, is under Alternatives.

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

**Vectors.** Appendix B's block is shared today by 1.0 and the draft, and `vectors/check.mjs`
asserts that the two carry the same bytes "until a change to the wire regenerates it". This SEP is
that change, and 1.0's Appendix B does not move. The plan:

1. `vectors/gen.mjs` writes `vectors/hdtp-1.0-vectors.json` unchanged and a draft block that is the
   1.0 block plus one member, `invalid_envelopes`. It splices the 1.0 block into 1.0's Appendix B
   (a no-op) and the draft block into the draft's.
2. Each entry of `invalid_envelopes` is `{name, envelope, arguments_text, answer}`:
   `envelope` names one of `envelopes`, `arguments_text` is the raw JSON text of the `sealed_call`
   arguments, and `answer` is the code a receiver at `now` holding that envelope's recipient key
   gives. The vector is text, not parsed JSON, because a parsed fixture cannot hold a duplicate. The
   entries, on `alina-to-bharat` unless named:
   - a fifth member (`"note":"x"`), `envelope_invalid`;
   - `SIG` in place of `sig`, `envelope_invalid`;
   - `Protected` beside `protected`, `envelope_invalid`;
   - `sig` absent, on `alina-to-bharat-by-reference` (the small form), `envelope_invalid`;
   - `sig` `null`, on the same, `envelope_invalid`;
   - `sig` a number, `envelope_invalid`;
   - `sig` not base64url (`!!!!`), on the same small-form envelope, `envelope_invalid`;
   - an array in place of the object, `envelope_invalid`;
   - `sig` twice, `AAAA` then the real one, `ok`: the control for MUST 2;
   - `sig` twice, the real one then `AAAA`, `envelope_invalid`;
   - `sig` twice, `5` then the real one, `ok`.
   Every entry but the controls is the unmodified text of a vector that opens with one change, so
   each refusal is due to that change.
3. `vectors/check.mjs` holds 1.0's Appendix B to the 1.0 file and the draft's to the draft block,
   and runs every entry through `vectors/lib/envelope.mjs`. Its `receive` gains a reader for the
   text (`receiveText`) that applies step 1 before the existing steps. Each entry is checked to
   answer its `answer`, and the unmodified text of each referenced envelope is checked to answer
   `ok`.

**Battery.** The cloud's conformance battery, in its `envelope` group, gains one subtest that posts
each refusal above as raw `sealed_call` arguments, as the pinned contact. It wants `envelope_invalid`
for each. The group's existing control, a well-formed envelope opened, runs first and changes no
state (`get_card`). The duplicate control, the real `sig` last, runs after the refusals and wants an
opened envelope. The subtest needs a raw-text post beside the battery's struct-encoding one, which
cannot write a duplicate, a fifth member or an absent one. The node's live harness gains the same
cases in its `envelope` scenarios.

**Implementations.**

| Holder | Change |
|---|---|
| hdtp-identity, both ports | `decide` refuses a `sig` that is not canonical base64url as `envelope_invalid` before any form-specific answer, as §13.1 already requires. That aligns the node, which calls `decide` without decoding first |
| the node, requests | `envelopeOf` refuses an absent or `null` member and reads each member from the map of last occurrences |
| the node, results | the result reader goes through `envelopeOf` |
| the cloud, results | the result is read by the request side's envelope reader before `open_result` |

The node's `TestAnEnvelopeOfOtherMembersIsRefused` and the cloud's envelope reader tests gain the
absent, `null` and duplicate cases, each shown red on the code as it is.
