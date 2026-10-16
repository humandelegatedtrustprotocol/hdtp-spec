# SEP-0006: Two forms of a `thread_id`

| | |
|---|---|
| Status | Accepted (by the owner, 2026-10-11) |
| Author | Sumit Agrawal <security@hdtp.io> |
| Created | 2026-10-11 |
| Target | 1.0.2 |

## Summary

A `thread_id` is 1 to 64 ASCII letters and digits, or a UUID in lower case, and nothing else. A
receiver refuses one of more than 64 bytes with `too_large` and any other of neither form with
`bad_request`, at every tool that takes one, and records nothing of the call. A host sends only these
forms, and assigns one not taken from the call's arguments. A host deletes every thread it holds outside them, with its messages, when it
adopts this SEP; an importer leaves such a thread out of an import. A writer re-issues an id that
reads as a private key as `r` and 62 hex digits, which is of the first form.

## Motivation

§7 lets whoever sends first choose a `thread_id`, and no rule bounds it. It enters at three
arguments (§6.2): `send_message`, `send_media` and `book_slot`. Each implementation set its own
bounds, measured on both `main` branches on 2026-10-11:

| | The node | The cloud |
|---|---|---|
| `send_message`, `send_media` | at most 1024 bytes, any characters | at most 128 bytes, any characters |
| `book_slot` | at most 1024 bytes, then ignored | at most 256 bytes, then ignored |
| absent or empty | a new id: 32 random lower-case hex digits | the call's `msg_id`, which the contact also chose |

The cloud's owner surface counted 128 UTF-16 code units until batondeck #285, which counts bytes.
What a contact could do with an unbounded id:

- **Stop the owner leaving.** An importer refuses any cell or message member that holds a private key
  (§9.2, Key material). hdtp-identity 0.8.0 refused the whole `export_write` for a thread whose `id`
  was `x PRIVATE KEY----- y` (20 bytes) or `MAoCAQAwAwYBAAQA` (16 bytes, a PKCS #8 shape in
  base64url), and `export_write_messages` the same way for the message's `thread` member, so one
  `send_message` from a contact failed the owner's export. hdtp-identity 0.8.1 fixed this in the
  writer: such an id is written as `r-` and the first 62 hex digits of its sha256. That re-issued id
  contains `-` and is of neither form of this SEP, so this SEP changes the prefix to `r` (§9.2).
- **Make a conversation unreachable in the owner's interface.** Both portals took a thread's id as a
  URL path segment, escaped by `encodeURIComponent`, which leaves `.` and `..` unchanged; a URL parser
  removes those segments and Go's `ServeMux` redirects them. A thread whose id was `.` or `..` could
  not be opened, sent into or deleted. hdtp-gateway #118 and batondeck #285 fixed this, by moving the
  id to the query or the form. Neither form of this SEP can spell `.` or `..`.
- **Fill an export with what a reader expands.** An id could hold characters below U+0020, which a
  reader answering a member as JSON writes as six bytes each. SEP-0004 left this open: "bound
  `thread_id` where it enters (§7), or leave such a file to a host's ceiling."
- **Write into what other systems read.** The cloud delivers a `send_message`'s `thread_id` to
  webhooks in its `message.received` event, so control and bidirectional characters the contact chose
  reached them.

Storage is not the motivation. The `text` beside a `thread_id` may already be 16384 bytes.

## Specification changes

Sections touched: §6.2 (`mcp-server.md`), §7 (`messaging.md`), §9.2 (`hosting.md`).

**§7, Messaging and threads**, a new paragraph after the first:

> A `thread_id` has one of two forms: 1 to 64 ASCII letters and digits, `^[A-Za-z0-9]{1,64}$`; or a
> UUID in the textual form of RFC 9562, Section 4, in lower case,
> `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`, whatever its version and
> variant. Two `thread_id`s are the same only when their bytes are. A receiver **MUST** refuse, at
> every tool that takes a `thread_id`, a `thread_id` of more than 64 bytes with `too_large`, and any
> other `thread_id` of neither form, the empty string included, with `bad_request`, and record
> nothing of the call: not the message, its thread, nor the call's `msg_id` or its envelope's as
> seen; what §13.3 learns before dispatch, a renewal (§14.3) or a new address (§5.3), is still
> learned, and the call spends its budget (§12). A `thread_id` of
> `null` is no `thread_id`. A host **MUST NOT** send a `thread_id` of neither form. A host that
> assigns a `thread_id` **MUST** assign one of the two forms, and one not taken from the call's
> arguments.

`too_large` comes first, so a 2000-byte id of any characters is `too_large`, as both implementations
answer an over-long id today. The empty string is `bad_request`; both implementations read it today as
no `thread_id`.

**§6.2, Contact tier.** `send_message`, `send_media` and `book_slot` list `thread_id` as "string or
`null`, optional: at most 64 bytes, fixed, of a form of §7". §6.1 says the bounds of §6.2 are
`limits` defaults "but for a `thread_id`'s, which §7 fixes".

**§9.2, Import.** Step 1 shows the person "the `id` of each thread it leaves out (step 3)". Step 3
adds:

> An importer **MUST NOT** write a thread whose `id` is of neither form of §7, nor its messages, nor a
> media file that only those messages name, and writes `null` as the `reply_to` of a message it writes
> that names one it left out; such an `id` is not a reason to refuse the file.

**§9.2, What a contact controls**, new last sentences:

> To re-issue an id is to write it as `r` followed by the first 62 lowercase hex digits of the
> sha256 of its UTF-8 bytes. A writer **MUST** re-issue every id that is already `r` followed by 62
> lowercase hex digits, wherever it appears: a thread's `id`, or a message's `thread`, `msg_id` or
> `reply_to`. A writer **MUST** re-issue a thread's `id`, a message's `thread` and `reply_to`, and
> the `msg_id` of a message that came in, that the key-material check above would refuse; the
> `msg_id` of a message that went out that the check would refuse is refused (The owner's own
> strings). Every other id is written as it is. A contact can choose a thread's `id` (§7) and the
> `msg_id` of a message it sends, and an id is written alike wherever it appears, so the file's
> references hold and no two ids are written as one.

**§9.2, The owner's own strings** adds "a message that went out whose `msg_id` that check would
refuse, naming the message".

The export format does not change: `threads.csv`'s `id` and a message's `thread` stay strings, and a
file with an `id` of neither form is still read and validated whole.

### The MUSTs this adds or changes

1. §7: a receiver refuses a `thread_id` of neither form: `too_large` over 64 bytes, `bad_request`
   otherwise, recording nothing of the call, neither its `msg_id` nor its envelope's (a renewal or
   new address learned from its envelope, §14.3 and §5.3, is still learned, and the call spends its
   budget, §12).
2. §7: a host does not send a `thread_id` of neither form.
3. §7: a host that assigns a `thread_id` assigns one of the two forms, not taken from the call's arguments.
4. §9.2 Import, step 3: an importer does not write a thread of neither form, its messages or the files
   only they name.
5. §9.2 Import, step 1 (changed): the importer shows the `id` of each thread it leaves out.
6. §9.2 What a contact controls: a writer re-issues every id already of the re-issued form, outgoing
   `msg_id`s included, as hdtp-identity 0.8.1's `reissued_id` does; and a thread id, a `thread`, a
   `reply_to` and an incoming `msg_id` that read as a key.
7. §9.2 The owner's own strings (changed): a writer refuses a message that went out whose `msg_id`
   reads as a key.

## Grammar

- **Letters and digits, or a UUID.** Neither form holds `.`, `/`, a space, a control or bidirectional
  character, or anything outside ASCII, each of which breaks a URL path segment, a CSV cell, a log line
  or a display. Neither can begin a CSV cell with a character §9.2's Spreadsheet formulas guards, so a
  cell is the id byte for byte. Hyphens appear only in the UUID form.
- **No minimum beyond one character.** A host need not fill 64 characters: the bound is a ceiling,
  room for a UUID (36), the node's 32 hex digits, a SHA-256 in hex (64) and the writer's re-issued
  ids (63). The forms are ASCII, so characters, bytes and UTF-16 units are the same count.
- **One spelling of a UUID.** Lower case only, so a UUID cannot be sent in two spellings that compare
  unequal, and a UUID with its hyphens removed is of the first form and a different id.
- **Case matters in the first form.** `Abc` and `abc` are two ids. §7's rule that a `thread_id`
  belongs to the contact that first used it compares bytes.
- **Key material is the writer's.** `MAoCAQAwAwYBAAQA` is of the first form, and decodes as a PKCS #8
  shape. The forms do not keep a key out of an id; §9.2's writer rule does, by re-issuing it.
- **Fixed, not a `limits` member.** A `thread_id` is shared by two hosts (§7). A bound one host could
  raise would let it start a thread its peer must refuse.
- **What both implementations already assign is of a form.** The node's new threads are 32 lower-case
  hex digits; the cloud's are `crypto.randomUUID()`, which is lower case. The spec's own examples
  (§6.2, Appendix A) are a lower-case UUID and 32 lower-case hex digits.

## Migration

The owner chose the migration on 2026-10-11: "wipe them". No implementation keeps a path for an id of
neither form: no alias, no redirect, no second reader, no new id.

- **Stored threads.** A host adopting this SEP deletes every thread it holds whose id is of neither
  form, with its messages, their files, its read marker and its change-feed rows, in the migration
  that ships the check. This reaches a thread a host imported from a file hdtp-identity 0.8.1 wrote
  under a re-issued `r-` id.
- **The peer** still holds its copy. If it continues the thread under the old id, a host that has
  adopted this SEP refuses it (MUST 1). A peer that has adopted this SEP has deleted its own copy.
- **Exports.** After the migration a host holds no id of neither form, so its exports carry none. A
  file written earlier still imports; the importer leaves out each thread of neither form with its
  messages, and shows the person their ids first (MUSTs 4 and 5). A file hdtp-identity 0.8.1 wrote
  with a re-issued `r-` id loses that thread on import.
- **The cloud's fallback** to the caller's `msg_id` as a thread's id ends. A `send_message` without a
  `thread_id` gets a new id the host chooses (MUST 3).

How many stored threads each host deletes is one query against its own store. This SEP does not state
a number.

## Wire

A 1.0.2 receiver refuses an earlier 1.0 sender's `thread_id` of neither form, and the empty string. Both
implementations' own ids are of a form, so between them the break is only for ids a caller chose: a
contact's agent, or an owner on a surface that passes the owner's choice through. A 1.0.2 importer
leaves out an earlier 1.0 file's thread of neither form. No version moves: GOVERNANCE moves `X-HDTP-VERSION`
and `hdtp_export` only with X, and a caller that sends no `thread_id`, or sends back the one it was
given, is not affected. The node and the cloud ship this before 1.0.2 is released.

## Security

What this closes: an id that hides a conversation from the owner's interface, an id that expands an
export's JSON reading, and control characters a contact passes to webhooks. An id that reads as a
private key stays possible in the first form; §9.2's writer rule keeps it from stopping the export,
and the importer's key-material check is unchanged. It does not touch §14.5's cases.

A contact can still choose a `topic`, a `display_name` and a `msg_id`; hdtp-identity 0.8.1's writer
blanks a key-shaped `topic` or `display_name` and re-issues a key-shaped `msg_id`. Only the `msg_id`
part of that is written into §9.2 here.

## Alternatives

- **`^[a-z0-9][a-z0-9-]{0,63}$`** (this SEP's draft). Lower case keeps a key's base64 out of an id,
  but not its hex, and refuses the upper-case ids and UUIDs a caller might reasonably send. The owner
  chose letters and digits, or a UUID.
- **A length bound alone** (both implementations before this SEP). `.`, `..` and control characters
  stay ids.
- **Re-id stored and imported threads** (the draft's migration). It keeps a second id space alive in
  the store and the import path. The owner chose deletion.
- **Refuse a file with an `id` of neither form.** A person's whole import would fail for one thread.
- **A host-tunable bound in `limits`.** See Grammar.

## Implementations

| Where | What it implements | State |
|---|---|---|
| The node (hdtp-gateway) | MUST 1 at `send_message`, `send_media` and `book_slot` (replacing the 1024-byte cap for `thread_id`), MUST 2 at the owner surfaces (owner MCP, portal), MUST 3 (already 32 hex digits); migration 0005, which deletes stored threads of neither form; the import of MUSTs 4 and 5 through hdtp-identity | built, v0.1.4 (#120, #121) |
| The cloud (batondeck) | MUST 1 at the three tools (replacing the 128- and 256-byte caps), MUST 2 at `/v1`, the owner MCP and the portal, MUST 3 (ending the fallback to `msg_id`); the identity Durable Object's migration 1005, which deletes stored threads of neither form, and which a snapshot restore runs again over what it writes back; the import of MUSTs 4 and 5 through hdtp-identity | built (#287), in production since 2026-10-12 (batondeck 39fb9b7e) |
| hdtp-identity, export | MUST 6 with the `r` prefix in both ports (0.8.1 wrote `r-`), and a re-issued form of `r` and 62 lowercase hex digits; MUST 7 (0.8.1 already refuses an outgoing key-shaped `msg_id`) | built, 0.8.2 |
| hdtp-identity, import | MUSTs 4 and 5 in both ports: the threads of neither form, their messages and the files only they name left out and listed, `reply_to` into them written `null`; a corpus file holding such a thread, and one holding an `r-` id | built, 0.8.2 |
| hdtp-identity, intrusion parity | the 22 `thread` scenarios of the seed, run on both ports | built, 0.8.2 |
| The seed (`vectors/`) | MUST 1 in `receive()` (`threadIdRefusal` in `lib/envelope.mjs`) and the 22 `thread` scenarios of `intrude.mjs` | built (hdtp-spec #62) |

## Evidence

| MUST | Holder |
|---|---|
| 1 | the seed's 22 `thread` scenarios: 65 letters and digits, 65 bytes of neither form and 33 two-byte characters refused `too_large`; `.`, `..`, `a/b`, `a-b`, `r-` and 62 hex digits, an upper-case UUID, 32 hex digits with one hyphen, the empty string, U+0001, a trailing line break, `é` and a number refused `bad_request`, nothing recorded; the same at `send_media`, `book_slot` and in the small form; the controls, run last: `null`, `r` and 62 hex digits, a lower-case UUID, and 64 letters and digits at all three tools. Each was shown red on a mutated `receive()`, the controls included. hdtp-identity 0.8.2 runs the 22 on both ports. The node's tool tests run one table of ids at each tool, holding the seed's ids and others (`testid.ThreadIDs`). The cloud's `thread-id-door` tests refuse at each tool with nothing recorded. The cloud's conformance battery sends three cases: a dot, 65 letters and a control |
| 2 | the node's owner-surface tests (portal and owner MCP: an id of neither form is refused); the cloud's `thread-id-door` test of the owner's `callContact`, refused before anything is sent |
| 3 | the cloud's `thread-id-door` test: a call that names no thread is placed in a new thread whose id is not its `msg_id`. (planned) the node's test of the same |
| 4, 5 | hdtp-identity 0.8.2's import tests on both ports, over the corpus files `valid-export-with-a-left-out-thread.zip` and `valid-export-with-a-0.8.1-reissued-thread-id.zip`; the node's `TestTheReviewShowsEachThreadTheImportLeavesOut`; the cloud's export tests over the corpus's left-out thread |
| 6, 7 | hdtp-identity 0.8.2's export tests on both ports: `MAoCAQAwAwYBAAQA` as a thread id and as a `msg_id`, re-issued alike in `threads.csv` and `messages.jsonl`, an id already re-issued re-issued again, and an outgoing key-shaped `msg_id` refused |
| The migration | the node's `TestTheWipeDeletesEveryConversationOfNeitherFormAndOnlyThose`: a stored thread of neither form goes with its messages, change rows and read marker, and a thread of a form is untouched (the control); the cloud's migration 1005 test: each thread of neither form goes with its messages, files and read marker, the rest and every acknowledgment stay |

The new MUSTs are in `docs/specification/draft/`. hdtp-identity's MUST registry reads the newest
released version, 1.0.1, so it holds them when 1.0.2 is released, not before.

The spec repository's vectors do not change: no envelope, certificate or card carries a `thread_id`,
and the examples of §6.2 and Appendix A are of the UUID and first forms.
