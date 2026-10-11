# SEP-0006: A bounded `thread_id`

| | |
|---|---|
| Status | Draft |
| Author | Sumit Agrawal <security@hdtp.io> |
| Created | 2026-10-11 |
| Target | 1.1 |

## Summary

A `thread_id` is 1 to 64 characters, each a lower-case ASCII letter, a digit or `-`, and the first
is not `-`. A receiver refuses a longer one with `too_large` and any other spelling with
`bad_request`, at every tool that takes one. A host that assigns a `thread_id` assigns one in this
grammar. A host that holds a thread outside it gives that thread a new id once, when it adopts this
SEP or imports it. No reader for the old id remains.

## Motivation

§7 lets whoever sends first choose a `thread_id`, and no rule bounds it. It enters at three
arguments (§6.2): `send_message`, `send_media` and `book_slot`. Each implementation set its own
bounds:

| | The node | The cloud |
|---|---|---|
| `send_message`, `send_media` | at most 1024 bytes, any characters | at most 128 bytes, any characters |
| `book_slot` | at most 1024 bytes, then ignored | at most 256 bytes, then ignored |
| absent or empty | a new id: 32 random lower-case hex digits | the call's `msg_id`, which the contact also chose |
| owner surfaces | the owner MCP passes the owner's choice through | at most 128 UTF-16 code units, any characters |

Measured 2026-10-11 against both implementations' code. What a contact can do with that today:

- **Stop the owner leaving.** An export carries every thread (§9.2, "Which conversations travel"),
  and an importer refuses any cell or message member that holds a private key (§9.2, Key material).
  hdtp-identity 0.8.0, which both implementations export with, refuses the whole `export_write` for
  a thread whose `id` is `x PRIVATE KEY----- y` (20 bytes) or `MAoCAQAwAwYBAAQA` (16 bytes, a
  PKCS #8 shape in base64url): `threads[0], column id: holds a private key`. It refuses
  `export_write_messages` the same way for the message's `thread` member. No rule lets a writer leave
  a thread out for its id, and an id cannot be rewritten in an export, because messages refer to it.
  One `send_message` from a contact fails the owner's export until the owner deletes that
  conversation. §9 says a person can always leave with their data. The id is not the only such
  door (Security), but it is the one a writer cannot repair, because messages refer to it.
- **Fill an export with what a reader expands.** An id may hold characters below U+0020, which a
  reader answering a member as JSON writes as six bytes each. SEP-0004 leaves this open: "bound
  `thread_id` where it enters (§7), or leave such a file to a host's ceiling."
- **Make a conversation unreachable in the owner's interface.** The cloud's portal opens, marks read
  and deletes a thread by its id in a URL path segment, and the node's portal deletes one that way.
  Both escape the id with `encodeURIComponent`, which leaves `.` and `..` unchanged. A URL parser
  removes those segments (WHATWG URL in Node 24: `…/threads/..` becomes `…/`), and Go's `ServeMux`
  redirects them (307). A thread whose id is `.` or `..` cannot be opened in the cloud's portal or
  deleted from either portal.
- **Write into what other systems read.** The cloud delivers a `send_message`'s `thread_id` to
  webhooks in its `message.received` event, so control and bidirectional characters the contact
  chose reach them.

Storage is not the motivation. The `text` beside a `thread_id` may already be 16384 bytes.

The URL and expansion findings were measured on replicas: Go 1.26.9's `ServeMux` and Node's `URL`
with the portals' escaping, and the JSON expansion from SEP-0004's measurement. The export refusals
were measured on hdtp-identity 0.8.0's pinned Wasm release.

## Specification changes

Sections touched: §6.2 (`mcp-server.md`), §7 (`messaging.md`), §9.2 (`hosting.md`).

**§7, Messaging and threads.** After "A `thread_id` is a unique string chosen by whoever sends
first; …":

> A `thread_id` matches `^[a-z0-9][a-z0-9-]{0,63}$`: 1 to 64 characters, each a lower-case ASCII
> letter, a digit or `-`, the first not `-`. A receiver **MUST** refuse a `thread_id` of more than 64
> bytes with `too_large`, and any other `thread_id` that does not match with `bad_request`, at every
> tool that takes one, before it records anything. A host **MUST NOT** send a `thread_id` that does
> not match. A host that assigns a `thread_id` (a `send_message` that carries none) **MUST** assign
> one that matches and that the caller did not choose.

A `thread_id` of `null` is no `thread_id`, as both implementations read it today. `too_large`
comes first, so a 2000-byte id with upper-case letters is `too_large`, as both
implementations answer an over-long id today. An empty string does not match and is `bad_request`.
Today both implementations read it as no `thread_id`, and the empty string is the one input whose
answer this changes in both.

**§6.2, Contact tier.** `send_message`, `send_media` and `book_slot` list `thread_id` as "string,
optional, §7's grammar".

**§9.2, Import**, step 3 adds:

> A thread whose `id` does not match §7's grammar is written under an id the importer assigns by §7,
> and its messages with it.

The export format does not change: `threads.csv`'s `id` and a message's `thread` stay strings
bounded by an importer's ceilings. A file written before its host adopted this SEP still imports.

### The MUSTs this adds

1. §7: a receiver refuses a `thread_id` outside the grammar: `too_large` over 64 bytes,
   `bad_request` otherwise.
2. §7: a host does not send a `thread_id` outside the grammar.
3. §7: a host that assigns a `thread_id` assigns one in the grammar that the caller did not choose.

The rule of §9.2 Import, step 3, is an addition to an existing step, not a new MUST.

## Grammar

- **Lower-case letters, digits and `-`.** Every key-material reader decodes only a word that begins
  with `M`, which is how base64 of either alphabet writes a DER key's first byte, `0x30`. The armour
  test looks for `PRIVATE KEY-----`. A lower-case id can spell neither. Allowing upper case lets a
  16-character id stop an export, as shown above. The guarantee rests on those readers, not on a
  MUST: §9.2's Key material row says a cell that "decodes as a private key" and names no encoding.
  A key's DER in lower-case hex is a valid id (`300a02010030030601000400` is the PKCS #8 shape above),
  and hdtp-identity 0.8.0 writes it. A reader that also decoded hex would refuse it. Naming the
  encodings in §9.2 (PEM armour, a base64 or base64url word) is an open question for this SEP. Lower case also gives one spelling per id: no two
  ids differ only by case.
- **No `.`, `/`, space, control or bidirectional character.** Each one breaks a URL path segment, a
  CSV cell, a log line or a display. `-` cannot begin an id, because a CSV cell that begins with `-`
  is written with a guarding `'` (§9.2, Spreadsheet formulas), which would make the cell differ
  from the id.
- **64 characters.** Room for a UUID (36), the node's 32 hex digits, a SHA-256 in hex (64) and
  anything a host might derive from them. The grammar is ASCII, so characters and bytes are the same
  count, and so are UTF-16 units.
- **Fixed, not a `limits` member.** A `thread_id` is shared by two hosts (§7). A bound one host could
  raise would let it start a thread its peer must refuse.
- **What both implementations already assign matches.** The node's new threads are 32 lower-case
  hex digits. The cloud's are `crypto.randomUUID()`, which is lower case. The spec's own examples
  (§6.2, Appendix A) are a lower-case UUID and 32 lower-case hex digits.

## Migration

No implementation keeps a path for an id outside the grammar: no alias, no redirect, no second
reader.

- **Stored threads.** A host adopting this SEP gives every thread it holds whose id does not match a
  new id, assigned by §7, once, in the migration that ships the bound. Its messages, read marker and
  change-feed rows move with it. Nothing records the old id.
- **The peer** still holds the old id. If it continues the thread under it, a host that has adopted
  this SEP refuses it `bad_request` (MUST 1), as it would refuse any id outside the grammar. A peer
  that has adopted this SEP has also renamed its own copy and does not send the old id (MUST 2). The
  conversation continues as a new thread on each side: the owner's next reply goes out under the new
  id.
- **Exports.** After the migration a host holds no id outside the grammar, so its exports carry
  none, and no contact can choose one again. A file written earlier imports by §9.2 step 3, which
  renames. A file that already holds an id the key-material check refuses cannot be written in the
  first place. Its host's migration renames the thread, and the next export succeeds.
- **The cloud's fallback** to the caller's `msg_id` as a thread's id ends. A `send_message` without
  a `thread_id` gets a new id the host chooses (MUST 3).

How many stored threads each host renames is one query against its own store. This SEP does not
state a number.

## Wire

A 1.1 receiver refuses a 1.0 sender's `thread_id` that is outside the grammar, and the empty string.
Both implementations' own ids already match, so between the two the break is only for ids a caller
chose: a contact's agent, or an owner on a surface that passes the owner's choice through. No version
moves. GOVERNANCE moves `X-HDTP-VERSION` only with X, and the break is narrow: a caller that sends no
`thread_id`, or sends back the one it was given, is not affected.

## Security

A contact can stop the owner's export through any string it chooses that the export carries.
Measured on hdtp-identity 0.8.0, `x PRIVATE KEY----- y` refuses the whole write as a thread's `id`,
as a thread's `topic`, as a contact's `display_name`, and as a message's `msg_id`. This SEP closes
the first. A writer can repair a `topic` or a `display_name`, which it already cleans of control
characters (§9.2, What a contact controls), and no message refers to either. `msg_id` needs a bound
of its own, as the id does here. Neither is in this SEP.

What this SEP closes without any compromise: an id that blocks the export, an id that expands an
export's JSON reading, and an id that hides a conversation from the owner's interface. It does not
touch §14.5's cases.

## Alternatives

- **A length bound alone** (both implementations today). A 16-byte base64url id still stops an
  export.
- **Base64url, `[A-Za-z0-9_-]`.** Its words can begin with `M` and decode to a key's shape.
- **Let the writer leave out a thread whose id is key material.** This drops a conversation from the
  person's export because of the contact's choice, and keeps the id unbounded everywhere else (URLs,
  events, the export's JSON reading). A writer rule is the right answer for `topic` and
  `display_name`, which it can rewrite, and not for an id, which it cannot.
- **Keep stored ids, bound only new ones.** The owner could then not reply in an old thread
  (MUST 2), and an old id would still block the export.
- **A host-tunable bound in `limits`.** See Grammar.

## Evidence

| MUST | Holder |
|---|---|
| 1 | the node's `internal/public` tool tests and the cloud's tool tests, each over the three tools: 64 bytes accepted (the control), 65 refused `too_large`, `A`, `.`, `..`, `-a`, `a b`, `a/b`, U+0001 and the empty string refused `bad_request`, nothing recorded for a refusal; the cloud's conformance battery, built from the node's Go code and run against a cloud host, gains the same cases in its contact group, with the 64-byte control last |
| 2 | the owner surfaces' tests in each implementation: an owner-chosen id outside the grammar is refused `bad_request` before anything is sent |
| 3 | a `send_message` with no `thread_id` answers an id that matches and is not the call's `msg_id` |
| Import, step 3 | hdtp-identity's export corpus gains a file with a thread whose `id` is outside the grammar, imported by each implementation's import test, which asserts the thread and its messages arrive under one new id |
| The migration | each implementation's migration test: a stored thread outside the grammar, with messages, a read marker and a change row, comes out under one new id with all of them, and a thread inside the grammar is untouched (the control) |

The spec repository's vectors do not change: no envelope, certificate or card carries a
`thread_id`. The examples of §6.2 and Appendix A already match the grammar.
