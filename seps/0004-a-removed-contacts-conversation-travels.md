# SEP-0004: A removed contact's conversation travels in the export

| | |
|---|---|
| Status | Draft |
| Author | Sumit Agrawal <security@hdtp.io> |
| Created | 2026-10-10 |
| Target | 1.1 |

## Summary

An export (§9.2) carries the conversations a person had with former contacts: roots that were ever
active and are no longer contacts. A former contact is identified on its conversation, not in a
list of contacts. A **removed thread** is a row of `threads.csv` whose `contact` is not a root of
`contacts.csv`. It carries the two names last known for that root in two new columns,
`contact_name` and `contact_display_name`, which are empty on every other thread. A removed thread's
root is never a contact (Import, steps 3 and 5). `hdtp_export` stays `1`.

## Motivation

§5 deletes the pin and says nothing of the conversation; hosts keep it. §9.2 cannot carry it. A
thread's `contact` must be a `root` of `contacts.csv`, and anything else is refused. Implementations
today either leave the conversation out and report it, or drop it silently. Either way, a person who
moves loses every conversation with every contact they have removed.

A fingerprint alone is unreadable to a person. A name alone does not tell two former contacts with the
same name apart. A removed thread carries both.

The names belong with the conversation and nowhere else. A former contact is not a contact, so it has
no place in `contacts.csv`, and a list of its own would be a second contact list for roots the person
removed.

## Specification changes

The text is quoted where the wording is new; otherwise the change is described. Sections touched:
§9 and §9.2 (`hosting.md`), §14.5 (`certificates.md`) and §3 (`contact-cards.md`).

**§9, Moving.** "The archive is the export of §9.2: the person's contacts and their conversations,
including those with former contacts, with the media in them, …"

**§9.2, `contacts.csv`, `status`.** The cell's last clause becomes: "a request received and not yet
decided stays with the host that received it; the request stays, and a conversation from when its root
was active travels as a removed thread."

**§9.2, `threads.csv`** (replaces its paragraph):

> **`threads.csv`** has exactly one of two headers. A file with no removed thread has the header
> `id,contact,topic,created_at,last_at`, and every `contact` is a `root` from `contacts.csv`. A file
> with at least one removed thread has the header
> `id,contact,topic,created_at,last_at,contact_name,contact_display_name`. `id` is unique in the
> file, `topic` is the thread's topic (§7), and the times are RFC 3339.
>
> A **removed thread** is a thread whose `contact` is not a `root` from `contacts.csv`: the
> conversation of a former contact. Its `contact` is a fingerprint and never `owner`.
>
> | Column | What it holds |
> |---|---|
> | `contact_name` | on a removed thread, the name the owner last gave the contact, at most 200 characters, or empty; on any other thread, empty |
> | `contact_display_name` | on a removed thread, the name the contact last gave themselves, at most 200 characters, or empty; on any other thread, empty |
>
> Every removed thread of one root carries the same two names.

**§9.2, `messages.jsonl`.** A message's `contact` is a `root` from `contacts.csv` or the `contact`
of a removed thread.

**§9.2, which conversations travel** (new, after the `contacts.csv` table):

> A writer **MUST** carry every thread it holds whose root is a row of `contacts.csv`, or whose root
> was ever active and is not; a thread of the second kind is a removed thread. A writer **MUST** list
> each thread it holds and does not carry in the report it gives the person, by its `id` and the
> reason.

"Ever active" is what `was_active` records for a contact: whether the root was ever a contact. A
root held as a request received and not yet decided is not a row of `contacts.csv`: its thread
travels as a removed thread if the root was ever active, and otherwise stays. A blocked root is a row
of `contacts.csv`, whatever its `was_active`, and its thread travels with that row.

**§9.2, Validation.** These rows change.

| Check | Changes to |
|---|---|
| Rows | `threads.csv`'s header is one of the two shown, and the longer one only when at least one thread is a removed thread; a removed thread's `contact` is a fingerprint and not `owner`; on a thread that is not removed, `contact_name` and `contact_display_name` are empty; on a removed thread, each is at most 200 characters, and every removed thread of one root carries the same two |
| References | "a thread whose `contact` names nothing in the file" is replaced by the rule above; a message's `contact` names a root of `contacts.csv` or of a removed thread |

The key-material check and the spreadsheet-formula rule already reach "any cell", so they reach the
two new columns unchanged. The manifest does not change: `counts.threads` counts every thread.

**§9.2, Import.**

- Step 1 adds: "and the root and the names of each removed thread".
- Step 3 becomes: "It writes the contacts, which are recognised at once in the status their rows give,
  then the threads, the messages and the files. A removed thread belongs to the importer's contact
  with that root if it holds one, and is otherwise kept as a removed contact's conversation, labelled
  with its names. An importer **MUST NOT** write a removed thread's root as a contact. A host
  **MUST NOT** send a message it imported, whatever its `status`: retries belonged to the host that
  exported it."
  A contact the importer "holds" is a row of any status, a request received or a block included.
- Step 5 adds: "An importer **MUST NOT** call a removed thread's root, and does not report it
  unreached."

**§9.2, What a contact controls.** "A writer **MUST** truncate `display_name` to 200 characters"
now covers `contact_display_name` too.

**§3, Reading a card.** The `FN` rule widens to the names an export carries: "`FN`, and a
`display_name` or `contact_display_name` an export carries (§9.2), is untrusted display input: a
receiver **MUST** strip control and bidirectional-format characters from it before rendering it, …"

**§14.5, "A planted row".** The residual column adds: "a former contact's conversation the person
never had, shown with its root and labelled removed; it never becomes a contact".

### The MUSTs this adds

1. §9.2: a writer carries every thread whose root is a contact or was ever active.
2. §9.2: a writer lists each thread it does not carry, by its `id` and the reason.
3. §9.2 step 3: an importer does not write a removed thread's root as a contact.
4. §9.2 step 5: an importer does not call a removed thread's root.

The Rows and References rows above, the contact-control truncation and §3's stripping rule are
existing MUSTs whose reach changes.

## Grammar

Two columns on `threads.csv`, present only when a thread needs them:

- **Why on the thread.** The owner's decision: a former contact belongs with its conversation, and
  not in a contact list. A row of `threads.csv` is the conversation, so the names travel there.
- **Why the header switches.** 1.0 holds `threads.csv`'s header to be exactly five columns. Writing
  the longer header only when a removed thread exists keeps every other file byte for byte a 1.0
  file. Allowing the longer header only then keeps one form per content.
- **Why removal is "not in contacts.csv".** Not being a row of `contacts.csv` is what removal is. A
  marker column would say the same thing twice, and the two could disagree. Both names may be empty,
  because a host may hold no name for a former contact: an imported contact without a display name
  and a petname is one. The root identifies the conversation, and a host labels a nameless one by its
  root.
- **Why the names agree per root.** One former contact is one identity in the review and in the
  conversation list. Two threads of one root naming it differently would leave the importer to choose.
- **What it costs.** The check that a thread's `contact` names a row of `contacts.csv` becomes, for
  the longer header, the check that a root not in `contacts.csv` is a well-formed fingerprint that is
  not the owner's. A mistyped root in a file that also carries a removed thread would read as a
  removed thread. A writer writes canonical rows, the manifest's hash binds them, and the review
  shows the root. So such a file is what its writer wrote.

The member's size is bounded as before: `threads.csv` at 16 MiB. The new columns add at most 1608
bytes to a row: two names of at most 200 characters of at most 4 bytes each, a guard `'` and two
quotes each, and two commas.

## Schema

hdtp-identity's `contract/contract.json`, and through `npm run schema` this repository's
`schema/draft/`, change:

- `$defs.ThreadRow` gains the optional strings `contact_name` and `contact_display_name`.
- `export_read` answers both on every thread, empty on a thread that is not removed.
- `export_write` takes them on a removed thread and refuses them on any other.
- `export_read_messages` is handed, as `contacts`, the roots of `contacts.csv` and of the removed
  threads.

`ExportManifest` does not change.

## Wire

A 1.1 writer's file interoperates with a 1.0 importer only when it carries no removed thread. One
that does has the longer header, and a 1.0 importer refuses it whole (§9.2, Rows). No version moves:
GOVERNANCE moves `hdtp_export` only with X, and a bump would refuse every file, not only these.

A 1.1 importer accepts every file a 1.0 writer writes.

An export carries exactly the conversations the identity holds, with no choice at export time. A
person controls what travels by deleting a conversation beforehand. A host that implements only 1.0
refuses a file that carries a removed thread: that is the accepted residual, and a person who must
move to such a host deletes those conversations first.

## Privacy

The host already holds the conversation. A removed thread's two names are the minimum that tells two
former contacts apart and gives the person a label they can read. They carry no endpoint, certificate
or permission, so they cannot reach the former contact or speak to them. They stay within what an
export is, "contacts and chats": they are on the chat.

§9.2's "What a contact controls" holds that what a contact sent does not stop the owner taking their
export. Removal does not make the record the contact's to withhold.

The Unencrypted notice still describes the file: "your contact list and all your conversations and
files".

## Security

A removed thread's root cannot become a contact: no endpoint, no certificate (Import, steps 3 and 5).
A planted removed thread yields at most a conversation the person did not have, shown with its root,
labelled removed, in the review the person must approve (step 1).

No key material can enter. The key-material check covers every cell. A removed thread's
`contact_display_name` is the contact's own claim: it is cut to 200 characters, stripped as `FN` is
(§3), and shown with its root when it matches another name.

## Alternatives

- **A separate member listing former contacts** (`removed.csv`, this SEP's first draft). This is a
  contact list for roots that are not contacts. The owner declined it: the conversation carries them.
- **A `removed` status in `contacts.csv`.** A removed contact would need an endpoint and permissions it
  does not have, and every importer would special-case a contact row it must never write as one.
- **Always the longer header.** Every file would change, and every 1.0 importer would refuse every
  1.1 file.
- **A marker column for removal.** It says what "not in `contacts.csv`" already says, and could
  disagree with it.
- **Leave the conversation out, as today.** A person who moves loses every conversation with every
  contact they have removed.

## Evidence

hdtp-identity's export corpus gains one accepted file carrying a removed thread with a message and a
file in it, and refusals for each of these:

- a removed thread whose root is the owner;
- a removed thread whose root is not a fingerprint;
- names on a thread that is not removed;
- a name over 200 characters;
- two removed threads of one root with different names;
- the longer header with no removed thread;
- the shorter header with a thread whose root is not in `contacts.csv`;
- a header that is neither;
- a key in a name;
- a message whose `contact` is a root of neither kind.

Both ports and `js/parity.mjs` are held to the corpus. The existing valid export and book stay byte for
byte what they are, which holds the omission rule.

Holders of the MUSTs, for hdtp-identity's `js/musts.json` when the draft is released:

| MUST | Holder |
|---|---|
| 1 and 2 (the writer) | the node's `internal/portable` export tests and the cloud's export test, each over a removed contact, a stranger never accepted and a former contact asking again |
| 3 (no contact written) | the node's and the cloud's import tests, and the round trip each way |
| 4 (no call) | the same import tests, asserting no `update_contact` and no `request_contact` to a removed thread's root |
| The changed Rows and References rows, and the truncation | the corpus cases above, on both ports |
| §3's stripping of a `contact_display_name` | the node's and the cloud's label tests |
