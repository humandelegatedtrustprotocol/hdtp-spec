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
§2 (`identity.md`), §9 and §9.2 (`hosting.md`), §14.5 (`certificates.md`) and §3 (`contact-cards.md`).

**§2, the fingerprint** (new, after its formula):

> A fingerprint has one spelling. Its 43 characters carry 258 bits for the digest's 256, and the last
> character's two spare bits are zero (RFC 4648 §3.5), so that character is one of
> `AEIMQUYcgkosw048`. A reader **MUST** refuse a fingerprint whose last character is any other: it
> spells the same 32 bytes again, a second name for one root.

Without it, one root has four spellings. In an export, a contact's root spelled another way would
read as a removed thread's root, the owner's would pass the rule that a removed thread's root is never
the owner, and two rows of `contacts.csv` would be two roots.

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

> A writer of a full export **MUST** carry every thread it holds, except a thread whose root was never
> active and is not a row of `contacts.csv`, and **MUST** list each thread it leaves out in the report
> it gives the person, by its `id` and the reason. A thread it carries whose root is not a row of
> `contacts.csv` is a removed thread.

"Ever active" is what `was_active` records for a contact: whether the root was ever a contact. A root
that a removed thread brought in by an import was ever active (step 3). A blocked root is a row of
`contacts.csv`, whatever its `was_active`, and its thread travels with that row. A root held as a
request received and not yet decided is not a row: its thread travels as a removed thread if the root
was ever active, and otherwise stays. A book has no threads, and this rule does not reach it.

**§9.2, Validation.** These rows change.

| Check | Changes to |
|---|---|
| Rows | "a header that is not exactly the one shown" becomes "a header that is not exactly the one shown — for `threads.csv`, one of the two, and the longer one only when a thread is a removed thread — a removed thread whose `contact` is not a fingerprint or is `owner`, a thread that is not removed with a `contact_name` or `contact_display_name` that is not empty, a removed thread with either over 200 characters, two removed threads of one root that carry different names" |
| References | "a thread whose `contact`, a message whose" becomes "a thread, under the shorter header, whose `contact` names no row of `contacts.csv`, a message whose"; a message's `contact` is checked against the `messages.jsonl` table, which reads "`contact` is a `root` from `contacts.csv` or the `contact` of a removed thread" |

The key-material check and the spreadsheet-formula rule already reach "any cell", so they reach the
two new columns unchanged. The manifest does not change: `counts.threads` counts every thread.

**§9.2, Import.**

- Step 1 adds: "and the root and the names of each removed thread".
- Step 3 becomes: "It writes the contacts, which are recognised at once in the status their rows give,
  then the threads, the messages and the files. A removed thread belongs to the importer's contact
  with that root if it holds one, of any status, and is otherwise kept as a removed thread, labelled
  with its names; either way its root was ever active. An importer **MUST NOT** write a removed
  thread's root as a contact. A host **MUST NOT** send a message it imported, whatever its `status`:
  retries belonged to the host that exported it."
  A contact of any status includes a request received and a block. "Its root was ever active" is what
  lets the conversation travel again in the next export, on a second move.
- Step 5 adds: "An importer **MUST NOT** call a removed thread's root, and does not report it
  unreached."

**§9.2, What a contact controls.** "A writer **MUST** truncate `display_name` to 200 characters, since
it is the contact's own claim." becomes "A writer **MUST** truncate `display_name` and
`contact_display_name` to 200 characters, since each is the contact's own claim." It is followed by:
"A writer **MUST** drop from every `name`, `display_name`, `contact_name` and `contact_display_name`,
and from a thread's `topic`, every character below U+0020 but tab, line feed and carriage return,
before it checks a name's length: a contact can set the topic and their own name, and an importer
may bound those characters by a ceiling of its own (Ceilings)." The paragraph's last sentence,
"The importer's checks are unchanged, so a file that breaks any of these was not written by a
conforming writer, and is refused as hostile.", becomes "The importer's checks are unchanged, so a
file that breaks any of these but the dropping of characters below U+0020 was not written by a
conforming writer, and is refused as hostile; an importer does not refuse those characters, and a host
may bound them by a ceiling of its own (Ceilings)."

**§9.2, Ceilings.** "on counts — contacts, threads, lines of `messages.jsonl`, the characters of an
`id` —" becomes "on counts — contacts, threads, lines of `messages.jsonl`, the characters of an `id`,
the characters below U+0020 but tab, line feed and carriage return in one member —".

**§3, Reading a card.** The `FN` rule widens to the names an export carries: "`FN`, and a
`display_name` or `contact_display_name` an export carries (§9.2), is untrusted display input: a
receiver **MUST** strip control and bidirectional-format characters from it before rendering it, …"

**§14.5, "A planted row".** The residual column adds: "a removed thread the person never had, shown
with its root and labelled removed, which never becomes a contact; and a writer's bug that files a
contact's thread as a removed thread under a wrong root that is still a well-formed fingerprint,
shown with that root".

### The MUSTs this adds

1. §9.2: a writer of a full export carries every thread but one whose root was never active and is
   not a contact.
2. §9.2: a writer lists each thread it leaves out, by its `id` and the reason.
3. §9.2 step 3: an importer does not write a removed thread's root as a contact.
4. §9.2 step 5: an importer does not call a removed thread's root.
5. §2: a reader refuses a fingerprint whose last character is not one of `AEIMQUYcgkosw048`.
6. §9.2: a writer drops control characters but tab, line feed and carriage return from every name
   and a thread's `topic`.

The Rows and References rows above, the contact-control truncation and §3's stripping rule are
existing MUSTs whose reach changes. The Ceilings sentence names one more count a host may bound; its
MUST, to name the ceiling in the refusal, is unchanged.

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
- **What it costs.** Under the longer header, the check that a thread's `contact` names a row of
  `contacts.csv` becomes the check that a root not in `contacts.csv` is a fingerprint in its one
  spelling (§2) and not the owner's. A root the writer got wrong, if it is still a well-formed
  fingerprint, reads as a removed thread rather than as a dangling reference: the manifest's hash
  binds what the writer wrote, not whether it was right. The review shows the root, and §14.5 names
  the residual.

The member's size is bounded as before: `threads.csv` at 16 MiB. The new columns add at most 1608
bytes to a row: two names of at most 200 characters of at most 4 bytes each, a guard `'` and two
quotes each, and two commas.

## Schema

hdtp-identity's `contract/contract.json`, and through `npm run schema` this repository's
`schema/draft/`, change:

- `$defs.ThreadRow` gains the optional strings `contact_name` and `contact_display_name`.
- `export_read` answers both on a removed thread, and neither on any other.
- `export_write` takes them on a removed thread, and refuses them, when not empty, on any other.
- `$defs.Fingerprint`'s pattern takes the one spelling (§2).
- `export_read_messages` is handed, as `contacts`, the roots of `contacts.csv` and of the removed
  threads.

`ExportManifest` does not change.

## Wire

A 1.1 writer's file interoperates with a 1.0 importer only when it carries no removed thread. One
that does has the longer header, and a 1.0 importer refuses it whole (§9.2, Rows). No version moves:
GOVERNANCE moves `hdtp_export` only with X, and a bump would refuse every file, not only these.

A 1.1 importer accepts every file a 1.0 writer writes.

An export carries every conversation the identity holds but those with a root that was never a
contact, with no choice at export time. A person controls what travels by deleting a conversation
beforehand. A host that implements only 1.0
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

A reader that answers a member as JSON writes U+0001 as six bytes (`\u0001`), as it does every
character below U+0020 but tab, line feed, carriage return, U+0008 and U+000C, which take two. A
`threads.csv` of removed threads whose names were 200 U+0001 characters
each is a legal file of 16 MiB that grew hdtp-identity's Wasm instance by 413.9 MB, measured
2026-10-10. A host bounds them by a ceiling of its own (hdtp-identity takes at most 65,536 in one
member and names that ceiling when it refuses), and a writer drops them from every name and topic
(MUST 6). An `id` is written as given, because messages refer to it. A thread's `id` can be a
`thread_id` a contact chose (§7), which no rule bounds, so a contact can still fill a `threads.csv`
with these characters through its ids. That is an open question for this SEP: bound `thread_id` where
it enters (§7), or leave such a file to a host's ceiling.

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

hdtp-identity's export corpus gains two accepted files, a removed thread with a message and a file in
it (`valid-export-with-removed-thread.zip`) and the same with both names empty
(`valid-export-with-a-nameless-removed-thread.zip`), and a refusal for each of these:

- a removed thread whose root is the owner (`removed-thread-is-owner.zip`);
- a removed thread whose root is not a fingerprint (`removed-thread-not-a-fingerprint.zip`);
- names on a thread that is not removed (`names-on-a-live-thread.zip`);
- a `contact_name` over 200 characters (`removed-thread-name-over-200.zip`);
- a `contact_display_name` over 200 characters (`removed-thread-display-name-over-200.zip`);
- two removed threads of one root with different names (`removed-thread-names-disagree.zip`);
- the longer header with no removed thread (`named-header-without-a-removed-thread.zip`);
- a header that is neither (`threads-bad-header.zip`);
- a key in a name (`key-in-a-thread-name.zip`);
- six fields under the longer header (`removed-thread-six-fields.zip`);
- a message whose `contact` is no contact's root and no removed thread's (`message-names-no-contact.zip`);
- a contact's root misspelt, as a removed thread's (`removed-thread-alias-of-a-contact.zip`);
- the owner's root misspelt, as a removed thread's (`removed-thread-alias-of-the-owner.zip`);
- a contacts.csv root that is another row's misspelt (`contact-root-alias.zip`).

The shorter header with a thread whose root is not in `contacts.csv` is the existing
`dangling-thread-contact.zip`.

Both ports and `js/parity.mjs` are held to the corpus. The existing valid export and book stay byte for
byte what they are, which holds the omission rule.

Holders of the MUSTs, for hdtp-identity's `js/musts.json` when the draft is released:

| MUST | Holder |
|---|---|
| 1 and 2 (the writer) | the node's `internal/portable` export tests and the cloud's export test, each over a removed contact, a stranger never accepted and a former contact asking again, and a conversation exported again after an import (the second move) |
| 3 (no contact written) | the node's and the cloud's import tests, and the round trip each way |
| 5 (one spelling) | both ports' `is_fingerprint`, and the three alias cases of the corpus |
| 4 (no call) | the same import tests, asserting no `update_contact` and no `request_contact` to a removed thread's root |
| The changed Rows and References rows, and the truncation | the corpus cases above, on both ports |
| 6 (control characters dropped) | hdtp-identity's parity case `export_write: control characters in what a contact controls, dropped`, which holds both ports to the file written without them |
| The ceiling named in its refusal | hdtp-identity's parity cases `export_read: threads.csv with one control character over the ceiling` (refused, naming it) and `export_read: threads.csv with as many control characters as the ceiling` (read), and the three memory tests |
| §3's stripping of a `contact_display_name` | the node's and the cloud's label tests |
