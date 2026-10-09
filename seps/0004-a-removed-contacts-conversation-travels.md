# SEP-0004: A removed contact's conversation travels in the export

| | |
|---|---|
| Status | Draft |
| Author | Sumit Agrawal <security@hdtp.io> |
| Created | 2026-10-10 |
| Target | 1.1 |

## Summary

An export (§9.2) carries the conversations a person had with former contacts: roots that were ever
active and are no longer contacts. Each former contact is named in a new optional member,
`removed.csv`, by its root and the two names last known for it. A **removed row** is one row of that
member. It is not a contact, and an importer never writes it as one or calls it. `hdtp_export` stays `1`.

## Motivation

§5 deletes the pin and says nothing of the conversation; hosts keep it. §9.2 cannot carry it. A
thread's `contact` must be a `root` of `contacts.csv`, and anything else is refused. Implementations
today either leave the conversation out and report it, or drop it silently. Either way, a person who
moves loses every conversation with every contact they have removed.

A fingerprint alone is unreadable to a person. A name alone does not tell two former contacts with the
same name apart. A removed row carries both.

## Specification changes

The text is quoted where the wording is new; otherwise the change is described. Sections touched:
§9 and §9.2 (`hosting.md`), §14.5 (`certificates.md`) and §3 (`contact-cards.md`).

**§9, Moving.** "The archive is the export of §9.2: the person's contacts and their conversations,
including those with former contacts, with the media in them, …"

**§9.2, the members.** A new line after `contacts.csv`:

```
removed.csv        one row per former contact a thread names; present only when there is one
```

**§9.2, `manifest.json`.** `counts` gains the optional `removed`, a whole number of at least 1, and
`files` gains the optional `removed.csv`. Absent, `removed.csv`, `counts.removed` and
`files["removed.csv"]` mean no removed conversation.

**§9.2, `contacts.csv`, `status`.** The cell's last clause becomes: "a request received and not yet
decided stays with the host that received it; the request stays, and a conversation from when its root
was active travels with a removed row."

**§9.2, `removed.csv`** (new, after `contacts.csv`):

> **`removed.csv`** is UTF-8 CSV as `contacts.csv` is, and its first row is exactly
> `root,name,display_name`. A **removed row** names a former contact whose conversation the file carries.
>
> | Column | What it holds |
> |---|---|
> | `root` | the former contact's fingerprint; unique in the file, in no row of `contacts.csv`, and never `owner` |
> | `name` | the name the owner last gave the contact, at most 200 characters, or empty |
> | `display_name` | the name the contact last gave themselves, at most 200 characters, or empty |
>
> A removed row has no endpoint, certificate, status or permission.

**§9.2, `threads.csv` and `messages.jsonl`.** A thread's `contact`, and a message's `contact`, is a
`root` from `contacts.csv` or `removed.csv`.

**§9.2, which conversations travel** (new, after the `contacts.csv` table):

> A writer **MUST** carry every thread it holds whose root is a row of `contacts.csv`, or whose root
> was ever active and is not, and **MUST** write one removed row for each root of the second kind. A
> writer **MUST** list each thread it holds and does not carry in the report it gives the person, by
> its `id` and the reason.

"Ever active" is what `was_active` records for a contact: whether the root was ever a contact. A
stranger whose request was never accepted, blocked or not, was never active, and its thread stays.

**§9.2, Validation.** These rows change.

| Check | Changes to |
|---|---|
| Names | adds `removed.csv` |
| Members | adds: "An importer **MUST** refuse a file that holds `removed.csv` without both `counts.removed` and `files["removed.csv"]`, or holds either of those without the other or without the member, and a `counts.removed` of 0." |
| Sizes | adds "a `removed.csv` over 16 MiB" (see Grammar below) |
| Hashes | `removed.csv` is a text member, listed in `files` |
| Owner | adds "a removed row whose `root` is `owner`" |
| Rows | the header exact; `root` a fingerprint, unique, and in no row of `contacts.csv`; each name at most 200 characters |
| References | adds "a removed row that no thread names" |

The key-material check and the spreadsheet-formula rule already reach "any cell", so they reach
`removed.csv` unchanged.

**§9.2, Import.**

- Step 1 adds: "and each removed row, with its names and its root".
- Step 3 becomes: "It writes the contacts, which are recognised at once in the status their rows give,
  then the threads, the messages and the files. A thread whose root is a removed row belongs to the
  importer's contact with that root if it holds one, and is otherwise kept as a removed contact's
  conversation, labelled with the row's names. An importer **MUST NOT** write a removed row as a contact. A
  host **MUST NOT** send a message it imported, whatever its `status`: retries belonged to the host
  that exported it."
  A contact the importer "holds" is a row of any status, a request received or a block included.
- Step 5 adds: "An importer **MUST NOT** call a removed row's root, and does not report it unreached."

**§9.2, What a contact controls.** "A writer **MUST** truncate `display_name` to 200 characters" now
covers `removed.csv` as well as `contacts.csv`.

**§9.2, Ceilings.** "Removed rows" joins the counts a host may set a ceiling on.

**§3, Reading a card.** The `FN` rule widens to the names an export carries: "`FN`, and the
`display_name` of a row of `contacts.csv` or `removed.csv` (§9.2), is untrusted display input: a
receiver **MUST** strip control and bidirectional-format characters from it before rendering it, …"

**§14.5, "A planted row".** The residual column adds: "a former contact's conversation the person
never had, shown with its root and labelled removed; it never becomes a contact".

### The MUSTs this adds

1. §9.2: a writer carries every thread whose root is a contact or was ever active, with a removed row
   for each of the second kind.
2. §9.2: a writer lists each thread it does not carry, by its `id` and the reason.
3. §9.2 step 3: an importer does not write a removed row as a contact.
4. §9.2 step 5: an importer does not call a removed row's root.

The Validation rows above (Names, Members, Sizes, Hashes, Owner, Rows, References), the contact-control
truncation and §3's stripping rule are existing MUSTs whose reach widens.

## Grammar

`removed.csv` is bounded at 16 MiB, the bound of `threads.csv`. The largest row is 1681 bytes:

- the root, 71 bytes;
- each name, at most 200 characters of at most 4 bytes, plus one guard `'` and two quotes, which is
  803 bytes (a doubled `"` is 2 bytes for one character, below 4);
- two commas and a CRLF.

So the member holds at least 9,980 rows of the longest names. At 40 ASCII characters a name, a row is
some 160 bytes and the member holds about 100,000. There is never more than one row per thread. A
writer refuses a file it cannot fit, as it does for `threads.csv`.

## Schema

hdtp-identity's `contract/contract.json`, and through `npm run schema` this repository's
`schema/draft/`, change:

- `$defs.ExportManifest.counts.removed`: an optional integer, minimum 1.
- `$defs.ExportManifest.files["removed.csv"]`: an optional `Sha256Hex`.
- `$defs.RemovedRow`: `{root: Fingerprint, name: string, display_name: string}`, with no other member.
- `ExportLimits.removed_csv`: 16777216.
- `export_read` takes `removed_csv` and answers `removed: RemovedRow[]`.
- `export_write` takes `removed: RemovedRow[]` and answers `removed_csv`.

The co-presence of the count, the `files` entry and the member is in the notes of `export_read`, as the
rule for `threads.csv` is, rather than an `if`/`then` the contract's validator does not implement. A new
example, `schema/draft/examples/ExportManifest/with-removed.json`, holds a manifest that counts and lists
`removed.csv`.

## Wire

A 1.1 writer's file interoperates with a 1.0 importer only when it carries no removed conversation.
One that does is refused whole, naming the entry (§9.2, Names). No version moves: GOVERNANCE moves
`hdtp_export` only with X, and a bump would refuse every file, not only these.

A 1.1 importer accepts every file a 1.0 writer writes.

Hosts deploy the reader before any writer emits the member.

Moving into a host that implements only 1.0 is refused whole when the file carries a removed
conversation. **Accepted residual, pending the maintainer's decision.**

## Privacy

The host already holds the conversation. A removed row is the minimum that tells two former contacts
apart and gives the person a label they can read. It carries no endpoint, certificate or permission, so
it cannot reach the former contact or speak to them. It stays within what an export is, "contacts and
chats".

§9.2's "What a contact controls" holds that what a contact sent does not stop the owner taking their
export. Removal does not make the record the contact's to withhold.

The Unencrypted notice still describes the file: "your contact list and all your conversations and
files".

## Security

A removed row cannot become a contact. It carries no endpoint and no certificate, and the importer
never writes it as one or calls it. A planted removed row yields at most a conversation the person did
not have, shown with its root, labelled removed, in the review the person must approve (step 1).

No key material can enter. The key-material check covers every cell, and a removed row has no
certificate column. A removed row's `display_name` is the contact's own claim: it is cut to 200
characters, stripped as `FN` is (§3), and shown with its root when it matches another name.

## Alternatives

- **A `removed` status in `contacts.csv`.** A removed contact would need an endpoint and permissions it
  does not have, and every importer would special-case a contact row it must never write as one. It
  would also count against the 5000-row bound of the person's live book.
- **Names as columns of `threads.csv`.** This changes the header of every file, so every 1.0 file would
  be refused. It also repeats the names on each thread, where they can disagree.
- **Always present, with `counts.removed` 0.** Every 1.0 file would lack a required count, and a 1.1
  reader would refuse it.
- **Leave the conversation out, as today.** A person who moves loses every conversation with every
  contact they have removed.

## Evidence

hdtp-identity's export corpus gains one accepted file carrying a removed conversation with a file in
it, and refusals for each of these:

- a removed root that is also a contact;
- a removed root that is the owner;
- a removed root that appears twice;
- a removed row that no thread names;
- a header that is not `root,name,display_name`;
- a header with no rows;
- `counts.removed` 0;
- a key in a removed row's cell;
- `removed.csv` present without `counts.removed` and `files["removed.csv"]`;
- `counts.removed` and `files["removed.csv"]` without the member;
- a message whose `contact` is a root of neither member.

Both ports and `js/parity.mjs` are held to the corpus. The existing valid export and book stay byte for
byte what they are, which holds the omission rule.

Holders of the MUSTs, for hdtp-identity's `js/musts.json` when the draft is released:

| MUST | Holder |
|---|---|
| 1 and 2 (the writer) | the node's `internal/portable` export tests and the cloud's export test, each over a removed contact, a stranger never accepted and a former contact asking again |
| 3 (no contact written) | the node's and the cloud's import tests, and the round trip each way |
| 4 (no call) | the same import tests, asserting no `update_contact` and no `request_contact` to a removed root |
| The widened Validation rows and truncation | the corpus cases above, on both ports |
| §3's stripping of a removed row's `display_name` | the node's and the cloud's label tests |
