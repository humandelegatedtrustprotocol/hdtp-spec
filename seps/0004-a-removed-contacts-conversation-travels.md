# SEP-0004: A removed contact's conversation travels in the export

| | |
|---|---|
| Status | Draft |
| Author | Sumit Agrawal <security@hdtp.io> |
| Created | 2026-10-10 |
| Target | 1.1 |

## Summary

An export (§9.2) carries the conversations a person had with contacts they no longer have, each
named by the removed contact's fingerprint and the two names last known for it, in a new optional
member `removed.csv`. A removed contact is not a contact: its row has no endpoint, certificate, status
or permission, and an importer never writes it as one or calls it. `hdtp_export` stays `1`.

## Motivation

Removing a contact deletes the pin, not the record of what was said: a host keeps the conversation.
§9.2 cannot carry it. A thread's `contact` must be a `root` of `contacts.csv`, and a reference to
anything else is refused, so a writer has two choices. It can leave the conversation out, which the
reference node does, listing it in its report. Or it can drop it silently, which BatonDeck does. Either
way, a person who moves loses every conversation with everyone they have removed. A conversation is
the person's record of an exchange, whether or not the contact remains.

A fingerprint alone does not let a person read the list, and a name alone does not tell apart two
removed contacts called the same thing. Both go together: the name the owner gave the contact, the
name the contact gave themselves, and the fingerprint.

## Specification changes

All in `docs/specification/draft/hosting.md`, §9 and §9.2. Each is quoted as it will read.

**§9, Moving.** "The archive is the export of §9.2: the person's contacts and their conversations,
including the conversations of contacts since removed, with the media in them, …"

**§9.2, the members.** A new line after `contacts.csv`:

```
removed.csv        one row per removed contact a thread names; present only when there is one
```

**§9.2, `manifest.json`.** `counts` gains `removed` and `files` gains `removed.csv`. They are present
together, and only when the file holds `removed.csv`. `counts.removed` is then at least 1. A file
without `removed.csv` has the manifest 1.0 defined.

**§9.2, a new paragraph after `contacts.csv`.**

> **`removed.csv`** names the contacts the owner no longer has whose conversations the file carries.
> It is UTF-8 CSV as `contacts.csv` is, and its first row is exactly `root,name,display_name`.
>
> | Column | What it holds |
> |---|---|
> | `root` | the removed contact's fingerprint; unique in the file, in no row of `contacts.csv`, and never `owner` |
> | `name` | the owner's last name for the contact, at most 200 characters, or empty |
> | `display_name` | the contact's last name for themselves, at most 200 characters, or empty |
>
> A removed row is not a contact: it has no endpoint, certificate, status or permission.

**§9.2, which conversations travel** (new, after the `contacts.csv` table). Two MUSTs are added:

> A writer **MUST** carry every thread it holds with a root that is or was a contact of the identity:
> with that root's row of `contacts.csv` when it still is one, and otherwise with a row of
> `removed.csv`, also when the root is now a request received and not yet decided. A thread with a
> root that was never a contact stays with the host, and a writer **MUST** list each such thread, by
> its `id` and why, in the report it gives the person.

**§9.2, `threads.csv` and `messages.jsonl`.** A thread's `contact`, and a message's `contact`, is a
`root` from `contacts.csv` or `removed.csv`.

**§9.2, Validation.** These existing MUSTs change.

| Check | Changes to |
|---|---|
| Names | adds `removed.csv` to the names an importer accepts |
| Members | "a file **MAY** omit `removed.csv` only when its manifest neither counts nor lists it" |
| Sizes | adds "a `removed.csv` over 4 MiB" |
| Hashes | `removed.csv` is a text member, listed in `files` like the others |
| Owner | adds "a removed row whose `root` is `owner`" |
| Rows | the header exact; `root` a fingerprint, unique, and in no row of `contacts.csv` |
| References | adds "a removed row that no thread names" |

The key-material check and the spreadsheet-formula rule already reach "any cell", so they reach
`removed.csv` unchanged.

**§9.2, Import.** These three steps change.

- Step 1: "It **MUST** show the person the contacts, and each removed contact whose conversation the
  file carries, and write nothing until the person agrees."
- Step 3: "… then the threads, the messages and the files. A thread whose root is a removed row is
  written as the conversation of a removed contact, labelled with the row's names, unless the host
  holds that root as a contact, whose conversation it then is. An importer **MUST NOT** write a removed
  row as a contact."
- Step 5: "… A removed row is never called — neither `update_contact` nor `request_contact` — and is not
  reported unreached."

**§9.2, What a contact controls.** "A writer **MUST** truncate `display_name` to 200 characters" now
covers `removed.csv` as well as `contacts.csv`.

**§9.2, Ceilings.** "Removed rows" joins the counts a host may set a ceiling on.

**§14.5, "A planted row".** The residual column gains "a removed contact's conversation the person
never had, shown labelled as removed; it never becomes a contact".

## Wire

`hdtp_export` stays `1`. A writer that has no removed conversation to carry writes exactly the file
1.0 defines, so every 1.0 importer reads it, and every 1.0 file is a 1.1 file.

A file that holds `removed.csv` is refused whole by a 1.0 importer, which names the entry (§9.2,
Names). That is §9's "refuse, rather than ignore", not a silent loss. Hosts therefore deploy the
reader before any writer emits the member. The omission rule is the one `threads.csv` already has: it
is a property of the format, not a reader for an older one.

## Security

A removed row cannot become a contact: it carries no endpoint and no certificate, and the importer
never writes it as one or calls it. A planted removed row therefore yields at most a conversation the
person did not have, shown with its fingerprint and labelled as removed, in the review the person
must approve (step 1).

No key material can enter. The key-material check covers every cell, and a removed row has no
certificate column to hold one.

The names are the contact's claims and the owner's own, bounded at 200 characters like those of
`contacts.csv`. A removed contact's `display_name` shown beside a live contact's name is decorated with
its fingerprint by the same rule that tells two live contacts with one name apart.

## Alternatives

- **A `removed` status in `contacts.csv`.** It would need an endpoint, permissions and the rest of a
  contact's columns, and an importer would have to special-case a contact row it must never write as
  a contact. It would also count against the 5000-row bound of the person's live book.
- **Names as extra columns of `threads.csv`.** This changes the header of every file, so every 1.0
  file would be refused. It also repeats the names on each of a contact's threads, which can then
  disagree.
- **Always present, with `counts.removed` 0.** Every 1.0 file would then lack a required count, and a
  1.1 reader would refuse it: a wire break for no gain.
- **Leave it out, as today.** A person who moves loses every conversation with everyone they removed.

## Evidence

hdtp-identity's export corpus gains one accepted file carrying a removed conversation with a file in
it. It also gains six refusals, one each for:

- a removed root that is also a contact;
- a removed root that is the owner;
- a removed row that no thread names;
- a bad header;
- a key in a removed cell;
- `removed.csv` not listed in `files`.

Both ports and `js/parity.mjs` are held to the corpus. The corpus's existing valid export and book stay
byte for byte what they are, which holds the omission rule. The reference node and BatonDeck gain a
round trip each way that ends with the conversation labelled removed and no contact written.
