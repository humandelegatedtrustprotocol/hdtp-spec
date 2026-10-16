# HDTP — revision history

What each released version of the specification changed. The text of a version is
`docs/specification/<X.Y>/`; its index page's version line is the version and the date, and its
body reads as the specification as it stands and names no version of its own history.

The wire carries the major alone: `X-HDTP-VERSION`, an envelope's `v`, `hdtp_export`. A version
within a major can still change what an implementation writes or accepts; each entry says whether
it does.

The versions published before the rename, 1.0.0 of 2026-08-23 to 2.2.5 of 2026-09-30, are recorded
as they were written in `docs/release/changes-before-hdtp.md`, a dated record kept byte for byte.

## 1.0.2-draft

An export carries the conversations a person had with former contacts (§9.2, SEP-0004): a removed
thread is a row of `threads.csv` whose `contact` is not a root of `contacts.csv`, and it carries the
names the contact is known by in two new columns, `contact_name` and `contact_display_name`, empty on
every other thread. `threads.csv` takes the longer header only when a removed thread exists, and the
manifest does not change: a 1.0.2 importer accepts every file an earlier 1.0 writer writes, and an
earlier 1.0 importer refuses a file with a removed thread. A full export carries every thread but one whose root was
never a contact, and names each it leaves out; a removed thread's root is never written as a contact
or called, and counts as once a contact, so the conversation travels again on a second move. A
fingerprint has one spelling: its last character is one of `AEIMQUYcgkosw048`, and a reader refuses
any other (§2). A writer drops every character below U+0020 but tab, line feed and carriage return
from every name and a thread's `topic`, before a name's length is checked, and
§9.2's Ceilings name those characters in one member as a count a host may bound. This changes what an
implementation writes and accepts. §3's stripping of `FN` reaches an
exported `display_name` and `contact_display_name`, and §14.5's planted row names a former contact's
conversation as its residual.

A `thread_id` has one of two forms, 1 to 64 ASCII letters and digits or a lower-case UUID, and two
are the same only when their bytes are (§7, SEP-0006); §6.2 types it as a string or `null`, at most
64 bytes, a bound no host tunes. A receiver refuses one of more than 64 bytes with `too_large` and
any other of neither form, the empty string included, with `bad_request`, at `send_message`,
`send_media` and `book_slot`, recording nothing of the call but what §13.3 learns before dispatch,
and spending the call's budget (§12); a host sends only these forms, and
assigns one not taken from the call's arguments. An importer leaves out a thread whose `id` is of
neither form, with its messages and the files only they name, and shows the person each such `id`
before it writes anything; the file is not refused for it. A writer re-issues, as `r` and the first
62 hex digits of its sha256, every id already of that form, and a thread's `id`, a message's
`thread` and `reply_to`, and an incoming message's `msg_id`, that reads as a private key; it refuses
a message that went out whose `msg_id` reads as a key (§9.2). This changes what an implementation
accepts and writes: an earlier 1.0 sender's `thread_id` of neither form is refused, and a thread of
an earlier 1.0 file whose `id` is of neither form does not arrive. `vectors/intrude.mjs` gained the 22 scenarios
that hold the two forms at the seed's receiving side.

An envelope is exactly `protected`, `enc`, `ct` and `sig`, each present and each a JSON string
(§13.1, SEP-0005). A receiver refuses any other object with `envelope_invalid` at step 1 of §13.3 —
a fifth member, a member spelled another way, an absent or `null` member, one that is not a string —
for request and result envelopes alike, comparing member names byte for byte, and reads a member that
occurs more than once at its last occurrence, never an earlier one. Step 1 reads all four members in
their canonical base64url before the key is resolved, so a misspelled member sealed to a former key
is `envelope_invalid`, not `certificate_renewed`. This changes what an implementation accepts, and no
version moves: 1.0.1 already defines the envelope as these four members, so what an earlier 1.0 sender
writes is unaffected, and an envelope carrying anything else, which some earlier 1.0 receivers read, is
refused. The draft's Appendix B adds `invalid_envelopes`, eleven `sealed_call` arguments as raw JSON
text with the code each gets; 1.0.1's Appendix B does not change. `vectors/intrude.mjs` gained the 12 scenarios that
hold the four members at the seed's receiving side.

In §14.5, the row for a stolen leaf key said the key "speaks only from its one address". It is
*reached* only there: a receiver verifies a chain against the endpoint it pinned, never against where
a call came from, so until the renewal reaches a contact the thief calls that contact as the person
from anywhere, in either form of §13.2, and opens what the contact still seals to the key. The row now
says so, in both columns; no requirement changes. `vectors/intrude.mjs` gained the six scenarios that
measure it: the stolen key in the small form, before and after the renewal is learned; an envelope
sealed to the superseded key opening at the host (§2) and for whoever holds that key; and what a
contact seals to once the renewal has reached it, with the thief replaying the superseded chain.

## 1.0.1 · 2026-10-16

The 1.0 text as it was amended after `v1.0.0` was tagged, released under its own number so that each
version names one text. Four of its pages differ from 1.0.0's.

An address belongs to the hosting, not to the identity (§9; SEP-0002, SEP-0003). Whenever an
identity leaves an address, deleted or moved, the host keeps the address for 24 hours for the
account that held it, which may be one the person shares at the host, for any identity of that
account, and then frees it; 1.0.0 held it until the last leaf issued for it expired. The root is the
person's and is not touched. The MUST only relaxes, and changes nothing an implementation writes or
accepts: a host of 1.0.0 conforms to it.

A caller at the pending tier is refused `pending_approval` for a tool it cannot see or that does not
exist, as §6.1 required; 1.0.0's §6.2 and §12 said `permission_denied` (SEP-0003). This changes what
a host writes: one that answers `permission_denied` there does not conform to 1.0.1.

§14.5's row for a former host's leaf says that the old address is freed 24 hours after the identity
leaves it, and that a later holder of it is another root, which a contact that pinned this one never
auto-accepts (§5); 1.0.0's row said the address was not reassigned until the leaf expired. §12's
*The record* numbers a MUST by its section's number as the section's heading writes it, as in
`9.#4`, and lets `PROOFS.md` name the implementation role that holds one. Neither changes a
requirement.

## 1.0.0 · 2026-10-03

The first release. An identity is the fingerprint of a self-signed root certificate the person
holds, derived from a passkey or kept in a wallet (§2); a host serves it under a leaf the root
issued for one address, valid for at most 398 days (§14). Contacts are vCards carrying the leaf
(`X-HDTP-VERSION:1`, `X-HDTP-CERT`, `X-HDTP-SEAL`, §3), added by invite and human approval (§4, §5);
everything a contact may do is an MCP tool behind per-contact permissions (§6, §8). Calls may be
sealed end to end, HPKE Base with `info` `HDTP-SEAL-v1` and a detached signature, in an envelope
whose header has `v` 1 (§13). A person can move between hosts, taking an export of their contacts and
conversations, and a host that is left deletes what it held (§9).
Appendix B carries the vectors, generated from the seeds `hdtp-1.0-vectors/{label}`.

Amended on 2026-10-04, before HDTP went live, in this version rather than a new one: a root may
carry an end date its person chooses, and has none by default (§14.1). Chain validation refuses a
chain whose root is past its end date, and a leaf whose `notAfter` is after its root's (§14.2 rule 4);
a wallet signs nothing under such a root and ends a leaf no later than its root (§2.2). Appendix B
gained a root with an end date, three leaves under it and five chain cases. An implementation of
this version from before the amendment refuses, by rule 1, every chain whose root has an end date.

Amended again on 2026-10-05, before HDTP went live, in this version: a reader takes every line after
`X-HDTP-CERT` that starts no property into its value, blank lines included, and removes every space,
tab, CR and LF from it (§3, *Reading a card*; SEP-0001), so a card whose folding a chat or a mail
client damaged reads. Writers do not change. An implementation of this version from before the
amendment refuses such a card, and a certificate with a space or a tab inside it.
