# SEP-0001: Reading a card whose folding was damaged in transit

| | |
|---|---|
| Status | Accepted (2026-10-05, the owner's decision: "accept but it goes in version 1.0.0 only") |
| Author | Sumit Agrawal <mr.sumitagrawal.17@gmail.com> |
| Created | 2026-10-05 |
| Target | 1.0, amending 1.0.0 in place, as the amendment of 2026-10-04 was |

## Summary

A card's `X-HDTP-CERT` is several hundred characters of base64url, so every writer folds it (RFC 6350,
Section 3.2: a line break and one space before each continuation). A card pasted through a chat often
arrives with that folding damaged: continuations that lost their leading space, and blank lines
between them. Today every reader refuses such a card. This SEP makes a reader take the certificate's
continuation lines whatever happened to their folding, and remove the whitespace inside its value.
Writers do not change.

## Motivation

Observed on 2026-10-05: the owner pasted his own card into Claude and asked it to add the person
through BatonDeck's MCP connector. The text that arrived had the first line of `X-HDTP-CERT` and
then the rest of the value over many lines, most without their leading space, some separated by
blank lines, one with its space kept. Unfolded per RFC 6350, each line that lost its space is a line
of its own with no colon; every reader (the seed, both hdtp-identity ports, and through them the node
and the cloud) skips such a line, so the certificate is cut short and the card is refused
`certificate does not parse`. A person cannot add a contact from a card copied out of a chat, which
is one of the carriers §3 names.

## Specification changes

§3 *Contact cards*, in `docs/specification/1.0/` and identically in `draft/`, gains one paragraph, after the intake paragraph:

> **Reading a card.** A reader unfolds a card as RFC 6350, Section 3.2 says — a line break (CRLF or
> LF) followed by one space or tab is removed — and splits it into lines at CRLF or LF. A line
> *starts a property* when it begins `[group.]name[;params]:`, where the group and the name are
> letters, digits and `-`. A card copied through a chat or a mail client can arrive with its
> continuations' leading spaces removed and blank lines added, so a reader **MUST** read
> `X-HDTP-CERT` as follows: its value also takes every following line that does not start a
> property, blank lines included, and every space, tab, CR and LF is removed from it. Any other line
> that starts no property is ignored. Base64url contains none of the four removed characters, so
> this gives back the bytes the writer wrote unless another character was changed or lost; a
> certificate cut short then fails to parse (§14.1), and one with a character changed either fails
> to parse or reads as a certificate its root did not sign, as a card altered in transit does.

One MUST is added (the one quoted). No MUST is changed or removed. The intake refusals of §3 are
unchanged: they apply to the value read this way.

## Wire

Writers are unchanged, so every card written by an implementation of this SEP is read by one that
does not implement it. A reader that implements it accepts more: every card the previous rule read,
read the same, plus cards whose certificate was folded wrongly or carries spaces, tabs or line breaks
inside it. No version moves.

One reading changes: a certificate value with a space or a tab in the middle was refused
(`certificate does not parse: not base64url`) and is now read. Every other character outside
base64url — a no-break space, a vertical tab, a full stop — is refused as before.

## Security

Base64url contains no space, tab, CR or LF, so removing them changes nothing the writer wrote: the
decoded bytes are the writer's unless some other character was changed, added or lost, which could
happen before this SEP too, and such damage is what it was before. A cut certificate fails the DER
parse (§14.1), and the card is refused. A changed character usually still parses, as a certificate
whose signature does not verify under its root; a card carries no root, so reading does not find
it, and the card is in the position of one altered in transit: what it pins is a leaf the real host
cannot match. The trust in a card remains the trust in the channel that carried it (§3), and no
§14.5 case changes.

A line that starts a property is never taken into the certificate, so a property after it — an
`X-HDTP-SEAL`, the `END:VCARD` — cannot be swallowed into the value. A line written to look like a
continuation can only add base64url characters to the certificate, which the parse and the chain
then judge; it cannot add a property.

## Alternatives

- **Leave the reader strict and ask people to send the file.** That is what the refusal says
  today, and it fails the person who has only the pasted text.
- **Repair only at the door that takes pasted text** (the owner MCP). That is a second card parser
  beside the identity core's, which every door uses so that they agree; two readers that differ
  answer the same card two ways.
- **Strip all Unicode whitespace.** The three implementations' notions of "whitespace" differ
  (Rust `is_whitespace`, Go `unicode.IsSpace`, a JavaScript `\s`); four named code points read the
  same everywhere, and are what a fold or a paste inserts.

## Evidence

The seed (`vectors/lib/card.mjs`) and `vectors/check.mjs` hold the rule: a card as the owner's paste
damaged it reads; a correctly folded card and an unfolded one read; a property after the
certificate, with and without a group prefix, stays a property; a cut certificate is refused at
intake; a certificate with one character changed reads and does not validate under its root.
hdtp-identity holds both ports to the seed on the same cards (`js/cases/cards.mjs`).
