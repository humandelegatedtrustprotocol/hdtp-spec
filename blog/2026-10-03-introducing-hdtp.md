# Introducing HDTP

*Sumit Agrawal · 2026-10-03*

HDTP, the Human Delegated Trust Protocol, is how one person's AI agent talks to another person's
agent across the open internet, on terms both people set. Version 1.0.0 is released today.

## The problem

Assistants are starting to act for people: they read the mail, keep the calendar, answer the
routine. The next step is obvious — let my assistant ask yours when you are free, send you the
file, tell you I am running late — and it raises three questions no product answers on its own.
Who is on the other end? What is it allowed to do? And does that answer survive me changing
provider?

## What HDTP does

- **Your identity is yours.** It is the fingerprint of a self-signed root certificate that you
  hold, derived from your passkey or kept in your wallet. The machine or provider that runs your
  agent holds only a leaf certificate your root issued for one address, for at most 398 days. Move
  to another host and your contacts follow the new leaf; leave a host and it deletes what it held.
- **Contacts are vCards.** A card carries your current leaf certificate and fits a QR code, so it
  travels over the channels people already use and lands in an ordinary phone book. Adding a
  contact is always a human decision, on both sides.
- **Everything is an MCP tool.** Your agent is an MCP server. Sending a message is calling the
  other side's `send_message`; checking availability or booking a slot are tools too. What each
  contact may call is your choice, per contact, and a caller sees only the tools it may use.
- **Trust is checked on every call.** Calls are mutual TLS with the leaf key, and may be sealed
  end to end in an envelope that a terminating edge in the path can neither read nor forge.

## What it does not do

The specification states its trade-offs instead of hiding them. There is no forward secrecy at the
envelope layer. An edge or tunnel in the path sees metadata. A card is only as trustworthy as the
channel it came through. A lost root is a new identity: the protocol has no recovery and no root rotation.

## How it is built

Every rule in the specification is meant to be held by something that runs. Appendix B carries test vectors generated from labelled seeds; an intrusion
battery replays the compromise cases against a small reference node; and one identity library — a
Rust core compiled to WebAssembly, with an independent Go port — is proven against the same vectors
and scenarios in both ports, with every MUST of the text mapped to what holds it.

Two implementations are built on that library: HDTP Gateway, a node you run yourself, and
BatonDeck, a hosted platform. Neither is public yet.

## What comes next

The open work is an external review of the sealed envelope and the certificate profile, a
conformance suite that runs §12's checklist, and an implementation by someone other than us.
Changes to the protocol go through enhancement proposals (`seps/`).
