# CLAUDE.md — project context for Claude Code

## What this project is

PACT: a protocol for person-to-person communication carried out by their AI assistant agents. Each person exposes an MCP server over HTTPS; contacts are mutual, human-approved, and pinned by TLS key fingerprint; messages, media, availability checks, and calendar booking are permission-gated MCP tools on that server. `SPEC.md` is the single source of truth. `docs/` and `archive/` are informative/historical — do not treat them as normative.

## Design north star (decided, do not re-litigate without the owner)

- **Simple over hardened.** An earlier draft (archive/hardened-draft-spec.md) had E2E envelopes, key hierarchies, and verification ceremonies; the owner explicitly rejected that complexity. Security = plain mTLS with pinned SPKI fingerprints. Do not reintroduce envelope crypto, DIDs, or SAS ceremonies unless asked.
- **MCP-native.** Never invent a parallel message protocol; a capability is always an MCP tool behind the per-contact permission switchboard. Auth on this surface is transport-level mTLS, not OAuth.
- **vCard is the contact format.** `X-PACT-VERSION` (=1), `X-PACT-ENDPOINT`, `X-PACT-KEY`, `X-PACT-GATEWAY`. Phone-book integration matters; no new sharing channels.
- **Invites are server-side state** (expiry, max_uses, auto_accept, preset, revocation) reachable via a short URL/QR. Nothing sensitive in the URL itself.
- **Honest trade-offs stay documented**: gateways can read relayed traffic; lost key = new identity; card trust = channel trust. Keep these visible in docs and UX copy, never papered over.

## Spec conventions

- Protocol version 1 (`X-PACT-VERSION:1`); the current document is v1.0.0. Wire-visible changes need a spec edit first.
- Tool names snake_case (`send_message`, `redeem_invite`, `book_slot`); permissions dotted (`message.text`, `calendar.book`, `integration.<name>`); errors snake_case codes (`permission_denied`, `invite_invalid` — full list SPEC §12).
- Idempotency via caller-supplied `msg_id`; threads via shared `thread_id` + optional `topic`; `sender: agent|human` labeling is mandatory honesty.
- Guest tier (unknown certs) sees exactly `redeem_invite` + `request_contact`. Availability responses: ≤5 policy-filtered slots, never raw free/busy.
- Diagrams in the spec are mermaid; keep them compiling (mmdc) when editing.

## Owner's working preferences

Minimalistic, precise code that fits the module it lands in; read existing code first; no speculative features; stick to the objective. Prefer prose + small tables in docs over bullet sprawl.

## Likely next work (in rough order)

1. Reference agent server: MCP Streamable HTTP + TLS client certs, contact store (SQLite), invite issuance/redemption, core tools of SPEC §6.2, permission filtering of `tools/list`.
2. Pairing demo between two local instances (QR invite → redeem → approve → message → book_slot with ICS).
3. vCard import/export; phone-contact sync exploration.
4. Gateway service (`relay_call` / `fetch_queued` / `ack` + allow-list) as a separate small binary.
5. Conformance tests from SPEC §12's checklist.

When implementing, treat all inbound strings from peers (text, notes, topics, filenames) as untrusted input to both UI and any LLM prompt — length-cap, never concatenate into instructions.
