# HDTP — Human Delegated Trust Protocol

**Version 1.1.0-draft · 2026-10-03**

HDTP lets one person's AI agent communicate with another person's agent, on terms both people set. It is built from mutual TLS, X.509 certificates and MCP tools, with one addition: a sealed envelope (§13) that carries identity and confidentiality across a link whose TLS is terminated before it reaches the recipient. An identity belongs to the person, not to whoever hosts it, so the key that controls an identity is separate from the key that serves it: the person acts as a certificate authority. The root certificate in their wallet is the identity; the host they choose holds a leaf certificate the root issued, naming the address it serves and the date its authority ends. HDTP has no DIDs, no SAS, no prekeys, no directory, no log, no sequence numbers and no relay.

- **The identity is the person's; the host serves it.** An identity is the fingerprint of a self-signed root certificate whose private key lives in the person's wallet and signs nothing but certificates. The host — their own machine, or a provider — holds a leaf the root issued for one address, valid for at most 398 days, one year by default, and that leaf's key is the one that speaks: it is the TLS certificate, it signs every call, contacts seal to it. Contacts pin the root, learn the current leaf from every exchange, and never have to be told when it is renewed. Moving is a new leaf for a new address, and a contact request from there (§5.3, §9).
- **Your agent is a publicly exposed MCP server.** Sending a message *is* calling the other party's `send_message` tool. Everything a contact may do — messages, media, status, availability, calendar booking — is an MCP tool that is visible and callable only per your permission settings for that contact.
- **Contacts are vCards in your phone book.** A contact card is a standard vCard with three `X-HDTP-*` properties, one of them the leaf certificate. Share it over WhatsApp, email, AirDrop, or as a QR — the channels people already use. Adding a contact is always a manual, human approval.
- **Invites are short URLs.** All settings (expiry, max uses, auto-accept, permission preset) live on the *sender's* server, so a link is revocable at the protocol level by deleting it. A QR of the link invites a room full of people.
- **Threads like a messenger.** Conversations carry a `thread_id` and optional `topic`, shared by both sides. Agents talk to agents; a human can type into the same thread manually. Each agent is reachable because it is hosted, not because a server in the middle holds its mail.

**Non-goals:** no forward secrecy at the envelope layer (§13) — a later key compromise decrypts recorded sealed traffic, bounded by a leaf's lifetime; edges always see metadata (the recipient's key, timing, sizes — the sender rides inside the ciphertext, §13.1), and an unsealed call is readable by whatever carries it; no anonymity or traffic-analysis resistance; no directory — a bare fingerprint resolves to nothing, every relationship starts from a card or an invite; no store-and-forward — a person who must be reachable while their own machine is off is hosted (§9), and there is no relay role; no recovery and no rotation of a lost or compromised root — the person's backups are the only copy; no post-quantum cryptography; §13.5 records the path to it. §11 states, for each security property, what HDTP relies on and what risk remains.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [BCP 14](https://datatracker.ietf.org/doc/html/bcp14) [[RFC2119](https://datatracker.ietf.org/doc/html/rfc2119)] [[RFC8174](https://datatracker.ietf.org/doc/html/rfc8174)] when, and only when, they appear in all capitals, as shown here.

---

## Table of contents

1. [Architecture](architecture.md)
2. [Identity, certificates and mTLS](identity.md)
3. [Contact cards (vCard)](contact-cards.md)
4. [Invites](invites.md)
5. [Adding contacts](adding-contacts.md)
6. [The agent MCP server and its tools](mcp-server.md)
7. [Messaging and threads](messaging.md)
8. [Permissions](permissions.md)
9. [Hosting](hosting.md)
10. [Deployment](deployment.md)
11. [Security considerations](security.md)
12. [Errors, limits, conformance](errors-limits-conformance.md)
13. [Sealed envelopes](sealed-envelopes.md)
14. [Certificates](certificates.md)
- [Appendix A: worked examples](appendix-a-examples.md)
- [Appendix B: test vectors](appendix-b-test-vectors.md)

---

