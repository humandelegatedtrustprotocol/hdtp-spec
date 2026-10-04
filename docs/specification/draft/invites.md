## 4. Invites

An invite is a short URL whose entire state lives server-side with the issuer:

```
https://agent.alina.example/i/3f9c2a7b51e04d8c9a6f0b2e7d1c4a85
```

(The token is a path segment on the issuer's host — `/i/<token>` — because the landing below is served by the issuer, and a URL *fragment* never reaches a server. A QR of this URL is the shareable form.)

Issuer-side settings per invite — because state is server-side, all of this is enforceable and changeable *after* the link is shared:

| Setting | Default | Notes |
|---|---|---|
| `expires_at` | 14 days | Redeems after this fail |
| `max_uses` | 1 | Set high for a QR shown to a room; each redeem becomes its own contact |
| `auto_accept` | false | `true` = redeeming immediately creates the contact (conference-badge mode); `false` = each redeem lands as a pending request for manual approval |
| `preset` | "basic" | Permission preset granted on accept (§8) |
| `label` | — | "Pune conference 2026" — shows on incoming requests |
| revoked | — | Deleting the token invalidates the link at the protocol level; nothing cryptographic to chase |

The invite URL itself contains no personal data and no key — only the bearer token. The URL resolves (over TLS, to the endpoint the issuer personally handed over as QR/link) to a landing page serving the issuer's **signed card**: the vCard plus a signature over it by the issuer's leaf key. The same URL serves two audiences by content negotiation: a browser gets the human landing page; a client sending `Accept: application/hdtp-invite+json` or `Accept: application/json`, or appending `?format=json`, gets `{"card","card_sig","chain"}` — the signed card and the issuer's chain (§2), whose leaf **MUST** byte-equal the card's `X-HDTP-CERT` and which the redeemer **MUST** validate (§14.2) before use, so it can seal its very first call. That answer's `Content-Type` is `application/hdtp-invite+json`. An unknown, revoked, expired, or used-up token answers with one indistinguishable not-found on both views. The redeemer therefore holds the issuer's card *before* redeeming — which is also what lets a guest seal `redeem_invite` toward a `required` issuer (§13) — and redemption re-returns the same signed card in-band, so the redeemer pins a root whose chain reached it over the URL the issuer personally handed out.

---

