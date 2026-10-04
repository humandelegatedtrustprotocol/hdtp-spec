## 2. Identity, certificates and mTLS

An identity is a **root certificate**: self-signed X.509, its private key held by the person in a wallet and used for one thing, issuing certificates. The root's fingerprint is the identity's name everywhere — in pins, in envelopes, on screen — and is computed from the root's key:

```
fingerprint = "sha256:" + base64url( SHA-256( SubjectPublicKeyInfo ) )
```

A **host** — the person's own machine, or a provider — serves the identity under a **leaf certificate** the root issued. The leaf carries the host's own key, the one address the identity answers at, and the dates between which the host's authority runs. The leaf's key does three jobs: it is the TLS certificate, it signs every envelope, and contacts seal to it (§13). Contacts pin the root above it and learn the leaf beneath. §14 gives both certificates' profile and the validation rules; this section is what they mean.

| Certificate | Key held by | Algorithm | Names | Lives |
|---|---|---|---|---|
| root | the person, in a wallet | Ed25519; P-256 permitted | the identity, by fingerprint | as long as the identity; never rotated |
| leaf | the host, one per identity | Ed25519 or ECDSA P-256 | the endpoint, as its subject alternative name | as long as the person chooses, up to 398 days, one year by default; renewed by the wallet with a fresh key |

A **chain** is exactly two certificates, leaf then root. It travels everywhere identity must: as the TLS client certificate chain, inside a sealed envelope until the receiver holds the leaf and by fingerprint after that (§13.2), in the `redeem_invite` and `get_card` results, and on the invite landing (§4). A card carries the leaf alone (§3); the root arrives with the first exchange, and nothing about it needs to be trusted in advance, because it must hash to the fingerprint the leaf names as its issuer.

**Verification**, in full in §14.2: the root is self-signed and hashes to the fingerprint the verifier holds or is about to pin; the leaf is signed by that root, within its validity now, no longer than 398 days, and names exactly one endpoint; that endpoint equals the address in question, byte for byte. Then the leaf's key is the identity's voice at that address — until a newer leaf says otherwise, which it does the instant it is seen (§14.3).

**Client side (who is calling):** a caller proves possession of its leaf key in either of two ways — by presenting the chain as its TLS client certificate, or by the detached signature on a sealed envelope (§13), which survives pipes that strip client certificates. The receiver validates the chain, takes the root's fingerprint as the caller's identity, and resolves it through its pins (§6.1). A pin records the root, the endpoint and the leaf last accepted: the caller's leaf must name the pinned endpoint and be no older than the pinned leaf. An older leaf proves nothing (§14.3); a different endpoint is a request to change it (§5.3). When both proofs are present their leaf keys MUST match, else `envelope_invalid`. A chain whose root resolves to no pin gets the *guest* tier only (§6.1).

**Server side (who am I calling):** the endpoint is the pinned leaf's subject alternative name — a card carries no separate address, and a wallet signs no leaf without one. The endpoint's TLS server certificate is validated as either (a) normal WebPKI for the URL's hostname — the default, works with Let's Encrypt and behind terminating edges — or (b) the contact's own chain, which a self-hosted node MAY present as its server certificate and which the caller validates to the pinned root. Either way the name in the certificate equals the host dialed, and the *authorization* anchor is the root pinned at add-contact time, which no leaf moves.

**Renewal.** A leaf is renewed by the wallet issuing a new one for the same endpoint — with a fresh key — before the old expires; a host SHOULD ask thirty days ahead, at a moment the person is already present. Nothing is announced: a host carries its chain in its first envelope to each contact after a renewal, and a contact that has not seen it asks for it (§13.2), so a contact learns the new leaf on the next exchange in either direction, and because the endpoint is unchanged it needs no one's approval to accept it. A host keeps a superseded leaf's private key until that leaf's `notAfter`, so an envelope sealed to it by a contact that has not yet heard still opens; an envelope sealed to a key the host once held and holds no longer is answered `certificate_renewed` with the current chain (§14.4). A contact that sealed to an expired leaf learns the current one the same way — which is what keeps a card printed a year ago usable, as long as the address on it still stands. An expired leaf is refused everywhere, not demoted to guest, until the wallet renews it; a host's reminders are part of serving the identity.

**Moving** is a new leaf for a new endpoint, a contact request from there, and the old host forgetting: §5.3 and §9.

**Losing keys.** A lost or compromised leaf key is a renewal with a new key. A lost **root** is the end of the identity: re-share a new card from a new identity. A compromised root is the same, because whoever holds it can issue leaves, and no rotation ceremony could tell the two holders apart. There is deliberately no recovery and no rotation; the person's own backups of the wallet are the only copy, and the wallet says so once, when the root is made. Where the root is derived from a credential (§2.1) the rule is unchanged, but what counts as a copy is wider: a passkey its provider synchronises is a copy of the identity, and an export (§9) is another.

### 2.1 Deriving the root from a passkey

A wallet that can use a WebAuthn credential MUST **derive the root's private key from one** rather than generate and store it; a wallet that cannot — a command-line tool — generates the key and keeps it as §9 says. A wallet that derives holds no root at rest: the key is reconstructed on each use from a secret the authenticator returns, and exists only as long as one signing takes.

The derivation is specified so that any conforming wallet reproduces the same identity from the same credential. Without that, a person's identity would depend on which wallet they happened to use, which is the opposite of what a root in the person's own hands is for. A wallet MUST use exactly these values.

```
salt = SHA-256("hdtp/vault/1")                                  # 32 bytes, the PRF input
prf  = the WebAuthn prf extension's first output for that salt  # 32 bytes, from the authenticator
seed = HKDF-SHA256(ikm = prf, salt = "", info, L = 32)
key  = the Ed25519 private key whose 32-byte seed is `seed`
```

| `info` | Derives |
|---|---|
| `"hdtp/root/1"` | the root's private key |
| `"hdtp/store-key/1"` | the key sealing the wallet's own record — its ledger, its contact book and, once the root has been re-bound (§9), the root itself |
| `"hdtp/store-id/1"` | the address that record is kept at, wherever it is kept |

`info` strings are US-ASCII without a terminator. HKDF is RFC 5869 with an **empty** salt, so the extract step is `HMAC-SHA256(key = 0x00 × 32, prf)`. The root's algorithm is **Ed25519**: P-256 remains permitted for a generated root, but a derived root is Ed25519 so that one credential yields one identity and not two. Appendix B carries vectors for all three `info` strings over one PRF output.

The PRF salt is a fixed constant rather than a per-credential one, because a wallet arriving cold on a new device must derive before it can fetch anything, and a per-credential salt would have to be fetched first. A fixed salt still yields a per-credential secret, since the PRF is keyed by the credential. The salt's wording carries no meaning: it is a fixed byte string.

Three properties follow:

- **A derived root is indistinguishable on the wire.** It is a self-signed X.509 root like any other, validated by §14.2 like any other. No verifier learns how it was made and none may behave differently because of it.
- **The identity travels with the credential.** Where the authenticator's provider synchronises the credential across a person's devices, the identity follows, with nothing to copy and nothing to lose. A wallet MUST NOT present this as a guarantee: whether a given provider carries the PRF secret across its own sync is that provider's property and not the protocol's, and a wallet that has not verified it SHOULD say so rather than imply otherwise.
- **Which credential answered matters.** Deriving from the wrong credential does not fail — it produces a valid root belonging to a different identity. A wallet holding more than one credential for its origin MUST name the intended credential when it knows which one that is, and MUST prove the derived root before signing (§2.2).

A wallet that derives its root MUST still be able to export it (§9). A derived root is exportable key material like any other, and the export is what lets a person use a tool that cannot speak WebAuthn, or leave the provider whose credential it is.

### 2.2 Proving a root before using it

Before issuing any certificate, a wallet MUST establish that the root it is about to sign with is the root the identity already has. For a derived root this is not a formality: the wrong credential yields a well-formed root, ready to sign, belonging to somebody else.

A wallet MUST refuse to sign unless all three hold:

1. the root key's fingerprint equals the fingerprint the identity is known by;
2. the root **certificate** it will return parses, and its `SubjectPublicKeyInfo` equals the root key's;
3. the root key signs a challenge that verifies under that certificate's public key. The challenge MUST be domain-separated from certificate bytes — the ASCII `HDTP root proof v1` followed by a newline and at least 32 random bytes — so that proving possession can never be made to sign a certificate.

A wallet MUST validate a chain it has assembled (§14.2) against the expected root and endpoint before returning it. A chain that fails validation is a wallet defect, and returning it makes the defect the host's to discover.

**A root certificate is issued once.** A wallet MUST NOT rebuild a root certificate for an identity that already has one. A rebuilt root has the same fingerprint, a fresh serial and a later `notBefore`; leaves issued earlier still validate under it, because chain validation reads no date of the root (§14.2). Where the wallet keeps no copy of its own, the root certificate is supplied with the signing request and returned unchanged beside the new leaf.

---

