// Deterministic keys for the vectors, and the conversions §13.1 names.
import { createHash, createPrivateKey, createPublicKey, hkdfSync } from 'node:crypto';

const ED25519_PKCS8 = Buffer.from('302e020100300506032b657004220420', 'hex');
const X25519_PKCS8 = Buffer.from('302e020100300506032b656e04220420', 'hex');
const X25519_SPKI = Buffer.from('302a300506032b656e032100', 'hex');
const P256_N = BigInt('0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551');
const P = (1n << 255n) - 19n;

export const b64url = (b) => Buffer.from(b).toString('base64url');
export const fromB64url = (s) => Buffer.from(s, 'base64url');
/**
 * Bytes this library did not write — a card's certificate, the chain in a peer's plaintext — read as
 * both pact-identity ports read them (its CONTRACT §0): base64url, forgiving the padding and the
 * standard alphabet's `+` and `/`, and nothing else. Returns the bytes, or null.
 *
 * `fromB64url` above cannot fail: Buffer.from skips every character it does not know, so a card whose
 * certificate carried a stray `!`, and a plaintext chain member with one, were read here and by the Go
 * port while the Rust core refused them — the reference and two ports disagreeing about which cards
 * and which chains exist (the port-parity audit of 2026-09-29, R24, T11, C7, T10). It stays for bytes
 * this library wrote itself. Whitespace is a character outside the alphabet; a last character with a
 * spare bit set is a second spelling, which the round trip refuses.
 */
export const strictB64url = (s) => {
  if (typeof s !== 'string') return null;
  const t = s.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  if (!/^[A-Za-z0-9_-]*$/.test(t)) return null;
  const bytes = Buffer.from(t, 'base64url');
  return b64url(bytes) === t ? bytes : null;
};
/**
 * A member of an envelope, as it travels: unpadded base64url in its ONE canonical spelling (§13.1).
 * Returns the bytes, or null.
 *
 * `fromB64url` — Node's `Buffer.from(s, 'base64url')` — cannot fail: it skips every character it does
 * not know and ignores a last character's spare bits. `sig` covers the DECODED bytes, so an envelope
 * with a stray character in `protected` decoded to the same header, verified, and was accepted here
 * and by the Go port, which read the wire as this library did, while the Rust core refused it. Two
 * spellings of one envelope, and implementations that disagreed about which of them exist (found
 * 2026-09-21). The round trip is the whole test: there is exactly one string that encodes these bytes.
 */
export const wireB64url = (s) => {
  if (typeof s !== 'string' || !/^[A-Za-z0-9_-]*$/.test(s)) return null;
  const bytes = Buffer.from(s, 'base64url');
  return b64url(bytes) === s ? bytes : null;
};
export const sha256 = (b) => createHash('sha256').update(b).digest();

// Every secret in the vectors derives from a label, so the generator is reproducible.
export const seed = (label) => sha256(Buffer.from('pact-2.0-vectors/' + label));

// §2.1: a root derived from a passkey. `PRF_SALT` is the fixed input handed to the authenticator's
// prf extension — fixed because a wallet arriving cold on a new device has to derive before it can
// fetch anything, and a per-credential salt would have to be fetched first. The secret is still
// per-credential, because the PRF is keyed by the credential.
//
// The name is stale on purpose: there is no vault at the address any more. Every PRF measurement
// this design rests on was taken with these exact bytes, so renaming the string would invalidate
// the measurement and buy nothing but tidiness.
export const PRF_SALT = sha256(Buffer.from('pact/vault/1'));

// HKDF-SHA256 with an EMPTY salt, so extract is HMAC-SHA256(key = 0x00 x 32, prf). One PRF output
// yields unrelated 32-byte seeds per `info`, which is what lets one credential hold a root, the key
// that seals the wallet's record, and the address that record is kept at, without any of the three
// telling you anything about the others.
export const deriveSeed = (prf, info) =>
  Buffer.from(hkdfSync('sha256', prf, Buffer.alloc(0), Buffer.from(info, 'ascii'), 32));

export function ed25519FromSeed(s) {
  const priv = createPrivateKey({ key: Buffer.concat([ED25519_PKCS8, s]), format: 'der', type: 'pkcs8' });
  return { priv, pub: createPublicKey(priv) };
}

export function p256FromSeed(s) {
  let k = BigInt('0x' + s.toString('hex')) % P256_N;
  if (k === 0n) k = 1n;
  const scalar = Buffer.from(k.toString(16).padStart(64, '0'), 'hex');
  const sec1 = Buffer.concat([Buffer.from('30310201010420', 'hex'), scalar, Buffer.from('a00a06082a8648ce3d030107', 'hex')]);
  const priv = createPrivateKey({ key: sec1, format: 'der', type: 'sec1' });
  return { priv, pub: createPublicKey(priv) };
}

export const spkiOf = (pub) => pub.export({ format: 'der', type: 'spki' });
export const pkcs8Of = (priv) => priv.export({ format: 'der', type: 'pkcs8' });
export const fingerprint = (pub) => 'sha256:' + b64url(sha256(spkiOf(pub)));
export const keyId = (pub) => sha256(spkiOf(pub));

export function algorithmOf(key) {
  if (key.asymmetricKeyType === 'ed25519') return 'ed25519';
  if (key.asymmetricKeyType === 'ec' && key.asymmetricKeyDetails?.namedCurve === 'prime256v1') return 'p256';
  throw new Error('unsupported key type ' + key.asymmetricKeyType);
}

const jwk = (key) => key.export({ format: 'jwk' });

function modpow(b, e, m) { let r = 1n; b %= m; while (e > 0n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; } return r; }
const le = (buf) => { let v = 0n; for (let i = buf.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(buf[i]); return v; };
const toLe = (v, n) => { const out = Buffer.alloc(n); for (let i = 0; i < n; i++) { out[i] = Number(v & 0xffn); v >>= 8n; } return out; };

// RFC 7748 §4.1: u = (1 + y) / (1 - y) on the Ed25519 public key's y coordinate.
export function ed25519PublicToX25519(pub) {
  const y = le(fromB64url(jwk(pub).x)) & ((1n << 255n) - 1n);
  const u = ((1n + y) * modpow((1n - y + P) % P, P - 2n, P)) % P;
  return createPublicKey({ key: Buffer.concat([X25519_SPKI, toLe(u, 32)]), format: 'der', type: 'spki' });
}

// RFC 8032 §5.1.5: the clamped low half of SHA-512(seed) is the scalar.
export function ed25519PrivateToX25519(priv) {
  const h = createHash('sha512').update(fromB64url(jwk(priv).d)).digest();
  const a = Buffer.from(h.subarray(0, 32));
  a[0] &= 248; a[31] &= 127; a[31] |= 64;
  return createPrivateKey({ key: Buffer.concat([X25519_PKCS8, a]), format: 'der', type: 'pkcs8' });
}

export function x25519FromSeed(s) {
  const a = Buffer.from(s); a[0] &= 248; a[31] &= 127; a[31] |= 64;
  const priv = createPrivateKey({ key: Buffer.concat([X25519_PKCS8, a]), format: 'der', type: 'pkcs8' });
  return { priv, pub: createPublicKey(priv) };
}

export const x25519Raw = (pub) => fromB64url(jwk(pub).x);
export const p256Uncompressed = (pub) => { const j = jwk(pub); return Buffer.concat([Buffer.from([4]), fromB64url(j.x), fromB64url(j.y)]); };
export const p256Scalar = (priv) => fromB64url(jwk(priv).d);
