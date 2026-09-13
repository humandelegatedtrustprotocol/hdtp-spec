// Deterministic keys for the vectors, and the conversions §13.1 names.
import { createHash, createPrivateKey, createPublicKey } from 'node:crypto';

const ED25519_PKCS8 = Buffer.from('302e020100300506032b657004220420', 'hex');
const X25519_PKCS8 = Buffer.from('302e020100300506032b656e04220420', 'hex');
const X25519_SPKI = Buffer.from('302a300506032b656e032100', 'hex');
const P256_N = BigInt('0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551');
const P = (1n << 255n) - 19n;

export const b64url = (b) => Buffer.from(b).toString('base64url');
export const fromB64url = (s) => Buffer.from(s, 'base64url');
export const sha256 = (b) => createHash('sha256').update(b).digest();

// Every secret in the vectors derives from a label, so the generator is reproducible.
export const seed = (label) => sha256(Buffer.from('pact-2.0-vectors/' + label));

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
