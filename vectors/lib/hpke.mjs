// HPKE Base mode (RFC 9180) for the two PACT suites, and the detached signature of §13.1.
import { createHmac, createCipheriv, createDecipheriv, createECDH, diffieHellman, createPublicKey, randomBytes, sign, verify } from 'node:crypto';
import { algorithmOf, ed25519PublicToX25519, ed25519PrivateToX25519, x25519Raw, x25519FromSeed, p256Uncompressed, p256Scalar, p256FromSeed } from './keys.mjs';

// `npk` is the encapsulated key's length, which is the KEM's public-key length (RFC 9180 §7.1): an
// uncompressed P-256 point, or an X25519 key. §13.1 pins it so `enc` has one length per suite and the
// signature over `protected ‖ enc ‖ ct` cannot be read with the boundary in a second place.
export const SUITES = {
  'PACT-SEAL-P256': { kem: 0x0010, kdf: 0x0001, aead: 0x0001, nk: 16, nn: 12, nsecret: 32, npk: 65, cipher: 'aes-128-gcm' },
  'PACT-SEAL-X25519': { kem: 0x0020, kdf: 0x0001, aead: 0x0003, nk: 32, nn: 12, nsecret: 32, npk: 32, cipher: 'chacha20-poly1305' },
};

const V = Buffer.from('HPKE-v1');
const i2osp2 = (n) => Buffer.from([n >> 8, n & 0xff]);
const hmac = (key, data) => createHmac('sha256', key).update(data).digest();
function expand(prk, info, L) {
  let t = Buffer.alloc(0), okm = Buffer.alloc(0), i = 1;
  while (okm.length < L) { t = hmac(prk, Buffer.concat([t, info, Buffer.from([i++])])); okm = Buffer.concat([okm, t]); }
  return okm.subarray(0, L);
}
const labeledExtract = (id, salt, label, ikm) => hmac(salt, Buffer.concat([V, id, Buffer.from(label), ikm]));
const labeledExpand = (id, prk, label, info, L) => expand(prk, Buffer.concat([i2osp2(L), V, id, Buffer.from(label), info]), L);

function keySchedule(s, sharedSecret, info) {
  const id = Buffer.concat([Buffer.from('HPKE'), i2osp2(s.kem), i2osp2(s.kdf), i2osp2(s.aead)]);
  const empty = Buffer.alloc(0);
  const ksc = Buffer.concat([Buffer.from([0]), labeledExtract(id, empty, 'psk_id_hash', empty), labeledExtract(id, empty, 'info_hash', info)]);
  const secret = labeledExtract(id, sharedSecret, 'secret', empty);
  return { key: labeledExpand(id, secret, 'key', ksc, s.nk), nonce: labeledExpand(id, secret, 'base_nonce', ksc, s.nn) };
}
function sharedSecret(s, dh, kemContext) {
  if (dh.every((b) => b === 0)) throw new Error('all-zero DH output: low-order point');
  const id = Buffer.concat([Buffer.from('KEM'), i2osp2(s.kem)]);
  return labeledExpand(id, labeledExtract(id, Buffer.alloc(0), 'eae_prk', dh), 'shared_secret', kemContext, s.nsecret);
}

// Which suite a recipient key needs (§13.1): its curve's. A leaf takes the suite of its key.
export const suiteForKey = (pub) => (algorithmOf(pub) === 'p256' ? 'PACT-SEAL-P256' : 'PACT-SEAL-X25519');
export const suiteFor = suiteForKey;
export const suiteForLeaf = (leaf) => suiteForKey(leaf.publicKey);
export const recipientOf = (leaf) => leaf.publicKey;

function recipientPublic(suite, pub) {
  if (suite === 'PACT-SEAL-P256') return p256Uncompressed(pub);
  return x25519Raw(pub.asymmetricKeyType === 'ed25519' ? ed25519PublicToX25519(pub) : pub);
}

function encap(suite, pub, seed) {
  const s = SUITES[suite], pkR = recipientPublic(suite, pub);
  if (suite === 'PACT-SEAL-P256') {
    const e = createECDH('prime256v1'); e.setPrivateKey(p256Scalar(p256FromSeed(seed).priv));
    const enc = e.getPublicKey();
    return { enc, ss: sharedSecret(s, e.computeSecret(pkR), Buffer.concat([enc, pkR])) };
  }
  const e = x25519FromSeed(seed);
  const enc = x25519Raw(e.pub);
  const pkRobj = createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b656e032100', 'hex'), pkR]), format: 'der', type: 'spki' });
  return { enc, ss: sharedSecret(s, diffieHellman({ privateKey: e.priv, publicKey: pkRobj }), Buffer.concat([enc, pkR])) };
}
function decap(suite, priv, pub, enc) {
  const s = SUITES[suite], pkR = recipientPublic(suite, pub);
  if (suite === 'PACT-SEAL-P256') {
    const e = createECDH('prime256v1'); e.setPrivateKey(p256Scalar(priv));
    return sharedSecret(s, e.computeSecret(enc), Buffer.concat([enc, pkR]));
  }
  const sk = priv.asymmetricKeyType === 'ed25519' ? ed25519PrivateToX25519(priv) : priv;
  const encObj = createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b656e032100', 'hex'), enc]), format: 'der', type: 'spki' });
  return sharedSecret(s, diffieHellman({ privateKey: sk, publicKey: encObj }), Buffer.concat([enc, pkR]));
}

function sealWith(suite, recipientPub, info, aad, plaintext, seed) {
  const s = SUITES[suite];
  const { enc, ss } = encap(suite, recipientPub, seed);
  const { key, nonce } = keySchedule(s, ss, info);
  const c = createCipheriv(s.cipher, key, nonce, { authTagLength: 16 });
  c.setAAD(aad);
  return { enc, ct: Buffer.concat([c.update(plaintext), c.final(), c.getAuthTag()]) };
}
// Production sealing draws a fresh ephemeral every time. A reused ephemeral repeats the key and the
// nonce, and two ciphertexts under them leak the XOR of their plaintexts — so no seed can be passed here.
export const seal = (suite, recipientPub, info, aad, plaintext) => sealWith(suite, recipientPub, info, aad, plaintext, randomBytes(32));
// For vectors and for demonstrating the leak only.
export const sealDeterministic = (suite, recipientPub, info, aad, plaintext, seed) => sealWith(suite, recipientPub, info, aad, plaintext, seed);

export function open(suite, recipientPriv, recipientPub, info, aad, enc, ct) {
  const s = SUITES[suite];
  const { key, nonce } = keySchedule(s, decap(suite, recipientPriv, recipientPub, enc), info);
  const d = createDecipheriv(s.cipher, key, nonce, { authTagLength: 16 });
  d.setAAD(aad);
  d.setAuthTag(ct.subarray(ct.length - 16));
  return Buffer.concat([d.update(ct.subarray(0, ct.length - 16)), d.final()]);
}

// §13.1: Ed25519 pure, or ECDSA P-256/SHA-256 in DER, by the signer's own algorithm.
export function signDetached(priv, data) {
  return algorithmOf(priv) === 'ed25519' ? sign(null, data, priv) : sign('sha256', data, { key: priv, dsaEncoding: 'der' });
}
export function verifyDetached(pub, data, sig) {
  return algorithmOf(pub) === 'ed25519' ? verify(null, data, pub, sig) : verify('sha256', data, { key: pub, dsaEncoding: 'der' }, sig);
}
