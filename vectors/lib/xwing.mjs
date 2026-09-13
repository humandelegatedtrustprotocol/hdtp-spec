// X-Wing (draft-connolly-cfrg-xwing-kem): X25519 and ML-KEM-768 combined, the KEM of PACT-SEAL-XWING.
// Built on Node's native ML-KEM; a key derives from one 32-byte seed as the draft specifies.
import { createHash, createPrivateKey, createPublicKey, encapsulate, decapsulate, diffieHellman, randomBytes } from 'node:crypto';

const MLKEM_PKCS8 = Buffer.from('3054020100300b060960864801650304040204428040', 'hex'); // then the 64-byte (d ‖ z) seed
const MLKEM_SPKI = Buffer.from('308204b2300b0609608648016503040402038204a100', 'hex');     // then the 1184-byte public key
const X25519_PKCS8 = Buffer.from('302e020100300506032b656e04220420', 'hex');
const X25519_SPKI = Buffer.from('302a300506032b656e032100', 'hex');
export const LABEL = Buffer.from('\\.//^\\', 'ascii');
export const PK_BYTES = 1216, CT_BYTES = 1120, SK_BYTES = 32;

const xPub = (raw) => createPublicKey({ key: Buffer.concat([X25519_SPKI, raw]), format: 'der', type: 'spki' });
const xPriv = (raw) => createPrivateKey({ key: Buffer.concat([X25519_PKCS8, raw]), format: 'der', type: 'pkcs8' });
const rawOf = (pub) => pub.export({ format: 'der', type: 'spki' }).subarray(X25519_SPKI.length);

export function keyFromSeed(sk) {
  if (sk.length !== SK_BYTES) throw new Error('X-Wing seed must be 32 bytes');
  const expanded = createHash('shake256', { outputLength: 96 }).update(sk).digest();
  const mlkemPriv = createPrivateKey({ key: Buffer.concat([MLKEM_PKCS8, expanded.subarray(0, 64)]), format: 'der', type: 'pkcs8' });
  const pkM = createPublicKey(mlkemPriv).export({ format: 'der', type: 'spki' }).subarray(MLKEM_SPKI.length);
  const x = xPriv(expanded.subarray(64, 96));
  return { sk, mlkemPriv, xPriv: x, pk: Buffer.concat([pkM, rawOf(createPublicKey(x))]) };
}
export const generateKey = () => keyFromSeed(randomBytes(SK_BYTES));

function combine(ssM, ssX, ctX, pkX) {
  if (ssX.every((b) => b === 0)) throw new Error('all-zero X25519 output: low-order point');
  return createHash('sha3-256').update(Buffer.concat([ssM, ssX, ctX, pkX, LABEL])).digest();
}

// ML-KEM encapsulation is randomised inside the platform; only the X25519 half can be seeded, for vectors.
export function encap(pk, ekSeed = randomBytes(32)) {
  if (pk.length !== PK_BYTES) throw new Error('X-Wing public key must be 1216 bytes');
  const pkM = pk.subarray(0, 1184), pkX = pk.subarray(1184);
  const { sharedKey: ssM, ciphertext: ctM } = encapsulate(createPublicKey({ key: Buffer.concat([MLKEM_SPKI, pkM]), format: 'der', type: 'spki' }));
  const ek = xPriv(ekSeed), ctX = rawOf(createPublicKey(ek));
  return { ss: combine(ssM, diffieHellman({ privateKey: ek, publicKey: xPub(pkX) }), ctX, pkX), ct: Buffer.concat([ctM, ctX]) };
}

export function decap(key, ct) {
  if (ct.length !== CT_BYTES) throw new Error('X-Wing ciphertext must be 1120 bytes');
  const ctM = ct.subarray(0, 1088), ctX = ct.subarray(1088);
  return combine(decapsulate(key.mlkemPriv, ctM), diffieHellman({ privateKey: key.xPriv, publicKey: xPub(ctX) }), ctX, key.pk.subarray(1184));
}
