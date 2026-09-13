// The §14.1 profile as bytes, §14.2 chain validation, and the §14.3 comparison.
import { createPublicKey } from 'node:crypto';
import { seq, set, explicit, implicit, octet, utf8, bool, int, bitstr, oid, time, read, children, readOid, readTime } from './der.mjs';
import { spkiOf, keyId, sha256, b64url, algorithmOf } from './keys.mjs';
import { signDetached, verifyDetached } from './hpke.mjs';

const OID = {
  cn: '2.5.4.3', ed25519: '1.3.101.112', ecdsaSha256: '1.2.840.10045.4.3.2',
  basicConstraints: '2.5.29.19', keyUsage: '2.5.29.15', eku: '2.5.29.37', san: '2.5.29.17', ski: '2.5.29.14', aki: '2.5.29.35',
  serverAuth: '1.3.6.1.5.5.7.3.1', clientAuth: '1.3.6.1.5.5.7.3.2',
};
export const MAX_LEAF_DAYS = 398;
const DAY = 86_400_000;
const FOREVER = new Date(Date.UTC(9999, 11, 31, 23, 59, 59));

const name = (cn) => seq(set(seq(oid(OID.cn), utf8(cn))));
const sigAlg = (alg) => seq(oid(alg === 'ed25519' ? OID.ed25519 : OID.ecdsaSha256));
const ext = (o, critical, value) => seq(oid(o), ...(critical ? [bool(true)] : []), octet(value));
function keyUsage(bits) {
  let byte = 0; for (const b of bits) byte |= 0x80 >> b;
  let unused = 0; for (let v = byte; v && !(v & 1); v >>= 1) unused++;
  return bitstr(Buffer.from([byte]), unused);
}
const serialOf = (label) => sha256(Buffer.from('serial/' + label)).subarray(0, 8);

function certificate(tbsParts, signer) {
  const alg = algorithmOf(signer);
  const tbs = seq(...tbsParts(sigAlg(alg)));
  return seq(tbs, sigAlg(alg), bitstr(signDetached(signer, tbs)));
}

export function buildRoot({ cn, key, notBefore, label }) {
  const spki = spkiOf(key.pub), id = keyId(key.pub);
  return certificate((alg) => [
    explicit(0, int(2)), int(serialOf(label)), alg, name(cn), seq(time(notBefore), time(FOREVER)), name(cn), spki,
    explicit(3, seq(
      ext(OID.basicConstraints, true, seq(bool(true), int(0))),
      ext(OID.keyUsage, true, keyUsage([5])),
      ext(OID.ski, false, octet(id)),
    )),
  ], key.priv);
}

export function buildLeaf({ cn, rootCn, root, hostKey, endpoint, dnsName, notBefore, notAfter, label, cA = false }) {
  const spki = spkiOf(hostKey.pub), id = keyId(hostKey.pub), issuerId = keyId(root.pub);
  const usage = algorithmOf(hostKey.pub) === 'p256' ? [0, 4] : [0];
  const sanNames = [implicit(6, Buffer.from(endpoint, 'ascii'))];
  if (dnsName) sanNames.push(implicit(2, Buffer.from(dnsName, 'ascii')));
  return certificate((alg) => [
    explicit(0, int(2)), int(serialOf(label)), alg, name(rootCn), seq(time(notBefore), time(notAfter)), name(cn), spki,
    explicit(3, seq(
      ext(OID.basicConstraints, true, cA ? seq(bool(true)) : seq()),
      ext(OID.keyUsage, true, keyUsage(usage)),
      ext(OID.eku, false, seq(oid(OID.serverAuth), oid(OID.clientAuth))),
      ext(OID.san, false, seq(...sanNames)),
      ext(OID.ski, false, octet(id)),
      ext(OID.aki, false, seq(implicit(0, issuerId))),
    )),
  ], root.priv);
}

// Reading a certificate back into the fields the rules need. Throws on anything malformed.
export function parse(der) {
  const cert = read(der);
  if (cert.tag !== 0x30) throw new Error('not a SEQUENCE');
  const [tbs, alg, sig] = children(cert);
  const f = children(tbs);
  if (f[0].tag !== 0xa0 || children(f[0])[0].content[0] !== 2) throw new Error('not v3');
  const out = {
    der, tbs: tbs.raw, sigAlg: readOid(children(alg)[0]), sig: sig.content.subarray(1),
    serial: f[1].content, issuer: cnOf(f[3]), subject: cnOf(f[5]),
    notBefore: readTime(children(f[4])[0]), notAfter: readTime(children(f[4])[1]),
    spki: f[6].raw, ca: false, pathLen: null, keyUsage: [], eku: [], uris: [], dns: [], ski: null, aki: null, unknownCritical: [],
  };
  out.publicKey = createPublicKey({ key: out.spki, format: 'der', type: 'spki' });
  out.keyId = sha256(out.spki);
  const exts = f[7]?.tag === 0xa3 ? children(children(f[7])[0]) : [];
  for (const e of exts) {
    const parts = children(e);
    const id = readOid(parts[0]), critical = parts[1].tag === 0x01 && parts[1].content[0] !== 0;
    const value = read(parts[parts.length - 1].content);
    switch (id) {
      case OID.basicConstraints: { const c = children(value); if (c[0]?.tag === 0x01) out.ca = c[0].content[0] !== 0; if (c.at(-1)?.tag === 0x02) out.pathLen = c.at(-1).content[0]; break; }
      case OID.keyUsage: { const byte = value.content[1] ?? 0; for (let b = 0; b < 8; b++) if (byte & (0x80 >> b)) out.keyUsage.push(b); break; }
      case OID.eku: out.eku = children(value).map(readOid); break;
      case OID.san: for (const n of children(value)) { if (n.tag === 0x86) out.uris.push(n.content.toString('ascii')); if (n.tag === 0x82) out.dns.push(n.content.toString('ascii')); } break;
      case OID.ski: out.ski = value.content; break;
      case OID.aki: out.aki = children(value).find((c) => c.tag === 0x80)?.content ?? null; break;
      default: if (critical) out.unknownCritical.push(id);
    }
  }
  return out;
}
function cnOf(nameNode) {
  for (const rdn of children(nameNode)) for (const atv of children(rdn)) { const [o, v] = children(atv); if (readOid(o) === OID.cn) return v.content.toString('utf8'); }
  return '';
}
const verifyCert = (cert, issuerKey) => verifyDetached(issuerKey, cert.tbs, cert.sig);
export const fingerprintOf = (cert) => 'sha256:' + b64url(cert.keyId);

// §14.2, refusing at the first failure and naming the rule.
const refuse = (rule, reason) => ({ ok: false, rule, reason });
export function validateChain(chainDer, { now, expectedRoot, expectedEndpoint } = {}) {
  if (chainDer.length !== 2) return refuse(1, `chain of ${chainDer.length}`);
  let leaf, root;
  try { leaf = parse(chainDer[0]); root = parse(chainDer[1]); } catch (e) { return refuse(1, e.message); }
  for (const c of [leaf, root]) { if (c.unknownCritical.length) return refuse(1, 'unknown critical extension'); if (c.der.length > 4096) return refuse(1, 'certificate over 4 KiB'); }

  if (root.issuer !== root.subject || !verifyCert(root, root.publicKey)) return refuse(2, 'root is not self-signed');
  if (!root.ca || !root.keyUsage.includes(5)) return refuse(2, 'root is not a CA with keyCertSign');
  const rootFingerprint = fingerprintOf(root);
  if (expectedRoot && expectedRoot !== rootFingerprint) return refuse(2, 'root is not the one expected');

  if (!verifyCert(leaf, root.publicKey)) return refuse(3, 'leaf is not signed by the root');
  if (!leaf.aki || !leaf.aki.equals(root.keyId)) return refuse(3, 'authority key identifier is not the root');
  if (leaf.ca || !leaf.keyUsage.includes(0)) return refuse(3, 'leaf is a CA or lacks digitalSignature');

  if (now < leaf.notBefore || now > leaf.notAfter) return refuse(4, 'leaf outside its validity');
  if (leaf.notAfter - leaf.notBefore > MAX_LEAF_DAYS * DAY) return refuse(4, 'leaf longer than 398 days');

  if (leaf.uris.length !== 1) return refuse(5, `${leaf.uris.length} URIs`);
  const endpoint = leaf.uris[0];
  if (!isNormalHttps(endpoint)) return refuse(5, 'endpoint is not an https URL in normal form');
  if (expectedEndpoint && expectedEndpoint !== endpoint) return refuse(5, 'endpoint differs from the one in question');
  const host = new URL(endpoint).host;
  if (leaf.dns.some((d) => d !== host)) return refuse(5, 'dNSName differs from the URI host');

  return { ok: true, leafKey: leaf.publicKey, rootFingerprint, endpoint, leaf, root };
}

// The normal form of §14.1: what the string must already be, so nothing is normalised at comparison time.
export function isNormalHttps(s) {
  let u; try { u = new URL(s); } catch { return false; }
  if (u.protocol !== 'https:' || u.username || u.password || u.search || u.hash || s.includes('#') || s.includes('?')) return false;
  if (u.pathname === '/' || u.pathname.endsWith('/')) return false;
  return u.href === s && u.host === u.host.toLowerCase() && u.port === '';
}

// §14.3: which of two leaves under one root is current.
export function compareLeaves(pinnedDer, presentedDer) {
  const a = parse(pinnedDer), b = parse(presentedDer);
  if (b.notBefore < a.notBefore) return 'superseded';
  if (b.notBefore > a.notBefore) return 'newer';
  return a.der.equals(b.der) ? 'same' : 'conflict';
}
