// The §14.1 profile as bytes, the exact-profile check and §14.2 chain validation, and the §14.3 comparison.
import { createPublicKey } from 'node:crypto';
import { seq, set, explicit, implicit, octet, utf8, bool, int, bitstr, oid, time, read, children, readOid, readTime } from './der.mjs';
import { spkiOf, keyId, sha256, b64url, algorithmOf } from './keys.mjs';
import { signDetached, verifyDetached } from './hpke.mjs';

export const OID = {
  cn: '2.5.4.3', ed25519: '1.3.101.112', ecdsaSha256: '1.2.840.10045.4.3.2',
  basicConstraints: '2.5.29.19', keyUsage: '2.5.29.15', eku: '2.5.29.37', san: '2.5.29.17', ski: '2.5.29.14', aki: '2.5.29.35',
  serverAuth: '1.3.6.1.5.5.7.3.1', clientAuth: '1.3.6.1.5.5.7.3.2',
};
export const MAX_LEAF_DAYS = 398, MAX_CERT_BYTES = 4096;
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

export function buildRoot({ cn, key, notBefore, label }) {
  const spki = spkiOf(key.pub), id = keyId(key.pub), alg = sigAlg(algorithmOf(key.priv));
  const tbs = seq(
    explicit(0, int(2)), int(serialOf(label)), alg, name(cn), seq(time(notBefore), time(FOREVER)), name(cn), spki,
    explicit(3, seq(
      ext(OID.basicConstraints, true, seq(bool(true), int(0))),
      ext(OID.keyUsage, true, keyUsage([5])),
      ext(OID.ski, false, octet(id)),
    )),
  );
  return seq(tbs, alg, bitstr(signDetached(key.priv, tbs)));
}

// `uris`, `cA`, `usage`, `aki`, `extra` and `algOid` exist so the intrusion suite can build what a wallet never would.
export function buildLeaf({ cn, rootCn, root, hostKey, endpoint, uris, dnsName, notBefore, notAfter, label, cA = false, usage, aki, extra = [], algOid }) {
  const spki = spkiOf(hostKey.pub), id = keyId(hostKey.pub), issuerId = aki ?? keyId(root.pub);
  const bits = usage ?? (algorithmOf(hostKey.pub) === 'p256' ? [0, 4] : [0]);
  const sanNames = (uris ?? [endpoint]).map((u) => implicit(6, Buffer.from(u, 'utf8')));
  if (dnsName) sanNames.push(implicit(2, Buffer.from(dnsName, 'ascii')));
  const alg = algOid ? seq(oid(algOid)) : sigAlg(algorithmOf(root.priv));
  const tbs = seq(
    explicit(0, int(2)), int(serialOf(label)), alg, name(rootCn), seq(time(notBefore), time(notAfter)), name(cn), spki,
    explicit(3, seq(
      ext(OID.basicConstraints, true, cA ? seq(bool(true)) : seq()),
      ext(OID.keyUsage, true, keyUsage(bits)),
      ext(OID.eku, false, seq(oid(OID.serverAuth), oid(OID.clientAuth))),
      ext(OID.san, false, seq(...sanNames)),
      ext(OID.ski, false, octet(id)),
      ext(OID.aki, false, seq(implicit(0, issuerId))),
      ...extra.map((e) => ext(e.oid, e.critical, e.value)),
    )),
  );
  return seq(tbs, alg, bitstr(signDetached(root.priv, tbs)));
}

// Reading a certificate back into the fields the rules need. Throws on anything malformed.
export function parse(der) {
  const cert = read(der);
  if (cert.tag !== 0x30 || cert.end !== der.length) throw new Error('not one SEQUENCE');
  const [tbs, alg, sig, ...more] = children(cert);
  if (more.length || !tbs || !alg || !sig || sig.tag !== 0x03 || sig.content[0] !== 0) throw new Error('certificate shape');
  const f = children(tbs);
  if (f.length !== 8 || f[0].tag !== 0xa0 || children(f[0])[0].content[0] !== 2 || f[7].tag !== 0xa3) throw new Error('not a v3 certificate with extensions');
  const [notBefore, notAfter] = children(f[4]);
  const out = {
    der, tbs: tbs.raw, sigAlg: readOid(children(alg)[0]), sig: sig.content.subarray(1),
    serial: f[1].content, issuer: nameOf(f[3]), subject: nameOf(f[5]),
    notBefore: readTime(notBefore), notAfter: readTime(notAfter), timeTags: [notBefore.tag, notAfter.tag],
    spki: f[6].raw, extensions: [], ca: false, pathLen: null, keyUsage: [], eku: [], uris: [], dns: [], otherNames: 0, ski: null, aki: null, akiExtra: false,
  };
  out.publicKey = createPublicKey({ key: out.spki, format: 'der', type: 'spki' });
  out.keyId = sha256(out.spki);
  for (const e of children(children(f[7])[0])) {
    const parts = children(e);
    const id = readOid(parts[0]), critical = parts.length === 3 && parts[1].content[0] !== 0;
    const value = read(parts[parts.length - 1].content);
    out.extensions.push({ id, critical });
    switch (id) {
      case OID.basicConstraints: { const c = children(value); if (c[0]?.tag === 0x01) out.ca = c[0].content[0] !== 0; if (c.at(-1)?.tag === 0x02) out.pathLen = c.at(-1).content[0]; break; }
      case OID.keyUsage: { const byte = value.content[1] ?? 0; for (let b = 0; b < 8; b++) if (byte & (0x80 >> b)) out.keyUsage.push(b); break; }
      case OID.eku: out.eku = children(value).map(readOid); break;
      case OID.san: for (const n of children(value)) { if (n.tag === 0x86) out.uris.push(n.content.toString('utf8')); else if (n.tag === 0x82) out.dns.push(n.content.toString('ascii')); else out.otherNames++; } break;
      case OID.ski: out.ski = value.content; break;
      case OID.aki: { const c = children(value); out.aki = c.find((x) => x.tag === 0x80)?.content ?? null; out.akiExtra = c.length !== 1; break; }
      default: break;
    }
  }
  return out;
}
function nameOf(node) {
  const rdns = children(node);
  if (rdns.length !== 1) throw new Error('name is not one RDN');
  const atvs = children(rdns[0]);
  if (atvs.length !== 1) throw new Error('RDN is not one attribute');
  const [o, v] = children(atvs[0]);
  if (readOid(o) !== OID.cn || v.tag !== 0x0c) throw new Error('name is not a UTF-8 commonName');
  return v.content.toString('utf8');
}

// §14.1 exactly: every field, every extension and its criticality, nothing else.
const same = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
export function profileError(c, kind) {
  if (c.der.length > MAX_CERT_BYTES) return 'over 4 KiB';
  if (c.serial.length < 8 || c.serial.length > 20 || c.serial[0] & 0x80) return 'serial not 64–160 bits positive';
  if (![OID.ed25519, OID.ecdsaSha256].includes(c.sigAlg)) return 'signature algorithm not in the profile';
  try { algorithmOf(c.publicKey); } catch { return 'key algorithm not in the profile'; }
  const tagFor = (d) => (d.getUTCFullYear() < 2050 ? 0x17 : 0x18);
  if (c.timeTags[0] !== tagFor(c.notBefore) || c.timeTags[1] !== tagFor(c.notAfter)) return 'time encoding not per RFC 5280';
  if (!c.ski || !c.ski.equals(c.keyId)) return 'subject key identifier is not the key';
  const ids = c.extensions.map((e) => e.id);
  if (new Set(ids).size !== ids.length) return 'duplicate extension';
  const crit = (id) => c.extensions.find((e) => e.id === id)?.critical;
  if (kind === 'root') {
    if (!same([...ids].sort(), [OID.basicConstraints, OID.keyUsage, OID.ski].sort())) return 'root extensions are not exactly the profile';
    if (crit(OID.basicConstraints) !== true || !c.ca || c.pathLen !== 0) return 'root basicConstraints';
    if (crit(OID.keyUsage) !== true || !same(c.keyUsage, [5])) return 'root keyUsage is not keyCertSign alone';
    if (crit(OID.ski) !== false || c.issuer !== c.subject) return 'root identity';
    if (c.notAfter.getTime() !== FOREVER.getTime()) return 'root notAfter is not 9999-12-31';
    return null;
  }
  if (!same([...ids].sort(), [OID.basicConstraints, OID.keyUsage, OID.eku, OID.san, OID.ski, OID.aki].sort())) return 'leaf extensions are not exactly the profile';
  if (crit(OID.basicConstraints) !== true || c.ca || c.pathLen !== null) return 'leaf basicConstraints';
  const expectedUsage = algorithmOf(c.publicKey) === 'p256' ? [0, 4] : [0];
  if (crit(OID.keyUsage) !== true || !same(c.keyUsage, expectedUsage)) return 'leaf keyUsage';
  if (crit(OID.eku) !== false || !same([...c.eku].sort(), [OID.serverAuth, OID.clientAuth].sort())) return 'leaf extendedKeyUsage';
  if (crit(OID.san) !== false || c.otherNames || c.dns.length > 1) return 'leaf subjectAltName carries a name type the profile does not';
  if (crit(OID.aki) !== false || !c.aki || c.akiExtra) return 'leaf authorityKeyIdentifier is not a key identifier alone';
  return null;
}

// The signature algorithm the certificate declares must be the issuer key's own; a verifier never
// picks the algorithm from the certificate, so a mismatch is simply a certificate the key did not sign.
const verifyCert = (cert, issuerKey) => cert.sigAlg === (algorithmOf(issuerKey) === 'ed25519' ? OID.ed25519 : OID.ecdsaSha256) && verifyDetached(issuerKey, cert.tbs, cert.sig);
export const fingerprintOf = (cert) => 'sha256:' + b64url(cert.keyId);

// §14.2, refusing at the first failure and naming the rule.
const refuse = (rule, reason) => ({ ok: false, rule, reason });
export function validateChain(chainDer, { now, expectedRoot, expectedEndpoint } = {}) {
  if (chainDer.length !== 2) return refuse(1, `chain of ${chainDer.length}`);
  let leaf, root;
  try { leaf = parse(chainDer[0]); root = parse(chainDer[1]); } catch (e) { return refuse(1, e.message); }
  const bad = profileError(leaf, 'leaf') ?? profileError(root, 'root');
  if (bad) return refuse(1, bad);

  if (!verifyCert(root, root.publicKey)) return refuse(2, 'root is not self-signed');
  const rootFingerprint = fingerprintOf(root);
  if (expectedRoot && expectedRoot !== rootFingerprint) return refuse(2, 'root is not the one expected');

  if (!verifyCert(leaf, root.publicKey)) return refuse(3, 'leaf is not signed by the root');
  if (!leaf.aki.equals(root.keyId)) return refuse(3, 'authority key identifier is not the root');

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
  if (u.href !== s || u.host !== u.host.toLowerCase() || u.port !== '') return false;
  // The path in RFC 3986 normal form: pchar only, no dot segments, percent-encoding uppercase and
  // never for an unreserved character — so two strings for one address cannot both be "normal".
  const path = s.slice(s.indexOf('/', 8));
  if (!/^(\/(?:[A-Za-z0-9\-._~!$&'()*+,;=:@]|%[0-9A-F]{2})*)+$/.test(path)) return false;
  if (path.split('/').some((seg) => seg === '.' || seg === '..')) return false;
  return !/%(2[DE]|5F|7E|3[0-9]|[46][1-9A-F]|[57][0-9A])/.test(path);
}

// §14.3: which of two leaves under one root is current. A later notBefore wins the instant it is seen,
// whatever the validity of the older leaf.
export function compareLeaves(pinnedDer, presentedDer) {
  const a = parse(pinnedDer), b = parse(presentedDer);
  if (b.notBefore < a.notBefore) return 'superseded';
  if (b.notBefore > a.notBefore) return 'newer';
  return a.der.equals(b.der) ? 'same' : 'conflict';
}
