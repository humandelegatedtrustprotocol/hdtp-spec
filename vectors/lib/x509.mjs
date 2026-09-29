// The §14.1 profile as bytes, the exact-profile check and §14.2 chain validation, and the §14.3 comparison.
import { createPublicKey } from 'node:crypto';
import { seq, set, explicit, implicit, octet, utf8, bool, int, bitstr, oid, time, tlv, read, children, readOid, readOidStrict, readTime, boolTrue, intMinimal, oidMinimal, namedBitsOk, ecdsaIsLowS, ecdsaTwin } from './der.mjs';
import { spkiOf, keyId, sha256, b64url, algorithmOf } from './keys.mjs';
import { signDetached, verifyDetached } from './hpke.mjs';

export const OID = {
  cn: '2.5.4.3', ed25519: '1.3.101.112', ecdsaSha256: '1.2.840.10045.4.3.2', ecPublicKey: '1.2.840.10045.2.1', prime256v1: '1.2.840.10045.3.1.7',
  basicConstraints: '2.5.29.19', keyUsage: '2.5.29.15', eku: '2.5.29.37', san: '2.5.29.17', ski: '2.5.29.14', aki: '2.5.29.35',
  serverAuth: '1.3.6.1.5.5.7.3.1', clientAuth: '1.3.6.1.5.5.7.3.2',
};
export const MAX_LEAF_DAYS = 398, MAX_CERT_BYTES = 4096;
const DAY = 86_400_000;
const FOREVER = new Date(Date.UTC(9999, 11, 31, 23, 59, 59));

const name = (cn, cnOid) => seq(set(seq(cnOid ?? oid(OID.cn), utf8(cn))));
// The ASN.1 type each profile extension's VALUE is: SEQUENCE for the four structured ones, BIT STRING
// for keyUsage, OCTET STRING for subjectKeyIdentifier (RFC 5280 §4.2.1).
const VALUE_TAG = {
  [OID.basicConstraints]: 0x30, [OID.keyUsage]: 0x03, [OID.eku]: 0x30, [OID.san]: 0x30, [OID.ski]: 0x04, [OID.aki]: 0x30,
};
const sigAlg = (alg) => seq(oid(alg === 'ed25519' ? OID.ed25519 : OID.ecdsaSha256));
const ext = (o, critical, value) => seq(oid(o), ...(critical ? [bool(true)] : []), octet(value));
function keyUsage(bits) {
  let byte = 0; for (const b of bits) byte |= 0x80 >> b;
  let unused = 0; for (let v = byte; v && !(v & 1); v >>= 1) unused++;
  return bitstr(Buffer.from([byte]), unused);
}
const serialOf = (label) => sha256(Buffer.from('serial/' + label)).subarray(0, 8);

// `basicConstraints` (DER bytes, hex) exists so the intrusion suite can build a root a wallet never
// would: the two readings of that extension only matter on a certificate that claims to be a CA.
export function buildRoot({ cn, key, notBefore, label, basicConstraints }) {
  const spki = spkiOf(key.pub), id = keyId(key.pub), alg = sigAlg(algorithmOf(key.priv));
  const tbs = seq(
    explicit(0, int(2)), int(serialOf(label)), alg, name(cn), seq(time(notBefore), time(FOREVER)), name(cn), spki,
    explicit(3, seq(
      ext(OID.basicConstraints, true, basicConstraints ? Buffer.from(basicConstraints, 'hex') : seq(bool(true), int(0))),
      ext(OID.keyUsage, true, keyUsage([5])),
      ext(OID.ski, false, octet(id)),
    )),
  );
  return seq(tbs, alg, bitstr(signDetached(key.priv, tbs)));
}

// `uris`, `cA`, `usage`, `aki`, `extra` and `algOid` exist so the intrusion suite can build what a wallet never would.
//
// `misencode` is the same idea one layer down: DER has exactly one encoding of each of these, and a
// certificate that spells one of them another way is the parser differential §14.1 exists to close.
// Every field here writes bytes an encoder never would, so the reader can be asked to refuse them:
//   criticalTrue   the criticality BOOLEAN of basicConstraints, as raw content bytes (DER: one 0xFF)
//   explicitFalse  an OID to carry an explicit `critical FALSE` (DER: a DEFAULT is not encoded)
//   keyUsage       the keyUsage BIT STRING's content, unused-count first (DER: trailing zeros removed)
//   oidFor         `{ oid, der }` — that extension's OID written as the given bytes
//   sigAlgOid      the AlgorithmIdentifier's OID, inside the TBS and outside it alike, as DER bytes
//   cnOid          the commonName attribute type's OID, as DER bytes
//   ekuOid         the serverAuth OID inside extendedKeyUsage, as DER bytes
//   spkiAlgOid     the SubjectPublicKeyInfo's AlgorithmIdentifier OID, as DER bytes; the
//                  subjectKeyIdentifier follows the bytes written, so the certificate stays
//                  self-consistent and is refused for the encoding rather than for a stale identifier
//   serial         the serialNumber INTEGER's content (DER: the shortest two's-complement form)
//   notBefore      the notBefore UTCTime's content, as ASCII (DER: a date that exists)
//   retag          `{ oid, tag }` — that extension's VALUE under another ASN.1 tag (DER: its own type)
//   basicConstraints  the basicConstraints value, as DER bytes (DER: nothing, [TRUE] or [TRUE, n])
//   sigTwin        write the ECDSA signature's OTHER twin, `(r, n − s)` — it verifies, under the same
//                  key over the same bytes, and §14.1 admits only the low-S one
export function buildLeaf({ cn, rootCn, root, hostKey, endpoint, uris, dnsName, notBefore, notAfter, label, cA = false, usage, aki, extra = [], algOid, outerAlgOid, misencode = {} }) {
  const plainSpki = spkiOf(hostKey.pub);
  const spki = misencode.spkiAlgOid
    ? seq(seq(Buffer.from(misencode.spkiAlgOid, 'hex')), children(read(plainSpki))[1].raw)
    : plainSpki;
  const id = sha256(spki), issuerId = aki ?? keyId(root.pub);
  const bits = usage ?? (algorithmOf(hostKey.pub) === 'p256' ? [0, 4] : [0]);
  const sanNames = (uris ?? [endpoint]).map((u) => implicit(6, Buffer.from(u, 'utf8')));
  if (dnsName) sanNames.push(implicit(2, Buffer.from(dnsName, 'ascii')));
  const alg = misencode.sigAlgOid ? seq(Buffer.from(misencode.sigAlgOid, 'hex')) : algOid ? seq(oid(algOid)) : sigAlg(algorithmOf(root.priv));
  const cnOid = misencode.cnOid ? Buffer.from(misencode.cnOid, 'hex') : undefined;
  const extOid = (o) => (misencode.oidFor?.oid === o ? Buffer.from(misencode.oidFor.der, 'hex') : oid(o));
  const flag = (o, critical) => {
    if (critical) return [o === OID.basicConstraints && misencode.criticalTrue ? tlv(0x01, Buffer.from(misencode.criticalTrue)) : bool(true)];
    return misencode.explicitFalse === o ? [bool(false)] : [];
  };
  const retagged = (o, value) => (misencode.retag?.oid === o ? Buffer.concat([Buffer.from([misencode.retag.tag]), value.subarray(1)]) : value);
  const xt = (o, critical, value) => seq(extOid(o), ...flag(o, critical), octet(retagged(o, value)));
  const tbs = seq(
    explicit(0, int(2)), misencode.serial ? tlv(0x02, Buffer.from(misencode.serial)) : int(serialOf(label)),
    alg, name(rootCn, cnOid), seq(misencode.notBefore ? tlv(0x17, Buffer.from(misencode.notBefore, 'ascii')) : time(notBefore), time(notAfter)), name(cn, cnOid), spki,
    explicit(3, seq(
      xt(OID.basicConstraints, true, misencode.basicConstraints ? Buffer.from(misencode.basicConstraints, 'hex') : cA ? seq(bool(true)) : seq()),
      xt(OID.keyUsage, true, misencode.keyUsage ? tlv(0x03, Buffer.from(misencode.keyUsage)) : keyUsage(bits)),
      xt(OID.eku, false, seq(misencode.ekuOid ? Buffer.from(misencode.ekuOid, 'hex') : oid(OID.serverAuth), oid(OID.clientAuth))),
      xt(OID.san, false, seq(...sanNames)),
      xt(OID.ski, false, octet(id)),
      xt(OID.aki, false, seq(implicit(0, issuerId))),
      ...extra.map((e) => ext(e.oid, e.critical, e.value)),
    )),
  );
  // `outerAlgOid` writes a different AlgorithmIdentifier outside the TBS than inside — what one
  // parser reads one way and another the other, which RFC 5280 §4.1.1.2 forbids and parse() refuses.
  const signature = signDetached(root.priv, tbs);
  return seq(tbs, outerAlgOid ? seq(oid(outerAlgOid)) : alg, bitstr(misencode.sigTwin ? ecdsaTwin(signature) : signature));
}

// Reading a certificate back into the fields the rules need. Throws on anything malformed.
export function parse(der) {
  const cert = read(der);
  if (cert.tag !== 0x30 || cert.end !== der.length) throw new Error('not one SEQUENCE');
  const [tbs, alg, sig, ...more] = children(cert);
  if (more.length || !tbs || !alg || !sig || sig.tag !== 0x03 || sig.content[0] !== 0) throw new Error('certificate shape');
  const f = children(tbs);
  if (f.length !== 8 || f[0].tag !== 0xa0 || children(f[0])[0].content[0] !== 2 || f[7].tag !== 0xa3) throw new Error('not a v3 certificate with extensions');
  // RFC 5280 §4.1.1.2: the algorithm inside the TBS and the one outside are the same field twice.
  if (!f[2].raw.equals(alg.raw) || children(alg).length !== 1) throw new Error('signature algorithm inside and outside differ');
  if (!intMinimal(f[1].content)) throw new Error('INTEGER not minimal');
  const [notBefore, notAfter] = children(f[4]);
  const out = {
    der, tbs: tbs.raw, sigAlg: readOidStrict(children(alg)[0]), sig: sig.content.subarray(1),
    serial: f[1].content, issuer: nameOf(f[3]), subject: nameOf(f[5]),
    notBefore: readTime(notBefore), notAfter: readTime(notAfter), timeTags: [notBefore.tag, notAfter.tag],
    spki: f[6].raw, extensions: [], ca: false, pathLen: null, keyUsage: [], eku: [], uris: [], dns: [], otherNames: 0, ski: null, aki: null, akiExtra: false,
  };
  // The SubjectPublicKeyInfo's AlgorithmIdentifier is an OID like any other, and the one that matters
  // most: the fingerprint of §2 is SHA-256 over these bytes, so a second encoding of the OID is a
  // second fingerprint for one key. Checked here rather than left to whatever the platform's key
  // reader happens to refuse, so the rule is the profile's and not OpenSSL's.
  const algorithm = children(children(read(out.spki))[0]);
  for (const part of algorithm) if (part.tag === 0x06) readOidStrict(part);
  // And the key is one of the profile's two (§14.1): Ed25519 with no parameters (RFC 8410), or P-256.
  // Any other is refused here, where it is read, named by its OID, as both ports refuse it. OpenSSL
  // reads an RSA, P-384 or X25519 key, so a certificate carrying one was parsed here — compared by
  // compareLeaves, taken on a card by decodeCard — and refused only at the profile, while an Ed25519
  // key with a NULL after its OID was refused in OpenSSL's words (the port-parity audit, R12, T2).
  const [algOid, param] = algorithm.map((x) => (x.tag === 0x06 ? readOid(x) : null));
  const inProfile = (algOid === OID.ed25519 && algorithm.length === 1) || (algOid === OID.ecPublicKey && algorithm.length === 2 && param === OID.prime256v1);
  if (algOid && !inProfile) throw new Error(`unsupported key type ${algOid}`);
  // An Ed25519 key is 32 bytes that decode to a point; OpenSSL reads any 32, so a certificate whose key
  // decodes to none was a certificate here, and its chain validated, while both ports refuse it.
  if (algOid === OID.ed25519) {
    const key = children(read(out.spki))[1].content.subarray(1);
    if (key.length !== 32) throw new Error('Ed25519 key is not 32 bytes');
    if (!ed25519IsPoint(key)) throw new Error('Ed25519 key is not a point');
  }
  out.publicKey = createPublicKey({ key: out.spki, format: 'der', type: 'spki' });
  out.keyId = sha256(out.spki);
  for (const e of children(children(f[7])[0])) {
    const parts = children(e);
    if (parts.length < 2 || parts.length > 3) throw new Error('extension shape');
    // Criticality is a DEFAULT FALSE: present means critical, and the only encoding of that is one
    // 0xFF byte. An explicit FALSE and a TRUE spelled 0x01 are both second ways to say what DER
    // already says one way.
    const critical = parts.length === 3;
    if (critical && !boolTrue(parts[1])) throw new Error('BOOLEAN not in the DER form');
    const id = readOidStrict(parts[0]);
    const octets = parts[parts.length - 1].content;
    const value = read(octets);
    // The value fills its OCTET STRING, and is the TYPE its extension names. Neither was checked
    // here, in the library CONTRACT §0 calls the authority, while both ports refused a trailing byte
    // — and none of the three looked at the value's own tag, so a `keyUsage` that is an OCTET STRING
    // whose body happens to look like a BIT STRING's was read as one, a `subjectKeyIdentifier` took
    // its 32 bytes from anything, and a `subjectAltName` could be a SET. §14.1's profile is exact:
    // "a name of another shape" is not a PACT certificate, and neither is a value of another type.
    if (value.end !== octets.length) throw new Error('extension value has trailing bytes');
    if (VALUE_TAG[id] !== undefined && value.tag !== VALUE_TAG[id]) throw new Error('extension value of another type');
    out.extensions.push({ id, critical });
    switch (id) {
      case OID.basicConstraints: {
        // BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER OPTIONAL },
        // which in DER is exactly one of: nothing, [TRUE], [TRUE, n]. This read `c[0]` and `c.at(-1)`,
        // so `SEQUENCE { NULL }` was a valid leaf, and `SEQUENCE { TRUE, 5, 0 }` was a root whose
        // pathLen is 0 here and 5 to every other X.509 reader — the two-readings case §14.1 exists for.
        const c = children(value);
        const shape = c.map((x) => x.tag).join(',');
        if (!['', '1', '1,2'].includes(shape)) throw new Error('basicConstraints not in the DER form');
        if (c[0]) { if (!boolTrue(c[0])) throw new Error('BOOLEAN not in the DER form'); out.ca = true; }
        if (c[1]) {
          if (!intMinimal(c[1].content) || c[1].content.length > 8) throw new Error('INTEGER not minimal');
          // The WHOLE integer. This read `content[0]`, so a pathLenConstraint of 128 — `02 02 00 80` —
          // read as 0, and a root carrying it was in the profile here while both ports refused it.
          out.pathLen = c[1].content.length === 0 ? -1 : Number(c[1].content.reduce((acc, b) => (acc << 8n) | BigInt(b), 0n));
        }
        break;
      }
      case OID.keyUsage: {
        // Every named bit of every byte counts, so a second byte — decipherOnly — is seen rather
        // than dropped, and the profile can then refuse it.
        if (!namedBitsOk(value.content)) throw new Error('BIT STRING not in the DER form');
        const unused = value.content[0] ?? 0, bits = value.content.subarray(1);
        const total = bits.length * 8 - unused;
        for (let b = 0; b < total; b++) if (bits[b >> 3] & (0x80 >> (b & 7))) out.keyUsage.push(b);
        break;
      }
      case OID.eku: out.eku = children(value).map(readOidStrict); break;
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
  if (readOidStrict(o) !== OID.cn || v.tag !== 0x0c) throw new Error('name is not a UTF-8 commonName');
  return v.content.toString('utf8');
}

// Whether 32 bytes encode an Ed25519 point (RFC 8032 §5.1.3, decoding only): x² = (y² − 1)/(d·y² + 1)
// has a root. The high bit is the sign of x and y is read mod p, as both ports' libraries read it
// (ed25519-dalek's decompress, filippo.io/edwards25519's SetBytes), so a non-canonical spelling of a
// point is a point here too; a point of small order is a point.
const P25519 = (1n << 255n) - 19n;
const powP = (b, e) => { let r = 1n; b %= P25519; for (; e > 0n; e >>= 1n, b = (b * b) % P25519) if (e & 1n) r = (r * b) % P25519; return r; };
const D25519 = ((P25519 - 121665n) * powP(121666n, P25519 - 2n)) % P25519;
function ed25519IsPoint(bytes) {
  let y = 0n;
  for (let i = 31; i >= 0; i--) y = (y << 8n) | BigInt(bytes[i]);
  y = (y & ((1n << 255n) - 1n)) % P25519;
  const yy = (y * y) % P25519;
  const xx = (((yy - 1n + P25519) % P25519) * powP((D25519 * yy + 1n) % P25519, P25519 - 2n)) % P25519;
  return xx === 0n || powP(xx, (P25519 - 1n) / 2n) === 1n;
}

// §14.1 exactly: every field, every extension and its criticality, nothing else.
const same = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
export function profileError(c, kind) {
  if (c.der.length > MAX_CERT_BYTES) return 'over 4 KiB';
  if (c.serial.length < 8 || c.serial.length > 20 || c.serial[0] & 0x80) return 'serial not 64–160 bits positive';
  if (![OID.ed25519, OID.ecdsaSha256].includes(c.sigAlg)) return 'signature algorithm not in the profile';
  // §14.1: of an ECDSA signature's two twins, only the low-S one is a PACT certificate (der.mjs).
  // Judged only where the bits ARE an ECDSA value. A certificate that declares ECDSA over bytes that
  // are not one — an Ed25519 root's signature under the wrong label — is not a profile matter: it
  // cannot verify under any key, so rule 3 refuses it as "a certificate the key did not sign", which
  // is what §14.1's first sentence says a mismatch is. Refusing it here first would have moved that
  // refusal to rule 1 and told the caller something else.
  if (c.sigAlg === OID.ecdsaSha256) {
    let low = true;
    try { low = ecdsaIsLowS(c.sig); } catch { /* not an ECDSA value at all: rule 3's to refuse */ }
    if (!low) return 'ECDSA signature not in the low-S form';
  }
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
  // A key identifier is the 32-byte SHA-256 of a SubjectPublicKeyInfo (§14.1). The subject one is held
  // to that above; this one was only asked to be THERE, so a leaf could name its issuer in three bytes
  // — and a card would show those three bytes to a person as the identity to pin.
  if (crit(OID.aki) !== false || c.aki?.length !== 32 || c.akiExtra) return 'leaf authorityKeyIdentifier is not a key identifier alone';
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
  if (u.href !== s || u.host !== u.host.toLowerCase() || u.port === '0') return false; // the default port is omitted, so an explicit :443 fails href === s; port 0 is no port
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
