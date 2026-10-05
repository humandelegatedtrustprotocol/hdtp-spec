// Proves Appendix B: checks every vector does what the spec says.
// Reads the vectors from the specification itself (site/spec-source.mjs: the newest released
// version), so the bytes in the document are the bytes proven.
import { readFileSync, existsSync } from 'node:fs';
import { createPrivateKey, createPublicKey, X509Certificate } from 'node:crypto';
import { open, verifyDetached, suiteForLeaf, suiteForKey, sealDeterministic, signDetached } from './lib/hpke.mjs';
import { validateChain, compareLeaves, parse, profileError, buildRoot, buildLeaf, fingerprintOf, OID } from './lib/x509.mjs';
import { fingerprint, fromB64url, b64url, sha256, PRF_SALT, deriveSeed, ed25519FromSeed, p256FromSeed, spkiOf, seed, p256Uncompressed, strictB64url } from './lib/keys.mjs';
import { decodeCard } from './lib/card.mjs';
import { canonical } from './lib/canonical.mjs';
import { makeNode, pin, receive } from './lib/envelope.mjs';
import { appendixB } from './lib/appendix.mjs';
import { ARTICLE, stated } from './lib/stated.mjs';
import { execFileSync } from 'node:child_process';
import { splitSpec } from '../site/markdown.mjs';
import { readSpec, root, current } from '../site/spec-source.mjs';
import { licence } from '../site/licence.mjs';

const spec = readSpec();
const blocks = appendixB(spec).blocks.map((b) => b.value);
if (blocks.length < 1) throw new Error('Appendix B has no vector blocks');
const [vec] = blocks;
// The HPKE info string is the one the TEXT states (§13.1), read out of its sentence: the envelopes
// below open under what the document says, not under a second copy of the label written here.
const INFO = Buffer.from(stated(spec).info[0] ?? '');

let failures = 0, checks = 0;
const ok = (cond, what) => { checks++; if (!cond) { failures++; console.log('  FAIL ' + what); } };

if (!vec) {
  console.log('no vector block in Appendix B');
} else {
  const file = new URL('./hdtp-1.0-vectors.json', import.meta.url);
  if (existsSync(file)) {
    const generated = JSON.stringify(JSON.parse(readFileSync(file, 'utf8')));
    ok(generated === JSON.stringify(vec), `${current()} carries the generated vectors unchanged`);
    // The draft is written from the release and carries the same Appendix B until a change to the
    // wire regenerates it (vectors/gen.mjs splices into both).
    if (existsSync(new URL('../docs/specification/draft/index.md', import.meta.url))) {
      ok(JSON.stringify(appendixB(readSpec(root, 'draft')).blocks[0]?.value) === generated, 'the draft carries the generated vectors unchanged');
    }
  }
  const der = Object.fromEntries(Object.entries(vec.certificates).map(([k, c]) => [k, Buffer.from(c.der_hex, 'hex')]));
  const chainOf = (names) => names.map((n) => der[n]);

  console.log('certificates parse under OpenSSL as well');
  for (const [name, bytes] of Object.entries(der)) {
    // A certificate marked `refused` exists to be refused (§14.1): it must NOT come out of parse and
    // the profile check clean. `leaf_b_twin` is the instructive one — OpenSSL verifies it under
    // root_b, because the twin of an ECDSA signature is a valid signature; the profile is what refuses.
    if (vec.certificates[name].refused) {
      let why = null;
      try { why = profileError(parse(bytes), name.startsWith('root') ? 'root' : 'leaf'); } catch (e) { why = e.message; }
      ok(why !== null, `${name}: marked refused, and parse + profile let it through`);
      if (name === 'leaf_b_twin') ok(new X509Certificate(bytes).verify(new X509Certificate(der.root_b).publicKey), `${name}: the twin VERIFIES under root_b per OpenSSL, which is why the profile has to refuse it`);
      continue;
    }
    const c = new X509Certificate(bytes), mine = parse(bytes);
    ok(c.subject.includes(mine.subject), `${name}: subject`);
    ok(c.ca === mine.ca, `${name}: cA`);
    if (mine.uris.length) ok(c.subjectAltName.includes('URI:' + mine.uris[0]), `${name}: subjectAltName`);
    ok(Math.abs(c.validFromDate - mine.notBefore) < 1000, `${name}: notBefore`);
    ok(Math.abs(c.validToDate - mine.notAfter) < 1000, `${name}: notAfter`);
    if (name.startsWith('leaf_a')) ok(c.checkIssued(new X509Certificate(der.root_a)) && c.verify(new X509Certificate(der.root_a).publicKey), `${name}: issued and verified by root_a per OpenSSL`);
    if (name.startsWith('leaf_c')) ok(c.checkIssued(new X509Certificate(der.root_c)) && c.verify(new X509Certificate(der.root_c).publicKey), `${name}: issued and verified by root_c per OpenSSL`);
    if (name === 'leaf_b') ok(c.checkIssued(new X509Certificate(der.root_b)) && c.verify(new X509Certificate(der.root_b).publicKey), `${name}: issued and verified by root_b per OpenSSL`);
    ok(bytes.length <= 4096, `${name}: under 4 KiB`);
  }

  console.log('chain cases (§14.2)');
  for (const c of vec.chain_cases) {
    const r = validateChain(chainOf(c.chain), { now: new Date(c.now), expectedRoot: c.expected_root, expectedEndpoint: c.expected_endpoint });
    if (c.expect === 'accept') ok(r.ok, `${c.name}: expected accept, got rule ${r.rule} (${r.reason})`);
    else ok(!r.ok && r.rule === c.rule, `${c.name}: expected refusal by rule ${c.rule}, got ${r.ok ? 'accept' : 'rule ' + r.rule + ' (' + r.reason + ')'}`);
    // A case that names its reason is held to it: rule 4 refuses for four reasons, and a guard that
    // went missing would still refuse by rule 4 for another one.
    if (c.reason) ok(!r.ok && r.reason === c.reason, `${c.name}: expected the reason "${c.reason}", got ${r.ok ? 'accept' : '"' + r.reason + '"'}`);
    console.log(`  ${c.name}: ${r.ok ? 'accepted' : 'refused by rule ' + r.rule}`);
  }

  console.log('newest leaf (§14.3)');
  for (const c of vec.newest_leaf_cases) {
    const got = compareLeaves(der[c.pinned], der[c.presented]);
    ok(got === c.expect, `${c.pinned} vs ${c.presented}: expected ${c.expect}, got ${got}`);
    console.log(`  ${c.pinned} then ${c.presented}: ${got}`);
  }

  console.log('certificate_renewed (§14.4)');
  for (const c of vec.certificate_renewed_cases) {
    const chain = c.answer.data.chain.map(fromB64url);
    const pinned = parse(der[c.pinned_leaf]);
    const r = validateChain(chain, { now: new Date(c.now), expectedRoot: 'sha256:' + Buffer.from(pinned.aki).toString('base64url'), expectedEndpoint: c.dialed });
    const follow = r.ok && ['newer', 'same'].includes(compareLeaves(der[c.pinned_leaf], chain[0]));
    ok(follow === (c.expect === 'follow'), `${c.name}: expected ${c.expect}`);
    console.log(`  ${c.name}: ${follow ? 'followed' : 'discarded'}${r.ok ? '' : ' (rule ' + r.rule + ')'}`);
  }

  console.log('v: 1 envelopes (§13)');
  for (const v of vec.envelopes) {
    const recipientLeaf = parse(der[v.recipient_chain[0]]);
    const recipientPriv = createPrivateKey({ key: Buffer.from(vec.leaf_keys_pkcs8_hex[v.recipient_chain[0]], 'hex'), format: 'der', type: 'pkcs8' });
    const aad = fromB64url(v.protected), enc = fromB64url(v.enc), ct = fromB64url(v.ct);
    const header = JSON.parse(aad.toString());
    ok(Object.keys(header).sort().join(',') === 'cty,exp,kid,msg_id,suite,ts,v', `${v.name}: header members`);
    ok(header.v === 1 && header.suite === v.suite && header.suite === suiteForLeaf(recipientLeaf), `${v.name}: version and suite`);
    ok(header.kid === fingerprint(recipientLeaf.publicKey), `${v.name}: kid is the recipient leaf key`);
    ok(createPublicKey(recipientPriv).export({ format: 'der', type: 'spki' }).equals(recipientLeaf.spki), `${v.name}: the recipient key is the leaf's`);
    let plaintext = null;
    try { plaintext = open(v.suite, recipientPriv, recipientLeaf.publicKey, INFO, aad, enc, ct); } catch (e) { ok(false, `${v.name}: open threw ${e.message}`); }
    ok(plaintext && plaintext.toString('hex') === v.plaintext_hex, `${v.name}: plaintext`);
    if (plaintext) {
      const body = JSON.parse(plaintext.toString());
      const senderLeaf = parse(der[v.sender_chain[0]]);
      if (v.form === 'leaf') {
        ok(Object.keys(body).sort().join(',') === 'leaf,method,params', `${v.name}: small form carries leaf, method, params`);
        ok(body.leaf === fingerprint(senderLeaf.publicKey), `${v.name}: leaf names the sender's held leaf`);
        ok(verifyDetached(senderLeaf.publicKey, Buffer.concat([aad, enc, ct]), fromB64url(v.sig)), `${v.name}: signature under the held leaf's key`);
        ok(ct.length < 400, `${v.name}: small form stays small (${ct.length} bytes sealed)`);
      } else {
        ok(Object.keys(body).sort().join(',') === 'chain,method,params', `${v.name}: full form carries chain, method, params`);
        const chain = body.chain.map(fromB64url);
        const r = validateChain(chain, { now: new Date(vec.now) });
        ok(r.ok, `${v.name}: chain inside validates`);
        ok(r.ok && chain[0].equals(der[v.sender_chain[0]]), `${v.name}: chain inside is the sender's`);
        ok(r.ok && verifyDetached(r.leafKey, Buffer.concat([aad, enc, ct]), fromB64url(v.sig)), `${v.name}: signature under the chain's leaf key`);
      }
    }
    console.log(`  ${v.name}: ${plaintext ? 'opened' : 'closed'}${v.form === 'leaf' ? ' (by reference)' : ''}`);
  }

  // §2.1. Recomputed from the published `prf` alone, so what passes here is what a third
  // implementation reading Appendix B would have to reproduce — not what the generator happened
  // to write.
  console.log('derivation (§2.1)');
  const seeds = new Map();
  for (const d of vec.derivation ?? []) {
    ok(d.salt === b64url(PRF_SALT), `${d.label}: salt is SHA-256("hdtp/vault/1")`);
    const s = deriveSeed(fromB64url(d.prf), d.info);
    ok(b64url(s) === d.seed, `${d.label}: HKDF-SHA256(prf, empty salt, "${d.info}", 32)`);
    ok(s.length === 32, `${d.label}: 32 bytes`);
    if (d.alg) {
      ok(d.alg === 'ed25519', `${d.label}: a derived root is Ed25519`);
      const key = ed25519FromSeed(s);
      ok(b64url(spkiOf(key.pub)) === d.spki, `${d.label}: the key the seed makes`);
      ok(fingerprint(key.pub) === d.fingerprint, `${d.label}: the identity that key is`);
    }
    // The property the three `info` strings exist for: one credential, three unrelated secrets.
    // A port that dropped `info` from the expand step would pass every check above and fail here.
    ok(!seeds.has(d.seed), `${d.label}: a different info gives a different seed`);
    seeds.set(d.seed, d.info);
    console.log(`  ${d.label} (${d.info}): ${d.fingerprint ?? 'seed only'}`);
  }
  ok((vec.derivation ?? []).length >= 3, 'all three info strings are covered');

  // §3. The signed card, verified as a receiver verifies one: its certificate is the leaf it names, and
  // card_sig verifies under that leaf's key over the card text's UTF-8 bytes as written here. The
  // control: the same card with one character changed must not verify.
  console.log('a signed card (§3)');
  const sc = vec.signed_card;
  ok(sc && typeof sc.card === 'string' && typeof sc.card_sig === 'string', 'Appendix B carries a signed card');
  if (sc) {
    const decoded = decodeCard(sc.card);
    ok(!decoded.error && Buffer.from(decoded.cert).equals(der[sc.leaf]), `the card's X-HDTP-CERT is ${sc.leaf}`);
    ok(strictB64url(sc.card_sig) !== null && b64url(strictB64url(sc.card_sig)) === sc.card_sig, 'card_sig is base64url without padding, in its one spelling');
    const leafKey = new X509Certificate(der[sc.leaf]).publicKey;
    const sig = fromB64url(sc.card_sig);
    ok(verifyDetached(leafKey, Buffer.from(sc.card, 'utf8'), sig), 'card_sig verifies under the leaf key over the card\'s UTF-8 bytes');
    ok(!verifyDetached(leafKey, Buffer.from(sc.card.replace('Alina', 'Alinb'), 'utf8'), sig), 'and not over a card with one character changed (the control)');
    ok(sc.card.endsWith('\r\n') && !/[^\r]\n/.test(sc.card), 'the card\'s lines end in CRLF');
  }
}

// The receiving node reads a header and a body as JSON exactly when every port does
// (hdtp-identity CONTRACT §0): bytes that are not UTF-8, a \u escape of half a surrogate pair, a
// number that is infinite as a double (`1e400`) or containers nested more than 127 deep is not JSON. JSON.parse read 1e400 as Infinity, and the node decided `ok` on a
// validly signed call whose body held one, where both ports refuse it. The body and header are
// written as text, because JSON.stringify writes 1e400 as null; the controls hold the largest double
// and 127 deep, and are decided. A header's integers likewise: the ports read `-0`, `1757764800.0`
// and a number past 64 bits as no integer, and this node read the first two as integers and refused a
// ts past 2^53 that the ports read and judged by its time.
console.log('JSON as the ports read it (§13.1, §13.3)');
{
  const at = (iso) => new Date(iso), now = at('2026-09-13T12:00:00Z'), nowS = Math.floor(now / 1000);
  const key = (label) => ed25519FromSeed(seed('check/json/' + label));
  const rootA = key('root/a'), hostA = key('host/a'), rootB = key('root/b'), hostB = key('host/b');
  const whole = { notBefore: at('2026-09-01T00:00:00Z'), notAfter: at('2027-09-01T00:00:00Z') };
  const ROOT_A = buildRoot({ cn: 'A', key: rootA, notBefore: whole.notBefore, label: 'check/json/root/a' });
  const ROOT_B = buildRoot({ cn: 'B', key: rootB, notBefore: whole.notBefore, label: 'check/json/root/b' });
  const LEAF_A = buildLeaf({ cn: 'A', rootCn: 'A', root: rootA, hostKey: hostA, endpoint: 'https://a.example/mcp', ...whole, label: 'check/json/leaf/a' });
  const LEAF_B = buildLeaf({ cn: 'B', rootCn: 'B', root: rootB, hostKey: hostB, endpoint: 'https://b.example/mcp', ...whole, label: 'check/json/leaf/b' });
  const node = () => {
    const n = makeNode({ path: '/b', leafKey: hostB, chain: [LEAF_B, ROOT_B], now });
    pin(n, fingerprintOf(parse(ROOT_A)), { endpoint: 'https://a.example/mcp', leafDer: LEAF_A });
    return n;
  };
  let msg = 0;
  // `header` and `bytes` edit the header's and the body's text; either may hand back bytes, which is
  // how a byte that is not UTF-8 gets in.
  const call = (argsText, header = (t) => t, bytes = (b) => b) => {
    const to = parse(LEAF_B).publicKey, suite = suiteForKey(to);
    const aad = Buffer.from(header(canonical({ v: 1, suite, kid: fingerprint(to), msg_id: 'json-' + ++msg, ts: nowS, exp: nowS + 600, cty: 'application/hdtp-call+json' })));
    const body = `{"method":"tools/call","params":{"name":"send_message","arguments":${argsText}},"chain":${JSON.stringify([b64url(LEAF_A), b64url(ROOT_A)])}}`;
    const { enc, ct } = sealDeterministic(suite, to, INFO, aad, Buffer.from(bytes(Buffer.from(body))), Buffer.alloc(32, 9));
    return { protected: b64url(aad), enc: b64url(enc), ct: b64url(ct), sig: b64url(signDetached(hostA.priv, Buffer.concat([aad, enc, ct]))) };
  };
  // The body is the first container and params the second; `arguments` is the rest.
  const nested = (n) => '['.repeat(n) + '1' + ']'.repeat(n);
  // `@` in a text, as the bytes given: the one way to write bytes that are not UTF-8 into JSON text.
  const bytesAt = (text, ...b) => { const t = Buffer.from(text), i = t.indexOf('@'); return Buffer.concat([t.subarray(0, i), Buffer.from(b), t.subarray(i + 1)]); };
  const msgIdOf = (text) => (t) => t.replace(/"msg_id":"[^"]*"/, `"msg_id":${text}`);
  for (const [what, envelope, want] of [
    // Text that is not UTF-8, and a \u escape of half a surrogate pair, are not JSON to serde_json,
    // which the core reads with, and are to JSON.parse, which read the first as U+FFFD and kept the
    // second as a lone surrogate: this node decided `ok` on both, as the Go port did, where the core
    // refused them. A pair, and an escaped backslash before a `u`, are the controls.
    ['a header whose msg_id is half a surrogate pair', call('{}', msgIdOf('"\\ud800"')), 'envelope_invalid: protected is not JSON'],
    ['a header holding a byte that is not UTF-8', call('{}', (t) => bytesAt(msgIdOf('"@"')(t), 0xff)), 'envelope_invalid: protected is not JSON'],
    ['a body whose value is half a surrogate pair', call('{"text":"\\ud800"}'), 'envelope_invalid: does not open'],
    ['a body whose value is the low half of a surrogate pair', call('{"text":"\\udc00"}'), 'envelope_invalid: does not open'],
    ['a body whose member name is half a surrogate pair', call('{"\\ud800":1}'), 'envelope_invalid: does not open'],
    ['a body holding bytes that are not UTF-8', call('{"text":"@"}', undefined, (b) => bytesAt(b.toString('latin1'), 0xff, 0xfe)), 'envelope_invalid: does not open'],
    ['a body holding a surrogate pair (the control)', call('{"text":"\\ud83d\\ude00"}'), 'ok'],
    ['a body holding an escaped backslash before a u (the control)', call('{"text":"\\\\ud800"}'), 'ok'],
    ['a body holding a number past the largest double', call('{"n":1e400}'), 'envelope_invalid: does not open'],
    ['a body nested 128 deep', call(nested(126)), 'envelope_invalid: does not open'],
    ['a header holding a ts past the largest double', call('{}', (t) => t.replace(`"ts":${nowS}`, '"ts":1e400')), 'envelope_invalid: protected is not JSON'],
    // The header's integers, judged on their text as the ports read them (serde_json's `as_i64`):
    // -0, a fraction and an exponent are not integers, however JSON.parse reads them; past 64 bits is
    // not one either; past 2^53 and within 64 bits is one, and is judged by its time, as the ports
    // judge it.
    ['a header whose ts is -0', call('{}', (t) => t.replace(`"ts":${nowS}`, '"ts":-0')), 'envelope_invalid: header member types'],
    ['a header whose exp is -0', call('{}', (t) => t.replace(`"exp":${nowS + 600}`, '"exp":-0')), 'envelope_invalid: header member types'],
    ['a header whose ts is written with a fraction', call('{}', (t) => t.replace(`"ts":${nowS}`, `"ts":${nowS}.0`)), 'envelope_invalid: header member types'],
    ['a header whose ts is written with an exponent', call('{}', (t) => t.replace(`"ts":${nowS}`, `"ts":${(nowS / 1e8).toString()}e8`)), 'envelope_invalid: header member types'],
    ['a header whose ts is past 64 bits', call('{}', (t) => t.replace(`"ts":${nowS}`, '"ts":9223372036854775808')), 'envelope_invalid: header member types'],
    ['a header whose ts is past 2^53 and within 64 bits', call('{}', (t) => t.replace(`"ts":${nowS}`, '"ts":9223372036854775807')), 'envelope_invalid: outside the time window'],
    ['a body holding the largest double (the control)', call('{"n":1.7976931348623157e308}'), 'ok'],
    ['a body nested 127 deep (the control)', call(nested(125)), 'ok'],
  ]) {
    const r = receive(node(), envelope), got = r.why ? `${r.code}: ${r.why}` : r.code;
    ok(got === want, `${what}: ${want}, not ${got}`);
    console.log(`  ${what}: ${got}`);
  }
}

// A key outside the profile is refused where a certificate is read (§14.1), named by its OID, as both
// hdtp-identity ports refuse it: RSA, P-384, a bare X25519 key and an Ed25519 key with a NULL after
// its OID. parse() read the first three and left them to profileError, so compareLeaves compared a
// certificate carrying one and decodeCard took it on a card. The control, the same leaf under the
// same root with Ed25519 as RFC 8410 writes it, parses.
console.log('keys outside the profile (§14.1)');
{
  const { generateKeyPairSync } = await import('node:crypto');
  const { x25519FromSeed } = await import('./lib/keys.mjs');
  const { decodeCard, encodeCard } = await import('./lib/card.mjs');
  const root = ed25519FromSeed(seed('check/outside/root')), host = ed25519FromSeed(seed('check/outside/host'));
  const whole = { notBefore: new Date('2026-09-01T00:00:00Z'), notAfter: new Date('2027-09-01T00:00:00Z') };
  const leafFor = (hostKey, o = {}) => buildLeaf({ cn: 'A', rootCn: 'A', root, hostKey, endpoint: 'https://a.example/mcp', ...whole, label: 'check/outside', usage: [0], ...o });
  const control = leafFor(host);
  for (const [what, leaf, oid] of [
    ['an RSA key', leafFor({ pub: generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey }), '1.2.840.113549.1.1.1'],
    ['a P-384 key', leafFor({ pub: generateKeyPairSync('ec', { namedCurve: 'secp384r1' }).publicKey }), '1.2.840.10045.2.1'],
    ['a bare X25519 key', leafFor({ pub: x25519FromSeed(seed('check/outside/x25519')).pub }), '1.3.101.110'],
    ['an Ed25519 key with a NULL after its OID', leafFor(host, { misencode: { spkiAlgOid: '06032b65700500' } }), '1.3.101.112'],
    ['an Ed25519 key that is not a point (y = 2)', leafFor({ pub: { export: () => Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from([2]), Buffer.alloc(31)]) } }), null],
  ]) {
    const why = oid ? `unsupported key type ${oid}` : 'Ed25519 key is not a point';
    let got = 'parsed';
    try { parse(leaf); } catch (e) { got = e.message; }
    ok(got === why, `a leaf holding ${what}: parse says ${JSON.stringify(why)}, not ${JSON.stringify(got)}`);
    let order = 'refused';
    try { order = compareLeaves(control, leaf); } catch { /* refused, as it should be */ }
    ok(order === 'refused', `a leaf holding ${what}: compareLeaves refuses it, not ${order}`);
    const card = decodeCard(encodeCard({ fn: 'A', cert: leaf, seal: 'required' }));
    ok(card.why === `certificate does not parse: ${why}`, `a card whose leaf holds ${what} is refused for it, not ${JSON.stringify(card.why ?? card.fn)}`);
    console.log(`  ${what}: ${got}`);
  }
  let controlParsed = true;
  try { parse(control); } catch { controlParsed = false; }
  ok(controlParsed && profileError(parse(control), 'leaf') === null, 'the control, an Ed25519 leaf of the profile, parses and is in the profile');
  // y = 3 and every-bit-set decode to points, which both ports read too; so does the identity (y = 1).
  for (const [what, first, fill] of [['y = 3', 3, 0], ['every bit set', 0xff, 0xff], ['the identity', 1, 0]]) {
    const pointLeaf = leafFor({ pub: { export: () => Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from([first]), Buffer.alloc(31, fill)]) } });
    let read = 'parsed';
    try { parse(pointLeaf); } catch (e) { read = e.message; }
    ok(read === 'parsed', `an Ed25519 key that is a point (${what}) is read, not refused as ${JSON.stringify(read)}`);
  }
}

// A SubjectPublicKeyInfo is read as both hdtp-identity ports read it (their `from_spki` / `ParseSPKI`),
// in their words: exactly SEQUENCE { AlgorithmIdentifier, BIT STRING } with no unused bits, an
// algorithm OID in its one DER form, a curve OID the profile names, and a key that is a point. This
// read the key past the unused-bits octet whatever it said, so a key with 1 or 7 unused bits was a
// key here, and it answered a trailing member, a key in an OCTET STRING and an off-curve P-256 point
// in OpenSSL's words and a padded curve OID as `OID not in the DER form`, where both ports answer
// the words below. The two leaves as a wallet writes them are the controls.
console.log('a SubjectPublicKeyInfo as the ports read it (§2, §14.1)');
{
  const root = ed25519FromSeed(seed('check/spki/root')), host = ed25519FromSeed(seed('check/spki/host')), hostP = p256FromSeed(seed('check/spki/p256'));
  const whole = { notBefore: new Date('2026-09-01T00:00:00Z'), notAfter: new Date('2027-09-01T00:00:00Z') };
  const leafFor = (pub, usage) => buildLeaf({ cn: 'A', rootCn: 'A', root, hostKey: { pub }, endpoint: 'https://a.example/mcp', ...whole, label: 'check/spki', usage });
  const spki = (hex) => ({ export: () => Buffer.from(hex, 'hex') });
  const ed = spkiOf(host.pub).subarray(12).toString('hex'), pt = p256Uncompressed(hostP.pub).toString('hex');
  const offCurve = pt.slice(0, -2) + (parseInt(pt.slice(-2), 16) ^ 1).toString(16).padStart(2, '0');
  const P256_ALG = '301306072a8648ce3d020106082a8648ce3d030107';
  for (const [what, pub, usage, want] of [
    ['an Ed25519 key with 1 unused bit', spki('302a300506032b6570032101' + ed), [0], 'SubjectPublicKeyInfo shape'],
    ['an Ed25519 key with 7 unused bits', spki('302a300506032b6570032107' + ed), [0], 'SubjectPublicKeyInfo shape'],
    ['an Ed25519 key followed by a NULL', spki('302c300506032b6570032100' + ed + '0500'), [0], 'SubjectPublicKeyInfo shape'],
    ['an Ed25519 key in an OCTET STRING', spki('302a300506032b6570042100' + ed), [0], 'SubjectPublicKeyInfo shape'],
    ['a P-256 key with 1 unused bit', spki('3059' + P256_ALG + '034201' + pt), [0, 4], 'SubjectPublicKeyInfo shape'],
    ['a P-256 key whose curve OID has a padded subidentifier', spki('305a301406072a8648ce3d020106092a8648ce3d03800107034200' + pt), [0, 4], 'unsupported key type 1.2.840.10045.2.1'],
    ['a P-256 point that is not on the curve', spki('3059' + P256_ALG + '034200' + offCurve), [0, 4], 'P-256 key is not a point'],
    ['an Ed25519 key as a wallet writes it (the control)', host.pub, [0], 'parsed'],
    ['a P-256 key as a wallet writes it (the control)', hostP.pub, [0, 4], 'parsed'],
  ]) {
    let got = 'parsed';
    try { parse(leafFor(pub, usage)); } catch (e) { got = e.message; }
    ok(got === want, `a leaf holding ${what}: parse says ${JSON.stringify(want)}, not ${JSON.stringify(got)}`);
    console.log(`  ${what}: ${got}`);
  }
}

// Bytes this library did not write are read as both hdtp-identity ports read them (its CONTRACT §0):
// base64url, forgiving the padding and the standard alphabet, and nothing else — a card's certificate
// (once its spaces, tabs and line breaks are removed: §3, Reading a card), and the chain in a peer's
// plaintext. Buffer.from skipped a stray character, so a card carrying one was
// taken here and by the Go port and a chain carrying one validated, where the Rust core refused each
// (the port-parity audit of 2026-09-29: R24, T11, C7, T10). An empty X-HDTP-VERSION names no version.
// The controls — padded, and in the standard alphabet — read.
console.log('bytes this library did not write (§3, §13.3)');
{
  const { strictB64url } = await import('./lib/keys.mjs');
  const { decodeCard, encodeCard } = await import('./lib/card.mjs');
  for (const [text, want] of [
    ['AQID', '010203'], ['AQ', '01'], ['AQ==', '01'], ['AQ===', '01'], ['+/8', 'fbff'], ['-_8', 'fbff'],
    ['A Q', null], ['A\tQ', null], ['A\nQ', null], ['AQ==\n', null], ['A\u000bQ', null], ['A Q', null],
    ['A', null], ['A=Q', null], ['AR', null], ['AQ!', null], ['A.Q', null], [7, null],
  ]) {
    const got = strictB64url(text);
    ok((got === null ? null : got.toString('hex')) === want, `strictB64url(${JSON.stringify(text)}) is ${want ?? 'refused'}, not ${got === null ? 'refused' : got.toString('hex')}`);
  }
  const at = (iso) => new Date(iso), now = at('2026-09-13T12:00:00Z'), nowS = Math.floor(now / 1000);
  const key = (label) => ed25519FromSeed(seed('check/strict/' + label));
  const rootA = key('root/a'), hostA = key('host/a'), rootB = key('root/b'), hostB = key('host/b');
  const whole = { notBefore: at('2026-09-01T00:00:00Z'), notAfter: at('2027-09-01T00:00:00Z') };
  const ROOT_A = buildRoot({ cn: 'A', key: rootA, notBefore: whole.notBefore, label: 'check/strict/root/a' });
  const ROOT_B = buildRoot({ cn: 'B', key: rootB, notBefore: whole.notBefore, label: 'check/strict/root/b' });
  const LEAF_A = buildLeaf({ cn: 'A', rootCn: 'A', root: rootA, hostKey: hostA, endpoint: 'https://a.example/mcp', ...whole, label: 'check/strict/leaf/a' });
  const LEAF_B = buildLeaf({ cn: 'B', rootCn: 'B', root: rootB, hostKey: hostB, endpoint: 'https://b.example/mcp', ...whole, label: 'check/strict/leaf/b' });
  const leafText = b64url(LEAF_A), pad = '='.repeat((4 - (leafText.length % 4)) % 4);
  const stray = leafText.slice(0, 8) + '!' + leafText.slice(8);
  const withCert = (value) => `BEGIN:VCARD\r\nVERSION:4.0\r\nFN:A\r\nX-HDTP-VERSION:1\r\nX-HDTP-CERT:${value}\r\nEND:VCARD\r\n`;
  for (const [what, value, want] of [
    ['a stray character', stray, 'certificate does not parse: not base64url'],
    ['a no-break space', leafText.slice(0, 8) + ' ' + leafText.slice(8), 'certificate does not parse: not base64url'],
    ['a vertical tab', leafText.slice(0, 8) + '\u000b' + leafText.slice(8), 'certificate does not parse: not base64url'],
    // A space or a tab is removed from a card's certificate before it is read (§3, Reading a card), as
    // a paste puts them there and base64url has neither: both read.
    ['a space', leafText.slice(0, 8) + ' ' + leafText.slice(8), 'read'],
    ['a tab', leafText.slice(0, 8) + '\t' + leafText.slice(8), 'read'],
    ['padding inside', leafText.slice(0, 8) + '=' + leafText.slice(8), 'certificate does not parse: not base64url'],
    ['nothing wrong with it (the control)', leafText, 'read'],
    ['padding at the end (the control)', leafText + pad, 'read'],
    ['the standard alphabet (the control)', leafText.replace(/-/g, '+').replace(/_/g, '/'), 'read'],
  ]) {
    const card = decodeCard(withCert(value)), got = card.error ? card.why : card.cert.equals(LEAF_A) ? 'read' : 'another certificate';
    ok(got === want, `a card whose certificate has ${what}: ${want}, not ${got}`);
  }
  const empty = decodeCard(encodeCard({ fn: 'A', cert: LEAF_A }).replace('X-HDTP-VERSION:1', 'X-HDTP-VERSION:'));
  ok(empty.why === 'no X-HDTP-VERSION', `a card with an empty X-HDTP-VERSION: no X-HDTP-VERSION, not ${empty.why}`);
  const node = () => {
    const n = makeNode({ path: '/b', leafKey: hostB, chain: [LEAF_B, ROOT_B], now });
    pin(n, fingerprintOf(parse(ROOT_A)), { endpoint: 'https://a.example/mcp', leafDer: LEAF_A });
    return n;
  };
  let msg = 0;
  const call = (chain) => {
    const to = parse(LEAF_B).publicKey, suite = suiteForKey(to);
    const aad = Buffer.from(canonical({ v: 1, suite, kid: fingerprint(to), msg_id: 'strict-' + ++msg, ts: nowS, exp: nowS + 600, cty: 'application/hdtp-call+json' }));
    const body = JSON.stringify({ method: 'tools/call', params: { name: 'send_message', arguments: {} }, chain });
    const { enc, ct } = sealDeterministic(suite, to, INFO, aad, Buffer.from(body), Buffer.alloc(32, 9));
    return { protected: b64url(aad), enc: b64url(enc), ct: b64url(ct), sig: b64url(signDetached(hostA.priv, Buffer.concat([aad, enc, ct]))) };
  };
  for (const [what, member, want] of [
    ['a stray character', stray, 'envelope_invalid: plaintext shape'],
    ['a vertical tab', leafText.slice(0, 8) + '\u000b' + leafText.slice(8), 'envelope_invalid: plaintext shape'],
    ['padding (the control)', leafText + pad, 'ok'],
  ]) {
    const r = receive(node(), call([member, b64url(ROOT_A)])), got = r.why ? `${r.code}: ${r.why}` : r.code;
    ok(got === want, `a chain in the plaintext whose leaf has ${what}: ${want}, not ${got}`);
    console.log(`  a chain in the plaintext whose leaf has ${what}: ${got}`);
  }
}

// A card as a chat delivers it (§3, Reading a card; SEP-0001). Observed 2026-10-05: a card pasted into
// a chat came back with X-HDTP-CERT's continuations without their leading space, blank lines between
// some, and one continuation with its space kept; every reader dropped those lines and refused the
// card. Each case is the seed's card for one leaf, damaged one way. A cut certificate is still refused,
// by the DER parse. A changed character either fails to parse or is not found by reading (a card
// carries no root to check its leaf against): one changed in the signature reads, as a certificate its
// root did not sign, which validateChain shows.
console.log('a card as a chat delivers it (§3)');
{
  const { decodeCard, encodeCard } = await import('./lib/card.mjs');
  const at = (iso) => new Date(iso), now = at('2026-09-13T12:00:00Z');
  const rootKey = ed25519FromSeed(seed('check/paste/root')), hostKey = ed25519FromSeed(seed('check/paste/host'));
  const whole = { notBefore: at('2026-09-01T00:00:00Z'), notAfter: at('2027-09-01T00:00:00Z') };
  const ROOT = buildRoot({ cn: 'A', key: rootKey, notBefore: whole.notBefore, label: 'check/paste/root' });
  const LEAF = buildLeaf({ cn: 'A', rootCn: 'A', root: rootKey, hostKey, endpoint: 'https://a.example/mcp', ...whole, label: 'check/paste/leaf' });
  const card = encodeCard({ fn: 'Alina Rao', cert: LEAF, seal: 'required' });
  const lines = card.split('\r\n');
  const first = lines.findIndex((l) => l.startsWith('X-HDTP-CERT:'));
  const conts = lines.slice(first + 1).filter((l) => l.startsWith(' ')).length;
  ok(conts >= 4, `the card's certificate is folded over ${conts + 1} lines, enough to damage`);
  // The owner's shape: every continuation loses its space but the third, blank lines after the first
  // and the fourth, LF line ends.
  const pasted = lines.map((l, i) => {
    const k = i - first;
    if (k < 1 || k > conts) return l;
    const body = k === 3 ? l : l.slice(1);
    return k === 1 || k === 4 ? body + '\n' : body;
  }).join('\n');
  const unfolded = lines.join('\r\n').replace(/\r\n /g, '');
  const said = (text) => { const c = decodeCard(text); return c.error ? c.why : c.cert.equals(LEAF) ? 'read' : 'another certificate'; };
  for (const [what, text, want] of [
    ['as the owner pasted it: spaces lost, blank lines, one space kept', pasted, 'read'],
    ['folded correctly (the control)', card, 'read'],
    ['not folded at all', unfolded, 'read'],
    ['with its continuations indented by a tab and CR LF kept', lines.map((l, i) => (i > first && i <= first + conts ? '\t' + l.slice(1) : l)).join('\r\n'), 'read'],
    ['with a space and a tab inside a continuation', card.replace(lines[first + 2], lines[first + 2].slice(0, 9) + ' \t' + lines[first + 2].slice(9)), 'read'],
    // Cut at 120 characters, a multiple of four, so what is refused is the DER and not the base64url.
    ['cut short', card.replace(/X-HDTP-CERT:[^]*?(?=\r\nX-HDTP-SEAL)/, () => 'X-HDTP-CERT:' + b64url(LEAF).slice(0, 120)), 'certificate does not parse: DER length overruns the buffer'],
  ]) {
    const got = said(text);
    ok(got === want, `a card ${what}: ${want}, not ${got}`);
    console.log(`  a card ${what}: ${got}`);
  }
  // A line that starts a property is never taken into the certificate: an X-HDTP-SEAL after it, with
  // and without a group prefix, stays a property when the continuations before it lost their spaces.
  for (const [what, prop, seal] of [['X-HDTP-SEAL:none', 'X-HDTP-SEAL:none', 'none'], ['a group-prefixed EMAIL, then the seal', 'item1.EMAIL;type=INTERNET:a@example.com\nX-HDTP-SEAL:optional', 'optional']]) {
    const text = pasted.replace('X-HDTP-SEAL:required', prop);
    const c = decodeCard(text);
    const got = c.error ? c.why : `${c.cert.equals(LEAF) ? 'read' : 'another certificate'}, seal ${c.seal}`;
    ok(got === `read, seal ${seal}`, `a pasted card with ${what} after the certificate: read, seal ${seal}, not ${got}`);
    console.log(`  a pasted card with ${what} after the certificate: ${got}`);
  }
  // One character changed in the middle of the signature: the card reads, its certificate is not the
  // leaf the root signed, and the chain does not validate. The character is replaced, not added, and
  // inside the value, so no spare bit and no length moves.
  const b64 = b64url(LEAF), mid = b64.length - 30, swap = b64[mid] === 'A' ? 'B' : 'A';
  const changed = card.replace(/X-HDTP-CERT:[^]*?(?=\r\nX-HDTP-SEAL)/, () => {
    const v = b64.slice(0, mid) + swap + b64.slice(mid + 1);
    return 'X-HDTP-CERT:' + v.match(/.{1,60}/g).join('\n');
  });
  const c = decodeCard(changed);
  const chain = c.error ? null : validateChain([c.cert, ROOT], { now });
  const got = c.error ? c.why : c.cert.equals(LEAF) ? 'the writer\'s leaf' : chain.ok ? 'another leaf, and its chain validates' : `another leaf, chain refused by rule ${chain.rule}`;
  ok(got === 'another leaf, chain refused by rule 3', `a card with one character of its signature changed: another leaf, chain refused by rule 3, not ${got}`);
  ok(validateChain([LEAF, ROOT], { now }).ok, 'the unchanged leaf validates under its root (the control)');
  console.log(`  a card with one character of its signature changed: ${got}`);
}

// Certificates the three readers answered three ways (the port-parity audit of 2026-09-29, R33): an
// empty keyUsage BIT STRING (`03 00`, which X.690 §8.6.2 says is none: the initial octet is required)
// was a keyUsage of no bits here and to the Rust core, and refused by the Go port; an empty [3] threw a
// TypeError here; and a validity of three times was read as its first two. Each is refused now in the
// ports' words. The controls — `03 01 00`, a keyUsage of no bits written with its initial octet, and the
// leaf rebuilt unchanged — read.
console.log('certificates the readers answered three ways (§14.1)');
{
  const { read, children, seq, tlv } = await import('./lib/der.mjs');
  const root = ed25519FromSeed(seed('check/r33/root')), host = ed25519FromSeed(seed('check/r33/host'));
  const at = (iso) => new Date(iso);
  const leafWith = (misencode) => buildLeaf({ cn: 'A', rootCn: 'A', root, hostKey: host, endpoint: 'https://a.example/mcp', notBefore: at('2026-09-01T00:00:00Z'), notAfter: at('2027-09-01T00:00:00Z'), label: 'check/r33/leaf', misencode });
  const leaf = leafWith({});
  const p256Root = p256FromSeed(seed('check/r33/p256/root')), p256Host = p256FromSeed(seed('check/r33/p256/host'));
  const p256LeafWith = (misencode) => buildLeaf({ cn: 'B', rootCn: 'B', root: p256Root, hostKey: p256Host, endpoint: 'https://b.example/mcp', notBefore: at('2026-09-01T00:00:00Z'), notAfter: at('2027-09-01T00:00:00Z'), label: 'check/r33/p256/leaf', misencode });
  const [tbs, alg, sig] = children(read(leaf));
  const fields = children(tbs).map((x) => x.raw);
  const [nb, na] = children(children(tbs)[4]).map((x) => x.raw);
  const rebuilt = (over) => seq(seq(...fields.map((x, i) => over[i] ?? x)), alg.raw, sig.raw);
  const said = (der) => { try { const c = parse(der); return `read, keyUsage [${c.keyUsage}]`; } catch (e) { return e.message; } };
  for (const [what, der, want] of [
    ['a keyUsage BIT STRING with no initial octet', leafWith({ keyUsage: [] }), 'BIT STRING not in the DER form'],
    ['an extensions wrapper with nothing in it', rebuilt({ 7: tlv(0xa3, Buffer.alloc(0)) }), 'not a v3 certificate with extensions'],
    ['three validity times', rebuilt({ 4: seq(nb, na, na) }), 'time not in the DER form'],
    // Three more the seed read and both ports refused (2026-09-30), each written before signing: an
    // extension of four parts, an extnValue that is not an OCTET STRING, a P-256 key as its compressed
    // point. The first was refused here in other words (`extension shape`); the other two were read.
    ['an extension of four parts', leafWith({ extensionParts: { oid: OID.ski, der: '05000500' } }), 'certificate shape'],
    ['an extnValue that is not an OCTET STRING', leafWith({ wrapperTag: { oid: OID.ski, tag: 0x03 } }), 'certificate shape'],
    ['a P-256 key written as its compressed point', p256LeafWith({ compressedPoint: true }), 'P-256 key is not the uncompressed point'],
    ['a keyUsage of no bits, with its initial octet (the control)', leafWith({ keyUsage: [0] }), 'read, keyUsage []'],
    ['nothing changed (the control)', rebuilt({}), `read, keyUsage [${parse(leaf).keyUsage}]`],
    ['a P-256 key, uncompressed (the control)', p256LeafWith({}), `read, keyUsage [${parse(p256LeafWith({})).keyUsage}]`],
  ]) {
    const got = said(der);
    ok(got === want, `a leaf with ${what}: ${want}, not ${got}`);
    console.log(`  a leaf with ${what}: ${got}`);
  }
}

// Appendix B itself is read by one rule, the checker's and the splicer's (lib/appendix.mjs), held here
// to vectors/appendix-b-reader.json, refusals word for word (TC-12). The two readers this replaced
// found the end marker from the start of the file and dropped an open fence without a word.
console.log('Appendix B, as vectors/appendix-b-reader.json reads it');
{
  const { cases } = JSON.parse(readFileSync(new URL('./appendix-b-reader.json', import.meta.url), 'utf8'));
  ok(cases.length >= 10 && cases.some((c) => c.refused) && cases.some((c) => c.blocks?.length), `vectors/appendix-b-reader.json holds ${cases.length} cases, refusals and reads among them`);
  for (const c of cases) {
    let got;
    try { got = { blocks: appendixB(c.doc).blocks.map((b) => b.value) }; } catch (e) { got = { refused: e.message }; }
    const want = c.refused ? { refused: c.refused } : { blocks: c.blocks };
    ok(JSON.stringify(got) === JSON.stringify(want), `${c.name}: ${JSON.stringify(want)}, not ${JSON.stringify(got)}`);
  }
}

// Every sentence that states a wire version, or says what the appendix holds, against the bytes: an
// envelope header's `v` is the one in Appendix B's envelopes, a card's major the one the card codec
// writes, an export's version the one the schema (generated from hdtp-identity's contract) gives,
// and the appendix's counts the vectors' own. Nothing here is a second copy of a number: each
// expected value is read from the thing itself. The released version and the draft are both held.
console.log('what the text states about versions and its vectors, against the bytes');
{
  const { decodeCard, encodeCard } = await import('./lib/card.mjs');
  const headers = vec.envelopes.map((e) => JSON.parse(fromB64url(e.protected).toString('utf8')));
  const envelopeV = String(headers[0].v);
  ok(headers.every((h) => String(h.v) === envelopeV), `Appendix B's envelopes carry one v: ${headers.map((h) => h.v)}`);
  const card = encodeCard({ fn: 'A', cert: Buffer.from(vec.certificates.leaf_a.der_hex, 'hex') });
  const cardMajor = /^X-HDTP-VERSION:(\d+)\r?$/m.exec(card)?.[1];
  ok(cardMajor !== undefined && decodeCard(card).error === undefined, 'the card codec writes a major it reads back');
  ok(decodeCard(card.replace(`X-HDTP-VERSION:${cardMajor}`, `X-HDTP-VERSION:${Number(cardMajor) + 1}`)).error === 'bad_request', 'and refuses the next one');
  const refused = Object.values(vec.certificates).filter((c) => c.refused).length;
  const counts = {
    certificates: Object.keys(vec.certificates).length - refused, refused,
    chainCases: vec.chain_cases.length, comparisons: vec.newest_leaf_cases.length,
    renewed: vec.certificate_renewed_cases.length, discarded: vec.certificate_renewed_cases.filter((c) => c.expect === 'discard').length,
    envelopes: vec.envelopes.length,
  };
  for (const dir of [current(), 'draft']) {
    if (!existsSync(new URL(`../docs/specification/${dir}/index.md`, import.meta.url))) continue;
    const said = stated(readSpec(root, dir));
    const schemaPath = new URL(`../schema/${dir}/schema.json`, import.meta.url);
    const exportV = existsSync(schemaPath) ? String(JSON.parse(readFileSync(schemaPath, 'utf8')).$defs.ExportManifest.properties.hdtp_export.const) : undefined;
    ok(exportV !== undefined, `${dir}: schema/${dir}/schema.json gives the export's version`);
    // A floor under each, so a scan that found nothing cannot pass: the sentences are there today.
    for (const [what, got, want, floor] of [['an envelope\'s v', said.envelope, envelopeV, 4], ['a card\'s major', said.card, cardMajor, 4], ['hdtp_export', said.exported, exportV, 2]]) {
      ok(got.length >= floor, `${dir}: the text states ${what} ${got.length} times, fewer than ${floor}: the scan is broken, or the sentences went`);
      ok(got.every((g) => g === want), `${dir}: the text states ${what} as ${JSON.stringify(got)}; the bytes say ${want}`);
    }
    ok(said.info.length === 1 && said.info[0] === INFO.toString(), `${dir}: one sentence defines the HPKE info string, and it is the one the envelopes open under: ${JSON.stringify(said.info)}`);
    ok(said.infoLabels.length >= 2 && said.infoLabels.every((l) => l === said.info[0]), `${dir}: every spelling of the info label is that string: ${JSON.stringify([...new Set(said.infoLabels)])}`);
    ok(said.generations.length === 0, `${dir}: the prose names a generation by a bare number: ${said.generations.join(', ')}`);
    ok(said.articles.length === 0, `${dir}: the text writes "a" before the name, which takes "an": ${said.articles.join(', ')}`);
    for (const [k, want] of Object.entries(counts)) ok(said.counts[k] === want, `${dir}: Appendix B's paragraph says ${said.counts[k]} for ${k}; the vectors hold ${want}`);
  }
  // The same article, in every other tracked text of this repository (a rename leaves "a" where the
  // old name took it). Where git cannot list the tree — an export with no .git — only the text is held.
  let tracked = [];
  try { tracked = execFileSync('git', ['-C', root, 'ls-files', '-z'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).split('\0').filter(Boolean); } catch { /* no git here */ }
  const wrong = [];
  for (const rel of tracked) {
    if (rel.startsWith('docs/specification/') || /\.(woff2|png|pdf)$/.test(rel) || rel === 'package-lock.json') continue;
    const file = new URL(`../${rel}`, import.meta.url);
    if (!existsSync(file)) continue;
    const body = readFileSync(file, 'utf8');
    for (const m of body.matchAll(ARTICLE)) wrong.push(`${rel}:${body.slice(0, m.index).split('\n').length} ${JSON.stringify(m[0])}`);
  }
  ok(wrong.length === 0, `"a" before the name outside the text: ${wrong.join(', ')}`);
  console.log(`  envelope v ${envelopeV}, card major ${cardMajor}, info ${INFO}, ${counts.certificates}+${counts.refused} certificates, ${counts.chainCases} chain cases`);
}

// The citation carries the version and date a second and a third time: CITATION.cff (twice, the
// work and its preferred citation) and the attribution line in the README. All are held to the
// header line of the specification's index page, the one place a version is written, so a release cannot leave them behind.
// The README's line is the one site/licence.mjs words for the whitepaper and the web fragment,
// whole, so the three cannot drift apart.
console.log('the citation, as the version line of the specification reads');
{
  const { version, date } = splitSpec(spec);
  const cff = readFileSync(new URL('../CITATION.cff', import.meta.url), 'utf8');
  const field = (k) => [...cff.matchAll(new RegExp(`^\\s*${k}:\\s*"?([^"\\n]*?)"?\\s*$`, 'gm'))].map((m) => m[1]);
  const versions = field('version'), dates = field('date-released');
  ok(versions.length === 2 && versions.every((v) => v === version), `CITATION.cff: version ${JSON.stringify(versions)}, not twice ${version}`);
  ok(dates.length === 2 && dates.every((d) => d === date), `CITATION.cff: date-released ${JSON.stringify(dates)}, not twice ${date}`);
  const readme = readFileSync(new URL('../README.md', import.meta.url), 'utf8');
  const line = readme.split('\n').filter((l) => /^> \*HDTP\b.*licensed under/.test(l));
  const read = (p) => existsSync(new URL(`../${p}`, import.meta.url)) ? readFileSync(new URL(`../${p}`, import.meta.url), 'utf8') : null;
  const want = `> ${licence(read, { version, date }).attribution.markdown}`;
  ok(line.length === 1 && line[0] === want, `README.md: the attribution line says ${JSON.stringify(line)}, not ${JSON.stringify(want)}`);
  // And three more places say which version is current, and when it was released.
  ok(readme.includes(`**Status: ${version} (${date}), released.`), `README.md: the status line does not say ${version} (${date}), released`);
  ok(new RegExp(`^## ${version.replace(/\./g, '\\.')} · ${date}$`, 'm').test(read('CHANGES.md') ?? ''), `CHANGES.md: no entry headed "## ${version} · ${date}"`);
  ok((read('CLAUDE.md') ?? '').includes(`**${version} (${date})**`), `CLAUDE.md: the current version is not given as ${version} (${date})`);
  console.log(`  ${version} (${date}): CITATION.cff, the README's attribution and status lines, CHANGES.md's entry, CLAUDE.md`);
}

console.log(`${checks - failures}/${checks} checks passed`);
process.exit(failures ? 1 : 0);
