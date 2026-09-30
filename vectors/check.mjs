// Proves Appendix B: checks every vector does what the spec says.
// Reads the vectors from SPEC.md itself, so the bytes in the document are the bytes proven.
import { readFileSync, existsSync } from 'node:fs';
import { createPrivateKey, createPublicKey, X509Certificate } from 'node:crypto';
import { open, verifyDetached, suiteForLeaf, suiteForKey, sealDeterministic, signDetached } from './lib/hpke.mjs';
import { validateChain, compareLeaves, parse, profileError, buildRoot, buildLeaf, fingerprintOf, OID } from './lib/x509.mjs';
import { fingerprint, fromB64url, b64url, sha256, PRF_SALT, deriveSeed, ed25519FromSeed, p256FromSeed, spkiOf, seed, p256Uncompressed } from './lib/keys.mjs';
import { canonical } from './lib/canonical.mjs';
import { makeNode, pin, receive } from './lib/envelope.mjs';
import { appendixB } from './lib/appendix.mjs';

const specPath = new URL('../SPEC.md', import.meta.url);
const spec = readFileSync(specPath, 'utf8');
const blocks = appendixB(spec).blocks.map((b) => b.value);
if (blocks.length < 1) throw new Error('Appendix B has no vector blocks');
const [v2] = blocks;

let failures = 0, checks = 0;
const ok = (cond, what) => { checks++; if (!cond) { failures++; console.log('  FAIL ' + what); } };

if (!v2) {
  console.log('no 2.0 block in Appendix B yet');
} else {
  const file = new URL('./pact-2.0-vectors.json', import.meta.url);
  if (existsSync(file)) ok(JSON.stringify(JSON.parse(readFileSync(file, 'utf8'))) === JSON.stringify(v2), 'SPEC.md carries the generated vectors unchanged');
  const der = Object.fromEntries(Object.entries(v2.certificates).map(([k, c]) => [k, Buffer.from(c.der_hex, 'hex')]));
  const chainOf = (names) => names.map((n) => der[n]);

  console.log('certificates parse under OpenSSL as well');
  for (const [name, bytes] of Object.entries(der)) {
    // A certificate marked `refused` exists to be refused (§14.1): it must NOT come out of parse and
    // the profile check clean. `leaf_b_twin` is the instructive one — OpenSSL verifies it under
    // root_b, because the twin of an ECDSA signature is a valid signature; the profile is what refuses.
    if (v2.certificates[name].refused) {
      let why = null;
      try { why = profileError(parse(bytes), 'leaf'); } catch (e) { why = e.message; }
      ok(why !== null, `${name}: marked refused, and parse + profile let it through`);
      if (name === 'leaf_b_twin') ok(new X509Certificate(bytes).verify(new X509Certificate(der.root_b).publicKey), `${name}: the twin VERIFIES under root_b per OpenSSL, which is why the profile has to refuse it`);
      continue;
    }
    const c = new X509Certificate(bytes), mine = parse(bytes);
    ok(c.subject.includes(mine.subject), `${name}: subject`);
    ok(c.ca === mine.ca, `${name}: cA`);
    if (mine.uris.length) ok(c.subjectAltName.includes('URI:' + mine.uris[0]), `${name}: subjectAltName`);
    ok(Math.abs(c.validFromDate - mine.notBefore) < 1000, `${name}: notBefore`);
    if (name.startsWith('leaf_a')) ok(c.checkIssued(new X509Certificate(der.root_a)) && c.verify(new X509Certificate(der.root_a).publicKey), `${name}: issued and verified by root_a per OpenSSL`);
    if (name === 'leaf_b') ok(c.checkIssued(new X509Certificate(der.root_b)) && c.verify(new X509Certificate(der.root_b).publicKey), `${name}: issued and verified by root_b per OpenSSL`);
    ok(bytes.length <= 4096, `${name}: under 4 KiB`);
  }

  console.log('chain cases (§14.2)');
  for (const c of v2.chain_cases) {
    const r = validateChain(chainOf(c.chain), { now: new Date(c.now), expectedRoot: c.expected_root, expectedEndpoint: c.expected_endpoint });
    if (c.expect === 'accept') ok(r.ok, `${c.name}: expected accept, got rule ${r.rule} (${r.reason})`);
    else ok(!r.ok && r.rule === c.rule, `${c.name}: expected refusal by rule ${c.rule}, got ${r.ok ? 'accept' : 'rule ' + r.rule + ' (' + r.reason + ')'}`);
    console.log(`  ${c.name}: ${r.ok ? 'accepted' : 'refused by rule ' + r.rule}`);
  }

  console.log('newest leaf (§14.3)');
  for (const c of v2.newest_leaf_cases) {
    const got = compareLeaves(der[c.pinned], der[c.presented]);
    ok(got === c.expect, `${c.pinned} vs ${c.presented}: expected ${c.expect}, got ${got}`);
    console.log(`  ${c.pinned} then ${c.presented}: ${got}`);
  }

  console.log('certificate_renewed (§14.4)');
  for (const c of v2.certificate_renewed_cases) {
    const chain = c.answer.data.chain.map(fromB64url);
    const pinned = parse(der[c.pinned_leaf]);
    const r = validateChain(chain, { now: new Date(c.now), expectedRoot: 'sha256:' + Buffer.from(pinned.aki).toString('base64url'), expectedEndpoint: c.dialed });
    const follow = r.ok && ['newer', 'same'].includes(compareLeaves(der[c.pinned_leaf], chain[0]));
    ok(follow === (c.expect === 'follow'), `${c.name}: expected ${c.expect}`);
    console.log(`  ${c.name}: ${follow ? 'followed' : 'discarded'}${r.ok ? '' : ' (rule ' + r.rule + ')'}`);
  }

  console.log('v2 envelopes (§13)');
  for (const v of v2.envelopes) {
    const recipientLeaf = parse(der[v.recipient_chain[0]]);
    const recipientPriv = createPrivateKey({ key: Buffer.from(v2.leaf_keys_pkcs8_hex[v.recipient_chain[0]], 'hex'), format: 'der', type: 'pkcs8' });
    const aad = fromB64url(v.protected), enc = fromB64url(v.enc), ct = fromB64url(v.ct);
    const header = JSON.parse(aad.toString());
    ok(Object.keys(header).sort().join(',') === 'cty,exp,kid,msg_id,suite,ts,v', `${v.name}: header members`);
    ok(header.v === 2 && header.suite === v.suite && header.suite === suiteForLeaf(recipientLeaf), `${v.name}: version and suite`);
    ok(header.kid === fingerprint(recipientLeaf.publicKey), `${v.name}: kid is the recipient leaf key`);
    ok(createPublicKey(recipientPriv).export({ format: 'der', type: 'spki' }).equals(recipientLeaf.spki), `${v.name}: the recipient key is the leaf's`);
    let plaintext = null;
    try { plaintext = open(v.suite, recipientPriv, recipientLeaf.publicKey, Buffer.from('PACT-SEAL-v2'), aad, enc, ct); } catch (e) { ok(false, `${v.name}: open threw ${e.message}`); }
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
        const r = validateChain(chain, { now: new Date(v2.now) });
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
  for (const d of v2.derivation ?? []) {
    ok(d.salt === b64url(PRF_SALT), `${d.label}: salt is SHA-256("pact/vault/1")`);
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
  ok((v2.derivation ?? []).length >= 3, 'all three info strings are covered');
}

// The receiving node reads a header and a body as JSON exactly when every port does
// (pact-identity CONTRACT §0): bytes that are not UTF-8, a \u escape of half a surrogate pair, a
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
    const aad = Buffer.from(header(canonical({ v: 2, suite, kid: fingerprint(to), msg_id: 'json-' + ++msg, ts: nowS, exp: nowS + 600, cty: 'application/pact-call+json' })));
    const body = `{"method":"tools/call","params":{"name":"send_message","arguments":${argsText}},"chain":${JSON.stringify([b64url(LEAF_A), b64url(ROOT_A)])}}`;
    const { enc, ct } = sealDeterministic(suite, to, Buffer.from('PACT-SEAL-v2'), aad, Buffer.from(bytes(Buffer.from(body))), Buffer.alloc(32, 9));
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
// pact-identity ports refuse it: RSA, P-384, a bare X25519 key and an Ed25519 key with a NULL after
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

// A SubjectPublicKeyInfo is read as both pact-identity ports read it (their `from_spki` / `ParseSPKI`),
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

// Bytes this library did not write are read as both pact-identity ports read them (its CONTRACT §0):
// base64url, forgiving the padding and the standard alphabet, and nothing else — a card's certificate,
// and the chain in a peer's plaintext. Buffer.from skipped a stray character, so a card carrying one was
// taken here and by the Go port and a chain carrying one validated, where the Rust core refused each
// (the port-parity audit of 2026-09-29: R24, T11, C7, T10). An empty X-PACT-VERSION names no version.
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
  const withCert = (value) => `BEGIN:VCARD\r\nVERSION:4.0\r\nFN:A\r\nX-PACT-VERSION:2\r\nX-PACT-CERT:${value}\r\nEND:VCARD\r\n`;
  for (const [what, value, want] of [
    ['a stray character', stray, 'certificate does not parse: not base64url'],
    ['a no-break space', leafText.slice(0, 8) + ' ' + leafText.slice(8), 'certificate does not parse: not base64url'],
    ['a space', leafText.slice(0, 8) + ' ' + leafText.slice(8), 'certificate does not parse: not base64url'],
    ['padding inside', leafText.slice(0, 8) + '=' + leafText.slice(8), 'certificate does not parse: not base64url'],
    ['nothing wrong with it (the control)', leafText, 'read'],
    ['padding at the end (the control)', leafText + pad, 'read'],
    ['the standard alphabet (the control)', leafText.replace(/-/g, '+').replace(/_/g, '/'), 'read'],
  ]) {
    const card = decodeCard(withCert(value)), got = card.error ? card.why : card.cert.equals(LEAF_A) ? 'read' : 'another certificate';
    ok(got === want, `a card whose certificate has ${what}: ${want}, not ${got}`);
  }
  const empty = decodeCard(encodeCard({ fn: 'A', cert: LEAF_A }).replace('X-PACT-VERSION:2', 'X-PACT-VERSION:'));
  ok(empty.why === 'no X-PACT-VERSION', `a card with an empty X-PACT-VERSION: no X-PACT-VERSION, not ${empty.why}`);
  const node = () => {
    const n = makeNode({ path: '/b', leafKey: hostB, chain: [LEAF_B, ROOT_B], now });
    pin(n, fingerprintOf(parse(ROOT_A)), { endpoint: 'https://a.example/mcp', leafDer: LEAF_A });
    return n;
  };
  let msg = 0;
  const call = (chain) => {
    const to = parse(LEAF_B).publicKey, suite = suiteForKey(to);
    const aad = Buffer.from(canonical({ v: 2, suite, kid: fingerprint(to), msg_id: 'strict-' + ++msg, ts: nowS, exp: nowS + 600, cty: 'application/pact-call+json' }));
    const body = JSON.stringify({ method: 'tools/call', params: { name: 'send_message', arguments: {} }, chain });
    const { enc, ct } = sealDeterministic(suite, to, Buffer.from('PACT-SEAL-v2'), aad, Buffer.from(body), Buffer.alloc(32, 9));
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

console.log(`${checks - failures}/${checks} checks passed`);
process.exit(failures ? 1 : 0);
