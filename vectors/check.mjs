// Proves Appendix B: checks every vector does what the spec says.
// Reads the vectors from SPEC.md itself, so the bytes in the document are the bytes proven.
import { readFileSync, existsSync } from 'node:fs';
import { createPrivateKey, createPublicKey, X509Certificate } from 'node:crypto';
import { open, verifyDetached, suiteForLeaf, suiteForKey, sealDeterministic, signDetached } from './lib/hpke.mjs';
import { validateChain, compareLeaves, parse, profileError, buildRoot, buildLeaf, fingerprintOf } from './lib/x509.mjs';
import { fingerprint, fromB64url, b64url, sha256, PRF_SALT, deriveSeed, ed25519FromSeed, spkiOf, seed } from './lib/keys.mjs';
import { canonical } from './lib/canonical.mjs';
import { makeNode, pin, receive } from './lib/envelope.mjs';

const specPath = new URL('../SPEC.md', import.meta.url);
const spec = readFileSync(specPath, 'utf8');
const appendixB = spec.slice(spec.indexOf('## Appendix B'), spec.indexOf('*End of PACT'));
const blocks = [...appendixB.matchAll(/```json\n([\s\S]*?)\n```/g)].map((m) => JSON.parse(m[1]));
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
// (pact-identity CONTRACT §0): a number that is infinite as a double (`1e400`) or containers nested
// more than 127 deep is not JSON. JSON.parse read 1e400 as Infinity, and the node decided `ok` on a
// validly signed call whose body held one, where both ports refuse it. The body and header are
// written as text, because JSON.stringify writes 1e400 as null; the controls hold the largest double
// and 127 deep, and are decided.
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
  const call = (argsText, header = (t) => t) => {
    const to = parse(LEAF_B).publicKey, suite = suiteForKey(to);
    const aad = Buffer.from(header(canonical({ v: 2, suite, kid: fingerprint(to), msg_id: 'json-' + ++msg, ts: nowS, exp: nowS + 600, cty: 'application/pact-call+json' })));
    const body = `{"method":"tools/call","params":{"name":"send_message","arguments":${argsText}},"chain":${JSON.stringify([b64url(LEAF_A), b64url(ROOT_A)])}}`;
    const { enc, ct } = sealDeterministic(suite, to, Buffer.from('PACT-SEAL-v2'), aad, Buffer.from(body), Buffer.alloc(32, 9));
    return { protected: b64url(aad), enc: b64url(enc), ct: b64url(ct), sig: b64url(signDetached(hostA.priv, Buffer.concat([aad, enc, ct]))) };
  };
  // The body is the first container and params the second; `arguments` is the rest.
  const nested = (n) => '['.repeat(n) + '1' + ']'.repeat(n);
  for (const [what, envelope, want] of [
    ['a body holding a number past the largest double', call('{"n":1e400}'), 'envelope_invalid: does not open'],
    ['a body nested 128 deep', call(nested(126)), 'envelope_invalid: does not open'],
    ['a header holding a ts past the largest double', call('{}', (t) => t.replace(`"ts":${nowS}`, '"ts":1e400')), 'envelope_invalid: protected is not JSON'],
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
  ]) {
    const why = `unsupported key type ${oid}`;
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
}

console.log(`${checks - failures}/${checks} checks passed`);
process.exit(failures ? 1 : 0);
