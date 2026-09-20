// Proves Appendix B: checks every vector does what the spec says.
// Reads the vectors from SPEC.md itself, so the bytes in the document are the bytes proven.
import { readFileSync, existsSync } from 'node:fs';
import { createPrivateKey, createPublicKey, X509Certificate } from 'node:crypto';
import { open, verifyDetached, suiteForLeaf } from './lib/hpke.mjs';
import { validateChain, compareLeaves, parse, profileError } from './lib/x509.mjs';
import { fingerprint, fromB64url, b64url, sha256, PRF_SALT, deriveSeed, ed25519FromSeed, spkiOf } from './lib/keys.mjs';

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

console.log(`${checks - failures}/${checks} checks passed`);
process.exit(failures ? 1 : 0);
