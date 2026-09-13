// Proves Appendix B: opens the v1 vectors, and checks every 2.0 vector does what the spec says.
// Reads the vectors from SPEC.md itself, so the bytes in the document are the bytes proven.
import { readFileSync, existsSync } from 'node:fs';
import { createPrivateKey, createPublicKey, X509Certificate } from 'node:crypto';
import { open, verifyDetached, suiteForLeaf, recipientOf } from './lib/hpke.mjs';
import { validateChain, compareLeaves, parse, fingerprintOf, OID } from './lib/x509.mjs';
import { fingerprint, fromB64url } from './lib/keys.mjs';
import * as xwing from './lib/xwing.mjs';

const specPath = new URL('../SPEC.md', import.meta.url);
const spec = readFileSync(specPath, 'utf8');
const appendixB = spec.slice(spec.indexOf('## Appendix B'), spec.indexOf('## Appendix C'));
const blocks = [...appendixB.matchAll(/```json\n([\s\S]*?)\n```/g)].map((m) => JSON.parse(m[1]));
if (blocks.length < 1) throw new Error('Appendix B has no vector blocks');
const [v1, v2] = blocks;

let failures = 0, checks = 0;
const ok = (cond, what) => { checks++; if (!cond) { failures++; console.log('  FAIL ' + what); } };

console.log('v1 envelopes');
for (const v of v1) {
  const recipientPriv = createPrivateKey({ key: Buffer.from(v.recipient_key_pkcs8_hex, 'hex'), format: 'der', type: 'pkcs8' });
  const senderPub = createPublicKey(createPrivateKey({ key: Buffer.from(v.sender_key_pkcs8_hex, 'hex'), format: 'der', type: 'pkcs8' }));
  const aad = fromB64url(v.protected), enc = fromB64url(v.enc), ct = fromB64url(v.ct);
  let plaintext = null;
  try { plaintext = open(v.suite, recipientPriv, createPublicKey(recipientPriv), Buffer.from('PACT-SEAL-v1'), aad, enc, ct); } catch (e) { ok(false, `${v.name}: open threw ${e.message}`); }
  ok(plaintext && plaintext.toString('hex') === v.plaintext_hex, `${v.name}: plaintext`);
  ok(verifyDetached(senderPub, Buffer.concat([aad, enc, ct]), fromB64url(v.sig)), `${v.name}: signature`);
  console.log(`  ${v.name}: ${plaintext ? 'opened' : 'closed'}`);
}

if (!v2) {
  console.log('no 2.0 block in Appendix B yet');
} else {
  const file = new URL('./pact-2.0-vectors.json', import.meta.url);
  if (existsSync(file)) ok(JSON.stringify(JSON.parse(readFileSync(file, 'utf8'))) === JSON.stringify(v2), 'SPEC.md carries the generated vectors unchanged');
  ok(v2.seal_key_extension_oid === OID.sealKey, 'sealing-key extension OID');
  const der = Object.fromEntries(Object.entries(v2.certificates).map(([k, c]) => [k, Buffer.from(c.der_hex, 'hex')]));
  const chainOf = (names) => names.map((n) => der[n]);

  console.log('certificates parse under OpenSSL as well');
  for (const [name, bytes] of Object.entries(der)) {
    const c = new X509Certificate(bytes), mine = parse(bytes);
    ok(c.subject.includes(mine.subject), `${name}: subject`);
    ok(c.ca === mine.ca, `${name}: cA`);
    if (mine.uris.length) ok(c.subjectAltName.includes('URI:' + mine.uris[0]), `${name}: subjectAltName`);
    ok(Math.abs(c.validFromDate - mine.notBefore) < 1000, `${name}: notBefore`);
    if (name.startsWith('leaf_a')) ok(c.checkIssued(new X509Certificate(der.root_a)) && c.verify(new X509Certificate(der.root_a).publicKey), `${name}: issued and verified by root_a per OpenSSL`);
    if (name === 'leaf_b') ok(c.checkIssued(new X509Certificate(der.root_b)) && c.verify(new X509Certificate(der.root_b).publicKey), `${name}: issued and verified by root_b per OpenSSL`);
    ok(bytes.length <= 4096, `${name}: under 4 KiB`);
    if (name.startsWith('leaf') && name !== 'leaf_a_unsealed') ok(mine.sealKey?.length === xwing.PK_BYTES, `${name}: carries a 1216-byte sealing key`);
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
    const follow = r.ok && compareLeaves(der[c.pinned_leaf], chain[0]) !== 'superseded';
    ok(follow === (c.expect === 'follow'), `${c.name}: expected ${c.expect}`);
    console.log(`  ${c.name}: ${follow ? 'followed' : 'discarded'}${r.ok ? '' : ' (rule ' + r.rule + ')'}`);
  }

  console.log('v2 envelopes (§13, hybrid suite)');
  for (const v of v2.envelopes) {
    const recipientLeaf = parse(der[v.recipient_chain[0]]);
    const sealKey = xwing.keyFromSeed(Buffer.from(v2.leaf_keys[v.recipient_chain[0]].sealing_key_seed_hex, 'hex'));
    const aad = fromB64url(v.protected), enc = fromB64url(v.enc), ct = fromB64url(v.ct);
    const header = JSON.parse(aad.toString());
    ok(Object.keys(header).sort().join(',') === 'cty,exp,kid,msg_id,suite,ts,v', `${v.name}: header members`);
    ok(header.v === 2 && header.suite === 'PACT-SEAL-XWING' && header.suite === suiteForLeaf(recipientLeaf), `${v.name}: version and suite`);
    ok(header.kid === fingerprint(recipientLeaf.publicKey), `${v.name}: kid is the recipient leaf key`);
    ok(sealKey.pk.equals(recipientOf(recipientLeaf)), `${v.name}: the sealing seed yields the leaf's sealing key`);
    ok(enc.length === xwing.CT_BYTES, `${v.name}: enc is an X-Wing ciphertext`);
    let plaintext = null;
    try { plaintext = open(v.suite, sealKey, sealKey.pk, Buffer.from('PACT-SEAL-v2'), aad, enc, ct); } catch (e) { ok(false, `${v.name}: open threw ${e.message}`); }
    ok(plaintext && plaintext.toString('hex') === v.plaintext_hex, `${v.name}: plaintext`);
    if (plaintext) {
      const body = JSON.parse(plaintext.toString());
      const chain = body.chain.map(fromB64url);
      const r = validateChain(chain, { now: new Date(v2.now) });
      ok(r.ok, `${v.name}: chain inside validates`);
      ok(r.ok && chain[0].equals(der[v.sender_chain[0]]), `${v.name}: chain inside is the sender's`);
      ok(r.ok && verifyDetached(r.leafKey, Buffer.concat([aad, enc, ct]), fromB64url(v.sig)), `${v.name}: signature under the chain's leaf key`);
    }
    console.log(`  ${v.name}: ${plaintext ? 'opened' : 'closed'}`);
  }
}

console.log(`${checks - failures}/${checks} checks passed`);
process.exit(failures ? 1 : 0);
