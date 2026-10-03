// Generates the vectors of Appendix B deterministically: every key derives from a label.
// Output: vectors/hdtp-1.0-vectors.json. Run `node vectors/check.mjs` to prove them against the specification.
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { root, current, versionDir, pagesOf } from '../site/spec-source.mjs';
import { seed, ed25519FromSeed, p256FromSeed, pkcs8Of, spkiOf, fingerprint, b64url, PRF_SALT, deriveSeed } from './lib/keys.mjs';
import { buildRoot, buildLeaf, fingerprintOf, parse } from './lib/x509.mjs';
import { signDetached, suiteForLeaf, recipientOf, sealDeterministic } from './lib/hpke.mjs';
import { canonical } from './lib/canonical.mjs';
import { appendixB } from './lib/appendix.mjs';

const at = (iso) => new Date(iso);
const NOW = '2026-09-13T12:00:00Z';
const ENDPOINT_A = 'https://agent.alina.example/mcp';
const ENDPOINT_B = 'https://agent.bharat.example/mcp';

// Alina: an Ed25519 root and Ed25519 host keys. Bharat: a P-256 root and a P-256 host key.
const rootA = ed25519FromSeed(seed('root/alina'));
const rootB = p256FromSeed(seed('root/bharat'));
const hosts = {
  leaf_a: ed25519FromSeed(seed('host/alina/2026')),
  leaf_a_next: ed25519FromSeed(seed('host/alina/2027')),
  leaf_b: p256FromSeed(seed('host/bharat/2026')),
};
const leafA = (name, o) => buildLeaf({ cn: 'Alina Rao', rootCn: 'Alina Rao', root: rootA, hostKey: hosts[o.host ?? 'leaf_a'], endpoint: ENDPOINT_A, label: name, ...o });

const certs = {
  root_a: buildRoot({ cn: 'Alina Rao', key: rootA, notBefore: at('2026-09-01T00:00:00Z'), label: 'root_a' }),
  root_b: buildRoot({ cn: 'Bharat Mehta', key: rootB, notBefore: at('2026-09-01T00:00:00Z'), label: 'root_b' }),
  leaf_a: leafA('leaf_a', { dnsName: 'agent.alina.example', notBefore: at('2026-09-01T00:00:00Z'), notAfter: at('2027-09-01T00:00:00Z') }),
  leaf_b: buildLeaf({ cn: 'Bharat Mehta', rootCn: 'Bharat Mehta', root: rootB, hostKey: hosts.leaf_b, endpoint: ENDPOINT_B, notBefore: at('2026-09-01T00:00:00Z'), notAfter: at('2027-09-01T00:00:00Z'), label: 'leaf_b' }),
  leaf_a_expired: leafA('leaf_a_expired', { notBefore: at('2025-06-01T00:00:00Z'), notAfter: at('2026-06-01T00:00:00Z') }),
  leaf_a_long: leafA('leaf_a_long', { notBefore: at('2026-09-01T00:00:00Z'), notAfter: at('2027-10-10T00:00:00Z') }),
  leaf_a_next: leafA('leaf_a_next', { host: 'leaf_a_next', notBefore: at('2027-08-02T00:00:00Z'), notAfter: at('2028-08-01T00:00:00Z') }),
  // Two certificates that exist to be refused (§14.1), so every implementation reading this appendix
  // is held to both refusals. `leaf_b_twin` is leaf_b signed again with the signature swapped for its
  // twin `(r, n − s)`: it VERIFIES under root_b, which is the point. `leaf_a_feb30` is leaf_a with a
  // notBefore of 30 February, which a reader that normalises dates takes for 2 March.
  leaf_b_twin: buildLeaf({ cn: 'Bharat Mehta', rootCn: 'Bharat Mehta', root: rootB, hostKey: hosts.leaf_b, endpoint: ENDPOINT_B, notBefore: at('2026-09-01T00:00:00Z'), notAfter: at('2027-09-01T00:00:00Z'), label: 'leaf_b', misencode: { sigTwin: true } }),
  leaf_a_feb30: leafA('leaf_a_feb30', { notBefore: at('2026-03-02T12:00:00Z'), notAfter: at('2027-03-01T00:00:00Z'), misencode: { notBefore: '260230120000Z' } }),
  // …and a third: leaf_a naming its issuer in THREE bytes. It parses, its signature verifies,
  // and a card made from it used to show a person `sha256:AQID` as the identity to pin.
  leaf_a_aki3: leafA('leaf_a_aki3', { notBefore: at('2026-09-01T00:00:00Z'), notAfter: at('2027-09-01T00:00:00Z'), aki: Buffer.from([1, 2, 3]) }),
};
const hex = (b) => Buffer.from(b).toString('hex');
const REFUSED = ['leaf_b_twin', 'leaf_a_feb30', 'leaf_a_aki3'];
const notes = {
  root_a: 'Ed25519 root, self-signed, CN "Alina Rao", notAfter 9999-12-31',
  root_b: 'P-256 root, self-signed, CN "Bharat Mehta"',
  leaf_a: `Ed25519 leaf under root_a for ${ENDPOINT_A}, 2026-09-01 to 2027-09-01, with a dNSName beside the URI`,
  leaf_b: `P-256 leaf under root_b for ${ENDPOINT_B}, 2026-09-01 to 2027-09-01, keyUsage digitalSignature+keyAgreement`,
  leaf_a_expired: 'leaf_a\'s key and endpoint, 2025-06-01 to 2026-06-01: expired at NOW',
  leaf_a_long: 'leaf_a\'s key and endpoint, 2026-09-01 to 2027-10-10: 404 days',
  leaf_a_next: 'a fresh key for the same endpoint, 2027-08-02 to 2028-08-01: the renewal that supersedes leaf_a',
  leaf_b_twin: 'leaf_b\'s TBS under the OTHER twin of an ECDSA signature, (r, n − s): it verifies under root_b and is refused by the profile (§14.1: low-S)',
  leaf_a_feb30: 'leaf_a\'s key and endpoint with a notBefore of 260230120000Z, 30 February: refused, not read as 2 March (§14.1)',
  leaf_a_aki3: 'leaf_a\'s key and endpoint with an authorityKeyIdentifier of three bytes, 01 02 03: refused, because a key identifier is 32 bytes (§14.1), at card intake as much as in a chain',
};

const chainCases = [
  { name: 'alina valid', chain: ['leaf_a', 'root_a'], expected_root: fingerprintOf(parse(certs.root_a)), expected_endpoint: ENDPOINT_A, now: NOW, expect: 'accept' },
  { name: 'bharat valid', chain: ['leaf_b', 'root_b'], expected_root: fingerprintOf(parse(certs.root_b)), expected_endpoint: ENDPOINT_B, now: NOW, expect: 'accept' },
  { name: 'first contact, no expectation', chain: ['leaf_a', 'root_a'], now: NOW, expect: 'accept' },
  { name: 'chain of three', chain: ['leaf_a', 'root_a', 'root_a'], now: NOW, expect: 'refuse', rule: 1 },
  { name: 'single certificate is not a chain', chain: ['root_a'], now: NOW, expect: 'refuse', rule: 1 },
  { name: 'leaf presented as root', chain: ['leaf_a', 'leaf_a'], now: NOW, expect: 'refuse', rule: 1 },
  { name: 'root is not the one pinned', chain: ['leaf_a', 'root_a'], expected_root: fingerprintOf(parse(certs.root_b)), now: NOW, expect: 'refuse', rule: 2 },
  { name: 'leaf under the wrong root', chain: ['leaf_a', 'root_b'], now: NOW, expect: 'refuse', rule: 3 },
  { name: 'expired leaf', chain: ['leaf_a_expired', 'root_a'], now: NOW, expect: 'refuse', rule: 4 },
  { name: 'leaf not yet valid', chain: ['leaf_a_next', 'root_a'], now: NOW, expect: 'refuse', rule: 4 },
  { name: 'leaf longer than 398 days', chain: ['leaf_a_long', 'root_a'], now: NOW, expect: 'refuse', rule: 4 },
  { name: 'endpoint mismatch', chain: ['leaf_a', 'root_a'], expected_endpoint: ENDPOINT_A + '/', now: NOW, expect: 'refuse', rule: 5 },
  { name: 'an ECDSA signature swapped for its twin', chain: ['leaf_b_twin', 'root_b'], now: NOW, expect: 'refuse', rule: 1 },
  { name: 'a validity field that is not a date', chain: ['leaf_a_feb30', 'root_a'], now: NOW, expect: 'refuse', rule: 1 },
  { name: 'an issuer key identifier that is not 32 bytes', chain: ['leaf_a_aki3', 'root_a'], now: NOW, expect: 'refuse', rule: 1 },
];

const newestLeafCases = [
  { pinned: 'leaf_a', presented: 'leaf_a', expect: 'same' },
  { pinned: 'leaf_a', presented: 'leaf_a_next', expect: 'newer' },
  { pinned: 'leaf_a_next', presented: 'leaf_a', expect: 'superseded' },
  { pinned: 'leaf_a', presented: 'leaf_a_long', expect: 'conflict' },
];

const chainB64 = (...names) => names.map((n) => b64url(certs[n]));
const renewedCases = [
  { name: 'renewal followed', pinned_leaf: 'leaf_a', dialed: ENDPOINT_A, now: '2027-08-15T12:00:00Z', answer: { code: 'certificate_renewed', data: { chain: chainB64('leaf_a_next', 'root_a') } }, expect: 'follow' },
  { name: 'older chain discarded', pinned_leaf: 'leaf_a_next', dialed: ENDPOINT_A, now: '2027-08-15T12:00:00Z', answer: { code: 'certificate_renewed', data: { chain: chainB64('leaf_a', 'root_a') } }, expect: 'discard' },
  { name: 'another root discarded', pinned_leaf: 'leaf_a', dialed: ENDPOINT_A, now: NOW, answer: { code: 'certificate_renewed', data: { chain: chainB64('leaf_b', 'root_b') } }, expect: 'discard' },
];

// Three v: 1 envelopes: one each way carrying the chain, pairing the curves, and one
// in the small form, naming a leaf the receiver already holds (§13.2).
const ts = Math.floor(Date.parse(NOW) / 1000);
function envelope(name, sender, senderChain, recipientChain, msgId, form = 'chain') {
  const recipientLeaf = parse(certs[recipientChain[0]]);
  const suite = suiteForLeaf(recipientLeaf);
  const protectedHeader = { v: 1, suite, kid: fingerprint(recipientLeaf.publicKey), msg_id: msgId, ts, exp: ts + 600, cty: 'application/hdtp-call+json' };
  const aad = Buffer.from(canonical(protectedHeader));
  const call = { method: 'tools/call', params: { name: 'send_message', arguments: { msg_id: 'vec-1', text: 'hello from the HDTP test vectors' } } };
  const plaintext = Buffer.from(JSON.stringify(form === 'chain' ? { ...call, chain: chainB64(...senderChain) } : { ...call, leaf: fingerprint(sender.pub) }));
  const { enc, ct } = sealDeterministic(suite, recipientOf(recipientLeaf), Buffer.from('HDTP-SEAL-v1'), aad, plaintext, seed('ephemeral/' + name));
  const sig = signDetached(sender.priv, Buffer.concat([aad, enc, ct]));
  return { name, form, suite, sender_chain: senderChain, recipient_chain: recipientChain, plaintext_hex: hex(plaintext), protected: b64url(aad), enc: b64url(enc), ct: b64url(ct), sig: b64url(sig) };
}
const envelopes = [
  envelope('alina-to-bharat', hosts.leaf_a, ['leaf_a', 'root_a'], ['leaf_b', 'root_b'], 'vec-v1-alina-to-bharat'),
  envelope('bharat-to-alina', hosts.leaf_b, ['leaf_b', 'root_b'], ['leaf_a', 'root_a'], 'vec-v1-bharat-to-alina'),
  envelope('alina-to-bharat-by-reference', hosts.leaf_a, ['leaf_a', 'root_a'], ['leaf_b', 'root_b'], 'vec-v1-alina-to-bharat-ref', 'leaf'),
];

// §2.1, a root derived from a passkey. There is no authenticator in a vector file, so the PRF output
// is a fixed test value and what these prove is the part an implementation can get wrong: the HKDF
// with its empty salt, and the seed-to-key step. The three `info` strings over ONE prf are here
// together on purpose — they must come out unrelated, and a reader can see that they do.
//
// These carry a seed, which is a private key, and the rule everywhere else in this file is that root
// private keys stay out. The rule is intact: this derives a throwaway identity that exists in no
// certificate and nowhere else — `root_a` and `root_b` above come from different labels and their
// private keys remain absent. A derivation vector without its seed could only say "wrong" and never
// which of the two steps was wrong, which is most of its value.
const PRF = seed('prf/derived-vector');
const derivation = [
  { label: 'root', info: 'hdtp/root/1', alg: 'ed25519' },
  { label: 'store-key', info: 'hdtp/store-key/1' },
  { label: 'store-id', info: 'hdtp/store-id/1' },
].map(({ label, info, alg }) => {
  const s = deriveSeed(PRF, info);
  const base = { label, prf: b64url(PRF), salt: b64url(PRF_SALT), info, seed: b64url(s) };
  if (!alg) return { ...base, note: `HKDF-SHA256 over the same prf; a 32-byte secret, not a key` };
  const key = ed25519FromSeed(s);
  return { ...base, alg, spki: b64url(spkiOf(key.pub)), fingerprint: fingerprint(key.pub),
    note: 'the identity this passkey is: Ed25519 from the derived seed. No certificate: a root\'s serial and notBefore are the wallet\'s, not the derivation\'s, so the key is what reproduces and the certificate is not' };
});

const out = {
  generated_by: 'vectors/gen.mjs (every key derives from a label; what Ed25519 signs reproduces byte for byte; an ECDSA signature is one valid signature and is NEW EACH RUN, so root_b, leaf_b, leaf_b_twin and the P-256 envelope differ in their signature bytes from one generation to the next, and are to be verified, never compared)',
  now: NOW,
  // `refused: true` marks a certificate that exists to be REFUSED, so a reader of this appendix is
  // told which is which by the data rather than by a name: a conforming implementation refuses it at
  // rule 1 (it does not parse, or it parses and is outside the profile), and accepts every other one.
  certificates: Object.fromEntries(Object.entries(certs).map(([k, v]) => [k, { der_hex: hex(v), note: notes[k], ...(REFUSED.includes(k) ? { refused: true } : {}) }])),
  leaf_keys_pkcs8_hex: Object.fromEntries(Object.entries(hosts).map(([k, h]) => [k, hex(pkcs8Of(h.priv))])),
  chain_cases: chainCases, newest_leaf_cases: newestLeafCases, certificate_renewed_cases: renewedCases, envelopes,
  derivation,
};
const path = new URL('./hdtp-1.0-vectors.json', import.meta.url);
const json = JSON.stringify(out, null, 2);
writeFileSync(path, json + '\n');

// And into Appendix B, because the document is what implementations read: of the newest released
// version and of the draft, which carries the same vectors until the wire changes. `check.mjs`
// asserts they agree; it used to be the only thing standing between a regenerated file and a spec
// still carrying yesterday's bytes, which is a gate reporting a mistake rather than preventing one.
for (const version of [current(), 'draft']) {
  const dir = versionDir(root, version);
  if (!existsSync(join(dir, 'index.md'))) continue;
  // The page that holds the appendix, read by the one rule the checker reads it by
  // (lib/appendix.mjs): the end marker after the heading, every fence closed, the block JSON.
  const page = pagesOf(readFileSync(join(dir, 'index.md'), 'utf8')).map((p) => join(dir, p)).find((p) => readFileSync(p, 'utf8').includes('## Appendix B'));
  if (!page) throw new Error(`${version}: no page holds Appendix B`);
  const text = readFileSync(page, 'utf8');
  const { blocks } = appendixB(text);
  if (blocks.length !== 1) throw new Error(`${version}: Appendix B should hold one json block, found ${blocks.length}`);
  const [b] = blocks;
  const spliced = text.slice(0, b.from) + '```json\n' + json + '\n```' + text.slice(b.to);
  if (spliced !== text) {
    writeFileSync(page, spliced);
    console.log(`spliced into ${version}'s Appendix B`);
  }
}
console.log(`wrote ${path.pathname}: ${Object.keys(certs).length} certificates, ${chainCases.length} chain cases, ${envelopes.length} envelopes, ${derivation.length} derivations`);
