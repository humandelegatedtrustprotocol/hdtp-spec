// Generates the 2.0 vectors of Appendix B deterministically: every secret derives from a label.
// Output: vectors/pact-2.0-vectors.json. Run `node vectors/check.mjs` to prove them against SPEC.md.
import { writeFileSync } from 'node:fs';
import { createPublicKey } from 'node:crypto';
import { seed, ed25519FromSeed, p256FromSeed, pkcs8Of, fingerprint, b64url } from './lib/keys.mjs';
import { buildRoot, buildLeaf, fingerprintOf, parse } from './lib/x509.mjs';
import { seal, signDetached, suiteFor } from './lib/hpke.mjs';
import { canonical } from './lib/canonical.mjs';

const at = (iso) => new Date(iso);
const NOW = '2026-09-13T12:00:00Z';
const ENDPOINT_A = 'https://agent.alina.example/mcp';
const ENDPOINT_B = 'https://agent.bharat.example/mcp';

// Alina: an Ed25519 root and Ed25519 host keys. Bharat: a P-256 root and a P-256 host key.
const rootA = ed25519FromSeed(seed('root/alina'));
const rootB = p256FromSeed(seed('root/bharat'));
const hostA = ed25519FromSeed(seed('host/alina/2026'));
const hostA2 = ed25519FromSeed(seed('host/alina/2027'));
const hostB = p256FromSeed(seed('host/bharat/2026'));

const certs = {
  root_a: buildRoot({ cn: 'Alina Rao', key: rootA, notBefore: at('2026-09-01T00:00:00Z'), label: 'root_a' }),
  root_b: buildRoot({ cn: 'Bharat Mehta', key: rootB, notBefore: at('2026-09-01T00:00:00Z'), label: 'root_b' }),
  leaf_a: buildLeaf({ cn: 'Alina Rao', rootCn: 'Alina Rao', root: rootA, hostKey: hostA, endpoint: ENDPOINT_A, dnsName: 'agent.alina.example', notBefore: at('2026-09-01T00:00:00Z'), notAfter: at('2027-09-01T00:00:00Z'), label: 'leaf_a' }),
  leaf_b: buildLeaf({ cn: 'Bharat Mehta', rootCn: 'Bharat Mehta', root: rootB, hostKey: hostB, endpoint: ENDPOINT_B, notBefore: at('2026-09-01T00:00:00Z'), notAfter: at('2027-09-01T00:00:00Z'), label: 'leaf_b' }),
  leaf_a_expired: buildLeaf({ cn: 'Alina Rao', rootCn: 'Alina Rao', root: rootA, hostKey: hostA, endpoint: ENDPOINT_A, notBefore: at('2025-06-01T00:00:00Z'), notAfter: at('2026-06-01T00:00:00Z'), label: 'leaf_a_expired' }),
  leaf_a_long: buildLeaf({ cn: 'Alina Rao', rootCn: 'Alina Rao', root: rootA, hostKey: hostA, endpoint: ENDPOINT_A, notBefore: at('2026-09-01T00:00:00Z'), notAfter: at('2027-10-10T00:00:00Z'), label: 'leaf_a_long' }),
  leaf_a_next: buildLeaf({ cn: 'Alina Rao', rootCn: 'Alina Rao', root: rootA, hostKey: hostA2, endpoint: ENDPOINT_A, notBefore: at('2027-08-02T00:00:00Z'), notAfter: at('2028-08-01T00:00:00Z'), label: 'leaf_a_next' }),
};
const hex = (b) => Buffer.from(b).toString('hex');
const notes = {
  root_a: 'Ed25519 root, self-signed, CN "Alina Rao", notAfter 9999-12-31',
  root_b: 'P-256 root, self-signed, CN "Bharat Mehta"',
  leaf_a: `Ed25519 leaf under root_a for ${ENDPOINT_A}, 2026-09-01 to 2027-09-01, with a dNSName beside the URI`,
  leaf_b: `P-256 leaf under root_b for ${ENDPOINT_B}, 2026-09-01 to 2027-09-01, keyUsage digitalSignature+keyAgreement`,
  leaf_a_expired: 'leaf_a\'s key and endpoint, 2025-06-01 to 2026-06-01: expired at NOW',
  leaf_a_long: 'leaf_a\'s key and endpoint, 2026-09-01 to 2027-10-10: 404 days',
  leaf_a_next: 'a fresh key for the same endpoint, 2027-08-02 to 2028-08-01: the renewal that supersedes leaf_a',
};

const chainCases = [
  { name: 'alina valid', chain: ['leaf_a', 'root_a'], expected_root: fingerprintOf(parse(certs.root_a)), expected_endpoint: ENDPOINT_A, now: NOW, expect: 'accept' },
  { name: 'bharat valid', chain: ['leaf_b', 'root_b'], expected_root: fingerprintOf(parse(certs.root_b)), expected_endpoint: ENDPOINT_B, now: NOW, expect: 'accept' },
  { name: 'first contact, no expectation', chain: ['leaf_a', 'root_a'], now: NOW, expect: 'accept' },
  { name: 'chain of three', chain: ['leaf_a', 'root_a', 'root_a'], now: NOW, expect: 'refuse', rule: 1 },
  { name: 'single certificate is not a chain', chain: ['root_a'], now: NOW, expect: 'refuse', rule: 1 },
  { name: 'root is not the one pinned', chain: ['leaf_a', 'root_a'], expected_root: fingerprintOf(parse(certs.root_b)), now: NOW, expect: 'refuse', rule: 2 },
  { name: 'leaf under the wrong root', chain: ['leaf_a', 'root_b'], now: NOW, expect: 'refuse', rule: 3 },
  { name: 'leaf presented as root', chain: ['leaf_a', 'leaf_a'], now: NOW, expect: 'refuse', rule: 2 },
  { name: 'expired leaf', chain: ['leaf_a_expired', 'root_a'], now: NOW, expect: 'refuse', rule: 4 },
  { name: 'leaf not yet valid', chain: ['leaf_a_next', 'root_a'], now: NOW, expect: 'refuse', rule: 4 },
  { name: 'leaf longer than 398 days', chain: ['leaf_a_long', 'root_a'], now: NOW, expect: 'refuse', rule: 4 },
  { name: 'endpoint mismatch', chain: ['leaf_a', 'root_a'], expected_endpoint: ENDPOINT_A + '/', now: NOW, expect: 'refuse', rule: 5 },
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

// Two v2 envelopes, one each way, as the v1 vectors paired the curves.
const ts = Math.floor(Date.parse(NOW) / 1000);
function envelope(name, sender, senderChain, recipient, recipientChain, msgId) {
  const recipientLeaf = parse(certs[recipientChain[0]]);
  const suite = suiteFor(recipientLeaf.publicKey);
  const protectedHeader = { v: 2, suite, kid: fingerprint(recipientLeaf.publicKey), msg_id: msgId, ts, exp: ts + 600, cty: 'application/pact-call+json' };
  const aad = Buffer.from(canonical(protectedHeader));
  const plaintext = Buffer.from(JSON.stringify({
    method: 'tools/call', params: { name: 'send_message', arguments: { msg_id: 'vec-1', text: 'hello from the PACT test vectors' } }, chain: chainB64(...senderChain),
  }));
  const { enc, ct } = seal(suite, recipientLeaf.publicKey, Buffer.from('PACT-SEAL-v2'), aad, plaintext, seed('ephemeral/' + name));
  const sig = signDetached(sender.priv, Buffer.concat([aad, enc, ct]));
  return {
    name, suite, sender_chain: senderChain, sender_leaf_key_pkcs8_hex: hex(pkcs8Of(sender.priv)),
    recipient_chain: recipientChain, recipient_leaf_key_pkcs8_hex: hex(pkcs8Of(recipient.priv)),
    plaintext_hex: hex(plaintext), protected: b64url(aad), enc: b64url(enc), ct: b64url(ct), sig: b64url(sig),
  };
}
const envelopes = [
  envelope('alina-to-bharat', hostA, ['leaf_a', 'root_a'], hostB, ['leaf_b', 'root_b'], 'vec-v2-alina-to-bharat'),
  envelope('bharat-to-alina', hostB, ['leaf_b', 'root_b'], hostA, ['leaf_a', 'root_a'], 'vec-v2-bharat-to-alina'),
];

const out = {
  generated_by: 'vectors/gen.mjs (deterministic; Ed25519 signatures and every certificate reproduce byte for byte, ECDSA signatures are one valid signature)',
  now: NOW,
  certificates: Object.fromEntries(Object.entries(certs).map(([k, v]) => [k, { der_hex: hex(v), note: notes[k] }])),
  leaf_keys_pkcs8_hex: { leaf_a: hex(pkcs8Of(hostA.priv)), leaf_a_next: hex(pkcs8Of(hostA2.priv)), leaf_b: hex(pkcs8Of(hostB.priv)) },
  chain_cases: chainCases, newest_leaf_cases: newestLeafCases, certificate_renewed_cases: renewedCases, envelopes,
};
const path = new URL('./pact-2.0-vectors.json', import.meta.url);
writeFileSync(path, JSON.stringify(out, null, 2) + '\n');
console.log(`wrote ${path.pathname}: ${Object.keys(certs).length} certificates, ${chainCases.length} chain cases, ${envelopes.length} envelopes`);
