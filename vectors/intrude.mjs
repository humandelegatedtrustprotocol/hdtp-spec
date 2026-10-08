// Intrusion scenarios against the seed implementation: Mallory holds each artifact she could steal
// and tries what it lets her do. Every scenario states what the spec says should happen.
//   blocked    — the attack fails where the spec says it fails
//   residual   — the attack succeeds, and §14.5 already says so and bounds it
//   REPRODUCES — the attack succeeds and nothing in the spec stops it: a finding
import { createPublicKey } from 'node:crypto';
import { seed, ed25519FromSeed, p256FromSeed, pkcs8Of, b64url, fromB64url } from './lib/keys.mjs';
import { buildRoot, buildLeaf, validateChain, parse, fingerprintOf, OID } from './lib/x509.mjs';
import { seal, sealDeterministic, open } from './lib/hpke.mjs';
import { encodeCard, decodeCard } from './lib/card.mjs';
import { sealEnvelope, makeNode, renew, forgetKeysPast, pin, removeContact, receive } from './lib/envelope.mjs';
import { readSpec, root, versions } from '../site/spec-source.mjs';

const at = (iso) => new Date(iso);
const NOW = at('2026-09-13T12:00:00Z'), nowS = Math.floor(NOW / 1000);
const H = 3_600_000, D = 86_400_000;
const E_A = 'https://agent.alina.example/mcp', E_B = 'https://agent.bharat.example/mcp', E_M = 'https://mallory.example/mcp', E_N = 'https://alina.host.example/alina/mcp';

// The cast. Every key derives from a label; a host is one signing key.
const host = (label, p256 = false) => ({ sign: p256 ? p256FromSeed(seed('intrude/sign/' + label)) : ed25519FromSeed(seed('intrude/sign/' + label)) });
const rootA = ed25519FromSeed(seed('intrude/root/alina')), rootB = p256FromSeed(seed('intrude/root/bharat')), rootM = ed25519FromSeed(seed('intrude/root/mallory'));
const hostA = host('alina'), hostA2 = host('alina/2'), hostN = host('alina/new'), hostB = host('bharat', true), hostM = host('mallory');
const leafOf = (root, rootCn, h, endpoint, o = {}) => buildLeaf({ cn: o.cn ?? rootCn, rootCn, root, hostKey: h.sign, endpoint, notBefore: o.notBefore ?? at('2026-09-01T00:00:00Z'), notAfter: o.notAfter ?? at('2027-09-01T00:00:00Z'), label: o.label ?? endpoint + (o.cn ?? '') + (o.notBefore ?? ''), ...o });
const ROOT_A = buildRoot({ cn: 'Alina Rao', key: rootA, notBefore: at('2026-09-01T00:00:00Z'), label: 'i/root_a' });
const ROOT_B = buildRoot({ cn: 'Bharat Mehta', key: rootB, notBefore: at('2026-09-01T00:00:00Z'), label: 'i/root_b' });
const ROOT_M = buildRoot({ cn: 'Alina Rao', key: rootM, notBefore: at('2026-09-01T00:00:00Z'), label: 'i/root_m' }); // same name, on purpose
const LEAF_A = leafOf(rootA, 'Alina Rao', hostA, E_A), LEAF_B = leafOf(rootB, 'Bharat Mehta', hostB, E_B), LEAF_M = leafOf(rootM, 'Alina Rao', hostM, E_M);
const chainA = [LEAF_A, ROOT_A], chainB = [LEAF_B, ROOT_B], chainM = [LEAF_M, ROOT_M];
const FP_A = fingerprintOf(parse(ROOT_A)), FP_M = fingerprintOf(parse(ROOT_M));
const fresh = (h, endpoint, hoursAgo = 1, root = rootA) => leafOf(root, 'Alina Rao', h, endpoint, { notBefore: new Date(NOW - hoursAgo * H), notAfter: new Date(NOW + 365 * D) });

let n = 0;
const msgId = () => 'i-' + (++n);
const env = (o) => sealEnvelope({ ts: nowS, msgId: msgId(), ...o });
const card = (chain, fn = 'Alina Rao', extra) => encodeCard({ fn, cert: chain[0], seal: 'required', extra });
const request = (h, chain, recipientLeaf, o = {}) => env({ senderKey: h.sign, senderChain: chain, recipientLeaf, params: { name: 'request_contact', arguments: { card: card(chain, o.fn, o.extra), note: 'hi' } }, ...o });
const message = (h, chain, recipientLeaf, o = {}) => env({ senderKey: h.sign, senderChain: chain, recipientLeaf, params: { name: 'send_message', arguments: { msg_id: 'm', text: 'hello' } }, ...o });
const update = (h, chain, recipientLeaf, o = {}) => env({ senderKey: h.sign, senderChain: chain, recipientLeaf, params: { name: 'update_contact', arguments: { card: card(chain) } }, ...o });

function bharat(acceptNewHosts = 'auto') {
  const node = makeNode({ path: '/bharat', leafKey: hostB.sign, chain: chainB, now: NOW, acceptNewHosts });
  pin(node, FP_A, { endpoint: E_A, leafDer: LEAF_A });
  return node;
}
// Bharat once Alina's renewal has reached him in her host's first envelope (§13.2): null unless it
// was learned — answered as a contact, with the renewal event raised.
const bharatWhoHeard = () => {
  const b = bharat();
  const learned = receive(b, message(hostA2, [fresh(hostA2, E_A), ROOT_A], LEAF_B));
  return learned.tier === 'contact' && b.events.some((e) => e.event === 'renewal') ? b : null;
};
const rule = (chain, o = {}) => { const r = validateChain(chain, { now: NOW, ...o }); return r.ok ? 'accepted' : 'rule ' + r.rule; };

const results = [];
const scenario = (category, name, expect, fn) => {
  let got;
  try { got = fn(); } catch (e) { got = 'threw: ' + e.message; }
  const verdict = typeof expect === 'function' ? expect(got) : (got === expect ? 'blocked' : 'REPRODUCES');
  results.push({ category, name, got: typeof got === 'string' ? got : JSON.stringify(got), verdict });
};
const residual = (label) => (got) => (got === label ? 'residual' : 'REPRODUCES');
const blockedIf = (pred) => (got) => (pred(got) ? 'blocked' : 'REPRODUCES');

// ── Identity theft ──────────────────────────────────────────────────────────────
scenario('identity', 'a stranger at a fresh address is a plain guest (baseline)', blockedIf((r) => r.tier === 'guest' && !r.addressClaim), () => receive(bharat(), request(hostM, chainM, LEAF_B)));
scenario('identity', 'Mallory, own root, claims Alina\'s address in her leaf', blockedIf((r) => r.tier === 'guest' && r.addressClaim === FP_A), () => receive(bharat(), request(hostM, [leafOf(rootM, 'Alina Rao', hostM, E_A), ROOT_M], LEAF_B)));
scenario('identity', 'Alina\'s leaf presented under Mallory\'s root', 'rule 3', () => rule([LEAF_A, ROOT_M]));
scenario('identity', 'one byte of Alina\'s leaf changed', 'rule 3', () => { const t = Buffer.from(LEAF_A); t[t.indexOf(Buffer.from('Alina Rao')) + 1] ^= 1; return rule([t, ROOT_A]); });
scenario('identity', 'Mallory\'s root with the same display name', blockedIf((r) => r.tier === 'guest' && r.root === FP_M), () => receive(bharat(), request(hostM, chainM, LEAF_B, { fn: 'Alina Rao' })));
scenario('identity', 'stolen leaf key certified under Mallory\'s own root', blockedIf((r) => r.tier === 'guest'), () => receive(bharat(), request(hostA, [leafOf(rootM, 'Alina Rao', hostA, E_M), ROOT_M], LEAF_B)));
scenario('identity', 'stolen leaf key: sends as Alina while the leaf lives', residual('contact'), () => receive(bharat(), message(hostA, chainA, LEAF_B)).tier);
scenario('identity', 'stolen leaf key: after Alina renews with a fresh key, the old chain is a guest', blockedIf((r) => r.code === 'envelope_invalid' && /guest/.test(r.why)), () => {
  const b = bharat();
  const learned = receive(b, message(hostA2, [fresh(hostA2, E_A), ROOT_A], LEAF_B));
  if (learned.tier !== 'contact' || !b.events.some((e) => e.event === 'renewal')) return 'renewal not learned';
  return receive(b, message(hostA, chainA, LEAF_B));
});
// §14.2 rule 5 compares the chain's endpoint with the endpoint the receiver PINNED, never with where
// the call came from — this harness has no source address at all. So a stolen leaf key sends as
// Alina, from anywhere and in either form of §13.2, to every contact whose pin is still that leaf,
// until the renewal reaches them; what it cannot do is claim another address (above) or outlast a
// leaf the contact has seen superseded.
scenario('identity', 'stolen leaf key: the small form passes too, while Bharat\'s pin is the stolen leaf', residual('contact'), () => receive(bharat(), message(hostA, chainA, LEAF_B, { reference: true })).tier);
scenario('identity', 'stolen leaf key: after Alina renews, the small form naming the old leaf is asked for a chain, and the only chain it has is a guest\'s', blockedIf((r) => r.code === 'envelope_invalid' && /guest/.test(r.why)), () => {
  const b = bharatWhoHeard(); if (!b) return 'renewal not learned';
  if (receive(b, message(hostA, chainA, LEAF_B, { reference: true })).code !== 'chain_required') return 'not asked';
  return receive(b, message(hostA, chainA, LEAF_B));
});
scenario('identity', 'stolen root: re-homes Bharat under auto', residual('re-pinned, event raised'), () => {
  const b = bharat();
  const r = receive(b, update(hostM, [fresh(hostM, E_M), ROOT_A], LEAF_B));
  return r.tier === 'contact' && b.pins.get(FP_A).endpoint === E_M && b.events.some((e) => e.event === 'new_address') ? 're-pinned, event raised' : JSON.stringify(r);
});
scenario('identity', 'stolen root: held under ask', blockedIf((r) => r.tier === 'pending_new_address'), () => receive(bharat('ask'), update(hostM, [fresh(hostM, E_M), ROOT_A], LEAF_B)));
scenario('identity', 'stolen root: the owner\'s newer leaf takes priority the instant it is seen', blockedIf((r) => r.tier === 'contact' && r.endpoint === E_A), () => {
  const b = bharat();
  receive(b, update(hostM, [fresh(hostM, E_M, 2), ROOT_A], LEAF_B)); // the thief
  return receive(b, update(hostA2, [fresh(hostA2, E_A, 1), ROOT_A], LEAF_B)); // the owner, newer
});
scenario('identity', 'stolen root: the thief mints again and wins again — a fought-over root is lost', residual('re-pinned twice, two events'), () => {
  const b = bharat();
  receive(b, update(hostM, [fresh(hostM, E_M, 3), ROOT_A], LEAF_B));
  receive(b, update(hostA2, [fresh(hostA2, E_A, 2), ROOT_A], LEAF_B));
  const r = receive(b, update(hostM, [fresh(hostM, E_M, 1), ROOT_A], LEAF_B));
  return r.tier === 'contact' && b.pins.get(FP_A).endpoint === E_M && b.events.filter((e) => e.event === 'new_address').length === 3 ? 're-pinned twice, two events' : JSON.stringify(r);
});
scenario('identity', 'former host wipes the contact, the person returns from a new host', blockedIf((r) => r.tier === 'pending_new_address' && r.forced === 'tombstone'), () => {
  const b = bharat();
  removeContact(b, FP_A); // what Mallory's remove_contact from the still-valid old leaf does
  return receive(b, update(hostN, [fresh(hostN, E_N), ROOT_A], LEAF_B));
});
scenario('identity', 'former host squats the vacated address with its own root and Alina\'s name', blockedIf((r) => r.tier === 'guest' && r.addressClaim === FP_A), () => {
  const b = bharat();
  receive(b, update(hostN, [fresh(hostN, E_N), ROOT_A], LEAF_B)); // Alina moved
  return receive(b, request(hostM, [leafOf(rootM, 'Alina Rao', hostM, E_A), ROOT_M], LEAF_B, { fn: 'Alina Rao' }));
});
scenario('identity', 'former host\'s superseded leaf cannot claim any address', blockedIf((r) => r.code === 'envelope_invalid' && /guest/.test(r.why)), () => {
  const b = bharat();
  receive(b, update(hostN, [fresh(hostN, E_N), ROOT_A], LEAF_B));
  return receive(b, update(hostA, chainA, LEAF_B));
});
// §6.1: a caller at the pending tier may list its two tools, and nothing else passes before the
// owner decides. The listing is the control that must get through; the message must not.
scenario('identity', 'a contact still pending_out lists the pending tier (baseline)', blockedIf((r) => r.code === 'ok' && r.tier === 'pending' && r.method === 'tools/list'), () => {
  const b = makeNode({ path: '/bharat', leafKey: hostB.sign, chain: chainB, now: NOW });
  pin(b, FP_A, { endpoint: E_A, leafDer: LEAF_A, state: 'pending_out' });
  return receive(b, env({ senderKey: hostA.sign, senderChain: chainA, recipientLeaf: LEAF_B, method: 'tools/list', params: {} }));
});
scenario('identity', 'a contact still pending_out cannot message before accepting', blockedIf((r) => r.code === 'pending_approval'), () => {
  const b = makeNode({ path: '/bharat', leafKey: hostB.sign, chain: chainB, now: NOW });
  pin(b, FP_A, { endpoint: E_A, leafDer: LEAF_A, state: 'pending_out' });
  return receive(b, message(hostA, chainA, LEAF_B));
});
scenario('identity', 'a contact still pending_out moves before accepting (auto)', blockedIf((r) => r.tier === 'pending'), () => {
  const b = makeNode({ path: '/bharat', leafKey: hostB.sign, chain: chainB, now: NOW });
  pin(b, FP_A, { endpoint: E_A, leafDer: LEAF_A, state: 'pending_out' });
  const leafN = fresh(hostN, E_N);
  return receive(b, env({ senderKey: hostN.sign, senderChain: [leafN, ROOT_A], recipientLeaf: LEAF_B, params: { name: 'contact_accepted', arguments: { card: card([leafN, ROOT_A]), permissions: ['message.text'] } } }));
});

// ── Certificate corner cases: the profile is exact ──────────────────────────────
scenario('certificate', 'leaf with cA true', 'rule 1', () => rule([leafOf(rootA, 'Alina Rao', hostA, E_A, { cA: true }), ROOT_A]));
scenario('certificate', 'leaf without digitalSignature', 'rule 1', () => rule([leafOf(rootA, 'Alina Rao', hostA, E_A, { usage: [4] }), ROOT_A]));
scenario('certificate', 'leaf whose issuer key identifier names another root', 'rule 3', () => rule([leafOf(rootA, 'Alina Rao', hostA, E_A, { aki: parse(ROOT_M).keyId }), ROOT_A]));
scenario('certificate', 'leaf whose issuer key identifier is three bytes', 'rule 1', () => rule([leafOf(rootA, 'Alina Rao', hostA, E_A, { aki: Buffer.from([1, 2, 3]) }), ROOT_A]));
scenario('certificate', 'leaf declaring ECDSA but signed by an Ed25519 root', 'rule 3', () => rule([leafOf(rootA, 'Alina Rao', hostA, E_A, { algOid: '1.2.840.10045.4.3.2' }), ROOT_A]));
scenario('certificate', 'one algorithm inside the TBS, another outside it', 'rule 1', () => rule([leafOf(rootA, 'Alina Rao', hostA, E_A, { outerAlgOid: '1.2.840.10045.4.3.2' }), ROOT_A]));
scenario('certificate', 'an extension the profile does not list, critical', 'rule 1', () => rule([leafOf(rootA, 'Alina Rao', hostA, E_A, { extra: [{ oid: '1.3.6.1.4.1.99999.1', critical: true, value: Buffer.from('0500', 'hex') }] }), ROOT_A]));
scenario('certificate', 'an extension the profile does not list, non-critical', 'rule 1', () => rule([leafOf(rootA, 'Alina Rao', hostA, E_A, { extra: [{ oid: '1.3.6.1.4.1.99999.1', critical: false, value: Buffer.from('0500', 'hex') }] }), ROOT_A]));
scenario('certificate', 'a duplicated extension', 'rule 1', () => rule([leafOf(rootA, 'Alina Rao', hostA, E_A, { extra: [{ oid: '2.5.29.37', critical: false, value: Buffer.from('3000', 'hex') }] }), ROOT_A]));
scenario('certificate', 'certificate over 4 KiB', 'rule 1', () => rule([leafOf(rootA, 'Alina Rao', hostA, E_A, { extra: [{ oid: '1.3.6.1.4.1.99999.2', critical: false, value: Buffer.concat([Buffer.from('04821000', 'hex'), Buffer.alloc(4096)]) }] }), ROOT_A]));
scenario('certificate', 'trailing bytes after the certificate', 'rule 1', () => rule([Buffer.concat([LEAF_A, Buffer.from([0])]), ROOT_A]));
scenario('certificate', 'a padded DER length', 'rule 1', () => { const t = Buffer.concat([Buffer.from([0x30, 0x83, 0x00]), LEAF_A.subarray(1)]); return rule([t, ROOT_A]); });
// A four-octet DER length. The suite had no such shape — the padded case above is caught by the
// minimal-length check before any arithmetic — and it is the only one that can reach an
// implementation's length guard with a value near 2^32. A parser that adds `at + len` before
// comparing wraps on a 32-bit target, passes its own guard, and panics on the slice: measured in
// hdtp-identity's wasm build on 2026-09-20, `RuntimeError: unreachable` from these six bytes.
scenario('certificate', 'a four-octet DER length that overruns the buffer', 'rule 1', () => rule([Buffer.from([0x30, 0x84, 0xff, 0xff, 0xff, 0xff]), ROOT_A]));
// An ECDSA signature has a twin, (r, n − s), that anybody can compute and that VERIFIES. On a leaf it
// mints a second byte string for one certificate — same key, same fingerprint, same address, same
// notBefore — which §14.3 reads as a conflict, so a card altered in transit pins a leaf the real host
// can never match, and reading the fingerprint aloud (§3) finds nothing wrong. §14.1 admits only the
// low-S twin; this is the other one, built honestly and then swapped.
scenario('certificate', 'a P-256 leaf whose signature was swapped for its twin', 'rule 1', () => rule([leafOf(rootB, 'Bharat Mehta', hostB, E_B, { misencode: { sigTwin: true } }), ROOT_B]));
// A notBefore of 30 February. A reader that normalises dates takes it for 2 March and accepts; the
// leaf IS the TLS certificate, and no TLS stack reads that date at all.
scenario('certificate', 'a validity field that is not a date', 'rule 1', () => rule([leafOf(rootA, 'Alina Rao', hostA, E_A, { misencode: { notBefore: '260230120000Z' } }), ROOT_A]));
// An extension VALUE under another type, and a basicConstraints that reads two ways. None of the three
// implementations looked at a value's own tag, and the reference library read basicConstraints by its
// first and last elements and a pathLenConstraint by its first BYTE — so a root carrying
// SEQUENCE { TRUE, 5, 0 } was a root with pathLen 0 here and pathLen 5 to every other X.509 reader,
// and one carrying a pathLenConstraint of 128 (`02 02 00 80`) was in the profile here while both
// ports refused it. §14.1: a certificate that reads one way to one parser and another to the next.
const rootWith = (basicConstraints, label) => buildRoot({ cn: 'Alina Rao', key: rootA, notBefore: at('2026-09-01T00:00:00Z'), label, basicConstraints });
const leafUnder = (root) => rule([LEAF_A, root]);
for (const [what, o] of [
  ['a keyUsage whose value is an OCTET STRING', { retag: { oid: '2.5.29.15', tag: 0x04 } }],
  ['a subjectKeyIdentifier that is a BIT STRING', { retag: { oid: '2.5.29.14', tag: 0x03 } }],
  ['a subjectAltName that is a SET', { retag: { oid: '2.5.29.17', tag: 0x31 } }],
  ['a leaf whose basicConstraints holds a NULL', { basicConstraints: '30020500' }],
]) scenario('certificate', what, 'rule 1', () => rule([leafOf(rootA, 'Alina Rao', hostA, E_A, { misencode: o }), ROOT_A]));
scenario('certificate', 'a root whose basicConstraints reads two ways: TRUE, 5, 0', 'rule 1', () => leafUnder(rootWith('30090101ff020105020100', 'i/root_bc3')));
scenario('certificate', 'a root whose pathLenConstraint is 128', 'rule 1', () => leafUnder(rootWith('30070101ff02020080', 'i/root_pl128')));
scenario('certificate', 'exactly 398 days is accepted', 'accepted', () => rule([leafOf(rootA, 'Alina Rao', hostA, E_A, { notBefore: at('2026-09-01T00:00:00Z'), notAfter: new Date(at('2026-09-01T00:00:00Z').getTime() + 398 * D) }), ROOT_A]));
scenario('certificate', '398 days and one second is refused', 'rule 4', () => rule([leafOf(rootA, 'Alina Rao', hostA, E_A, { notBefore: at('2026-09-01T00:00:00Z'), notAfter: new Date(at('2026-09-01T00:00:00Z').getTime() + 398 * D + 1000) }), ROOT_A]));
for (const [what, uris, dns] of [
  ['userinfo in the URI', ['https://agent.alina.example@mallory.example/mcp']],
  ['uppercase host', ['https://Agent.Alina.example/mcp']],
  ['trailing slash', [E_A + '/']],
  ['http scheme', ['http://agent.alina.example/mcp']],
  ['two URIs', [E_A, E_M]],
  ['dot segment', ['https://agent.alina.example/mcp/../admin']],
  ['query string', [E_A + '?x=1']],
  ['dNSName of another host', [E_A], 'mallory.example'],
  // A host as both ports read one (their `normalHost`): letters, digits, `-` and `.`, no empty label,
  // and no IPv6 literal that holds an IPv4 address. WHATWG's URL, which the seed parses with, keeps
  // all four as written, so each was an endpoint in normal form here until 2026-09-30.
  ['an underscore in the host', ['https://agent_alina.example/mcp']],
  ['a trailing dot on the host', ['https://agent.alina.example./mcp']],
  ['an empty label in the host', ['https://agent..alina.example/mcp']],
  ['an IPv4-mapped IPv6 literal', ['https://[::ffff:102:304]/mcp']],
]) scenario('certificate', 'endpoint: ' + what, 'rule 5', () => rule([leafOf(rootA, 'Alina Rao', hostA, E_A, { uris, dnsName: dns }), ROOT_A]));

// The same exactness one layer down. DER has one encoding of each of these, and a certificate that
// spells one another way is precisely what one parser sees and the next does not — §14.1's strict DER
// and the last row of §14.5. The builder writes them; nothing else can.
for (const [what, misencode] of [
  ['a criticality BOOLEAN that is not 0xFF', { criticalTrue: [0x01] }],
  ['an explicit `critical FALSE`, which DER never encodes', { explicitFalse: OID.eku }],
  ['keyUsage carrying a bit in a second byte', { keyUsage: [0x07, 0x80, 0x80] }],
  ['keyUsage whose trailing zero bits are not removed', { keyUsage: [0x00, 0x80] }],
  ['keyUsage with an unused bit set', { keyUsage: [0x07, 0x81] }],
  ['an extension OID with a padded subidentifier', { oidFor: { oid: OID.keyUsage, der: '060455801d0f' } }],
  ['a signature-algorithm OID with a padded subidentifier', { sigAlgOid: '06042b806570' }],
  ['a commonName attribute type with a padded subidentifier', { cnOid: '060455800403' }],
  ['an extendedKeyUsage OID with a padded subidentifier', { ekuOid: '06092b0601050507800301' }],
  ['a SubjectPublicKeyInfo algorithm OID with a padded subidentifier', { spkiAlgOid: '06042b806570' }],
  ['a serial with a needless leading zero', { serial: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77] }],
  // Four more shapes hdtp-identity's contract names among what parsing refuses (parse_certificate's
  // notes), each written into the TBS before it is signed, so the signature is good and the one fault
  // is the only reason to refuse. The seed read the second and third of them until 2026-09-30.
  ['a validity with three times', { validityTimes: 3 }],
  ['an extension of four parts', { extensionParts: { oid: OID.ski, der: '05000500' } }],
  ['an extnValue that is not an OCTET STRING', { wrapperTag: { oid: OID.ski, tag: 0x03 } }],
  ['an extnValue OCTET STRING holding two TLVs', { valueTail: { oid: OID.ski, der: '0500' } }],
]) scenario('certificate', 'DER: ' + what, 'rule 1', () => rule([leafOf(rootA, 'Alina Rao', hostA, E_A, { misencode }), ROOT_A]));
// A P-256 key is read as its uncompressed point only. The compressed one is the same key under a
// second SubjectPublicKeyInfo, so a second fingerprint (§2); OpenSSL reads it, and the seed did until
// 2026-09-30.
scenario('certificate', 'DER: a P-256 key written as its compressed point', 'rule 1', () => rule([leafOf(rootB, 'Bharat Mehta', hostB, E_B, { misencode: { compressedPoint: true } }), ROOT_B]));
// §2: the fingerprint is SHA-256 over the SubjectPublicKeyInfo, so its key BIT STRING has one
// spelling, with no unused bits, and the structure holds its AlgorithmIdentifier and key and nothing
// else. The seed read the key after the unused-bits octet whatever it said, until 2026-09-30.
for (const [what, misencode] of [
  ['an Ed25519 key BIT STRING with 1 unused bit', { spkiUnusedBits: 1 }],
  ['an Ed25519 key BIT STRING with 7 unused bits', { spkiUnusedBits: 7 }],
  ['a SubjectPublicKeyInfo with a member after its key', { spkiTail: '0500' }],
]) scenario('certificate', 'DER: ' + what, 'rule 1', () => rule([leafOf(rootA, 'Alina Rao', hostA, E_A, { misencode }), ROOT_A]));
scenario('certificate', 'DER: a P-256 key BIT STRING with 1 unused bit', 'rule 1', () => rule([leafOf(rootB, 'Bharat Mehta', hostB, E_B, { misencode: { spkiUnusedBits: 1 } }), ROOT_B]));

// A root's notBefore carries no trust — its fingerprint is the identity, and rule 4 reads the root's
// notAfter and never its notBefore (§14.2). Recorded as accepted on purpose: an implementation that
// reaches for RFC 5280 path validation would refuse this, and that divergence is the interoperability
// break to avoid.
scenario('certificate', 'a root whose notBefore is years away is not a refusal', 'accepted', () =>
  rule([LEAF_A, buildRoot({ cn: 'Alina Rao', key: rootA, notBefore: at('2030-01-01T00:00:00Z'), label: 'i/root_a' })]));

// A root with the end date its person chose (§14.1). Past it, rule 4 refuses every chain under it, and
// a leaf may not outlive it, so a pinned leaf (§13.2's small form) ends no later than its root does.
const why = (chain) => { const r = validateChain(chain, { now: NOW }); return r.ok ? 'accepted' : `rule ${r.rule}: ${r.reason}`; };
const endingRoot = (notAfter) => buildRoot({ cn: 'Alina Rao', key: rootA, notBefore: at('2026-09-01T00:00:00Z'), notAfter, label: 'i/root_a' });
scenario('certificate', 'a root with an end date not yet reached (the control)', 'accepted', () =>
  why([leafOf(rootA, 'Alina Rao', hostA, E_A), endingRoot(at('2027-09-01T00:00:00Z'))]));
scenario('certificate', 'a root past its end date', 'rule 4: root has expired', () =>
  why([leafOf(rootA, 'Alina Rao', hostA, E_A, { notBefore: at('2026-01-01T00:00:00Z'), notAfter: new Date(NOW.getTime() + 30 * D) }), endingRoot(new Date(NOW.getTime() - 1000))]));
scenario('certificate', 'a leaf that outlives its root', 'rule 4: leaf outlives the root', () =>
  why([leafOf(rootA, 'Alina Rao', hostA, E_A), endingRoot(new Date(NOW.getTime() + 30 * D))]));
scenario('certificate', 'a root whose end date is before its start', 'rule 1: root notAfter is before its notBefore', () =>
  why([leafOf(rootA, 'Alina Rao', hostA, E_A), endingRoot(at('2026-08-31T23:59:59Z'))]));
scenario('reference', 'a pinned leaf that ended with its root, named in the small form, is asked for its chain', 'chain_required', () => {
  const ended = leafOf(rootA, 'Alina Rao', hostA, E_A, { notBefore: at('2026-01-01T00:00:00Z'), notAfter: new Date(NOW.getTime() - 1000) });
  const b = makeNode({ path: '/bharat', leafKey: hostB.sign, chain: chainB, now: NOW });
  pin(b, FP_A, { endpoint: E_A, leafDer: ended });
  return receive(b, message(hostA, [ended, endingRoot(new Date(NOW.getTime() - 1000))], LEAF_B, { reference: true })).code;
});

// ── Secrets ─────────────────────────────────────────────────────────────────────
const openTo = (h, e, pub = h.sign.pub) => { try { open('HDTP-SEAL-X25519', h.sign.priv, pub, Buffer.from('HDTP-SEAL-v1'), fromB64url(e.protected), fromB64url(e.enc), fromB64url(e.ct)); return 'opened'; } catch { return 'closed'; } };
scenario('secrets', 'a stolen leaf key opens traffic recorded while it was current', residual('opened'), () => openTo(hostA, message(hostB, chainB, LEAF_A)));
scenario('secrets', 'after a rekey, new traffic is closed to the old key', 'closed', () => openTo(hostA, message(hostB, chainB, fresh(hostA2, E_A)), hostA2.sign.pub));
scenario('secrets', 'the wrong suite for the recipient\'s key', 'suite does not fit the leaf', () => receive(bharat(), message(hostA, chainA, LEAF_B, { suite: 'HDTP-SEAL-X25519', recipientPub: hostA.sign.pub })).why);
scenario('secrets', 'a flipped ciphertext byte', 'does not open', () => { const e = message(hostA, chainA, LEAF_B); const ct = fromB64url(e.ct); ct[3] ^= 1; return receive(bharat(), { ...e, ct: b64url(ct) }).why; });
scenario('secrets', 'a flipped byte of the encapsulated key', 'does not open', () => { const e = message(hostA, chainA, LEAF_B); const enc = fromB64url(e.enc); enc[3] ^= 1; return receive(bharat(), { ...e, enc: b64url(enc) }).why; });
scenario('secrets', 'the header\'s exp extended after sealing', 'does not open', () => {
  const e = message(hostA, chainA, LEAF_B); const h = JSON.parse(fromB64url(e.protected).toString()); h.exp += 3600;
  return receive(bharat(), { ...e, protected: b64url(Buffer.from(JSON.stringify(h))) }).why;
});
scenario('secrets', 'sealed with a stale info string', 'does not open', () => receive(bharat(), message(hostA, chainA, LEAF_B, { info: 'HDTP-SEAL-v2' })).why);
scenario('secrets', 'Alina\'s envelope re-signed by Mallory', 'signature is not the chain\'s leaf key', () => receive(bharat(), message(hostA, chainA, LEAF_B, { signWith: hostM.sign })).why);
scenario('secrets', 'Mallory seals with Alina\'s chain inside and her own signature', 'signature is not the chain\'s leaf key', () => receive(bharat(), message(hostM, chainM, LEAF_B, { chainInside: chainA })).why);
scenario('secrets', 'the same envelope twice is acknowledged, not re-executed', blockedIf((r) => r.replayed === true), () => { const b = bharat(); const e = message(hostA, chainA, LEAF_B); receive(b, e); return receive(b, e); });
scenario('secrets', 'an envelope past its exp', 'outside the time window', () => receive(bharat(), message(hostA, chainA, LEAF_B, { ts: nowS - 1200, exp: nowS - 600 })).why);
scenario('secrets', 'an envelope ten minutes old', 'outside the time window', () => receive(bharat(), message(hostA, chainA, LEAF_B, { ts: nowS - 600, exp: nowS + 600 })).why);
scenario('secrets', 'an envelope that asks to be remembered for a year', 'exp too far from ts', () => receive(bharat(), message(hostA, chainA, LEAF_B, { ts: nowS, exp: nowS + 365 * 86_400 })).why);
scenario('secrets', 'a header with an extra member', 'header members', () => receive(bharat(), message(hostA, chainA, LEAF_B, { header: { note: 'x' } })).why);
scenario('secrets', 'a header without suite', 'header members', () => receive(bharat(), message(hostA, chainA, LEAF_B, { header: { suite: undefined } })).why);
scenario('secrets', 'an empty msg_id', 'empty msg_id', () => receive(bharat(), message(hostA, chainA, LEAF_B, { msgId: '' })).why);
scenario('secrets', 'a result envelope dispatched as a request', 'not a request', () => receive(bharat(), message(hostA, chainA, LEAF_B, { cty: 'application/hdtp-result+json' })).why);
scenario('secrets', 'an envelope for Alina\'s key delivered at Mallory\'s path on a shared host', 'key held for another identity', () => {
  const a = makeNode({ path: '/alina', leafKey: hostA.sign, chain: chainA, now: NOW }), m = makeNode({ path: '/mallory', leafKey: hostM.sign, chain: chainM, now: NOW });
  return receive(m, message(hostB, chainB, LEAF_A), { siblings: [a] }).why;
});
scenario('secrets', 'a guessed kid learns nothing', 'unknown kid', () => receive(bharat(), message(hostA, chainA, LEAF_M)).why);
scenario('secrets', 'a former key of a still-served identity gets the current chain', 'certificate_renewed', () => {
  const a = makeNode({ path: '/alina', leafKey: hostA.sign, chain: chainA, now: NOW });
  renew(a, hostA2.sign, [fresh(hostA2, E_A), ROOT_A]);
  a.now = new Date(at('2027-09-01T00:00:00Z').getTime() + D); forgetKeysPast(a);
  return receive(a, message(hostB, chainB, LEAF_A, { ts: Math.floor(a.now / 1000) })).code;
});

// §2 (Renewal) and §13.3 step 3: a contact the renewal has not reached keeps sealing to the leaf it
// pinned, and the host keeps that key until the leaf's notAfter so the envelope still opens. What the
// rule costs is the stolen-leaf residual of §14.5, per contact, until the next exchange: the envelope
// the host accepts opens just as well for whoever holds the key the host kept. The exchange is the
// remedy — a host carries its chain in its first envelope to each contact after a renewal (§13.2),
// which is the step measured here — and what the contact seals to from then on is a leaf the
// superseded key cannot open, however the thief tries to roll the pin back.
const alinaRenewed = () => {
  const a = makeNode({ path: '/alina', leafKey: hostA.sign, chain: chainA, now: NOW });
  pin(a, fingerprintOf(parse(ROOT_B)), { endpoint: E_B, leafDer: LEAF_B });
  renew(a, hostA2.sign, [fresh(hostA2, E_A), ROOT_A]);
  return a;
};
scenario('secrets', 'stale sender: an envelope sealed to the superseded key still opens at the host, until that leaf\'s notAfter (the control)', blockedIf((r) => r.tier === 'contact'), () => receive(alinaRenewed(), message(hostB, chainB, LEAF_A)));
scenario('secrets', 'stale sender: the envelope the host accepted after the renewal opens for whoever holds the superseded key', residual('opened'), () => {
  const e = message(hostB, chainB, LEAF_A);
  if (receive(alinaRenewed(), e).tier !== 'contact') return 'not accepted';
  return openTo(hostA, e);
});
scenario('secrets', 'stale sender: once the renewal reaches Bharat, what he seals next is closed to the superseded key', 'closed', () => {
  const b = bharatWhoHeard(); if (!b) return 'renewal not learned';
  return openTo(hostA, message(hostB, chainB, b.pins.get(FP_A).leafDer));
});
scenario('secrets', 'stale sender: Mallory replays the superseded chain to roll Bharat back onto the key she holds; what he seals next is still closed to it', 'closed', () => {
  const b = bharatWhoHeard(); if (!b) return 'renewal not learned';
  const r = receive(b, message(hostA, chainA, LEAF_B));
  if (!(r.code === 'envelope_invalid' && /guest/.test(r.why))) return 'not refused as a guest: ' + JSON.stringify(r);
  return openTo(hostA, message(hostB, chainB, b.pins.get(FP_A).leafDer));
});
scenario('secrets', 'HPKE ephemeral reuse leaks the XOR of two plaintexts; production sealing cannot take a seed', (got) => (got === 'leaks with a fixed seed, differs without' ? 'blocked' : 'REPRODUCES'), () => {
  const p1 = Buffer.alloc(32, 0x41), p2 = Buffer.alloc(32, 0x42), aad = Buffer.from('aad'), info = Buffer.from('HDTP-SEAL-v1');
  const c1 = sealDeterministic('HDTP-SEAL-X25519', hostA.sign.pub, info, aad, p1, seed('same')), c2 = sealDeterministic('HDTP-SEAL-X25519', hostA.sign.pub, info, aad, p2, seed('same'));
  const x = Buffer.alloc(32); for (let i = 0; i < 32; i++) x[i] = c1.ct[i] ^ c2.ct[i];
  const leaks = x.equals(Buffer.alloc(32, 0x41 ^ 0x42)) && c1.enc.equals(c2.enc);
  const d1 = seal('HDTP-SEAL-X25519', hostA.sign.pub, info, aad, p1), d2 = seal('HDTP-SEAL-X25519', hostA.sign.pub, info, aad, p1);
  return leaks && !d1.enc.equals(d2.enc) && seal.length === 5 ? 'leaks with a fixed seed, differs without' : 'unexpected';
});
scenario('secrets', 'a low-order X25519 recipient point', blockedIf((got) => /threw/.test(got)), () => {
  const zero = createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b656e032100', 'hex'), Buffer.alloc(32)]), format: 'der', type: 'spki' });
  seal('HDTP-SEAL-X25519', zero, Buffer.from('HDTP-SEAL-v1'), Buffer.alloc(0), Buffer.from('x'));
  return 'sealed';
});
scenario('secrets', 'the root private keys are not in the spec', 'absent', () => {
  const spec = [...versions(), 'draft'].map((v) => readSpec(root, v)).join('');
  const roots = [ed25519FromSeed(seed('root/alina')), p256FromSeed(seed('root/bharat'))].map((k) => pkcs8Of(k.priv).toString('hex'));
  return roots.some((h) => spec.includes(h)) ? 'present' : 'absent';
});

// §13.1 names the header's members and their types. A closed set of names exists so two
// implementations cannot disagree about what was signed; latitude in the types reopens exactly that.
scenario('secrets', 'a header whose ts and exp are strings', 'header member types', () => receive(bharat(), message(hostA, chainA, LEAF_B, { header: { ts: String(nowS), exp: String(nowS + 600) } })).why);

// `sig` covers `protected ‖ enc ‖ ct` with no length prefixes, so moving a byte across the enc/ct
// boundary leaves the signed bytes identical. What refuses it is `enc` being the suite's own length.
scenario('secrets', 'a byte moved from the encapsulated key into the ciphertext', 'encapsulated key is not the suite\'s length', () => {
  const e = message(hostA, chainA, LEAF_B), enc = fromB64url(e.enc), ct = fromB64url(e.ct);
  return receive(bharat(), { ...e, enc: b64url(enc.subarray(0, enc.length - 1)), ct: b64url(Buffer.concat([enc.subarray(enc.length - 1), ct])) }).why;
});

// ── The small form: a leaf named by fingerprint (§13.2) ─────────────────────────
const size = (e) => JSON.stringify(e).length;
scenario('reference', 'a known contact from its known host sends the small form and is a contact', blockedIf((r) => r.tier === 'contact' && r.form === 'leaf'), () => receive(bharat(), message(hostA, chainA, LEAF_B, { reference: true })));
scenario('reference', 'the small form is a fraction of the full one', blockedIf((got) => got < 0.45), () => size(message(hostA, chainA, LEAF_B, { reference: true })) / size(message(hostA, chainA, LEAF_B)));
scenario('reference', 'an unknown leaf named by fingerprint is asked for its chain', 'chain_required', () => receive(bharat(), message(hostM, chainM, LEAF_B, { reference: true })).code);
scenario('reference', 'a known leaf named with a bad signature gets the same answer, so nothing leaks', 'chain_required', () => receive(bharat(), message(hostA, chainA, LEAF_B, { reference: true, signWith: hostM.sign })).code);
scenario('reference', 'a blocked contact naming its leaf is answered as a stranger would be', 'chain_required', () => {
  const b = bharat(); pin(b, FP_M, { endpoint: E_M, leafDer: LEAF_M, state: 'blocked' });
  return receive(b, message(hostM, chainM, LEAF_B, { reference: true })).code;
});
scenario('reference', 'after chain_required, the chain is sent and the leaf is learned', blockedIf((r) => r.tier === 'contact' && r.form === 'chain'), () => {
  const b = bharat();
  const leafA2 = fresh(hostA2, E_A);
  if (receive(b, message(hostA2, [leafA2, ROOT_A], LEAF_B, { reference: true })).code !== 'chain_required') return 'not asked';
  const r = receive(b, message(hostA2, [leafA2, ROOT_A], LEAF_B));
  return r.tier === 'contact' && b.events.some((e) => e.event === 'renewal') && receive(b, message(hostA2, [leafA2, ROOT_A], LEAF_B, { reference: true })).tier === 'contact' ? r : 'not learned';
});
scenario('reference', 'a chain with an older leaf does not roll the pin back', blockedIf((r) => r.code === 'envelope_invalid' && /guest/.test(r.why)), () => {
  const b = bharat();
  receive(b, message(hostA2, [fresh(hostA2, E_A), ROOT_A], LEAF_B)); // renewal learned
  return receive(b, message(hostA, chainA, LEAF_B)); // the older leaf, explicit chain
});
scenario('reference', 'both chain and leaf in one plaintext', 'plaintext members', () => receive(bharat(), message(hostA, chainA, LEAF_B, { both: true })).why);
scenario('reference', 'a chain that fails is refused, never asked for again', blockedIf((r) => r.code === 'envelope_invalid'), () => receive(bharat(), message(hostA, [LEAF_A, ROOT_M], LEAF_B)));
scenario('reference', 'the small form cannot move a contact to a new address', blockedIf((r) => r.code === 'chain_required'), () => receive(bharat(), update(hostN, [fresh(hostN, E_N), ROOT_A], LEAF_B, { reference: true })));
scenario('reference', 'the small form against a held leaf that has expired is asked for the chain', 'chain_required', () => {
  const b = bharat(); b.now = new Date(at('2027-09-02T00:00:00Z')); // LEAF_A expired yesterday
  return receive(b, message(hostA, chainA, LEAF_B, { reference: true, ts: Math.floor(b.now / 1000) })).code;
});
scenario('reference', 'a flood of guessed fingerprints consumes nothing: every answer is chain_required and no state moves', blockedIf((got) => got === 'no state moved'), () => {
  const b = bharat(); const before = JSON.stringify([...b.pins]) + b.seen.size + b.pending.length + b.events.length;
  let all = true;
  for (let i = 0; i < 200; i++) {
    // The guess IS what the envelope names: a fingerprint of nobody's leaf, signed by Mallory's key.
    const guess = 'sha256:' + b64url(seed('guess/' + i));
    const e = env({ senderKey: hostM.sign, senderChain: chainM, recipientLeaf: LEAF_B, params: { name: 'send_message', arguments: { msg_id: 'm', text: 'x' } }, reference: true, referenceFingerprint: guess });
    all &&= receive(b, e).code === 'chain_required';
  }
  return all && JSON.stringify([...b.pins]) + b.seen.size + b.pending.length + b.events.length === before ? 'no state moved' : 'state moved';
});

// ── Guests, cards, oracles ──────────────────────────────────────────────────────
scenario('guest', 'a sealed tools/list from a stranger', 'guest may only redeem or request', () => receive(bharat(), env({ senderKey: hostM.sign, senderChain: chainM, recipientLeaf: LEAF_B, method: 'tools/list', params: {} })).why);
scenario('guest', 'a guest whose card carries a different certificate than the chain', 'guest card certificate is not the chain\'s leaf', () => {
  const other = leafOf(rootM, 'Alina Rao', hostM, E_M, { notBefore: at('2026-08-01T00:00:00Z') });
  return receive(bharat(), env({ senderKey: hostM.sign, senderChain: chainM, recipientLeaf: LEAF_B, params: { name: 'request_contact', arguments: { card: encodeCard({ fn: 'M', cert: other }) } } })).why;
});
// §14.5: "a guest's endpoint never equals the receiver's own". A stranger who puts this node's own
// address in their leaf would otherwise be pinned to it, and every reply would come back here.
scenario('guest', 'a guest whose leaf names the receiver\'s own address', 'guest endpoint is this node\'s own address', () =>
  receive(bharat(), request(hostM, [leafOf(rootM, 'Alina Rao', hostM, E_B), ROOT_M], LEAF_B)).why);

scenario('guest', 'a blocked sender is answered exactly as an unknown one', 'same', () => {
  const b = bharat(); pin(b, FP_M, { endpoint: E_M, leafDer: LEAF_M, state: 'blocked' });
  const blocked = receive(b, message(hostM, chainM, LEAF_B)), unknown = receive(bharat(), message(hostM, chainM, LEAF_B));
  return blocked.code === unknown.code && blocked.why === unknown.why ? 'same' : 'different';
});
scenario('card', 'a folded certificate round-trips', 'ok', () => (decodeCard(card(chainA)).cert.equals(LEAF_A) ? 'ok' : 'mismatch'));
scenario('card', 'two X-HDTP-CERT properties', 'bad_request', () => decodeCard(card(chainA).replace('END:VCARD', 'X-HDTP-CERT:' + b64url(LEAF_M) + '\r\nEND:VCARD')).error);
scenario('card', 'an expired leaf is accepted at intake', 'expired but accepted', () => { const c = decodeCard(encodeCard({ fn: 'A', cert: leafOf(rootA, 'Alina Rao', hostA, E_A, { notBefore: at('2025-06-01T00:00:00Z'), notAfter: at('2026-06-01T00:00:00Z') }) })); return c.error ? c.error : c.expired ? 'expired but accepted' : 'not expired'; });
scenario('card', 'an unknown endpoint property on a card is ignored; the address comes from the leaf', E_A, () => decodeCard(card(chainA, 'Alina', ['X-HDTP-ENDPOINT:' + E_M])).endpoint);
scenario('card', 'a card without a certificate', 'bad_request', () => decodeCard('BEGIN:VCARD\r\nVERSION:4.0\r\nFN:X\r\nX-HDTP-VERSION:1\r\nEND:VCARD\r\n').error);
// §14.1: a key identifier is 32 bytes. A card turns the leaf's into the identity a person is shown, so
// three bytes became `sha256:AQID` — a contact no chain could ever satisfy.
scenario('card', 'a card whose leaf names its issuer in three bytes', 'bad_request', () => decodeCard(encodeCard({ fn: 'A', cert: leafOf(rootA, 'Alina Rao', hostA, E_A, { aki: Buffer.from([1, 2, 3]) }) })).error);
scenario('card', 'a card stays under a kilobyte', blockedIf((got) => got < 1024), () => card(chainA).length);

// ── Chain confusion: §14.2 takes exactly two certificates, in one order ──────────
// Every shape below is a path an X.509 verifier that was NOT written to this profile
// would take: a single certificate, a bundle, an issuer reached through a CA. §14.2 is
// deliberately not RFC 5280 path validation — it is two certificates, the second
// self-signed, and its fingerprint is the identity. These lock that door from inside.
scenario('chain', 'a chain of one certificate', 'rule 1', () => rule([LEAF_A]));
scenario('chain', 'a chain of three certificates', 'rule 1', () => rule([LEAF_A, ROOT_A, ROOT_A]));
scenario('chain', 'an empty chain', 'rule 1', () => rule([]));
scenario('chain', 'the leaf presented as its own root', 'rule 1', () => rule([LEAF_A, LEAF_A]));
scenario('chain', 'the root presented as its own leaf', 'rule 1', () => rule([ROOT_A, ROOT_A]));
scenario('chain', 'the chain in reverse order', 'rule 1', () => rule([ROOT_A, LEAF_A]));
// A CA-signed intermediate in the root slot is the whole of WebPKI asking to be let in:
// accept it and any public CA could mint an identity. Rule 2 wants the root self-signed,
// so there is no hierarchy to climb and no authority above the person.
scenario('chain', 'an intermediate posing as the root', 'rule 1', () =>
  rule([LEAF_A, buildLeaf({ cn: 'Alina Rao', rootCn: 'Alina Rao', root: rootM, hostKey: rootA, endpoint: E_A, notBefore: at('2026-09-01T00:00:00Z'), notAfter: at('2027-09-01T00:00:00Z'), cA: true, usage: [5], label: 'i/intermediate' })]));

// ── Time: the two windows, at their edges ───────────────────────────────────────
// Rule 4 checks the leaf's dates and only the leaf's; §13.3 checks the envelope's. Both
// have an exact boundary, and a boundary nothing tests is a boundary that drifts.
scenario('time', 'a leaf that is not valid yet', 'rule 4', () => rule([leafOf(rootA, 'Alina Rao', hostA, E_A, { notBefore: new Date(NOW.getTime() + H), notAfter: new Date(NOW.getTime() + 300 * D) }), ROOT_A]));
scenario('time', 'a leaf that expired yesterday', 'rule 4', () => rule([leafOf(rootA, 'Alina Rao', hostA, E_A, { notBefore: at('2025-01-01T00:00:00Z'), notAfter: new Date(NOW.getTime() - D) }), ROOT_A]));
scenario('time', 'an envelope exactly 300 seconds old is still inside the window', blockedIf((r) => r.tier === 'contact'), () => receive(bharat(), message(hostA, chainA, LEAF_B, { ts: nowS - 300, exp: nowS + 300 })));
scenario('time', 'one second past that', 'outside the time window', () => receive(bharat(), message(hostA, chainA, LEAF_B, { ts: nowS - 301, exp: nowS + 300 })).why);
scenario('time', 'an envelope exactly 300 seconds ahead is still inside the window', blockedIf((r) => r.tier === 'contact'), () => receive(bharat(), message(hostA, chainA, LEAF_B, { ts: nowS + 300, exp: nowS + 900 })));
scenario('time', 'one second past that, in the other direction', 'outside the time window', () => receive(bharat(), message(hostA, chainA, LEAF_B, { ts: nowS + 301, exp: nowS + 900 })).why);

// ── The carrier: a MITM by construction ─────────────────────────────────────────
// In edge mode the TLS ends at the edge, so a party that can read, drop, reorder, replay
// and ANSWER every call is not a hypothetical position an attacker must reach — it is the
// deployment. These say what that party still cannot do.
scenario('carrier', 'a v: 2 header, a version that does not exist', 'version or suite', () => receive(bharat(), message(hostA, chainA, LEAF_B, { header: { v: 2 } })).why);
scenario('carrier', 'a header claiming a version that does not exist yet', 'version or suite', () => receive(bharat(), message(hostA, chainA, LEAF_B, { header: { v: 3 } })).why);
// §13.1: a member has ONE spelling. `sig` covers the DECODED bytes, so every other spelling a reader
// forgives — a character it skips, padding, a line break, a last character with its spare bits set —
// is a second envelope that verifies. Each of these is a REAL envelope, honestly sealed and signed.
const respelled = (s) => s.slice(0, -1) + 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'['ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'.indexOf(s.at(-1)) | 1];
scenario('carrier', 'a real envelope whose protected carries a stray character', 'protected is not JSON', () => { const m = message(hostA, chainA, LEAF_B); return receive(bharat(), { ...m, protected: m.protected + '!' }).why; });
scenario('carrier', 'a real envelope whose enc is padded', 'does not open', () => { const m = message(hostA, chainA, LEAF_B); return receive(bharat(), { ...m, enc: m.enc + '='.repeat((4 - (m.enc.length % 4)) % 4 || 4) }).why; });
scenario('carrier', 'a real envelope whose ct has a line break in it', 'does not open', () => { const m = message(hostA, chainA, LEAF_B); return receive(bharat(), { ...m, ct: m.ct.slice(0, 8) + '\n' + m.ct.slice(8) }).why; });
scenario('carrier', 'a real envelope whose signature is spelled with its spare bits set', "signature is not the chain's leaf key", () => { const m = message(hostA, chainA, LEAF_B); return receive(bharat(), { ...m, sig: respelled(m.sig) }).why; });
scenario('carrier', 'a card naming a major that is not 1', 'bad_request', () => decodeCard(card(chainA).replace('X-HDTP-VERSION:1', 'X-HDTP-VERSION:2')).error);
// §3: any other X-HDTP-* property — an endpoint, a key, a gateway — is ignored. A carrier that
// appends one to a card in flight must move nothing.
scenario('carrier', 'X-HDTP-KEY appended to a card in flight is ignored', blockedIf((r) => r.root === FP_A && r.endpoint === E_A), () => {
  const c = decodeCard(card(chainA).replace('END:VCARD', 'X-HDTP-KEY:sha256:AAAA\r\nEND:VCARD'));
  return { root: c.root, endpoint: c.endpoint };
});
scenario('carrier', 'X-HDTP-GATEWAY appended to a card in flight buys no store-and-forward', blockedIf((r) => r.endpoint === E_A && r.gateway === undefined), () => {
  const c = decodeCard(card(chainA).replace('END:VCARD', 'X-HDTP-GATEWAY:' + E_M + '\r\nEND:VCARD'));
  return { endpoint: c.endpoint, gateway: c.gateway };
});
// §13.5: the carrier sees kid, timing and sizes — and NOT who sent the message. The chain
// rides inside the ciphertext, so it can neither be read nor stripped to force the small
// form: the wire bytes carry no certificate at all.
scenario('carrier', 'the sender\'s chain is not on the wire to be read or stripped', 'not on the wire', () => {
  const e = message(hostA, chainA, LEAF_B), wire = JSON.stringify(e);
  return wire.includes(b64url(LEAF_A)) || wire.includes(b64url(ROOT_A)) ? 'visible to the carrier' : 'not on the wire';
});
// Reflection: the carrier bounces a request back at whoever sent it. The envelope is sealed
// to the RECIPIENT's leaf key, which the sender does not hold, so it does not even open.
scenario('carrier', 'a request reflected back at its own sender', 'unknown kid', () => {
  const a = makeNode({ path: '/alina', leafKey: hostA.sign, chain: chainA, now: NOW });
  pin(a, fingerprintOf(parse(ROOT_B)), { endpoint: E_B, leafDer: LEAF_B });
  return receive(a, message(hostA, chainA, LEAF_B)).why;
});

// ── Report ──────────────────────────────────────────────────────────────────────
let last = '';
for (const r of results) {
  if (r.category !== last) { console.log(`\n${r.category}`); last = r.category; }
  console.log(`  ${r.verdict.padEnd(10)} ${r.name}${r.verdict === 'REPRODUCES' ? '  → ' + r.got : ''}`);
}
const count = (v) => results.filter((r) => r.verdict === v).length;
console.log(`\n${results.length} scenarios: ${count('blocked')} blocked, ${count('residual')} residual by decision, ${count('REPRODUCES')} reproduce`);
process.exit(count('REPRODUCES') ? 1 : 0);
