// Intrusion scenarios against the seed implementation: Mallory holds each artifact she could steal
// and tries what it lets her do. Every scenario states what the spec says should happen.
//   blocked    — the attack fails where the spec says it fails
//   residual   — the attack succeeds, and §14.5 already says so and bounds it
//   REPRODUCES — the attack succeeds and nothing in the spec stops it: a finding
import { readFileSync } from 'node:fs';
import { createPublicKey } from 'node:crypto';
import { seed, ed25519FromSeed, p256FromSeed, pkcs8Of, fingerprint, b64url, fromB64url } from './lib/keys.mjs';
import { buildRoot, buildLeaf, validateChain, parse, fingerprintOf } from './lib/x509.mjs';
import { seal, open } from './lib/hpke.mjs';
import { encodeCard, decodeCard } from './lib/card.mjs';
import { sealEnvelope, makeNode, renew, forgetKeysPast, pin, removeContact, receive } from './lib/envelope.mjs';

const at = (iso) => new Date(iso);
const NOW = at('2026-09-13T12:00:00Z'), nowS = Math.floor(NOW / 1000);
const H = 3_600_000, D = 86_400_000;
const E_A = 'https://agent.alina.example/mcp', E_B = 'https://agent.bharat.example/mcp', E_M = 'https://mallory.example/mcp', E_N = 'https://alina.pact.contact/alina/mcp';

// The cast. Every key derives from a label, like the vectors.
const rootA = ed25519FromSeed(seed('intrude/root/alina')), rootB = p256FromSeed(seed('intrude/root/bharat')), rootM = ed25519FromSeed(seed('intrude/root/mallory'));
const hostA = ed25519FromSeed(seed('intrude/host/alina')), hostA2 = ed25519FromSeed(seed('intrude/host/alina/2')), hostN = ed25519FromSeed(seed('intrude/host/alina/new'));
const hostB = p256FromSeed(seed('intrude/host/bharat')), hostM = ed25519FromSeed(seed('intrude/host/mallory'));
const leafOf = (root, rootCn, hostKey, endpoint, o = {}) => buildLeaf({ cn: o.cn ?? rootCn, rootCn, root, hostKey, endpoint, notBefore: o.notBefore ?? at('2026-09-01T00:00:00Z'), notAfter: o.notAfter ?? at('2027-09-01T00:00:00Z'), label: o.label ?? endpoint + (o.cn ?? '') + (o.notBefore ?? ''), ...o });
const ROOT_A = buildRoot({ cn: 'Alina Rao', key: rootA, notBefore: at('2026-09-01T00:00:00Z'), label: 'i/root_a' });
const ROOT_B = buildRoot({ cn: 'Bharat Mehta', key: rootB, notBefore: at('2026-09-01T00:00:00Z'), label: 'i/root_b' });
const ROOT_M = buildRoot({ cn: 'Alina Rao', key: rootM, notBefore: at('2026-09-01T00:00:00Z'), label: 'i/root_m' }); // same name, on purpose
const LEAF_A = leafOf(rootA, 'Alina Rao', hostA, E_A), LEAF_B = leafOf(rootB, 'Bharat Mehta', hostB, E_B), LEAF_M = leafOf(rootM, 'Alina Rao', hostM, E_M);
const chainA = [LEAF_A, ROOT_A], chainB = [LEAF_B, ROOT_B], chainM = [LEAF_M, ROOT_M];
const FP_A = fingerprintOf(parse(ROOT_A)), FP_M = fingerprintOf(parse(ROOT_M));

let n = 0;
const msgId = () => 'i-' + (++n);
const env = (o) => sealEnvelope({ ts: nowS, msgId: msgId(), ...o });
const card = (chain, fn = 'Alina Rao', extra) => encodeCard({ fn, cert: chain[0], seal: 'required', extra });
const request = (senderKey, chain, recipientPub, o = {}) => env({ senderKey, senderChain: chain, recipientLeafPub: recipientPub, params: { name: 'request_contact', arguments: { card: card(chain, o.fn, o.extra), note: 'hi' } }, ...o });
const message = (senderKey, chain, recipientPub, o = {}) => env({ senderKey, senderChain: chain, recipientLeafPub: recipientPub, params: { name: 'send_message', arguments: { msg_id: 'm', text: 'hello' } }, ...o });
const update = (senderKey, chain, recipientPub, o = {}) => env({ senderKey, senderChain: chain, recipientLeafPub: recipientPub, params: { name: 'update_contact', arguments: { card: card(chain) } }, ...o });

function bharat(acceptNewHosts = 'auto') {
  const node = makeNode({ path: '/bharat', leafKey: hostB, chain: chainB, now: NOW, acceptNewHosts });
  pin(node, FP_A, { endpoint: E_A, leafDer: LEAF_A });
  return node;
}
const rule = (chain, o = {}) => { const r = validateChain(chain, { now: NOW, ...o }); return r.ok ? 'accepted' : 'rule ' + r.rule; };

const results = [];
const scenario = (category, name, expect, fn) => {
  let got, error = null;
  try { got = fn(); } catch (e) { got = 'threw: ' + e.message; error = e; }
  const verdict = typeof expect === 'function' ? expect(got) : (got === expect ? 'blocked' : 'REPRODUCES');
  results.push({ category, name, got: String(got), verdict });
  void error;
};
const residual = (label) => (got) => (got === label ? 'residual' : 'REPRODUCES');
const blockedIf = (pred) => (got) => (pred(got) ? 'blocked' : 'REPRODUCES');

// ── Identity theft ──────────────────────────────────────────────────────────────
scenario('identity', 'a stranger at a fresh address is a plain guest (baseline)', blockedIf((r) => r.tier === 'guest' && !r.addressClaim), () => receive(bharat(), request(hostM, chainM, hostB.pub)));
scenario('identity', 'Mallory, own root, claims Alina\'s address in her leaf', blockedIf((r) => r.tier === 'guest' && r.addressClaim === FP_A), () => {
  const leaf = leafOf(rootM, 'Alina Rao', hostM, E_A);
  return receive(bharat(), request(hostM, [leaf, ROOT_M], hostB.pub));
});
scenario('identity', 'Alina\'s leaf presented under Mallory\'s root', 'rule 3', () => rule([LEAF_A, ROOT_M]));
scenario('identity', 'one byte of Alina\'s leaf changed', 'rule 3', () => { const t = Buffer.from(LEAF_A); t[t.indexOf(Buffer.from('Alina Rao')) + 1] ^= 1; return rule([t, ROOT_A]); });
scenario('identity', 'Mallory\'s root with the same display name', blockedIf((r) => r.tier === 'guest' && r.root === FP_M), () => receive(bharat(), request(hostM, chainM, hostB.pub, { fn: 'Alina Rao' })));
scenario('identity', 'stolen leaf key certified under Mallory\'s own root', blockedIf((r) => r.tier === 'guest'), () => receive(bharat(), request(hostA, [leafOf(rootM, 'Alina Rao', hostA, E_M), ROOT_M], hostB.pub)));
scenario('identity', 'stolen leaf key: sends as Alina while the leaf lives', residual('contact'), () => receive(bharat(), message(hostA, chainA, hostB.pub)).tier);
scenario('identity', 'stolen leaf key: after Alina renews with a fresh key, the old chain is a guest', blockedIf((r) => r.code === 'envelope_invalid' && /guest/.test(r.why)), () => {
  const b = bharat();
  const leafA2 = leafOf(rootA, 'Alina Rao', hostA2, E_A, { notBefore: new Date(NOW - H), notAfter: new Date(NOW + 365 * D) });
  const learned = receive(b, message(hostA2, [leafA2, ROOT_A], hostB.pub));
  if (learned.tier !== 'contact' || !b.events.some((e) => e.event === 'renewal')) return 'renewal not learned';
  return receive(b, message(hostA, chainA, hostB.pub));
});
scenario('identity', 'stolen root: re-homes Bharat under auto', residual('re-pinned, event raised'), () => {
  const b = bharat();
  const leafM = leafOf(rootA, 'Alina Rao', hostM, E_M, { notBefore: new Date(NOW - H), notAfter: new Date(NOW + 365 * D) });
  const r = receive(b, update(hostM, [leafM, ROOT_A], hostB.pub));
  return r.tier === 'contact' && b.pins.get(FP_A).endpoint === E_M && b.events.some((e) => e.event === 'new_address') ? 're-pinned, event raised' : JSON.stringify(r);
});
scenario('identity', 'stolen root: held under ask', blockedIf((r) => r.tier === 'pending_new_address'), () => {
  const leafM = leafOf(rootA, 'Alina Rao', hostM, E_M, { notBefore: new Date(NOW - H), notAfter: new Date(NOW + 365 * D) });
  return receive(bharat('ask'), update(hostM, [leafM, ROOT_A], hostB.pub));
});
scenario('identity', 'stolen root: the flapping war is dampened (second move inside 30 days is asked)', blockedIf((r) => r.tier === 'pending_new_address' && r.forced === 'flapping'), () => {
  const b = bharat();
  receive(b, update(hostM, [leafOf(rootA, 'Alina Rao', hostM, E_M, { notBefore: new Date(NOW - 2 * H), notAfter: new Date(NOW + 365 * D) }), ROOT_A], hostB.pub));
  return receive(b, update(hostA2, [leafOf(rootA, 'Alina Rao', hostA2, E_A, { notBefore: new Date(NOW - H), notAfter: new Date(NOW + 365 * D) }), ROOT_A], hostB.pub));
});
scenario('identity', 'former host wipes the contact, the person returns from a new host', blockedIf((r) => r.tier === 'pending_new_address' && r.forced === 'tombstone'), () => {
  const b = bharat();
  removeContact(b, FP_A); // what Mallory's remove_contact from the still-valid old leaf does
  const leafN = leafOf(rootA, 'Alina Rao', hostN, E_N, { notBefore: new Date(NOW - H), notAfter: new Date(NOW + 365 * D) });
  return receive(b, update(hostN, [leafN, ROOT_A], hostB.pub));
});
scenario('identity', 'former host squats the vacated address with its own root and Alina\'s name', blockedIf((r) => r.tier === 'guest' && r.addressClaim === FP_A), () => {
  const b = bharat();
  receive(b, update(hostN, [leafOf(rootA, 'Alina Rao', hostN, E_N, { notBefore: new Date(NOW - H), notAfter: new Date(NOW + 365 * D) }), ROOT_A], hostB.pub)); // Alina moved
  return receive(b, request(hostM, [leafOf(rootM, 'Alina Rao', hostM, E_A), ROOT_M], hostB.pub, { fn: 'Alina Rao' }));
});
scenario('identity', 'former host\'s superseded leaf cannot claim any address', blockedIf((r) => r.code === 'envelope_invalid' && /guest/.test(r.why)), () => {
  const b = bharat();
  receive(b, update(hostN, [leafOf(rootA, 'Alina Rao', hostN, E_N, { notBefore: new Date(NOW - H), notAfter: new Date(NOW + 365 * D) }), ROOT_A], hostB.pub));
  return receive(b, update(hostA, chainA, hostB.pub));
});
scenario('identity', 'a contact still pending_out moves before accepting (auto)', blockedIf((r) => r.tier === 'pending'), () => {
  const b = makeNode({ path: '/bharat', leafKey: hostB, chain: chainB, now: NOW });
  pin(b, FP_A, { endpoint: E_A, leafDer: LEAF_A, state: 'pending_out' });
  const leafN = leafOf(rootA, 'Alina Rao', hostN, E_N, { notBefore: new Date(NOW - H), notAfter: new Date(NOW + 365 * D) });
  return receive(b, env({ senderKey: hostN, senderChain: [leafN, ROOT_A], recipientLeafPub: hostB.pub, params: { name: 'contact_accepted', arguments: { card: card([leafN, ROOT_A]), permissions: ['message.text'] } } }));
});

// ── Certificate corner cases ────────────────────────────────────────────────────
scenario('certificate', 'leaf with cA true', 'rule 3', () => rule([leafOf(rootA, 'Alina Rao', hostA, E_A, { cA: true }), ROOT_A]));
scenario('certificate', 'leaf without digitalSignature', 'rule 3', () => rule([leafOf(rootA, 'Alina Rao', hostA, E_A, { usage: [4] }), ROOT_A]));
scenario('certificate', 'leaf whose issuer key identifier names another root', 'rule 3', () => rule([leafOf(rootA, 'Alina Rao', hostA, E_A, { aki: parse(ROOT_M).keyId }), ROOT_A]));
scenario('certificate', 'leaf declaring ECDSA but signed by an Ed25519 root', 'rule 3', () => rule([leafOf(rootA, 'Alina Rao', hostA, E_A, { algOid: '1.2.840.10045.4.3.2' }), ROOT_A]));
scenario('certificate', 'unknown critical extension', 'rule 1', () => rule([leafOf(rootA, 'Alina Rao', hostA, E_A, { extra: [{ oid: '1.3.6.1.4.1.99999.1', critical: true, value: Buffer.from('0500', 'hex') }] }), ROOT_A]));
scenario('certificate', 'certificate over 4 KiB', 'rule 1', () => rule([leafOf(rootA, 'Alina Rao', hostA, E_A, { extra: [{ oid: '1.3.6.1.4.1.99999.2', critical: false, value: Buffer.concat([Buffer.from('048210 00'.replace(/ /g, ''), 'hex'), Buffer.alloc(4096)]) }] }), ROOT_A]));
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
]) scenario('certificate', 'endpoint: ' + what, 'rule 5', () => rule([leafOf(rootA, 'Alina Rao', hostA, E_A, { uris, dnsName: dns }), ROOT_A]));

// ── Secrets ─────────────────────────────────────────────────────────────────────
scenario('secrets', 'stolen leaf key opens traffic recorded while it was current', residual('opened'), () => {
  const e = message(hostB, chainB, hostA.pub);
  try { open('PACT-SEAL-X25519', hostA.priv, hostA.pub, Buffer.from('PACT-SEAL-v2'), fromB64url(e.protected), fromB64url(e.enc), fromB64url(e.ct)); return 'opened'; } catch { return 'closed'; }
});
scenario('secrets', 'after a rekey, new traffic is closed to the old key', 'closed', () => {
  const e = message(hostB, chainB, hostA2.pub);
  try { open('PACT-SEAL-X25519', hostA.priv, hostA2.pub, Buffer.from('PACT-SEAL-v2'), fromB64url(e.protected), fromB64url(e.enc), fromB64url(e.ct)); return 'opened'; } catch { return 'closed'; }
});
scenario('secrets', 'a flipped ciphertext byte', 'does not open', () => { const e = message(hostA, chainA, hostB.pub); const ct = fromB64url(e.ct); ct[3] ^= 1; return receive(bharat(), { ...e, ct: b64url(ct) }).why; });
scenario('secrets', 'the header\'s exp extended after sealing', 'does not open', () => {
  const e = message(hostA, chainA, hostB.pub); const h = JSON.parse(fromB64url(e.protected).toString()); h.exp += 3600;
  return receive(bharat(), { ...e, protected: b64url(Buffer.from(JSON.stringify(h))) }).why;
});
scenario('secrets', 'sealed with the v1 info string', 'does not open', () => receive(bharat(), message(hostA, chainA, hostB.pub, { info: 'PACT-SEAL-v1' })).why);
scenario('secrets', 'Alina\'s envelope re-signed by Mallory', 'signature is not the chain\'s leaf key', () => receive(bharat(), message(hostA, chainA, hostB.pub, { signWith: hostM })).why);
scenario('secrets', 'Mallory seals with Alina\'s chain inside and her own signature', 'signature is not the chain\'s leaf key', () => receive(bharat(), message(hostM, chainM, hostB.pub, { chainInside: chainA })).why);
scenario('secrets', 'the same envelope twice is acknowledged, not re-executed', blockedIf((r) => r.replayed === true), () => { const b = bharat(); const e = message(hostA, chainA, hostB.pub); receive(b, e); return receive(b, e); });
scenario('secrets', 'an envelope past its exp', 'outside the time window', () => receive(bharat(), message(hostA, chainA, hostB.pub, { ts: nowS - 1200, exp: nowS - 600 })).why);
scenario('secrets', 'an envelope ten minutes old', 'outside the time window', () => receive(bharat(), message(hostA, chainA, hostB.pub, { ts: nowS - 600, exp: nowS + 600 })).why);
scenario('secrets', 'a header with an extra member', 'header members', () => receive(bharat(), message(hostA, chainA, hostB.pub, { header: { note: 'x' } })).why);
scenario('secrets', 'a header without suite', 'header members', () => receive(bharat(), message(hostA, chainA, hostB.pub, { header: { suite: undefined } })).why);
scenario('secrets', 'an empty msg_id', 'empty msg_id', () => receive(bharat(), message(hostA, chainA, hostB.pub, { msgId: '' })).why);
scenario('secrets', 'a result envelope dispatched as a request', 'not a request', () => receive(bharat(), message(hostA, chainA, hostB.pub, { cty: 'application/pact-result+json' })).why);
scenario('secrets', 'an envelope for Alina\'s key delivered at Mallory\'s path on a shared host', 'key held for another identity', () => {
  const a = makeNode({ path: '/alina', leafKey: hostA, chain: chainA, now: NOW }), m = makeNode({ path: '/mallory', leafKey: hostM, chain: chainM, now: NOW });
  return receive(m, message(hostB, chainB, hostA.pub), { siblings: [a] }).why;
});
scenario('secrets', 'a guessed kid learns nothing', 'unknown kid', () => receive(bharat(), message(hostA, chainA, hostM.pub)).why);
scenario('secrets', 'a former key of a still-served identity gets the current chain', 'certificate_renewed', () => {
  const a = makeNode({ path: '/alina', leafKey: hostA, chain: chainA, now: NOW });
  renew(a, hostA2, [leafOf(rootA, 'Alina Rao', hostA2, E_A, { notBefore: new Date(NOW - H), notAfter: new Date(NOW + 365 * D) }), ROOT_A]);
  a.now = new Date(at('2027-09-01T00:00:00Z').getTime() + D); forgetKeysPast(a); // the old leaf's notAfter has passed
  return receive(a, message(hostB, chainB, hostA.pub, { ts: Math.floor(a.now / 1000) })).code;
});
scenario('secrets', 'HPKE ephemeral reuse leaks the XOR of two plaintexts', (got) => (got === 'leaks with a fixed seed, differs without' ? 'blocked' : 'REPRODUCES'), () => {
  const p1 = Buffer.alloc(32, 0x41), p2 = Buffer.alloc(32, 0x42), aad = Buffer.from('aad'), info = Buffer.from('PACT-SEAL-v2');
  const c1 = seal('PACT-SEAL-X25519', hostA.pub, info, aad, p1, seed('same')), c2 = seal('PACT-SEAL-X25519', hostA.pub, info, aad, p2, seed('same'));
  const x = Buffer.alloc(32); for (let i = 0; i < 32; i++) x[i] = c1.ct[i] ^ c2.ct[i];
  const leaks = x.equals(Buffer.alloc(32, 0x41 ^ 0x42)) && c1.enc.equals(c2.enc);
  const d1 = seal('PACT-SEAL-X25519', hostA.pub, info, aad, p1), d2 = seal('PACT-SEAL-X25519', hostA.pub, info, aad, p1);
  return leaks && !d1.enc.equals(d2.enc) ? 'leaks with a fixed seed, differs without' : 'unexpected';
});
scenario('secrets', 'a low-order X25519 recipient point', blockedIf((got) => /threw/.test(got)), () => {
  const zero = createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b656e032100', 'hex'), Buffer.alloc(32)]), format: 'der', type: 'spki' });
  seal('PACT-SEAL-X25519', zero, Buffer.from('PACT-SEAL-v2'), Buffer.alloc(0), Buffer.from('x'));
  return 'sealed';
});
scenario('secrets', 'the root private keys are not in the spec', 'absent', () => {
  const spec = readFileSync(new URL('../SPEC.md', import.meta.url), 'utf8');
  const roots = [ed25519FromSeed(seed('root/alina')), p256FromSeed(seed('root/bharat'))].map((k) => pkcs8Of(k.priv).toString('hex'));
  return roots.some((h) => spec.includes(h)) ? 'present' : 'absent';
});

// ── Guests, cards, oracles ──────────────────────────────────────────────────────
scenario('guest', 'a sealed tools/list from a stranger', 'guest may only redeem or request', () => receive(bharat(), env({ senderKey: hostM, senderChain: chainM, recipientLeafPub: hostB.pub, method: 'tools/list', params: {} })).why);
scenario('guest', 'a guest whose card carries a different certificate than the chain', 'guest card certificate is not the chain\'s leaf', () => {
  const other = leafOf(rootM, 'Alina Rao', hostM, E_M, { notBefore: at('2026-08-01T00:00:00Z') });
  return receive(bharat(), env({ senderKey: hostM, senderChain: chainM, recipientLeafPub: hostB.pub, params: { name: 'request_contact', arguments: { card: encodeCard({ fn: 'M', cert: other }) } } })).why;
});
scenario('guest', 'a blocked sender is answered exactly as an unknown one', 'same', () => {
  const b = bharat(); pin(b, FP_M, { endpoint: E_M, leafDer: LEAF_M, state: 'blocked' });
  const blocked = receive(b, message(hostM, chainM, hostB.pub)), unknown = receive(bharat(), message(hostM, chainM, hostB.pub));
  return blocked.code === unknown.code && blocked.why === unknown.why ? 'same' : 'different';
});
scenario('card', 'a folded certificate round-trips', 'ok', () => (decodeCard(card(chainA)).cert.equals(LEAF_A) ? 'ok' : 'mismatch'));
scenario('card', 'two X-PACT-CERT properties', 'bad_request', () => decodeCard(card(chainA).replace('END:VCARD', 'X-PACT-CERT:' + b64url(LEAF_M) + '\r\nEND:VCARD')).error);
scenario('card', 'an expired leaf is accepted at intake', 'expired but accepted', () => { const c = decodeCard(encodeCard({ fn: 'A', cert: leafOf(rootA, 'Alina Rao', hostA, E_A, { notBefore: at('2025-06-01T00:00:00Z'), notAfter: at('2026-06-01T00:00:00Z') }) })); return c.error ? c.error : c.expired ? 'expired but accepted' : 'not expired'; });
scenario('card', 'a 1.x endpoint property on a 2.0 card is ignored; the address comes from the leaf', E_A, () => decodeCard(card(chainA, 'Alina', ['X-PACT-ENDPOINT:' + E_M])).endpoint);
scenario('card', 'a card without a certificate', 'bad_request', () => decodeCard('BEGIN:VCARD\r\nVERSION:4.0\r\nFN:X\r\nX-PACT-VERSION:2\r\nEND:VCARD\r\n').error);

// ── Report ──────────────────────────────────────────────────────────────────────
let last = '';
for (const r of results) {
  if (r.category !== last) { console.log(`\n${r.category}`); last = r.category; }
  console.log(`  ${r.verdict.padEnd(10)} ${r.name}${r.verdict === 'REPRODUCES' ? '  → ' + r.got : ''}`);
}
const count = (v) => results.filter((r) => r.verdict === v).length;
console.log(`\n${results.length} scenarios: ${count('blocked')} blocked, ${count('residual')} residual by decision, ${count('REPRODUCES')} reproduce`);
process.exit(count('REPRODUCES') ? 1 : 0);
