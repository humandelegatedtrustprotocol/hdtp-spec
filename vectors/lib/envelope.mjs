// A node's receiving side: §13.3 in order, §6.1 tiers, §5.3 new addresses, §14.4 certificate_renewed.
// Small and in-memory, so intrusions can be replayed against it.
import { seal, sealDeterministic, open, signDetached, verifyDetached, suiteForLeaf, recipientOf, SUITES } from './hpke.mjs';
import { validateChain, compareLeaves, parse } from './x509.mjs';
import { fingerprint, b64url, fromB64url, wireB64url } from './keys.mjs';
import { canonical } from './canonical.mjs';
import { decodeCard } from './card.mjs';

export const HEADER_MEMBERS = 'cty,exp,kid,msg_id,suite,ts,v';
// §13.1 gives each member a type as well as a name. The closed set of names exists so two
// implementations cannot disagree about what was signed; latitude in the types reopens the same gap,
// since `"1757000000"` and `1757000000` are different bytes under one signature and compare alike.
const INTEGER_MEMBERS = ['v', 'ts', 'exp'], STRING_MEMBERS = ['suite', 'kid', 'msg_id', 'cty'];
const isInt = (n) => typeof n === 'number' && Number.isSafeInteger(n);
const headerTypesOk = (h) => INTEGER_MEMBERS.every((k) => isInt(h[k])) && STRING_MEMBERS.every((k) => typeof h[k] === 'string');
export const SKEW_S = 300;
export const MAX_LIFETIME_S = 30 * 86_400; // §13.1: exp − ts is at most 30 days
export const CLAIM_WINDOW_MS = 30 * 86_400_000;
export const TOMBSTONE_MS = 30 * 86_400_000;
const GUEST_TOOLS = ['redeem_invite', 'request_contact'];
const PENDING_TOOLS = ['contact_accepted', 'contact_rejected'];

// Sender side, with every knob an attacker would turn. `recipientLeaf` is the DER of the leaf being sealed to.
// `reference: true` names the sender's leaf by fingerprint instead of carrying the chain (§13.2): the small form,
// for a receiver that already holds the leaf. A host sends the chain on first contact and after each renewal.
export function sealEnvelope({ senderKey, senderChain, recipientLeaf, method = 'tools/call', params, msgId, ts, exp, cty = 'application/pact-call+json', ephemeralSeed, signWith, header = {}, chainInside, info = 'PACT-SEAL-v2', suite, recipientPub, reference = false, referenceKey, referenceFingerprint, both = false }) {
  const leaf = parse(recipientLeaf);
  const s = suite ?? suiteForLeaf(leaf), pub = recipientPub ?? recipientOf(leaf);
  const h = { v: 2, suite: s, kid: fingerprint(leaf.publicKey), msg_id: msgId, ts, exp: exp ?? ts + 600, cty, ...header };
  const aad = Buffer.from(canonical(h));
  const chain = (chainInside ?? senderChain).map(b64url);
  // `referenceFingerprint` names a leaf by a string nobody holds: what a guesser sends.
  const ref = referenceFingerprint ?? fingerprint((referenceKey ?? senderKey).pub ?? referenceKey ?? senderKey);
  const body = both ? { method, params, chain, leaf: ref } : reference ? { method, params, leaf: ref } : { method, params, chain };
  const plaintext = Buffer.from(JSON.stringify(body));
  const { enc, ct } = ephemeralSeed ? sealDeterministic(s, pub, Buffer.from(info), aad, plaintext, ephemeralSeed) : seal(s, pub, Buffer.from(info), aad, plaintext);
  const signer = signWith ?? senderKey;
  const sig = signDetached(signer.priv ?? signer, Buffer.concat([aad, enc, ct]));
  return { protected: b64url(aad), enc: b64url(enc), ct: b64url(ct), sig: b64url(sig) };
}

function slot(leafKey, leafDer) {
  return { key: leafKey, kid: fingerprint(leafKey.pub), leafDer, notAfter: parse(leafDer).notAfter, current: true };
}
export function makeNode({ path, leafKey, chain, now, acceptNewHosts = 'auto' }) {
  return {
    path, endpoint: parse(chain[0]).uris[0], now, acceptNewHosts, chain,
    keys: [slot(leafKey, chain[0])],
    former: new Set(), pins: new Map(), tombstones: new Map(), formerEndpoints: [], seen: new Set(), events: [], pending: [],
  };
}
export function renew(node, leafKey, chain) {
  for (const k of node.keys) k.current = false;
  node.keys.push(slot(leafKey, chain[0]));
  node.chain = chain; node.endpoint = parse(chain[0]).uris[0];
}
export function forgetKeysPast(node) {
  for (const k of [...node.keys]) if (!k.current && node.now > k.notAfter) { node.keys.splice(node.keys.indexOf(k), 1); node.former.add(k.kid); }
}
export function pin(node, root, { endpoint, leafDer, state = 'active' }) { node.pins.set(root, { endpoint, leafDer, state }); }
export function removeContact(node, root) {
  const p = node.pins.get(root);
  if (p) { node.tombstones.set(root, { leafDer: p.leafDer, at: node.now }); node.pins.delete(root); }
}

const invalid = (why) => ({ code: 'envelope_invalid', why });

export function receive(node, envelope, { siblings = [] } = {}) {
  let header;
  const aad = wireB64url(envelope.protected);
  if (!aad) return invalid('protected is not JSON');
  try { header = JSON.parse(aad.toString()); } catch { return invalid('protected is not JSON'); }
  if (Object.keys(header).sort().join(',') !== HEADER_MEMBERS) return invalid('header members');
  if (!headerTypesOk(header)) return invalid('header member types');
  if (header.v !== 2 || !SUITES[header.suite]) return invalid('version or suite');

  const held = node.keys.find((k) => k.kid === header.kid && (k.current || node.now <= k.notAfter));
  if (!held) {
    if (siblings.some((s) => s.keys.some((k) => k.kid === header.kid))) return invalid('key held for another identity');
    if (node.former.has(header.kid)) return { code: 'certificate_renewed', data: { chain: node.chain.map(b64url) } };
    return invalid('unknown kid');
  }
  if (suiteForLeaf(parse(held.leafDer)) !== header.suite) return invalid('suite does not fit the leaf');

  const enc = wireB64url(envelope.enc), ct = wireB64url(envelope.ct);
  if (!enc || !ct) return invalid('does not open');
  // `sig` covers the three members concatenated with nothing between them, so the suite's own `enc`
  // length is what fixes the boundary: without it a byte moved from `enc` into `ct` leaves the signed
  // bytes identical.
  if (enc.length !== SUITES[header.suite].npk) return invalid("encapsulated key is not the suite's length");
  let body;
  try { body = JSON.parse(open(header.suite, held.key.priv, held.key.pub, Buffer.from('PACT-SEAL-v2'), aad, enc, ct).toString()); } catch { return invalid('does not open'); }
  const members = body && typeof body === 'object' ? Object.keys(body).sort().join(',') : '';
  if (members !== 'chain,method,params' && members !== 'leaf,method,params') return invalid('plaintext members');
  if (!['tools/call', 'tools/list'].includes(body.method)) return invalid('plaintext shape');
  // A signature that does not read is no signature: it fails below, in the words of the form it came in.
  const signed = Buffer.concat([aad, enc, ct]), sig = wireB64url(envelope.sig) ?? Buffer.alloc(0);
  const tool = body.params?.name;
  const freshness = () => {
    if (header.cty !== 'application/pact-call+json') return invalid('not a request');
    const nowS = Math.floor(node.now / 1000);
    if (!(nowS < header.exp) || Math.abs(nowS - header.ts) > SKEW_S) return invalid('outside the time window');
    if (header.exp - header.ts > MAX_LIFETIME_S) return invalid('exp too far from ts');
    if (typeof header.msg_id !== 'string' || !header.msg_id) return invalid('empty msg_id');
    if (node.seen.has(header.msg_id)) return { code: 'ok', replayed: true };
    return null;
  };

  // The small form: the sender names a leaf this node already holds. Anything that cannot be verified
  // against a held leaf — unknown, blocked, or a bad signature — gets the same answer, so nothing leaks.
  if (members === 'leaf,method,params') {
    if (typeof body.leaf !== 'string') return invalid('plaintext shape');
    const chainRequired = { code: 'chain_required' };
    const hit = [...node.pins].find(([, p]) => p.state !== 'blocked' && fingerprint(parse(p.leafDer).publicKey) === body.leaf);
    if (!hit) return chainRequired;
    const [root, p] = hit;
    const held = parse(p.leafDer);
    if (node.now > held.notAfter) return chainRequired; // expiry darkens the small form as it darkens the chain
    if (!verifyDetached(held.publicKey, signed, sig)) return chainRequired;
    const early = freshness(); if (early) return early;
    const result = (tier) => { node.seen.add(header.msg_id); return { code: 'ok', tier, root, endpoint: p.endpoint, method: body.method, tool, form: 'leaf' }; };
    if (p.state === 'pending_out') return PENDING_TOOLS.includes(tool) ? result('pending') : { code: 'pending_approval' };
    return result('contact');
  }

  // The full form: a chain is a proof from the root and the one way a held leaf is updated.
  if (!Array.isArray(body.chain)) return invalid('plaintext shape');
  const chain = body.chain.map(fromB64url);
  const v = validateChain(chain, { now: node.now });
  if (!v.ok) return invalid(`chain rule ${v.rule}: ${v.reason}`);
  if (!verifyDetached(v.leafKey, signed, sig)) return invalid('signature is not the chain\'s leaf key');
  const early = freshness(); if (early) return early;

  const root = v.rootFingerprint, endpoint = v.endpoint;
  const result = (tier, extra = {}) => { node.seen.add(header.msg_id); return { code: 'ok', tier, root, endpoint, method: body.method, tool, form: 'chain', ...extra }; };
  const asGuest = (why) => {
    if (body.method !== 'tools/call' || !GUEST_TOOLS.includes(tool)) return invalid('guest may only redeem or request');
    // §14.5: a guest's endpoint never equals the receiver's own. Otherwise a stranger is pinned to
    // this node's own address and every reply it is sent comes straight back here.
    if (endpoint === node.endpoint) return invalid("guest endpoint is this node's own address");
    const card = decodeCard(body.params.arguments?.card ?? '');
    if (card.error) return invalid('guest card: ' + card.why);
    if (!card.cert.equals(chain[0])) return invalid('guest card certificate is not the chain\'s leaf');
    const held = [...node.pins].find(([r, p]) => r !== root && p.endpoint === endpoint);
    const former = node.formerEndpoints.find((f) => f.endpoint === endpoint && f.root !== root && node.now - f.at < CLAIM_WINDOW_MS);
    return result('guest', { why, addressClaim: held ? held[0] : former ? former.root : null });
  };

  const p = node.pins.get(root);
  if (!p) {
    const t = node.tombstones.get(root);
    if (t && node.now - t.at < TOMBSTONE_MS && compareLeaves(t.leafDer, chain[0]) === 'newer') {
      node.pending.push({ root, endpoint, why: 'returned after removal' });
      return result('pending_new_address', { forced: 'tombstone', decision: 'ask' });
    }
    return asGuest('unknown root');
  }
  if (p.state === 'blocked') return asGuest('blocked');
  const cmp = compareLeaves(p.leafDer, chain[0]);
  if (cmp === 'superseded') return asGuest('superseded leaf');
  if (cmp === 'conflict') return invalid('a different leaf with the same notBefore');

  // §14.3 is absolute: a newer leaf from the root takes priority the instant it is seen, whatever the
  // validity of the older one. At another address it is a new address; under `ask` the owner decides.
  if (endpoint !== p.endpoint) {
    if (node.acceptNewHosts !== 'auto') { node.pending.push({ root, endpoint, why: 'ask' }); return result('pending_new_address', { decision: 'ask' }); }
    node.formerEndpoints.push({ root, endpoint: p.endpoint, at: node.now });
    p.endpoint = endpoint; p.leafDer = chain[0];
    node.events.push({ event: 'new_address', root, endpoint });
  } else if (cmp === 'newer') { p.leafDer = chain[0]; node.events.push({ event: 'renewal', root }); }

  if (p.state === 'pending_out') return PENDING_TOOLS.includes(tool) ? result('pending') : { code: 'pending_approval' };
  return result('contact');
}
