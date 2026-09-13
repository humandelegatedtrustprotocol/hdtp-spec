// A node's receiving side: §13.3 in order, §6.1 tiers, §5.3 new addresses, §14.4 certificate_renewed.
// Small and in-memory, so intrusions can be replayed against it.
import { seal, sealDeterministic, open, signDetached, verifyDetached, suiteForLeaf, recipientOf, SUITES } from './hpke.mjs';
import { validateChain, compareLeaves, parse } from './x509.mjs';
import { fingerprint, b64url, fromB64url } from './keys.mjs';
import { canonical } from './canonical.mjs';
import { decodeCard } from './card.mjs';

export const HEADER_MEMBERS = 'cty,exp,kid,msg_id,suite,ts,v';
export const SKEW_S = 300;
export const CLAIM_WINDOW_MS = 30 * 86_400_000;
export const TOMBSTONE_MS = 30 * 86_400_000;
const GUEST_TOOLS = ['redeem_invite', 'request_contact'];
const PENDING_TOOLS = ['contact_accepted', 'contact_rejected'];

// Sender side, with every knob an attacker would turn. `recipientLeaf` is the DER of the leaf being sealed to.
export function sealEnvelope({ senderKey, senderChain, recipientLeaf, method = 'tools/call', params, msgId, ts, exp, cty = 'application/pact-call+json', ephemeralSeed, signWith, header = {}, chainInside, info = 'PACT-SEAL-v2', suite, recipientPub }) {
  const leaf = parse(recipientLeaf);
  const s = suite ?? suiteForLeaf(leaf), pub = recipientPub ?? recipientOf(leaf);
  const h = { v: 2, suite: s, kid: fingerprint(leaf.publicKey), msg_id: msgId, ts, exp: exp ?? ts + 600, cty, ...header };
  const aad = Buffer.from(canonical(h));
  const plaintext = Buffer.from(JSON.stringify({ method, params, chain: (chainInside ?? senderChain).map(b64url) }));
  const { enc, ct } = ephemeralSeed ? sealDeterministic(s, pub, Buffer.from(info), aad, plaintext, ephemeralSeed) : seal(s, pub, Buffer.from(info), aad, plaintext);
  const signer = signWith ?? senderKey;
  const sig = signDetached(signer.priv ?? signer, Buffer.concat([aad, enc, ct]));
  return { protected: b64url(aad), enc: b64url(enc), ct: b64url(ct), sig: b64url(sig) };
}

// A host holds, per leaf, the signing key and the X-Wing sealing key the leaf carries.
function slot(leafKey, sealKey, leafDer) {
  const leaf = parse(leafDer);
  return { key: leafKey, seal: sealKey, kid: fingerprint(leafKey.pub), leafDer, notAfter: leaf.notAfter, current: true };
}
export function makeNode({ path, leafKey, sealKey, chain, now, acceptNewHosts = 'auto' }) {
  return {
    path, endpoint: parse(chain[0]).uris[0], now, acceptNewHosts, chain,
    keys: [slot(leafKey, sealKey, chain[0])],
    former: new Set(), pins: new Map(), tombstones: new Map(), formerEndpoints: [], seen: new Set(), events: [], pending: [],
  };
}
export function renew(node, leafKey, sealKey, chain) {
  for (const k of node.keys) k.current = false;
  node.keys.push(slot(leafKey, sealKey, chain[0]));
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
  try { header = JSON.parse(fromB64url(envelope.protected).toString()); } catch { return invalid('protected is not JSON'); }
  if (Object.keys(header).sort().join(',') !== HEADER_MEMBERS) return invalid('header members');
  if (header.v !== 2 || !SUITES[header.suite]) return invalid('version or suite');

  const held = node.keys.find((k) => k.kid === header.kid && (k.current || node.now <= k.notAfter));
  if (!held) {
    if (siblings.some((s) => s.keys.some((k) => k.kid === header.kid))) return invalid('key held for another identity');
    if (node.former.has(header.kid)) return { code: 'certificate_renewed', data: { chain: node.chain.map(b64url) } };
    return invalid('unknown kid');
  }
  const heldLeaf = parse(held.leafDer);
  if (suiteForLeaf(heldLeaf) !== header.suite) return invalid('suite does not fit the leaf');

  const aad = fromB64url(envelope.protected), enc = fromB64url(envelope.enc), ct = fromB64url(envelope.ct);
  let body;
  try {
    const [priv, pub] = SUITES[header.suite].pq ? [held.seal, held.seal.pk] : [held.key.priv, held.key.pub];
    body = JSON.parse(open(header.suite, priv, pub, Buffer.from('PACT-SEAL-v2'), aad, enc, ct).toString());
  } catch { return invalid('does not open'); }
  if (!body || typeof body !== 'object' || Object.keys(body).sort().join(',') !== 'chain,method,params') return invalid('plaintext members');
  if (!['tools/call', 'tools/list'].includes(body.method) || !Array.isArray(body.chain)) return invalid('plaintext shape');

  const chain = body.chain.map(fromB64url);
  const v = validateChain(chain, { now: node.now });
  if (!v.ok) return invalid(`chain rule ${v.rule}: ${v.reason}`);
  if (!verifyDetached(v.leafKey, Buffer.concat([aad, enc, ct]), fromB64url(envelope.sig))) return invalid('signature is not the chain\'s leaf key');
  if (header.cty !== 'application/pact-call+json') return invalid('not a request');
  const nowS = Math.floor(node.now / 1000);
  if (!(nowS < header.exp) || Math.abs(nowS - header.ts) > SKEW_S) return invalid('outside the time window');
  if (typeof header.msg_id !== 'string' || !header.msg_id) return invalid('empty msg_id');
  if (node.seen.has(header.msg_id)) return { code: 'ok', replayed: true };

  const root = v.rootFingerprint, endpoint = v.endpoint, tool = body.params?.name;
  const result = (tier, extra = {}) => { node.seen.add(header.msg_id); return { code: 'ok', tier, root, endpoint, method: body.method, tool, ...extra }; };
  const asGuest = (why) => {
    if (body.method !== 'tools/call' || !GUEST_TOOLS.includes(tool)) return invalid('guest may only redeem or request');
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
