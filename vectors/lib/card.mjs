// The §3 card: a vCard 4.0 with the leaf in it, folded per RFC 6350, read back with the intake rules.
import { b64url, fromB64url } from './keys.mjs';
import { parse, MAX_LEAF_DAYS } from './x509.mjs';

const DAY = 86_400_000;

// A card is LINES, and everything a caller supplies is written into one. A control character in any of
// it is refused: a line break writes a property of the writer's choosing, and the decoder reads the
// FIRST of a name, so `FN` "x\r\nX-PACT-SEAL:none" made a card that requires sealing into one that does
// not. A name with a line break in it is not a name.
export function encodeCard({ fn, cert, seal, extra = [] }) {
  for (const [what, text] of [['fn', fn], ['seal', seal ?? ''], ...extra.map((e) => ['extra', e])])
    if (/\p{Cc}/u.test(String(text))) throw new Error(`${what} carries a control character`);
  const lines = ['BEGIN:VCARD', 'VERSION:4.0', 'FN:' + fn, 'X-PACT-VERSION:2', 'X-PACT-CERT:' + b64url(cert), ...extra];
  if (seal) lines.push('X-PACT-SEAL:' + seal);
  lines.push('END:VCARD');
  return lines.map(fold).join('\r\n') + '\r\n';
}
function fold(line) {
  if (line.length <= 75) return line;
  const parts = [line.slice(0, 75)];
  for (let i = 75; i < line.length; i += 74) parts.push(' ' + line.slice(i, i + 74));
  return parts.join('\r\n');
}

// Intake per §3: refuses what has no root to pin or no address to reach; an expired leaf is not a refusal.
export function decodeCard(text) {
  const unfolded = text.replace(/\r?\n[ \t]/g, '').split(/\r?\n/).filter(Boolean);
  const props = new Map();
  for (const line of unfolded) {
    const i = line.indexOf(':'); if (i < 0) continue;
    const name = line.slice(0, i).split(';')[0].toUpperCase();
    if (!props.has(name)) props.set(name, []);
    props.get(name).push(line.slice(i + 1));
  }
  const bad = (why) => ({ error: 'bad_request', why });
  const version = props.get('X-PACT-VERSION')?.[0];
  if (version !== '2') return bad(version ? 'version not implemented' : 'no X-PACT-VERSION');
  const certs = props.get('X-PACT-CERT') ?? [];
  if (certs.length !== 1) return bad(`${certs.length} certificates`);
  let leaf;
  try { leaf = parse(fromB64url(certs[0])); } catch (e) { return bad('certificate does not parse: ' + e.message); }
  if (!leaf.aki) return bad('no issuer key identifier');
  // What is about to be shown to a person as the identity to pin is this value, so it has to BE a key
  // identifier: 32 bytes (§14.1). Three bytes used to come out as `sha256:AQID`.
  if (leaf.aki.length !== 32) return bad('issuer key identifier is not 32 bytes');
  if (leaf.uris.length !== 1) return bad(`${leaf.uris.length} endpoints`);
  if (leaf.notAfter - leaf.notBefore > MAX_LEAF_DAYS * DAY) return bad('validity over 398 days');
  return {
    fn: props.get('FN')?.[0] ?? '', version: 2, seal: props.get('X-PACT-SEAL')?.[0] ?? 'none',
    cert: leaf.der, leaf, root: 'sha256:' + b64url(leaf.aki), endpoint: leaf.uris[0],
    expired: leaf.notAfter < new Date(), ignored: [...props.keys()].filter((k) => k.startsWith('X-PACT-') && !['X-PACT-VERSION', 'X-PACT-CERT', 'X-PACT-SEAL'].includes(k)),
  };
}
