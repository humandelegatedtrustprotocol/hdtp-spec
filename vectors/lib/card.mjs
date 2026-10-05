// The §3 card: a vCard 4.0 with the leaf in it, folded per RFC 6350, read back with the intake rules.
import { b64url, strictB64url } from './keys.mjs';
import { parse, MAX_LEAF_DAYS } from './x509.mjs';

const DAY = 86_400_000;

// A card is LINES, and everything a caller supplies is written into one. A control character in any of
// it is refused: a line break writes a property of the writer's choosing, and the decoder reads the
// FIRST of a name, so `FN` "x\r\nX-HDTP-SEAL:none" made a card that requires sealing into one that does
// not. A name with a line break in it is not a name.
export function encodeCard({ fn, cert, seal, extra = [] }) {
  for (const [what, text] of [['fn', fn], ['seal', seal ?? ''], ...extra.map((e) => ['extra', e])])
    if (/\p{Cc}/u.test(String(text))) throw new Error(`${what} carries a control character`);
  const lines = ['BEGIN:VCARD', 'VERSION:4.0', 'FN:' + fn, 'X-HDTP-VERSION:1', 'X-HDTP-CERT:' + b64url(cert), ...extra];
  if (seal) lines.push('X-HDTP-SEAL:' + seal);
  lines.push('END:VCARD');
  return lines.map(fold).join('\r\n') + '\r\n';
}
// RFC 6350 §3.2: a line is at most 75 octets, a continuation a space and at most 74 more, and a
// break never falls inside a UTF-8 sequence — it moves back to the start of the character.
function fold(line) {
  const b = Buffer.from(line, 'utf8');
  if (b.length <= 75) return line;
  const start = (i) => { while (i > 0 && i < b.length && (b[i] & 0xc0) === 0x80) i--; return i; };
  const parts = [];
  for (let i = 0, width = 75; i < b.length; width = 74) {
    const end = Math.min(b.length, start(i + width));
    parts.push((i ? ' ' : '') + b.subarray(i, end).toString('utf8'));
    i = end;
  }
  return parts.join('\r\n');
}

// Reading a card (§3, "Reading a card"), in three steps:
//   1. RFC 6350 §3.2 unfolding: a line break (CRLF or LF) followed by ONE space or tab is removed;
//   2. the text is split into lines at CRLF or LF, and a line STARTS A PROPERTY when it begins
//      `[group.]NAME[;params]:` — NAME and group of letters, digits and `-` (PROPERTY below);
//   3. a base64url-valued property (B64URL: X-HDTP-CERT) also takes every following line that does
//      not start a property, blank ones included, and its value loses every space, tab, CR and LF.
// Step 3 reads a card whose folding was damaged in transit — pasted through a chat, which drops a
// continuation's leading space or adds blank lines. Base64url has none of those four characters, so
// removing them gives back the writer's bytes whenever nothing else was damaged; a character that was
// changed or lost still is, and is caught where it always was: by the DER parse below, or by chain
// validation (§14.2) and the first exchange, since a card carries no root to check its leaf against.
// Any other line that starts no property is ignored.
const PROPERTY = /^(?:[A-Za-z0-9-]+\.)?[A-Za-z0-9-]+(?:;[^:]*)?:/;
const B64URL = ['X-HDTP-CERT'];

// Intake per §3: refuses what has no root to pin or no address to reach; an expired leaf is not a refusal.
export function decodeCard(text) {
  const lines = text.replace(/\r?\n[ \t]/g, '').split(/\r?\n/);
  const props = new Map();
  let joining = null; // [name, index] of the base64url value later lines join, while they start no property
  for (const line of lines) {
    if (!PROPERTY.test(line)) {
      if (joining) props.get(joining[0])[joining[1]] += line;
      continue;
    }
    const i = line.indexOf(':');
    const name = line.slice(0, i).split(';')[0].toUpperCase();
    if (!props.has(name)) props.set(name, []);
    props.get(name).push(line.slice(i + 1));
    joining = B64URL.includes(name) ? [name, props.get(name).length - 1] : null;
  }
  for (const name of B64URL) if (props.has(name)) props.set(name, props.get(name).map((v) => v.replace(/[ \t\r\n]/g, '')));
  const bad = (why) => ({ error: 'bad_request', why });
  const version = props.get('X-HDTP-VERSION')?.[0];
  if (version !== '1') return bad(version ? 'version not implemented' : 'no X-HDTP-VERSION');
  const certs = props.get('X-HDTP-CERT') ?? [];
  if (certs.length !== 1) return bad(`${certs.length} certificates`);
  // Read as the ports read it (strictB64url): Buffer.from skipped a stray character, so a card the
  // Rust core refused was taken here.
  const der = strictB64url(certs[0]);
  if (!der) return bad('certificate does not parse: not base64url');
  let leaf;
  try { leaf = parse(der); } catch (e) { return bad('certificate does not parse: ' + e.message); }
  if (!leaf.aki) return bad('no issuer key identifier');
  // What is about to be shown to a person as the identity to pin is this value, so it has to BE a key
  // identifier: 32 bytes (§14.1). Three bytes used to come out as `sha256:AQID`.
  if (leaf.aki.length !== 32) return bad('issuer key identifier is not 32 bytes');
  if (leaf.uris.length !== 1) return bad(`${leaf.uris.length} endpoints`);
  if (leaf.notAfter - leaf.notBefore > MAX_LEAF_DAYS * DAY) return bad('validity over 398 days');
  return {
    fn: props.get('FN')?.[0] ?? '', version: 1, seal: props.get('X-HDTP-SEAL')?.[0] ?? 'none',
    cert: leaf.der, leaf, root: 'sha256:' + b64url(leaf.aki), endpoint: leaf.uris[0],
    expired: leaf.notAfter < new Date(), ignored: [...props.keys()].filter((k) => k.startsWith('X-HDTP-') && !['X-HDTP-VERSION', 'X-HDTP-CERT', 'X-HDTP-SEAL'].includes(k)),
  };
}
