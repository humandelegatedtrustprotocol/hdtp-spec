// The little DER the certificate profile needs: an encoder for building, a strict walker for reading.

function length(n) {
  if (n < 0x80) return Buffer.from([n]);
  const bytes = []; for (let v = n; v > 0; v >>= 8) bytes.unshift(v & 0xff);
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}
export const tlv = (tag, content) => Buffer.concat([Buffer.from([tag]), length(content.length), content]);
export const seq = (...parts) => tlv(0x30, Buffer.concat(parts));
export const set = (...parts) => tlv(0x31, Buffer.concat(parts));
export const explicit = (n, content) => tlv(0xa0 | n, content);
export const implicit = (n, content) => tlv(0x80 | n, content);
export const octet = (b) => tlv(0x04, b);
export const utf8 = (s) => tlv(0x0c, Buffer.from(s, 'utf8'));
export const ia5 = (s) => tlv(0x16, Buffer.from(s, 'ascii'));
export const bool = (v) => tlv(0x01, Buffer.from([v ? 0xff : 0x00]));
/**
 * A DER INTEGER: minimal two's-complement, always.
 *
 * Prepending 0x00 for a set top bit was only half the rule. The other half is that a
 * *redundant* leading 0x00 must be removed, and leaving it out was not academic: the cores'
 * `random_serial` hands eight random bytes straight to this, so one serial in 256 begins
 * 0x00 and was encoded non-minimally — a certificate the strict parser added by the
 * cryptographic review then refused, including the parser in the very core that had just
 * issued it. Intermittent, at 1/256, which is the worst rate to find a bug at.
 *
 * Canonical form: strip leading 0x00 while the next byte's top bit is clear (never below one
 * byte, so zero stays `02 01 00`), then prepend 0x00 if the top bit is set.
 */
export function int(v) {
  if (typeof v === 'number' || typeof v === 'bigint') {
    let h = BigInt(v).toString(16); if (h.length % 2) h = '0' + h;
    v = Buffer.from(h, 'hex');
  }
  let at = 0;
  while (at + 1 < v.length && v[at] === 0 && (v[at + 1] & 0x80) === 0) at++;
  v = v.subarray(at);
  return tlv(0x02, v[0] & 0x80 ? Buffer.concat([Buffer.from([0]), v]) : v);
}
export function bitstr(bytes, unused = 0) { return tlv(0x03, Buffer.concat([Buffer.from([unused]), bytes])); }
export function oid(s) {
  const p = s.split('.').map(BigInt);
  const out = [Number(p[0] * 40n + p[1])];
  for (const v of p.slice(2)) {
    const b = [Number(v & 0x7fn)]; for (let r = v >> 7n; r > 0n; r >>= 7n) b.unshift(Number(r & 0x7fn) | 0x80);
    out.push(...b);
  }
  return tlv(0x06, Buffer.from(out));
}
const pad = (n, w = 2) => String(n).padStart(w, '0');
export function time(d) {
  const y = d.getUTCFullYear();
  const rest = `${pad(d.getUTCMonth() + 1)}${pad(d.getUTCDate())}${pad(d.getUTCHours())}${pad(d.getUTCMinutes())}${pad(d.getUTCSeconds())}Z`;
  return y < 2050 ? tlv(0x17, Buffer.from(String(y).slice(2) + rest)) : tlv(0x18, Buffer.from(pad(y, 4) + rest));
}

// Reading, strictly: definite and minimal lengths only, nothing past the end. Indefinite forms, padded
// lengths and trailing bytes are how one parser is made to see what another does not.
export function read(buf, pos = 0) {
  if (pos + 2 > buf.length) throw new Error('DER truncated');
  const tag = buf[pos];
  let len = buf[pos + 1], at = pos + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4) throw new Error('DER indefinite or oversized length');
    if (buf[at] === 0) throw new Error('DER length not minimal');
    len = 0; for (let i = 0; i < n; i++) len = (len << 8) | buf[at++];
    if (len < 0x80) throw new Error('DER length not minimal');
  }
  if (at + len > buf.length) throw new Error('DER length overruns the buffer');
  return { tag, content: buf.subarray(at, at + len), raw: buf.subarray(pos, at + len), end: at + len };
}
export function children(node) {
  const out = []; let pos = 0;
  while (pos < node.content.length) { const c = read(node.content, pos); out.push(c); pos = c.end; }
  return out;
}
// DER's one encoding of TRUE: a single 0xFF. Anything else — 0x01, or an explicit FALSE where the
// DEFAULT should simply be absent — is a second spelling, which is what an exact profile excludes.
export const boolTrue = (node) => node.tag === 0x01 && node.content.length === 1 && node.content[0] === 0xff;

// DER's INTEGER: at least one byte, and the shortest two's-complement form — no 0x00 before a byte
// under 0x80, no 0xFF before one at or above it.
export function intMinimal(content) {
  if (content.length === 0) return false;
  if (content.length === 1) return true;
  if (content[0] === 0x00) return (content[1] & 0x80) !== 0;
  if (content[0] === 0xff) return (content[1] & 0x80) === 0;
  return true;
}

// DER's OBJECT IDENTIFIER: every subidentifier in its shortest base-128 form, so no leading 0x80,
// and the last byte ends one — a padded arc reads as the same OID to a lenient parser and as nothing
// at all to a strict one, which is the whole of the parser-differential problem in four bytes.
export function oidMinimal(node) {
  const b = node.content;
  if (node.tag !== 0x06 || b.length === 0 || (b[b.length - 1] & 0x80) !== 0) return false;
  let start = true;
  for (const x of b.subarray(1)) {
    if (start && x === 0x80) return false;
    start = (x & 0x80) === 0;
  }
  return true;
}

// DER's BIT STRING for a named bit list (keyUsage): the unused bits are zero, and trailing zero bits
// are removed — so the lowest bit still encoded is set. Either spelling of the same set is a second
// encoding. Not for the signature or the public key, where every bit is carried and `unused` is 0.
export function namedBitsOk(content) {
  const unused = content[0] ?? 0, bits = content.subarray(1);
  if (unused > 7) return false;
  if (bits.length === 0) return unused === 0;
  const last = bits[bits.length - 1];
  return (last & ((1 << unused) - 1)) === 0 && (last & (1 << unused)) !== 0;
}

// Every OID a certificate carries is read through this, so no call site can be the one that forgot:
// the profile is exact, and an exactness applied at one of four read positions is not one.
export function readOidStrict(node) {
  if (!oidMinimal(node)) throw new Error('OID not in the DER form');
  return readOid(node);
}

export function readOid(node) {
  const b = node.content, out = [Math.floor(b[0] / 40), b[0] % 40];
  let v = 0n;
  for (let i = 1; i < b.length; i++) { v = (v << 7n) | BigInt(b[i] & 0x7f); if (!(b[i] & 0x80)) { out.push(v.toString()); v = 0n; } }
  return out.join('.');
}
export function readTime(node) {
  const s = node.content.toString('ascii');
  const full = node.tag === 0x17 ? (Number(s.slice(0, 2)) < 50 ? '20' : '19') + s : s;
  if (!/^\d{14}Z$/.test(full)) throw new Error('time not in the DER form');
  return new Date(Date.UTC(+full.slice(0, 4), +full.slice(4, 6) - 1, +full.slice(6, 8), +full.slice(8, 10), +full.slice(10, 12), +full.slice(12, 14)));
}
