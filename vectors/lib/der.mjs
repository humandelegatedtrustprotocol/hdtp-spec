// The little DER the certificate profile needs: an encoder for building, a walker for reading.

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
export function int(v) {
  if (typeof v === 'number' || typeof v === 'bigint') {
    let h = BigInt(v).toString(16); if (h.length % 2) h = '0' + h;
    v = Buffer.from(h, 'hex');
  }
  return tlv(0x02, v[0] & 0x80 ? Buffer.concat([Buffer.from([0]), v]) : v);
}
export function bitstr(bytes, unused = 0) { return tlv(0x03, Buffer.concat([Buffer.from([unused]), bytes])); }
export function oid(s) {
  const p = s.split('.').map(Number);
  const out = [p[0] * 40 + p[1]];
  for (const v of p.slice(2)) {
    const b = [v & 0x7f]; for (let r = v >> 7; r > 0; r >>= 7) b.unshift((r & 0x7f) | 0x80);
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

// Reading: one TLV at an offset, and the children of a constructed value.
export function read(buf, pos = 0) {
  const tag = buf[pos];
  let len = buf[pos + 1], at = pos + 2;
  if (len & 0x80) { const n = len & 0x7f; len = 0; for (let i = 0; i < n; i++) len = (len << 8) | buf[at++]; }
  if (at + len > buf.length) throw new Error('DER length overruns the buffer');
  return { tag, content: buf.subarray(at, at + len), raw: buf.subarray(pos, at + len), end: at + len };
}
export function children(node) {
  const out = []; let pos = 0;
  while (pos < node.content.length) { const c = read(node.content, pos); out.push(c); pos = c.end; }
  return out;
}
export function readOid(node) {
  const b = node.content, out = [Math.floor(b[0] / 40), b[0] % 40];
  let v = 0;
  for (let i = 1; i < b.length; i++) { v = (v << 7) | (b[i] & 0x7f); if (!(b[i] & 0x80)) { out.push(v); v = 0; } }
  return out.join('.');
}
export function readTime(node) {
  const s = node.content.toString('ascii');
  const full = node.tag === 0x17 ? (Number(s.slice(0, 2)) < 50 ? '20' : '19') + s : s;
  return new Date(Date.UTC(+full.slice(0, 4), +full.slice(4, 6) - 1, +full.slice(6, 8), +full.slice(8, 10), +full.slice(10, 12), +full.slice(12, 14)));
}
