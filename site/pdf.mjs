// What the whitepaper build needs from a PDF after Chrome has printed it, and nothing more: read
// the document information, add entries to it, and read back the text a reader would copy out.
// Only the shape Chrome's Skia writes is handled — classic cross-reference tables (no object
// streams), Flate streams with a direct /Length, text shown with hex strings through fonts that
// carry a ToUnicode map — and anything else is refused rather than guessed at.
//
// Measured on a 62-page build of this whitepaper (2026-10-01), page by page against poppler's
// pdftotext, whitespace removed: the same characters, in a different order (pdftotext orders by
// position), except two kinds pdftotext rewrites: a hyphen ending a line, which it drops, and
// JetBrains Mono's contextual alternates in "://", whose ToUnicode entry Chrome writes as ":".
// This reader reports what the PDF's own maps say.

import { inflateSync } from 'node:zlib'

const latin1 = (bytes) => Buffer.from(bytes).toString('latin1')

// Every object's offset, newest definition first, following the trailers' /Prev chain.
function xref(bytes) {
  const s = latin1(bytes)
  const at = /startxref\s+(\d+)\s+%%EOF\s*$/.exec(s)
  if (!at) throw new Error('pdf: no startxref at the end')
  const offsets = new Map()
  let trailer = null
  for (let pos = Number(at[1]); pos !== null;) {
    if (!s.startsWith('xref', pos)) throw new Error(`pdf: no classic xref table at ${pos} (object streams are not read here)`)
    const end = s.indexOf('trailer', pos)
    const lines = s.slice(pos + 4, end).trim().split(/\r?\n|\r/)
    for (let i = 0; i < lines.length;) {
      const [first, count] = lines[i++].trim().split(/\s+/).map(Number)
      for (let k = 0; k < count; k++, i++) {
        const [off, , kind] = lines[i].trim().split(/\s+/)
        if (kind === 'n' && !offsets.has(first + k)) offsets.set(first + k, Number(off))
      }
    }
    const dict = /^trailer\s*<<([\s\S]*?)>>\s*startxref/.exec(s.slice(end))[1]
    trailer ??= dict
    const prev = /\/Prev (\d+)/.exec(dict)
    pos = prev ? Number(prev[1]) : null
  }
  return { s, offsets, trailer }
}

function object(doc, n) {
  const off = doc.offsets.get(n)
  if (off === undefined) throw new Error(`pdf: object ${n} is not in the xref`)
  const head = new RegExp(`^${n} 0 obj\\s*`).exec(doc.s.slice(off, off + 32))
  if (!head) throw new Error(`pdf: object ${n} is not at its offset`)
  const start = off + head[0].length
  const stream = doc.s.indexOf('stream', start), endobj = doc.s.indexOf('endobj', start)
  if (stream < 0 || endobj < stream) return { dict: doc.s.slice(start, endobj).trim() }
  return { dict: doc.s.slice(start, stream).trim(), dataAt: stream + 6 + (doc.s[stream + 6] === '\r' ? 2 : 1) }
}

function streamOf(doc, bytes, n) {
  const { dict, dataAt } = object(doc, n)
  if (dataAt === undefined) throw new Error(`pdf: object ${n} is not a stream`)
  const length = /\/Length (\d+)(?!\s+\d+\s+R)/.exec(dict)
  if (!length) throw new Error(`pdf: object ${n} has no direct /Length`)
  const raw = Buffer.from(bytes).subarray(dataAt, dataAt + Number(length[1]))
  return latin1(/\/Filter\s*\/FlateDecode/.test(dict) ? inflateSync(raw) : raw)
}

const ref = (dict, key) => {
  const m = new RegExp(`/${key}\\s+(\\d+)\\s+0\\s+R`).exec(dict)
  return m ? Number(m[1]) : null
}

// The document information dictionary's entries, as the raw PDF tokens Chrome wrote, plus
// readable values for literal strings.
export function info(bytes) {
  const doc = xref(bytes)
  const n = ref(doc.trailer, 'Info')
  if (n === null) return { n: null, dict: '', values: {} }
  const { dict } = object(doc, n)
  const values = {}
  for (const m of dict.matchAll(/\/(\w+)\s*\(((?:\\.|[^\\)])*)\)/g)) values[m[1]] = m[2].replace(/\\(.)/g, '$1')
  return { n, dict, values }
}

const literal = (v) => {
  if (!/^[\x20-\x7e]*$/.test(v)) throw new Error(`pdf: document information is written ASCII only, not ${JSON.stringify(v)}`)
  return `(${v.replace(/[\\()]/g, '\\$&')})`
}

// Returns the PDF with `entries` added to (or replacing those of) its document information, as
// an incremental update: the original bytes, then the information object again, a one-entry
// xref section and a trailer pointing back at the original's.
export function withInfo(bytes, entries) {
  const doc = xref(bytes)
  const { n, dict } = info(bytes)
  if (n === null) throw new Error('pdf: no /Info in the trailer')
  let body = dict.replace(/^<<|>>$/g, '')
  for (const key of Object.keys(entries)) body = body.replace(new RegExp(`/${key}\\s*(\\((?:\\\\.|[^\\\\)])*\\)|<[0-9A-Fa-f]*>)`), '')
  body = `${body.trim()}\n${Object.entries(entries).map(([k, v]) => `/${k} ${literal(v)}`).join('\n')}`
  const base = Buffer.from(bytes)
  const sep = base.at(-1) === 0x0a ? '' : '\n'
  const objAt = base.length + sep.length
  const obj = `${n} 0 obj\n<<${body}>>\nendobj\n`
  const xrefAt = objAt + Buffer.byteLength(obj, 'latin1')
  const size = /\/Size (\d+)/.exec(doc.trailer)[1]
  const root = /\/Root (\d+ 0 R)/.exec(doc.trailer)[1]
  const prev = /startxref\s+(\d+)\s+%%EOF\s*$/.exec(doc.s)[1]
  const tail = `xref\n0 1\n0000000000 65535 f \n${n} 1\n${String(objAt).padStart(10, '0')} 00000 n \n` +
    `trailer\n<</Size ${size}\n/Root ${root}\n/Info ${n} 0 R\n/Prev ${prev}>>\nstartxref\n${xrefAt}\n%%EOF\n`
  return Buffer.concat([base, Buffer.from(sep + obj + tail, 'latin1')])
}

// A ToUnicode CMap as code → string, with the code length its codespace range sets.
function cmap(text) {
  const width = /begincodespacerange\s*<([0-9A-Fa-f]+)>/.exec(text)?.[1].length ?? 2
  const map = new Map()
  const utf16 = (hex) => String.fromCharCode(...hex.match(/.{4}/g).map((h) => parseInt(h, 16)))
  for (const block of text.matchAll(/beginbfchar([\s\S]*?)endbfchar/g)) {
    for (const m of block[1].matchAll(/<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>/g)) map.set(parseInt(m[1], 16), utf16(m[2]))
  }
  for (const block of text.matchAll(/beginbfrange([\s\S]*?)endbfrange/g)) {
    for (const m of block[1].matchAll(/<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>\s*(<[0-9A-Fa-f]+>|\[[^\]]*\])/g)) {
      const lo = parseInt(m[1], 16), hi = parseInt(m[2], 16)
      if (m[3].startsWith('[')) {
        const list = [...m[3].matchAll(/<([0-9A-Fa-f]+)>/g)].map((x) => utf16(x[1]))
        for (let c = lo; c <= hi; c++) map.set(c, list[c - lo])
      } else {
        const dst = m[3].slice(1, -1)
        const last = parseInt(dst.slice(-4), 16)
        for (let c = lo; c <= hi; c++) map.set(c, utf16(dst.slice(0, -4) + (last + c - lo).toString(16).padStart(4, '0')))
      }
    }
  }
  return { width, map }
}

// The text of every page, in page order, one string per page: the glyphs each content stream
// shows, mapped through their fonts' ToUnicode. Positioning is not read, so where layout alone
// separates two words (a line break) they run together; compare with whitespace removed.
export function text(bytes) {
  const doc = xref(bytes)
  const pages = []
  const walk = (n) => {
    const { dict } = object(doc, n)
    if (/\/Type\s*\/Pages\b/.test(dict)) {
      for (const k of /\/Kids\s*\[([^\]]*)\]/.exec(dict)[1].matchAll(/(\d+)\s+0\s+R/g)) walk(Number(k[1]))
    } else pages.push(dict)
  }
  walk(ref(object(doc, ref(doc.trailer, 'Root')).dict, 'Pages'))
  const fonts = new Map()
  const fontOf = (n) => {
    if (!fonts.has(n)) {
      const u = ref(object(doc, n).dict, 'ToUnicode')
      fonts.set(n, u === null ? null : cmap(streamOf(doc, bytes, u)))
    }
    return fonts.get(n)
  }
  return pages.map((page) => {
    const resources = /\/Font\s*<<([^>]*)>>/.exec(page)?.[1] ?? ''
    const byName = new Map([...resources.matchAll(/\/(\S+)\s+(\d+)\s+0\s+R/g)].map((m) => [m[1], Number(m[2])]))
    const contents = /\/Contents\s*(\[[^\]]*\]|\d+\s+0\s+R)/.exec(page)[1]
    let out = ''
    for (const c of contents.matchAll(/(\d+)\s+0\s+R/g)) {
      let font = null
      for (const m of streamOf(doc, bytes, Number(c[1])).matchAll(/\/(\S+)\s+[\d.]+\s+Tf|(\[(?:[^\]])*\]\s*TJ|<[0-9A-Fa-f]*>\s*Tj)|\((?:\\.|[^\\)])*\)\s*T[jJ]/g)) {
        if (m[1]) { font = byName.has(m[1]) ? fontOf(byName.get(m[1])) : null; continue }
        if (!m[2]) throw new Error('pdf: a literal text string, which this reader does not decode')
        if (!font) continue
        for (const h of m[2].matchAll(/<([0-9A-Fa-f]*)>/g)) {
          for (let i = 0; i < h[1].length; i += font.width) out += font.map.get(parseInt(h[1].slice(i, i + font.width), 16)) ?? ''
        }
      }
    }
    return out
  })
}
