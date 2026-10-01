// Renders one committed SPEC.md into layout-agnostic HTML fragments for the protocol site.
//
//   node site/spec-html.mjs --ref <git ref> --out <dir> [--musts <path>|none]
//
// The text comes from `git show <ref>:SPEC.md`, never from the working tree, so an uncommitted
// SPEC is never published and a superseded one (the PACT 1 text, d130444) is rendered without
// ever being written into this repository as markdown — its retired names would fail
// vectors/check-no-1x.mjs the day they were committed. For the same reason `--out` may not be
// a tracked path: inside the repository it must be gitignored (dist/), or it must be outside.
//
// Written into <dir>:
//   spec.html    the whole spec as one fragment: no <html>, <head> or <body>; the site wraps it.
//                Headings start at h2 with stable ids from the section number — §2 is #s2,
//                §2.1 is #s2-1, "Appendix B" is #appendix-b, the preamble is #introduction
//                (its heading is synthesized, as in the whitepaper); anything else takes its
//                slug. Every MUST and MUST NOT in prose is <span class="must">. Mermaid blocks
//                are <figure class="diagram"> holding a pre-rendered inline SVG that carries
//                classes only — no <style>, no style= attribute, no paint or font attribute,
//                no HTML inside the drawing, no font fetched — so the site's stylesheet owns
//                every colour and font. The classes are pact-web-kit's diagram contract
//                (site/diagram-classes.json, a copy of the kit's kit/diagram-classes.json).
//                Flowcharts and state diagrams are laid out by ELK (site/mermaid.mjs); a
//                flowchart wider than the text column is also laid out the other way round
//                (LR <-> TB, the rule the whitepaper follows) and drawn whichever way reads
//                larger in the column. When the commit carries LICENSE-docs, the fragment ends in
//                <div class="licence">: the copyright line and the attribution line for that
//                commit's version, worded by site/licence.mjs from that commit's NOTICE and
//                CITATION.cff, as the whitepaper's licence page is. The PACT 1.2.0 text predates the
//                licences and has no such block.
//   diagrams.json  what each drawing was drawn from, in document order: [{ kind, source,
//                turned }] — `source` is the mermaid the SVG was rendered from (SPEC.md's
//                block, with a flowchart's direction swapped where `turned` is true), so the
//                site can show the source beside the drawing.
//   toc.json     the heading tree: [{ level, text, id, children: [...] }].
//   musts.json   every normative sentence, [{ heading, section, id, hash, text }]: `heading` is
//                the id of the heading it sits under, `id` is pact-identity's registry id for
//                that sentence (musts.json, matched by the sentence hash its checker computes)
//                or null when the registry has no entry for these exact words.
//   meta.json    the version and date the whitepaper build parses from the header line, the
//                ref, the commit, this generator's version, and the counts.
//   vectors/     when the commit has vectors/pact-2.0-vectors.json: that file, byte for byte,
//                as a download, and index.html, a fragment rendering it.
//
// The markdown pipeline is site/markdown.mjs and the mermaid pipeline site/mermaid.mjs, both
// shared with the whitepaper; this file adds the id scheme, the MUST markup, the SVG class
// mapping and the JSON sidecars. Same commit in, same bytes out: site/spec-html.test.mjs holds
// that, and the site regenerates from its locked commit to prove its copy is this output.

import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, isAbsolute, join, relative, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { licence } from './licence.mjs'
import { esc, renderSpec, slugify, splitSpec } from './markdown.mjs'
import { FONT, installMermaid, launch } from './mermaid.mjs'

export const GENERATOR = 'spec-html 3'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')

// The column a drawing is read in on the site, in px: pact-web-kit's docs layout gives the text
// 46rem (736 px), and a drawing past 960 px tall no longer fits a laptop's window beside its text.
const COLUMN = 736, TALL = 960

/* ---------------------------------------------------------- the contract */

// Every class an emitted drawing may carry is pact-web-kit's diagram contract, whose one copy
// is the kit's kit/diagram-classes.json; site/diagram-classes.json is that file byte for byte,
// so a build needs no sibling checkout, and site/spec-html.test.mjs holds the copy to the
// kit's whenever the kit is checked out beside this repository. The shape: the <svg> carries
// `dg` and its kind (`dg-flowchart`, `dg-state`, `dg-sequence`) inside <figure class="diagram">;
// each primitive carries a part, then a role, then modifiers — `dg-node dg-shape`,
// `dg-node dg-label`, `dg-edge dg-label`, `dg-edge dg-bg`, `dg-actor dg-shape`,
// `dg-note dg-label`, `dg-frame dg-shape`, `dg-arrow dg-shape`, `dg-number dg-label` … — and
// a line carries its part alone (`dg-edge`, `dg-edge dg-dashed`, `dg-lifeline`, `dg-frame`,
// and `dg-number` for the zero-length line that carries a sequence number's marker, whose
// circle is the `dg-number dg-shape`). A <g>, <defs>, <marker> or <tspan> carries nothing.
// "classes" lists every valid combination with the tags it lands on; "text" is the size and
// weight every label was laid out at, which the build checks against what mermaid wrote.
export const CONTRACT_PATH = resolve(root, 'site', 'diagram-classes.json')
export const CONTRACT = Object.freeze(JSON.parse(readFileSync(CONTRACT_PATH, 'utf8')))
const PRIMITIVES = ['rect', 'circle', 'ellipse', 'line', 'path', 'polygon', 'polyline', 'text']
const SVG_TAGS = new Set(['svg', 'g', 'defs', 'marker', 'tspan', ...PRIMITIVES])
const kindsOf = (contract) => Object.keys(contract.svg).filter((k) => k !== 'dg')

// A heading's id: the section number where there is one, a slug otherwise.
export function sectionId(title) {
  const t = title.trim()
  let m
  if ((m = /^(\d+)\.(\d+)\s/.exec(t))) return `s${m[1]}-${m[2]}`
  if ((m = /^(\d+)\.\s/.exec(t))) return `s${m[1]}`
  if ((m = /^Appendix ([A-Z])\b/.exec(t))) return `appendix-${m[1].toLowerCase()}`
  return slugify(t)
}

/* ----------------------------------------------------------------- MUSTs */

// A copy of `extract` in pact-identity/js/musts.mjs: the same units, the same sentence
// splitter, the same hash, so a sentence here matches the registry's entry for it. The copy is
// held to the original by site/spec-html.test.mjs whenever the sibling is checked out.
export function extractMusts(markdown) {
  const lines = markdown.split('\n')
  const units = []
  let fence = false, section = '(front matter)', buf = []
  const flush = () => { if (buf.length) { units.push({ section, text: buf.join(' ') }); buf = [] } }
  for (const line of lines) {
    if (/^\s*```/.test(line)) { fence = !fence; flush(); continue }
    if (fence) continue
    const h = /^(#{2,4})\s+(.*)$/.exec(line)
    if (h) { flush(); section = h[2].trim(); continue }
    if (!line.trim()) { flush(); continue }
    if (/^\s*[-*|]/.test(line)) { flush(); units.push({ section, text: line.trim() }); continue }
    buf.push(line.trim())
  }
  flush()

  const splitter = /(?<=[.!?:])\s+(?=[A-Z`*(§"“—\d])/
  const NORM = /\bMUST NOT\b|\bMUST\b|\bREQUIRED\b/
  const out = []
  const seen = new Map()
  for (const u of units) {
    const pieces = u.text.startsWith('|') ? u.text.split('|').map((x) => x.trim()).filter(Boolean) : u.text.split(splitter)
    for (const p of pieces) {
      if (!NORM.test(p)) continue
      const n = (seen.get(u.section) ?? 0) + 1
      seen.set(u.section, n)
      const text = p.replace(/\s+/g, ' ').trim()
      out.push({
        id: `${u.section.split(/\s/)[0].replace(/^§/, '')}#${n}`,
        section: u.section,
        hash: createHash('sha256').update(text).digest('hex').slice(0, 12),
        text,
      })
    }
  }
  return out
}

// The sentences of `body`, each under its heading id, with the registry's id where the
// registry holds these exact words (the same hash under the same section prefix).
export function mustsOf(body, registry) {
  const byHash = new Map()
  for (const [id, entry] of Object.entries(registry ?? {})) {
    if (!byHash.has(entry.hash)) byHash.set(entry.hash, [])
    byHash.get(entry.hash).push(id)
  }
  return extractMusts(body).map((m) => {
    const ids = byHash.get(m.hash) ?? []
    const prefix = m.id.split('#')[0]
    const id = ids.find((x) => x.split('#')[0] === prefix) ?? (ids.length === 1 ? ids[0] : null)
    return { heading: sectionId(m.section), section: m.section, id, hash: m.hash, text: m.text }
  })
}

/* --------------------------------------------------------------- the SVG */

// Runs inside the page, over one rendered <svg>: maps mermaid's markup onto the class
// contract and strips everything else it styled with. Returns what it could not map (the
// build fails on any) and, per text class, the font sizes and weights mermaid had written
// on the text before they were stripped (the build holds them to the contract's "text").
// Closes over nothing: installed by string, like site/mermaid.mjs.
export function cleanSvg(svg) {
  const KINDS = { 'flowchart-v2': 'flowchart', stateDiagram: 'state', sequence: 'sequence' }
  const kind = KINDS[svg.getAttribute('aria-roledescription')]
  const unmapped = []
  const text = {}
  if (!kind) return { unmapped: [`diagram kind ${svg.getAttribute('aria-roledescription')}`], text }
  // A flowchart's or a state diagram's labels carry no size of their own: they were measured
  // at the root rule of mermaid's <style> (`#<id>{…font-size:16px…}`), which is recorded as
  // dg-label's, the base every label takes, before the <style> goes. Missing, it is recorded
  // as "(none)", which the contract's 16px refuses.
  const style = svg.querySelector('style')
  const rootSize = style && new RegExp(`#${CSS.escape(svg.id)}\\{[^}]*font-size:\\s*([^;}]+)`).exec(style.textContent)
  text['dg-label'] = { 'font-size': [rootSize ? rootSize[1].trim() : '(none)'] }
  for (const el of svg.querySelectorAll('style, symbol, filter, linearGradient')) el.remove()
  for (const defs of svg.querySelectorAll('defs')) if (!defs.children.length) defs.remove()
  // An edge with no label still gets an empty label group; nothing to draw, nothing to keep.
  for (const g of svg.querySelectorAll('g.edgeLabel')) if (!g.textContent.trim()) g.remove()
  // A node's or cluster's label sits on its own background rect, which the node's shape
  // already provides, and an unlabelled edge leaves a dimensionless one in a bare group;
  // only an edge label needs one, to knock the line out behind its text. A rect with no
  // width draws nothing wherever it is.
  for (const r of svg.querySelectorAll('rect')) {
    if (r.hasAttribute('width') && (!r.classList.contains('background') || r.closest('g.edgeLabel'))) continue
    const g = r.parentElement
    r.remove()
    if (g.tagName === 'g' && !g.children.length && !g.getAttribute('class')) g.remove()
  }
  // What mermaid's stylesheet and inline styles decide about LAYOUT survives as attributes:
  // an actor's name is centred by an inline text-anchor; a flowchart node's label by a rule
  // of the <style> element (`.node .label text { text-anchor: middle }`) that the state
  // diagram's stylesheet does not have — its labels, like a cluster's, are placed by their
  // translate and anchor at the start. Paint and fonts do not survive: they are the site's.
  const LAYOUT = ['text-anchor', 'dominant-baseline', 'alignment-baseline']
  for (const el of svg.querySelectorAll('[style]')) {
    for (const p of el.getAttribute('style').split(';')) {
      const [name, value] = p.split(':').map((s) => s?.trim())
      if (LAYOUT.includes(name) && value && !el.hasAttribute(name)) el.setAttribute(name, value)
    }
  }
  if (kind === 'flowchart') {
    for (const t of svg.querySelectorAll('g.node text')) if (!t.hasAttribute('text-anchor')) t.setAttribute('text-anchor', 'middle')
  }

  const had = (el, name) => el.classList.contains(name)
  const dashes = (el) => {
    const dash = /stroke-dasharray:\s*([\d.]+)[,\s]+([\d.]+)/.exec(el.getAttribute('style') || '')
      || /^([\d.]+)[,\s]+([\d.]+)/.exec(el.getAttribute('stroke-dasharray') || '')
    return (dash && Number(dash[1]) > 0 && Number(dash[2]) > 0) || /edge-pattern-(dotted|dashed)/.test(el.getAttribute('class') || '')
  }
  const describe = (el) => {
    const chain = []
    for (let e = el; e && e !== svg; e = e.parentElement) chain.unshift(`${e.tagName}${e.getAttribute('class') ? '.' + e.getAttribute('class').trim().replace(/\s+/g, '.') : ''}`)
    return chain.join(' > ')
  }
  // The contract's spelling: a part, a role, modifiers, each under the kit's prefix.
  const c = (...names) => names.map((n) => `dg-${n}`).join(' ')
  const classify = (el) => {
    const tag = el.tagName
    const marker = el.closest('marker')
    if (tag === 'g' || tag === 'defs' || tag === 'tspan' || tag === 'marker') return ''
    if (marker) return /sequencenumber$/.test(marker.id) ? c('number', 'shape') : c('arrow', 'shape')
    const isText = tag === 'text'
    if (kind !== 'sequence') {
      if (el.closest('g.cluster-label')) return isText ? c('cluster', 'label') : null
      if (el.closest('g.cluster')) return isText ? null : c('cluster', 'shape')
      const node = el.closest('g.node')
      if (node) {
        if (isText) return c('node', 'label')
        return had(node, 'state-start') || had(node, 'state-end') || had(el, 'state-start') || had(el, 'state-end')
          ? c('node', 'shape', 'terminal') : c('node', 'shape')
      }
      if (el.closest('g.edgeLabel')) return isText ? c('edge', 'label') : tag === 'rect' ? c('edge', 'bg') : null
      if (el.closest('g.edges') && tag === 'path') return dashes(el) ? c('edge', 'dashed') : c('edge')
      return null
    }
    if (el.closest('g.actor-man')) return isText ? c('actor', 'label') : c('actor', 'shape')
    if (had(el, 'actor')) return isText ? c('actor', 'label') : c('actor', 'shape')
    if (had(el, 'actor-line')) return c('lifeline')
    if (had(el, 'note')) return c('note', 'shape')
    if (had(el, 'noteText')) return c('note', 'label')
    if (had(el, 'loopLine')) return dashes(el) ? c('frame', 'dashed') : c('frame')
    if (had(el, 'labelBox')) return c('frame', 'shape')
    if (had(el, 'labelText') || had(el, 'loopText') || had(el, 'sectionTitle')) return c('frame', 'label')
    if (had(el, 'messageText')) return c('edge', 'label')
    if (had(el, 'messageLine0') || had(el, 'messageLine1')) return dashes(el) ? c('edge', 'dashed') : c('edge')
    if (had(el, 'sequenceNumber')) return c('number', 'label')
    // A sequence number's circle is a marker on a zero-length line; the line carries
    // `dg-number` alone: it draws nothing itself, and the marker's circle is the
    // `dg-number dg-shape`.
    if (tag === 'line' && /sequencenumber\)$/.test(el.getAttribute('marker-start') || '')) return c('number')
    return null
  }
  // What mermaid wrote about a text's font, as an attribute or in its style: recorded per
  // class before it is stripped, so the build can hold it to the contract.
  const fontOf = (el) => {
    const out = {}
    for (const p of (el.getAttribute('style') || '').split(';')) {
      const [name, value] = p.split(':').map((s) => s?.trim())
      if ((name === 'font-size' || name === 'font-weight') && value) out[name] = value
    }
    for (const name of ['font-size', 'font-weight']) if (el.hasAttribute(name)) out[name] = el.getAttribute(name).trim()
    return out
  }

  const PAINT = /^(style|fill|fill-rule|stroke|stroke-width|stroke-dasharray|stroke-dashoffset|stroke-linecap|stroke-linejoin|font|font-family|font-size|font-weight|font-style|color|opacity|filter|name|data-.*)$/
  // Every decision is taken before any class is rewritten: a child is classified by the
  // mermaid classes of its ancestors, which the rewrite removes.
  const decisions = [...svg.querySelectorAll('*')].map((el) => [el, classify(el), describe(el)])
  for (const [el, cls, where] of decisions) {
    if (cls === null) { unmapped.push(where); continue }
    if (el.tagName === 'text' && cls) {
      const seen = (text[cls] ??= {})
      for (const [name, value] of Object.entries(fontOf(el))) {
        if (!(seen[name] ??= []).includes(value)) seen[name].push(value)
      }
    }
    if (cls) el.setAttribute('class', cls); else el.removeAttribute('class')
    for (const a of [...el.getAttributeNames()]) {
      if (PAINT.test(a) || (a === 'id' && el.tagName !== 'marker')) el.removeAttribute(a)
    }
  }
  svg.setAttribute('class', `dg dg-${kind}`)
  for (const a of [...svg.getAttributeNames()]) if (PAINT.test(a)) svg.removeAttribute(a)
  return { unmapped, text }
}

// What the audit refuses in a fragment, against a contract (the committed copy unless the
// caller passes the kit's). Exported so the tests can show it red on a planted defect, and
// run by the build on its own output before anything is written.
export function auditFragment(html, contract = CONTRACT) {
  const problems = []
  if (/\sstyle=/i.test(html)) problems.push('a style= attribute')
  if (/<style\b/i.test(html)) problems.push('a <style> element')
  if (/<script\b/i.test(html)) problems.push('a <script> element')
  if (/\son[a-z]+=/i.test(html)) problems.push('an inline event handler')
  const ids = [...html.matchAll(/\sid="([^"]*)"/g)].map((m) => m[1])
  const dup = ids.filter((id, i) => ids.indexOf(id) !== i)
  if (dup.length) problems.push(`duplicate ids: ${[...new Set(dup)].join(', ')}`)
  const svgs = html.match(/<svg\b[\s\S]*?<\/svg>/g) ?? []
  const figures = (html.match(/<figure class="diagram"><svg\b/g) ?? []).length
  if (figures !== svgs.length) problems.push(`${svgs.length} drawings, ${figures} inside <figure class="diagram">`)
  const kinds = kindsOf(contract)
  svgs.forEach((svg, i) => {
    const where = `diagram ${i + 1}`
    if (/<foreignObject/i.test(svg)) problems.push(`${where}: a foreignObject (HTML inside the drawing)`)
    for (const m of svg.matchAll(/<([a-zA-Z][\w:-]*)\b([^>]*)>/g)) {
      const [, tag, attrs] = m
      if (!SVG_TAGS.has(tag)) { problems.push(`${where}: a <${tag}>`); continue }
      const paint = /\s(fill|stroke|stroke-width|stroke-dasharray|font-family|font-size|font-weight|font-style|color|opacity|filter)=/.exec(attrs)
      if (paint) problems.push(`${where}: <${tag}> carries ${paint[1]}=`)
      const cls = /\sclass="([^"]*)"/.exec(attrs)
      const classes = cls ? cls[1].trim().replace(/\s+/g, ' ') : ''
      if (tag === 'svg') {
        const t = classes.split(' ')
        if (!(t.length === 2 && t[0] === 'dg' && kinds.includes(t[1]))) problems.push(`${where}: the <svg> carries "${classes}", not "dg" and one of ${kinds.join(', ')}`)
      } else if (PRIMITIVES.includes(tag)) {
        if (!classes) problems.push(`${where}: an unclassed <${tag}>`)
        else if (!contract.classes[classes]) problems.push(`${where}: <${tag}> carries "${classes}", which the contract does not have`)
        else if (!contract.classes[classes].on.includes(tag)) problems.push(`${where}: <${tag}> carries "${classes}", which the contract puts on ${contract.classes[classes].on.join(', ')}`)
      } else if (cls) problems.push(`${where}: a <${tag}> carries a class`)
    }
  })
  return problems
}

// What the drawings' text was laid out at, held to the contract's "text": every size and
// weight mermaid wrote on a label is the one the contract records for that class (a class
// not listed takes dg-label's), so a stylesheet that sets what the contract says draws the
// text the boxes were measured for. `seen` is cleanSvg's report, merged over the drawings.
export function auditText(seen, contract = CONTRACT) {
  const problems = []
  for (const [cls, fonts] of Object.entries(seen)) {
    for (const [name, values] of Object.entries(fonts)) {
      const want = contract.text[cls]?.[name] ?? contract.text['dg-label']?.[name]
      for (const value of values) {
        if (want === undefined) problems.push(`${cls} was laid out at ${name} ${value}, which the contract does not record`)
        else if (value !== want) problems.push(`${cls} was laid out at ${name} ${value}; the contract says ${want}`)
      }
    }
  }
  return problems
}

/* --------------------------------------------------------------- vectors */

function renderVectors(json) {
  const v = JSON.parse(json)
  const block = (value) => `<div class="code-block" data-lang="json"><pre><code class="language-json">${esc(JSON.stringify(value, null, 2))}</code></pre></div>\n`
  const rows = Object.entries(v).map(([k, x]) => {
    const kind = Array.isArray(x) ? `${x.length} cases` : typeof x === 'object' ? `${Object.keys(x).length} entries` : 'text'
    return `<tr><td><a href="#vectors-${esc(slugify(k))}"><code>${esc(k)}</code></a></td><td>${esc(kind)}</td></tr>`
  }).join('\n')
  let out = `<div class="table-wrap">\n<table>\n<thead>\n<tr><th>Member</th><th>Holds</th></tr>\n</thead>\n<tbody>\n${rows}\n</tbody>\n</table>\n</div>\n`
  for (const [k, x] of Object.entries(v)) {
    out += `<h2 id="vectors-${esc(slugify(k))}"><code>${esc(k)}</code></h2>\n`
    if (Array.isArray(x) && x.every((c) => c && typeof c === 'object' && ('name' in c || 'label' in c) && 'expect' in c)) {
      out += `<div class="table-wrap">\n<table>\n<thead>\n<tr><th>Case</th><th>Expect</th></tr>\n</thead>\n<tbody>\n`
      out += x.map((c) => `<tr><td>${esc(String(c.name ?? c.label))}</td><td><code>${esc(String(c.expect))}</code></td></tr>`).join('\n')
      out += `\n</tbody>\n</table>\n</div>\n`
    }
    out += block(x)
  }
  return out
}

/* ------------------------------------------------------------- the build */

const git = (...args) => execFileSync('git', ['-C', root, ...args], { encoding: 'utf8', maxBuffer: 1 << 26 })
const sha256 = (s) => createHash('sha256').update(s).digest('hex')

function parseArgs(argv) {
  const opts = { ref: null, out: null, musts: undefined }
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a === '--ref') opts.ref = argv[++i]
    else if (a === '--out') opts.out = argv[++i]
    else if (a === '--musts') opts.musts = argv[++i]
    else throw new Error(`unknown argument ${a}`)
  }
  if (!opts.ref || !opts.out) throw new Error('usage: node site/spec-html.mjs --ref <git ref> --out <dir> [--musts <path>|none]')
  return opts
}

// The output directory may not become tracked content of this repository.
function refuseTrackedOut(out) {
  const rel = relative(root, out)
  if (rel.startsWith('..') || isAbsolute(rel)) return
  try { execFileSync('git', ['-C', root, 'check-ignore', '-q', rel]); return } catch {}
  throw new Error(`--out ${out} is inside this repository and not gitignored; the site vendors the output, this repository never holds it`)
}

function loadRegistry(musts) {
  if (musts === 'none') return null
  const path = musts ?? resolve(root, '..', 'pact-identity', 'js', 'musts.json')
  if (!existsSync(path)) {
    if (musts) throw new Error(`--musts ${musts}: no such file`)
    return null
  }
  const text = readFileSync(path, 'utf8')
  return { registry: JSON.parse(text), sha256: sha256(text) }
}

// `contract` is the committed copy unless a test passes another, to show the audits red.
export async function build({ ref, out, musts, contract = CONTRACT }) {
  const commit = git('rev-parse', '--verify', '--quiet', `${ref}^{commit}`).trim()
  out = resolve(out)
  refuseTrackedOut(out)
  const spec = git('show', `${commit}:SPEC.md`)
  const tree = new Set(git('ls-tree', '-r', '--name-only', commit).split('\n'))
  const vectorsPath = 'vectors/pact-2.0-vectors.json'
  const vectors = tree.has(vectorsPath) ? git('show', `${commit}:${vectorsPath}`) : null

  const { version, date, revisionNote, body } = splitSpec(spec)
  const rights = licence((p) => tree.has(p) ? git('show', `${commit}:${p}`) : null, { version, date })
  const { html, headings } = renderSpec(body, { slugify: sectionId, must: true })
  const sources = [...body.matchAll(/^```mermaid\n([\s\S]*?)\n```/gm)].map((m) => m[1])
  const figures = html.match(/<figure class="diagram"><pre class="mermaid">[\s\S]*?<\/pre><\/figure>/g) ?? []
  if (figures.length !== sources.length) throw new Error(`${sources.length} mermaid blocks in the text, ${figures.length} figures in the HTML`)

  // Render the figures alone in a page that loads the whitepaper's fonts, so text is measured
  // exactly as the whitepaper measures it, then read each cleaned <svg> back.
  const scratch = await mkdtemp(join(tmpdir(), 'spec-html-'))
  const browser = await launch()
  let drawings
  try {
    const page = join(scratch, 'figures.html')
    writeFileSync(page, `<!doctype html>\n<html lang="en"><head><meta charset="utf-8">\n<link rel="stylesheet" href="${pathToFileURL(resolve(root, 'site', 'whitepaper.css')).href}">\n</head><body>\n${figures.join('\n')}\n</body></html>\n`)
    const tab = await browser.newPage()
    const problems = []
    tab.on('pageerror', (e) => problems.push(`page error: ${e.message}`))
    tab.on('console', (m) => { if (m.type() === 'error') problems.push(`console: ${m.text()}`) })
    await tab.goto(pathToFileURL(page).href, { waitUntil: 'load' })
    // The page shows no prose, so nothing has asked for the fonts yet; mermaid measures
    // text the instant it renders, and a face still loading measures as the fallback,
    // which moved a sequence diagram's actors by 5 px between two runs. Load every face
    // the drawings use first, and refuse to go on without them.
    const fonts = await tab.evaluate(async () => {
      await Promise.all(['400 16px Inter', '500 16px Inter', '400 12px Inter'].map((f) => document.fonts.load(f, 'Aa→‖≠≤≥')))
      await document.fonts.ready
      return ['400 16px Inter', '500 16px Inter'].filter((f) => !document.fonts.check(f))
    })
    if (fonts.length) throw new Error(`fonts not loaded: ${fonts.join(', ')}`)
    await installMermaid(tab)
    await tab.addScriptTag({ content: `window.pactCleanSvg = ${cleanSvg}` })
    drawings = await tab.evaluate(async (font, column, tall) => {
      mermaid.initialize(pactMermaid.config(font, { htmlLabels: false, base: font }))
      // How large a drawing of w x h reads in the column: never above 1, and a drawing taller
      // than `tall` counts as shrunk to it, so turning a wide flowchart does not buy a tower.
      const fit = (w, h) => Math.min(1, column / w, tall / h)
      const turn = (src) => src.replace(/^(\s*(?:flowchart|graph))\s+(LR|TB|TD)\b/, (m, k, d) => `${k} ${d === 'LR' ? 'TB' : 'LR'}`)
      const out = []
      let n = 0
      for (const pre of document.querySelectorAll('figure.diagram pre.mermaid')) {
        const figure = pre.parentElement
        const draw = async (source) => {
          const { svg: markup } = await mermaid.render(`spec-diagram-${n++}`, source)
          figure.innerHTML = markup
          const svg = figure.querySelector('svg')
          pactMermaid.widenNotes(svg)
          const { x0, y0, x1, y1 } = pactMermaid.cover(svg)
          return { source, w: x1 - x0, h: y1 - y0, html: figure.innerHTML }
        }
        const written = pre.textContent.replace(/\n$/, '')   // the block as SPEC.md writes it
        let best = await draw(written)
        if (best.w > column && turn(written) !== written) {
          const other = await draw(turn(written))
          if (fit(other.w, other.h) > fit(best.w, best.h)) best = other
        }
        figure.innerHTML = best.html
        const svg = figure.querySelector('svg')
        const { unmapped, text } = pactCleanSvg(svg)
        svg.setAttribute('width', Math.round(best.w))
        svg.setAttribute('height', Math.round(best.h))
        out.push({ kind: svg.getAttribute('class').split(' ')[1].replace(/^dg-/, ''), svg: figure.innerHTML, source: best.source, turned: best.source !== written, unmapped, text })
      }
      return out
    }, FONT, COLUMN, TALL)
    if (problems.length) throw new Error(`browser reported:\n  ${problems.join('\n  ')}`)
  } finally {
    await browser.close()
    await rm(scratch, { recursive: true, force: true })
  }
  const unmapped = drawings.flatMap((d, i) => d.unmapped.map((u) => `diagram ${i + 1}: ${u}`))
  if (unmapped.length) throw new Error(`elements the class contract does not cover:\n  ${unmapped.join('\n  ')}`)
  const seen = {}
  for (const d of drawings) {
    for (const [cls, fonts] of Object.entries(d.text)) {
      for (const [name, values] of Object.entries(fonts)) {
        const all = ((seen[cls] ??= {})[name] ??= [])
        for (const v of values) if (!all.includes(v)) all.push(v)
      }
    }
  }
  const laidOut = auditText(seen, contract)
  if (laidOut.length) throw new Error(`the drawings' text is not laid out as the contract says:\n  ${laidOut.join('\n  ')}`)

  let fragment = html
  figures.forEach((figure, i) => {
    fragment = fragment.replace(figure, `<figure class="diagram">${drawings[i].svg}</figure>`)
  })
  if (rights) fragment += rights.web
  const problems = auditFragment(fragment, contract)
  if (problems.length) throw new Error(`the fragment fails its own audit:\n  ${problems.join('\n  ')}`)

  const toc = []
  for (const h of headings) {
    const node = { level: h.level, text: h.title, id: h.id, children: [] }
    if (h.level === 2 || !toc.length) toc.push(node); else toc.at(-1).children.push(node)
  }
  const loaded = loadRegistry(musts)
  const sentences = mustsOf(body, loaded?.registry)
  const meta = {
    generator: GENERATOR,
    ref, commit, version, date, revision_note: revisionNote ?? null,
    headings: headings.length,
    diagrams: drawings.length,
    musts: {
      sentences: sentences.length,
      keywords: (fragment.match(/<span class="must">/g) ?? []).length,
      registered: sentences.filter((s) => s.id).length,
      registry: loaded ? { sha256: loaded.sha256 } : null,
    },
    vectors: vectors ? { file: vectorsPath, bytes: Buffer.byteLength(vectors), sha256: sha256(vectors) } : null,
  }

  mkdirSync(out, { recursive: true })
  const json = (x) => JSON.stringify(x, null, 2) + '\n'
  writeFileSync(join(out, 'spec.html'), fragment)
  writeFileSync(join(out, 'diagrams.json'), json(drawings.map((d) => ({ kind: d.kind, source: d.source, turned: d.turned }))))
  writeFileSync(join(out, 'toc.json'), json(toc))
  writeFileSync(join(out, 'musts.json'), json(sentences))
  writeFileSync(join(out, 'meta.json'), json(meta))
  if (vectors) {
    mkdirSync(join(out, 'vectors'), { recursive: true })
    writeFileSync(join(out, 'vectors', 'pact-2.0-vectors.json'), vectors)
    writeFileSync(join(out, 'vectors', 'index.html'), renderVectors(vectors))
  }
  return meta
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const meta = await build(parseArgs(process.argv.slice(2)))
    console.log(`spec ${meta.version} (${meta.date}) at ${meta.commit.slice(0, 7)}: ${meta.headings} headings, ${meta.diagrams} diagrams, ${meta.musts.keywords} MUSTs in ${meta.musts.sentences} sentences (${meta.musts.registered} in the registry)${meta.vectors ? `, vectors ${meta.vectors.bytes} bytes` : ', no vectors file'}`)
  } catch (e) {
    console.error(`spec-html: ${e.message}`)
    process.exit(1)
  }
}
