// What site/spec-html.mjs promises, shown on both texts the protocol site publishes: the
// current SPEC.md (HEAD) and the PACT 1.2.0 text (d130444, which this repository must never
// hold as markdown). Run by `npm run spec:check`, part of `make check`.
//
// The MUST extractor here is a copy of pact-identity's; the copy is held to the original
// whenever the sibling checkout is beside this repository (PACT_IDENTITY_DIR overrides the
// place), and the run fails without it: a copy nothing compares drifts the day it is written.
// The diagram contract is a copy of pact-web-kit's kit/diagram-classes.json; with the kit
// beside this repository (PACT_WEB_KIT_DIR overrides the place) the copy is held to the
// kit's file byte for byte and the drawings are audited against the kit's; without it the
// audit holds to the committed copy, and the run says so on stderr and as a skipped test.

import { execFileSync } from 'node:child_process'
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import assert from 'node:assert/strict'
import { after, before, describe, it } from 'node:test'
import { slugify, splitSpec } from './markdown.mjs'
import { auditFragment, auditText, build, CONTRACT, CONTRACT_PATH, extractMusts, sectionId } from './spec-html.mjs'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const git = (...args) => execFileSync('git', ['-C', root, ...args], { encoding: 'utf8', maxBuffer: 1 << 26 })
const PACT1 = 'd130444'
const identity = process.env.PACT_IDENTITY_DIR ?? resolve(root, '..', 'pact-identity')
const kit = process.env.PACT_WEB_KIT_DIR ?? resolve(root, '..', 'pact-web-kit')
const kitContract = join(kit, 'kit', 'diagram-classes.json')
const sibling = existsSync(kitContract)
if (!sibling) console.error(`spec-html.test: pact-web-kit is not at ${kit} (set PACT_WEB_KIT_DIR): the drawings are audited against the committed copy site/diagram-classes.json, which this run cannot compare with the kit's`)
// The contract the drawings are audited against: the kit's when it is here, the copy otherwise.
const contract = sibling ? JSON.parse(readFileSync(kitContract, 'utf8')) : CONTRACT
const PRIMITIVE = /<(rect|circle|ellipse|line|path|polygon|polyline|text)\b[^>]*class="([^"]*)"/g

const files = (dir, prefix = '') => readdirSync(dir).sort().flatMap((name) => {
  const p = join(dir, name)
  return statSync(p).isDirectory() ? files(p, `${prefix}${name}/`) : [`${prefix}${name}`]
})
const read = (dir, name) => readFileSync(join(dir, name), 'utf8')
const json = (dir, name) => JSON.parse(read(dir, name))
const flat = (toc) => toc.flatMap((n) => [n, ...flat(n.children)])

// MUST tokens in prose: fences and inline code removed first, as the renderer marks none there.
const prose = (body) => body.replace(/^```[\s\S]*?^```/gm, '').replace(/`[^`\n]*`/g, '')
const count = (s, re) => (s.match(re) ?? []).length

let scratch, out2, out2again, out1, spec2, body2, spec1, body1

before(async () => {
  scratch = await mkdtemp(join(tmpdir(), 'spec-html-test-'))
  out2 = join(scratch, 'pact-2')
  out2again = join(scratch, 'pact-2-again')
  out1 = join(scratch, 'pact-1')
  // Once through the command line, so the contract on the shell is the one exercised.
  execFileSync(process.execPath, [resolve(root, 'site', 'spec-html.mjs'), '--ref', 'HEAD', '--out', out2], { stdio: 'pipe' })
  await build({ ref: 'HEAD', out: out2again })
  await build({ ref: PACT1, out: out1 })
  spec2 = git('show', 'HEAD:SPEC.md'); body2 = splitSpec(spec2).body
  spec1 = git('show', `${PACT1}:SPEC.md`); body1 = splitSpec(spec1).body
})
after(() => rm(scratch, { recursive: true, force: true }))

describe('the output', () => {
  it('is the same bytes for the same commit', () => {
    assert.deepEqual(files(out2), files(out2again))
    for (const f of files(out2)) assert.ok(readFileSync(join(out2, f)).equals(readFileSync(join(out2again, f))), `${f} differs between two runs`)
  })

  it('names the ref, the commit, the version and the date the whitepaper build parses', () => {
    const meta = json(out2, 'meta.json')
    assert.equal(meta.ref, 'HEAD')
    assert.equal(meta.commit, git('rev-parse', 'HEAD').trim())
    const { version, date } = splitSpec(spec2)
    assert.equal(meta.version, version)
    assert.equal(meta.date, date)
    assert.match(meta.date, /^\d{4}-\d{2}-\d{2}$/)
    assert.equal(meta.generator, 'spec-html 1')
  })

  it('is a fragment, not a page', () => {
    const html = read(out2, 'spec.html')
    assert.doesNotMatch(html, /<(html|head|body|!doctype)\b/i)
    assert.ok(html.startsWith('<h2 id="introduction"'))
  })
})

describe('headings', () => {
  it('each carry one id, unique, from the section number where there is one', () => {
    const html = read(out2, 'spec.html')
    const heads = [...html.matchAll(/<h([23]) id="([^"]*)"[^>]*>(.*?)<\/h\1>/g)].map((m) => ({ level: Number(m[1]), id: m[2], text: m[3] }))
    assert.equal(heads.length, json(out2, 'meta.json').headings)
    assert.equal(new Set(heads.map((h) => h.id)).size, heads.length, 'a duplicate heading id')
    assert.equal(count(html, /<h[23]\b/g), heads.length, 'a heading without an id')
    for (const h of heads) {
      const text = h.text.replace(/<[^>]+>/g, '')
      let m
      if ((m = /^(\d+)\.(\d+)\s/.exec(text))) assert.equal(h.id, `s${m[1]}-${m[2]}`)
      else if ((m = /^(\d+)\.\s/.exec(text))) assert.equal(h.id, `s${m[1]}`)
      else if ((m = /^Appendix ([A-Z])\b/.exec(text))) assert.equal(h.id, `appendix-${m[1].toLowerCase()}`)
    }
    assert.equal(sectionId('2.1 Deriving the root from a passkey'), 's2-1')
    assert.equal(sectionId('14. Certificates'), 's14')
    assert.equal(sectionId('Appendix B: sealed-envelope test vectors'), 'appendix-b')
    assert.equal(sectionId('Introduction'), 'introduction')
  })

  it('are the heading tree in toc.json, in document order', () => {
    const html = read(out2, 'spec.html')
    const heads = [...html.matchAll(/<h([23]) id="([^"]*)"/g)].map((m) => ({ level: Number(m[1]), id: m[2] }))
    const toc = json(out2, 'toc.json')
    assert.deepEqual(flat(toc).map((n) => ({ level: n.level, id: n.id })), heads)
    for (const n of toc) assert.equal(n.level, 2)
    for (const n of flat(toc)) for (const c of n.children) assert.equal(c.level, 3)
  })

  it("drop the spec's own table of contents", () => {
    assert.doesNotMatch(read(out2, 'spec.html'), /Table of contents/)
    assert.equal(flat(json(out2, 'toc.json')).filter((n) => /Table of contents/.test(n.text)).length, 0)
  })
})

describe('diagrams', () => {
  it("carry pact-web-kit's diagram contract: site/diagram-classes.json is the kit's kit/diagram-classes.json byte for byte", (t) => {
    if (!sibling) return t.skip(`pact-web-kit is not at ${kit}: the copy was not compared with the kit's; the audits below hold to the copy`)
    assert.ok(readFileSync(CONTRACT_PATH).equals(readFileSync(kitContract)), `site/diagram-classes.json differs from ${kitContract}: copy the kit's file over it`)
    assert.deepEqual(CONTRACT, contract)
  })

  it('replace every mermaid block with an inline SVG, inside <figure class="diagram">, that carries the contract\'s classes only', () => {
    const kinds = Object.keys(contract.svg).filter((k) => k !== 'dg')
    for (const [out, body] of [[out2, body2], [out1, body1]]) {
      const html = read(out, 'spec.html')
      const fences = count(body, /^```mermaid$/gm)
      assert.ok(fences >= 9, 'the text has diagrams to prove this on')
      assert.equal(count(html, /<svg\b/g), fences)
      assert.equal(count(html, new RegExp(`<figure class="diagram"><svg\\b[^>]*class="dg (${kinds.join('|')})"`, 'g')), fences)
      assert.equal(count(html, /mermaid/g), 0, 'no mermaid source left in the fragment')
      assert.deepEqual(auditFragment(html, contract), [])
      assert.equal(json(out, 'meta.json').diagrams, fences)
    }
    const drawn = new Set([...read(out2, 'spec.html').matchAll(/<svg\b[^>]*class="dg (dg-\w+)"/g)].map((m) => m[1]))
    assert.deepEqual([...drawn].sort(), [...kinds].sort(), 'the current text exercises every kind')
  })

  it('carry no style attribute, no <style>, no HTML label, no paint attribute, and only the contract classes — shown red on each planted defect', () => {
    const html = read(out2, 'spec.html')
    const svg = html.match(/<svg\b[\s\S]*?<\/svg>/)[0]
    const planted = (from, to) => auditFragment(html.replace(from, to), contract)
    assert.deepEqual(auditFragment(html, contract), [])
    assert.match(planted('<svg ', '<svg style="fill:red" ').join('\n'), /a style= attribute/)
    assert.match(planted('<svg ', '<svg STYLE="fill:red" ').join('\n'), /a style= attribute/)
    assert.match(planted('</svg>', '<style>text{fill:red}</style></svg>').join('\n'), /a <style> element/)
    assert.match(planted('</svg>', '<foreignObject></foreignObject></svg>').join('\n'), /foreignObject/)
    assert.match(planted('class="dg-node dg-shape"', 'class="dg-node dg-shape" fill="#fff"').join('\n'), /carries fill=/)
    assert.match(planted('class="dg-node dg-shape"', 'class="dg-node dg-shape" font-size="12px"').join('\n'), /carries font-size=/)
    assert.match(planted('class="dg-node dg-shape"', 'class="mermaid-node"').join('\n'), /"mermaid-node", which the contract does not have/)
    assert.match(planted('class="dg-node dg-shape"', 'class="node shape"').join('\n'), /"node shape", which the contract does not have/)
    assert.match(planted('class="dg-node dg-shape"', 'class="dg-shape dg-node"').join('\n'), /"dg-shape dg-node", which the contract does not have/)
    assert.match(planted('<rect ', '<rect data-x="1" ').concat(planted('class="dg-node dg-shape"', 'class=""')).join('\n'), /an unclassed <rect>/)
    assert.match(planted('<rect ', '<rect class="dg-number dg-shape" ').join('\n'), /<rect> carries "dg-number dg-shape", which the contract puts on circle/)
    assert.match(planted('<g>', '<g class="dg-node">').join('\n'), /a <g> carries a class/)
    assert.match(planted('</svg>', '<span>x</span></svg>').join('\n'), /a <span>/)
    assert.match(planted(svg, svg + svg).join('\n'), /duplicate ids/)
    assert.match(planted('class="dg dg-flowchart"', 'class="dg-flowchart"').join('\n'), /the <svg> carries "dg-flowchart", not "dg" and one of/)
    assert.match(planted('class="dg dg-flowchart"', 'class="diagram flowchart"').join('\n'), /the <svg> carries "diagram flowchart", not "dg" and one of/)
    assert.match(planted('<figure class="diagram"><svg', '<figure class="diagram diagram-flowchart"><svg').join('\n'), /9 drawings, 8 inside <figure class="diagram">/)
  })

  it('draw every class of the contract, on exactly the tags it lists, across the two texts; nothing else', () => {
    const drawn = new Map()
    for (const out of [out2, out1]) {
      for (const m of read(out, 'spec.html').matchAll(PRIMITIVE)) {
        if (!drawn.has(m[2])) drawn.set(m[2], new Set())
        drawn.get(m[2]).add(m[1])
      }
    }
    assert.deepEqual([...drawn.keys()].sort(), Object.keys(contract.classes).sort(), 'the classes drawn are the contract, no more, no fewer')
    for (const [cls, { on }] of Object.entries(contract.classes)) assert.deepEqual([...drawn.get(cls)].sort(), [...on].sort(), `${cls}: the tags it lands on`)
    // A class is a part, then a role or nothing (a line), then modifiers — the grammar the kit's own test holds the file to.
    for (const cls of drawn.keys()) {
      const t = cls.split(' ')
      assert.ok(t[0] in contract.parts, `${cls}: begins with a part`)
      const hasRole = t[1] in contract.roles
      for (const x of t.slice(hasRole ? 2 : 1)) assert.ok(x in contract.modifiers, `${cls}: ${x} is a modifier`)
      if (!hasRole) for (const tag of drawn.get(cls)) assert.ok(['line', 'path'].includes(tag), `${cls}: a role-less class is a line`)
    }
    const html = read(out2, 'spec.html')
    assert.ok(/<line [^>]*class="dg-number"/.test(html), 'the carrier of a sequence number')
    assert.ok(/<marker [^>]*>\s*<circle [^>]*class="dg-number dg-shape"/.test(html), "the number's disc is the marker's circle")
    assert.ok(/<marker [^>]*>\s*<path [^>]*class="dg-arrow dg-shape"/.test(html), "an arrowhead is the marker's path")
  })

  it("were laid out at the size and weight the contract's \"text\" records, and a build against a contract that says otherwise is refused", async () => {
    // What cleanSvg reports for a sequence diagram, held to the contract: green as measured, red on a planted size.
    const seen = { 'dg-label': { 'font-size': ['16px'] }, 'dg-actor dg-label': { 'font-size': ['16px'], 'font-weight': ['500'] }, 'dg-number dg-label': { 'font-size': ['12px'] } }
    assert.deepEqual(auditText(seen, contract), [])
    assert.match(auditText({ ...seen, 'dg-number dg-label': { 'font-size': ['13px'] } }, contract).join('\n'), /dg-number dg-label was laid out at font-size 13px; the contract says 12px/)
    assert.match(auditText({ 'dg-label': { 'font-size': ['(none)'] } }, contract).join('\n'), /dg-label was laid out at font-size \(none\); the contract says 16px/)
    assert.match(auditText({ 'dg-edge dg-label': { 'font-style': ['italic'] } }, contract).join('\n'), /dg-edge dg-label was laid out at font-style italic, which the contract does not record/)
    // The build calls it on what mermaid wrote: a contract recording 13px for the number is refused, and one lacking a class the text draws.
    const thirteen = { ...contract, text: { ...contract.text, 'dg-number dg-label': { 'font-size': '13px' } } }
    await assert.rejects(build({ ref: 'HEAD', out: join(scratch, 'thirteen'), contract: thirteen }), /not laid out as the contract says:\n\s+dg-number dg-label was laid out at font-size 12px; the contract says 13px/)
    const { 'dg-frame dg-shape': _, ...fewer } = contract.classes
    await assert.rejects(build({ ref: 'HEAD', out: join(scratch, 'fewer'), contract: { ...contract, classes: fewer } }), /fails its own audit:\n\s+diagram \d+: <polygon> carries "dg-frame dg-shape", which the contract does not have/)
  })

  it('keep what places text and drop what paints it', () => {
    const html = read(out2, 'spec.html')
    // Every flowchart node label is anchored at its centre, every sequence actor's name too;
    // a state's label is placed by its translate, as mermaid's own stylesheet has it.
    let seen = 0
    for (const svg of html.match(/<svg\b[\s\S]*?<\/svg>/g)) {
      const kind = /class="dg dg-(\w+)"/.exec(svg)[1]
      for (const m of svg.matchAll(/<text\b([^>]*)>/g)) {
        if (!/class="dg-(node|actor) dg-label"/.test(m[1])) continue
        seen++
        if (kind === 'state') assert.doesNotMatch(m[1], /text-anchor/, m[0])
        else assert.match(m[1], /text-anchor="middle"/, m[0])
      }
    }
    assert.ok(seen > 40, `${seen} node and actor labels looked at`)
    assert.doesNotMatch(html, /<rect\b(?![^>]*\swidth=)[^>]*>/, 'a rect without a width')
  })
})

describe('MUSTs', () => {
  it('are marked once each in prose, never in code, as many as the text has', () => {
    for (const [out, body] of [[out2, body2], [out1, body1]]) {
      const html = read(out, 'spec.html')
      const p = prose(body)
      assert.equal(count(html, /<span class="must">MUST NOT<\/span>/g), count(p, /\bMUST NOT\b/g))
      assert.equal(count(html, /<span class="must">MUST<\/span>/g), count(p, /\bMUST\b(?! NOT)/g))
      assert.equal(count(html, /<span class="must">/g), json(out, 'meta.json').musts.keywords)
      // Nothing left bare: a MUST outside a span sits in code or in a diagram's text, where
      // it is not marked.
      const text = html.replace(/<svg\b[\s\S]*?<\/svg>/g, '')
      for (const m of text.matchAll(/(?<!must">)(?<!must">MUST )\bMUST\b/g)) {
        const before = text.lastIndexOf('<code', m.index), after = text.lastIndexOf('</code>', m.index)
        assert.ok(before > after, `a bare MUST outside code at ${m.index}`)
      }
    }
    assert.ok(count(body1, /^```[\s\S]*?MUST[\s\S]*?^```/gm) >= 1, 'the PACT 1 text has a MUST inside a fence, so this is proven on one')
    assert.ok(/<svg\b[\s\S]*?MUST[\s\S]*?<\/svg>/.test(read(out1, 'spec.html')), 'and one inside a diagram')
  })

  it('are listed as sentences under their heading, by the extractor pact-identity uses', async () => {
    assert.ok(existsSync(join(identity, 'js', 'musts.mjs')), `pact-identity is not at ${identity}: set PACT_IDENTITY_DIR`)
    const { extract } = await import(pathToFileURL(join(identity, 'js', 'musts.mjs')).href)
    for (const [out, body] of [[out2, body2], [out1, body1]]) {
      const theirs = extract(body), mine = extractMusts(body)
      assert.deepEqual(mine, theirs, 'the copied extractor differs from the original')
      const listed = json(out, 'musts.json')
      assert.deepEqual(listed.map((s) => [s.hash, s.text]), theirs.map((s) => [s.hash, s.text]))
      const ids = new Set([...read(out, 'spec.html').matchAll(/<h[23] id="([^"]*)"/g)].map((m) => m[1]))
      for (const s of listed) assert.ok(ids.has(s.heading), `${s.heading} is a heading of the fragment`)
      assert.equal(json(out, 'meta.json').musts.sentences, listed.length)
    }
  })

  it("carry the registry's id where the registry holds the same words", () => {
    const registry = JSON.parse(readFileSync(join(identity, 'js', 'musts.json'), 'utf8'))
    for (const out of [out2, out1]) {
      const listed = json(out, 'musts.json')
      for (const s of listed) {
        if (s.id === null) { assert.ok(!Object.values(registry).some((e) => e.hash === s.hash), `${s.hash} is in the registry but unmatched`); continue }
        assert.equal(registry[s.id].hash, s.hash, `${s.id}: the registry's hash`)
      }
      assert.equal(json(out, 'meta.json').musts.registered, listed.filter((s) => s.id).length)
    }
    // The current text is what the registry was written against: every sentence is in it.
    const current = json(out2, 'musts.json')
    assert.ok(current.every((s) => s.id), 'every MUST of the current text has a registry id')
  })
})

describe('the PACT 1 text', () => {
  it('renders from git at d130444: 1.2.0, its diagrams, no vectors file', () => {
    const meta = json(out1, 'meta.json')
    assert.equal(meta.version, '1.2.0')
    assert.equal(meta.date, '2026-08-30')
    assert.equal(meta.commit, git('rev-parse', PACT1).trim())
    assert.equal(meta.diagrams, 9)
    assert.equal(meta.vectors, null)
    assert.ok(!existsSync(join(out1, 'vectors')))
  })

  it('carries names the 1.x guard refuses, which is why the output never enters this repository', async () => {
    const markers = readFileSync(join(root, 'vectors', 'pact1x-markers.txt'), 'utf8')
      .split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#')).map((l) => new RegExp(l))
    const html = read(out1, 'spec.html')
    assert.ok(markers.some((m) => m.test(html)), 'the PACT 1 fragment names a retired thing')
    await assert.rejects(build({ ref: 'HEAD', out: join(root, 'site', 'never') }), /not gitignored/)
  })
})

describe('vectors', () => {
  it('are the committed file, byte for byte, with a fragment that indexes every member', () => {
    const bytes = readFileSync(join(out2, 'vectors', 'pact-2.0-vectors.json'))
    assert.ok(bytes.equals(execFileSync('git', ['-C', root, 'show', 'HEAD:vectors/pact-2.0-vectors.json'])))
    const meta = json(out2, 'meta.json')
    assert.equal(meta.vectors.bytes, bytes.length)
    const html = read(out2, 'vectors/index.html')
    for (const key of Object.keys(JSON.parse(bytes))) assert.ok(html.includes(`<h2 id="vectors-${slugify(key)}">`), `${key} is indexed`)
    assert.deepEqual(auditFragment(html), [])
  })
})
