// Builds dist/pact-whitepaper.pdf from SPEC.md. Source of truth stays SPEC.md — this only
// renders it: markdown → HTML (site/markdown.mjs) → mermaid diagrams as inline SVG → paged.js
// for page numbers, running headers and the table of contents → headless Chrome for the PDF.
// Everything is local: fonts from site/brand/, mermaid and paged.js from node_modules.

import { readFile, writeFile, mkdir } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import puppeteer from 'puppeteer'
import { esc, renderSpec } from './markdown.mjs'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const out = resolve(root, 'dist')
const pdfPath = resolve(out, 'pact-whitepaper.pdf')
const htmlPath = resolve(out, 'pact-whitepaper.html')

/* ------------------------------------------------------------- SPEC.md */

const spec = await readFile(resolve(root, 'SPEC.md'), 'utf8')

// "**Version 1.1.0-draft · 2026-08-24 · adds …**" — the version and date come from here,
// nowhere else, so a spec bump moves the cover without touching this file.
const header = spec.match(/^\*\*Version\s+(\S+)\s+·\s+(\d{4}-\d{2}-\d{2})(?:\s+·\s+(.+?))?\*\*\s*$/m)
if (!header) throw new Error('SPEC.md: could not parse the "**Version … · date …**" header line')
const [headerLine, version, date, revisionNote] = header

// The body starts after the spec's own "## Table of contents" section — a list of markdown
// links that is redundant on paper, where the generated contents carry real page numbers.
// The h1 and the version line live on the cover; the preamble between them and the table of
// contents is rendered under a synthesized "Introduction" heading so it has a running title.
const tocStart = spec.indexOf('\n## Table of contents')
if (tocStart < 0) throw new Error('SPEC.md: "## Table of contents" section not found')
const tocEnd = spec.indexOf('\n## ', tocStart + 1)
const preamble = spec.slice(0, tocStart)
  .replace(/^# .*\n/, '')
  .replace(headerLine, '')
  .trim()
const body = `## Introduction\n\n${preamble}\n${spec.slice(tocEnd)}`

let specHtml, headings
try {
  ({ html: specHtml, headings } = renderSpec(body, { idPrefix: 's-' }))
} catch (e) {
  console.error(e.message)
  process.exit(1)
}
const diagramCount = (body.match(/^```mermaid/gm) || []).length

/* ---------------------------------------------------------------- HTML */

const mark = await readFile(resolve(root, 'site', 'brand', 'mark.svg'), 'utf8')

const toc = headings.map(h =>
  `<li class="lvl${h.level}"><a href="#${esc(h.id)}">${esc(h.title)}</a><span class="leader"></span><a class="pg" href="#${esc(h.id)}"></a></li>`
).join('\n')

const page = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>PACT — Protocol Specification ${esc(version)}</title>
<link rel="stylesheet" href="${pathToFileURL(resolve(root, 'site', 'whitepaper.css')).href}">
<style>
  @page { @bottom-left { content: "Whitepaper · Protocol Specification ${esc(version)}"; } }
</style>
</head>
<body>
<section class="cover">
  <div class="brand">${mark}<span class="wordmark">PACT</span></div>
  <div class="title-block">
    <div class="rule"></div>
    <p class="title">Personal Agent Communication &amp; Trust</p>
    <p class="kind">Protocol Specification · Whitepaper</p>
    <p class="version">Version ${esc(version)} · ${esc(date)}</p>
  </div>
  <p class="site">pact-protocol.com</p>
</section>
<section class="front">
  <div class="about">
    <p class="about-title">About this document</p>
    <p>This is the normative specification of PACT, the Personal Agent Communication &amp; Trust
    protocol. Its status is <strong>draft</strong>: version ${esc(version)}, dated ${esc(date)}.${
      revisionNote ? ` This revision ${esc(revisionNote)}.` : ''}</p>
    <p>The reference gateway is in private development.</p>
  </div>
  <h2 class="contents-title">Contents</h2>
  <nav class="toc"><ol>
${toc}
  </ol></nav>
</section>
<article class="doc">
${specHtml}
</article>
</body>
</html>
`

await mkdir(out, { recursive: true })
await writeFile(htmlPath, page)

/* ----------------------------------------------------------------- PDF */

const browser = await puppeteer.launch({
  headless: true,
  executablePath: process.env.PUPPETEER_EXECUTABLE_PATH || undefined,
  // The page is a file:// URL loading file:// fonts and stylesheets.
  args: ['--allow-file-access-from-files', '--font-render-hinting=none'],
})

try {
  const tab = await browser.newPage()
  const problems = []
  tab.on('pageerror', e => problems.push(`page error: ${e.message}`))
  tab.on('console', m => { if (m.type() === 'error') problems.push(`console: ${m.text()}`) })

  await tab.goto(pathToFileURL(htmlPath).href, { waitUntil: 'load' })
  await tab.evaluate(() => document.fonts.ready)

  // Diagrams first, so paged.js lays out finished SVGs, not source text. Each diagram is
  // scaled to the text column, so a wide one would shrink its labels below print size. A
  // flowchart whose source orientation prints too small is therefore laid out the other way
  // round (LR ↔ TB — same nodes, same edges, same labels) when that fits the page better;
  // state diagrams are always laid out LR, because dagre's top-down placement piles their
  // edge labels on top of each other. A diagram that still fits poorly may bleed 10 mm
  // into each margin (figure.wide).
  await tab.addScriptTag({ path: resolve(root, 'node_modules', 'mermaid', 'dist', 'mermaid.min.js') })
  const diagrams = await tab.evaluate(async () => {
    const COLUMN = 642, BLEED = 718, HEIGHT = 760   // px at 96 dpi: 170 mm, 190 mm, ~80% of the page area
    const fit = (w, h, width) => Math.min(1, width / w, HEIGHT / h)
    const flipped = (src) => src.replace(/^(\s*(?:flowchart|graph))\s+(LR|TB|TD)\b/,
      (m, k, d) => `${k} ${d === 'LR' ? 'TB' : 'LR'}`)
    const sideways = (src) => /^\s*stateDiagram(-v2)?\s*\n/.test(src) && !/^\s*direction\s/m.test(src)
      ? src.replace(/^(\s*stateDiagram(?:-v2)?\s*\n)/, '$1    direction LR\n') : src

    mermaid.initialize({
      startOnLoad: false,
      securityLevel: 'loose',
      theme: 'base',
      fontFamily: 'Inter, sans-serif',
      themeVariables: {
        fontFamily: 'Inter, sans-serif',
        fontSize: '15px',
        background: '#FFFFFF',
        primaryColor: '#E6F7F1',
        primaryTextColor: '#0B100E',
        primaryBorderColor: '#0F9B7A',
        secondaryColor: '#F4F6F5',
        secondaryBorderColor: '#E3E8E5',
        secondaryTextColor: '#1F2724',
        tertiaryColor: '#FFFFFF',
        tertiaryBorderColor: '#E3E8E5',
        tertiaryTextColor: '#1F2724',
        lineColor: '#1F2724',
        textColor: '#1F2724',
        mainBkg: '#E6F7F1',
        nodeBorder: '#0F9B7A',
        nodeTextColor: '#0B100E',
        clusterBkg: '#F4F6F5',
        clusterBorder: '#E3E8E5',
        titleColor: '#0B100E',
        edgeLabelBackground: '#FFFFFF',
        actorBkg: '#E6F7F1',
        actorBorder: '#0F9B7A',
        actorTextColor: '#0B100E',
        actorLineColor: '#6B7671',
        signalColor: '#1F2724',
        signalTextColor: '#1F2724',
        labelBoxBkgColor: '#F4F6F5',
        labelBoxBorderColor: '#E3E8E5',
        labelTextColor: '#0B100E',
        loopTextColor: '#0B100E',
        noteBkgColor: '#E6F7F1',
        noteBorderColor: '#2BD4A4',
        noteTextColor: '#0B100E',
        activationBkgColor: '#F4F6F5',
        activationBorderColor: '#0F9B7A',
        sequenceNumberColor: '#FFFFFF',
      },
      flowchart: { htmlLabels: true, useMaxWidth: true, curve: 'basis', padding: 6, nodeSpacing: 22, rankSpacing: 30 },
      // Sequence text is measured with these families; they default to Trebuchet, and a
      // mismatch between measured and rendered font spills note text past its box.
      sequence: {
        useMaxWidth: true, wrap: true, width: 110, actorMargin: 16, messageMargin: 20, boxMargin: 4, noteMargin: 6, wrapPadding: 6,
        actorFontFamily: 'Inter, sans-serif', actorFontSize: 15, actorFontWeight: 500,
        noteFontFamily: 'Inter, sans-serif', noteFontSize: 14,
        messageFontFamily: 'Inter, sans-serif', messageFontSize: 14,
      },
      state: { useMaxWidth: true, nodeSpacing: 150, rankSpacing: 70 },
    })

    const report = []
    let n = 0
    for (const pre of document.querySelectorAll('figure.diagram pre.mermaid')) {
      const source = sideways(pre.textContent)
      const measure = async (src) => {
        const { svg } = await mermaid.render(`diagram-${n++}`, src)
        const [, , w, h] = svg.match(/viewBox="([^"]+)"/)[1].split(/\s+/).map(Number)
        return { svg, w, h, scale: fit(w, h, COLUMN), flipped: src !== source }
      }
      // Flip only when the source orientation would print its labels too small.
      let best = await measure(source)
      if (best.scale < 0.6 && flipped(source) !== source) {
        const other = await measure(flipped(source))
        if (other.scale > best.scale) best = other
      }
      const figure = pre.parentElement
      figure.innerHTML = best.svg
      const svg = figure.querySelector('svg')
      // mermaid never wraps a note that carries explicit line breaks, yet still draws it at
      // the configured actor width, so the text spills past its box. Widen such boxes to the
      // text and grow the viewBox if a widened note now reaches past the drawing.
      let grown = false
      for (const rect of svg.querySelectorAll('rect.note')) {
        const text = rect.parentElement.querySelector('text.noteText')
        if (!text) continue
        const need = text.getBBox().width + 16
        const width = Number(rect.getAttribute('width'))
        if (need <= width) continue
        const cx = Number(rect.getAttribute('x')) + width / 2
        rect.setAttribute('x', cx - need / 2)
        rect.setAttribute('width', need)
        grown = true
      }
      if (grown) {
        const bb = svg.getBBox()
        const [x, y, w, h] = svg.getAttribute('viewBox').split(/\s+/).map(Number)
        const x0 = Math.min(x, bb.x - 10), x1 = Math.max(x + w, bb.x + bb.width + 10)
        svg.setAttribute('viewBox', `${x0} ${y} ${x1 - x0} ${h}`)
        best.w = x1 - x0
        best.scale = fit(best.w, best.h, COLUMN)
      }
      if (best.scale < 0.7) { figure.classList.add('wide'); best.scale = fit(best.w, best.h, BLEED) }
      // Size the SVG explicitly: mermaid's width="100%" would stretch narrow diagrams.
      svg.setAttribute('width', Math.round(best.w * best.scale))
      svg.setAttribute('height', Math.round(best.h * best.scale))
      svg.style.maxWidth = 'none'
      report.push(`${Math.round(best.w)}x${Math.round(best.h)}${best.flipped ? ' flipped' : ''} @${best.scale.toFixed(2)}${figure.classList.contains('wide') ? ' wide' : ''}`)
    }
    return report
  })
  if (diagrams.length !== diagramCount) {
    throw new Error(`mermaid rendered ${diagrams.length} of ${diagramCount} diagrams`)
  }
  const rendered = diagrams.length

  // Keep headings and labels with what follows them, so no heading ends a page alone.
  await tab.evaluate(() => {
    const isLabel = (el) => el.tagName === 'P' && el.children.length === 1
      && el.firstElementChild.tagName === 'STRONG'
      && el.textContent.trim() === el.firstElementChild.textContent.trim()
    for (const el of [...document.querySelectorAll('.doc h2, .doc h3, .doc p')]) {
      if (el.tagName === 'P' && !isLabel(el)) continue
      const next = el.nextElementSibling
      if (!next || next.matches('h2, h3, .keep')) continue
      const keep = document.createElement('div')
      keep.className = 'keep'
      el.before(keep)
      keep.append(el, next)
    }
    // ✔ / ✖ are not in Inter; draw them instead of borrowing a system glyph.
    const marks = {
      '✔': '<span class="mark yes" role="img" aria-label="yes"><svg viewBox="0 0 12 12" width="12" height="12" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M2 6.5l2.6 2.6L10 3.5"/></svg></span>',
      '✖': '<span class="mark no" role="img" aria-label="no"><svg viewBox="0 0 12 12" width="12" height="12" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"><path d="M3 3l6 6M9 3l-6 6"/></svg></span>',
    }
    for (const td of document.querySelectorAll('.doc td')) {
      const t = td.textContent.trim()
      if (marks[t]) td.innerHTML = marks[t]
    }
    // A code block taller than a page must be allowed to split.
    for (const block of document.querySelectorAll('.doc .code-block')) {
      if (block.getBoundingClientRect().height > 600) block.classList.add('tall')
    }
  })

  await tab.evaluate(() => { window.PagedConfig = { auto: false } })
  await tab.addScriptTag({ path: resolve(root, 'node_modules', 'pagedjs', 'dist', 'paged.polyfill.js') })
  const pages = await tab.evaluate(async () => {
    const flow = await window.PagedPolyfill.preview()
    return flow.total
  })

  if (problems.length) throw new Error(`browser reported:\n  ${problems.join('\n  ')}`)

  await tab.pdf({
    path: pdfPath,
    preferCSSPageSize: true,
    printBackground: true,
    displayHeaderFooter: false,
    outline: true,
    tagged: true,
    timeout: 120_000,
  })

  console.log(`diagrams: ${diagrams.join(' · ')}`)
  console.log(`built ${pdfPath} — ${pages} pages, ${headings.length} headings, ${rendered} diagrams, spec ${version} (${date})`)
} finally {
  await browser.close()
}
