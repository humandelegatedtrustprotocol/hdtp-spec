// Builds dist/pact-whitepaper.pdf from SPEC.md. Source of truth stays SPEC.md — this only
// renders it: markdown → HTML (site/markdown.mjs) → mermaid diagrams as inline SVG → paged.js
// for page numbers, running headers and the table of contents → headless Chrome for the PDF.
// Everything is local: fonts from site/brand/, mermaid and paged.js from node_modules.

import { readFile, writeFile, mkdir, stat } from 'node:fs/promises'
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
    protocol. Its status is <strong>${version.includes('-draft') ? 'draft' : 'released'}</strong>: version ${esc(version)}, dated ${esc(date)}.${
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
  args: [
    '--allow-file-access-from-files', '--font-render-hinting=none',
    // GitHub's Ubuntu 24.04 runners restrict unprivileged user namespaces (AppArmor), so
    // Chrome aborts with "No usable sandbox!". The page rendered here is our own build
    // output, never remote content, so running unsandboxed in CI gives up nothing.
    ...(process.env.CI ? ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage'] : []),
  ],
})

try {
  const tab = await browser.newPage()
  const problems = []
  tab.on('pageerror', e => problems.push(`page error: ${e.message}`))
  tab.on('console', m => { if (m.type() === 'error') problems.push(`console: ${m.text()}`) })

  await tab.goto(pathToFileURL(htmlPath).href, { waitUntil: 'load' })
  await tab.evaluate(() => document.fonts.ready)

  // Diagrams first, so paged.js lays out finished SVGs, not source text. Each diagram is
  // scaled to the text column, and its text must print inside one size band so adjacent
  // figures read alike. While a diagram would print below that band the build escalates:
  // a flowchart is laid out the other way round (LR ↔ TB — same nodes, same edges, same
  // labels) and rendered at a larger font — its spacing stays in px, so the drawing grows
  // slower than its text and prints bigger after scaling — and only when no font reaches
  // the band does the figure bleed 10 mm into each margin (figure.wide). Only flowcharts
  // take a larger font: a sequence diagram's stick figures and sequence numbers are
  // fixed-size and would shrink instead, and a state diagram's free-floating edge labels
  // collide. State diagrams are always laid out LR, because dagre's top-down placement
  // piles their edge labels on top of each other.
  await tab.addScriptTag({ path: resolve(root, 'node_modules', 'mermaid', 'dist', 'mermaid.min.js') })
  const diagrams = await tab.evaluate(async () => {
    const COLUMN = 642, BLEED = 718, HEIGHT = 820   // px at 96 dpi: 170 mm, 190 mm, a page less its heading
    const FONT = 16                                  // px mermaid renders at; text prints at FONT × scale
    const PRINT = [11, 14]                           // px on paper every figure's text lands in (8¼–10½ pt)
    const fit = (w, h, width) => Math.min(1, width / w, HEIGHT / h)
    const flipped = (src) => src.replace(/^(\s*(?:flowchart|graph))\s+(LR|TB|TD)\b/,
      (m, k, d) => `${k} ${d === 'LR' ? 'TB' : 'LR'}`)
    const sideways = (src) => /^\s*stateDiagram(-v2)?\s*\n/.test(src) && !/^\s*direction\s/m.test(src)
      ? src.replace(/^(\s*stateDiagram(?:-v2)?\s*\n)/, '$1    direction LR\n') : src

    // The root fontSize sizes every diagram's text: the sequence renderer copies it over its
    // actor/message/note sizes. The sequence wrap width follows it so a larger font wraps
    // the same lines; the subgraph title margin grows faster than the font, because mermaid
    // offsets a cluster's nodes by only half of it while the title itself grows in full.
    const config = (font) => {
      const k = font / FONT
      return {
        startOnLoad: false,
        securityLevel: 'loose',
        theme: 'base',
        fontFamily: 'Inter, sans-serif',
        fontSize: font,
        themeVariables: {
          fontFamily: 'Inter, sans-serif',
          fontSize: `${font}px`,
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
        flowchart: {
          htmlLabels: true, useMaxWidth: true, curve: 'basis', padding: 6, nodeSpacing: 34, rankSpacing: 30,
          subGraphTitleMargin: { top: 0.6 * font, bottom: 0.8 * font },
        },
        // Sequence text is measured with these families; they default to Trebuchet, and a
        // mismatch between measured and rendered font spills note text past its box. The
        // actor width is also the wrap width, and mermaid never budgets height for a
        // stick figure's wrapped name: 130 keeps "Bharat (human)" on one line. boxMargin
        // is the gap between a label and its arrow; below 8 the sequence number of a
        // self-message sits on the label's descenders.
        sequence: {
          useMaxWidth: true, wrap: true, width: 130 * k, actorMargin: 16, messageMargin: 20, boxMargin: 8, noteMargin: 6, wrapPadding: 6,
          actorFontFamily: 'Inter, sans-serif', actorFontWeight: 500,
          noteFontFamily: 'Inter, sans-serif',
          messageFontFamily: 'Inter, sans-serif',
        },
        state: { useMaxWidth: true, nodeSpacing: 150, rankSpacing: 70 },
      }
    }

    const report = []
    let n = 0
    for (const pre of document.querySelectorAll('figure.diagram pre.mermaid')) {
      const figure = pre.parentElement
      const source = sideways(pre.textContent)
      // Renders into the figure and reports how the drawing would print.
      const render = async (src, font) => {
        mermaid.initialize(config(font))
        const { svg: markup } = await mermaid.render(`diagram-${n++}`, src)
        figure.innerHTML = markup
        const svg = figure.querySelector('svg')
        // mermaid never wraps a note that carries explicit line breaks, yet still draws it at
        // the configured actor width, so the text spills past its box. Widen such boxes to
        // the text.
        for (const rect of svg.querySelectorAll('rect.note')) {
          const text = rect.parentElement.querySelector('text.noteText')
          if (!text) continue
          const need = text.getBBox().width + 16
          const width = Number(rect.getAttribute('width'))
          if (need <= width) continue
          const cx = Number(rect.getAttribute('x')) + width / 2
          rect.setAttribute('x', cx - need / 2)
          rect.setAttribute('width', need)
        }
        // mermaid's viewBox stops short of its own drawing — the mirrored actors' names, a
        // widened note — and Chrome clips at the viewBox, so cover whatever was drawn.
        const bb = svg.getBBox()
        const [x, y, w, h] = svg.getAttribute('viewBox').split(/\s+/).map(Number)
        const x0 = Math.min(x, bb.x - 10), y0 = Math.min(y, bb.y - 10)
        const x1 = Math.max(x + w, bb.x + bb.width + 10), y1 = Math.max(y + h, bb.y + bb.height + 10)
        svg.setAttribute('viewBox', `${x0} ${y0} ${x1 - x0} ${y1 - y0}`)
        // Arrowheads are fixed-size markers; grow them with the font so they scale down with it.
        for (const marker of svg.querySelectorAll('marker')) {
          for (const a of ['markerWidth', 'markerHeight']) marker.setAttribute(a, Number(marker.getAttribute(a)) * font / FONT)
        }
        const size = { w: x1 - x0, h: y1 - y0 }
        const scale = fit(size.w, size.h, COLUMN)
        return { html: figure.innerHTML, font, ...size, scale, print: scale * font, flipped: src !== source }
      }
      const fonts = /^\s*(flowchart|graph)\b/.test(source) ? [FONT, 18, 20, 22, 24, 26, 28, 30, 32, 36, 40] : [FONT]
      let best
      for (const font of fonts) {
        if (best?.print >= PRINT[0]) break
        let candidate = await render(source, font)
        if (candidate.print < PRINT[0] && flipped(source) !== source) {
          const other = await render(flipped(source), font)
          if (other.print > candidate.print) candidate = other
        }
        if (!best || candidate.print > best.print) best = candidate
      }
      if (best.print < PRINT[0]) {
        const scale = fit(best.w, best.h, BLEED)
        if (scale > best.scale) best = { ...best, scale, print: scale * best.font, wide: true }
      }
      figure.innerHTML = best.html
      if (best.wide) figure.classList.add('wide')
      // Size the SVG explicitly: mermaid's width="100%" would stretch narrow diagrams.
      const scale = Math.min(best.scale, PRINT[1] / best.font)
      const svg = figure.querySelector('svg')
      svg.setAttribute('width', Math.round(best.w * scale))
      svg.setAttribute('height', Math.round(best.h * scale))
      svg.style.maxWidth = 'none'
      // How far the paginator may shrink this figure before its text leaves the band.
      svg.dataset.shrink = Math.min(1, PRINT[0] / (best.font * scale)).toFixed(3)
      report.push(`${Math.round(best.w)}x${Math.round(best.h)}${best.flipped ? ' flipped' : ''}${best.font !== FONT ? ` @${best.font}px` : ''} ×${scale.toFixed(2)} = ${(best.font * scale).toFixed(1)}px${best.wide ? ' wide' : ''}`)
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
    // Sections run on; only the body's first section and the appendices open a fresh page.
    // A break at every section left pages nearly empty, and one before §13 left a page
    // carrying three lines.
    for (const h2 of document.querySelectorAll('.doc h2')) {
      if (/^(Introduction|Appendix)/.test(h2.textContent.trim())) h2.classList.add('newpage')
    }
    // Auto table layout splits property and tool names mid-token and starves the argument
    // column, so each table shape gets fixed column widths (percent), keyed by its header row.
    const columns = {
      'Property|Required|Meaning': [24, 12, 64],
      'Setting|Default|Notes': [18, 12, 70],
      'Tool|Arguments|Returns': [23, 40, 37],
      'Tool|Permission|Arguments|Returns': [22, 24.5, 23.5, 30],
      'Permission|Gates|In "basic" preset': [30, 45, 25],
      "Property|This spec's answer|Given up vs the hardened draft": [20, 45, 35],
      'Member|Content': [16, 84],
      'Suite id|KEM|KDF|AEAD|For recipients with': [22, 22, 14, 16, 26],
    }
    for (const table of document.querySelectorAll('.doc table')) {
      const widths = columns[[...table.querySelectorAll('th')].map(th => th.textContent.trim()).join('|')]
      if (!widths) continue
      table.classList.add('cols')
      const colgroup = document.createElement('colgroup')
      colgroup.innerHTML = widths.map(w => `<col style="width:${w}%">`).join('')
      table.prepend(colgroup)
    }
    // A table shorter than a third of a page moves whole rather than strand a row or two
    // on the next page; longer tables split, and the paginator repeats their header row.
    for (const table of document.querySelectorAll('.doc table')) {
      if (table.getBoundingClientRect().height <= 300) table.parentElement.classList.add('short')
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

  // paged.js checks for overflow every maxChars characters it has laid onto a page; at the
  // default 1500 the check can land mid-paragraph, with the paragraph's tail not yet on the
  // page, and the widows handler below needs the whole paragraph in place to count lines.
  // A page holds about 4 000 characters, so this only defers the check.
  await tab.evaluate(() => { window.PagedConfig = { auto: false, settings: { maxChars: 20_000 } } })
  await tab.addScriptTag({ path: resolve(root, 'node_modules', 'pagedjs', 'dist', 'paged.polyfill.js') })

  // paged.js 0.4 leaves four things to the document: it ignores orphans/widows, it rebuilds
  // a split table on the next page without its header row (or its column widths), it pushes
  // a figure whole to the next page however little it overhangs, and its string(name, start)
  // takes a heading as opening the page only when the heading's box sits exactly on the page
  // top. These handlers hook the paginator to cover each. Geometry to know: paged.js lays a
  // page out as a multi-column box one page wide, so what Chrome cannot fit on the page —
  // an unbreakable figure, the lines past the bottom — sits in a second column to the right
  // of it (left ≥ bounds.right), where paged.js then reads the break from.
  await tab.evaluate(() => {
    const { Handler, registerHandlers } = window.Paged
    // Whether any text on the page precedes `el` — i.e. `el` does not open the page.
    const contentBefore = (el, page) => {
      const walker = document.createTreeWalker(page, NodeFilter.SHOW_TEXT)
      for (let n = walker.nextNode(); n; n = walker.nextNode()) {
        if (el.compareDocumentPosition(n) & (Node.DOCUMENT_POSITION_FOLLOWING | Node.DOCUMENT_POSITION_CONTAINED_BY)) return false
        if (n.textContent.trim()) return true
      }
      return false
    }
    const onPage = (rect, bounds) => rect.left < bounds.right
    const margin = (el, side) => parseFloat(getComputedStyle(el)[`margin${side}`]) || 0

    // The running header names the section in force at the top of the page: the first
    // heading when nothing precedes it on the page, else the last heading before the page.
    class Sections extends Handler {
      afterPageLayout(page) {
        const heads = [...page.querySelectorAll('.doc h2, .front .contents-title')]
        let top = this.last
        if (heads.length && (!top || !contentBefore(heads[0], page))) top = heads[0].textContent
        page.style.setProperty('--pagedjs-string-start-section', `"${(top || '').replace(/["\\]/g, '\\$&')}"`)
        if (heads.length) this.last = heads.at(-1).textContent
      }
    }

    // A table continued on a new page gets its column widths and header row back.
    class TableHeads extends Handler {
      renderNode(clone, node) {
        if (node.nodeName !== 'TR') return
        const table = clone.closest('table')
        if (!table?.dataset.splitFrom || table.tHead) return
        const source = node.closest('table')
        const parts = [source.querySelector('colgroup'), source.tHead].filter(Boolean).map(p => p.cloneNode(true))
        for (const p of parts) for (const el of [p, ...p.querySelectorAll('[data-ref]')]) el.removeAttribute('data-ref')
        table.prepend(...parts)
      }
    }

    // A figure Chrome could not fit under the page's last content shrinks into the room
    // left there, down to the scale the build allows for it (data-shrink keeps its text
    // inside the print band); beyond that it moves to the next page whole, as before. The
    // figure may share a keep-with-next wrapper with its heading, which then moves as one.
    class FitFigures extends Handler {
      renderNode(clone, node, layout) {
        if (node.nodeName !== 'svg' || !node.dataset.shrink) return
        const { bounds } = layout
        if (onPage(clone.getBoundingClientRect(), bounds)) return
        const figure = clone.closest('figure')
        const box = figure.parentElement.classList.contains('keep') ? figure.parentElement : figure
        // The last box on the page before this one, and the collapsed margin between them.
        let prev = box
        while (!prev.previousElementSibling && !prev.parentElement.classList.contains('pagedjs_page_content')) prev = prev.parentElement
        prev = prev.previousElementSibling
        if (!prev || !onPage(prev.getBoundingClientRect(), bounds)) return
        const gap = Math.max(margin(prev, 'Bottom'), margin(box, 'Top'), margin(box.firstElementChild, 'Top'))
        const overhead = box.getBoundingClientRect().height - clone.getBoundingClientRect().height
        const room = bounds.bottom - prev.getBoundingClientRect().bottom - gap - overhead - 2
        const w = Number(clone.getAttribute('width')), h = Number(clone.getAttribute('height'))
        for (let k = Math.min(room / h, 0.995); k >= Number(node.dataset.shrink); k -= 0.01) {
          clone.setAttribute('width', Math.floor(w * k))
          clone.setAttribute('height', Math.floor(h * k))
          if (onPage(clone.getBoundingClientRect(), bounds)) return
        }
        clone.setAttribute('width', w)
        clone.setAttribute('height', h)
      }
    }

    // Orphans and widows, read from the paragraph's own computed style: when a page break
    // falls inside a paragraph or list item, move it up so at least `widows` lines follow
    // it, or take the whole block to the next page if fewer than `orphans` could stay.
    class Widows extends Handler {
      onOverflow(overflow, rendered, bounds) {
        const node = overflow?.startContainer
        if (!node || node.nodeType !== Node.TEXT_NODE) return
        const block = node.parentElement.closest('p, li')
        if (!block) return
        // The whole block must be on the page (or past its bottom) to count its lines.
        const source = this.chunker.source.querySelector(`[data-ref="${block.dataset.ref}"]`)
        if (!source || source.textContent.length !== block.textContent.length) return
        const style = getComputedStyle(block)
        const orphans = Number(style.orphans), widows = Number(style.widows), half = parseFloat(style.lineHeight) / 2
        // Tops of the block's line boxes, on the page and past it; an inline code span's box
        // sits a little below its line.
        const all = document.createRange()
        all.selectNodeContents(block)
        const rects = [...all.getClientRects()].filter(r => r.width > 0 && r.height > 0)
        const lines = (rs) => rs.map(r => r.top).sort((a, b) => a - b)
          .reduce((tops, t) => (!tops.length || t - tops.at(-1) > half) ? [...tops, t] : tops, [])
        const fits = lines(rects.filter(r => onPage(r, bounds)))
        const total = fits.length + lines(rects.filter(r => !onPage(r, bounds))).length
        const keep = Math.min(fits.length, total - widows)
        if (keep === fits.length && keep >= orphans) return
        if (keep < orphans) {
          const whole = block.parentElement.classList.contains('keep') ? block.parentElement : block
          if (!contentBefore(whole, rendered)) return
          overflow.setStartBefore(whole)
          return overflow
        }
        // Break at the start of line `keep`: the first character whose box sits on that line.
        const walker = document.createTreeWalker(block, NodeFilter.SHOW_TEXT)
        const range = document.createRange()
        for (let n = walker.nextNode(); n; n = walker.nextNode()) {
          for (let i = 0; i < n.length; i++) {
            if (/\s/.test(n.data[i])) continue
            range.setStart(n, i)
            range.setEnd(n, i + 1)
            const r = range.getBoundingClientRect()
            if (r.height > 0 && onPage(r, bounds) && Math.abs(r.top - fits[keep]) < half) {
              overflow.setStart(n, i)
              return overflow
            }
          }
        }
      }
    }

    registerHandlers(Sections, TableHeads, FitFigures, Widows)
  })

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

  const { size: bytes } = await stat(pdfPath)
  const metaPath = pdfPath.replace(/\.pdf$/, '.meta.json')
  await writeFile(metaPath, JSON.stringify({
    version, date, pages, headings: headings.length, diagrams: rendered, bytes,
    status: version.includes('-draft') ? 'draft' : 'released',
  }) + '\n')

  console.log(`diagrams: ${diagrams.join(' · ')}`)
  console.log(`built ${pdfPath} — ${pages} pages, ${headings.length} headings, ${rendered} diagrams, spec ${version} (${date}) · meta ${metaPath}`)
} finally {
  await browser.close()
}
