// The one mermaid pipeline: the whitepaper (site/build-whitepaper.mjs) and the web fragments
// (site/spec-html.mjs) both render SPEC.md's diagrams through this — the bundled mermaid from
// node_modules inside headless Chrome, one configuration, and the same three fixes applied to
// every drawing. Nothing is fetched at render time.
//
// The functions under "browser side" run inside the page, so they take no imports and close over
// nothing: installMermaid() copies their source into the page as `window.pactMermaid`.

import { resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import puppeteer from 'puppeteer'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
export const mermaidScript = resolve(root, 'node_modules', 'mermaid', 'dist', 'mermaid.min.js')

// The font size mermaid lays a diagram out at; text is measured at this size.
export const FONT = 16

export function launch() {
  return puppeteer.launch({
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
}

/* --------------------------------------------------------- browser side */

// The root fontSize sizes every diagram's text: the sequence renderer copies it over its
// actor/message/note sizes. The sequence wrap width follows it so a larger font wraps the
// same lines; the subgraph title margin grows faster than the font, because mermaid offsets
// a cluster's nodes by only half of it while the title itself grows in full. `htmlLabels`
// decides whether flowchart and state labels are HTML in a foreignObject (the whitepaper) or
// SVG text (the web, whose fragments carry no HTML inside their drawings).
function mermaidConfig(font, { htmlLabels = true, base = 16 } = {}) {
  const k = font / base
  return {
    startOnLoad: false,
    securityLevel: 'loose',
    theme: 'base',
    htmlLabels,
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
      htmlLabels, useMaxWidth: true, curve: 'basis', padding: 6, nodeSpacing: 34, rankSpacing: 30,
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

// State diagrams are always laid out LR, because dagre's top-down placement piles their
// edge labels on top of each other.
function sideways(src) {
  return /^\s*stateDiagram(-v2)?\s*\n/.test(src) && !/^\s*direction\s/m.test(src)
    ? src.replace(/^(\s*stateDiagram(?:-v2)?\s*\n)/, '$1    direction LR\n') : src
}

// mermaid never wraps a note that carries explicit line breaks, yet still draws it at the
// configured actor width, so the text spills past its box. Widen such boxes to the text.
function widenNotes(svg) {
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
}

// mermaid's viewBox stops short of its own drawing — the mirrored actors' names, a widened
// note — and Chrome clips at the viewBox, so cover whatever was drawn. Returns the box set.
function cover(svg) {
  const bb = svg.getBBox()
  const [x, y, w, h] = svg.getAttribute('viewBox').split(/\s+/).map(Number)
  const x0 = Math.min(x, bb.x - 10), y0 = Math.min(y, bb.y - 10)
  const x1 = Math.max(x + w, bb.x + bb.width + 10), y1 = Math.max(y + h, bb.y + bb.height + 10)
  svg.setAttribute('viewBox', `${x0} ${y0} ${x1 - x0} ${y1 - y0}`)
  return { x0, y0, x1, y1 }
}

/* ------------------------------------------------------------ node side */

// Loads mermaid into the page and the helpers above as window.pactMermaid.
export async function installMermaid(tab) {
  await tab.addScriptTag({ path: mermaidScript })
  await tab.addScriptTag({ content: `window.pactMermaid = { config: ${mermaidConfig}, sideways: ${sideways}, widenNotes: ${widenNotes}, cover: ${cover} }` })
}
