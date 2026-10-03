// The markdown pipeline shared by whatever renders the specification. The source of truth is the
// text under docs/specification/ (read whole by site/spec-source.mjs); this only renders it.

import MarkdownIt from 'markdown-it'
import anchor from 'markdown-it-anchor'

export const esc = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
                           .replace(/"/g, '&quot;').replace(/'/g, '&#39;')

export const slugify = (s) =>
  s.toLowerCase().trim()
   .replace(/[^\w\s.-]/g, '')
   .replace(/[\s.]+/g, '-')
   .replace(/-+/g, '-')
   .replace(/^-|-$/g, '')

// "**Version 1.1.0-draft · 2026-08-24 · adds …**" — the version and date come from here,
// nowhere else, so a spec bump moves the cover without touching the renderers.
const HEADER = /^\*\*Version\s+(\S+)\s+·\s+(\d{4}-\d{2}-\d{2})(?:\s+·\s+(.+?))?\*\*\s*$/m

// Splits the specification (site/spec-source.mjs reads it whole) into what its header says and the body every renderer draws. The body
// starts after the spec's own "## Table of contents" section — a list of markdown links
// that is redundant wherever a table of contents is generated. The h1 and the version line
// belong to the cover or the page header; the preamble between them and the table of
// contents is rendered under a synthesized "Introduction" heading so it has a title.
export function splitSpec(markdown) {
  const header = markdown.match(HEADER)
  if (!header) throw new Error('the specification: could not parse the "**Version … · date …**" header line')
  const [headerLine, version, date, revisionNote] = header
  const tocStart = markdown.indexOf('\n## Table of contents')
  if (tocStart < 0) throw new Error('the specification: "## Table of contents" section not found')
  const tocEnd = markdown.indexOf('\n## ', tocStart + 1)
  const preamble = markdown.slice(0, tocStart)
    .replace(/^# .*\n/, '')
    .replace(headerLine, '')
    .trim()
  const body = `## Introduction\n\n${preamble}\n${markdown.slice(tocEnd)}`
  return { version, date, revisionNote, body }
}

// Renders spec markdown to HTML and returns the h2/h3 outline. Throws when a heading exceeds
// 120 characters: a paragraph followed immediately by `---` (no blank line) is a setext h2 in
// CommonMark, which silently promotes prose into a section heading here and on GitHub. Long
// headings are the tell, so the build refuses them.
// `idPrefix` keeps heading ids CSS-selector-safe ("1-architecture" is not; "s-1-architecture" is).
// `slugify` replaces the default id scheme; `must` wraps every MUST and MUST NOT in prose
// (never in code) as <span class="must">. Two headings that would share an id are refused
// rather than renamed: markdown-it-anchor would append "-1", and a citation of the wrong
// heading is exactly what a stable anchor must never become.
export function renderSpec(markdown, { idPrefix = '', slugify: slug = slugify, must = false } = {}) {
  const headings = []

  const md = new MarkdownIt({ html: true, linkify: true, typographer: false })
    .use(anchor, {
      level: [2, 3],
      slugify: (s) => idPrefix + slug(s),
      callback: (token, info) => {
        if (info.slug !== idPrefix + slug(info.title)) {
          throw new Error(`Two headings share the id "${idPrefix + slug(info.title)}"; the second is "${info.title}"`)
        }
        headings.push({ level: token.tag === 'h2' ? 2 : 3, id: info.slug, title: info.title })
      },
    })

  // Mermaid fences must become <pre class="mermaid">, not <pre><code class="language-mermaid">,
  // or mermaid.run() never finds them and the document ships raw diagram source as text.
  const defaultFence = md.renderer.rules.fence
  md.renderer.rules.fence = (tokens, idx, options, env, self) => {
    const token = tokens[idx]
    const info = (token.info || '').trim().split(/\s+/)[0]
    if (info === 'mermaid') {
      // textContent decodes these entities back to the original source, which is what
      // mermaid parses — so <br/> inside node labels survives the round trip.
      return `<figure class="diagram"><pre class="mermaid">${esc(token.content)}</pre></figure>\n`
    }
    const html = defaultFence(tokens, idx, options, env, self)
    return `<div class="code-block" data-lang="${esc(info || 'text')}">${html}</div>\n`
  }

  // Spec tables are wide; each gets its own wrapper so the renderer can constrain it.
  md.renderer.rules.table_open = () => '<div class="table-wrap">\n<table>\n'
  md.renderer.rules.table_close = () => '</table>\n</div>\n'

  // Runs after text_join, so it sees each run of prose as one text token. Only `text`
  // tokens are split: inline code, fences and raw HTML keep their MUSTs as they are.
  if (must) {
    md.core.ruler.push('must', (state) => {
      for (const block of state.tokens) {
        if (block.type !== 'inline') continue
        const out = []
        for (const child of block.children) {
          if (child.type !== 'text' || !/\bMUST\b/.test(child.content)) { out.push(child); continue }
          for (const piece of child.content.split(/(\bMUST NOT\b|\bMUST\b)/)) {
            if (!piece) continue
            const token = new state.Token(piece === 'MUST' || piece === 'MUST NOT' ? 'html_inline' : 'text', '', 0)
            token.content = token.type === 'text' ? piece : `<span class="must">${piece}</span>`
            out.push(token)
          }
        }
        block.children = out
      }
    })
  }

  const html = md.render(markdown)

  const suspect = headings.filter(h => h.title.length > 120)
  if (suspect.length) {
    throw new Error(
      'Headings that look like accidental setext headings — add a blank line before the `---`:\n' +
      suspect.map(h => `  ${h.title.slice(0, 100)}...`).join('\n'),
    )
  }

  return { html, headings }
}
