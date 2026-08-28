// The markdown pipeline shared by whatever renders SPEC.md. Source of truth stays SPEC.md —
// this only renders it. docs/ and archive/ are deliberately NOT rendered: they document the
// rejected pre-pivot design, and publishing them would present them as current. See CLAUDE.md.

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

// Renders spec markdown to HTML and returns the h2/h3 outline. Throws when a heading exceeds
// 120 characters: a paragraph followed immediately by `---` (no blank line) is a setext h2 in
// CommonMark, which silently promotes prose into a section heading here and on GitHub. Long
// headings are the tell, so the build refuses them.
// `idPrefix` keeps heading ids CSS-selector-safe ("1-architecture" is not; "s-1-architecture" is).
export function renderSpec(markdown, { idPrefix = '' } = {}) {
  const headings = []

  const md = new MarkdownIt({ html: true, linkify: true, typographer: false })
    .use(anchor, {
      level: [2, 3],
      slugify: (s) => idPrefix + slugify(s),
      callback: (token, info) => {
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
