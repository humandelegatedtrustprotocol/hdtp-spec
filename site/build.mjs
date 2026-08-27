// Builds the PACT site into dist/. Source of truth stays SPEC.md — this only renders it.
// docs/ and archive/ are deliberately NOT published: they document the rejected pre-pivot
// design, and hosting them here would present them as current. See CLAUDE.md.

import { readFile, writeFile, mkdir, rm, cp } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import MarkdownIt from 'markdown-it'
import anchor from 'markdown-it-anchor'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const out = resolve(root, 'dist')

const GA = (process.env.GA_MEASUREMENT_ID || '').trim()
const MP = (process.env.MIXPANEL_TOKEN || '').trim()
const SITE_URL = (process.env.SITE_URL || '').trim().replace(/\/$/, '')

const esc = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
                    .replace(/"/g, '&quot;').replace(/'/g, '&#39;')

const slugify = (s) =>
  s.toLowerCase().trim()
   .replace(/[^\w\s.-]/g, '')
   .replace(/[\s.]+/g, '-')
   .replace(/-+/g, '-')
   .replace(/^-|-$/g, '')

/* ---------------------------------------------------------------- markdown */

const headings = []

const md = new MarkdownIt({ html: true, linkify: true, typographer: false })
  .use(anchor, {
    level: [2, 3],
    slugify,
    permalink: anchor.permalink.linkInsideHeader({
      symbol: '#', placement: 'after', class: 'anchor', ariaHidden: true,
    }),
    callback: (token, info) => {
      headings.push({ level: token.tag === 'h2' ? 2 : 3, id: info.slug, title: info.title })
    },
  })

// Mermaid fences must become <pre class="mermaid">, not <pre><code class="language-mermaid">,
// or mermaid.run() never finds them and the page ships raw diagram source as text.
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

// Spec tables are wide; each needs its own horizontal scroll container so the page body never
// scrolls sideways.
md.renderer.rules.table_open = () => '<div class="table-wrap" tabindex="0">\n<table>\n'
md.renderer.rules.table_close = () => '</table>\n</div>\n'

/* ------------------------------------------------------------------ layout */

const analyticsHead = (base) => {
  if (!GA && !MP) return ''
  const parts = []
  if (GA) {
    parts.push(`  <script async src="https://www.googletagmanager.com/gtag/js?id=${esc(GA)}"></script>`)
  }
  parts.push(`  <script>window.PACT_ANALYTICS=${JSON.stringify({ ga: GA || null, mixpanel: MP || null })};</script>`)
  if (MP) {
    parts.push(`  <script src="${base}assets/mixpanel.min.js"></script>`)
  }
  return parts.join('\n') + '\n'
}

// The disclosure has to describe what THIS build does. With neither GA_MEASUREMENT_ID nor
// MIXPANEL_TOKEN set nothing is collected, so printing the notice anyway would tell every
// visitor we track them when we do not — a false statement on a site whose own subject is
// honest trade-offs. Keep the wording in sync with assets/analytics.js.
const analyticsNotice = () => (!GA && !MP) ? '' : `\n  <p class="fine">This site records usage analytics: pages viewed, which sections are read and for how long, scroll depth, and clicks on links, diagrams and code blocks. It also records a replay of your visit — scrolling, pointer movement and clicks are captured so the session can be played back. This is a static document site with no accounts, forms, search or back end, so nothing you type is collected. Analytics and replay are switched off entirely if your browser sends Global Privacy Control or Do Not Track.</p>`

const layout = ({ title, description, base, page, body, toc, wide }) => `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)}</title>
<meta name="description" content="${esc(description)}">
<meta property="og:title" content="${esc(title)}">
<meta property="og:description" content="${esc(description)}">
<meta property="og:type" content="website">
${SITE_URL ? `<meta property="og:url" content="${esc(SITE_URL)}">\n` : ''}<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Ctext y='26' font-size='26'%3E%F0%9F%A4%9D%3C/text%3E%3C/svg%3E">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:opsz,wght@12..96,600;12..96,700;12..96,800&family=Schibsted+Grotesk:wght@400;500;700&family=Spline+Sans+Mono:wght@400;600&display=swap">
<link rel="stylesheet" href="${base}assets/site.css">
<script>
  // Applied before first paint so the correct theme is never repainted.
  try {
    var t = localStorage.getItem('pact-theme');
    if (t === 'light' || t === 'dark') document.documentElement.setAttribute('data-theme', t);
  } catch (e) {}
</script>
${analyticsHead(base)}<script>window.PACT_PAGE=${JSON.stringify(page)};</script>
<script defer src="${base}assets/analytics.js"></script>
</head>
<body${wide ? ' class="wide"' : ''}>
<div class="progress" id="progress" aria-hidden="true"><span></span></div>
<header class="topbar">
  <a class="brand" href="${base}">PACT</a>
  <nav>
    <a href="${base}spec/">Specification</a>
    <a href="${base}explainer/">Explainer</a>
    <button id="theme-toggle" type="button" aria-label="Switch colour theme">Theme</button>
  </nav>
</header>
${toc || ''}
<main class="${toc ? 'with-toc' : ''}">
${body}
</main>
<footer class="sitefoot">
  <p><strong>PACT</strong> — Personal Agent Communication &amp; Trust. Specification v1.0.0.</p>${analyticsNotice()}
</footer>
<script type="module" src="${base}assets/site.js"></script>
</body>
</html>
`

const tocHtml = (items) => {
  const li = items.map(h =>
    `<li class="lvl${h.level}"><a href="#${esc(h.id)}" data-toc="${esc(h.id)}">${esc(h.title)}</a></li>`
  ).join('\n      ')
  return `<aside class="toc" id="toc">
  <p class="toc-title">Contents</p>
  <nav>
    <ol>
      ${li}
    </ol>
  </nav>
</aside>`
}

/* ------------------------------------------------------------------- build */

await rm(out, { recursive: true, force: true })
await mkdir(resolve(out, 'spec'), { recursive: true })
await mkdir(resolve(out, 'explainer'), { recursive: true })

// --- spec
const specMd = await readFile(resolve(root, 'SPEC.md'), 'utf8')
headings.length = 0
const specBody = md.render(specMd)
const specHeadings = headings.slice()

// A paragraph followed immediately by `---` (no blank line) is a setext h2 in CommonMark, which
// silently promotes prose into a section heading here and on GitHub. Long headings are the tell.
const suspect = specHeadings.filter(h => h.title.length > 120)
if (suspect.length) {
  console.error('\nHeadings that look like accidental setext headings — add a blank line before the `---`:')
  suspect.forEach(h => console.error(`  ${h.title.slice(0, 100)}...`))
  process.exit(1)
}

await writeFile(resolve(out, 'spec', 'index.html'), layout({
  title: 'PACT 1.0 — Specification',
  description: 'PACT 1.0: person-to-person messaging between AI assistant agents over MCP and mTLS. The normative specification.',
  base: '../',
  page: { id: 'spec', title: 'Specification', sections: specHeadings.length },
  body: `<article class="doc" id="doc">\n${specBody}\n</article>`,
  toc: tocHtml(specHeadings),
}))

// --- explainer: the source file is an Artifact *body* (starts at <title>, no wrapper).
// It is wrapped here at build time and never modified on disk.
const explainerRaw = await readFile(resolve(root, 'explainer', 'pact-explainer.html'), 'utf8')
const explainerTitle = (explainerRaw.match(/<title>([\s\S]*?)<\/title>/i) || [, 'How PACT Works'])[1]
const explainerBody = explainerRaw.replace(/<title>[\s\S]*?<\/title>/i, '').trim()

await writeFile(resolve(out, 'explainer', 'index.html'), `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(explainerTitle)} — PACT</title>
<meta name="description" content="A visual walkthrough of how PACT pairs two people's agents and carries messages between them.">
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Ctext y='26' font-size='26'%3E%F0%9F%A4%9D%3C/text%3E%3C/svg%3E">
<script>
  try {
    var t = localStorage.getItem('pact-theme');
    if (t === 'light' || t === 'dark') document.documentElement.setAttribute('data-theme', t);
  } catch (e) {}
</script>
${analyticsHead('../')}<script>window.PACT_PAGE=${JSON.stringify({ id: 'explainer', title: 'Explainer' })};</script>
<script defer src="../assets/analytics.js"></script>
<style>
  .pact-return{font:500 14px/1 'Schibsted Grotesk',system-ui,sans-serif;display:block;max-width:900px;
    margin:20px auto 0;padding:0 24px;color:#0E7C66;text-decoration:none}
  .pact-return:hover{text-decoration:underline}
  @media (prefers-color-scheme:dark){:root:not([data-theme="light"]) .pact-return{color:#45C7A4}}
  :root[data-theme="dark"] .pact-return{color:#45C7A4}
</style>
</head>
<body>
<a class="pact-return" href="../">← PACT</a>
${explainerBody}
</body>
</html>
`)

// --- landing
const readme = await readFile(resolve(root, 'README.md'), 'utf8')
const status = (readme.match(/^\*\*?Status.*$/mi) || [''])[0].replace(/\*\*/g, '')

const landing = `<section class="hero">
  <p class="eyebrow">Specification v1.0.0 · 2026-08-23</p>
  <h1>Personal Agent<br>Communication &amp; Trust</h1>
  <p class="lede">A protocol for person-to-person communication carried out by their AI assistant agents.
  Each person exposes an MCP server over HTTPS; contacts are mutual, human-approved, and pinned by TLS key
  fingerprint. Messages, media, availability checks, and calendar booking are permission-gated MCP tools.</p>
  <p class="cta">
    <a class="btn primary" href="spec/" data-cta="spec">Read the specification</a>
    <a class="btn" href="explainer/" data-cta="explainer">See how it works</a>
  </p>
</section>

<section class="pillars">
  <div class="pillar">
    <h2>One keypair per person</h2>
    <p>Your agent's TLS client certificate <em>is</em> your identity. Friends pin each other's key
    fingerprints when they add each other. No envelope crypto, no key ceremonies.</p>
  </div>
  <div class="pillar">
    <h2>Your agent is an MCP server</h2>
    <p>Sending a message <em>is</em> calling the other party's <code>send_message</code> tool. Every
    capability is a tool, visible and callable only per your permission settings for that contact.</p>
  </div>
  <div class="pillar">
    <h2>Contacts are vCards</h2>
    <p>A contact card is a standard vCard with three extra <code>X-PACT-*</code> fields. Share it over
    WhatsApp, email, AirDrop, or as a QR — the channels people already use.</p>
  </div>
  <div class="pillar">
    <h2>Invites are short URLs</h2>
    <p>Expiry, max uses, auto-accept and permission preset all live on the sender's server, so a link
    is revocable at the protocol level by deleting it.</p>
  </div>
</section>

<section class="tradeoffs">
  <h2>Stated trade-offs</h2>
  <p>No end-to-end encryption beyond the TLS session — a gateway you route through can read traffic, so
  you choose gateways you trust, or connect direct. No anonymity or metadata hiding. No decentralized
  identity layer. §11 of the specification records what was dropped from an earlier hardened draft and
  what each drop costs.</p>
</section>
`

await writeFile(resolve(out, 'index.html'), layout({
  title: 'PACT — Personal Agent Communication & Trust',
  description: 'PACT is a protocol for person-to-person communication carried out by AI assistant agents, over MCP and mTLS.',
  base: '',
  page: { id: 'home', title: 'Home' },
  body: landing,
  toc: null,
  wide: true,
}))

// --- 404: served from the site root for any path, so it carries its own styling.
await writeFile(resolve(out, '404.html'), `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Not found — PACT</title>
<style>
  body{margin:0;min-height:100vh;display:grid;place-items:center;background:#FAFAF8;color:#1B2422;
    font:400 16px/1.6 system-ui,-apple-system,sans-serif;text-align:center;padding:24px}
  a{color:#0E7C66}
  @media (prefers-color-scheme:dark){body{background:#0F1614;color:#E7ECE8}a{color:#45C7A4}}
</style>
</head>
<body>
  <div>
    <h1>404</h1>
    <p>That page isn't here.</p>
    <p><a href="/">Go to the PACT specification</a></p>
  </div>
</body>
</html>
`)

await cp(resolve(root, 'site', 'assets'), resolve(out, 'assets'), { recursive: true })

// Self-hosted so the page makes no third-party request. Only shipped when Mixpanel is
// actually configured, so an analytics-off build stays byte-for-byte free of it.
//
// This is deliberately the WITH-RECORDER build. Session replay is enabled, and the
// plain bundle lazy-loads its recorder from cdn.mxpnl.com at runtime, which would put
// a third-party script back on the page after we just removed one. The recorder is
// inlined here instead, which is most of the 433 kB.
if (MP) {
  await cp(
    resolve(root, 'node_modules', 'mixpanel-browser', 'dist', 'mixpanel-with-recorder.min.js'),
    resolve(out, 'assets', 'mixpanel.min.js'),
  )
}

console.log(`built dist/ — spec (${specHeadings.length} sections), explainer, landing, 404`)
console.log(`analytics: GA4 ${GA ? 'on' : 'off'}, Mixpanel ${MP ? 'on' : 'off'}`)
