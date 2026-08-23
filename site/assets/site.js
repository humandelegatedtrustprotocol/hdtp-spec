/* Page behaviour: theme, reading progress, contents highlighting, code copy, mermaid.
 * Order matters at the end — mermaid changes section heights substantially, so impression
 * observers are only attached once diagrams have rendered. */

const root = document.documentElement
const track = (n, p) => window.pact && window.pact.track(n, p)

/* ------------------------------------------------------------------ theme */

const themeToggle = document.getElementById('theme-toggle')

function currentTheme () {
  return root.getAttribute('data-theme') ||
    (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light')
}

if (themeToggle) {
  themeToggle.addEventListener('click', () => {
    const next = currentTheme() === 'dark' ? 'light' : 'dark'
    root.setAttribute('data-theme', next)
    try { localStorage.setItem('pact-theme', next) } catch (e) {}
    track('theme_change', { theme: next })
    renderMermaid()
  })
}

/* --------------------------------------------------------------- progress */

const progress = document.querySelector('#progress span')

function onScroll () {
  if (progress) {
    const h = Math.max(1, document.documentElement.scrollHeight - innerHeight)
    progress.style.width = Math.min(100, (scrollY / h) * 100) + '%'
  }
  highlightToc()
}

let ticking = false
addEventListener('scroll', () => {
  if (ticking) return
  ticking = true
  requestAnimationFrame(() => { ticking = false; onScroll() })
}, { passive: true })

// Hidden tabs fire neither scroll nor rAF, so re-sync on the way back.
// visibilitychange is dispatched at document — a window listener is not reliable.
document.addEventListener('visibilitychange', () => {
  if (!document.hidden) { ticking = false; onScroll() }
})

/* ------------------------------------------------------------- code copy */

document.querySelectorAll('.code-block').forEach((block, i) => {
  const btn = document.createElement('button')
  btn.className = 'copy'
  btn.type = 'button'
  btn.textContent = 'Copy'
  btn.addEventListener('click', async () => {
    const text = block.querySelector('code')?.textContent ?? ''
    try {
      await navigator.clipboard.writeText(text)
      btn.textContent = 'Copied'
      setTimeout(() => { btn.textContent = 'Copy' }, 1600)
      track('code_copy', { lang: block.dataset.lang || 'text', block_index: i, chars: text.length })
    } catch (e) {
      btn.textContent = 'Failed'
      setTimeout(() => { btn.textContent = 'Copy' }, 1600)
    }
  })
  block.appendChild(btn)
})

/* ---------------------------------------------------------------- mermaid */

const diagrams = [...document.querySelectorAll('pre.mermaid')]
diagrams.forEach(n => { n.dataset.src = n.textContent })

function mermaidVars () {
  const cs = getComputedStyle(root)
  const v = (name, fallback) => (cs.getPropertyValue(name).trim() || fallback)
  const line = v('--line', '#D9DED8')
  const ink = v('--ink', '#1B2422')
  return {
    background: v('--card', '#FFFFFF'),
    primaryColor: v('--accent-soft', '#E3F0EB'),
    primaryTextColor: ink,
    primaryBorderColor: v('--accent', '#0E7C66'),
    secondaryColor: v('--surface', '#F1F2EE'),
    tertiaryColor: v('--surface', '#F1F2EE'),
    lineColor: v('--muted', '#5D6B66'),
    textColor: ink,
    mainBkg: v('--surface', '#F1F2EE'),
    nodeBorder: v('--accent', '#0E7C66'),
    clusterBkg: v('--card', '#FFFFFF'),
    clusterBorder: line,
    edgeLabelBackground: v('--card', '#FFFFFF'),
    actorBkg: v('--accent-soft', '#E3F0EB'),
    actorBorder: v('--accent', '#0E7C66'),
    actorTextColor: ink,
    signalColor: ink,
    signalTextColor: ink,
    labelBoxBkgColor: v('--surface', '#F1F2EE'),
    labelBoxBorderColor: line,
    noteBkgColor: v('--amber-soft', '#F6ECDD'),
    noteBorderColor: v('--amber', '#A9691C'),
    noteTextColor: ink,
    fontFamily: "'Schibsted Grotesk', system-ui, sans-serif",
  }
}

let mermaidMod = null

async function renderMermaid () {
  if (!diagrams.length) return
  try {
    if (!mermaidMod) {
      mermaidMod = (await import('https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs')).default
    }
    mermaidMod.initialize({
      startOnLoad: false,
      securityLevel: 'strict',
      theme: 'base',
      themeVariables: mermaidVars(),
    })
    diagrams.forEach(n => {
      n.textContent = n.dataset.src
      n.removeAttribute('data-processed')
    })
    await mermaidMod.run({ nodes: diagrams, suppressErrors: true })
  } catch (e) {
    // Diagram source stays visible as text — degraded, not broken.
    track('mermaid_error', { message: String(e && e.message).slice(0, 120) })
  }
}

/* --------------------------------------------------- sections + contents */

const doc = document.getElementById('doc')
const sections = []

if (doc) {
  const nodes = [...doc.childNodes]
  let current = null
  let index = 0

  const open = (id, title) => {
    current = document.createElement('section')
    current.className = 'section'
    current.setAttribute('data-section-id', id)
    current.setAttribute('data-section-title', title)
    current.setAttribute('data-section-index', String(index++))
    doc.appendChild(current)
    sections.push(current)
  }

  open('intro', 'Introduction')
  for (const node of nodes) {
    if (node.nodeType === 1 && (node.tagName === 'H2' || node.tagName === 'H3')) {
      open(node.id || 'section-' + index, node.textContent.replace(/#$/, '').trim())
    }
    current.appendChild(node)
  }
}

const tocLinks = [...document.querySelectorAll('.toc a')]
const tocById = new Map(tocLinks.map(a => [a.dataset.toc, a]))
let activeId = null

function highlightToc () {
  if (!sections.length || !tocLinks.length) return
  const y = scrollY + 90
  let found = null
  for (const s of sections) {
    if (s.offsetTop <= y) found = s.getAttribute('data-section-id')
    else break
  }
  if (found === activeId) return
  if (activeId && tocById.has(activeId)) tocById.get(activeId).classList.remove('active')
  activeId = found
  const link = tocById.get(activeId)
  if (link) {
    link.classList.add('active')
    const nav = link.closest('.toc')
    if (nav && link.offsetTop < nav.scrollTop) nav.scrollTop = link.offsetTop - 40
    else if (nav && link.offsetTop > nav.scrollTop + nav.clientHeight - 60) {
      nav.scrollTop = link.offsetTop - nav.clientHeight + 60
    }
  }
}

/* -------------------------------------------------------------- sequence */

await renderMermaid()
onScroll()
if (window.pact) window.pact.observeSections(sections)
