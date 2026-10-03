// Every font a HDTP page or document names is an open font: one of fonts.json's families (each
// shipped as a file under its SIL Open Font License) or one of CSS's generic families, which resolve
// to the reader's own system font and name nothing. A family on the list is also refused where
// nothing in the scanned files supplies it (an @font-face, or the file's own Google Fonts link).
//
// The one copy of the list and of this scanner is hdtp-web-kit's bin/; a site's are .kit/bin/,
// held to the release by kit.lock, and hdtp-spec's site/fonts.json and site/fonts.mjs are held
// to the kit's byte for byte by its spec:check. Self-contained (node:fs and node:path only) so the
// copy runs anywhere.
//
// What it reads, in .css, .html, .svg, .js and .mjs files: `font-family:` and the `font:` shorthand
// (the family list is what follows the size), wherever they are written (a stylesheet, a <style>,
// a template string); SVG `font-family="…"`; and script `fontFamily` / `…FontFamily` set to a string
// (mermaid's configuration). `var(--x)` is followed to every `--x:` defined in the scanned files.
import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs'
import { join, relative } from 'node:path'

export const FONTS = JSON.parse(readFileSync(new URL('./fonts.json', import.meta.url), 'utf8'))
export const EXTENSIONS = ['.css', '.html', '.svg', '.js', '.mjs']
const CSS_WIDE = new Set(['inherit', 'initial', 'unset', 'revert', 'revert-layer'])
const SIZE = /(?:^|\s)(?:[\d.]+(?:px|em|rem|%|pt|pc|vw|vh|vmin|vmax|ch|ex|cap|ic|lh|rlh|q|mm|cm|in)|xx-small|x-small|small|medium|large|x-large|xx-large|xxx-large|smaller|larger|(?:calc|clamp|min|max)\([^)]*\))(?:\s*\/\s*\S+)?\s+(\S[\s\S]*)$/i

/** Every file under `dir` with one of EXTENSIONS, relative to `base`; dotfiles and node_modules skipped. */
export function fontFiles(dir, base = dir) {
  if (!existsSync(dir)) return []
  const out = []
  for (const name of readdirSync(dir).sort()) {
    if (name.startsWith('.') || name === 'node_modules') continue
    const p = join(dir, name)
    if (statSync(p).isDirectory()) out.push(...fontFiles(p, base))
    else if (EXTENSIONS.some((e) => name.endsWith(e))) out.push(relative(base, p).split('\\').join('/'))
  }
  return out
}

/**
 * Comments blanked (newlines kept, so line numbers hold): block comments in a stylesheet, markup
 * comments in HTML and SVG, and in a script the comments that begin a line (a `//` or `/*` inside a
 * line may be a URL or a pattern, so those stay).
 */
function blank(text, rel) {
  const keep = (c) => c.replace(/[^\n]/g, ' ')
  if (rel.endsWith('.css')) return text.replace(/\/\*[\s\S]*?\*\//g, keep)
  if (rel.endsWith('.html') || rel.endsWith('.svg')) return text.replace(/<!--[\s\S]*?-->/g, keep)
  return text.replace(/^[ \t]*\/\*[\s\S]*?\*\//gm, keep).replace(/^[ \t]*\/\/.*$/gm, keep)
}

/** A comma list split at top level (not inside var(…)). */
function split(list) {
  const out = []
  let depth = 0, cur = ''
  for (const ch of list) {
    if (ch === '(') depth++
    if (ch === ')') depth--
    if (ch === ',' && depth === 0) { out.push(cur); cur = '' } else cur += ch
  }
  out.push(cur)
  return out.map((s) => s.trim()).filter(Boolean)
}

/** What each file names: font stacks (as written), custom properties, @font-face families, Google Fonts families. */
export function scan(text, rel) {
  const t = blank(text, rel)
  const line = (i) => t.slice(0, i).split('\n').length
  const stacks = []
  for (const m of t.matchAll(/(?<![\w-])(font-family|font)\s*:\s*([^;{}<>\n]+)/g)) {
    let value = cut(m[2]).replace(/!important$/, '').trim()
    if (m[1] === 'font') {
      if (CSS_WIDE.has(value.toLowerCase())) continue
      const s = value.match(SIZE)
      if (s) value = s[1] // otherwise a lone var(--x) or a system font keyword: read as written
    }
    stacks.push({ at: line(m.index), value })
  }
  for (const m of t.matchAll(/\bfont-family\s*=\s*(["'])([^"']*)\1/g)) stacks.push({ at: line(m.index), value: m[2] })
  for (const m of t.matchAll(/\b\w*[fF]ont[fF]amily['"]?\s*[:=]\s*(["'`])([^"'`]*)\1/g)) stacks.push({ at: line(m.index), value: m[2] })
  const vars = []
  for (const m of t.matchAll(/(?<![\w-])--([\w-]+)\s*:\s*([^;{}]+)/g)) vars.push({ at: line(m.index), name: m[1], value: m[2].trim() })
  const faces = []
  for (const m of t.matchAll(/@font-face\s*\{[^}]*?font-family\s*:\s*([^;}]+)/g)) faces.push(unquote(m[1]))
  const google = []
  for (const m of t.matchAll(/fonts\.googleapis\.com\/css2?\?[^"'\s>]*/g)) {
    for (const f of m[0].matchAll(/family=([^&:;"']+)/g)) google.push(decodeURIComponent(f[1].replace(/\+/g, ' ')))
  }
  return { stacks, vars, faces, google }
}

/**
 * A declaration's value, ended where an enclosing string ends: a quote that does not open a family
 * name (at the start of an item) closes the attribute or the script string the CSS sits in.
 */
function cut(v) {
  let q = null, start = true, out = ''
  for (const ch of v) {
    if (q) { if (ch === q) q = null; out += ch; continue }
    if (ch === '"' || ch === "'" || ch === '`') { if (!start) break; q = ch; out += ch; start = false; continue }
    if (ch === ',') start = true
    else if (!/\s/.test(ch)) start = false
    out += ch
  }
  return out.trim()
}

function unquote(s) {
  return s.trim().replace(/^(["'])([\s\S]*)\1$/, '$2').replace(/\s+/g, ' ').trim()
}

/**
 * The problems with the fonts `files` (paths relative to `root`) name. `extra` maps a file to further
 * families that file may name (hdtp-spec's explainer, which loads open families from Google Fonts).
 * `fonts` is the allow-list (fonts.json by default). A family reached through var(--x) is reported at
 * the definition of --x, once, not at every use.
 */
export function fontProblems(root, files, { extra = {}, fonts = FONTS } = {}) {
  const allowed = new Set(Object.keys(fonts.families).map((f) => f.toLowerCase()))
  const generic = new Set(fonts.generic.map((g) => g.toLowerCase()))
  const scanned = new Map(files.map((rel) => [rel, scan(readFileSync(join(root, rel), 'utf8'), rel)]))
  const defs = new Map()
  for (const [rel, f] of scanned) for (const v of f.vars) defs.set(v.name, [...(defs.get(v.name) || []), { rel, ...v }])
  const faces = new Set([...scanned.values()].flatMap((f) => f.faces.map((x) => x.toLowerCase())))
  const problems = new Set()
  const followed = new Set()
  const check = (rel, at, value) => {
    const own = new Set((extra[rel] || []).map((x) => x.toLowerCase()))
    const google = new Set(scanned.get(rel).google.map((x) => x.toLowerCase()))
    for (const item of split(value)) {
      const v = item.match(/^var\(\s*--([\w-]+)\s*(?:,([\s\S]*))?\)$/)
      if (v) {
        if (v[2] !== undefined) check(rel, at, v[2])
        if (!defs.has(v[1])) { if (v[2] === undefined) problems.add(`${rel}:${at}: names var(--${v[1]}), which no scanned file defines`); continue }
        if (followed.has(v[1])) continue
        followed.add(v[1])
        for (const d of defs.get(v[1])) check(d.rel, d.at, d.value)
        continue
      }
      const name = unquote(item)
      const key = name.toLowerCase()
      if (generic.has(key) || CSS_WIDE.has(key)) continue
      if (!allowed.has(key) && !own.has(key)) problems.add(`${rel}:${at}: names the font "${name}", which is not an open font on the list (fonts.json: ${Object.keys(fonts.families).join(', ')}; and the generic families ${fonts.generic.join(', ')})`)
      else if (!faces.has(key) && !google.has(key)) problems.add(`${rel}:${at}: names "${name}", which no @font-face in the scanned files and no Google Fonts link in this file supplies`)
    }
  }
  for (const [rel, f] of scanned) for (const s of f.stacks) check(rel, s.at, s.value)
  return [...problems]
}
