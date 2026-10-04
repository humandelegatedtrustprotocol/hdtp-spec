// Every section reference and every relative link in this repository's living text resolves.
//
//   node scripts/check-refs.mjs             check, and exit 1 on any reference that resolves to nothing
//   node scripts/check-refs.mjs --selftest  prove the check refuses what it should, then check
//
// A section reference is `§N`, `§N.M`, … (a space after `§` allowed). In a page of
// docs/specification/<version>/ it must name a numbered heading of that version; in any other
// living text it must name one of the newest released version, which is the one such text
// describes. A `§` that follows `RFC <number>` is that RFC's section, and one that follows `CONTRACT` is
// a section of hdtp-identity's contract (whose descriptions the schema reference carries): neither is
// ours, and both are skipped.
// A relative link `[text](path)` must name a file that exists, from the file it is written in.
//
// The dated records listed in docs/records.sha256 are not living text and are not read: they are
// true of their date and keep the references of their day.
import { execFileSync } from 'node:child_process'
import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { current, root, SPEC_DIR } from '../site/spec-source.mjs'

// The numbered headings of one version's pages: `## 2. Identity…`, `### 2.1 Deriving…`.
export function headingsOf(files) {
  const out = new Set()
  for (const text of files) {
    for (const m of text.matchAll(/^#{2,4} (\d+(?:\.\d+)*)\.? /gm)) out.add(m[1])
  }
  return out
}

// The section references and relative links of `text` that resolve to nothing. `exists(path)`
// answers for a link, relative to the file the text came from.
export function unresolved(text, headings, exists) {
  const bad = []
  const lines = text.split('\n')
  let fence = false
  lines.forEach((line, i) => {
    if (/^\s*```/.test(line)) { fence = !fence; return }
    if (fence) return
    for (const m of line.matchAll(/§\s?(\d+(?:\.\d+)*)/g)) {
      if (/(?:RFC\s?\d+,?|CONTRACT)\s*$/.test(line.slice(0, m.index))) continue
      if (!headings.has(m[1])) bad.push(`${i + 1}: §${m[1]} names no section`)
    }
    for (const m of line.matchAll(/\]\(([^)\s]+)\)/g)) {
      const target = m[1].split('#')[0]
      if (!target || /^[a-z][a-z0-9+.-]*:/i.test(target)) continue
      if (!exists(target)) bad.push(`${i + 1}: the link ${m[1]} names no file`)
    }
  })
  return bad
}

function tracked() {
  try {
    return execFileSync('git', ['-C', root, 'ls-files', '-z'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).split('\0').filter(Boolean)
  } catch {
    const walk = (dir) => readdirSync(join(root, dir), { withFileTypes: true }).flatMap((e) =>
      e.name === '.git' || e.name === 'node_modules' ? [] : e.isDirectory() ? walk(join(dir, e.name)) : [join(dir, e.name)])
    return walk('.')
  }
}

function records() {
  const path = join(root, 'docs', 'records.sha256')
  if (!existsSync(path)) return new Set()
  return new Set(readFileSync(path, 'utf8').split('\n').filter(Boolean).map((l) => l.split(/\s+/)[1]))
}

export function check() {
  const frozen = records()
  const files = tracked().filter((f) => f.endsWith('.md') && !frozen.has(f))
  const all = readdirSync(join(root, SPEC_DIR), { withFileTypes: true }).filter((e) => e.isDirectory()).map((e) => e.name)
  const byVersion = new Map(all.map((v) => {
    const dir = join(root, SPEC_DIR, v)
    const pages = readdirSync(dir).filter((n) => n.endsWith('.md')).map((n) => readFileSync(join(dir, n), 'utf8'))
    return [v, headingsOf(pages)]
  }))
  const newest = byVersion.get(current())
  const problems = []
  let refs = 0
  for (const f of files) {
    const m = new RegExp(`^${SPEC_DIR}/([^/]+)/`).exec(f)
    const headings = m ? byVersion.get(m[1]) : newest
    if (!headings) continue
    const text = readFileSync(join(root, f), 'utf8')
    refs += [...text.matchAll(/§\s?\d/g)].length
    for (const p of unresolved(text, headings, (t) => existsSync(join(root, dirname(f), t)))) problems.push(`${f}:${p}`)
  }
  return { problems, files: files.length, refs }
}

function selftest() {
  const headings = headingsOf(['## 2. Identity\n\n### 2.1 Deriving\n'])
  const here = (t) => t === 'identity.md'
  const cases = [
    ['§2 and §2.1 and § 2', 0],
    ['§3', 1],
    ['§2.2', 1],
    ['RFC 9180 §7.1 and RFC 8032, §5.1.5', 0],
    ['(CONTRACT §0)', 0],
    ['(SPEC §9.3)', 1],
    ['[the page](identity.md) and [a place](identity.md#s2) and [web](https://example.com/x)', 0],
    ['[gone](gone.md)', 1],
    ['```\n§9\n```', 0],
  ]
  for (const [text, want] of cases) {
    const got = unresolved(text, headings, here).length
    if (got !== want) { console.error(`check-refs: the self-test failed on ${JSON.stringify(text)}: ${got} problems, wanted ${want}`); process.exit(1) }
  }
}

if (process.argv.includes('--selftest')) selftest()
const { problems, files, refs } = check()
if (problems.length) {
  console.error(`check-refs: ${problems.length} reference(s) resolve to nothing:`)
  for (const p of problems) console.error('  ' + p)
  process.exit(1)
}
console.log(`check-refs: ok (${files} files, ${refs} section references${process.argv.includes('--selftest') ? ', self-test passed' : ''})`)
