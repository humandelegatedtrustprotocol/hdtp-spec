// No living text of this repository carries a path from the machine that wrote it.
//
//   node scripts/check-local-paths.mjs             check, and exit 1 on any tracked text that carries one
//   node scripts/check-local-paths.mjs --selftest  prove the check refuses what it should, then check
//
// A home directory on macOS or Linux — a path under /Users or /home, whatever the name — is the
// writer's own machine, and in a public repository that is a stranger reading someone's home
// directory layout. Every tracked file is read, whatever its extension, except what git itself would
// call binary (a NUL byte in its first 8000 bytes).
//
// The dated records listed in docs/records.sha256 are not living text and are not read: they are
// true of their date and keep the words of their day. Whether one of them is redacted, and its hash
// pinned again, is the maintainer's decision, not this check's. This repository has no git hooks, so
// a commit message is held to the same rule by whoever writes it (CONTRIBUTING.md, "Sending a change").
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { root } from '../site/spec-source.mjs'
import { records, tracked } from './tracked.mjs'

const LOCAL = /\/Users\/|\/home\/[A-Za-z0-9._-]+\//

// The lines of `text` that carry a local path, as `line: what`.
export function localPaths(text) {
  const bad = []
  text.split('\n').forEach((line, i) => {
    const m = LOCAL.exec(line)
    if (m) bad.push(`${i + 1}: carries a local machine path (${m[0]})`)
  })
  return bad
}

const binary = (bytes) => bytes.subarray(0, 8000).includes(0)

export function check() {
  const frozen = records()
  const problems = []
  let files = 0
  for (const f of tracked()) {
    if (frozen.has(f)) continue
    const bytes = readFileSync(join(root, f))
    if (binary(bytes)) continue
    files++
    for (const p of localPaths(bytes.toString('utf8'))) problems.push(`${f}:${p}`)
  }
  return { problems, files }
}

function selftest() {
  // Spelled in pieces, so that this file does not carry what it refuses.
  const mac = ['', 'Users', 'someone', 'notes.md'].join('/')
  const linux = ['', 'home', 'someone', 'notes.md'].join('/')
  const cases = [
    [`the draft is at ${mac}`, 1],
    [`the draft is at ${linux}`, 1],
    [`see ${mac}\nand ${linux}`, 2],
    ['/usr/local/bin, /var/lib/hdtp and the worktree', 0],
    ['a path under /Users or /home, whatever the name', 0],
  ]
  for (const [text, want] of cases) {
    const got = localPaths(text).length
    if (got !== want) { console.error(`check-local-paths: the self-test failed on ${JSON.stringify(text)}: ${got} problems, wanted ${want}`); process.exit(1) }
  }
}

if (process.argv.includes('--selftest')) selftest()
const { problems, files } = check()
if (problems.length) {
  console.error(`check-local-paths: ${problems.length} line(s) carry a path from the machine that wrote them; say "the worktree" or "the sibling checkout" instead:`)
  for (const p of problems) console.error('  ' + p)
  process.exit(1)
}
console.log(`check-local-paths: ok (${files} files${process.argv.includes('--selftest') ? ', self-test passed' : ''})`)
