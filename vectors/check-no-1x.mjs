#!/usr/bin/env node
// PACT 1.x is gone, and this is what holds it gone in this repository: no tracked file carries a
// NAME that 1.x had and 2.x does not — a card property, a tool, a mode, an info string — outside
// the two kinds of file that are allowed to:
//
//   - a dated record: `archive/` (the rejected pre-pivot drafts) and `docs/landscape-and-roadmap.md`,
//     neither of which is rendered or normative;
//   - a file listed below WITH ITS REASON.
//
// The generation's own name is not forbidden — the specification has to say "PACT 1.x is not
// supported". The names are in vectors/pact1x-markers.txt; the node (pact-gateway) and pact-cloud
// carry their own guard and their own copy of that file, and the node's test compares the three
// byte for byte whenever the repositories are checked out side by side.
//
//   node vectors/check-no-1x.mjs            # the gate (run by `npm run vectors:check`)
//   node vectors/check-no-1x.mjs --selftest # proves the gate fails on a planted name
import { execFileSync } from 'node:child_process'
import { readFileSync, statSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const repo = resolve(here, '..')

const markers = readFileSync(join(here, 'pact1x-markers.txt'), 'utf8')
  .split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#')).map((l) => new RegExp(l))
if (markers.length < 10) {
  console.error(`check-no-1x: read only ${markers.length} markers: the reader is broken, not the tree`)
  process.exit(1)
}

const history = /^(archive\/|docs\/landscape-and-roadmap\.md$)/
const built = /(^|\/)(dist|node_modules)\/|package-lock\.json$|\.(png|jpg|jpeg|gif|ico|pdf|wasm|woff2?)$/
const allowed = new Map(Object.entries({
  'SPEC.md': 'the normative refusal: §3 and §9 name the retired card properties in order to say none is written and none is honoured',
  'vectors/intrude.mjs': 'the intrusion battery: every 1.x input it sends — a stale info string, a retired property appended in flight — must be refused or ignored',
}))

function namesIn(text) {
  const out = []
  text.split('\n').forEach((line, i) => {
    for (const m of markers) {
      const hit = m.exec(line)
      if (hit) { out.push([i + 1, hit[0]]); break }
    }
  })
  return out
}

if (process.argv.includes('--selftest')) {
  const planted = namesIn('a clean line\nthe card carries X-PACT-' + 'KEY here\ncall relay_' + 'call when offline\n')
  const clean = namesIn('PACT 1.x is not supported; a leaf is renewed, a root never rotates.\n')
  if (planted.length !== 2 || planted[0][0] !== 2 || clean.length !== 0) {
    console.error('check-no-1x --selftest: the matcher did not find two planted names, or found one in clean prose')
    process.exit(1)
  }
  console.log('check-no-1x --selftest: ok (2 planted names found, clean prose passes)')
  process.exit(0)
}

const tracked = execFileSync('git', ['-C', repo, 'ls-files'], { encoding: 'utf8' }).split('\n').filter(Boolean)
const carries = new Set()
const found = []
let scanned = 0
for (const rel of tracked) {
  if (history.test(rel) || built.test(rel) || rel.endsWith('pact1x-markers.txt')) continue
  let st
  try { st = statSync(join(repo, rel)) } catch { continue } // deleted since ls-files
  if (st.isDirectory()) continue
  const buf = readFileSync(join(repo, rel))
  if (buf.includes(0)) continue // binary
  scanned++
  for (const [line, name] of namesIn(buf.toString('utf8'))) {
    carries.add(rel)
    if (!allowed.has(rel)) found.push(`${rel}:${line}: ${name}`)
  }
}

const problems = []
// A guard that read nothing passes. This repository has about twenty tracked text files.
if (scanned < 12) problems.push(`scanned only ${scanned} files: the walk is broken, not the tree`)
if (found.length) {
  problems.push(`${found.length} line(s) carry a name PACT 1.x had and 2.x does not. Say it without the name, or list the file above with its reason.\n  ` + found.sort().join('\n  '))
}
for (const [rel, why] of allowed) {
  if (!carries.has(rel)) problems.push(`${rel} is allowed to carry a 1.x name (${why}) and carries none: the list is stale`)
}
if (problems.length) {
  console.error('check-no-1x:\n' + problems.join('\n'))
  process.exit(1)
}
console.log(`check-no-1x: ok (${scanned} files, ${markers.length} names, ${allowed.size} allowed with a reason)`)
