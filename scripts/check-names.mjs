#!/usr/bin/env node
// The HDTP name guard: no tracked file of this repository carries, in its path or its text, a name
// that hdtp-names.txt (beside this file) forbids, outside that list's allow entries. The list says
// what each kind of line means; this file is the same bytes in every repository that runs it.
//
//   node <dir>/check-names.mjs              # the gate
//   node <dir>/check-names.mjs --selftest   # proves the matcher finds planted names and passes English
//
// The repository is named by its origin remote, never by its folder: a checkout's folder can carry
// any name. Outside hdtp-spec, the list and this file are compared byte for byte with hdtp-spec's
// scripts/ copies whenever that repository is beside this one (or at HDTP_SPEC_DIR).
import { execFileSync } from 'node:child_process'
import { existsSync, readFileSync, statSync } from 'node:fs'
import { basename, dirname, join, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const LIST = 'hdtp-names.txt'
const SELF = basename(fileURLToPath(import.meta.url))
const listPath = join(here, LIST)

export function readList(text) {
  const list = { names: [], except: [], retired: [], allow: [] }
  for (const raw of text.split('\n')) {
    const line = raw.trim()
    if (!line || line.startsWith('#')) continue
    const [kind] = line.split(' ', 1)
    const rest = line.slice(kind.length + 1)
    if (kind === 'name') list.names.push(rest)
    else if (kind === 'except-after') list.except.push(rest.toLowerCase())
    else if (kind === 'retired') list.retired.push(new RegExp(rest))
    else if (kind === 'allow' || kind === 'once') {
      const [repo, path] = rest.split(' ', 2)
      const text = rest.slice(repo.length + path.length + 2)
      if (!repo || !path || !text) throw new Error(`${LIST}: an ${kind} entry needs a repository, a path and a text: ${line}`)
      list.allow.push({ once: kind === 'once', repo, path, text })
    } else throw new Error(`${LIST}: a line of no known kind: ${line}`)
  }
  return list
}

// Every forbidden name in `text`: [{ at, found }], `at` the offset in `text`.
export function hits(list, text) {
  const out = []
  // A name is matched as it is spelled in the list, never folded: the list has a line for each way
  // the old name was written, and any other casing of its letters is two words joined (stepAction).
  // The exception before it is read in any case (impact, Compact, COMPACT).
  for (const name of list.names) {
    for (let i = text.indexOf(name); i >= 0; i = text.indexOf(name, i + 1)) {
      if (list.except.some((p) => i >= p.length && text.slice(i - p.length, i).toLowerCase() === p)) continue
      out.push({ at: i, found: name })
    }
  }
  for (const re of list.retired) {
    const g = new RegExp(re.source, 'g')
    for (let m = g.exec(text); m; m = g.exec(text)) {
      out.push({ at: m.index, found: m[0] })
      if (!m[0].length) g.lastIndex++
    }
  }
  return out
}

const lineOf = (text, at) => text.slice(0, at).split('\n').length

if (process.argv.includes('--selftest')) {
  const list = readList(readFileSync(listPath, 'utf8'))
  const p = 'pa' + 'ct'
  const P = p[0].toUpperCase() + p.slice(1)
  const planted = [`${p.toUpperCase()}_FOO`, `${p}Id`, `${P}Id`, `is${P}`, `x_${p}`, `${p}_identity`, `\\n${p} id`, `%2F${p}-probe`, `x-${p}-cert`, `x/${p}-probe.txt`, 'relay_' + 'call']
  // English words, and two words joined in camelCase, which are not the name.
  const english = ['impact', 'Compact', 'IMPACT', 'COMPACT', 'compacted', 'impacts', 'the compactor', 'stepAction', 'stepUpActions', 'keepActive', 'skipAction', 'HTTPAction']
  const missed = planted.filter((s) => hits(list, s).length !== 1)
  const flagged = english.filter((s) => hits(list, s).length !== 0)
  if (missed.length || flagged.length) {
    console.error(`check-names --selftest: missed ${JSON.stringify(missed)}, flagged ${JSON.stringify(flagged)}`)
    process.exit(1)
  }
  console.log(`check-names --selftest: ok (${planted.length} planted names found, ${english.length} English words and joined words pass)`)
  process.exit(0)
}

const root = execFileSync('git', ['-C', process.cwd(), 'rev-parse', '--show-toplevel'], { encoding: 'utf8' }).trim()
const origin = execFileSync('git', ['-C', root, 'remote', 'get-url', 'origin'], { encoding: 'utf8' }).trim()
const repo = basename(origin).replace(/\.git$/, '')
const listText = readFileSync(listPath, 'utf8')
const list = readList(listText)
const problems = []
if (list.names.length < 3 || list.retired.length < 10) problems.push(`read ${list.names.length} names and ${list.retired.length} retired names from ${LIST}: the reader is broken, not the tree`)

const listRel = relative(root, listPath)
const selfRel = relative(root, join(here, SELF))
const built = /(^|\/)(dist|node_modules|target)\/|(^|\/)go\.sum$/
const tracked = execFileSync('git', ['-C', root, 'ls-files', '-z'], { encoding: 'utf8', maxBuffer: 1 << 28 }).split('\0').filter(Boolean)
const mine = list.allow.filter((a) => a.repo === repo)
const used = new Map(mine.map((a) => [a, []]))
const found = []
let scanned = 0
for (const rel of tracked) {
  for (const h of hits(list, rel)) found.push(`${rel}: the path carries ${JSON.stringify(h.found)}`)
  if (rel === listRel || built.test(rel)) continue
  let buf
  try { if (statSync(join(root, rel)).isDirectory()) continue; buf = readFileSync(join(root, rel)) } catch { continue } // deleted since ls-files
  if (buf.includes(0)) continue
  scanned++
  const text = buf.toString('utf8')
  // Every occurrence of an allowed text is a span a forbidden name may sit in. It counts as a USE of
  // its entry unless it lies inside a longer entry's occurrence: `www.old.example` is not a use of
  // the entry for `old.example`, so that entry goes stale when the bare host is gone.
  const spans = []
  for (const a of mine.filter((a) => a.path === rel)) {
    for (let i = text.indexOf(a.text); i >= 0; i = text.indexOf(a.text, i + 1)) spans.push([i, i + a.text.length, a])
  }
  for (const [s, e, a] of spans) {
    if (!spans.some(([s2, e2, b]) => b !== a && s2 <= s && e2 >= e && e2 - s2 > e - s)) used.get(a).push(rel)
  }
  for (const a of mine.filter((a) => a.once && a.path !== rel)) if (text.includes(a.text)) used.get(a).push(rel)
  for (const h of hits(list, text)) {
    if (rel === selfRel) continue
    if (spans.some(([s, e]) => h.at >= s && h.at < e)) continue
    found.push(`${rel}:${lineOf(text, h.at)}: ${JSON.stringify(h.found)}`)
  }
}
// The guard checks its own code too, for everything but the planted names of its self-test.
if (hits(list, readFileSync(join(here, SELF), 'utf8')).length) problems.push(`${selfRel} carries a forbidden name outside its self-test's planted ones`)

// A guard that read nothing passes.
if (scanned < 10) problems.push(`scanned only ${scanned} files: the walk is broken, not the tree`)
if (found.length) problems.push(`${found.length} forbidden name(s) in ${repo}:\n  ` + found.sort().join('\n  '))
for (const [a, where] of used) {
  if (!where.includes(a.path)) problems.push(`allow entry for ${a.path} (${JSON.stringify(a.text)}) matches nothing there: the list is stale`)
  else if (a.once && where.length !== 1) problems.push(`${JSON.stringify(a.text)} is to occur once, in ${a.path}, and occurs in ${where.join(', ')}`)
}

if (repo !== 'hdtp-spec') {
  const spec = process.env.HDTP_SPEC_DIR || resolve(root, '..', 'hdtp-spec')
  if (!existsSync(join(spec, 'scripts', LIST))) console.log(`check-names: ${LIST} and ${SELF} not compared: hdtp-spec is not at ${spec}`)
  for (const [mine, name] of [[listPath, LIST], [join(here, SELF), SELF]]) {
    const canonical = join(spec, 'scripts', name)
    if (existsSync(canonical) && !readFileSync(canonical).equals(readFileSync(mine))) problems.push(`${relative(root, mine)} differs from hdtp-spec's scripts/${name}: every copy is that file's bytes`)
  }
}

if (problems.length) {
  console.error('check-names:\n' + problems.join('\n'))
  process.exit(1)
}
console.log(`check-names: ok (${repo}: ${tracked.length} paths, ${scanned} files, ${list.names.length + list.retired.length} rules, ${mine.length} allowed)`)
