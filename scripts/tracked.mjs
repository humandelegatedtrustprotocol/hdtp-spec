// What the checks over this repository's text read: the tracked files, and which of them are the
// dated records of docs/records.sha256, frozen while their bytes are the ones it pins — not living text, true of their date, and not read by any
// check of what the text says today. Both readers are here and nowhere else, so that check-refs.mjs
// and check-local-paths.mjs cannot drift apart on which files are living text.
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { root } from '../site/spec-source.mjs'

// Every tracked file, relative to the repository's root; without git, every file under it.
export function tracked() {
  try {
    return execFileSync('git', ['-C', root, 'ls-files', '-z'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).split('\0').filter(Boolean)
  } catch {
    const walk = (dir) => readdirSync(join(root, dir), { withFileTypes: true }).flatMap((e) =>
      e.name === '.git' || e.name === 'node_modules' ? [] : e.isDirectory() ? walk(join(dir, e.name)) : [join(dir, e.name)])
    return walk('.')
  }
}

// What docs/records.sha256 lists: each path, as it lists it, to the sha256 it pins. No manifest is no record.
export function records() {
  const path = join(root, 'docs', 'records.sha256')
  if (!existsSync(path)) return new Map()
  return new Map(readFileSync(path, 'utf8').split('\n').filter(Boolean).map((l) => { const [hash, f] = l.split(/\s+/); return [f, hash] }))
}

// The records that are frozen now: listed, and their bytes still the ones the manifest pins. A listed
// file whose bytes have moved is living text again, so a line added to the manifest exempts nothing.
export function frozenRecords(manifest = records(), read = (f) => readFileSync(join(root, f))) {
  const frozen = new Set()
  for (const [f, hash] of manifest) {
    let bytes
    try { bytes = read(f) } catch { continue }
    if (createHash('sha256').update(bytes).digest('hex') === hash) frozen.add(f)
  }
  return frozen
}
