// What the checks over this repository's text read: the tracked files, and which of them are the
// dated records of docs/records.sha256 — not living text, true of their date, and not read by any
// check of what the text says today. Both readers are here and nowhere else, so that check-refs.mjs
// and check-local-paths.mjs cannot drift apart on which files are living text.
import { execFileSync } from 'node:child_process'
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

// The paths docs/records.sha256 lists, as it lists them. No manifest is no record.
export function records() {
  const path = join(root, 'docs', 'records.sha256')
  if (!existsSync(path)) return new Set()
  return new Set(readFileSync(path, 'utf8').split('\n').filter(Boolean).map((l) => l.split(/\s+/)[1]))
}
