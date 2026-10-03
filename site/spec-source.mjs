// Where the specification's text is, and how it is read whole. Every reader of the text goes
// through here: the whitepaper build, the web renderer, the vectors' checker and splicer, the
// intrusion battery, and hdtp-identity's MUST registry and proofs.
//
// The text of a version lives in docs/specification/<version>/: `index.md` (the title, the
// `**Version X.Y.Z · date**` line, the introduction and a "Table of contents" of links) and one page
// per top-level section, in the order those links give. A numbered directory (`1.0`) is a released
// version, and holds every X.Y.Z of it; `draft` is where the next one is written. The document a
// reader means by "the specification" is the index followed by its pages, joined as they are.
import { execFileSync } from 'node:child_process'
import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

export const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
export const SPEC_DIR = 'docs/specification'
const NUMBERED = /^\d+\.\d+$/

// The pages the index links, in its order: the contents' `(name.md)` targets.
export function pagesOf(index) {
  const toc = index.slice(index.indexOf('\n## Table of contents'))
  const pages = [...toc.matchAll(/\]\(([a-z0-9-]+\.md)\)/g)].map((m) => m[1])
  if (!pages.length) throw new Error('the index links no pages')
  return pages
}

// The whole document, from `read(name)`, which returns one file of the version's directory.
export function assemble(read) {
  const index = read('index.md')
  return index + pagesOf(index).map(read).join('')
}

// The released versions under `base` (a checkout of this repository), oldest first.
export function versions(base = root) {
  const dir = join(base, SPEC_DIR)
  if (!existsSync(dir)) return []
  return readdirSync(dir).filter((d) => NUMBERED.test(d))
    .sort((a, b) => a.split('.').map(Number).reduce((c, x, i) => c || x - b.split('.').map(Number)[i], 0))
}

// The newest released version: what "the specification" means when no version is named.
export function current(base = root) {
  const all = versions(base)
  if (!all.length) throw new Error(`no released version under ${join(base, SPEC_DIR)}`)
  return all.at(-1)
}

// The directory of `version` under `base`.
export const versionDir = (base = root, version = current(base)) => join(base, SPEC_DIR, version)

// The document of `version` in the working tree under `base`.
export function readSpec(base = root, version = current(base)) {
  const dir = versionDir(base, version)
  return assemble((name) => readFileSync(join(dir, name), 'utf8'))
}

// The document of `version` as commit `commit` of the repository at `base` has it, never the
// working tree.
export function readSpecAt(commit, version, base = root) {
  const show = (path) => execFileSync('git', ['-C', base, 'show', `${commit}:${path}`], { encoding: 'utf8', maxBuffer: 1 << 26 })
  return assemble((name) => show(`${SPEC_DIR}/${version}/${name}`))
}
