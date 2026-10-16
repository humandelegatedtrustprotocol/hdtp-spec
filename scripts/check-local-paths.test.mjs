// check-local-paths.mjs checks whatever path it is run through. Node resolves a module's own URL to
// its real path, so a script that runs its check only when argv[1] names that URL does nothing when
// it is reached through a symlink (the system's temporary directory on macOS is one) and passes
// silently. Here the check runs over a scratch repository, reached through a link, with a plant and
// without one.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { cpSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { join, resolve, dirname } from 'node:path'
import { tmpdir } from 'node:os'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const env = Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith('GIT_')))
// Spelled in pieces, so that this file does not carry what it refuses.
const mac = ['', 'Users', 'someone', 'notes.md'].join('/')

function throughALink(readme) {
  const dir = mkdtempSync(join(tmpdir(), 'hdtp-spec-paths-'))
  try {
    const repo = join(dir, 'repo')
    for (const f of ['scripts/check-local-paths.mjs', 'scripts/local-paths.mjs', 'scripts/tracked.mjs', 'site/spec-source.mjs']) {
      mkdirSync(dirname(join(repo, f)), { recursive: true })
      cpSync(join(root, f), join(repo, f))
    }
    writeFileSync(join(repo, 'README.md'), readme)
    for (const args of [['init', '-q'], ['add', '-A']]) spawnSync('git', ['-C', repo, ...args], { env })
    symlinkSync(repo, join(dir, 'link'))
    return spawnSync(process.execPath, [join(dir, 'link', 'scripts', 'check-local-paths.mjs')], { encoding: 'utf8', env })
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
}

test('run through a symlink, the check refuses a planted path', () => {
  const r = throughALink(`the draft is at ${mac}\n`)
  assert.equal(r.status, 1, r.stdout + r.stderr)
  assert.match(r.stderr, /README\.md:1: carries a local machine path/)
})

test('run through a symlink, the check passes clean text and says so', () => {
  const r = throughALink('the draft is in the worktree\n')
  assert.equal(r.status, 0, r.stdout + r.stderr)
  assert.match(r.stdout, /check-local-paths: ok \(\d+ files\)/)
})
