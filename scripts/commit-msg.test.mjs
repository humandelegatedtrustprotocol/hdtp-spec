// The hooks in githooks/, held here because no hook can hold itself. commit-msg's pattern is three
// copies of one rule: hdtp-identity's commit-msg (the line is held equal), and this repository's
// scripts/local-paths.mjs, the rule check-local-paths.mjs applies (held by verdict, case by case).
// pre-push refuses before the gate when a sibling it needs is missing, and gates nothing on a push of
// deletions only.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from 'node:fs'
import { join, resolve, dirname } from 'node:path'
import { tmpdir } from 'node:os'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'
import { localPaths } from './local-paths.mjs'
import { identityDir } from '../site/siblings.mjs'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const ours = join(root, 'githooks', 'commit-msg')
const pattern = (file) => readFileSync(file, 'utf8').split('\n').filter((l) => l.startsWith('LOCAL_PATH='))

// Spelled in pieces, so that this file does not carry what it refuses.
const mac = ['', 'Users', 'someone', 'notes.md'].join('/')
const linux = ['', 'home', 'someone', 'notes.md'].join('/')
const CASES = [
  `fix: the draft at ${mac} is gone`,
  `fix: see ${linux}`,
  `cd ${linux.split('/').slice(0, 3).join('/')}`,
  'fix: the route /a/home/mcp',
  'fix: /usr/local/bin, /var/lib/hdtp and the worktree',
  'docs: a path under /Users or /home, whatever the name',
]

function verdict(hook, text) {
  const dir = mkdtempSync(join(tmpdir(), 'hdtp-spec-msg-'))
  try {
    writeFileSync(join(dir, 'MSG'), text + '\n')
    return spawnSync('bash', [hook, join(dir, 'MSG')], { encoding: 'utf8' })
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
}

test("commit-msg's pattern is hdtp-identity's, line for line", () => {
  const theirs = join(identityDir(), 'githooks', 'commit-msg')
  assert.ok(existsSync(theirs), `hdtp-identity is not at ${identityDir()}: set HDTP_IDENTITY_DIR`)
  assert.equal(pattern(ours).length, 1, 'githooks/commit-msg has no single LOCAL_PATH line')
  assert.deepEqual(pattern(ours), pattern(theirs))
})

test('commit-msg refuses what check-local-paths refuses, and passes what it passes', () => {
  const refused = CASES.filter((t) => localPaths(t).length)
  assert.ok(refused.length >= 3 && refused.length < CASES.length, 'the cases need plants and controls both')
  for (const text of CASES) {
    const r = verdict(ours, text)
    assert.equal(r.status !== 0, localPaths(text).length > 0, `${JSON.stringify(text)}: the hook exits ${r.status}, check-local-paths finds ${localPaths(text).length}`)
    if (r.status !== 0) assert.match(r.stderr, /carries a path from this machine/)
  }
})

const prePush = (stdin, env) => spawnSync('bash', [join(root, 'githooks', 'pre-push'), 'origin', 'url'], {
  cwd: root, input: stdin, encoding: 'utf8',
  env: { ...Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith('GIT_'))), ...env },
})

test('pre-push stops before the gate when a sibling is missing', () => {
  const nowhere = join(tmpdir(), 'hdtp-no-such-sibling')
  const head = spawnSync('git', ['-C', root, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).stdout.trim()
  const line = `refs/heads/x ${head} refs/heads/x ${'0'.repeat(40)}\n`
  for (const [name, env] of [['hdtp-web-kit', { HDTP_WEB_KIT_DIR: nowhere }], ['hdtp-identity', { HDTP_IDENTITY_DIR: nowhere }]]) {
    const r = prePush(line, env)
    assert.equal(r.status, 1, r.stdout + r.stderr)
    assert.match(r.stderr, new RegExp(`${name} is not at ${nowhere}`))
    assert.match(r.stderr, /nothing was gated/)
    assert.doesNotMatch(r.stdout, /make check/)
  }
})

test('pre-push gates nothing on a push that only deletes', () => {
  const r = prePush(`(delete) ${'0'.repeat(40)} refs/heads/x ${'1'.repeat(40)}\n`, { HDTP_WEB_KIT_DIR: join(tmpdir(), 'hdtp-no-such-sibling') })
  assert.equal(r.status, 0, r.stdout + r.stderr)
  assert.equal(r.stdout + r.stderr, '')
})
