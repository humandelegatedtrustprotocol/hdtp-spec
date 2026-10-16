// `make publish` against a stub wrangler: the recipe only ever runs against the real bucket, so this
// runs it here, on every check, with a fake `wrangler` first on PATH that records each call and puts
// nothing anywhere. The Makefile and package.json are copied into a temp directory outside this
// checkout (where no node_modules/.bin can put the real wrangler ahead of the fake), with a stand-in
// dist/ and credentials file; `check` and `build` are taken as made (`make -o`), so what runs is the
// publish recipe itself: the credentials-file test, the meta-against-PDF test, and `npm run publish`.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { delimiter, join, resolve, dirname } from 'node:path'
import { tmpdir } from 'node:os'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const sha = (b) => createHash('sha256').update(b).digest('hex')

const FAKE = `#!/usr/bin/env node
import { appendFileSync, readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
const args = process.argv.slice(2)
const i = args.indexOf('--file')
const file = i >= 0 ? createHash('sha256').update(readFileSync(args[i + 1])).digest('hex') : null
appendFileSync(process.env.FAKE_WRANGLER_LOG, JSON.stringify({ args, file, token: process.env.CLOUDFLARE_API_TOKEN, account: process.env.CLOUDFLARE_ACCOUNT_ID }) + '\\n')
if (process.env.FAKE_WRANGLER_FAIL && args.some((a) => a.endsWith(process.env.FAKE_WRANGLER_FAIL))) process.exit(1)
`

const PDF = Buffer.from('%PDF-1.7 a stand-in, not a whitepaper\n')

function publish({ metaBytes = PDF.length, envFile = true, fail } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'hdtp-spec-publish-'))
  try {
    copyFileSync(join(root, 'Makefile'), join(dir, 'Makefile'))
    copyFileSync(join(root, 'package.json'), join(dir, 'package.json'))
    mkdirSync(join(dir, 'dist'))
    writeFileSync(join(dir, 'dist', 'hdtp-whitepaper.pdf'), PDF)
    const meta = JSON.stringify({ version: '9.9.9', bytes: metaBytes })
    writeFileSync(join(dir, 'dist', 'hdtp-whitepaper.meta.json'), meta)
    const env = join(dir, 'credentials.env')
    if (envFile) writeFileSync(env, 'CLOUDFLARE_API_TOKEN=stub-token\nCLOUDFLARE_ACCOUNT_ID=stub-account\n')
    const bin = join(dir, 'bin')
    mkdirSync(bin)
    writeFileSync(join(bin, 'wrangler'), FAKE)
    chmodSync(join(bin, 'wrangler'), 0o755)
    const log = join(dir, 'wrangler.log')
    // No inherited credential, no node_modules/.bin (an `npm run` above this one puts the real
    // wrangler there): the file is the only source of the token, the fake the only wrangler.
    const inherited = Object.fromEntries(Object.entries(process.env).filter(([k]) => !/^(CLOUDFLARE_|npm_|FAKE_WRANGLER_)/.test(k)))
    const path = [bin, ...(process.env.PATH || '').split(delimiter).filter((p) => p && !p.includes('node_modules'))].join(delimiter)
    const r = spawnSync('make', ['-C', dir, '-o', 'check', '-o', 'build', 'publish', `ENV_FILE=${env}`], {
      encoding: 'utf8',
      env: { ...inherited, PATH: path, FAKE_WRANGLER_LOG: log, ...(fail ? { FAKE_WRANGLER_FAIL: fail } : {}) },
    })
    const calls = existsSync(log) ? readFileSync(log, 'utf8').trim().split('\n').map((l) => JSON.parse(l)) : []
    return { status: r.status, out: r.stdout + r.stderr, calls, meta }
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
}

test('make publish puts the PDF, then its meta as JSON, into hdtp-private, with the credentials from the file', () => {
  const { status, out, calls, meta } = publish()
  assert.equal(status, 0, out)
  assert.doesNotMatch(out, /vectors:check|build-whitepaper/, 'check and build ran: the recipe under test was not reached alone')
  assert.match(out, /publishing 9\.9\.9 \(\d+ bytes\)/)
  assert.deepEqual(calls.map((c) => c.args), [
    ['r2', 'object', 'put', 'hdtp-private/hdtp-whitepaper.pdf', '--file', 'dist/hdtp-whitepaper.pdf', '--remote'],
    ['r2', 'object', 'put', 'hdtp-private/hdtp-whitepaper.meta.json', '--file', 'dist/hdtp-whitepaper.meta.json', '--content-type', 'application/json', '--remote'],
  ])
  assert.deepEqual(calls.map((c) => c.file), [sha(PDF), sha(meta)])
  for (const c of calls) assert.deepEqual([c.token, c.account], ['stub-token', 'stub-account'])
})

test('a meta that is not of the PDF beside it publishes nothing', () => {
  const { status, out, calls } = publish({ metaBytes: PDF.length + 1 })
  assert.notEqual(status, 0)
  assert.match(out, /not one build, nothing published/)
  assert.deepEqual(calls, [])
})

test('without the credentials file nothing is published', () => {
  const { status, out, calls } = publish({ envFile: false })
  assert.notEqual(status, 0)
  assert.match(out, /no \.env at /)
  assert.deepEqual(calls, [])
})

test('a PDF that did not go up leaves the meta where it was', () => {
  const { status, calls } = publish({ fail: 'hdtp-whitepaper.pdf' })
  assert.notEqual(status, 0)
  assert.deepEqual(calls.map((c) => c.args[3]), ['hdtp-private/hdtp-whitepaper.pdf'])
})
