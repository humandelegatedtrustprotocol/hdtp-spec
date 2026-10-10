// Open fonts only: every font this repository names — the whitepaper's stylesheet, the mermaid
// configuration its drawings are laid out with, the explainer — is an open font or a CSS generic
// family. Run by `npm run spec:check`, part of `make check`.
//
// site/fonts.json (the list) and site/fonts.mjs (the scanner) are copies of hdtp-web-kit's
// bin/fonts.json and bin/fonts.mjs, both held to the kit's byte for byte with the kit beside this
// repository (HDTP_WEB_KIT_DIR overrides the place). Without the kit that test fails, and the scan
// holds to the committed copies.
//
// The explainer alone may name more: the families its Google Fonts link loads, each of which must be
// on GOOGLE_OFL below.

import { execFileSync } from 'node:child_process'
import { existsSync, readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { EXTENSIONS, fontProblems, scan } from './fonts.mjs'
import { webKitDir } from './siblings.mjs'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const kit = webKitDir()
const sibling = existsSync(join(kit, 'kit', 'styles.css'))

// Families the explainer loads from Google Fonts, each published there under the SIL Open Font
// License 1.1 (fonts.google.com lists the licence on each family's page). A family added to the
// explainer's link is added here only after reading its licence.
const GOOGLE_OFL = ['Bricolage Grotesque', 'Schibsted Grotesk', 'Spline Sans Mono']
const EXPLAINER = 'explainer/hdtp-explainer.html'

// Every file of the repository a font can be named in: tracked, or new and not ignored. The scanner
// itself is left out: its source quotes the syntax it reads.
const files = execFileSync('git', ['-C', root, 'ls-files', '--cached', '--others', '--exclude-standard'], { encoding: 'utf8' })
  .split('\n').filter((f) => f && EXTENSIONS.some((e) => f.endsWith(e)) && f !== 'site/fonts.mjs' && existsSync(join(root, f)))

describe('fonts', () => {
  it("are hdtp-web-kit's list and scanner: site/fonts.json and site/fonts.mjs are the kit's bin/ files byte for byte", () => {
    assert.ok(sibling, `hdtp-web-kit is not at ${kit}: set HDTP_WEB_KIT_DIR`)
    for (const f of ['fonts.json', 'fonts.mjs']) {
      const theirs = join(kit, 'bin', f)
      assert.ok(existsSync(theirs), `${theirs} is missing: hdtp-web-kit's open-fonts change (bin/${f}) lands in the kit first`)
      assert.ok(readFileSync(join(root, 'site', f)).equals(readFileSync(theirs)), `site/${f} differs from ${theirs}: copy the kit's file over it`)
    }
  })

  it('the explainer loads from Google Fonts only families on GOOGLE_OFL', () => {
    const loaded = scan(readFileSync(join(root, EXPLAINER), 'utf8'), EXPLAINER).google
    assert.ok(loaded.length, 'the explainer loads no Google Fonts family: GOOGLE_OFL and this test are left over')
    for (const f of loaded) assert.ok(GOOGLE_OFL.includes(f), `the explainer loads "${f}" from Google Fonts, which is not on GOOGLE_OFL`)
  })

  it('every font a file names is an open font on the list, or a CSS generic family', () => {
    assert.ok(files.includes('site/whitepaper.css') && files.includes('site/mermaid.mjs') && files.includes(EXPLAINER), files.join(' '))
    const loaded = scan(readFileSync(join(root, EXPLAINER), 'utf8'), EXPLAINER).google.filter((f) => GOOGLE_OFL.includes(f))
    assert.deepEqual(fontProblems(root, files, { extra: { [EXPLAINER]: loaded } }), [])
  })
})
