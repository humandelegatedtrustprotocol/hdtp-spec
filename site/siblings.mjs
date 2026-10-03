// Where this repository finds hdtp-identity: `HDTP_IDENTITY_DIR` when it is set, else the checkout
// beside this one (`../hdtp-identity`, as the umbrella lays them out). Read at each call, not at
// load, so a caller can point it elsewhere. One copy, for every reader: the renderer's MUST
// registry (site/spec-html.mjs) and the test that holds its extractor to hdtp-identity's.
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')

export function identityDir(env = process.env) {
  return env.HDTP_IDENTITY_DIR || resolve(root, '..', 'hdtp-identity')
}
