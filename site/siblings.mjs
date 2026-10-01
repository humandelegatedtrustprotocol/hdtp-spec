// Where this repository finds pact-identity: `PACT_IDENTITY_DIR` when it is set, else the checkout
// beside this one (`../pact-identity`, as the umbrella lays them out). Read at each call, not at
// load, so a caller can point it elsewhere. One copy, for every reader: the renderer's MUST
// registry (site/spec-html.mjs) and the test that holds its extractor to pact-identity's.
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')

export function identityDir(env = process.env) {
  return env.PACT_IDENTITY_DIR || resolve(root, '..', 'pact-identity')
}
