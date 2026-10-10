// Where this repository finds its siblings: hdtp-identity at `HDTP_IDENTITY_DIR` when it is set, else
// the checkout beside this one (`../hdtp-identity`, as the umbrella lays them out); hdtp-web-kit at
// `HDTP_WEB_KIT_DIR`, else `../hdtp-web-kit`. Read at each call, not at load, so a caller can point
// them elsewhere. One copy, for every reader: hdtp-identity for the renderer's MUST registry
// (site/spec-html.mjs), the schema (schema/gen.mjs) and the test that holds the extractor to
// hdtp-identity's; hdtp-web-kit for the tests that hold the diagram contract and the fonts list and
// scanner to the kit's.
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')

export function identityDir(env = process.env) {
  return env.HDTP_IDENTITY_DIR || resolve(root, '..', 'hdtp-identity')
}

export function webKitDir(env = process.env) {
  return env.HDTP_WEB_KIT_DIR || resolve(root, '..', 'hdtp-web-kit')
}
