// The schema's examples: schema/<version>/examples/<Definition>/<name>.json, each one an object the
// schema defines, validated against schema/<version>/schema.json.
//
//   node schema/examples.mjs    exit 1 when an example fails its definition, when an object of the
//                               schema has no example, or when an example names no definition
//
// Every object schema/gen.mjs takes from the contract has at least one example. Each validation has a
// control: the same example with one member the definition does not list must FAIL, so a validator
// that accepted everything could not pass this check. The examples were written by real code — the
// envelope is Appendix B's first, the export objects come from hdtp-identity's own writer, the
// signing request's CSR from its csr_new — and hold certificates and fingerprints of the vectors.
import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import Ajv2020 from 'ajv/dist/2020.js'
import { root } from '../site/spec-source.mjs'
import { OBJECTS } from './gen.mjs'

const versions = readdirSync(join(root, 'schema'), { withFileTypes: true })
  .filter((e) => e.isDirectory() && existsSync(join(root, 'schema', e.name, 'schema.json'))).map((e) => e.name).sort()

const problems = []
let checked = 0
for (const version of versions) {
  const schema = JSON.parse(readFileSync(join(root, 'schema', version, 'schema.json'), 'utf8'))
  const ajv = new Ajv2020({ strict: false, allErrors: true })
  ajv.addSchema(schema)
  const dir = join(root, 'schema', version, 'examples')
  const defs = existsSync(dir) ? readdirSync(dir) : []
  // The objects of THIS version's schema: a released one is frozen and may define fewer than gen.mjs takes now.
  const objects = OBJECTS.filter((name) => schema.$defs[name])
  for (const name of objects) if (!defs.includes(name)) problems.push(`schema/${version}: ${name} has no example in examples/${name}/`)
  for (const def of defs) {
    if (!objects.includes(def)) { problems.push(`schema/${version}/examples/${def}: not an object of the schema (${objects.join(', ')})`); continue }
    const validate = ajv.getSchema(`${schema.$id}#/$defs/${def}`)
    for (const file of readdirSync(join(dir, def)).filter((f) => f.endsWith('.json'))) {
      const where = `schema/${version}/examples/${def}/${file}`
      const example = JSON.parse(readFileSync(join(dir, def, file), 'utf8'))
      if (!validate(example)) problems.push(`${where}: ${ajv.errorsText(validate.errors)}`)
      if (validate({ ...example, 'x-not-in-the-schema': true })) problems.push(`${where}: the control passed — a member ${def} does not list was accepted, so this validation proves nothing`)
      checked++
    }
  }
}
if (problems.length) {
  for (const p of problems) console.error('schema examples: ' + p)
  process.exit(1)
}
console.log(`schema examples: ok (${checked} examples, each with its control, in ${versions.join(', ')})`)
