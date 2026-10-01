// The one source of the licence and attribution wording every rendering of SPEC.md carries: the
// whitepaper's cover line and licence page, its PDF metadata, the web fragment's footer, and the
// README's attribution line (held to this by vectors/check.mjs). Nothing here is typed twice:
//
//   the copyright line   NOTICE's "Copyright <year> <holder>"
//   title, author, URL   CITATION.cff (its first title:, given-names:/family-names:, url:, license:)
//   version and date     the header line of SPEC.md, through splitSpec
//
// What the sentences say about which licence covers what is the README's "Licensing" table, PATENTS.md
// and NOTICE, as they read when this was written; site/spec-html.test.mjs holds the names and
// numbers each sentence relies on to those files, so a change there turns the check red here.
//
// `read(path)` returns a file of the repository, or null when it is absent: the whitepaper build
// reads the working tree, the web renderer reads the commit it renders. A tree without LICENSE-docs
// (the PACT 1.2.0 text, d130444, predates the licences) gets no licence at all: null.

import { esc } from './markdown.mjs'
import { info, text as pdfText } from './pdf.mjs'

// The licences the wording names, by their SPDX id.
export const LICENCES = Object.freeze({
  'CC-BY-4.0': { name: 'CC BY 4.0', title: 'Creative Commons Attribution 4.0 International', url: 'https://creativecommons.org/licenses/by/4.0/' },
  'Apache-2.0': { name: 'Apache-2.0', title: 'Apache License, Version 2.0', url: 'https://www.apache.org/licenses/LICENSE-2.0' },
  'OFL-1.1': { name: 'OFL-1.1', title: 'SIL Open Font License, Version 1.1' },
})

// The typefaces the whitepaper is set in (site/whitepaper.css), each with its licence file.
export const FONTS = Object.freeze([
  { family: 'Inter', file: 'site/brand/OFL-inter.txt' },
  { family: 'JetBrains Mono', file: 'site/brand/OFL-jetbrains-mono.txt' },
])

const field = (cff, key) => {
  const m = new RegExp(`^[\\s-]*${key}:\\s*"?([^"\\n]*?)"?\\s*$`, 'm').exec(cff)
  if (!m) throw new Error(`CITATION.cff: no ${key}:`)
  return m[1]
}

export function licence(read, { version, date }) {
  if (read('LICENSE-docs') === null) return null
  const notice = read('NOTICE'), cff = read('CITATION.cff')
  if (notice === null || cff === null) throw new Error('LICENSE-docs without NOTICE or CITATION.cff: the licence wording has nothing to read')
  const c = /^Copyright (\d{4}) (.+)$/m.exec(notice)
  if (!c) throw new Error('NOTICE: no "Copyright <year> <holder>" line')
  const [, year, holder] = c
  const title = field(cff, 'title')
  const author = `${field(cff, 'given-names')} ${field(cff, 'family-names')}`
  const url = field(cff, 'url')
  const text = LICENCES[field(cff, 'license')]
  if (!text) throw new Error(`CITATION.cff: license ${field(cff, 'license')} is not one this wording names`)
  if (author !== holder) throw new Error(`NOTICE names ${holder} as the copyright holder, CITATION.cff ${author} as the author`)

  // The attribution line the README asks for, in its three spellings.
  const tail = `, by ${author}, version ${version} (${date}), ${url}, licensed under ${text.name} (${text.url}).`
  const attribution = {
    text: `${title}${tail}`,
    markdown: `*${title}*${tail}`,
    html: `<em>${esc(title)}</em>${esc(tail)}`,
  }
  const copyright = `© ${year} ${holder}`
  const code = LICENCES['Apache-2.0'], fonts = LICENCES['OFL-1.1']
  const link = (u) => `<a href="${esc(u)}">${esc(u)}</a>`

  // The licence page of the whitepaper: [label, html] paragraphs, in reading order; the one
  // without a label is the attribution line itself.
  const page = [
    ['Copyright', `${esc(copyright)}.`],
    ['The text', `This document renders the specification, <code>SPEC.md</code>, whose text is licensed under the ${esc(text.title)} licence (${esc(text.name)}): ${link(text.url)}. ${esc(text.name)} requires attribution when the text is shared, as it is or adapted. Attribute it with this line, and state whether you changed the text:`],
    ['', attribution.html],
    ['Code and test vectors', `The test vectors, as the file <code>vectors/pact-2.0-vectors.json</code>, and the code of the specification's repository are licensed under the ${esc(code.title)} (${esc(code.name)}): ${link(code.url)}. Redistributions carry its <code>NOTICE</code> file. The copy of the vectors printed in Appendix B is part of this document's text.`],
    ['Patents', `${esc(holder)} has made the Open Web Foundation Final Specification Agreement (OWFa 1.0), Patent Only, for this specification, as an individual and, as its director, for Shailka Systems Private Limited as a Bound Entity; the declaration is the file <code>PATENTS.md</code>, beside <code>SPEC.md</code> in the specification's source repository.`],
    ['Typefaces', `Set in ${FONTS.map((f) => esc(f.family)).join(' and ')}, each under the ${esc(fonts.title)} (${esc(fonts.name)}).`],
    ['The mark', 'The PACT mark on the cover is not covered by any of these licences.'],
  ]

  return {
    version,
    date,
    copyright,
    licence: text,
    attribution,
    // The short line on the cover and in the web fragment's footer.
    short: `${copyright} · ${text.name}`,
    page,
    // The fragment's footer: one paragraph, no heading, so the site's contents are unchanged.
    footer: `<footer class="licence"><p>${esc(copyright)}. The text is licensed under <a href="${esc(text.url)}">${esc(text.name)}</a>; attribute it as: ${attribution.html}</p></footer>\n`,
    // The whitepaper's document information. ASCII only: written as PDF literal strings.
    info: {
      Author: author,
      Subject: `PACT specification ${version} (${date}). Text: ${text.name}, ${text.url}. Code and the test-vector file: ${code.name}.`,
      Keywords: `PACT, specification, ${text.name}, ${code.name}, OWFa 1.0`,
    },
  }
}

// What a printed whitepaper must carry, read back from the PDF's own bytes: the copyright line,
// the attribution line, the version and date `rights` was built from (the header line's) written
// into it, and the licence's address in the text a reader copies out; and the author and the
// licence in the document information. Whitespace is ignored, as the text extractor cannot see a
// line break.
export function pdfProblems(bytes, rights) {
  const problems = []
  const squash = (s) => s.replace(/\s+/g, '')
  const all = squash(pdfText(bytes).join(''))
  const versioned = `${rights.info.Author}, version ${rights.version} (${rights.date})`
  for (const [what, want] of [['the copyright line', rights.copyright], ['the attribution line', rights.attribution.text], ['the attribution with the version of the header line', versioned], ["the licence's address", rights.licence.url]]) {
    if (!all.includes(squash(want))) problems.push(`the PDF's text lacks ${what}: ${want}`)
  }
  const { values } = info(bytes)
  for (const [key, want] of Object.entries(rights.info)) {
    if (values[key] !== want) problems.push(`the PDF's ${key} is ${JSON.stringify(values[key])}, not ${JSON.stringify(want)}`)
  }
  if (!`${values.Subject} ${values.Keywords}`.includes(rights.licence.name)) problems.push(`neither the PDF's Subject nor its Keywords names ${rights.licence.name}`)
  return problems
}
