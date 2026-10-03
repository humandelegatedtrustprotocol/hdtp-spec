// What the text SAYS about the wire's versions and about its own vectors, read out of the prose so
// that check.mjs can hold each statement to the bytes. A version is written in a dozen sentences —
// the header table, the validation order, the conformance checklist, the appendix — and a sentence
// nobody compares with the vectors can say another number: 1.0.0's text said an envelope's `v` and a
// card's major were 2 in two places, and called its vectors `v: 2`, for as long as the only check
// was a reader's eye.
//
// Nothing here knows the right number. `stated(text)` returns every statement it finds, by kind, and
// the caller compares them with what the vectors, the card codec and the schema carry.

const WORDS = ['zero', 'one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine', 'ten', 'eleven', 'twelve',
  'thirteen', 'fourteen', 'fifteen', 'sixteen', 'seventeen', 'eighteen', 'nineteen', 'twenty']
const number = (word) => { const n = WORDS.indexOf(word.toLowerCase()); return n < 0 ? NaN : n }
const all = (text, re) => [...text.matchAll(re)].map((m) => m[1])
const lineOf = (text, at) => text.slice(0, at).split('\n').length

export function stated(text) {
  // Prose: the text with its fenced blocks taken out, so a diagram's or an example's own words are
  // not read as statements about a generation.
  const prose = text.replace(/^```[\s\S]*?^```/gm, (block) => block.replace(/[^\n]/g, ' '))
  const count = (re) => { const m = re.exec(text); return m ? number(m[1]) : null }
  const renewed = /(\w+) `certificate_renewed` answers, (\w+) of them discarded/.exec(text)
  return {
    // An envelope header's `v`: "`v` (=N)", "`v` is not `N`", "`v: N`", and a JSON member.
    envelope: [...all(text, /`v` \(=(\d+)\)/g), ...all(text, /`v` is not `(\d+)`/g), ...all(text, /\bv: (\d+)\b/g), ...all(text, /"v": ?(\d+)/g)],
    // A card's major: the property with its value, "is not `N`", and the property table's row.
    card: [...all(text, /X-HDTP-VERSION:(\d+)/g), ...all(text, /`X-HDTP-VERSION` is not `(\d+)`/g), ...all(text, /Protocol major version: `(\d+)`/g)],
    // An export's version: the manifest example and the sentence under it.
    exported: [...all(text, /"hdtp_export": ?(\d+)/g), ...all(text, /`hdtp_export` is `(\d+)`/g)],
    // The HPKE info string: the one sentence that defines it, and every other spelling of the label.
    info: all(text, /The HPKE `info` parameter is the ASCII string `([^`]+)`/g),
    infoLabels: all(text, /\b(HDTP-SEAL-v\d+)\b/g),
    // A bare generation word in prose ("the v2 core"): the text names no generation by number.
    // `-v1` inside a label, "proof v1" (the challenge labels) and "X.509 v3" are not generations.
    generations: [...prose.matchAll(/(?<![\w-])v(\d+)\b/g)]
      .filter((m) => !/(proof|X\.509) $/.test(prose.slice(Math.max(0, m.index - 6), m.index)))
      .map((m) => `v${m[1]} (line ${lineOf(prose, m.index)})`),
    // What the appendix says its vectors are, in words.
    counts: {
      certificates: count(/(\w+) certificates to the §14\.1 profile/),
      refused: count(/and (\w+) that exist to be refused/),
      chainCases: count(/(\w+) chain cases/),
      comparisons: count(/(\w+) §14\.3 comparisons/),
      renewed: renewed ? number(renewed[1]) : null,
      discarded: renewed ? number(renewed[2]) : null,
      envelopes: count(/(\w+) `v: \d+` envelopes/),
    },
  }
}
