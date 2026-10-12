// The draft's `invalid_envelopes` (§13.1, SEP-0005): `sealed_call` arguments as raw JSON text, each an
// Appendix B envelope with one change, and the code a receiver holding its recipient key answers.
// Text, not parsed JSON, because a parsed fixture cannot hold a repeated member. Both senders here are
// Ed25519 and seal from a labelled seed, so every entry reproduces byte for byte from the envelopes.

const four = (e) => ({ protected: e.protected, enc: e.enc, ct: e.ct, sig: e.sig });
const withSig = (e, ...sigs) => `{"protected":${JSON.stringify(e.protected)},"enc":${JSON.stringify(e.enc)},"ct":${JSON.stringify(e.ct)},${sigs.map((s) => `"sig":${s}`).join(',')}}`;

/** The entries, from Appendix B's `envelopes`: `[{ name, envelope, arguments_text, answer }]`. */
export function invalidEnvelopes(envelopes) {
  const byName = Object.fromEntries(envelopes.map((e) => [e.name, e]));
  const chain = byName['alina-to-bharat'], small = byName['alina-to-bharat-by-reference'];
  const entry = (name, e, text, answer) => ({ name, envelope: e.name, arguments_text: text, answer });
  const { sig: _, ...noSig } = four(small);
  const { sig, ...rest } = four(chain);
  return [
    entry('a fifth member', chain, JSON.stringify({ ...four(chain), note: 'x' }), 'envelope_invalid'),
    entry('sig spelled SIG', chain, JSON.stringify({ ...rest, SIG: sig }), 'envelope_invalid'),
    entry('Protected beside protected', chain, JSON.stringify({ ...four(chain), Protected: chain.protected }), 'envelope_invalid'),
    entry('sig absent, in the small form', small, JSON.stringify(noSig), 'envelope_invalid'),
    entry('sig null, in the small form', small, JSON.stringify({ ...noSig, sig: null }), 'envelope_invalid'),
    entry('sig a number', chain, JSON.stringify({ ...rest, sig: 5 }), 'envelope_invalid'),
    entry('sig not base64url, in the small form', small, JSON.stringify({ ...noSig, sig: '!!!!' }), 'envelope_invalid'),
    entry('an array in place of the object', chain, JSON.stringify(Object.values(four(chain))), 'envelope_invalid'),
    entry('sig twice, AAAA then the real one', chain, withSig(chain, '"AAAA"', JSON.stringify(sig)), 'ok'),
    entry('sig twice, the real one then AAAA', chain, withSig(chain, JSON.stringify(sig), '"AAAA"'), 'envelope_invalid'),
    entry('sig twice, 5 then the real one', chain, withSig(chain, '5', JSON.stringify(sig)), 'ok'),
  ];
}

/** The draft's Appendix B block: the released block and its `invalid_envelopes`. */
export const draftVectors = (vec) => ({ ...vec, invalid_envelopes: invalidEnvelopes(vec.envelopes) });
