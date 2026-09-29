// SPEC.md's Appendix B, read by one rule, which the checker (check.mjs) and the splicer (gen.mjs)
// share: every block fenced as ```json between the heading `## Appendix B` and the first `*End of
// PACT` AFTER it, both markers there, every fence closed, every block JSON. vectors/appendix-b-reader.json
// is the list of cases it is held to, refusals word for word, and a byte-identical copy of the list
// pact-identity holds its four readers to.
//
// The two copies here searched for the end marker from the start of the file, so an end marker quoted
// before the heading cut the appendix to nothing; with no end marker at all the checker's slice
// stopped one character short of the end of the file, and a fence left open was dropped without a
// word (the port-parity audit of 2026-09-29, TC-12).

/**
 * Where Appendix B is in `spec`, and its blocks: `{ start, end, blocks: [{ value, from, to }] }`, where
 * `from`..`to` is the fenced block's text in `spec`, fences included.
 */
export function appendixB(spec) {
  const start = spec.indexOf('## Appendix B');
  if (start < 0) throw new Error('the document has no Appendix B');
  const end = spec.indexOf('*End of PACT', start);
  if (end < 0) throw new Error('Appendix B has no end marker (*End of PACT)');
  const text = spec.slice(start, end);
  const blocks = [];
  let at = 0;
  for (;;) {
    const i = text.indexOf('```json\n', at);
    if (i < 0) return { start, end, blocks };
    const j = text.indexOf('\n```', i + 8);
    if (j < 0) throw new Error('an unterminated json fence in Appendix B');
    let value;
    try {
      value = JSON.parse(text.slice(i + 8, j));
    } catch {
      throw new Error(`Appendix B block ${blocks.length + 1} is not JSON`);
    }
    blocks.push({ value, from: start + i, to: start + j + 4 });
    at = j + 4;
  }
}
