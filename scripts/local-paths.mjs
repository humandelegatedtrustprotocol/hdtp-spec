// The one rule for a path from the writer's machine, with no side effect on import: check-local-paths.mjs
// applies it to the tracked files, and scripts/commit-msg.test.mjs holds githooks/commit-msg to it.

// A /home path counts where it begins a path (not inside one, as in a route like a/home/x) and names
// someone, whatever follows the name (a slash, a space, punctuation or the end of the line).
const LOCAL = /\/Users\/|(^|[^A-Za-z0-9_\/-])\/home\/[A-Za-z0-9._-]+/

// The lines of `text` that carry a local path, as `line: what`.
export function localPaths(text) {
  const bad = []
  text.split('\n').forEach((line, i) => {
    const m = LOCAL.exec(line)
    if (m) bad.push(`${i + 1}: carries a local machine path (${m[0]})`)
  })
  return bad
}
