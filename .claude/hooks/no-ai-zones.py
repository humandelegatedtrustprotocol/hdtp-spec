#!/usr/bin/env python3
"""No-AI zones: actions that need the owner, whatever mode the session runs in.

A Claude Code PreToolUse hook (Bash, Edit, Write, MultiEdit, NotebookEdit). It reads the tool call
on stdin and answers `deny` (the owner runs it himself with `!`) or `ask` (the owner approves it in
the prompt), or nothing. Common zones are below; a repository adds its own in
`.claude/no-ai-zones.json`. Any error answers `ask`: a broken guard never waves an action through.

The canonical copy lives in the umbrella's tools/no-ai-zones/; every repository carries an identical
copy at .claude/hooks/no-ai-zones.py, held equal by the umbrella's pre-push.
"""
import fnmatch
import json
import os
import re
import shlex
import sys
import time

DENY, ASK = "deny", "ask"

# (zone, decision, regex over one normalised command segment, reason)
BASH = [
    ("Z5", DENY, r"^git push\b.*\s(--force(-with-lease|-if-includes)?\b|-[a-zA-Z]*f[a-zA-Z]*\b|--delete\b|-d\b|--mirror\b|\+\S|:\S)",
     "history: force, delete or mirror push"),
    ("Z5", DENY, r"^git (filter-repo|filter-branch)\b", "history rewrite"),
    ("Z5", DENY, r"^gh repo (delete|archive|rename)\b|^gh repo edit\b.*--visibility", "repository visibility or existence"),
    ("Z5", DENY, r"^gh api\b.*(/protection\b|/rulesets\b)", "branch protection"),
    ("Z5", DENY, r"^gh api\b.*(-X|--method)[ =]?DELETE\b", "deletion through the GitHub API"),
    ("Z5", DENY, r"^gh pr close\b.*\s(-d|--delete-branch)\b", "closing a PR deletes its unmerged branch"),
    ("Z6", DENY, r"^docker (volume (rm|prune)|system prune|container prune|image prune)\b", "Docker data deletion"),
    ("Z6", DENY, r"^docker[- ]compose\b.*\bdown\b.*(\s-v\b|--volumes\b)", "Docker volume deletion"),
    ("Z6", ASK, r"^make\b.*(?<![\w-])[\w-]*(wipe|reset)(?!-(dry|inventory))(?![\w-]*-dry)[\w-]*", "wipe or reset target"),
    ("Z7", DENY, r"^git (commit|push|merge|rebase|cherry-pick|am)\b.*(\s--no-verify\b)", "hook bypass"),
    ("Z7", DENY, r"^git commit\b.*\s-[a-zA-Z]*n[a-zA-Z]*\b", "hook bypass (git commit -n)"),
    ("Z7", DENY, r"^git config\b.*\bcore\.hookspath\b", "hooks path change"),
    ("Z8", DENY, r"^git add\b.*\s(-A|--all|\.|\*|:/)(\s|$)", "git add -A/./*: stage explicit paths (a CA key and a 67 MB binary came in this way)"),
    ("Z1", ASK, r"\bship-production\b|(^|\s)env=prod(uction)?\b|--env[ =]prod(uction)?\b", "production deploy"),
    ("Z1", ASK, r"^terraform (apply|destroy|import|state|taint|untaint)\b|^make\b.*\btf-(apply|destroy)\b", "infrastructure change"),
    ("Z2", ASK, r"^wrangler d1 (migrations apply|execute)\b.*--remote\b|^wrangler d1 (create|delete)\b", "remote database change"),
    ("Z2", ASK, r"^make\b.*(?<![\w-])migrate[\w-]*", "database migration"),
    ("Z3", ASK, r"^gh release (create|edit|delete|upload)\b", "public release"),
    ("Z3", ASK, r"^git tag\b(?!\s*$)(?!.*\s(-l|--list|--contains|--points-at|-n)\b)", "release tag"),
    ("Z3", ASK, r"^git push\b.*(\s--tags\b|refs/tags/|\sv\d+\.\d+)", "release tag push"),
    ("Z3", ASK, r"^make\b.*(?<![\w-])(release|publish)(?![\w-])", "release or publish target"),
    ("Z4", ASK, r"^go get\b|^cargo add\b|^(pip3?|uv pip) install\b|^uv add\b|^brew install\b", "new dependency or host tool"),
    ("Z4", ASK, r"^(npm|pnpm|yarn|bun) (install|i|add)\b(\s+-\S+)*\s+[^-\s]", "new dependency"),
    ("Z8", ASK, r"^wrangler secret (put|delete|bulk)\b|^gh secret (set|delete)\b", "secrets"),
    ("Z8", ASK, r"^curl\b.*(api\.cloudflare\.com|api\.workos\.com|api\.github\.com|api\.stripe\.com).*(\s-X\s*(POST|PUT|PATCH|DELETE)|\s--request\s*(POST|PUT|PATCH|DELETE)|\s(-d|--data\S*|--json|-F|--form)\s)",
     "account or infrastructure change through an API"),
    ("Z8", ASK, r"^gh api\b(?!\s+graphql\b).*(\s(-X|--method)[ =]?(POST|PUT|PATCH)\b|\s(-f|-F|--field|--raw-field)\s)", "change through the GitHub API"),
]

# (zone, decision, glob over the repository-relative path, reason); the first matching rule wins
PATHS = [
    ("Z7", DENY, ".claude/settings*.json", "the guardrails' own settings"),
    ("Z7", DENY, ".claude/hooks/*", "the guardrails' own hooks"),
    ("Z7", DENY, ".claude/no-ai-zones.json", "the zone list"),
    ("Z7", DENY, "githooks/*", "git hooks"),
    ("Z7", DENY, "tools/git-hooks/*", "git hooks"),
    ("Z7", DENY, "tools/no-ai-zones/*", "the zone hook's canonical copy"),
    ("Z7", ASK, "CLAUDE.md", "agent instructions"),
    ("Z7", ASK, "AGENTS.md", "agent instructions"),
    ("Z2", ASK, "*migrations/*", "database migration"),
]
HOME_DENY = ["~/.claude/settings.json", "~/.claude/settings.local.json", "~/.claude/CLAUDE.md"]
GUARD_TOKENS = re.compile(r"\.claude/(settings[^/\s]*\.json|hooks/|no-ai-zones\.json)|(^|[\s/'\"])githooks/|tools/git-hooks/|tools/no-ai-zones/")
WRITERS = re.compile(r"^(cp|mv|tee|rm|ln|chmod|chown|truncate|install|touch|rsync|dd)\b|^sed\b.*\s-i|^perl\b.*\s-[a-z]*i|^(python3?|node|ruby)\b.*\s-(c|e)\b")
RECORDS = ["docs/release/*", ".claude/RESUME-*"]
RM_OK = ["/tmp/", "/private/tmp/", "/var/folders/"]
WRAPPERS = {"command", "builtin", "exec", "nohup", "time", "nice", "sudo", "caffeinate"}
RUNNERS = [["npx"], ["bunx"], ["pnpm", "exec"], ["pnpm", "dlx"], ["npm", "exec"], ["yarn", "dlx"], ["mise", "exec", "--"]]
MANIFESTS = {"package.json", "go.mod", "Cargo.toml"}


def segments(cmd, depth=0):
    """Split a shell command into simple-command strings, descending into sh -c, $( ) and backticks."""
    out = []
    for inner in re.findall(r"\$\(([^()]*)\)|`([^`]*)`", cmd):
        for part in inner:
            if part and depth < 4:
                out += segments(part, depth + 1)
    for raw in re.split(r"\|\||&&|;|\||\n|&(?!>)", cmd):
        raw = raw.strip()
        if not raw:
            continue
        try:
            toks = shlex.split(raw, comments=True)
        except ValueError:
            toks = raw.split()
        toks = normalise(toks)
        if not toks:
            continue
        if toks[0] in ("sh", "bash", "zsh", "dash") and depth < 4:
            for i, t in enumerate(toks):
                if re.fullmatch(r"-[a-z]*c[a-z]*", t) and i + 1 < len(toks):
                    out += segments(toks[i + 1], depth + 1)
                    break
        if toks[0] == "eval" and depth < 4:
            out += segments(" ".join(toks[1:]), depth + 1)
        out.append((" ".join(toks), raw))
    return out


def normalise(toks):
    env = []
    while toks:
        t = toks[0]
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", t):
            env.append(t.lower())
            toks = toks[1:]
        elif t == "env":
            toks = toks[1:]
            while toks and toks[0].startswith("-"):
                toks = toks[1:]
        elif t in WRAPPERS or os.path.basename(t) in WRAPPERS:
            toks = toks[1:]
            while toks and toks[0].startswith("-"):
                toks = toks[1:]
        else:
            break
    for r in RUNNERS:
        if toks[:len(r)] == r:
            toks = toks[len(r):]
            while toks and toks[0].startswith("-") and toks[0] not in ("--",):
                toks = toks[1:]
            break
    if toks:
        toks = [os.path.basename(toks[0])] + toks[1:]
    if toks and toks[0] == "git":
        rest, g = toks[1:], ["git"]
        while rest and rest[0].startswith("-"):
            o = rest.pop(0)
            if o in ("-C", "-c", "--git-dir", "--work-tree", "--namespace") and rest:
                v = rest.pop(0)
                if o == "-c" and v.lower().startswith("core.hookspath"):
                    g += ["config", "core.hookspath", v]
            elif o.startswith("-c") and "hookspath" in o.lower():
                g += ["config", "core.hookspath"]
        toks = g + rest
    if toks and toks[0] == "make":
        rest, m = toks[1:], ["make"]
        while rest:
            o = rest.pop(0)
            if o in ("-C", "-f", "--directory", "--file", "-j") and rest:
                rest.pop(0)
            elif not o.startswith("-") or re.fullmatch(r"[A-Za-z_]+=.*", o):
                m.append(o.lower() if "=" in o else o)
        toks = m
    return env + toks if env else toks


def rel(path, root):
    p = os.path.abspath(os.path.expanduser(path))
    r = os.path.abspath(root)
    return os.path.relpath(p, r) if p.startswith(r + os.sep) or p == r else None


def path_rules(path, root, extra):
    hits = []
    full = os.path.abspath(os.path.expanduser(path))
    for h in HOME_DENY:
        if full == os.path.abspath(os.path.expanduser(h)):
            hits.append(("Z7", DENY, "the guardrails' own settings"))
    r = rel(path, root)
    if r is not None:
        for zone, dec, glob, why in PATHS + [(e["zone"], e["decision"], e["glob"], e["reason"]) for e in extra]:
            if fnmatch.fnmatch(r, glob) or fnmatch.fnmatch(r, "*/" + glob):
                hits.append((zone, dec, why))
                break
    return hits


def manifest_adds(path, old, new):
    """True when an edit adds a dependency name that was not there before."""
    name = os.path.basename(path)
    if name not in MANIFESTS:
        return False

    def deps(text):
        if name == "package.json":
            try:
                d = json.loads(text)
                return {k for s in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies") for k in (d.get(s) or {})}
            except (ValueError, AttributeError):
                return set(re.findall(r'"(@?[\w./-]+)"\s*:\s*"[\^~>=<*\d]', text))
        if name == "go.mod":
            return set(re.findall(r"^\s*(?:require\s+)?([\w.-]+\.[\w./-]+)\s+v\d", text, re.M))
        found, sect = set(), ""
        for line in text.splitlines():
            m = re.match(r"^\s*\[([^\]]+)\]", line)
            if m:
                sect = m.group(1)
            elif "dependencies" in sect:
                m = re.match(r"^\s*([\w-]+)\s*=", line)
                if m:
                    found.add(m.group(1))
        return found
    return bool(deps(new) - deps(old))


def decide(data, root, extra):
    tool, ti, cwd = data.get("tool_name", ""), data.get("tool_input") or {}, data.get("cwd") or root
    hits = []
    if tool == "Bash":
        cmd = ti.get("command", "")
        rules = BASH + [(e["zone"], e["decision"], e["pattern"], e["reason"]) for e in extra.get("bash", [])]
        for canon, raw in segments(cmd):
            low = canon.lower()
            stripped = re.sub(r"^(\S+=\S*\s+)+", "", canon)
            for zone, dec, rx, why in rules:
                if re.search(rx, stripped.lower(), re.I) or re.search(rx, low, re.I):
                    hits.append((zone, dec, why))
            if GUARD_TOKENS.search(raw):
                words = [w for w in stripped.split() if not w.startswith("-")]
                if re.match(r"^(cp|mv|install|rsync|ln)\b", stripped):
                    writes = bool(words[1:]) and bool(GUARD_TOKENS.search(" " + words[-1]))  # only the destination counts
                else:
                    writes = bool(WRITERS.search(stripped))
                if writes or re.search(r">>?\s*\S*(\.claude/(settings|hooks/|no-ai-zones)|githooks/|tools/git-hooks/|tools/no-ai-zones/)", raw):
                    hits.append(("Z7", DENY, "writing to the guardrails' own files"))
            if re.match(r"^(rm|git rm)\b", stripped):
                args = stripped.split()[1:] if stripped.startswith("rm") else stripped.split()[2:]
                recursive = any(re.fullmatch(r"-[a-zA-Z]*[rR][a-zA-Z]*|--recursive", a) for a in args)
                for a in (x for x in args if not x.startswith("-")):
                    full = os.path.abspath(os.path.join(cwd, os.path.expanduser(a)))
                    r = rel(full, root)
                    if r is not None and any(fnmatch.fnmatch(r, g) for g in RECORDS):
                        hits.append(("Z6", DENY, "deleting dated records"))
                    elif recursive and stripped.startswith("rm") and not (
                            r.startswith(".claude/worktrees/") if r is not None else any(full.startswith(p) for p in RM_OK)):
                        hits.append(("Z6", DENY, "recursive delete outside the scratchpad, /tmp and .claude/worktrees"))
    elif tool in ("Edit", "Write", "MultiEdit", "NotebookEdit"):
        path = ti.get("file_path") or ti.get("notebook_path") or ""
        if path:
            hits += path_rules(path, root, extra.get("paths", []))
            if tool == "Write":
                old = open(path).read() if os.path.exists(path) else ""
                adds = manifest_adds(path, old, ti.get("content", ""))
            elif tool == "Edit":
                adds = manifest_adds(path, ti.get("old_string", ""), ti.get("new_string", ""))
            elif tool == "MultiEdit":
                adds = any(manifest_adds(path, e.get("old_string", ""), e.get("new_string", "")) for e in ti.get("edits", []))
            else:
                adds = False
            if adds:
                hits.append(("Z4", ASK, "new dependency"))
    return hits


def answer(hits, data, root):
    if not hits:
        return None
    dec = DENY if any(h[1] == DENY for h in hits) else ASK
    seen, why = set(), []
    for zone, d, w in hits:
        if (zone, w) not in seen:
            seen.add((zone, w))
            why.append(f"{zone} {w}")
    tail = (" Denied: hand the owner the exact command to run with `!`." if dec == DENY
            else " Needs the owner's approval in this prompt.")
    try:
        ti = data.get("tool_input") or {}
        head = (ti.get("command") or ti.get("file_path") or ti.get("notebook_path") or "")[:160].replace("\n", " ")
        with open(os.path.expanduser(os.environ.get("NO_AI_ZONES_LOG", "~/.claude/no-ai-zones.log")), "a") as f:
            f.write(f"{time.strftime('%Y-%m-%dT%H:%M:%S%z')}\t{os.path.basename(root)}\t{dec}\t{'; '.join(why)}\t{head}\n")
    except OSError:
        pass
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": dec,
                                   "permissionDecisionReason": "No-AI zone: " + "; ".join(why) + "." + tail}}


def main():
    root = os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
    try:
        data = json.load(sys.stdin)
        extra = {}
        zf = os.path.join(root, ".claude", "no-ai-zones.json")
        if os.path.exists(zf):
            extra = json.load(open(zf))
        out = answer(decide(data, root, extra), data, root)
    except Exception as e:  # a broken guard asks; it never waves an action through
        out = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": ASK,
                                      "permissionDecisionReason": f"No-AI zone hook failed ({type(e).__name__}); asking the owner."}}
    if out:
        print(json.dumps(out))


if __name__ == "__main__":
    main()
