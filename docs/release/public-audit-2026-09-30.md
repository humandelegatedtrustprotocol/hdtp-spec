# pact-protocol: can it go public? — sanity, leak and posture audit

Read-only audit, 2026-09-30. Nothing was edited, committed, pushed, installed or deployed; the
only network calls were `git fetch` and `gh` reads. `R` below is
`/Users/sumitagrawal/CODE/sumit/n8n/projects/pact-gateway/pact-protocol` (GitHub
`tech-sumit/pact-protocol`, private). Audited state: `origin/main` = `5662841` (SPEC 2.2.4), every
remote and local ref, both tags, the 11 locally unreachable commits, and the three in-flight
branches. Every count below was measured with the command named beside it.

---

## (a) Verdict

**Publishable after fixes, keeping history.** No secret, credential, internal hostname, private IP,
customer datum or phone number exists in any reachable object, any tag, any PR ref, or any object
GitHub still holds. The 41 gitleaks hits are all documented test vectors whose keys derive from
fixed labels. Nothing in history is large (largest blob 155,748 B). A fresh history is NOT needed
for safety; it would only be wanted if the owner objects to three personal e-mail addresses and
89 `Co-Authored-By: Claude …` lines in commit metadata, and by standing rule 7 that is the owner's
explicit order or nothing.

What blocks the flip today is posture, not leakage: **no LICENSE at all** (the spec text, the
code, and two vendored OFL fonts shipped without their licence), and a **README and CLAUDE.md that
are false about what the repository is** (README still says "v1.2.0 released … v2.0.0-draft in
progress" and describes SPEC.md as "PACT 1.0"; CLAUDE.md carries four stale claims, owner quotes,
and private paths).

---

## (b) Findings, ranked

Legend: **PR** = already addressed by an in-flight branch (named). Hashes are in `R` unless a
sibling is named.

### BLOCKER

**B1. No licence anywhere; fonts redistributed without their OFL notice.**
- Evidence: `git ls-tree -r --name-only origin/main` lists 36 files, none named LICENSE/NOTICE/OFL;
  GitHub `license: null`, community profile `health_percentage: 28`. `README.md:39` says "CC BY 4.0
  (recommended; not yet stamped)". `site/brand/*.woff2` (Inter ×2, JetBrains Mono ×3, 4–48 KB
  each, added at `c7936561`/`f2e8bb0^`) are SIL OFL 1.1 fonts; the OFL requires the copyright
  notice and licence text to accompany every copy, and a subset is a "Modified Version".
  `archive/hardened-draft-spec.md:9` already declares "Specification text … CC BY 4.0. Example
  code, schemas, and test vectors are additionally licensed under MIT" — a precedent that
  contradicts the sibling repos' Apache-2.0 (`pact-identity/LICENSE`, `pact-gateway/LICENSE`, and
  the umbrella `LICENSE` are Apache License 2.0; pact-cloud, the kit and the three sites have none).
- Fix (owner decided CC BY 4.0 for text on 2026-09-29): add `LICENSE` (Apache-2.0 for code) and
  `LICENSE-docs` or a `LICENSE` section (the CC BY 4.0 legal code, or the SPDX short form) with a
  file-class table in README; add `site/brand/OFL-inter.txt` and `site/brand/OFL-jetbrains-mono.txt`
  (the kit already carries `pact-web-kit/kit/fonts/OFL-bricolage-grotesque.txt` as the pattern);
  reconcile `archive/hardened-draft-spec.md:9` ("MIT") with the chosen code licence or leave it as
  the dated record it is and say so. File classes and the licence that covers each:

  | Class | Files | Licence |
  |---|---|---|
  | Normative spec text | `SPEC.md` | CC BY 4.0 |
  | Informative text | `README.md`, `docs/landscape-and-roadmap.md`, `archive/*.md`, `explainer/pact-explainer.html` (prose + inline SVG) | CC BY 4.0 |
  | Code | `vectors/**/*.mjs`, `vectors/check-no-1x.mjs`, `site/*.mjs`, `site/whitepaper.css`, `archive/test-vectors/gen_vectors.py`, `Makefile`, `.github/workflows/whitepaper.yml`, `package.json` | Apache-2.0 (sibling precedent) |
  | Data | `vectors/pact-2.0-vectors.json`, `vectors/pact1x-markers.txt`, `archive/test-vectors/vectors.json`, `dist/pact-whitepaper.meta.json` (untracked) | CC0 or the code licence; say which |
  | Brand | `site/brand/mark.svg` | owner's mark: state "all rights reserved" or CC BY with the name protected |
  | Fonts | `site/brand/inter-*.woff2`, `site/brand/jbmono-*.woff2` | SIL OFL 1.1 (upstream), licence text must ship beside them; check the Reserved Font Name clause of each upstream OFL header before shipping a subset under the original family name |

  Third-party deps (declared, `node -e` over `node_modules/*/package.json`, no network):
  markdown-it 14.1.0 MIT · markdown-it-anchor 9.2.0 Unlicense · mermaid 11.17.2 MIT · pagedjs 0.4.3
  MIT · puppeteer 25.9.0 Apache-2.0 · wrangler 4.127.0 MIT OR Apache-2.0. Transitive (198 packages):
  one LGPL-3.0-or-later (`@img/sharp-libvips-*`, via sharp, via wrangler) and one with no licence
  field (`khroma`, a mermaid dependency). All are build-time only; nothing from them is
  redistributed in the repo, so no notice obligation arises. Mermaid output (the SVGs the build
  makes) is the owner's. SPEC.md cites RFCs by number only (RFC 3339 ×8, 5280 ×5, 9180 ×3, 8032,
  6350, 8785, 8410, 7748, 5869, 4648, 4180, 3986: `grep -oE 'RFC ?[0-9]{4}'`); no verbatim RFC
  excerpt was found (`grep -niE 'copyright|\(c\) 20|licen[cs]e'` over every tracked text file hits
  only README:39 and the archive line above).

**B2. README is false about the repository (standing rule 3).**
- `README.md:5`: "Status: v1.2.0 released 2026-08-30 and implemented by the reference gateway;
  v2.0.0-draft in progress (2026-09-13)". Truth: `SPEC.md:3` is **Version 2.2.4 · 2026-09-28**,
  released (no `-draft`), and the ports pin `SPEC_VERSION = "2.2.4"`
  (`pact-identity/crates/pact-identity/src/api.rs:26`, `go/api.go:20`).
- `README.md:11`: "`SPEC.md` — The protocol. PACT 1.0 — identity & mTLS, … gateway mode …". PACT 1.x
  was removed on 2026-09-17 (`95af027`); there is no gateway mode (§9 is Hosting).
- `README.md:12`: "published privately at claude.ai/artifact/7txRRL4VBVXyMhsNUcuLJX" — a private
  artifact link an outsider cannot open.
- `README.md:18`: points the reader at "`pact-identity/` in the umbrella repository" — private.
- `README.md:39`: the licence line ("not yet stamped") and the pact.io collision note (see S8).
- Fix: rewrite the status line and the map row from the current SPEC header; drop the private
  links or label them "not public"; replace the licence line with the real one. **PR: none.**
  (`docs/spec-site-plan` item 2 promises CLAUDE.md fixes only, not README.)

### MUST-FIX

**M1. CLAUDE.md is an internal document with four stale claims, owner quotes and private paths.**
- Stale: `CLAUDE.md:20` "CI's Publish step does the same on every push to main … repo secrets …
  are live and verified, so pushing main IS publishing" — contradicted by `abe11b1` (2026-09-27),
  the workflow (`.github/workflows/whitepaper.yml:13-15`, no credential), the Makefile header, and
  GitHub (`gh api …/actions/secrets` → `total_count: 0`).
  `CLAUDE.md:37` "the version line stays `-draft` until then" — the line is released 2.2.4.
  `CLAUDE.md:5` says `docs/landscape-and-roadmap.md` "predates the pivot … never mentions vCard,
  `X-PACT-*`, or any current tool" — false since `44a4b0a`/`ff873f6`/`9bb8c26` (2026-09-22) rewrote
  it as "Companion document to PACT 2.1.3" (`docs/landscape-and-roadmap.md:3`; vCard at :43,
  `X-PACT-SEAL` at :370, `X-PACT-*` at :717). `CLAUDE.md:30` "95 scenarios, 91 blocked and 4
  residual (2026-09-15)" — measured on a clean export of origin/main: **132 scenarios: 128 blocked,
  4 residual by decision, 0 reproduce** (`node vectors/intrude.mjs`).
- Internal: `CLAUDE.md:7` private claude.ai artifact URLs; `:11` "the owner explicitly rejected",
  "the design of record is `pact-cloud/docs/superpowers/specs/2026-09-12-portable-identity-design.md`
  and the owner's overview page (artifact `b206b67a`)"; `:20` "sourced from conductor's .env"
  (conductor = BatonDeck's private repo); `:9` "do not re-litigate without the owner".
- Fix: either move CLAUDE.md's decision history into the umbrella (private) and leave a short,
  public-safe agent guide (what the files are, the gates, the vectors workflow, the north-star
  bullets without the quotes), or keep it and correct every claim. **PR: `docs/spec-site-plan`
  (`c8b9e2d`, plan item 2) commits to fixing the CI and `-draft` claims only; the landscape and
  scenario-count claims and the internal references are unaddressed.**

**M2. Orphaned GitHub Actions variable `MIXPANEL_TOKEN`.**
- `gh api …/actions/variables` → `MIXPANEL_TOKEN = 0d793a0f66d8c2a9a1d8e75feb524e72`. It fed the
  retired Pages workflow (`.github/workflows/pages.yml` at `f2e8bb0^`, `vars.MIXPANEL_TOKEN`,
  deleted in `f2e8bb0`, 2026-08-28). A Mixpanel project token is a client-side identifier, not a
  secret (the old workflow said so), but no workflow reads it now and any workflow run in a public
  repo can. `GA_MEASUREMENT_ID` was never set (only the one variable exists).
- Fix (owner, `gh` write): `gh variable delete MIXPANEL_TOKEN -R tech-sumit/pact-protocol`.
  Secrets: **0** (rule 4 holds; `b48a10c` and `abe11b1` record that CI once held
  `CLOUDFLARE_API_TOKEN`/`CLOUDFLARE_ACCOUNT_ID`, names only, never values).

**M3. The registration-gated whitepaper PDF becomes a free download via Actions artifacts.**
- `.github/workflows/whitepaper.yml:35-39` uploads `dist/pact-whitepaper.pdf` as artifact
  `pact-whitepaper` on every push to main; `gh api …/actions/artifacts` → **29 retained**, the
  newest (2.2.4, 992,712 B, 2026-09-28) unexpired. On a public repo anyone logged in to GitHub can
  download workflow artifacts. Plan decision D3 (`docs/release/spec-site-2026-09-30.md`, "The
  whitepaper PDF stays registration-gated") is then a lead-capture form beside a free copy, and
  `npm run build` reproduces the PDF from SPEC.md anyway.
- Fix: decide. Either accept (and say so in the plan), or drop the `upload-artifact` step and keep
  the job as the gate (`build` remains the required status check). Delete the 29 retained
  artifacts if the gate is to mean anything on day one.

**M4. No SECURITY.md, CONTRIBUTING.md, CODE_OF_CONDUCT.md, issue/PR templates.**
- Community profile: `code_of_conduct: null, contributing: null, issue_template: null,
  pull_request_template: null, license: null`. `.github/` holds only the workflow.
- Fix: SECURITY.md with `security@pact-protocol.com` (the umbrella's `SECURITY.md` has the text;
  trim its "Current hardening status" table, which is about the node); reuse the umbrella
  `CODE_OF_CONDUCT.md`; a CONTRIBUTING modelled on `pact-gateway/CONTRIBUTING.md` (which already
  links `https://github.com/tech-sumit/pact-protocol` publicly and says the node is "structured to
  open"): spec edits go through `npm run vectors:check` + `npm run build`, wire changes need the
  vectors regenerated, MUST sentences are hashed in pact-identity's `musts.json`.

**M5. The `pre-rewrite-backup` tag, and the pre-rewrite objects GitHub still holds.**
- Local tag `pre-rewrite-backup` → `9ef07f3` (tree identical to `58379dc`); its parent `de76296`
  "Initial commit" is authored **`AI Assistant <ai@example.com>`** (the only commit with that
  identity; tree identical to `379fbf4`). The tag is **not on the remote** (`git ls-remote --tags`
  → only `v1.2.0`). BUT both commits **exist on GitHub as unreachable objects**: `gh api
  repos/tech-sumit/pact-protocol/commits/de76296f…` and `…/9ef07f38…` return 200 (the stash-WIP
  commits `58bb916e`, `9993b39e`, `b23e93ed` return 422 — never pushed). Once public, anyone with
  the SHA can open `github.com/tech-sumit/pact-protocol/commit/de76296f…`; nothing links to it.
  Content risk: none (same trees as the rewritten commits; gitleaks over them: 0 findings).
  Metadata exposure: the `ai@example.com` identity and `sumit@shailka.com` on `9ef07f3`.
- Fix: `git -C R tag -d pre-rewrite-backup` (owner; local only, so no push is involved and rule 7 is
  untouched) so a `git push --tags` can never carry it. For the server-side objects, the only
  remedy is a GitHub Support request to run GC / purge unreachable objects — not a force-push, but
  the owner's call. Also keep in mind `refs/pull/3/head` (`43c77ea4`) and `30d52b5e` are served by
  GitHub although locally unreachable (PR #3 was squash-merged): scanned, clean.

**M6. The main checkout is dirty with someone else's vectors work.**
- `git status` in `R`: 7 modified (`vectors/check.mjs` +225, `gen.mjs`, `lib/{card,der,envelope,
  keys,x509}.mjs`) and 2 untracked (`vectors/appendix-b-reader.json`, `vectors/lib/appendix.mjs`).
  It is an older, partial copy of PR #10 (`feat/port-parity`): `git diff --stat
  origin/feat/port-parity -- vectors/` differs in `check.mjs`, `intrude.mjs`, `lib/appendix.mjs`,
  `lib/x509.mjs`. Standing rule (memory: one worktree per agent; main checkout only for
  ship-production) is being broken here.
- Fix: whoever owns it commits it on `feat/port-parity` or discards it; a release commit (the plan's
  2.2.5 step) must not be made from this tree. The 1.x guard still passes on it
  (`node vectors/check-no-1x.mjs` → "ok (24 files, 16 names, 2 allowed with a reason)").

**M7. The required status check `build` never runs on pull requests.**
- Branch protection (`gh api …/branches/main/protection`): required check `build` (app 15368 =
  GitHub Actions), `strict: false`, `enforce_admins: false`, `required_linear_history: true`,
  `allow_force_pushes: false`, `allow_deletions: false`, `required_conversation_resolution: true`.
  The workflow triggers on `push: branches: [main]` and `workflow_dispatch` only
  (`whitepaper.yml:3-6`), so no PR ever carries a `build` status; PRs #2–#9 merged because the
  owner is admin and `enforce_admins` is off. An outside contributor's PR can never satisfy it.
- Fix: add `pull_request:` to the triggers (safe: `permissions: contents: read`, no secrets, and
  fork PRs get a read-only token). On the flip, set Actions → "Require approval for all outside
  collaborators" (the API refused to read that setting while private: "Fork PR approval is not
  allowed for private repositories"). Leave the protection itself as it is (rule 7).

### SHOULD-FIX

**S1. `.gitignore` lacks `.claude/`.** `git check-ignore .claude` → not ignored; it is hidden only
by the local `…/.git/modules/pact-protocol/info/exclude:11` (`**/.claude/worktrees/`). A
contributor's clone has no such exclude; `R/.claude/worktrees/` holds six worktrees today.
Fix: add `.claude/` to `.gitignore:1-7`.

**S2. `archive/` reads as live and names the owner.**
- `archive/hardened-draft-spec.md:7`: "Status of this document: Proposed Specification, first
  public release. This document has completed an internal multi-lens review" — a rejected draft
  presenting itself as a release. `:1185` and `archive/design-study-v0.1.md:604-610` use "Sumit" as
  the worked-example persona; `design-study-v0.1.md:492` uses the owner's real domain,
  `sumit@sumit.dev`, as the self-hoster example (the only non-`.example` address in the tree).
  `design-study-v0.1.md:52,237,633` is business framing ("We run the MCP/agent servers for
  customers", "Phase 1 — Hosted MVP").
- Fix: a two-line banner at the top of each archive file ("historical; superseded by SPEC.md 2.x;
  not a PACT version"), swap `sumit@sumit.dev` for an `.example` domain, and decide whether the
  design study (a business document) is public at all. If `archive/` is excluded, update
  `vectors/check-no-1x.mjs:6,33` (its exemption regex) and README rows 14–16. The research
  (§2) confirms these are not PACT versions and must stay off any timeline.

**S3. `docs/landscape-and-roadmap.md` cites private code and is one revision behind.**
`:464` and `:848` cite `internal/messaging/service.go:122` (the node, private); `:635` "a plan item
under `pact-gateway/docs/release/`"; `:3` "Companion document to PACT 2.1.3" while SPEC is 2.2.4.
Fix: cite by behaviour not by private path, or say the node is not yet public; bump the companion
line when the timeless-text edit lands.

**S4. The explainer.** `explainer/pact-explainer.html:2` loads Google Fonts
(`fonts.googleapis.com/css2?family=Bricolage+Grotesque…`) — the only external fetch in the repo
(a privacy note for a public artifact; no OFL obligation since nothing is vendored). The file is an
Artifact body with no doctype (`CLAUDE.md:7`), yet `README.md:12` says "open in any browser"
(quirks mode). Fix: say what it is, or wrap it; drop the private artifact link.

**S5. Repository metadata.** `homepage` is `https://pact-protocol.com/whitepaper/`, which the site
301s to `/` (research §3). `topics: []`. `has_wiki: true`, `has_projects: true` (unused; a public
wiki is an editable surface). Seven merged branches remain on the remote (`spec/2.2.0`–`2.2.3`,
`spec/fair-rate-limits`, `chore/local-publish`, `fix/review-p21-p24`; `delete_branch_on_merge:
false`). Fix: homepage → `https://pact-protocol.com/`, topics (mcp, mtls, x509, protocol,
specification, agents), wiki/projects off, prune merged branches (deleting a merged ref is not a
rewrite; owner's call), enable `delete_branch_on_merge`.

**S6. The in-flight plan document is internal.** `docs/spec-site-plan` (`82dfa08`, `131ea83`,
`c8b9e2d`; no PR opened on GitHub as of 08:13) adds `docs/release/spec-site-2026-09-30.md`: owner
quotes with timestamps ("owner, 2026-09-30 03:20", "like google have for A2A"), the private bucket,
`ship-staging` / `ship-production`, the pact-identity release lockstep and Wasm re-pin. The umbrella
CLAUDE.md says plans of record live under `pact-gateway/docs/release/`. If merged before the flip it
is public. Fix: keep it in the node's `docs/release/` (private) or strip the operations steps and
quotes. Note `82dfa08` is authored `sumit@shailka.com` (a third personal address; unmerged; cannot
be amended once pushed — rule 7).

**S7. Author identities (disclosure, not a leak).** Across all refs (`git log --all
--format='%an <%ae>'`): `mr.sumitagrawal.17@gmail.com` (A 93 / C 83), `sumit@batondeck.com` (8 / 8,
2026-09-14/15), `sumit@shailka.com` (2 / 2: `9ef07f3` tag-only, `82dfa08` on the plan branch),
`64501866+tech-sumit@users.noreply.github.com` (2 / 10), `GitHub <noreply@github.com>` (C 2),
`AI Assistant <ai@example.com>` (1 / 1, `de76296`, see M5). A public repo shows these in every
`.patch` view and the API. Changing them is a rewrite (owner's explicit order only; see (c) option
C). Fix without a rewrite: make sure all three addresses are verified on the `tech-sumit` account
so commits attribute correctly; set `user.email` to the noreply address for future commits if
wanted.

**S8. The name.** `README.md:39` already flags the collision with pact.io (Pact contract testing,
Pact Foundation) — the same developer audience. Fix: a non-affiliation sentence in README and the
site before the first public link, or a decision on the name; `package.json` is `private: true`
under the name `pact-protocol-whitepaper`, so npm is not at risk.

**S9. Comments that point at repositories an outsider cannot open.** `vectors/check-no-1x.mjs:11-13`
(the node and pact-cloud carry the sister copies), `vectors/intrude.mjs:140` ("measured in
pact-identity's wasm build on 2026-09-20, `RuntimeError: unreachable`"), and PR #10's new comments
(`pact-identity CONTRACT §0`, lines 112, 168, 211, 385, 410 of its diff). Harmless prose; say
"(not yet public)" or link when those repos open.

### NICE

**N1.** 89 `Co-Authored-By: Claude …` trailers (5 model names) across the history — the owner's
call whether that is the public face; removable only by rewrite.
**N2.** `package.json` has no `engines` field; README says Node 22 (CI uses 22; the vectors gate
also ran clean on 24.13.0 here).
**N3.** `vectors/check-no-1x.mjs:6` still calls the landscape doc a "rejected pre-pivot draft"
(stale since 2026-09-22, same as M1's third claim).
**N4.** The `v1.2.0` release (`gh release view`) carries `pact-whitepaper.pdf` (1,379,331 B, "29
pages", PACT 1 content) — it becomes a public download; consistent with plan decision D2.
**N5.** `SPEC.md:3` is a 2,827-byte header line narrating every 2.1–2.2.4 change, plus 9 in-body
version references (`grep -oE '\b(in|from|since|added in|as of) (1|2)\.[0-9]…'`; the research
counts 20 with a wider pattern). **PR: `spec/timeless-text` is meant to fix this (plan D4) but the
branch is still at `5662841` = main with no commits;** `feat/spec-html-generator` does not exist on
any local or remote ref yet.
**N6.** No 2.x tag exists although CLAUDE.md's policy says a release "tags `vX.Y.Z`" (only
`v1.2.0`); the plan's step 5a tags `v2.2.5`.
**N7.** `Makefile:11` `ENV_FILE ?= $(abspath $(ROOT)/../.env)` assumes the umbrella layout, and
`package.json` `publish` names the private bucket `pact-cloud-private`. Values never appear; fine to
publish, but a README "Maintainers" paragraph should say `make publish` is the owner's and needs
`CLOUDFLARE_API_TOKEN`/`CLOUDFLARE_ACCOUNT_ID` in `ENV_FILE`.

### What was checked and found clean

- **Secrets, all history.** gitleaks 8.30.1 (`gitleaks git --log-opts="--all"`, 106 commits,
  2.01 MB, report `scratchpad/gitleaks-all-refs.json`): 41 findings, every one a test vector —
  `generic-api-key` on PKCS#8 hex (`302e020100300506032b65…` = Ed25519/X25519, `3041…2a8648ce3d…`
  = P-256) in `SPEC.md` Appendix B and `vectors/pact-2.0-vectors.json` (commits `77fd7ed`,
  `8cee1ff`, `f4f8fce`), the example invite id `inv_8Qq1xZk3` (`SPEC.md:625`), and a JWS plus two
  base64 values in `archive/test-vectors/vectors.json` and `archive/hardened-draft-spec.md`
  (`379fbf4`, `de76296`). A second gitleaks pass over the 11 unreachable commits
  (`--log-opts="… --not main"`): 0. Greps over `git log --all -p` added lines: `AKIA`, `ghp_`,
  `github_pat_`, `gho_`, `sk_live|sk_test`, `sk-…`, `eyJ…` JWTs, `-----BEGIN … PRIVATE` (0 in all
  history), `xox[baprs]-`, `whsec_`, `CLOUDFLARE_API_TOKEN\s*[=:]\s*value`, 32-hex ids (only
  `00112233…`, `a0a0…`, `b0b0…` placeholders and PKCS#8 prefixes), `G-XXXXXXXX`, Mixpanel init with
  a literal token (none: the retired site read `process.env.MIXPANEL_TOKEN`, `site/build.mjs:14-16`
  at `f2e8bb0^`). Limits: gitleaks default ruleset only (a bare 40-char Cloudflare token with no
  key name would need a custom rule; the assignment grep covers the named form); `refs/pull/*/merge`
  were not fetched (GitHub-made merges of heads that were scanned); binaries inspected by type and
  size only; trufflehog not installed and not installed.
- **Are the vector keys throwaways?** Yes, by construction: `vectors/lib/keys.mjs:31` `seed =
  (label) => sha256('pact-2.0-vectors/' + label)`; `gen.mjs:15-21` derives every root and host key
  from labels (`root/alina`, `host/alina/2026`, …); `gen.mjs:113-119` explains the derivation
  vector's `seed`/`prf` are a throwaway identity in no certificate. Published secret material at
  origin/main: `leaf_keys_pkcs8_hex` (three leaf keys, needed to reproduce the envelopes) and three
  `seed`/`prf` derivation values; root private keys are absent (`certificates.*` carry only
  `der_hex`+`note`). The archive's Python generator uses fixed seeds `0x01*32`…`"04"*32`
  (`gen_vectors.py:22-24,82`). `node vectors/check.mjs` on a clean export of origin/main:
  **108/108 checks passed**.
- **Hostnames, IPs, paths, private module paths.** Zero hits in all history for `-stg.`,
  `.pact.test`, `10.211.55.`, `192.168.`, `/Users/`, `/home/`, `github.com/pact-cloud`. Every URL in
  SPEC.md is `*.example` (`grep -oE 'https?://…'`). No phone numbers. E-mail addresses in content
  are `.example` except `sumit@sumit.dev` (S2) and `alina@example.com`.
- **Large or binary blobs.** Top 25 blobs (`git rev-list --objects --all | git cat-file
  --batch-check`) are all SPEC.md revisions, 124,768–155,748 B; the only binaries ever tracked are
  the five woff2 fonts (3,960–48,256 B). Nothing > 1 MB. Never tracked: `dist/`, `node_modules/`,
  `*.pdf`, `.env`, `*.pem/.key/.p12`, wallet or vault files (`git log --all --name-only`).
  `git count-objects -vH`: 597 loose objects, 5.50 MiB; GitHub `size: 713` KB.
- **Private-sibling coupling in code.** None: no `go.work`/`replace` (Node only); `package.json`
  has no private dependency; every script reads only `../SPEC.md` and in-repo paths
  (`check.mjs:9`, `gen.mjs:151`, `intrude.mjs:249`, `build-whitepaper.mjs:12-19,51,136,356`).
  `check-no-1x.mjs:68` needs a git checkout (`git ls-files`), which an outside clone is. An outside
  clone can run `npm ci && npm run vectors:check && npm run build` (build proven by CI run
  36402441867 on `5662841`, success).
- **Hooks.** No `githooks/` directory and no `core.hooksPath` in this repo (unlike the siblings);
  nothing to publish. The workflow pins actions by SHA and holds `permissions: contents: read`.
- **Commit messages.** No values; `b48a10c` and `abe11b1` narrate the CI-secret episode by name.

---

## (c) Publication procedure options

Standing rule 7: never a force-push, never an amend or rebase of a pushed commit; a history
rewrite happens only on the owner's explicit order. Standing rule 6: a written, approved plan
before restructuring.

**Option 1 — Flip visibility, history kept (recommended).**
Settings → Danger Zone → Change visibility → Public, after B1, B2, M1–M7 land as ordinary
commits on `main` through the gates. What becomes public: all 96 reachable commits, `v1.2.0` + its
PDF asset, the 10 PRs and their `refs/pull/*/head` objects (incl. PR #3's squashed originals
`43c77ea4`/`30d52b5e`), the 11 remote branches, Actions run history and the 29 retained artifacts
(M3), and the two pre-rewrite objects by SHA (M5). Cost: the fix list (about a day of edits, all
reviewable), one `gh variable delete`, one settings pass. Nothing is rewritten; rule 7 is
untouched. Residual exposure: personal e-mails and Claude trailers in metadata (S7, N1);
`de76296`/`9ef07f3` by SHA until GitHub Support purges unreachable objects on request.

**Option 2 — Fresh public repository from an exported tree.**
`git archive` of the release commit (e.g. the plan's `v2.2.5`) into a new repository (the
private one stays as the archive). Gains: one chosen author identity, no trailers, no pre-rewrite
objects, no stale branches, no old artifacts. Loses: the 106-commit spec history that the site
plan depends on (PACT 1 is rendered from `git show d130444:SPEC.md`, research §2/§7 — in a fresh
repo that commit does not exist, so the generator must read the private archive or the 1.2.0 text
must be committed under `archive/`, where `check-no-1x` exempts it but the 29 marker lines then
live in the public tree), the `v1.2.0` tag/release, PR numbers, and the umbrella gitlink (must be
repointed: `.gitmodules` URL, and every sibling doc that names the repo). Not a rewrite, but a
restructuring: rule 6 applies. Cost: half a day plus the site plan's pin logic reworked.

**Option 3 — Filtered mirror.**
`git filter-repo` (installed at `/opt/homebrew/bin/git-filter-repo`) on a fresh clone: `--mailmap`
to one identity, `--message-callback` to strip trailers, `--refs main v1.2.0` to drop everything
else; push the result to a NEW public repository. The private repo is never force-pushed, but every
SHA changes (the site plan's `spec.lock`, the research table, `d130444`, `v1.2.0`'s target all move)
and this is exactly the class of operation the owner said happens only on explicit order. Cost:
two hours plus re-pinning every SHA reference; the umbrella gitlink repoints as in option 2.
Choose it only if S7/N1 are unacceptable to the owner.

---

## (d) Re-check on the day of publishing

1. `git -C R status` clean (M6 resolved); `git -C R fetch --prune`; `main` = `origin/main`; the
   in-flight branches merged or consciously left private (S6).
2. `gitleaks git --no-banner --log-opts="--all" R` — only the vector false positives listed above;
   diff the finding list against `scratchpad/gitleaks-all-refs.json` (41).
3. `git -C R tag -l` shows no `pre-rewrite-backup`; `git ls-remote --tags origin` shows `v1.2.0`
   (and the new 2.x tag if released). Never `git push --tags` blindly.
4. `gh secret list -R tech-sumit/pact-protocol` → empty; `gh variable list` → empty (M2).
5. `LICENSE`, the docs licence, `site/brand/OFL-*.txt`, `SECURITY.md`, `CONTRIBUTING.md`,
   `CODE_OF_CONDUCT.md` at HEAD; README status line = `SPEC.md:3`'s version; CLAUDE.md claims
   re-read against the code (the scenario count: `node vectors/intrude.mjs | tail -1`).
6. CI green on HEAD (`gh run list --limit 1`); `npm run vectors:check` locally; decide the artifact
   (M3) and delete retained artifacts if the gate stays.
7. After the flip: Settings → Code security → confirm secret scanning and push protection are on
   (GitHub enables them for public repos; `security_and_analysis` was `null` while private);
   Actions → fork PR approval "all outside collaborators"; require SHA-pinned actions (optional);
   wiki/projects off; topics, homepage; verify `allow_force_pushes` is still false
   (`gh api …/branches/main/protection`).
8. Open `https://github.com/tech-sumit/pact-protocol/commit/de76296f39246f1df71f54ec7acdd6c84d0f3bd7`
   in a private window: if it renders, decide on the GitHub Support purge (M5).
9. Check the `v1.2.0` release page and its PDF asset are what the owner wants public (N4), and that
   the site's whitepaper gate story (D3) matches what the repo now gives away (M3).
10. Re-read `archive/` and `docs/` top banners (S2, S3) and the pact.io line (S8) once more as an
    outsider would.

Artefacts of this audit (scratch, session-scoped): `gitleaks-all-refs.json`,
`gitleaks-unreachable.json`, `dirty.diff`, `pr10.diff`, `clean-main/` (an export of origin/main used
to run the gates).
