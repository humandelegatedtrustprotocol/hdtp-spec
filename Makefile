# pact-protocol — the specification's gates, its whitepaper build, and publishing that build.
#
# Publishing is local and the owner's (standing rule 4 of the umbrella: no CI credentials). The PDF
# and its meta go into the private bucket pact-cloud-private, which pact-protocol-site reads for
# pact-protocol.com. CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID come from the umbrella's .env,
# loaded into the recipe's shell only (ENV_FILE=… from a checkout that is not the umbrella's).

SHELL := /bin/bash
.DEFAULT_GOAL := help
ROOT     := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
ENV_FILE ?= $(abspath $(ROOT)/../.env)
WITH_ENV  = set -a && . "$(ENV_FILE)" && set +a &&

.PHONY: help check build spec-html publish

help:
	@awk 'BEGIN{FS=":.*## "} /^[a-zA-Z_-]+:.*## /{printf "  \033[1m%-9s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

check: ## the vectors, the 1.x clearance, and the web renderer on both published texts
	npm run vectors:check
	npm run spec:check

build: ## render SPEC.md into dist/pact-whitepaper.pdf and its meta (the build is also a gate)
	npm run build

# The web fragments the protocol site vendors: one committed SPEC.md (REF, never the working
# tree) rendered into OUT, which must be gitignored here or outside this repository.
REF ?= HEAD
OUT ?= dist/spec
spec-html: ## render SPEC.md at REF (default HEAD) into OUT (default dist/spec): spec.html, toc, musts, meta, vectors
	npm run spec:html -- --ref $(REF) --out $(OUT)

publish: check build ## build, then put the PDF and its meta into the private bucket, together
	@test -f "$(ENV_FILE)" || { echo "no .env at $(ENV_FILE)"; exit 1; }
	node -e "const fs=require('fs');const m=JSON.parse(fs.readFileSync('dist/pact-whitepaper.meta.json','utf8'));const b=fs.statSync('dist/pact-whitepaper.pdf').size;if(m.bytes!==b){console.error('the meta says '+m.bytes+' bytes, the PDF is '+b+': not one build, nothing published');process.exit(1)}console.log('publishing '+m.version+' ('+b+' bytes)')"
	$(WITH_ENV) npm run publish
