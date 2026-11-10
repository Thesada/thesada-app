# thesada-app. Bare `make` prints this list and changes nothing.
# Build, run, and CSS pipeline. No node, no npm. Node only runs the inline-script tests.
.DEFAULT_GOAL := help
SHELL := bash

GO ?= go
TAILWIND ?= ./tools/tailwindcss
TAILWIND_VERSION ?= v4.2.2
NODE_VERSION ?= v24.22.1
BIN := bin/thesada-app

# A node-cli download wins over a system node. The harness gets the path
# itself, since a PATH entry breaks when the checkout path holds a colon.
export THESADA_NODE := $(CURDIR)/tools/node/bin/node

# Detect host OS/arch for the tailwind standalone CLI download URL.
# The release asset is named macos, not darwin.
TAILWIND_OS := $(shell uname -s | tr '[:upper:]' '[:lower:]' | sed 's/^darwin$$/macos/')
TAILWIND_ARCH_RAW := $(shell uname -m)
TAILWIND_ARCH := $(if $(filter x86_64,$(TAILWIND_ARCH_RAW)),x64,$(if $(filter aarch64 arm64,$(TAILWIND_ARCH_RAW)),arm64,$(TAILWIND_ARCH_RAW)))
TAILWIND_URL := https://github.com/tailwindlabs/tailwindcss/releases/download/$(TAILWIND_VERSION)/tailwindcss-$(TAILWIND_OS)-$(TAILWIND_ARCH)
NODE_OS := $(shell uname -s | tr '[:upper:]' '[:lower:]')
NODE_URL := https://nodejs.org/dist/$(NODE_VERSION)/node-$(NODE_VERSION)-$(NODE_OS)-$(TAILWIND_ARCH).tar.gz
# nodejs.org ships glibc builds only, a musl host (Alpine) keeps its system node.
NODE_MUSL := $(shell ldd --version 2>&1 | grep -qi musl && echo 1)

# Security scanner versions. Pinned so a transient upstream change cannot
# fail a CI run silently (e.g. gosec moved a default rule, govulncheck
# upgraded the database format).
GOVULNCHECK_VERSION ?= v1.1.4
GOSEC_VERSION       ?= v2.25.0

# Linter version. Pinned so local `make lint` and CI never diverge.
GOLANGCI_VERSION ?= v2.11.4

# Build metadata injected into pkg/buildinfo. VERSION
# resolves to e.g. v1.2.3 (git tag) or dev-abc1234-dirty when off-tag.
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT     ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_TIME ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -X thesada.app/app/pkg/buildinfo.Version=$(VERSION) \
           -X thesada.app/app/pkg/buildinfo.Commit=$(COMMIT) \
           -X thesada.app/app/pkg/buildinfo.BuildTime=$(BUILD_TIME)

##@ General

.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nusage: make <target>\n"} \
	  /^[a-zA-Z0-9_.-]+:.*##/ { printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2 } \
	  /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) }' $(MAKEFILE_LIST)

##@ Setup

.PHONY: setup
setup: tailwind-cli node-cli ## Modules plus the pinned Tailwind CLI and Node, enough for a clean clone to build and test
	$(GO) mod download

.PHONY: tailwind-cli
tailwind-cli: ## Download the pinned Tailwind standalone CLI into tools/ when it is missing
	@if [ ! -x $(TAILWIND) ]; then \
		mkdir -p tools; \
		echo "fetching tailwindcss $(TAILWIND_VERSION) from $(TAILWIND_URL)"; \
		curl -fsSL -o $(TAILWIND) $(TAILWIND_URL); \
		chmod +x $(TAILWIND); \
	fi

.PHONY: node-cli
node-cli: ## Download the pinned Node into tools/node for the inline-script tests when it is missing or another version
	@if [ -n "$(NODE_MUSL)" ]; then \
		echo "musl host, the inline-script tests use the system node"; \
	elif [ "$$(tools/node/bin/node --version 2>/dev/null)" != "$(NODE_VERSION)" ]; then \
		echo "fetching node $(NODE_VERSION) from $(NODE_URL)"; \
		rm -rf tools/node.tmp && mkdir -p tools/node.tmp && \
		curl -fsSL $(NODE_URL) | tar -xz --strip-components=1 -C tools/node.tmp && \
		rm -rf tools/node && mv tools/node.tmp tools/node; \
	fi

.PHONY: tidy
tidy: ## Refresh go.sum and prune unused modules
	$(GO) mod tidy

.PHONY: lint-tools
lint-tools: ## Install the pinned golangci-lint into GOPATH/bin
	$(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_VERSION)

.PHONY: sec-tools
sec-tools: ## Install the pinned govulncheck and gosec into GOPATH/bin
	$(GO) install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
	$(GO) install github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION)

##@ Build

.PHONY: css
css: tailwind-cli ## Build minified CSS into the embedded static tree
	$(TAILWIND) -i assets/css/app.css -o pkg/web/static/css/app.css --minify

.PHONY: css-watch
css-watch: tailwind-cli ## Rebuild CSS when templates or Go files change
	$(TAILWIND) -i assets/css/app.css -o pkg/web/static/css/app.css --watch

.PHONY: build
build: css ## Build the Go binary (depends on css so the embedded static tree is non-empty)
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/thesada-app

.PHONY: run
run: build ## Run the binary, loading .env when that file is present
	@if [ -f .env ]; then set -a; . ./.env; set +a; fi; $(BIN)

##@ Test

.PHONY: test
test: ## Unit tests, no database
	$(GO) test ./...

.PHONY: test-integration
test-integration: ## DB-backed tests via testcontainers (needs Docker, 600s timeout)
	$(GO) test -tags integration -timeout 600s ./...

.PHONY: cover
cover: ## Coverage of the security packages on the integration lane (needs Docker)
	$(GO) test -tags integration -cover -timeout 300s ./pkg/csrf/... ./pkg/oauth/... ./pkg/pki/... ./pkg/authmw/...

.PHONY: coverage
coverage: ## 80% floor on the security packages, the CI gate (needs Docker)
	bash scripts/check-coverage.sh

##@ Lint

.PHONY: fmt
fmt: ## Rewrite Go files with gofmt
	$(GO) fmt ./...

.PHONY: lint
lint: ## golangci-lint, including //go:build integration files (no database)
	golangci-lint run --build-tags integration ./...

.PHONY: pools
pools: ## Forbid new pools.App callers outside the pkg/db contract
	bash scripts/check-pools-app.sh

.PHONY: sec-vuln
sec-vuln: ## Reachability scan against the Go vulnerability database
	govulncheck ./...

.PHONY: sec-full
sec-full: ## Full gosec report; findings do not fail the run
	gosec -fmt text ./... || true

.PHONY: sec-static
sec-static: ## Fail on HIGH gosec findings
	gosec -severity high -confidence medium -fmt text -quiet ./...

.PHONY: sec
sec: sec-vuln sec-static ## govulncheck, then the HIGH gosec gate

.PHONY: ci
ci: lint pools test test-integration coverage sec ## Local CI: lint, pools guard, unit and integration tests, coverage, vuln and gosec gates

##@ Housekeeping

.PHONY: clean
clean: ## Remove the binary and the generated CSS
	rm -rf bin pkg/web/static/css/app.css

-include .forgejo/publish.mk
