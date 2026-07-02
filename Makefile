# thesada-app Makefile
# Build, run, and CSS pipeline. No node, no npm.

GO ?= go
TAILWIND ?= ./tools/tailwindcss
TAILWIND_VERSION ?= v4.2.2
BIN := bin/thesada-app

# Detect host OS/arch for the tailwind standalone CLI download URL.
TAILWIND_OS := $(shell uname -s | tr '[:upper:]' '[:lower:]')
TAILWIND_ARCH_RAW := $(shell uname -m)
TAILWIND_ARCH := $(if $(filter x86_64,$(TAILWIND_ARCH_RAW)),x64,$(if $(filter aarch64 arm64,$(TAILWIND_ARCH_RAW)),arm64,$(TAILWIND_ARCH_RAW)))
TAILWIND_URL := https://github.com/tailwindlabs/tailwindcss/releases/download/$(TAILWIND_VERSION)/tailwindcss-$(TAILWIND_OS)-$(TAILWIND_ARCH)

.PHONY: build run css css-watch tailwind-cli tidy clean test test-integration cover sec sec-vuln sec-static sec-tools lint lint-tools

# Security scanner versions. Pinned so a transient upstream change cannot
# fail a CI run silently (e.g. gosec moved a default rule, govulncheck
# upgraded the database format).
GOVULNCHECK_VERSION ?= v1.1.4
GOSEC_VERSION       ?= v2.25.0

# Linter version. Pinned to match .github/workflows/ci.yml so local
# `make lint` and CI never diverge.
GOLANGCI_VERSION ?= v2.11.4

# Build metadata injected into pkg/buildinfo. VERSION
# resolves to e.g. v1.2.3 (git tag) or dev-abc1234-dirty when off-tag.
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT     ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_TIME ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -X thesada.app/app/pkg/buildinfo.Version=$(VERSION) \
           -X thesada.app/app/pkg/buildinfo.Commit=$(COMMIT) \
           -X thesada.app/app/pkg/buildinfo.BuildTime=$(BUILD_TIME)

# Build the Go binary. Depends on css so the embedded static/ is non-empty.
build: css
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/thesada-app

# Download pinned tailwind standalone CLI into tools/ if missing.
tailwind-cli:
	@if [ ! -x $(TAILWIND) ]; then \
		mkdir -p tools; \
		echo "fetching tailwindcss $(TAILWIND_VERSION) from $(TAILWIND_URL)"; \
		curl -fsSL -o $(TAILWIND) $(TAILWIND_URL); \
		chmod +x $(TAILWIND); \
	fi

# Build CSS once (minified) for production.
css: tailwind-cli
	$(TAILWIND) -i assets/css/app.css -o pkg/web/static/css/app.css --minify

# Watch and rebuild CSS on template/go changes for dev.
css-watch: tailwind-cli
	$(TAILWIND) -i assets/css/app.css -o pkg/web/static/css/app.css --watch

# Refresh go.sum and prune unused deps.
tidy:
	$(GO) mod tidy

# Run the binary, env loaded from .env if present.
run: build
	@if [ -f .env ]; then set -a; . ./.env; set +a; fi; $(BIN)

# Run go tests (unit only - the default lane, no DB).
test:
	$(GO) test ./...

# Run DB-backed integration tests. Spins a throwaway
# TimescaleDB per package via testcontainers; needs a reachable Docker daemon.
# Off the default lane behind the `integration` build tag.
test-integration:
	$(GO) test -tags integration -timeout 600s ./...

# Per-package coverage for the security packages, enforced at 80%+ in CI
# (ci.yml coverage job) via scripts/check-coverage.sh. Runs the integration
# lane so oauth's DB-backed Start/LookupState count - real Postgres via
# testcontainers, needs Docker. pkg/service (auth.go) is not gated here.
cover:
	$(GO) test -tags integration -cover -timeout 300s ./pkg/csrf/... ./pkg/oauth/... ./pkg/pki/... ./pkg/authmw/...

# Remove build artifacts.
clean:
	rm -rf bin pkg/web/static/css/app.css

# ── Security scanners ─────────────────────────────────────────
# Two-tool stack:
#   govulncheck - Go vuln DB, reachability-scoped (low FP rate)
#   gosec       - SAST: hardcoded creds, weak crypto, SQLi-shaped concat
# Trivy is deferred until the app has a Dockerfile.

# Install pinned versions into $GOBIN (or $HOME/go/bin if unset).
sec-tools:
	$(GO) install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
	$(GO) install github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION)

# Module-graph + reachable-symbol scan against the Go vuln database.
sec-vuln:
	govulncheck ./...

# SAST scan. Severity threshold tuned to gate on HIGH+ only; medium/low
# findings still print but do not fail the build. Tweak via .gosec.json
# allowlist for vetted exceptions; new exceptions require a justification
# comment in the file.
sec-static:
	gosec -severity high -confidence medium -fmt text ./...

# Run both scanners. Use as a local pre-push gate or in CI alongside test.
sec: sec-vuln sec-static

# Install the pinned linter.
lint-tools:
	$(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_VERSION)

# Lint with the integration build tag so //go:build integration files are
# covered too (matches lint.yml CI). The tag only adds files; untagged files
# are still linted. Lint typechecks, it does not run tests, so no DB needed.
lint:
	golangci-lint run --build-tags integration ./...
