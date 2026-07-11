# syntax=docker/dockerfile:1
# thesada-app container image. Multi-stage: build the fully
# self-contained static binary, ship it on distroless. All assets (templates,
# static, tailwind CSS, SQL migrations) are go:embed'd, so the runtime image is
# just the single binary + CA roots - no Go, no shell, no assets on disk.

ARG GO_VERSION=1.25.12

# ---- build -----------------------------------------------------------------
# -bookworm (buildpack-deps based) ships curl + ca-certificates, which `make
# css` needs to fetch the pinned tailwind standalone CLI (no node).
# --platform=$BUILDPLATFORM keeps the builder native (no QEMU); the Go build
# cross-compiles to TARGETARCH below, and the final stage just copies the
# static binary, so multi-arch images build without emulating the toolchain.
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-bookworm AS build
WORKDIR /src

# Module download cached on go.mod/go.sum alone.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build metadata injected via args (no .git in the build context; the Makefile
# would otherwise fall back to VERSION=dev). CGO_ENABLED=0 so the binary is
# fully static for distroless/static (the default cgo net/user resolver would
# dynamically link libc and fail there). Reuses the Makefile build target
# (css -> embedded -> go build).
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_TIME=
# TARGETOS/TARGETARCH are set automatically by buildx per --platform (default
# linux/amd64 for a plain build), so the same Dockerfile cross-builds arm64.
# CGO_ENABLED=0 keeps the binary static for distroless on either arch.
ARG TARGETOS=linux
ARG TARGETARCH=amd64
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    make build VERSION="${VERSION}" COMMIT="${COMMIT}" BUILD_TIME="${BUILD_TIME}"

# Pre-made CA dir for the runtime stage: distroless has no shell, so the
# nonroot-owned mount point must be baked here. A named volume mounted at
# this path inherits the ownership on first use; without it Docker creates
# a root:root 0755 mount point and pki.Bootstrap's key write crash-loops
# the container.
RUN mkdir -p /ca && chown 65532:65532 /ca && chmod 700 /ca

# ---- runtime ---------------------------------------------------------------
# :nonroot runs as uid 65532; the CA-dir mount point below is baked with that
# ownership. static-debian12 includes ca-certificates for outbound
# OIDC/MQTT/SMTP TLS.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /src/bin/thesada-app /usr/local/bin/thesada-app
COPY --from=build --chown=65532:65532 /ca /opt/thesada-app/ca
EXPOSE 8080
# `migrate` is passed as an arg by the deploy workflow's one-shot run.
ENTRYPOINT ["/usr/local/bin/thesada-app"]
