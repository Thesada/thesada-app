# syntax=docker/dockerfile:1
# thesada-app container image. Multi-stage: build the fully
# self-contained static binary, ship it on distroless. All assets (templates,
# static, tailwind CSS, SQL migrations) are go:embed'd, so the runtime image is
# just the single binary + CA roots - no Go, no shell, no assets on disk.

ARG GO_VERSION=1.25.11

# ---- build -----------------------------------------------------------------
# -bookworm (buildpack-deps based) ships curl + ca-certificates, which `make
# css` needs to fetch the pinned tailwind standalone CLI (no node).
FROM golang:${GO_VERSION}-bookworm AS build
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
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    make build VERSION="${VERSION}" COMMIT="${COMMIT}" BUILD_TIME="${BUILD_TIME}"

# ---- runtime ---------------------------------------------------------------
# :nonroot runs as uid 65532; the
# CA-dir volume is chowned to it. static-debian12 includes ca-certificates for
# outbound OIDC/MQTT/SMTP TLS.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /src/bin/thesada-app /usr/local/bin/thesada-app
EXPOSE 8080
# `migrate` is passed as an arg by the deploy workflow's one-shot run.
ENTRYPOINT ["/usr/local/bin/thesada-app"]
