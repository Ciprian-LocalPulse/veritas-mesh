# Dockerfile for mesh/cmd/veritas-node -- the ONE genuinely runnable
# binary in this repository (everything else is a library: core/,
# zk-poc/, the SDKs, analysis/). Read main.go's own package doc comment
# before assuming this is more than it is:
#
#   "STATUS: this wires the real packages in internal/ together into a
#   runnable binary with a working local flow (feed it an attestation via
#   stdin JSON, it verifies-with-a-placeholder/stores/would-fan-out). It
#   does NOT open a real network listener yet [...]. Treat this as the
#   wiring skeleton the real network layer plugs into, not a deployable
#   node."
#
# This image is a faithful container of exactly that skeleton -- not a
# production node image. Concretely: there is no network transport, so
# there is no port to EXPOSE here on purpose (adding one would imply a
# service that doesn't exist). The binary reads newline-delimited JSON
# attestations from stdin and logs accept/reject decisions -- see "Usage"
# below for how that looks with `docker run`.
#
# Build from the repository root:
#   docker build -t veritas-node -f mesh/Dockerfile mesh/
# Or from inside mesh/:
#   docker build -t veritas-node .
#
# Usage (interactive, reading attestations from your terminal):
#   docker run -it --rm veritas-node
# Usage (piping a file of newline-delimited JSON attestations):
#   docker run -i --rm veritas-node < attestations.jsonl
# Usage (persisting the JSON-lines store to a bind-mounted volume):
#   docker run -i --rm -v "$(pwd)/data:/data" veritas-node -store /data/store.jsonl < attestations.jsonl

# ---- Build stage ----
# Pinned to the same Go version mesh/go.mod and sdk/go/go.mod declare
# (go 1.22) -- see STATUS.md/CHANGELOG.md for why other toolchains in
# this repo are version-pinned for compatibility reasons; this one is
# pinned simply to match what's actually declared and tested against.
FROM golang:1.22-alpine AS builder

WORKDIR /build

# Copy go.mod/go.sum first so dependency downloads are cached across
# builds that only change source files. This module currently has no
# external dependencies (see mesh/go.mod) -- `go mod download` is a
# near-no-op today, but kept as a real, correct step rather than skipped,
# since that stops being true the moment a real dependency is added.
COPY go.mod ./
RUN go mod download

COPY . .

# CGO_ENABLED=0: produces a fully static binary, which is what makes the
# minimal (non-glibc) runtime stage below possible at all.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" \
    -o /build/veritas-node ./cmd/veritas-node

# ---- Runtime stage ----
# Alpine, not distroless/scratch: this is early-stage research software
# (see STATUS.md) meant for people actively experimenting with it, not a
# hardened production deployment -- a shell and package manager for
# debugging are more useful right now than the smaller attack surface a
# distroless image would give a binary that doesn't even open a network
# port yet.
FROM alpine:3.20

RUN addgroup -S veritas && adduser -S veritas -G veritas
USER veritas

WORKDIR /home/veritas
COPY --from=builder --chown=veritas:veritas /build/veritas-node /usr/local/bin/veritas-node

# No EXPOSE: see header comment -- there is no network listener to
# expose. Data plane is stdin/stdout plus the optional -store file.
ENTRYPOINT ["/usr/local/bin/veritas-node"]
