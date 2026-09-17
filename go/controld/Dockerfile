# controld — one Go binary, five modules (05). Multi-stage, distroless, nonroot.
# Build from the repo ROOT:  docker build -f go/controld/Dockerfile -t omium/mark1-controld:<sha7> .
#
# R-13.2: runtime is distroless/static, NOT the estate checkpoint-manager's alpine:latest —
# a floating base tag is the exact class of pin the estate retired for image tags on 2026-08-13.

# ---------- builder ----------
FROM golang:1.25.14-bookworm AS builder
ENV GOTOOLCHAIN=local GOFLAGS=-mod=readonly
WORKDIR /build

# Generated contracts module first (the `replace` target) — layer-cache friendly.
COPY proto/gen/go ./proto/gen/go

# Module files, then deps, then source — standard cache ordering.
COPY go/controld/go.mod go/controld/go.sum ./go/controld/
WORKDIR /build/go/controld
RUN go mod download

COPY go/controld/ ./

# Static build: CGO off (repo invariant, §3.5); trimpath + stripped for reproducibility and size.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w" -o /build/controld ./cmd/controld

# ---------- runtime ----------
# distroless/static (not cc): a CGO_ENABLED=0 Go binary needs no libc at all.
FROM gcr.io/distroless/static-debian12:nonroot
ARG REVISION=unknown
LABEL org.opencontainers.image.source="https://github.com/Omium-ai/Mark-I" \
      org.opencontainers.image.revision="$REVISION"
COPY --from=builder /build/controld /usr/local/bin/controld
EXPOSE 8080 9092
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/controld"]
