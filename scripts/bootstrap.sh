#!/usr/bin/env bash
# =============================================================================
# omium-mark1 — clean-machine bootstrap (13 §6.4)
# =============================================================================
# Installs exactly the tool list below, verifies versions, and STOPS. It does not touch the
# repository: no codegen, no build, no git. What you run after it is `just gen-check && just
# build && just test`.
#
#   ./scripts/bootstrap.sh            install anything missing, then verify
#   ./scripts/bootstrap.sh --check    verify only; exit nonzero on the first gap
#
# Windows uses scripts/bootstrap.ps1. Everything here is pinned: a floating tool version is a
# statement about *time*, and nothing in a build should depend on when it ran (13 §9.5).
# =============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFIX="${PREFIX:-$HOME/.local}"
BIN="$PREFIX/bin"

# --- pins -------------------------------------------------------------------
GO_VERSION="1.25.0"
JUST_VERSION="1.42.4"
BUF_VERSION="1.50.0"
GOLANGCI_VERSION="2.1.6"
SYFT_VERSION="1.20.0"
# Rust is pinned by rust-toolchain.toml, which rustup reads on first cargo invocation.
RUST_VERSION="$(sed -n 's/^ *channel *= *"\([^"]*\)".*/\1/p' "$REPO_ROOT/rust-toolchain.toml" 2>/dev/null || echo "1.91")"

CHECK_ONLY=false
[[ "${1:-}" == "--check" ]] && CHECK_ONLY=true

OS="$(uname -s)"
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|amd64) GOARCH=amd64; UARCH=x86_64 ;;
    arm64|aarch64) GOARCH=arm64; UARCH=arm64 ;;
    *) echo "bootstrap: unsupported architecture: $ARCH" >&2; exit 1 ;;
esac
case "$OS" in
    Linux)  GOOS=linux;  LOWEROS=linux ;;
    Darwin) GOOS=darwin; LOWEROS=darwin ;;
    *) echo "bootstrap: use scripts/bootstrap.ps1 on Windows" >&2; exit 1 ;;
esac

ok()   { echo "  ok    $*"; }
miss() { echo "  MISS  $*"; }
info() { echo "[bootstrap] $*"; }

FAILED=0

# ---------------------------------------------------------------------------
# Install helpers. macOS prefers Homebrew because that is what §6.4 documents; Linux pulls
# release binaries into $PREFIX/bin so bootstrap never needs sudo or an apt repo.
# ---------------------------------------------------------------------------
fetch_tar() {  # url  strip-components  member-glob
    local url="$1" strip="$2" member="${3:-}"
    mkdir -p "$BIN"
    curl -fsSL "$url" | tar -xz -C "$BIN" --strip-components="$strip" ${member:+"$member"}
}

install_rustup() {
    command -v rustup >/dev/null 2>&1 && return 0
    info "installing rustup (rust-toolchain.toml pins the channel to $RUST_VERSION)"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path
    # shellcheck disable=SC1090
    . "$HOME/.cargo/env"
}

install_uv() {
    command -v uv >/dev/null 2>&1 && return 0
    info "installing uv"
    curl -LsSf https://astral.sh/uv/install.sh | sh
}

install_go() {
    command -v go >/dev/null 2>&1 && return 0
    info "installing go $GO_VERSION into $PREFIX/go"
    mkdir -p "$PREFIX"
    curl -fsSL "https://go.dev/dl/go${GO_VERSION}.${GOOS}-${GOARCH}.tar.gz" | tar -xz -C "$PREFIX"
    mkdir -p "$BIN"
    ln -sf "$PREFIX/go/bin/go" "$BIN/go"
    ln -sf "$PREFIX/go/bin/gofmt" "$BIN/gofmt"
}

install_just() {
    command -v just >/dev/null 2>&1 && return 0
    info "installing just $JUST_VERSION"
    fetch_tar "https://github.com/casey/just/releases/download/${JUST_VERSION}/just-${JUST_VERSION}-${UARCH}-$( [ "$OS" = Darwin ] && echo apple-darwin || echo unknown-linux-musl ).tar.gz" 0 just
}

install_buf() {
    command -v buf >/dev/null 2>&1 && return 0
    info "installing buf $BUF_VERSION"
    mkdir -p "$BIN"
    curl -fsSL -o "$BIN/buf" "https://github.com/bufbuild/buf/releases/download/v${BUF_VERSION}/buf-$(uname -s)-$(uname -m)"
    chmod +x "$BIN/buf"
}

install_golangci() {
    command -v golangci-lint >/dev/null 2>&1 && return 0
    info "installing golangci-lint $GOLANGCI_VERSION"
    fetch_tar "https://github.com/golangci/golangci-lint/releases/download/v${GOLANGCI_VERSION}/golangci-lint-${GOLANGCI_VERSION}-${LOWEROS}-${GOARCH}.tar.gz" 1 "golangci-lint-${GOLANGCI_VERSION}-${LOWEROS}-${GOARCH}/golangci-lint"
}

install_syft() {
    command -v syft >/dev/null 2>&1 && return 0
    info "installing syft $SYFT_VERSION"
    curl -fsSL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b "$BIN" "v${SYFT_VERSION}"
}

install_all() {
    if [[ "$OS" == "Darwin" ]] && command -v brew >/dev/null 2>&1; then
        info "using Homebrew"
        brew install just uv go buf golangci-lint syft pre-commit || true
        install_rustup
        return
    fi
    install_rustup
    install_uv
    install_go
    install_just
    install_buf
    install_golangci
    install_syft
    command -v pre-commit >/dev/null 2>&1 || uv tool install pre-commit
}

# ---------------------------------------------------------------------------
# Verify. This is the half that matters: a bootstrap that installs but does not check has
# only moved the failure later.
# ---------------------------------------------------------------------------
require() {  # name  version-command  expected-substring(optional)
    local name="$1" cmd="$2" want="${3:-}"
    if ! command -v "$name" >/dev/null 2>&1; then
        miss "$name not on PATH"
        FAILED=1
        return
    fi
    local got
    got="$($cmd 2>&1 | head -n1)"
    if [[ -n "$want" && "$got" != *"$want"* ]]; then
        miss "$name: expected '$want', got '$got'"
        FAILED=1
        return
    fi
    ok "$name — $got"
}

export PATH="$BIN:$HOME/.cargo/bin:$PATH"

if ! $CHECK_ONLY; then
    install_all
    export PATH="$BIN:$HOME/.cargo/bin:$PATH"
fi

info "verifying toolchain"
require cargo          "cargo --version"                "$RUST_VERSION"
require rustc          "rustc --version"                "$RUST_VERSION"
require go             "go version"                     "go${GO_VERSION%.*}"
require uv             "uv --version"
require buf            "buf --version"                  "$BUF_VERSION"
require just           "just --version"                 "$JUST_VERSION"
require golangci-lint  "golangci-lint --version"        "$GOLANGCI_VERSION"
require psql           "psql --version"

if [[ $FAILED -ne 0 ]]; then
    echo
    echo "bootstrap: toolchain incomplete. Re-run without --check to install, or fix the versions above." >&2
    echo "  \$PREFIX/bin is $BIN — put it on your PATH." >&2
    exit 1
fi

echo
info "toolchain OK. Next:"
echo "    pre-commit install                 # once, per checkout (13 §7.6)"
echo "    just gen-check && just build && just test"
echo
info "Fuzz targets additionally need:  rustup toolchain install nightly && cargo install cargo-fuzz"
info "Store-backed suites: 'just stores-up' (native binaries, no Docker). 'just dev-up' is the"
info "optional Docker dev stack; nothing else in the loop needs Docker."
