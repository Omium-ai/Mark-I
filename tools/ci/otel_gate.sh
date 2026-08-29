#!/bin/sh
# otel_gate.sh — 13 §7.5 gate 1 (CON-005). Zero OpenTelemetry anywhere: M1P is the only
# telemetry fabric (ADR-0005). cargo-deny [bans], Go depguard and ruff banned-api cover
# imports; this is the belt to their suspenders, so a misconfigured linter still cannot let
# an otel package into the dependency graph.
#
# Coverage is accounted PER ECOSYSTEM and split in two, because the two kinds of file prove
# different things and §7.5 only earns its "direct and transitive" claim from the second:
#   direct  — Cargo.toml, go.mod, pyproject.toml. The deps a human typed. Committed source,
#             so absence is a defect in this gate, not a build state. Proves NOTHING about
#             transitives: scanning go.mod is not a substitute for scanning go.sum.
#   closure — Cargo.lock, go.sum, go.work.sum, uv.lock. The resolved graph, which is the
#             coverage §7.5 actually claims. Absence is forgivable only while the toolchain
#             cannot yet produce the file, and that forgiveness is computed from the tree
#             below — never from an allowlist someone must remember to shorten, which is
#             exactly how a deferral turns into a permanent excuse.
set -eu

cd "$(dirname "$0")/../.."

# One pattern, all three ecosystems: crate/package names, go module paths, and the
# OTLP exporter family under any name.
PATTERN='opentelemetry|otlp'

FAILED=0
THIN=''
ECOS=''
HIT=0   # an actual OTel match, as opposed to a coverage failure — they need different advice

scan() { # scan <file> — 1 if absent, else grep it and record any hit
  if [ ! -f "$1" ]; then
    return 1
  fi
  if grep -inE "$PATTERN" "$1"; then
    echo "FAIL: OpenTelemetry package present in $1 (CON-005: zero OTel anywhere)."
    FAILED=1
    HIT=1
  else
    echo "otel_gate: $1 clean (direct+resolved as applicable)"
  fi
  return 0
}

direct() { # direct <manifest>
  if scan "$1"; then
    DIRECT=$((DIRECT + 1))
  else
    echo "FAIL: $1 is missing. Manifests are committed source, so this is not a build state —"
    echo "      either the path moved and nobody updated this gate, or the manifest was deleted."
    FAILED=1
  fi
}

closure() { # closure <lockfile> <generatable 0|1> <trigger> <how-to-generate>
  if scan "$1"; then
    CLOSURE=$((CLOSURE + 1))
    return 0
  fi
  if [ "$2" -eq 1 ]; then
    echo "FAIL: $1 is missing and $3 — the resolved dependency closure is UNSCANNED."
    echo "      Generate and commit it: $4"
    FAILED=1
  else
    echo "otel_gate: $1 deferred — not generatable at this commit."
    echo "           Becomes a hard failure the moment this is true: $3"
  fi
}

eco_open() { ECO=$1; DIRECT=0; CLOSURE=0; }
eco_close() {
  # direct() already fails on an absent manifest, so DIRECT==0 can only mean this block
  # stopped calling it at all — the "gate that passes by never executing" tripwire.
  [ "$DIRECT" -gt 0 ] || { echo "FAIL: otel_gate scanned no $ECO manifest — the gate is decoration for $ECO."; FAILED=1; }
  [ "$CLOSURE" -gt 0 ] || THIN="$THIN $ECO"
  ECOS="$ECOS $ECO"
}

# --- generatability, derived from the tree so each excuse expires without an edit here ---

# Stops at the array's own `]` rather than running to EOF, which would swallow [workspace.exclude]
# (the fuzz crates, deliberately not members) and every quoted version string after it.
MEMBERS=$(awk '/^members = \[/{f=1} f{print} f && /\]/{exit}' Cargo.toml | grep -oE '"[^"]+"' | tr -d '"')
# An empty parse would leave the per-member scan below covering nothing while still printing
# clean, and would silently mark Cargo.lock generatable, so it asserts rather than assumes.
[ -n "$MEMBERS" ] || { echo "FAIL: parsed no [workspace] members from Cargo.toml — the per-member scan covers nothing."; FAILED=1; }

# Cargo, verbatim, on this workspace today: "no targets specified in the manifest — either
# src/lib.rs, src/main.rs, a [lib] section, or [[bin]] section must be present". Those four
# conditions are transcribed from cargo's own message rather than allowlisted.
#
# The deferral is keyed on EVERY member having a target, not any, because cargo refuses the whole
# workspace on the first member that has none — keying it on `any` would demand a Cargo.lock that
# cargo still will not write, and a gate that demands the impossible is a gate someone deletes.
# That is not a softer excuse: the workspace does not build until the last member has a target
# either, so the deferral cannot outlive anything that could ship.
NO_TARGET=''
for m in $MEMBERS; do
  [ -f "$m/src/lib.rs" ] || [ -f "$m/src/main.rs" ] ||
    grep -qE '^\[lib\]|^\[\[bin\]\]' "$m/Cargo.toml" 2>/dev/null ||
    NO_TARGET="$NO_TARGET $m"
done
if [ -n "$NO_TARGET" ]; then
  RUST_LOCKABLE=0
  RUST_TRIGGER="every workspace member has a target (src/lib.rs, src/main.rs, [lib] or [[bin]]) — still without one:$NO_TARGET"
else
  RUST_LOCKABLE=1
  RUST_TRIGGER="every workspace member has a target"
fi

# `go mod tidy` on a module with no packages prunes every require and writes no go.sum.
# The first .go file makes go.sum both generatable and required to build.
go_lockable() { if find "$@" -name '*.go' -type f 2>/dev/null | grep -q .; then echo 1; else echo 0; fi; }

echo "== rust =="
eco_open rust
# Every Cargo.toml in the tree, not the [workspace.members] list: a member may name a dependency
# outright instead of `workspace = true`, and the fuzz crates sit in [workspace.exclude] — outside
# the graph cargo-deny walks, so for those this gate is not the belt, it is the only layer.
for f in $(find . -name Cargo.toml -not -path '*/target/*' | sed 's|^\./||' | sort); do direct "$f"; done
# find only visits files that exist, so a member whose manifest was deleted would drop out of the
# scan silently instead of failing. direct() owns that wording; call it for the missing case only.
for m in $MEMBERS; do [ -f "$m/Cargo.toml" ] || direct "$m/Cargo.toml"; done
closure Cargo.lock "$RUST_LOCKABLE" "$RUST_TRIGGER" "cargo generate-lockfile"
eco_close

echo "== go =="
eco_open go
# Module list read from go.work for the same reason the rust list is read from [workspace.members]:
# a module added to the build but never added to a hardcoded list here is F12 again.
[ -f go.work ] || { echo "FAIL: go.work is missing — this gate derives its module list from it."; FAILED=1; }
GO_MODS=$(sed -n '/^use (/,/^)/p' go.work 2>/dev/null | tr -d ' \t' | grep '^\./' | sed 's|^\./||')
for m in $GO_MODS; do
  direct "$m/go.mod"
  closure "$m/go.sum" "$(go_lockable "$m")" "$m contains Go source" "cd $m && go mod tidy"
done
# Same list, not a second hardcoded pair of roots: go.work.sum covers exactly the modules go.work
# names, and a root list that drifts from go.work is F12 in miniature.
closure go.work.sum "$(go_lockable $GO_MODS)" \
  "any go.work module contains Go source" "go work sync"
eco_close

echo "== python =="
eco_open python
# Member manifests as well as the root: a dep added to python/intel/pyproject.toml without a
# re-lock is not in uv.lock yet, so the closure scan below cannot see it.
for f in $(find . -name pyproject.toml -not -path './.venv/*' | sed 's|^\./||' | sort); do direct "$f"; done
# No ordering trap here: `uv lock` resolves a bare pyproject with zero packages, so uv.lock
# is required from the same commit as the manifest.
closure uv.lock 1 "pyproject.toml exists" "uv lock"
eco_close

# The tripwires in eco_close only fire for a block that RUNS. Deleting a whole block is the same
# vacuous pass one level up, so the set of blocks is itself checked against what §7.5 claims.
[ "$ECOS" = " rust go python" ] || {
  echo "FAIL: otel_gate accounted ecosystems '$ECOS'; 13 §7.5 claims rust, go and python."
  echo "      A block that no longer runs cannot report that it stopped checking."
  FAILED=1
}

if [ "$FAILED" -ne 0 ]; then
  [ "$HIT" -eq 0 ] ||
    echo "Remove the dependency. Telemetry rides M1P; there is no exception and no feature flag."
  exit 1
fi

if [ -n "$THIN" ]; then
  echo "otel_gate: PARTIAL — no lockfile scanned for:$THIN"
  echo "           Direct manifests are clean, but a TRANSITIVE otel dep in$THIN passes unseen."
  echo "           §7.5's \"direct and transitive\" claim holds only for the ecosystems whose"
  echo "           lockfiles are listed clean above."
  exit 0
fi

echo "otel_gate: OK — resolved closure scanned for rust, go and python; all free of /$PATTERN/."
