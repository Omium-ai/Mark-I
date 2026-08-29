#!/bin/sh
# conformance_crosslang.sh — 13 §1/§5.5, 12 §3.4. The frozen vectors in conformance/vectors/
# (M1PL frames, redact, receipts, bundle decode) must produce identical results in Rust, Go and
# Python. Divergence in any pair fails CI (NFR-CORRECTNESS-005/006).
#
# The vectors are the anti-drift mechanism for three hand-written implementations of one wire
# format, so a run that executes zero vector tests is a FAILED run, not a passed one.
#
# Required languages: Rust and Go from C3 (frames). Python joins at C6, the commit that lands
# conformance/vectors/receipt/ — so this gate's own scope is driven by the vectors on disk.
set -eu

cd "$(dirname "$0")/../.."

VEC=conformance/vectors
EXPECTED_FILE="$VEC/EXPECTED"

# Which families are DUE is a committed claim, not an inference from the filesystem: "no vectors
# yet" (C0) and "the vectors were deleted" (any commit after C3) are indistinguishable to a
# directory scan, and exactly one of them may pass. See the header of EXPECTED.
[ -f "$EXPECTED_FILE" ] || { echo "FAIL: $EXPECTED_FILE is missing — the gate cannot know what it is owed"; exit 1; }
EXPECTED=$(grep -v '^[[:space:]]*#' "$EXPECTED_FILE" | tr -d ' \t' | grep -v '^$' || true)

TOTAL=0
MISSING=""
for fam in $EXPECTED; do
  n=$(find "$VEC/$fam" -type f 2>/dev/null | wc -l | tr -d ' ')
  echo "conformance: $VEC/$fam — $n vector file(s)"
  [ "$n" -eq 0 ] && MISSING="$MISSING $fam"
  TOTAL=$((TOTAL + n))
done

if [ -n "$MISSING" ]; then
  echo "FAIL: families listed in $EXPECTED_FILE have no vector files:$MISSING"
  echo "      A cross-language gate with no vectors is decoration. Land the vectors, or remove"
  echo "      the line in the same commit that removes the implementation it guards."
  exit 1
fi

if [ "$TOTAL" -eq 0 ]; then
  echo "conformance: $EXPECTED_FILE lists no families — no wire implementation is due yet (C0)."
  echo "conformance: nothing to check. This gate arms itself the moment a family is listed."
  exit 0
fi

need() {
  command -v "$1" >/dev/null 2>&1 || { echo "FAIL: '$1' not found; run scripts/bootstrap.sh"; exit 1; }
}

# ---- Rust (reference implementation: prost, mark1-receipt, mark1-policy, m1p-wire) ----
need cargo
echo "conformance: rust — cargo test --workspace conf_vectors_"
RS_OUT=$(cargo test --workspace --locked conf_vectors_ 2>&1) || { echo "$RS_OUT"; echo "FAIL: Rust conformance vectors"; exit 1; }
echo "$RS_OUT"
RS_N=$(echo "$RS_OUT" | awk '/^test result:/ {for (i = 2; i <= NF; i++) if ($i == "passed;") s += $(i-1)} END {print s + 0}')

# ---- Go (the parallel decoder: mark1d frame reader + origin-sign mirror, controld ingest) ----
need go
GO_N=0
for m in mark1d controld; do
  [ -f "go/$m/go.mod" ] || { echo "conformance: go/$m (absent, skipped)"; continue; }
  echo "conformance: go — go/$m: go test -run ConfVectors ./..."
  GO_OUT=$( (cd "go/$m" && go test -run ConfVectors -v ./...) 2>&1 ) || { echo "$GO_OUT"; echo "FAIL: Go conformance vectors in go/$m"; exit 1; }
  echo "$GO_OUT"
  GO_N=$((GO_N + $(echo "$GO_OUT" | grep -c '^=== RUN' || true)))
done

# ---- Python (betterproto + the vendored mark1_receipts package) ----
need uv
echo "conformance: python — pytest -k conf_vectors"
PY_N=1
set +e
uv run --frozen -m pytest python -o asyncio_mode=auto -k conf_vectors
PY_RC=$?
set -e
case "$PY_RC" in
  0) ;;
  5) PY_N=0 ;;  # pytest exit 5 = no tests collected
  *) echo "FAIL: Python conformance vectors"; exit 1 ;;
esac

echo "conformance: vector tests ran — rust=$RS_N go=$GO_N python_collected=$PY_N"

[ "$RS_N" -gt 0 ] || { echo "FAIL: zero Rust vector tests ran (filter conf_vectors_) — a skipped run is a failed run"; exit 1; }
[ "$GO_N" -gt 0 ] || { echo "FAIL: zero Go vector tests ran (filter ConfVectors) — a skipped run is a failed run"; exit 1; }
if [ "$(find "$VEC/receipt" -type f 2>/dev/null | wc -l | tr -d ' ')" -gt 0 ] && [ "$PY_N" -eq 0 ]; then
  echo "FAIL: receipt vectors exist but zero Python vector tests ran — the three languages are"
  echo "      supposed to be locked together from C6 (13 §1)"
  exit 1
fi

echo "conformance_crosslang: OK — $TOTAL vector file(s) agree across the implementations present"
