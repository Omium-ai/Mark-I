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
GO_OUT_ALL=""
for m in mark1d controld; do
  [ -f "go/$m/go.mod" ] || { echo "conformance: go/$m (absent, skipped)"; continue; }
  echo "conformance: go — go/$m: go test -run ConfVectors ./..."
  GO_OUT=$( (cd "go/$m" && go test -run ConfVectors -v ./...) 2>&1 ) || { echo "$GO_OUT"; echo "FAIL: Go conformance vectors in go/$m"; exit 1; }
  echo "$GO_OUT"
  GO_OUT_ALL="$GO_OUT_ALL
$GO_OUT"
  GO_N=$((GO_N + $(echo "$GO_OUT" | grep -c '^=== RUN' || true)))
done

# ---- per-FAMILY Go coverage. A single global GO_N > 0 lets one family's tests green-light
# every other family: the receipt tests alone satisfied it while the bundle family had ZERO Go
# coverage and nothing noticed. Each EXPECTED family must run its OWN Go tests — or be declared
# pending below, printed loudly. An honest gap beats a green light over nothing. ----
# bundle: the Go bundle decoder lands with Wave B fusion; DELETE the entry in that same commit.
GO_PENDING="bundle"
for fam in $EXPECTED; do
  # Family → Go test-name token (m1pl→ConfVectorsM1pl, receipt→ConfVectorsReceipt, ...).
  token=$(printf '%s' "$fam" | awk '{ print toupper(substr($0,1,1)) substr($0,2) }')
  fam_n=$(printf '%s\n' "$GO_OUT_ALL" | grep -c "^=== RUN.*ConfVectors$token" || true)
  if [ "$fam_n" -gt 0 ]; then
    echo "conformance: go — family $fam: $fam_n vector test(s)"
    continue
  fi
  case " $GO_PENDING " in
    *" $fam "*)
      echo "conformance: go — family $fam: NO GO TWIN YET (declared pending — Go bundle decoder"
      echo "              lands with Wave B fusion). Rust is the only implementation locked on"
      echo "              this family today; the cross-language claim does NOT cover it." ;;
    *)
      echo "FAIL: family $fam ran zero Go vector tests (filter ConfVectors$token) — a silently"
      echo "      uncovered family is a failed gate. Land the Go tests, or declare the family in"
      echo "      GO_PENDING in the commit that explains why its twin is not due."
      exit 1 ;;
  esac
done

# ---- Python (betterproto + the vendored mark1_receipts package) ----
# Per-suite invocation (mirrors justfile `test-py`): adjudicator and intel both export a
# top-level `app` package (06 §1.1), and one pytest process caches whichever `app` imports
# first — a combined `pytest python` run can never resolve both.
need uv
PY_N=0
for suite in python/shared/mark1_receipts/tests python/adjudicator/tests python/intel/tests; do
  [ -d "$suite" ] || continue
  echo "conformance: python — pytest $suite -k conf_vectors"
  set +e
  uv run --frozen -m pytest "$suite" -o asyncio_mode=auto -k conf_vectors
  PY_RC=$?
  set -e
  case "$PY_RC" in
    0) PY_N=1 ;;
    5) ;;  # pytest exit 5 = no tests collected in this suite
    *) echo "FAIL: Python conformance vectors in $suite"; exit 1 ;;
  esac
done

echo "conformance: vector tests ran — rust=$RS_N go=$GO_N python_collected=$PY_N"

[ "$RS_N" -gt 0 ] || { echo "FAIL: zero Rust vector tests ran (filter conf_vectors_) — a skipped run is a failed run"; exit 1; }
[ "$GO_N" -gt 0 ] || { echo "FAIL: zero Go vector tests ran (filter ConfVectors) — a skipped run is a failed run"; exit 1; }
if [ "$(find "$VEC/receipt" -type f 2>/dev/null | wc -l | tr -d ' ')" -gt 0 ] && [ "$PY_N" -eq 0 ]; then
  echo "FAIL: receipt vectors exist but zero Python vector tests ran — the three languages are"
  echo "      supposed to be locked together from C6 (13 §1)"
  exit 1
fi

echo "conformance_crosslang: OK — $TOTAL vector file(s) agree across the implementations present"
