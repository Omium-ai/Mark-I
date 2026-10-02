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
  command -v "$1" >/dev/null 2>&1 || { echo "FAIL: '$1' not found; run tools/bootstrap.sh"; exit 1; }
}

# ---- D-AP: where each leg writes the raw IEEE-754 bits of every fusion posterior it
# computed. Diffed below. See the "cross-language BIT IDENTITY" block. ----
POSTHEX_DIR=$(mktemp -d)
trap 'rm -rf "$POSTHEX_DIR"' EXIT
POSTHEX_GO="$POSTHEX_DIR/go.txt"
POSTHEX_PY="$POSTHEX_DIR/py.txt"

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
  GO_OUT=$( (cd "go/$m" && M1_POSTHEX_OUT="$POSTHEX_GO" go test -count=1 -run ConfVectors -v ./...) 2>&1 ) || { echo "$GO_OUT"; echo "FAIL: Go conformance vectors in go/$m"; exit 1; }
  echo "$GO_OUT"
  GO_OUT_ALL="$GO_OUT_ALL
$GO_OUT"
  GO_N=$((GO_N + $(echo "$GO_OUT" | grep -c '^=== RUN' || true)))
done

# ---- per-FAMILY Go coverage. A single global GO_N > 0 lets one family's tests green-light
# every other family: the receipt tests alone satisfied it while the bundle family had ZERO Go
# coverage and nothing noticed. Each EXPECTED family must run its OWN Go tests — or be declared
# pending below, printed loudly. An honest gap beats a green light over nothing. ----
GO_PENDING=""
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
PY_OUT_ALL=""
for suite in python/shared/mark1_receipts/tests python/adjudicator/tests python/intel/tests; do
  [ -d "$suite" ] || continue
  echo "conformance: python — pytest $suite -k conf_vectors"
  set +e
  # --all-packages, for the reason the justfile's build-py recipe spells out: the repo root is a
  # virtual workspace anchor with no dependencies of its own, so a bare `uv run --frozen` resolves
  # to "no changes", installs NOTHING, and pytest is simply absent. That fix landed in build-py and
  # test-py and was missed here, so the gates job died on `No module named pytest` — a cross-language
  # conformance gate that could not run the Python half at all.
  PY_OUT=$(M1_POSTHEX_OUT="$POSTHEX_PY" uv run --frozen --all-packages -m pytest "$suite" -o asyncio_mode=auto -k conf_vectors -v 2>&1)
  PY_RC=$?
  set -e
  echo "$PY_OUT"
  PY_OUT_ALL="$PY_OUT_ALL
$PY_OUT"
  case "$PY_RC" in
    0) PY_N=1 ;;
    5) ;;  # pytest exit 5 = no tests collected in this suite
    *) echo "FAIL: Python conformance vectors in $suite"; exit 1 ;;
  esac
done

# ---- per-FAMILY Python coverage, same argument as the Go loop above: a global PY_N > 0 lets
# the receipt suite green-light a family Python has never touched. Only families whose contract
# actually HAS a Python implementation are required here — fusion is ADJUDICATE, which 06 §3
# says runs in exactly two places, and Python is one of them. Families absent from PY_REQUIRED
# have no Python twin by design (m1pl/redact/bundle: Rust reference + Go), so demanding one
# would be theatre. Matching is on the `conf_vectors_<family>` token, which is why the test
# module is named test_conf_vectors_fusion.py. coverage is the band family (Go querychoke +
# Python intel, the SQL fold in between — NFR-OPERABILITY-001). ----
PY_REQUIRED="receipt fusion coverage ext"
for fam in $PY_REQUIRED; do
  # $EXPECTED is newline-separated, so a `case " $EXPECTED "` glob would never match.
  printf '%s\n' "$EXPECTED" | grep -qx "$fam" || continue
  # A pytest node id carries the FILE PATH, so a bare substring match bound a filename,
  # not a behaviour: dropping in tests/test_conf_vectors_fusion_zzrev.py containing only
  # `def test_nothing(): pass` raised this count and satisfied the gate. Two shapes count,
  # and that spoof satisfies neither: the family token as a COMPLETE identifier in the
  # module stem (receipt's functions carry no token), or as a PREFIX of the test FUNCTION
  # name after `::` (coverage: test_conf_vectors_coverage_band[...]) — the latter is the
  # same shape of claim the Go loop above makes when it matches a test NAME.
  fam_n=$(printf '%s\n' "$PY_OUT_ALL" | grep -cE "(conf_vectors_$fam[^A-Za-z0-9_].*::|::test_conf_vectors_$fam[^A-Za-z0-9]).*PASSED" || true)
  if [ "$fam_n" -eq 0 ]; then
    echo "FAIL: family $fam ran zero Python vector tests (filter -k conf_vectors, token"
    echo "      conf_vectors_$fam) — a silently uncovered family is a failed gate. Both"
    echo "      languages are required to have coverage of it, or the cross-language claim"
    echo "      is a claim about one implementation agreeing with itself."
    exit 1
  fi
  echo "conformance: python — family $fam: $fam_n vector test(s)"
done

# ---- cross-language DECISION agreement on the fusion family (D-AC clause b). Each leg
# checking its own posterior against the manifest inside a 1e-12 tolerance is NOT the
# claim 06 §3 makes. The tolerance is four orders of magnitude wider than the one-ulp gap
# between Go's pure-Go log/exp and CPython's libm, and the Chow rule compares against
# exactly A/R = 1/3 — so that gap flips `refused` to `violated` (the edge blocks a
# developer the cloud does not) while BOTH suites still pass. Both legs assert `verdict`
# exactly, with no tolerance, so "every frozen vector was decided AND passed by BOTH" is
# equality of the derived verdict between the languages. One language missing empties its
# set and fails here; a vector only one language drives fails here too. ----
if printf '%s\n' "$EXPECTED" | grep -qx fusion; then
  FUS_MAN=$(sed -n 's/^ *"name": "\([^"]*\)".*/\1/p' "$VEC/fusion/manifest.json" | sort -u)
  FUS_GO=$(printf '%s\n' "$GO_OUT_ALL" | sed -n 's/^ *--- PASS: TestConfVectorsFusion\/\([^ ]*\).*/\1/p' | sort -u)
  FUS_PY=$(printf '%s\n' "$PY_OUT_ALL" | sed -n 's/.*::test_conf_vectors_fusion\[\([^]]*\)\] PASSED.*/\1/p' | sort -u)
  [ -n "$FUS_MAN" ] || { echo "FAIL: fusion manifest names no vectors — the agreement check would be vacuous"; exit 1; }
  if [ "$FUS_GO" != "$FUS_MAN" ] || [ "$FUS_PY" != "$FUS_MAN" ]; then
    echo "FAIL: fusion verdicts are not locked ACROSS languages — every manifest vector must be"
    echo "      decided and passed by BOTH legs, or the cross-language claim is one implementation"
    echo "      agreeing with itself (D-AC clause b)."
    echo "  manifest: $(printf '%s' "$FUS_MAN" | tr '\n' ' ')"
    echo "  go:       $(printf '%s' "$FUS_GO" | tr '\n' ' ')"
    echo "  python:   $(printf '%s' "$FUS_PY" | tr '\n' ' ')"
    exit 1
  fi
  # Says what it measured and nothing more. The previous wording — "decided
  # identically" — was printed by a run in which the two legs gave
  # chow_boundary_eta_exactly_one_minus_a_over_d OPPOSITE verdicts, because this
  # block compares the SET OF PASSING TEST NAMES and never a verdict. The word
  # "identically" is earned two blocks down, by the hex diff, or not at all.
  echo "conformance: fusion — $(printf '%s\n' "$FUS_MAN" | wc -l | tr -d ' ') vector(s) driven and passed by BOTH legs"

  # ---- cross-language BIT IDENTITY on the fusion posteriors (D-AP). The family's
  # README asserts the two legs "agree BIT FOR BIT" and, until this block, NOTHING
  # enforced it: each leg checked its own posterior against the manifest inside a 1e-12
  # tolerance — about four orders of magnitude looser than an ulp at these magnitudes —
  # and `bit_identical_to` compares two vectors WITHIN one language, never across.
  # 7 of 25 vectors were measurably diverging between the legs and 6 of them were green;
  # the 7th was red only because it happened to land on a Chow boundary.
  #
  # The assertion is BETWEEN THE LEGS, never against the manifest, and that is forced:
  # the oracle rounds once in exact rationals while a float64 implementation rounds per
  # multiply, so an independent generator and a bit-comparable manifest cannot both
  # exist. Keeping the independent generator means the bit claim belongs here, where
  # both operands are floats. The verdict rides on the same line, which is also what
  # asserts a D-AQ boundary vector's verdict at all.
  [ -s "$POSTHEX_GO" ] || { echo "FAIL: the Go leg dumped no fusion posteriors — the bit-identity control would be vacuous"; exit 1; }
  [ -s "$POSTHEX_PY" ] || { echo "FAIL: the Python leg dumped no fusion posteriors — the bit-identity control would be vacuous"; exit 1; }
  sort "$POSTHEX_GO" -o "$POSTHEX_GO"
  sort "$POSTHEX_PY" -o "$POSTHEX_PY"
  if ! diff -u "$POSTHEX_GO" "$POSTHEX_PY"; then
    echo "FAIL: the two ADJUDICATE legs do NOT agree bit for bit (D-AP). Lines are"
    echo "      '<vector> <verdict> <posterior bits, big-endian IEEE-754>'; '-' is Go, '+' is"
    echo "      Python. One ulp here is a Chow threshold away from being the edge blocking a"
    echo "      developer the cloud does not — 06 §3: divergence is a CI failure, not a"
    echo "      runtime surprise."
    exit 1
  fi
  # The diff is silent about a vector that dumps on NEITHER leg, so the coverage
  # of this control has to be pinned rather than printed. Exactly one shape may
  # be absent: `expect: zero_mass`, where the two legs are contractually
  # ASYMMETRIC — Go answers the degenerate error class, Python raises — so there
  # is no shared operand to compare and a synthesised line would assert a
  # constant. Every other vector must appear. Without this an early return added
  # anywhere above the dump hook silently shrinks D-AP's reach and still prints a
  # green line.
  FUS_ZM=$(grep -c '"expect": "zero_mass"' "$VEC/fusion/manifest.json" || true)
  FUS_WANT=$(( $(printf '%s\n' "$FUS_MAN" | wc -l) - FUS_ZM ))
  FUS_GOT=$(wc -l < "$POSTHEX_GO")
  if [ "$FUS_GOT" -ne "$FUS_WANT" ]; then
    echo "FAIL: D-AP compared $FUS_GOT posterior(s); the manifest has $(printf '%s\n' "$FUS_MAN" | wc -l)"
    echo "      vector(s) of which $FUS_ZM are zero_mass, so $FUS_WANT must be dumped. A vector that"
    echo "      reaches neither dump hook is outside the bit-identity control while still counting"
    echo "      toward the line above it."
    exit 1
  fi
  echo "conformance: fusion — $FUS_GOT posterior(s) BIT-IDENTICAL across Go and Python ($FUS_ZM zero-mass vector(s) are contractually asymmetric and excluded by name)"
fi

echo "conformance: vector tests ran — rust=$RS_N go=$GO_N python_collected=$PY_N"

[ "$RS_N" -gt 0 ] || { echo "FAIL: zero Rust vector tests ran (filter conf_vectors_) — a skipped run is a failed run"; exit 1; }
[ "$GO_N" -gt 0 ] || { echo "FAIL: zero Go vector tests ran (filter ConfVectors) — a skipped run is a failed run"; exit 1; }
if [ "$(find "$VEC/receipt" -type f 2>/dev/null | wc -l | tr -d ' ')" -gt 0 ] && [ "$PY_N" -eq 0 ]; then
  echo "FAIL: receipt vectors exist but zero Python vector tests ran — the three languages are"
  echo "      supposed to be locked together from C6 (13 §1)"
  exit 1
fi

echo "conformance_crosslang: OK — $TOTAL vector file(s) agree across the implementations present"
