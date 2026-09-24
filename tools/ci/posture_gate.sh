#!/bin/sh
# posture_gate.sh -- CON-007's missing check: "the LLD posture tables exist but nothing checks
# a Posture column is present in each or that observed behaviour matches a row." 04 Sec.10 and
# 05 Sec.9 are the two failure-mode catalogs with both a Posture column (frozen matrix: open for
# availability, static for policy, closed for legality/secrets -- 04 Sec.0.2, 05 Sec.9 header,
# 12 Sec.0.4) and a per-row test slug 12 owns (adoption rule, 12 Sec.0.4: `12/` prefix drops,
# dashes become underscores in the implementing language).
#
# Two independent checks, because CON-007 names two different gaps:
#   (a) POSTURE     every row's Posture cell must carry a value from the closed set.
#   (b) TEST SLUG    every row's backticked test slug must resolve to a real test somewhere in
#                     the tree, or be a reviewed, reasoned backlog entry in the allow-list.
set -eu

cd "$(dirname "$0")/../.."
ROOT=.
ALLOWLIST=tools/ci/posture_allowlist.txt
DOCS="docs/design/04-lld-edge.md docs/design/05-lld-cloud.md"
TAB=$(printf '\t')

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# --- the one table parser, shared by the self-test and the real scan --------------------------
# A "posture table" is any markdown table whose header row has a column named exactly Posture
# (case-insensitive) AND another column whose name starts with "test". Anything else --
# 04's short Sec.3.5 Failure/Posture pair has no test column and is out of scope on that basis.
cat > "$TMP/extract.awk" <<'AWK'
function trim(s) { gsub(/^[ \t]+|[ \t]+$/, "", s); return s }
BEGIN { state = 0 }
{
  line = $0
  if (state == 0) {
    if (line ~ /^\|/ && tolower(line) ~ /\|[ \t]*posture[ \t]*\|/ && tolower(line) ~ /test/) {
      n = split(line, cells, "|")
      posture_idx = 0; test_idx = 0
      for (i = 1; i <= n; i++) {
        c = tolower(trim(cells[i]))
        if (c == "posture") posture_idx = i
        if (c ~ /^test/) test_idx = i
      }
      if (posture_idx > 0 && test_idx > 0) { state = 1; next }
    }
    next
  }
  if (state == 1) { state = 2; next }  # the |---|---| separator row, unread
  if (state == 2) {
    if (line ~ /^\|/) {
      n = split(line, cells, "|")
      rowid = trim(cells[2]); gsub(/\*/, "", rowid)
      posture = trim(cells[posture_idx])
      test = trim(cells[test_idx])
      gsub(/\t/, " ", rowid); gsub(/\t/, " ", posture); gsub(/\t/, " ", test)
      printf "%s\t%s\t%s\n", rowid, posture, test
      next
    } else {
      state = 0
    }
  }
}
AWK
extract_table() { awk -f "$TMP/extract.awk" "$1"; }  # -> rowid<TAB>posture<TAB>test per row

# --- posture check (a): closed set is open / static / closed, anywhere in the cell ------------
# Bounded by non-letters rather than \b -- \b is a GNU extension this repo's other gates avoid
# (verifier_offline_gate's NETSYMS comment explains why). Case-insensitive: docs mix "open" and
# "**open --". Every doc value seen (fail-open, fails closed, static (per section), open (capture)
# / closed (egress) ...) contains one of the three bare words; a row that names no closed-set
# word at all -- "integrity", "refusal", "n/a", "Refusal-by-design", a cross-reference to another
# row's posture with no word of its own -- is exactly the gap CON-007 names.
posture_ok() { printf '%s' "$1" | grep -qiE '(^|[^A-Za-z])(open|static|closed)($|[^A-Za-z])'; }

# --- test slug (b): extract, adopt (12 Sec.0.4), resolve -----------------------------------------
normalize_slug() {
  raw=$(printf '%s' "$1" | sed -n 's/[^`]*`\([^`]*\)`.*/\1/p' | head -n1)
  [ -n "$raw" ] || { printf ''; return 0; }
  raw=${raw#12/}
  printf '%s' "$raw" | tr '-' '_'
}

fuzzy() { printf '%s' "$1" | tr -dc 'A-Za-z' | tr 'A-Z' 'a-z'; }

# build_index <root> -- every candidate test-ish identifier in the tree, fuzzy-normalized
# (letters only, lowercase) so a digit inserted mid-name (TestChaosProxyKill9MidStream for the
# slug chaos_proxy_kill_midstream) or a case seam doesn't produce a false gap. One awk pass over
# the whole candidate stream, not a shell loop, so this stays fast at repo scale.
build_index() {
  root="$1"
  {
    [ -d "$root/go" ] && grep -rhoE '^func[ \t]+Test[A-Za-z0-9_]+' "$root/go" --include='*_test.go' --exclude-dir=target 2>/dev/null | sed -E 's/^func[ \t]+Test//'
    [ -d "$root/go" ] && grep -rhoE 't\.Run\(["`][^"`]+["`]' "$root/go" --include='*_test.go' --exclude-dir=target 2>/dev/null | sed -E 's/^t\.Run\(["`]//'
    [ -d "$root/rust" ] && grep -rhoE '\bfn[ \t]+[A-Za-z0-9_]+' "$root/rust" --include='*.rs' --exclude-dir=target 2>/dev/null | sed -E 's/^fn[ \t]+//'
    [ -d "$root/python" ] && grep -rhoE '\bdef[ \t]+test_[A-Za-z0-9_]+' "$root/python" --include='*.py' --exclude-dir=.venv 2>/dev/null | sed -E 's/^def[ \t]+//'
    [ -d "$root/conformance/e2e" ] && grep -rhoE '\bdef[ \t]+test_[A-Za-z0-9_]+' "$root/conformance/e2e" --include='*.py' --exclude-dir=__pycache__ 2>/dev/null | sed -E 's/^def[ \t]+//'
    true
  } | awk '{ s=$0; gsub(/[^A-Za-z]/, "", s); if (length(s) > 0) print tolower(s) }' | LC_ALL=C sort -u
}

# resolve_slug <slug> <index-file> <justfile> -- 0 if a real test or a named justfile recipe
# answers this slug. The index covers go func Test*, go t.Run subtests, rust fn, python def
# test_ (incl. conformance/e2e); the justfile leg is a literal substring match, because a
# chaos_* recipe there is invoked by its exact slug spelling, not a mangled one.
resolve_slug() {
  slug="$1"; idx="$2"; jf="$3"
  key=$(fuzzy "$slug")
  [ -n "$key" ] || return 1
  if grep -qxF "$key" "$idx" 2>/dev/null; then return 0; fi
  if [ -f "$jf" ] && grep -qF "$slug" "$jf" 2>/dev/null; then return 0; fi
  return 1
}

# ------------------------------------------------------------------------------------------------
# self-test: plants both defect classes on a scratch fixture and requires the SAME functions
# above (not a reimplementation) to catch them, before any of them is trusted on the real docs.
selftest() {
  d="$TMP/selftest"
  mkdir -p "$d/go/pkgx" "$d/conformance/e2e"
  cat > "$d/fixture.md" <<'EOF'
## Scratch

| # | Failure | Detection | Posture | Effect | Recovery | Test in 12 |
|---|---|---|---|---|---|---|
| S-01 | clean, resolvable | x | open | y | z | `12/scratch-clean-row` |
| S-02 | planted bad posture | x | mystery | y | z | `12/scratch-clean-row` |
| S-03 | planted unresolved, no allow-list entry | x | closed | y | z | `12/scratch-missing-row` |
| S-04 | unresolved but allow-listed | x | static | y | z | `12/scratch-allowlisted-row` |
EOF
  cat > "$d/go/pkgx/scratch_test.go" <<'EOF'
package pkgx

import "testing"

func TestScratchCleanRow(t *testing.T) {}
EOF
  cat > "$d/scratch_allow.txt" <<EOF
$d/fixture.md:S-04:scratch_allowlisted_row${TAB}self-test fixture, deliberately unresolved
EOF
  build_index "$d" > "$d/index.txt"

  seen_s01=0; seen_s02=0; seen_s03=0; seen_s04=0
  while IFS="$TAB" read -r rowid posture test; do
    [ -n "$rowid" ] || continue
    slug=$(normalize_slug "$test")
    case "$rowid" in
      S-01)
        seen_s01=1
        posture_ok "$posture" || { echo "self-test FAIL: S-01's clean Posture 'open' was rejected -- posture_ok is broken" >&2; exit 1; }
        resolve_slug "$slug" "$d/index.txt" "$d/justfile" || { echo "self-test FAIL: S-01's real planted TestScratchCleanRow did not resolve -- resolve_slug's positive path is broken" >&2; exit 1; }
        ;;
      S-02)
        seen_s02=1
        posture_ok "$posture" && { echo "self-test FAIL: S-02's planted bad Posture 'mystery' was accepted -- posture_ok does not red on a real defect" >&2; exit 1; }
        ;;
      S-03)
        seen_s03=1
        resolve_slug "$slug" "$d/index.txt" "$d/justfile" && { echo "self-test FAIL: S-03's planted-missing slug resolved to something that is not there" >&2; exit 1; }
        grep -F "$d/fixture.md:S-03:$slug$TAB" "$d/scratch_allow.txt" >/dev/null 2>&1 && { echo "self-test FAIL: S-03 unexpectedly matched the scratch allow-list" >&2; exit 1; }
        ;;
      S-04)
        seen_s04=1
        resolve_slug "$slug" "$d/index.txt" "$d/justfile" && { echo "self-test FAIL: S-04's planted slug unexpectedly resolved without needing the allow-list" >&2; exit 1; }
        grep -F "$d/fixture.md:S-04:$slug$TAB" "$d/scratch_allow.txt" >/dev/null 2>&1 || { echo "self-test FAIL: S-04's allow-list entry did not match -- the allow-list lookup is broken" >&2; exit 1; }
        ;;
    esac
  done <<TBL
$(extract_table "$d/fixture.md")
TBL
  [ "$seen_s01" -eq 1 ] && [ "$seen_s02" -eq 1 ] && [ "$seen_s03" -eq 1 ] && [ "$seen_s04" -eq 1 ] || {
    echo "self-test FAIL: extract_table did not yield all four planted rows -- the parser itself is broken" >&2
    exit 1
  }
  echo "posture_gate: self-test OK -- planted bad posture caught, planted unresolved+unlisted slug caught,"
  echo "              a real planted test resolved, an allow-listed unresolved slug matched"
}

selftest

# ------------------------------------------------------------------------------------------------
[ -f "$ALLOWLIST" ] || { echo "FAIL: $ALLOWLIST is missing." >&2; exit 1; }

echo "== indexing go/rust/python/conformance test names =="
build_index "$ROOT" > "$TMP/index.txt"
N_IDX=$(wc -l < "$TMP/index.txt" | tr -d ' ')
[ "$N_IDX" -gt 50 ] || { echo "FAIL: the test-name index has only $N_IDX entries -- it read almost nothing. Check the grep roots." >&2; exit 1; }
echo "posture_gate: indexed $N_IDX candidate test identifiers"

FAILED=0
TOTAL=0
ALLOWCOUNT=0

for f in $DOCS; do
  [ -f "$f" ] || { echo "FAIL: $f is missing -- this gate's whole scope is the two named LLDs." >&2; FAILED=1; continue; }
  ROWS_THIS=0
  while IFS="$TAB" read -r rowid posture test; do
    [ -n "$rowid" ] || continue
    ROWS_THIS=$((ROWS_THIS + 1))
    TOTAL=$((TOTAL + 1))

    if ! posture_ok "$posture"; then
      echo "FAIL: $f row '$rowid' -- Posture cell '$posture' carries no value from the closed set (open/static/closed)."
      FAILED=1
    fi

    slug=$(normalize_slug "$test")
    if [ -z "$slug" ]; then
      echo "FAIL: $f row '$rowid' -- Test column has no backticked test slug at all: '$test'"
      FAILED=1
      continue
    fi
    if resolve_slug "$slug" "$TMP/index.txt" "$ROOT/justfile"; then
      continue
    fi
    key="$f:$rowid:$slug"
    entry=$(grep -F "${key}${TAB}" "$ALLOWLIST" 2>/dev/null || true)
    if [ -n "$entry" ]; then
      ALLOWCOUNT=$((ALLOWCOUNT + 1))
      echo "posture_gate: $key ALLOWLISTED -- ${entry#*"$TAB"}"
    else
      echo "FAIL: $f row '$rowid' -- test slug '$slug' resolves to nothing in go/rust/python/conformance/justfile,"
      echo "      and is not in $ALLOWLIST. Add the test, or add \"$key${TAB}reason\" to the allow-list."
      FAILED=1
    fi
  done <<TBL
$(extract_table "$f")
TBL
  [ "$ROWS_THIS" -gt 0 ] || { echo "FAIL: $f -- extract_table found zero posture-table rows. Either the table moved or the parser broke." >&2; FAILED=1; }
  echo "posture_gate: $f -- $ROWS_THIS row(s) checked"
done

[ "$TOTAL" -gt 50 ] || { echo "FAIL: only $TOTAL row(s) were checked across both docs -- expected well over 50. The gate is reading almost nothing." >&2; exit 1; }

if [ "$FAILED" -ne 0 ]; then
  echo ""
  echo "CON-007: every LLD failure-mode row must carry a Posture from the frozen matrix and a test"
  echo "slug that resolves. This is real: fix the doc's Posture wording (docs are frozen for this"
  echo "gate to touch) or land/point to the missing test; a slug that is a genuine, reasoned backlog"
  echo "item belongs in $ALLOWLIST, never a silently-widened match here."
  exit 1
fi

echo "posture_gate: OK -- $TOTAL row(s) across ${DOCS}, every Posture in the closed set, every test"
echo "               slug resolved ($ALLOWCOUNT allow-listed)."
