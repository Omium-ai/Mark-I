#!/bin/sh
# shapley_gate.sh — 12 §7.5's `unit_no_shapley_symbol`, enforcing FR-SPINE-022:
# "No Shapley code may exist before ADR-0003." A Shapley value is only as meaningful as the
# cooperative game (N, v) it is computed over, ADR-0003 is the document that defines that game,
# and it is unsigned — so a Shapley number shipped today is an authoritative-looking figure with
# no defined meaning, in a product whose entire identity is "every number traces to a ledger
# query". The deterministic taxonomy ships alone until the game is defined.
#
# Until now the ban existed only as prose (`python/intel/app/tvo/waste.py:7` and the test module
# docstring), which is the same as not existing: `conformance/traceability.yaml:60` carries a
# `partial:` for exactly this row.
#
# WHY THIS IS NOT A GREP. The word's only occurrences in the tree are the two sentences
# DECLARING the ban, so `grep -ri shapley` is red on a clean checkout and would be deleted on
# day one. The requirement bans a SYMBOL, not a word — 02 §427: "no Shapley symbol exists in
# the codebase". So the gate strips comment and docstring PROSE and greps what is left, which is
# code. String VALUES are deliberately kept: a literal "shapley" in a channel list or a column
# name is an implementation, a sentence in a docstring is not.
#
# The stripper's error direction is the safe one. Anything it fails to strip stays visible to
# the grep, so a stripper bug is a loud false positive, never a silent pass — and the
# self-test below refuses to report OK unless the stripper demonstrably ran and reclassified
# a real prose occurrence on this very run.
set -eu

cd "$(dirname "$0")/../.."

# --- applicability, read from the ADR rather than asserted here ------------------------------
# The ban is conditional on ADR-0003 being unsigned. Hardcoding "banned" would leave this gate
# still refusing Shapley code the day the founder signs the game definition, and a gate that
# forbids something now sanctioned is a gate someone deletes under deadline — taking the
# requirement with it. So the condition is read from the document that owns it.
ADR=docs/adr/0003-shapley-game-definition.md
if [ ! -f "$ADR" ]; then
  echo "FAIL: $ADR is missing. This gate's ban is conditional on that ADR being unsigned, so"
  echo "      without it the gate cannot know whether it still applies, and a pass would mean"
  echo "      nothing. Either the path moved or the ADR was deleted."
  exit 1
fi
STATUS=$(sed -n 's/^- \*\*Status:\*\* *//p' "$ADR" | head -1)
case "$STATUS" in
  '')
    echo "FAIL: no '- **Status:**' line parsed from $ADR — this gate derives its applicability"
    echo "      from that line and just derived nothing."
    exit 1 ;;
  Proposed*) ;;
  *)
    echo "FAIL: ADR-0003's status is now '$STATUS' — no longer Proposed."
    echo "      FR-SPINE-022's ban is conditional on that ADR being unsigned. If the game is now"
    echo "      defined, Shapley code is permitted and this gate is asserting a rule that no"
    echo "      longer exists: retire it from the justfile together with 02 §94's ban sentence,"
    echo "      deliberately and in one PR. Do not weaken it in place."
    exit 1 ;;
esac

# --- the scan ---------------------------------------------------------------------------------
# Code only. Prose lives in docs/ and in the comments this gate strips; markdown and YAML are
# not scanned because a requirement, an ADR and a traceability note all discuss the ban by name
# and none of them can compute anything.
FILES=$(find go rust python tools proto migrations bench scripts \
          \( -name '*.py' -o -name '*.go' -o -name '*.rs' -o -name '*.sql' -o -name '*.proto' \) \
          -type f ! -path '*/target/*' ! -path '*/.venv/*' 2>/dev/null | sort)

[ -n "$FILES" ] || {
  echo "FAIL: shapley_gate matched no source files — the gate is decoration. Either the tree"
  echo "      layout moved or the find expression above stopped selecting anything."
  exit 1
}

# Per-language floors: the find above spans three ecosystems, and losing one of them to a moved
# directory would still leave $FILES non-empty and this gate quietly half-blind.
for e in py go rs; do
  printf '%s\n' "$FILES" | grep -q "\.$e\$" || {
    echo "FAIL: shapley_gate scanned no .$e file. FR-SPINE-022 bans the symbol in the codebase,"
    echo "      not in two thirds of it."
    exit 1
  }
done

strip_prose() { # strip_prose <file> — same file, comment and docstring PROSE blanked.
  # Lines are blanked rather than dropped so grep line numbers still address the real file.
  awk -v ext="${1##*.}" '
    BEGIN { q3 = sprintf("%c%c%c", 39, 39, 39) }   # the triple-apostrophe, unwritable inline
    ext == "py" {
      if (doc != "") {
        p = index($0, doc)
        if (p) { print substr($0, p + 3); doc = "" } else { print "" }
        next
      }
      t = $0; sub(/^[ \t]*[rRbBuUfF]*/, "", t)
      # A triple quote in STATEMENT position opens a docstring. One after `=` or `(` is a
      # string value and stays: this gate bans a symbol, and a value is one.
      if (substr(t, 1, 3) == "\"\"\"" || substr(t, 1, 3) == q3) {
        d = substr(t, 1, 3)
        if (index(substr(t, 4), d) == 0) doc = d
        print ""
        next
      }
      sub(/#.*/, ""); print; next
    }
    ext == "sql" { sub(/--.*/, ""); print; next }
    {   # go, rs, proto
      if (blk) { if (sub(/.*\*\//, "")) blk = 0; else { print ""; next } }
      gsub(/\/\*[^*]*\*\//, "")
      if (sub(/\/\*.*/, "")) blk = 1
      sub(/\/\/.*/, ""); print
    }
  ' "$1"
}

FAILED=0
PROSE_RECLASSIFIED=0

echo "== shapley symbols =="
for f in $FILES; do
  # A file NAMED for it is an implementation before a single line is read.
  case "$f" in
    *[Ss]hapley*)
      echo "FAIL: $f — a source file named for Shapley. ADR-0003 is unsigned."
      FAILED=1 ;;
  esac

  grep -qi shapley "$f" || continue
  HITS=$(strip_prose "$f" | grep -in shapley || true)
  if [ -n "$HITS" ]; then
    echo "FAIL: Shapley symbol in $f (FR-SPINE-022: no Shapley code before ADR-0003):"
    printf '%s\n' "$HITS" | sed "s|^|        $f:|"
    FAILED=1
  else
    # The word is here and it is prose. Announced, because this is the gate proving on this
    # run that it can tell an implementation from its own prohibition.
    echo "shapley_gate: $f — mentions Shapley in prose only (the ban declaring itself)"
    PROSE_RECLASSIFIED=$((PROSE_RECLASSIFIED + 1))
  fi
done

if [ "$FAILED" -ne 0 ]; then
  echo "The deterministic waste taxonomy is the audit-grade floor and ships alone. Shapley needs"
  echo "ADR-0003 signed — players and v(S) written down — before any of it is written, because a"
  echo "Shapley value over an undefined game is a number that cannot be defended to a customer."
  exit 1
fi

if [ "$PROSE_RECLASSIFIED" -eq 0 ]; then
  # Not a failure — nobody is obliged to mention Shapley. But this run proved only that no file
  # contains the string, which is also what a broken stripper, an empty find and a `grep` typo
  # all produce. Say so, rather than printing an OK that four dead gates in this repo's history
  # would also have printed.
  echo "shapley_gate: PARTIAL — no file mentions Shapley at all, so the prose-vs-symbol" >&2
  echo "              distinction that is this gate's entire mechanism was never exercised." >&2
  echo "              Green here is indistinguishable from a stripper that blanks everything." >&2
  echo "              The two declarations at python/intel/app/tvo/waste.py and" >&2
  echo "              python/intel/tests/test_waste.py used to supply that exercise; if they" >&2
  echo "              were deleted, the ban now has neither prose nor a working check." >&2
  exit 0
fi

echo "shapley_gate: OK — no Shapley symbol in any scanned source; $PROSE_RECLASSIFIED prose"
echo "              mention(s) correctly reclassified, so the stripper ran and discriminated."
