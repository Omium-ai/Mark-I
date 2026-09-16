#!/bin/sh
# crush_reserved_gate.sh -- FR-AGENT-016: go/mark1d/adapters/crush/ is a reserved name and
# nothing else until a go/no-go spike exists. Package doc (adapters/adapter.go:5) says "a slot
# opens only when its spike fixture lands in conformance/"; the Roster row itself
# ({"crush", "", false, "roadmap"}) is the other half -- Implemented stays false until then.
# Neither half had a CI check (the FR-AGENT-016 ledger row: "nothing would go red if code
# landed in crush/ tomorrow"). Two checks:
#   (a) go/mark1d/adapters/crush/ holds no non-doc file (anything but *.md).
#   (b) the Roster's crush row's Implemented flag is false, UNLESS docs/spikes/crush-*.md
#       exists -- the go/no-go spike that is allowed to flip it.
set -eu

cd "$(dirname "$0")/../.."
ROOT=.
ADAPTER_GO=go/mark1d/adapters/adapter.go
CRUSH_DIR=go/mark1d/adapters/crush

# --- shared checks, used by both the self-test and the real scan ------------------------------

# crush_dir_clean <dir> -- prints any non-*.md file found; empty output means clean.
crush_dir_clean() { find "$1" -type f ! -iname '*.md' 2>/dev/null; }

# roster_implemented <adapter.go-like file> -- prints the crush row's Implemented literal
# (true/false), or nothing if the row cannot be found at all.
roster_implemented() {
  line=$(grep -m1 '{"crush"' "$1" 2>/dev/null) || return 0
  printf '%s' "$line" | awk -F',' '{ v=$3; gsub(/^[ \t]+|[ \t]+$/, "", v); print v }'
}

# spike_exists <root> -- 0 if a docs/spikes/crush-*.md go/no-go spike has landed.
spike_exists() { ls "$1"/docs/spikes/crush-*.md >/dev/null 2>&1; }

# ------------------------------------------------------------------------------------------------
selftest() {
  d=$(mktemp -d)
  trap 'rm -rf "$d"' EXIT

  mkdir -p "$d/clean/crush" "$d/dirty/crush" "$d/dirty/docs/spikes" "$d/promoted/docs/spikes"
  echo "# notes" > "$d/dirty/crush/notes.md"
  printf 'package crush\n' > "$d/dirty/crush/crush.go"

  cat > "$d/adapter_false.go" <<'EOF'
var Roster = []Slot{
	{"claudecode", "B", true, "1"},
	{"crush", "", false, "roadmap"},
}
EOF
  cat > "$d/adapter_true_no_spike.go" <<'EOF'
var Roster = []Slot{
	{"crush", "A", true, "6"},
}
EOF
  cat > "$d/adapter_true_with_spike.go" <<'EOF'
var Roster = []Slot{
	{"crush", "A", true, "6"},
}
EOF
  : > "$d/promoted/docs/spikes/crush-go-no-go.md"

  # (a) clean dir has nothing to report; dirty dir's planted .go file is caught
  [ -z "$(crush_dir_clean "$d/clean/crush")" ] || { echo "self-test FAIL: an empty crush/ was reported dirty" >&2; exit 1; }
  out=$(crush_dir_clean "$d/dirty/crush")
  case "$out" in
    *crush.go*) : ;;
    *) echo "self-test FAIL: planted crush/crush.go was not caught by crush_dir_clean" >&2; exit 1 ;;
  esac
  case "$out" in
    *notes.md*) echo "self-test FAIL: a *.md file was wrongly flagged as non-doc" >&2; exit 1 ;;
  esac

  # (b) Implemented:false never needs a spike; Implemented:true does
  [ "$(roster_implemented "$d/adapter_false.go")" = "false" ] || { echo "self-test FAIL: did not read Implemented=false off the planted Roster row" >&2; exit 1; }
  [ "$(roster_implemented "$d/adapter_true_no_spike.go")" = "true" ] || { echo "self-test FAIL: did not read Implemented=true off the planted Roster row" >&2; exit 1; }
  spike_exists "$d/dirty"    && { echo "self-test FAIL: spike_exists found a spike that was never planted" >&2; exit 1; }
  spike_exists "$d/promoted" || { echo "self-test FAIL: spike_exists missed the planted docs/spikes/crush-go-no-go.md" >&2; exit 1; }

  # end-to-end: Implemented=true with no spike must be flagged as the real violation this gate exists for
  if [ "$(roster_implemented "$d/adapter_true_no_spike.go")" = "true" ] && ! spike_exists "$d/dirty"; then
    : # this is the planted defect the gate must catch -- confirmed reachable
  else
    echo "self-test FAIL: the planted Implemented=true/no-spike defect was not reachable by the two checks together" >&2
    exit 1
  fi
  # and the promoted case (Implemented=true + a real spike) must NOT be flagged
  if [ "$(roster_implemented "$d/adapter_true_with_spike.go")" = "true" ] && spike_exists "$d/promoted"; then
    : # legitimately promoted, must not fail
  else
    echo "self-test FAIL: a legitimately spiked+promoted crush row would have been wrongly flagged" >&2
    exit 1
  fi

  trap - EXIT
  rm -rf "$d"
  echo "crush_reserved_gate: self-test OK -- planted non-doc file caught, *.md left alone, Implemented=true"
  echo "                      without a spike caught, Implemented=true with a real spike left alone"
}

selftest

# ------------------------------------------------------------------------------------------------
FAILED=0

[ -d "$CRUSH_DIR" ] || { echo "FAIL: $CRUSH_DIR does not exist -- this gate's whole premise is a reserved-but-present directory." >&2; exit 1; }
[ -f "$ADAPTER_GO" ] || { echo "FAIL: $ADAPTER_GO does not exist -- cannot read the Roster." >&2; exit 1; }

NONDOC=$(crush_dir_clean "$CRUSH_DIR")
if [ -n "$NONDOC" ]; then
  echo "FAIL: $CRUSH_DIR holds non-doc file(s) -- FR-AGENT-016 requires reserved-name-only until"
  echo "      a go/no-go spike lands at docs/spikes/crush-*.md:"
  printf '%s\n' "$NONDOC" | sed 's/^/        /'
  FAILED=1
else
  echo "crush_reserved_gate: $CRUSH_DIR holds no non-doc file"
fi

IMPL=$(roster_implemented "$ADAPTER_GO")
if [ -z "$IMPL" ]; then
  echo "FAIL: no {\"crush\", ...} row found in $ADAPTER_GO's Roster -- either it was renamed or" >&2
  echo "      removed; this gate needs a deliberate update, not a silent pass." >&2
  FAILED=1
elif [ "$IMPL" = "true" ]; then
  if spike_exists "$ROOT"; then
    echo "crush_reserved_gate: Roster's crush row is Implemented:true, backed by a docs/spikes/crush-*.md go/no-go spike -- OK"
  else
    echo "FAIL: $ADAPTER_GO's Roster flips crush's Implemented to true with no docs/spikes/crush-*.md"
    echo "      go/no-go spike on disk. FR-AGENT-016: this flag stays false until that spike lands."
    FAILED=1
  fi
elif [ "$IMPL" = "false" ]; then
  echo "crush_reserved_gate: Roster's crush row is Implemented:false -- OK"
else
  echo "FAIL: $ADAPTER_GO's crush row Implemented field is '$IMPL', neither true nor false --" >&2
  echo "      the Roster line shape changed under this gate; update it deliberately." >&2
  FAILED=1
fi

[ "$FAILED" -eq 0 ] || exit 1
echo "crush_reserved_gate: OK -- crush/ is reserved-name-only and Implemented:false has no unspiked promotion"
