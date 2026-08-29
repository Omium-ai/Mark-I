#!/bin/sh
# override_pattern_gate.sh — 13 §7.5 gate 3, enforcing 04 §3.1 step 4:
# "No override path is compiled into the binary." There is no env var, config key, CLI flag,
# bundle section, or debug build feature that causes forwarding of an unprovisioned credential.
#
# 12's negative test proves the binary that exists refuses; this gate refuses the source
# patterns that would build a different binary. Two-sided claim, both sides mechanical.
set -eu

cd "$(dirname "$0")/../.."

CRATE=rust/mark1-proxy
# The override-name vocabulary from 04 §3.1(4).
NAMES='bypass|override|allow_unprovisioned|skip_guard|insecure|no_guard'
# The three ways a name becomes a runtime switch: build feature, environment, CLI flag.
SWITCHES='(cfg|cfg_attr)!?[[:space:]]*\([[:space:]]*feature|env::var|option_env!|#\[[[:space:]]*(arg|clap|command)'

FAILED=0
DEFERRED=0

RS_FILES=$(find "$CRATE" -name '*.rs' -type f 2>/dev/null | sort)
if [ -z "$RS_FILES" ]; then
  echo "override_pattern_gate: no sources under $CRATE yet — nothing to scan"
  DEFERRED=1
else
  echo "override_pattern_gate: scanning $(echo "$RS_FILES" | wc -l | tr -d ' ') file(s) under $CRATE"
  M=$(echo "$RS_FILES" | xargs grep -inE "$SWITCHES" 2>/dev/null | grep -iE "$NAMES" || true)
  if [ -n "$M" ]; then
    echo "FAIL: guard-override switch in $CRATE (04 §3.1 step 4 — no override path is compiled in):"
    echo "$M"
    FAILED=1
  fi
fi

# A Cargo feature is a switch too, even before any code reads it.
MANIFEST="$CRATE/Cargo.toml"
if [ -f "$MANIFEST" ]; then
  M=$(awk '/^\[features\]/{f=1;next} /^\[/{f=0} f' "$MANIFEST" | grep -inE "$NAMES" || true)
  if [ -n "$M" ]; then
    echo "FAIL: guard-override feature declared in $MANIFEST:"
    echo "$M"
    FAILED=1
  fi
  echo "override_pattern_gate: checked [features] in $MANIFEST"
else
  echo "override_pattern_gate: $MANIFEST (absent, skipped)"
  DEFERRED=1
fi

if [ "$FAILED" -ne 0 ]; then
  echo "An operator escape hatch converts a legal guarantee into a policy, and policies get"
  echo "overridden under deadline pressure. If you believe you need one, you need an ADR first."
  exit 1
fi

# "OK" here asserts a property of the proxy's source. Over an empty $CRATE there is
# no source to have the property, and printing OK would make this gate the thing it
# exists to prevent: a claim about a binary, made by a check that never read one.
# 12's negative test is the other side of the two-sided claim (04 §3.1 step 4) and it
# is equally absent until the crate lands; both sides arrive together or neither does.
# Non-zero exit is deliberately NOT used — the gate is green on an empty tree by
# design, exactly like secret_type_gate and otel_gate — but green is not the same
# word as OK, and the difference is the whole point.
if [ "$DEFERRED" -ne 0 ]; then
  echo "override_pattern_gate: PARTIAL — $CRATE has no sources; the 04 §3.1(4) no-override"
  echo "                       property was NOT verified. This becomes OK when the crate lands."
  exit 0
fi

echo "override_pattern_gate: OK — no /$NAMES/ switch in $CRATE"
