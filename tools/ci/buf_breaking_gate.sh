#!/bin/sh
# buf_breaking_gate.sh — FR-SPINE-002. The wire is the compatibility contract: an event
# uploaded months ago must still decode, because receipts and billing ledgers are keyed on
# fields that shipped then. `buf breaking` at WIRE_JSON is the only thing standing between a
# careless .proto edit and data that can never be re-collected.
#
# That check was invoked in exactly two places (justfile `lint-proto`, ci.yml's `gen` job) and
# NOTHING HAD EVER SEEN IT GO RED. A gate nobody has watched fail is indistinguishable from a
# gate that cannot fail — this repo has already shipped that once (RECONCILIATION FIX-05:
# override_pattern_gate.sh printing OK over an empty crate). So this gate does not assert that
# the wire is compatible; `lint-proto` does that. It asserts that the ASSERTION WORKS, by
# breaking the wire on purpose in a scratch copy and requiring buf to notice.
#
# FIVE LEGS, because "buf exited non-zero" is not the same claim as "buf caught a break":
#
#   1 BREAK      delete a field with no `reserved` — must be REJECTED, naming the rule.
#   2 ADDITIVE   add a field with a fresh number  — must be ACCEPTED.
#   3 REMEDY     delete a field reserving BOTH number and name — must be ACCEPTED.
#   4 LEVEL      delete a field reserving only the NUMBER — must be REJECTED here, and the
#                SAME candidate re-run at `use: [WIRE]` must be ACCEPTED.
#   5 DECLARED   proto/buf.yaml's configured rule set must be the WIRE_JSON one by name.
#
# WHY 2 AND 3 ARE MANDATORY, NOT DECORATION. Leg 1 alone is satisfied by a buf that errors on
# everything: a syntax error in the scratch copy, a bad --against path, a missing binary, a
# module that no longer resolves. Every one of those exits non-zero and would let leg 1 report
# "break correctly detected" while detecting nothing. Legs 2 and 3 are the same buf, the same
# config, the same baseline, on changes that MUST pass — so a red there means the harness is
# broken, and a green there means leg 1's red was a verdict rather than a crash. A gate that
# cannot tell "correctly detected a break" from "buf is broken" is the exact disease this file
# exists to cure.
#
# WHY LEG 4 IS THE LEVEL CHECK AND NOT A GREP. FR-SPINE-002 names WIRE_JSON specifically, and
# the difference from the laxer WIRE is one rule: FIELD_NO_DELETE_UNLESS_NAME_RESERVED is in
# WIRE_JSON and not in WIRE. So a deletion that reserves the number but not the name is invisible
# at WIRE and fatal at WIRE_JSON — it is the exact discriminator, and running it BOTH ways in one
# breath is a demonstration rather than a claim. Leg 5 still exists because a config of
# `use: [CSR]` would pass all four behavioural legs (CSR contains both rules) while not being the
# level the requirement names.
#
# proto/ IS FROZEN AND THIS GATE NEVER WRITES TO IT. Every mutation happens on a copy under
# $TMPDIR; proto/ is only ever the read-only `--against` baseline. The fingerprint at the bottom
# proves it on every run, so this property cannot rot without going red.
#
# The baseline is the WORKING TREE, deliberately not `.git#branch=main` as lint-proto uses.
# This gate's subject is the checker, not the branch: a git-ref baseline would make it fail on a
# shallow clone, on a fork whose default branch is named otherwise, and on any tree with no .git
# at all — none of which says anything about whether buf can detect a broken wire.
set -eu

cd "$(dirname "$0")/../.."

FAILED=0
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

PROTO=proto
FROZEN="$PROTO/m1p $PROTO/buf.yaml $PROTO/buf.lock"

# The frozen surface, before anything runs. Compared again at the bottom. Scoped to what buf
# reads and what a mutation could plausibly touch — proto/gen/ is codegen output owned by
# gen_fresh.sh, and hashing its __pycache__ would make this gate flaky for an unrelated reason.
fingerprint() { find $FROZEN -type f | LC_ALL=C sort | xargs cksum; }
fingerprint > "$TMP/proto.before"

# ---------------------------------------------------------------------------------------------
# Precondition: buf itself.
# ---------------------------------------------------------------------------------------------
if ! command -v buf > /dev/null 2>&1; then
  # Nothing below can run, so this is a total skip rather than a partial one. In CI it is a
  # failure: the `gen` job installs buf via bufbuild/buf-setup-action, so an absent binary there
  # means the job changed shape and FR-SPINE-002's evidence was not produced on that run.
  # Same posture as verifier_offline_gate.sh, for the same reason.
  echo "buf_breaking_gate: SKIPPED — buf is not on PATH, so nothing about the breaking-change" >&2
  echo "                   check was observed. Install: https://buf.build/docs/installation" >&2
  if [ -n "${CI:-}" ]; then
    echo "" >&2
    echo "FAIL: that is a hard failure in CI (\$CI is set). This lane owes FR-SPINE-002 the" >&2
    echo "      evidence that \`buf breaking\` can actually go red, and it produced none." >&2
    exit 1
  fi
  exit 0
fi

# ---------------------------------------------------------------------------------------------
# Pick the mutation target off the tree, not out of this file.
# ---------------------------------------------------------------------------------------------
# A hardcoded file:line goes stale the first time anyone edits a .proto above it, and a gate that
# mutates the wrong line is a gate that stopped testing what it says. awk, not grep -n | head:
# awk walks its argv in order and `exit` stops the whole run, so the pick is deterministic.
#
# The pattern is a top-level scalar field at exactly two-space indent — never `repeated`, never
# `optional`, never a oneof member (four-space here), so deleting it trips the delete rules and
# nothing else. `$2` is the name, `$4` the number with its semicolon.
PICK=$(awk '
  /^  (bool|bytes|double|fixed32|fixed64|float|int32|int64|sfixed32|sfixed64|sint32|sint64|string|uint32|uint64) [a-z][a-z0-9_]* = [0-9]+;$/ {
    num = $4; sub(/;$/, "", num); print FILENAME, FNR, $2, num; exit
  }' "$PROTO"/m1p/v1/*.proto)

if [ -z "$PICK" ]; then
  echo "FAIL: no plain scalar field found anywhere in $PROTO/m1p/v1/*.proto, so this gate could"
  echo "      not construct a breaking change and proved nothing. Either the protos moved or the"
  echo "      field pattern in this script no longer matches how they are written."
  exit 1
fi
SRC=$(echo "$PICK" | cut -d' ' -f1)
LINE=$(echo "$PICK" | cut -d' ' -f2)
FNAME=$(echo "$PICK" | cut -d' ' -f3)
FNUM=$(echo "$PICK" | cut -d' ' -f4)
REL=${SRC#"$PROTO"/}
echo "buf_breaking_gate: mutating a COPY of $PROTO — subject is $REL:$LINE ($FNAME = $FNUM)"

# 536870911 is protobuf's maximum legal field number: guaranteed unused by any real message here,
# outside the 19000-19999 reserved block, and it needs no arithmetic over the existing numbers.
PROBE_NUM=536870911

# ---------------------------------------------------------------------------------------------
# Harness.
# ---------------------------------------------------------------------------------------------
CAND="$TMP/cand"

candidate() { # candidate <sed-script> — fresh copy of proto/ with one line rewritten
  rm -rf "$CAND"
  cp -R "$PROTO" "$CAND"
  sed -i "$1" "$CAND/$REL"
  # A sed that matched nothing leaves the copy identical to the baseline, and an identical
  # candidate passes every leg trivially — the inert-gate failure mode in miniature. Require the
  # mutation to have landed before believing any verdict about it.
  if cmp -s "$SRC" "$CAND/$REL"; then
    echo "FAIL: the mutation '$1' did not change $REL at all, so the leg that follows would have"
    echo "      compared the baseline against itself."
    exit 1
  fi
}

RC=0
breaking() { # breaking [extra buf args...] — run the check, leave output in $TMP/out
  set +e
  buf breaking "$CAND" --against "$PROTO" --error-format=json "$@" > "$TMP/out" 2>&1
  RC=$?
  set -e
}

show() { sed 's/^/        /' "$TMP/out"; }

expect_reject() { # expect_reject <leg> <rule-id> <why>
  if [ "$RC" -eq 0 ]; then
    echo "FAIL: [$1] buf breaking ACCEPTED a change that breaks the wire. $3"
    echo "        The check is inert: it would accept this on a real PR too, and FR-SPINE-002's"
    echo "        guarantee that an already-uploaded event stays decodable is not being enforced"
    echo "        by anything. Do not silence this gate — find out why buf stopped objecting."
    FAILED=1
  elif ! grep -q "\"$2\"" "$TMP/out"; then
    # Non-zero for the wrong reason — a parse error, an unresolvable module, a moved config —
    # is not a detection. Requiring the rule ID by name is what keeps leg 1 from being satisfied
    # by a buf that simply cannot read the tree.
    echo "FAIL: [$1] buf breaking exited $RC, but not for $2. It failed for some other"
    echo "      reason, so nothing here shows the breaking-change rules ran at all:"
    show
    FAILED=1
  else
    echo "buf_breaking_gate: [$1] rejected, $2 — $3"
  fi
}

expect_accept() { # expect_accept <leg> <why>
  if [ "$RC" -ne 0 ]; then
    echo "FAIL: [$1] buf breaking REJECTED a change that is compatible. $2"
    echo "        Every other leg here is worthless until this is green: a buf that errors on"
    echo "        everything satisfies the negative legs while detecting nothing. This is far"
    echo "        more likely to be a broken harness — bad config, bad --against path, a module"
    echo "        that no longer resolves — than a real finding:"
    show
    FAILED=1
  else
    echo "buf_breaking_gate: [$1] accepted — $2"
  fi
}

# ---------------------------------------------------------------------------------------------
# 1 BREAK — a field deleted with no `reserved` at all.
# ---------------------------------------------------------------------------------------------
# The rule asserted is the WIRE-level one (…UNLESS_NUMBER_RESERVED): a break this coarse must be
# caught at ANY configured level, so leg 1 stays meaningful even if leg 4 is what is failing.
candidate "${LINE}d"
breaking
expect_reject BREAK FIELD_NO_DELETE_UNLESS_NUMBER_RESERVED \
  "'$FNAME' deleted outright; field $FNUM would silently re-bind to whatever is added next."

# ---------------------------------------------------------------------------------------------
# 2 ADDITIVE — positive control. A new field on a fresh number.
# ---------------------------------------------------------------------------------------------
candidate "${LINE}a\\  string m1p_gate_probe = $PROBE_NUM;"
breaking
expect_accept ADDITIVE "a new field on fresh number $PROBE_NUM is compatible, and buf says so."

# ---------------------------------------------------------------------------------------------
# 3 REMEDY — positive control, and FR-SPINE-002's prescribed path for a real deletion.
# ---------------------------------------------------------------------------------------------
# Leg 1 proves the requirement's prohibition is enforced; this proves its REMEDY is reachable.
# Without it a buf that rejected reserved-and-all would be a gate telling engineers to do
# something it then refuses, and they would learn to route around this file.
candidate "${LINE}c\\  reserved $FNUM;\\n  reserved \"$FNAME\";"
breaking
expect_accept REMEDY "deleting '$FNAME' with both \`reserved $FNUM;\` and \`reserved \"$FNAME\";\` is allowed."

# ---------------------------------------------------------------------------------------------
# 4 LEVEL — the configured level is strictly above WIRE.
# ---------------------------------------------------------------------------------------------
# Number reserved, name not. Invisible at WIRE, fatal at WIRE_JSON — so this one candidate,
# judged twice, separates the two levels by observation. It also matters on its own terms: the
# name is what JSON-encoded receipts key on, so re-using it re-namespaces already-collected data
# even though the binary wire is untouched.
candidate "${LINE}c\\  reserved $FNUM;"
breaking
expect_reject LEVEL FIELD_NO_DELETE_UNLESS_NAME_RESERVED \
  "'$FNAME' deleted reserving only the number; the JSON name is left free to be re-used."

# The contrast. Same candidate, same baseline, same binary — only the level differs. If this
# ALSO fails, the leg above proved nothing about the level: some rule outside WIRE_JSON was
# firing and the two configurations are not being distinguished.
breaking --config '{"version":"v2","breaking":{"use":["WIRE"]}}'
if [ "$RC" -ne 0 ]; then
  echo "FAIL: [LEVEL] the same candidate was rejected at \`use: [WIRE]\` too, so the leg above did"
  echo "      not demonstrate anything about WIRE_JSON — something unrelated is failing:"
  show
  FAILED=1
else
  echo "buf_breaking_gate: [LEVEL] the identical candidate is ACCEPTED at \`use: [WIRE]\` — so the"
  echo "                   rejection above came from the configured level, which is above WIRE."
fi

# ---------------------------------------------------------------------------------------------
# 5 DECLARED — the level is the one FR-SPINE-002 names.
# ---------------------------------------------------------------------------------------------
# Behavioural legs only prove "at least as strict as WIRE_JSON". `use: [CSR]` or `[FILE]` would
# pass all four and still not be what the requirement says. Ask buf what it resolved rather than
# grepping YAML, so a module-path or config-precedence change cannot hide here.
if ! ( cd "$PROTO" && buf config ls-breaking-rules --configured-only ) > "$TMP/rules" 2>&1; then
  echo "FAIL: [DECLARED] could not read the configured breaking rules from $PROTO/buf.yaml:"
  sed 's/^/        /' "$TMP/rules"
  FAILED=1
elif ! grep -qE '^[[:space:]]*-[[:space:]]*WIRE_JSON[[:space:]]*$' "$PROTO/buf.yaml"; then
  echo "FAIL: [DECLARED] $PROTO/buf.yaml does not use WIRE_JSON. FR-SPINE-002 names that level"
  echo "      exactly; the checks above only establish 'at least as strict as', and a stricter"
  echo "      level chosen by accident is still a level nobody agreed to. Declared rules:"
  sed 's/^/        /' "$TMP/rules"
  FAILED=1
else
  N=$(grep -c 'WIRE_JSON' "$TMP/rules" || true)
  echo "buf_breaking_gate: [DECLARED] $PROTO/buf.yaml uses WIRE_JSON; $N of the resolved rules"
  echo "                   carry that category."
fi

# ---------------------------------------------------------------------------------------------
# proto/ is frozen. Prove this run left it alone.
# ---------------------------------------------------------------------------------------------
# Not paranoia about the code above — it is the one property that makes this gate safe to run
# anywhere, including on a dirty tree mid-review, and it is checked rather than asserted for the
# same reason as everything else in this file.
fingerprint > "$TMP/proto.after"
if ! diff -u "$TMP/proto.before" "$TMP/proto.after" > "$TMP/frozen.diff"; then
  echo "FAIL: this gate MODIFIED the frozen proto surface. Every mutation belongs on the copy"
  echo "      under \$TMPDIR; proto/ is only ever the read-only --against baseline."
  sed -n '3,$p' "$TMP/frozen.diff" | sed 's/^/        /'
  FAILED=1
else
  echo "buf_breaking_gate: $PROTO/{m1p,buf.yaml,buf.lock} byte-identical to the pre-run checksums."
fi

# ---------------------------------------------------------------------------------------------
if [ "$FAILED" -ne 0 ]; then
  echo ""
  echo "FR-SPINE-002: the breaking-change check runs at WIRE_JSON, deleted fields are reserved,"
  echo "and a genuinely breaking change becomes m1p.v2 rather than an in-place edit. Customers'"
  echo "receipts and billing ledgers are keyed on fields that shipped months ago and cannot be"
  echo "re-collected. If this gate is in your way, the wire is in your way — open the v2 package."
  exit 1
fi

echo "buf_breaking_gate: OK — a deleted field is caught, a compatible change is not, and the"
echo "                   configured level is demonstrably WIRE_JSON and not WIRE."
