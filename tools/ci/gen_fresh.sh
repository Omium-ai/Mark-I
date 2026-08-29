#!/bin/sh
# gen_fresh.sh — 13 §2.4 / §5.5. Committed codegen must equal regenerated codegen.
# Regenerates via the one definition of "gen" (the justfile recipe: buf generate +
# the stage-copy into rust/m1p-wire/gen) and refuses any resulting diff.
# Hand-editing generated code is not forbidden, it is unlandable.
set -eu

cd "$(dirname "$0")/../.."
PATHS="proto/gen rust/m1p-wire/gen"

command -v just >/dev/null 2>&1 || {
  echo "FAIL: gen_fresh: 'just' not found; the justfile is the CI contract (13 §6.1)"; exit 1
}
command -v buf >/dev/null 2>&1 || {
  echo "FAIL: gen_fresh: 'buf' not found; run scripts/bootstrap.sh"; exit 1
}
# Both checks below are `git`, and outside a work tree git exits 128 with "not a
# git repository" -- which this script would report as "committed codegen differs
# from regenerated codegen". That is a true failure with a false cause, and the
# reader spends the next hour running `just gen` at a problem regeneration cannot
# reach. The precondition is separate so the message names what is actually wrong.
git rev-parse --git-dir >/dev/null 2>&1 || {
  echo "FAIL: gen_fresh: not inside a git work tree."
  echo "      This gate is defined as 'committed == regenerated', and 'committed' has"
  echo "      no meaning without a repository. It cannot degrade to a content compare:"
  echo "      the untracked-file check below exists precisely to catch generated output"
  echo "      nobody committed, and that check has no non-git equivalent."
  exit 1
}

echo "gen_fresh: regenerating m1p bindings (just gen)"
just gen

echo "gen_fresh: diffing committed vs regenerated: $PATHS"
if ! git diff --exit-code -- $PATHS; then
  echo "FAIL: committed codegen differs from regenerated codegen."
  echo "      Run 'just gen' and commit the result; never hand-edit proto/gen or rust/m1p-wire/gen."
  exit 1
fi

# git diff cannot see a NEW generated file that was never added — a new .proto whose
# output nobody committed would otherwise pass silently.
UNTRACKED=$(git ls-files --others --exclude-standard -- $PATHS)
if [ -n "$UNTRACKED" ]; then
  echo "FAIL: regeneration produced files that are not committed:"
  echo "$UNTRACKED"
  exit 1
fi

echo "gen_fresh: OK — $PATHS match buf generate output"
