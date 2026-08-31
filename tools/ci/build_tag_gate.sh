#!/bin/sh
# build_tag_gate.sh — D-CB. Every Go build tag in the tree must be documented in the justfile's
# build-tag inventory.
#
# `go test ./...` cannot see a tag-gated file, so a tag is the one edit that removes a suite from
# a run while leaving every recipe, every job name and every exit code exactly as they were. The
# justfile has carried an inventory against precisely that since the beginning — and it listed
# `integration` and `chaos` and nothing else, while nine platform-tagged files (six `unix`, three
# `linux`/`!linux`) were hiding most of `mark1d`'s suite from `go (windows-2022)`. That leg had
# never compiled, so nothing was red, so nobody looked. Three phases closed that way.
#
# The lesson is not "write better comments". A hand-maintained inventory is an ENUMERATION, and
# D-BY already recorded what enumerations do: they decay on the next edit, silently. So this gate
# derives the tag set FROM THE TREE and checks the inventory against it. A new tag fails here
# until someone writes down what it hides and which recipe or CI leg still runs it. Renaming or
# moving a tagged file changes nothing, because no path is named below.
#
# It ALSO runs that comparison backwards, which the first version did not, and said so in this
# comment as though it were a design position (D-CG). It was not — it was the same blind spot one
# level up. Deriving from the tree catches a tag no one wrote down; it is structurally incapable
# of catching a tag written down that no file carries, and the justfile had one: `chaos`,
# described as a "fast set selected by the chaos harness" that does not exist. That row is the
# only artifact making `chaos_daemon_kill9` — NFR-DURABILITY-002, P0, Phase-1 green-required —
# look wired. D-BN's rule is that a gate which cannot catch the thing that broke is decoration,
# and the justfile itself already states the property at its own line 129: "the inventory above
# is a claim about tags in files that exist."
#
# A phantom row WARNS rather than fails, following lint-py's precedent: it is an unbacked claim,
# not a broken build, and failing here would only get the row deleted by whoever is unblocking
# CI — which is how an unmet P0 goes quiet (D-CA). Announced on every run, it self-clears the
# moment the first file carries the tag, so it needs no allowlist and cannot become an excuse.
set -eu

cd "$(dirname "$0")/../.."

FAILED=0

# --- the claim: what the justfile says it knows about --------------------------------------
# Bounded by the inventory's own heading and the recipe it guards, so a block that gets moved
# or renamed reads as absent (and fails) rather than as empty (and passes vacuously).
INVENTORY=$(awk '/^# Build-tag inventory:/{f=1} f{print} f && /^test-go:/{exit}' justfile)
if [ -z "$INVENTORY" ]; then
  echo "FAIL: no build-tag inventory found in justfile."
  echo "      This gate compares the tree against that block; without it there is nothing to"
  echo "      compare against and a pass would mean nothing. Expected a '# Build-tag inventory:'"
  echo "      comment immediately above the test-go recipe."
  exit 1
fi

# --- the fact: what is actually in the tree -------------------------------------------------
[ -d go ] && find go -name '*.go' -type f | grep -q . || {
  echo "FAIL: no .go files under go/ — this gate derives its tag set from that tree, so it just"
  echo "      scanned nothing. Either the layout moved or the gate is now decoration."
  exit 1
}

# Both spellings: gofmt keeps //go:build and the legacy // +build in sync, and a file carrying
# only the old form is still tag-gated.
TAG_LINES=$(grep -rhn --include='*.go' -e '^//go:build' -e '^// +build' go || true)
TAGS=$(printf '%s\n' "$TAG_LINES" \
  | sed -e 's|^[0-9]*:||' -e 's|^//go:build||' -e 's|^// +build||' \
  | tr '(),|&!' ' ' \
  | tr ' \t' '\n' \
  | grep -v '^$' \
  | sort -u)

if [ -z "$TAGS" ]; then
  echo "build_tag_gate: OK — no Go build tags in the tree, so nothing can be hidden by one."
  exit 0
fi

# --- compare ---------------------------------------------------------------------------------
echo "== go build tags =="
for t in $TAGS; do
  # Word-boundary match: `unix` must not be satisfied by the word "unix" appearing inside prose
  # about something else, but backticks, commas and end-of-word all count as documented.
  if printf '%s\n' "$INVENTORY" | grep -qE "(^|[^[:alnum:]_-])$t([^[:alnum:]_-]|$)"; then
    n=$(printf '%s\n' "$TAG_LINES" | grep -cE "(^|[^[:alnum:]_-])$t([^[:alnum:]_-]|$)" || true)
    echo "build_tag_gate: $t — documented ($n file(s))"
  else
    echo "FAIL: build tag '$t' appears in go/ but is absent from the justfile inventory:"
    printf '%s\n' "$TAG_LINES" | grep -E "(^|[^[:alnum:]_-])$t([^[:alnum:]_-]|$)" | sed 's/^/        /'
    echo "      A tag nobody writes down is a tag nobody audits. Add it to the inventory above"
    echo "      test-go with the recipe or CI leg that still runs what it hides — and if it hides"
    echo "      a suite from a platform leg, say which, because that leg will stay green either way."
    FAILED=1
  fi
done

[ "$FAILED" -eq 0 ] || exit 1

# --- the same comparison, backwards -----------------------------------------------------------
# Inventory rows are `#   <tag> -> <what runs it>`, so the declared name is what precedes the
# arrow. Parsing the row shape rather than scanning prose is what keeps a tag mentioned in a
# sentence from reading as a declaration.
DECLARED=$(printf '%s\n' "$INVENTORY" \
  | sed -n 's|^#[[:space:]]\{1,\}\([A-Za-z0-9_.-]\{1,\}\)[[:space:]]*->.*|\1|p' \
  | sort -u)

for d in $DECLARED; do
  printf '%s\n' "$TAGS" | grep -qx "$d" && continue
  echo "build_tag_gate: PHANTOM — the inventory declares '$d' but no file in go/ carries it." >&2
  echo "      A row here is a claim that a suite exists and something runs it. This one selects" >&2
  echo "      nothing, so the recipe it names runs an empty set and reports success by never" >&2
  echo "      executing. Either land the files or strike the row — but if the row is standing in" >&2
  echo "      for an unbuilt requirement, striking it deletes the evidence, so check first." >&2
done

echo "build_tag_gate: OK — every build tag in go/ is accounted for in the justfile inventory."
