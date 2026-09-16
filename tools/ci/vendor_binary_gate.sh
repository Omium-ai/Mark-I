#!/bin/sh
# vendor_binary_gate.sh — CON-003: "Mark 1 must not modify any vendor binary." Integration is
# exactly hooks, MCP, config includes, transcripts and (API-key regime only) the wire. This is
# the clause the entire legal posture rests on: modifying a vendor binary breaches the vendors'
# terms and destroys the "what did you change" audit answer that makes the product sellable.
#
# WHAT THIS GATE CAN AND CANNOT PROVE, stated up front because the honest split IS the design.
# 02 §386's acceptance is "vendor binaries hash-identical before/after install" — a RUNTIME
# property of a machine that has the vendor agent installed. A CI runner has no `claude` on it,
# so a gate here that claimed to have verified hash identity would be exactly the defect this
# repo keeps shipping: a check that looks like proof and is not.
#
# So the claim is split, and only the first half is asserted here:
#   STATIC (this gate, hard failure) — no code path in the repo can modify a vendor binary,
#     because no resolved binary path is ever passed to a mutating filesystem call. Modifying a
#     binary requires holding its path and then writing through it; this gate refuses the second
#     step wherever the first one happened. That is a property of committed source, so it is
#     fully decidable here and needs no vendor installed.
#   RUNTIME (NOT this gate) — `neg_vendor_binary_hash_identical`, hashing the real binary either
#     side of `mark1 enable`. It does not exist anywhere in the tree; the gate says so on every
#     run and stops saying it the moment a test carries the name.
#
# Not to be confused with `TestRunOneTamperOnSwappedBinary`, which hashes an ANCHOR sandbox tool
# (repo-supplied, consent-pinned) and is about anchor integrity, not the vendor clause.
set -eu

cd "$(dirname "$0")/../.."

FAILED=0

# The two ways source comes to hold a path to an already-installed executable. Tests are excluded
# deliberately: anchors' tamper tests WRITE a swapped binary into a temp dir on purpose, and that
# is the negative test proving detection works, not a violation of it.
DISCOVERY='exec\.LookPath\(|shutil\.which\(|which::which\('
# The struct-field spelling the anchors plane uses for an already-resolved executable path
# (internal/anchors/catalog.go:69, consent.go:34, doc.go:37). Tracked by name because a field is
# not an assignment and the parser below would otherwise never see it.
FIELDS='BinaryPath|binary_path'
# Mutation, across all three languages. Reads, stats, hashes and execs are absent by design:
# Mark 1 may hash and may run a vendor binary, it may never write one.
MUTATORS='os\.(Create|OpenFile|WriteFile|Truncate|Chmod|Chown|Rename|Remove|RemoveAll|Symlink|Link)\(|ioutil\.WriteFile\(|fs::(write|remove_file|remove_dir_all|rename|copy|hard_link|set_permissions)\(|File::create\(|OpenOptions::|shutil\.(copy|copy2|copyfile|move|rmtree)\(|\.(write_bytes|write_text|unlink|chmod|rename|replace)\(|open\([^)]*["'"'"'][^"'"'"']*[wax+]'

SRC=$(find go rust python tools \( -name '*.go' -o -name '*.rs' -o -name '*.py' \) \
        -type f ! -path '*/target/*' ! -path '*/.venv/*' ! -name '*_test.go' \
        ! -name '*_test.py' ! -name 'test_*.py' ! -path '*/tests/*' 2>/dev/null | sort)

[ -n "$SRC" ] || {
  echo "FAIL: vendor_binary_gate matched no source files — the gate is decoration."
  exit 1
}

# Identifiers bound from a discovery call, per file. Parsed rather than listed, so a new
# resolution site anywhere in the tree is covered on arrival instead of on remembering.
bound_idents() {
  awk '
    /exec\.LookPath\(|shutil\.which\(|which::which\(/ {
      n = index($0, "=")
      if (!n) next
      lhs = substr($0, 1, n - 1)
      gsub(/:/, " ", lhs)                       # go '\''s :=
      sub(/^[ \t]*/, "", lhs)
      sub(/^(else[ \t]+)?if[ \t]+/, "", lhs)   # go'\''s `if p, err := exec.LookPath(...)`: the keyword is not a binding
      sub(/^let[ \t]+/, "", lhs); sub(/^mut[ \t]+/, "", lhs); sub(/^var[ \t]+/, "", lhs)
      split(lhs, p, /[ \t,]+/)
      for (i in p) if (p[i] ~ /^[A-Za-z_][A-Za-z0-9_]*$/ && p[i] != "err") print p[i]
    }
  ' "$1" | sort -u
}

TRACKED=0
SITES=''
VENDOR_SITES=0

echo "== resolved binary paths =="
for f in $SRC; do
  IDENTS=$(bound_idents "$f")
  # A file naming the field convention holds a resolved path even without an assignment here.
  if grep -qE "$FIELDS" "$f"; then
    IDENTS=$(printf '%s\nBinaryPath\nbinary_path\n' "$IDENTS" | grep -v '^$' | sort -u)
  fi
  [ -n "$IDENTS" ] || continue

  case "$f" in go/mark1d/adapters/*) VENDOR_SITES=$((VENDOR_SITES + 1)) ;; esac
  SITES="$SITES $f"
  for id in $IDENTS; do
    TRACKED=$((TRACKED + 1))
    # A mutating call on the same line as a tracked path expression. Line-scoped rather than
    # file-scoped on purpose: adapters legitimately write the user's CONFIG file (08 §8's fenced
    # fragment) in the same file that resolves the vendor binary, and a file-level rule would
    # either fail on that or have to carve out an exception someone later widens.
    M=$(grep -nE "$MUTATORS" "$f" | grep -wE "$id" || true)
    if [ -n "$M" ]; then
      echo "FAIL: $f writes through a resolved binary path '$id' (CON-003: no vendor binary"
      echo "      modification, ever):"
      printf '%s\n' "$M" | sed "s|^|        $f:|"
      FAILED=1
    fi
  done
  echo "vendor_binary_gate: $f — holds $(printf '%s' "$IDENTS" | wc -w | tr -d ' ') resolved path(s), none written through"
done

if [ "$TRACKED" -eq 0 ]; then
  echo "FAIL: vendor_binary_gate tracked no resolved binary path in any non-test source."
  echo "      It proves 'a held path is never written through' by finding the places a path is"
  echo "      held; finding none means it just proved nothing about every file it read. Either"
  echo "      resolution moved to a spelling the parser above does not know (exec.LookPath,"
  echo "      shutil.which, which::which, or a *BinaryPath field), or the tree moved."
  exit 1
fi

if [ "$FAILED" -ne 0 ]; then
  echo "Mark 1's integration surface is exactly: hooks, MCP, config includes/extensions,"
  echo "transcripts, and — API-key regime only — the wire. A vendor binary is read, hashed and"
  echo "executed, never written. This is a legal boundary, not a preference: there is no ADR"
  echo "that can authorise it, because the terms it breaches are not ours to amend."
  exit 1
fi

# --- the half this gate cannot assert ---------------------------------------------------------
# Self-clearing by construction: the moment a TEST carries the name, this block goes quiet.
# No allowlist, nothing to remember to delete.
#
# Test files only, and tools/ is not searched at all — the first version of this line searched
# the whole tree and cleared itself on the comment 40 lines above, which is the same self-match
# that makes a naive grep gate green on its own documentation. A control is discharged by a
# test that runs, never by a sentence naming it. conformance/traceability.yaml is excluded for
# the same reason: it currently carries a `partial:` for this row, and a gate that reads a claim
# of coverage as coverage is the defect it exists to catch.
RUNTIME=$(grep -rl 'neg_vendor_binary_hash_identical' go rust python conformance \
            --include='*_test.go' --include='test_*.py' --include='*_test.py' \
            --include='*.rs' --include='*.json' 2>/dev/null || true)

if [ "$VENDOR_SITES" -eq 0 ]; then
  echo "vendor_binary_gate: PARTIAL — no non-test file under go/mark1d/adapters/ resolves a" >&2
  echo "                    vendor binary. The static claim above is then true of code that" >&2
  echo "                    never touches a vendor binary, which is not the same claim." >&2
fi

if [ -z "$RUNTIME" ]; then
  echo "vendor_binary_gate: PARTIAL — the static half holds ($TRACKED resolved path(s) across"
  echo "                    $(printf '%s' "$SITES" | wc -w | tr -d ' ') file(s), none written through), but 02 §386's actual acceptance —"
  echo "                    'vendor binaries hash-identical before/after install' — is UNPROVEN."
  echo "                    \`neg_vendor_binary_hash_identical\` (12 §455) exists nowhere in the"
  echo "                    tree. It cannot run here: no vendor agent is installed on a CI"
  echo "                    runner, so it belongs to the enrolled-machine conformance lane."
  echo "                    Until it lands, CON-003 is asserted against SOURCE, not against a"
  echo "                    binary — and \`TestRunOneTamperOnSwappedBinary\` is not it, that one"
  echo "                    hashes an anchor sandbox tool."
  exit 0
fi

echo "vendor_binary_gate: OK — $TRACKED resolved binary path(s), none written through, and"
echo "                    neg_vendor_binary_hash_identical is present: $RUNTIME"
