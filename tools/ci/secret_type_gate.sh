#!/bin/sh
# secret_type_gate.sh — 13 §7.5 gate 2 (plan §Compliance 2). The Secret<T> newtype must stay
# unprintable, unserializable, and unopenable outside its own module.
#
# This is a grep gate BY DESIGN, not a poor cousin of the type system: the type system enforces
# the property inside the compiler's view; the grep refuses the diffs that would change what the
# compiler is asked to enforce.
#
# It guards credential custody, so a false green here is a leak that CI blessed. Every branch
# below therefore either scans something or names, in tree terms, the condition that makes the
# skip illegal — a skip with no expiry condition is how this gate goes quietly decorative.
set -eu

cd "$(dirname "$0")/../.."

FAILED=0
DEFERRED=0
report() { # report <message> <matches>
  if [ -n "$2" ]; then
    echo "FAIL: $1"
    echo "$2"
    FAILED=1
  fi
}

# Every .rs in the tree, not just rust/: a crate once lived under tools/ and `find rust` let `cred.0` there
# pass green. The file set is read off the tree so no crate can be added to the build and left out of this gate.
RS_FILES=$(find . -name '*.rs' -type f -not -path '*/target/*' 2>/dev/null | sed 's|^\./||' | sort)
DECLARED=''

if [ -z "$RS_FILES" ]; then
  echo "secret_type_gate: no Rust sources yet (no *.rs anywhere in the tree) — nothing to scan"
else
  echo "secret_type_gate: scanning $(echo "$RS_FILES" | wc -l | tr -d ' ') Rust source file(s)"

  # -H on every rule below: xargs may hand grep a single file, and grep then omits the filename —
  # a FAIL reporting a line number in no file at all.

  # 1. No manual Debug/Display/Serialize impls for Secret. Anything may sit between `impl` and
  #    the trait: Secret is generic, so the real-world form is `impl<T: Bound> fmt::Debug for
  #    Secret<T>` and a pattern anchored on `impl[[:space:]]+Trait` never fires at all. The path
  #    prefix is left open for the same reason — fmt::Debug and std::fmt::Debug both count.
  M=$(echo "$RS_FILES" | xargs grep -HnE \
    'impl[^;{]*[[:space:]]([A-Za-z_][A-Za-z0-9_:]*::)?(Debug|Display|Serialize)[[:space:]]+for[[:space:]]+Secret' \
    2>/dev/null || true)
  report "manual Debug/Display/Serialize impl for Secret — the whole point is that it has none" "$M"

  # 2. No derived Debug/Serialize on the Secret struct itself (derive sits within 2 lines of it).
  M=$(echo "$RS_FILES" | xargs grep -HnE -B2 'struct[[:space:]]+Secret' 2>/dev/null \
    | grep -E 'derive\([^)]*(Debug|Serialize)' || true)
  report "derive(Debug|Serialize) on struct Secret" "$M"

  # 3. No .0 escapes outside secret.rs — the inner value is reachable only through the module's
  #    sealed expose_for_upstream() path.
  #
  #    The doc's pattern is a bare '\.0\b', which matches every float literal in the workspace.
  #    A previous revision answered that by narrowing the PATTERN to '[Ss]ecret[A-Za-z0-9_]*\.0',
  #    which only fires when the receiver is spelled "secret" — so `let k = cfg.api_key; k.0`,
  #    `token.0` and `self.inner.0` all read the inner value past a green gate. Narrow the FILE
  #    SET instead: only files that mention Secret can hold a Secret binding, and within those
  #    the receiver's name is not evidence of anything.
  #
  #    ']' leads the bracket expression (POSIX: literal there) so the class is ] A-Z a-z _ ) —
  #    a field access on an identifier, index or call, which is what excludes `1.0` and `2.0f32`.
  #
  #    False positive on an unrelated tuple index? Destructure it (`let (lhs, _) = pair;`) or
  #    move it out of a Secret-bearing file. If a real exception ever exists, exclude the PATH
  #    here with the reason written next to it — never widen the receiver pattern again, because
  #    that changes what the gate means without changing what it claims.
  SECRET_FILES=$(echo "$RS_FILES" | xargs grep -l 'Secret' 2>/dev/null || true)
  ESCAPE_FILES=$(echo "$SECRET_FILES" | grep -v '/secret\.rs$' || true)
  if [ -n "$ESCAPE_FILES" ]; then
    # Say what was covered. Rules 1-3 all pass by finding nothing, so a rule that skipped its
    # whole file set is indistinguishable from a clean one unless the count is on the record.
    echo "secret_type_gate: rule 3 over $(echo "$ESCAPE_FILES" | wc -l | tr -d ' ') Secret-bearing file(s) outside secret.rs"
    M=$(echo "$ESCAPE_FILES" | xargs grep -HnE '[]A-Za-z_)]\.0\b' 2>/dev/null || true)
    report "inner-value escape (.0) outside secret.rs — use expose_for_upstream()" "$M"
  else
    echo "secret_type_gate: rule 3 has no subject matter — no file outside secret.rs mentions Secret."
  fi

  DECLARED=$(echo "$RS_FILES" | xargs grep -l -E 'struct[[:space:]]+Secret' 2>/dev/null || true)
fi

# Subject-matter tripwire. Rules 1-3 are all "no match found", so they pass identically whether
# the newtype is correct or absent. mark1-proxy is the process that holds upstream credentials:
# once it has any Rust source, a Secret declaration must exist for those rules to be checking
# anything at all. Read off the tree, so the deferral expires without an edit here.
if [ -n "$DECLARED" ]; then
  echo "secret_type_gate: Secret declared in $(echo "$DECLARED" | tr '\n' ' ')"
elif find rust/mark1-proxy -name '*.rs' -type f 2>/dev/null | grep -q .; then
  echo "FAIL: rust/mark1-proxy has Rust sources but no file declares a Secret type — rules 1-3"
  echo "      above matched nothing because there is nothing to match. Credentials in the proxy"
  echo "      must be held in the Secret newtype (plan §Compliance 2)."
  FAILED=1
else
  echo "secret_type_gate: no Secret type yet — rules 1-3 have no subject matter."
  echo "           Becomes a hard failure the moment this is true: rust/mark1-proxy contains Rust source."
  DEFERRED=1
fi

# 4. Absence check: deleting the drop-guard must be as loud as printing the secret.
PROXY_MANIFEST=rust/mark1-proxy/Cargo.toml
if [ ! -f "$PROXY_MANIFEST" ]; then
  # mark1-proxy is a declared workspace member, so its manifest is committed source; missing
  # means the path moved and this gate was not updated, not that the check does not apply yet.
  echo "FAIL: $PROXY_MANIFEST is missing — this gate can no longer see the proxy's dependencies."
  FAILED=1
elif grep -qE '^[[:space:]]*zeroize[[:space:]]*(=|\.)' "$PROXY_MANIFEST"; then
  echo "secret_type_gate: zeroize present in $PROXY_MANIFEST"
else
  echo "FAIL: zeroize is not a dependency of mark1-proxy — the Secret drop-guard is gone"
  FAILED=1
fi

[ "$FAILED" -eq 0 ] || exit 1
[ "$DEFERRED" -eq 0 ] || { echo "secret_type_gate: PARTIAL — manifest checks only; no Secret type exists to guard."; exit 0; }
echo "secret_type_gate: OK"
