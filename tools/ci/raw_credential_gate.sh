#!/bin/sh
# raw_credential_gate.sh — NFR-SECURITY-001's missing half (12 s9 row 2, ci_grep_raw_credential_types):
# refuses a credential-named struct field / let binding / fn param holding a raw String/&str/Vec<u8>/
# &[u8]/string/[]byte instead of Rust's Secret<T> or a Go typed wrapper.
set -eu

cd "$(dirname "$0")/../.."

ALLOWLIST=tools/ci/raw_credential_allowlist.txt
VOCAB='api_key|apikey|token|secret|password|credential|bearer|authorization|session_key|private_key'
TAB=$(printf '\t')

# strip <file> — blank // and /* */ comments and the contents of "..." strings, line count kept.
strip() {
  awk '
    { line=$0; out=""; instr=0; L=length(line)
      for (i=1;i<=L;i++) {
        c=substr(line,i,1); nc=substr(line,i+1,1)
        if (blk) { if (c=="*" && nc=="/") { blk=0; i++ }; continue }
        if (!instr && c=="/" && nc=="/") break
        if (!instr && c=="/" && nc=="*") { blk=1; i++; continue }
        if (!instr && c=="\"") { instr=1; continue }
        if (instr) { if (c=="\\") { i++; continue }; if (c=="\"") instr=0; continue }
        out=out c
      }
      print out
    }
  ' "$1"
}

# strip_rust_tests <file> — blank #[cfg(test)]\nmod NAME { ... } blocks; fixtures aren't credentials.
strip_rust_tests() {
  awk '
    /#\[cfg\(test\)\]/ { intest=1; print ""; next }
    intest && depth==0 {
      if ($0 ~ /mod[ \t]+[A-Za-z_]+[ \t]*\{/) { depth=1; print ""; next }
      intest=0
    }
    depth>0 {
      o=gsub(/\{/,"{"); c=gsub(/\}/,"}")
      depth+=o-c
      print ""
      if (depth<=0) depth=0
      next
    }
    { print }
  ' "$1"
}

# normalize <ident> — PascalCase/camelCase/snake_case -> snake_case, lowercase.
normalize() {
  printf '%s' "$1" | sed -E 's/([A-Z]+)([A-Z][a-z])/\1_\2/g; s/([a-z0-9])([A-Z])/\1_\2/g' | tr '[:upper:]' '[:lower:]'
}

is_vocab() { printf '_%s_' "$1" | grep -qE "_(${VOCAB})_"; }

# check_file <path> — prints "lineno<TAB>ident<TAB>type" per raw-credential-named declaration.
check_file() {
  f="$1"
  case "$f" in
    *.rs) sep='[[:space:]]*:[[:space:]]*'; types='String|Vec<u8>|&str|&\[u8\]' ;;
    *.go) sep='[[:space:]]+'; types='string|\[\]byte' ;;
    *) return 0 ;;
  esac
  pat="[A-Za-z_][A-Za-z0-9_]*${sep}(${types})\\b"
  if [ "${f##*.}" = rs ]; then
    stripped=$(strip_rust_tests "$f" | strip -)
  else
    stripped=$(strip "$f")
  fi
  printf '%s\n' "$stripped" | grep -noE "$pat" 2>/dev/null | while IFS=: read -r lineno match; do
    # `type X string` (Go) names a wrapper TYPE, not a field/let/param holding one — out of scope.
    printf '%s\n' "$stripped" | sed -n "${lineno}p" | grep -qE '^[[:space:]]*type[[:space:]]' && continue
    ident=$(printf '%s' "$match" | sed -E 's/^([A-Za-z_][A-Za-z0-9_]*).*/\1/')
    norm=$(normalize "$ident")
    is_vocab "$norm" || continue
    ty=$(printf '%s' "$match" | sed -E "s/^[A-Za-z_][A-Za-z0-9_]*${sep}//")
    printf '%s\t%s\t%s\n' "$lineno" "$ident" "$ty"
  done
}

# --- self-test: the comparator must catch what it is told to catch, before it is trusted -----
selftest() {
  d=$(mktemp -d)
  cat >"$d/scratch.rs" <<'RS'
pub struct Violation {
    api_key: String,
}
pub struct Clean {
    key: Secret<String>,
}
RS
  cat >"$d/scratch.go" <<'GO'
package scratch

type Violation struct {
	Token []byte
}
GO
  rs_out=$(check_file "$d/scratch.rs")
  go_out=$(check_file "$d/scratch.go")
  ok=1
  printf '%s\n' "$rs_out" | grep -q "${TAB}api_key${TAB}" || { echo "self-test FAIL: did not catch planted 'api_key: String' in scratch.rs" >&2; ok=0; }
  printf '%s\n' "$rs_out" | grep -q "${TAB}key${TAB}" && { echo "self-test FAIL: false-matched positive control 'key: Secret<String>' in scratch.rs" >&2; ok=0; }
  printf '%s\n' "$go_out" | grep -q "${TAB}Token${TAB}" || { echo "self-test FAIL: did not catch planted 'Token []byte' in scratch.go" >&2; ok=0; }
  rm -rf "$d"
  [ "$ok" -eq 1 ] || { echo "FAIL: raw_credential_gate self-test failed — the comparator itself is broken; no result below can be trusted." >&2; exit 1; }
  echo "raw_credential_gate: self-test OK — planted api_key: String and Token []byte caught, key: Secret<String> correctly ignored"
}

selftest

RUST_FILES=$(find rust/mark1-proxy/src rust/mark1-hookshim/src rust/cortexd/src -name '*.rs' -type f 2>/dev/null | sort)
GO_FILES=$(find go -name '*.go' -type f ! -name '*_test.go' 2>/dev/null | sort)

[ -n "$RUST_FILES" ] || { echo "FAIL: raw_credential_gate matched no Rust source under the three scanned crates — the gate is decoration." >&2; exit 1; }
[ -n "$GO_FILES" ] || { echo "FAIL: raw_credential_gate matched no Go source under go/ — the gate is decoration." >&2; exit 1; }
[ -f "$ALLOWLIST" ] || { echo "FAIL: $ALLOWLIST is missing." >&2; exit 1; }

FAILED=0
HITCOUNT=0
ALLOWCOUNT=0

for f in $RUST_FILES $GO_FILES; do
  OUT=$(check_file "$f")
  [ -n "$OUT" ] || continue
  while IFS="$TAB" read -r lineno ident ty; do
    [ -n "$lineno" ] || continue
    HITCOUNT=$((HITCOUNT + 1))
    key="$f:$ident"
    entry=$(grep -F "${key}${TAB}" "$ALLOWLIST" 2>/dev/null || true)
    if [ -n "$entry" ]; then
      ALLOWCOUNT=$((ALLOWCOUNT + 1))
      echo "raw_credential_gate: $f:$lineno ALLOWLISTED ('$ident' $ty) — ${entry#*"$TAB"}"
    else
      src=$(sed -n "${lineno}p" "$f")
      echo "FAIL: $f:$lineno — '$ident' names a credential (NFR-SECURITY-001) but holds a raw $ty, not Secret<...>/a typed wrapper:"
      echo "      $src"
      echo "      Fix: wrap it in Secret<...> (Rust) or a typed credential wrapper (Go), or add \"$key${TAB}reason\" to $ALLOWLIST if it genuinely is not one."
      FAILED=1
    fi
  done <<HITSEOF
$OUT
HITSEOF
done

[ "$FAILED" -eq 0 ] || exit 1
echo "raw_credential_gate: OK — $HITCOUNT raw-credential-named declaration(s) found, $ALLOWCOUNT allow-listed, 0 unexplained"
