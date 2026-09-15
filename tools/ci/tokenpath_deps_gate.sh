#!/bin/sh
# tokenpath_deps_gate.sh — NFR-SECURITY-008 (P1, Phase 1): "Dependencies on token/hook paths
# must be vendored and pinned; the shim's dependency tree is minimal by review." Acceptance
# (02 §599): "Vendored/pinned manifest for shim + proxy token paths; unpinned addition fails
# review gate." The ledger's residual was "the vendored-manifest clause for the shim and proxy
# token paths is unsatisfied" — nothing named the closure of either binary, so a `cargo add`
# on the hook path or the token path was reviewed only if a reviewer happened to open
# Cargo.lock. 10 §8.1 says a new dependency on that path "is a security review, not a
# `cargo add`"; this gate is what makes that sentence enforceable rather than aspirational.
#
# THE TWO SUBJECTS. mark1-hookshim IS the hook path (04 §5: the synchronous, config-less shim
# every agent hook execs). mark1-proxy IS the token path (04 §3: the only process that holds
# the upstream credential in memory and puts it on the wire). Everything in either binary's
# resolved graph runs with that credential or that hook's file access, so the whole graph is
# the review surface, not the direct-dependency lines a human typed.
#
# INTERPRETATION OF "VENDORED AND PINNED" — read this before arguing with the gate. This
# estate has no `cargo vendor` directory and never had one. What it has is Cargo.lock, which
# pins every crate to an exact version AND a registry checksum, and a build that is `--locked`
# everywhere it matters (justfile build-rust, .github/workflows/ci.yml, release.yml's
# per-triple `cargo build --release --locked`). A `--locked` build against a checksummed
# lockfile cannot resolve a crate the lockfile does not name, and cannot accept a registry
# blob whose checksum drifted — which is the property vendoring buys, minus the copy of the
# source in-tree. So "vendored and pinned" is satisfied by the LOCKFILE plus THIS gate: the
# lockfile pins, and this gate makes the pinned set for each subject crate a reviewed,
# checked-in artifact that a PR must diff to change. A NEW crate in either closure is a red
# build that names the crate — that is the "unpinned addition fails review gate" clause,
# literally. (02's word "vendored" may want a doc reconciliation to say this; that is a docs
# decision, not this script's.)
#
# "MINIMAL BY REVIEW" is a human judgement and stays one. What this gate contributes is the
# number and the trend: the closure size is printed on every run and the reviewed baselines
# are recorded here, so a future diff to either list is read against a known size rather than
# against nothing. Reviewed baseline at the time this gate landed (Cargo.lock of 2026-09-15):
#
#     mark1-hookshim   68 crates   (tools/ci/tokenpath_deps_hookshim.txt)
#     mark1-proxy     143 crates   (tools/ci/tokenpath_deps_proxy.txt)
#
# A PR that moves either number UP has added a crate to a credential-bearing process and owes
# the reviewer a sentence about why. A PR that moves it DOWN is the good kind.
#
# MECHANISM — copied, not reinvented, from tools/ci/verifier_offline_gate.sh mechanism 1
# (CLOSURE), which already does exactly this for mark1-verifier: `cargo tree` over the
# lockfile, `--target all` so the list is the union over every shipped triple and not the
# host's, `--offline` after a `cargo fetch --locked` so a cold runner has the Windows-only
# crates the host build never pulled, versions stripped (a version bump is not a new line to
# audit; a new CRATE is), sorted unique, and compared in BOTH directions against the
# checked-in list. Both directions matter: an entry not in the closure fails too, because an
# allow list nobody has to prune decays into one that permits anything. Then the same three
# guards against a gate that passes by proving nothing: a >10-line floor (an empty `cargo
# tree` compares equal to nothing), a presence check for direct dependencies a human typed
# into the manifest (the graph resolved, but to THIS crate's graph?), and a comparator
# self-test that plants a synthetic `reqwest` and requires the diff to notice it on this run.
# Not extracted into a shared lib: the mechanical core is under 30 lines and every message
# line differs between the two gates, so a parameterised library would be longer than the
# duplication it removed.
#
# TO REGENERATE A LIST after a reviewed dependency change (say why in the same PR):
#   cargo fetch --locked && cargo tree -p mark1-proxy -e normal --target all --prefix none \
#     --no-dedupe --offline | sed 's/ v[0-9].*//; s/ (.*//; s/[[:space:]]*$//' | grep -v '^$' \
#     | sort -u
# and paste the output under the header comment of the matching list file.
set -eu

cd "$(dirname "$0")/../.."

# The one comparator. The real check and the self-test both go through it, so a comparator
# that stopped seeing one direction is caught by the self-test on this run rather than by
# the incident. The first version of this self-test ran its own diff -q and stayed green
# while the real comparison had been mutated to a single direction (lead mutation, 09-15).
closure_differs() { ! diff -u "$1" "$2" > "$3"; }

FAILED=0
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

closure() { # closure CRATE > stdout — sorted unique crate NAMES in CRATE's runtime graph
  cargo tree -p "$1" -e normal --target all --prefix none --no-dedupe --offline \
    | sed 's/ v[0-9].*//; s/ (.*//; s/[[:space:]]*$//' \
    | grep -v '^$' | sort -u
}

# check CRATE MANIFEST LISTFILE DIRECT_DEP... — one subject crate against its reviewed list.
check() {
  crate=$1; manifest=$2; list=$3; shift 3
  echo "== $crate =="
  [ -f "$list" ] || {
    echo "FAIL: $list is missing; $crate's closure is unreviewed and this gate is silently green."
    exit 1
  }
  # Comment lines are the file's own header; sorted on read so an appended entry is judged on
  # membership, not on where in the file someone put it.
  grep -Ev '^(#|$)' "$list" | sort -u > "$TMP/$crate.allowed"
  closure "$crate" > "$TMP/$crate.actual"
  N=$(wc -l < "$TMP/$crate.actual" | tr -d ' ')

  # A `cargo tree` that printed nothing — wrong package name, a manifest that stopped resolving,
  # a future cargo that moved a flag — is an empty file, and an empty file diffs as "everything
  # vanished" rather than as "the graph was never read". Say which it is.
  [ "$N" -gt 10 ] || {
    echo "FAIL: cargo tree returned $N crate(s) for $crate. The dependency graph was not read,"
    echo "      so this gate proved nothing. Check the package name and the flags above."
    exit 1
  }
  # Direct dependencies a human typed into the manifest. If the graph resolved to something
  # real but not to THIS crate's graph, the count above still passes; this does not.
  for d in "$@"; do
    grep -qx "$d" "$TMP/$crate.actual" || {
      echo "FAIL: '$d' is a direct dependency in $manifest but is absent from the resolved"
      echo "      closure. This gate is reading the wrong graph."
      exit 1
    }
  done

  if closure_differs "$TMP/$crate.allowed" "$TMP/$crate.actual" "$TMP/$crate.diff"; then
    echo "FAIL: $crate's dependency closure is not the reviewed one in $list."
    sed -n '3,$p' "$TMP/$crate.diff" | sed 's/^/        /'
    echo ""
    echo "        '+' = a crate now in $crate's graph that nobody reviewed. NFR-SECURITY-008 and"
    echo "              10 §8.1: a new dependency on the token/hook path is a security review, not"
    echo "              a 'cargo add'. This process holds the credential (proxy) or runs inside the"
    echo "              agent's hook (shim); every crate in its graph runs with that access. If the"
    echo "              crate belongs there, add it to $list IN THE SAME PR and"
    echo "              say in the message why a reviewer should accept it on this path."
    echo "        '-' = a listed crate that is no longer a dependency. Remove it. A list that drifts"
    echo "              longer than the graph is how a reviewed list rots into permitting anything."
    FAILED=1
  else
    echo "tokenpath_deps_gate: $crate closure is exactly the $N reviewed crates."
  fi

  # Anti-vacuity for the comparator. Everything above is one `diff`, and a `diff` that silently
  # succeeded — a broken pipeline, a sed that emptied both sides — is indistinguishable from a
  # clean graph. Put a network crate in and require it to be caught, on this run. The guard
  # first: if 'reqwest' ever lands in the list itself, this self-test would test nothing.
  if grep -qx reqwest "$TMP/$crate.allowed"; then
    echo "FAIL: 'reqwest' is in $list, so the comparator self-test below cannot discriminate."
    echo "      Pick a different synthetic crate in this script — and ask why reqwest is on a"
    echo "      path that already has hyper."
    FAILED=1
  fi
  printf 'reqwest\n' >> "$TMP/$crate.actual"
  sort -u -o "$TMP/$crate.actual" "$TMP/$crate.actual"
  if ! closure_differs "$TMP/$crate.allowed" "$TMP/$crate.actual" "$TMP/$crate.selftest.diff"; then
    echo "FAIL: the closure comparator did not notice a synthetic 'reqwest' added to $crate's"
    echo "      graph. Whatever it reported above, it was not comparing anything."
    FAILED=1
  else
    echo "tokenpath_deps_gate: $crate comparator self-test OK (a synthetic 'reqwest' was rejected)."
  fi
}

# Target-agnostic: pulls every crate Cargo.lock names, so `--offline` below means "from the
# lockfile" and not "from whatever the host build happened to touch". Subject of this gate is
# the shipped binaries' dependency sets, not this script's network; the script may fetch.
cargo fetch --locked --quiet

check mark1-hookshim rust/mark1-hookshim/Cargo.toml tools/ci/tokenpath_deps_hookshim.txt \
  mark1-hookshim m1p-wire mark1-redact x25519-dalek chacha20poly1305 hmac
check mark1-proxy   rust/mark1-proxy/Cargo.toml   tools/ci/tokenpath_deps_proxy.txt \
  mark1-proxy hyper rustls tokio mark1-policy mark1-frames

if [ "$FAILED" -ne 0 ]; then
  echo ""
  echo "NFR-SECURITY-008: 'dependencies on token/hook paths must be vendored and pinned; the shim's"
  echo "dependency tree is minimal by review.' The lockfile pins; this gate is the review. Do not"
  echo "widen a list to land a change without saying, in the PR, why the crate belongs on a path"
  echo "that carries the customer's credential."
  exit 1
fi

echo "tokenpath_deps_gate: OK — both token-path closures are exactly their reviewed lists."
