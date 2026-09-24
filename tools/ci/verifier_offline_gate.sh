#!/bin/sh
# verifier_offline_gate.sh — FR-SPINE-020 / FR-CLI-007, the clause no test covered:
# "validate the chain, checkpoints, inclusion paths, and witness heads offline, WITH EVERY
# OMIUM SERVER UNREACHABLE" (02 §92). 12 §12 names this obligation `conf_verifier_offline`
# and there was no such test — the guarantee lived in a comment at the bottom of
# rust/verifier/Cargo.toml ("nothing else, ever"), which is a note to a future reader, not
# a check. Nothing refused a network crate and nothing observed a run.
#
# This matters more than a normal gate because it is the SALES CLAIM. "Verify Omium, don't
# trust Omium" is only true if the verifier a customer runs cannot talk to us — a verifier
# that could phone home is one that could be told what verdict to reach, and then the whole
# receipt chain is worth exactly as much as our word. So the offline property has to be
# checked, not asserted.
#
# THREE INDEPENDENT MECHANISMS, because each one alone has a hole the next covers:
#
#   1 CLOSURE  the verifier's resolved dependency graph, exactly equal to a checked-in list.
#             Catches `reqwest` at the manifest level. Misses a crate that opens a socket
#             through std::net with no dependency at all.
#   2 SYMBOLS  the linked binary imports no socket syscall. Catches the std::net case, and
#             covers code paths no fixture exercises. Misses nothing at runtime, but is only
#             as good as the symbol table it can read.
#   3 BLACKHOLE the real end-to-end verify, executed inside a network namespace with no
#             reachable network at all. The only mechanism that observes the shipped binary
#             actually doing its job with us unreachable — which is the literal sentence in
#             02 §92 — and the only one a reader believes without understanding linkers.
#
# WHY AN ALLOW LIST AND NOT A DENY LIST (mechanism 1). A deny list of network crates is a
# list of every networking crate that will ever exist: reqwest, ureq, hyper, curl, isahc,
# attohttpc, surf, tokio, async-std, smol... it is red the day someone picks the one nobody
# listed, and it is silently green until then. The verifier's whole closure is 54 crates and
# every one is a line a customer must audit before trusting the verdict, so the list is
# enumerable and enumerating it is the point. Equality is checked in BOTH directions: an
# entry not in the closure fails too. That is what stops this from degenerating into the
# useless shape a deny list can reach — an allow list broad enough to permit anything cannot
# stay equal to a 54-crate graph, so over-broadness is itself a failure here.
#
# cargo-deny cannot express this. Its [bans] section is workspace-global, and this workspace
# legitimately contains hyper and tokio for mark1-proxy; a global ban on them would be wrong
# everywhere except in the one crate that needs it. The claim is scoped to ONE crate's
# subgraph, so the check is too.
set -eu

cd "$(dirname "$0")/../.."

# The one comparator. The real check and the self-test both go through it, so a comparator
# that stopped seeing one direction is caught by the self-test on this run rather than by
# the incident. The first version of this self-test ran its own diff -q and stayed green
# while the real comparison had been mutated to a single direction (lead mutation, 09-15).
closure_differs() { ! diff -u "$1" "$2" > "$3"; }

FAILED=0
PARTIAL=''
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# The shipped artifact. Mechanisms 2 and 3 both need it to exist, and building it here rather
# than requiring a prior recipe is what lets this gate be run alone by a developer.
echo "== building the shipped verifier =="
cargo build --locked -p mark1-verifier
BIN=target/debug/mark1-verifier
[ -x "$BIN" ] || { echo "FAIL: cargo build succeeded but $BIN is not executable."; exit 1; }

# ---------------------------------------------------------------------------------------------
# 1 CLOSURE — the resolved dependency graph, name for name.
# ---------------------------------------------------------------------------------------------
# --target all, not the host default: without it this list is platform-dependent (libc and
# windows-sys are in the graph only for some triples), so the gate would be red on macOS and
# green on Linux for no reason anyone could act on. The verifier ships to five triples; the
# closure that matters is their union.
#
# --offline, so the graph read is the LOCKFILE's and not whatever a registry happened to say
# today. But the build above populates the cache for the HOST triple only, while --target all
# walks every triple — so on a cold runner the Windows-only crates (anstyle-wincon) were never
# downloaded and `cargo tree --offline` failed to read the graph at all, which this gate then
# correctly reported as "proved nothing". `cargo fetch` is target-agnostic: it pulls every
# crate Cargo.lock names, after which --offline means "from the lockfile" rather than "from
# whatever the host build touched". The subject of this gate is the shipped BINARY's network
# needs, not this script's; the script may fetch.
#
# Versions are stripped. A version bump is not a new line to audit; a new CRATE is.
cat > "$TMP/allowed.txt" <<'EOF'
anstream
anstyle
anstyle-parse
anstyle-query
anstyle-wincon
arrayvec
blake3
block-buffer
cfg-if
clap
clap_builder
clap_derive
clap_lex
colorchoice
constant_time_eq
cpufeatures
crypto-common
curve25519-dalek
curve25519-dalek-derive
digest
ed25519
ed25519-dalek
fiat-crypto
generic-array
heck
is_terminal_polyfill
itoa
libc
mark1-receipt
mark1-verifier
memchr
once_cell_polyfill
proc-macro2
quote
rand_core
serde
serde_core
serde_derive
serde_json
sha2
signature
strsim
subtle
syn
thiserror
thiserror-impl
typenum
unicode-ident
utf8parse
windows-link
windows-sys
zeroize
zeroize_derive
zmij
EOF

closure() { # closure > stdout — sorted unique crate NAMES in mark1-verifier's runtime graph
  cargo tree -p mark1-verifier -e normal --target all --prefix none --no-dedupe --offline \
    | sed 's/ v[0-9].*//; s/ (.*//; s/[[:space:]]*$//' \
    | grep -v '^$' | sort -u
}

echo "== 1 CLOSURE =="
cargo fetch --locked --quiet
closure > "$TMP/actual.txt"
N=$(wc -l < "$TMP/actual.txt" | tr -d ' ')

# A `cargo tree` that printed nothing — wrong package name, a manifest that stopped resolving,
# a future cargo that moved the flag — produces an empty file, and an empty file compares equal
# to nothing and unequal to the list, so it would surface as a confusing 54-line diff rather
# than as "the graph was never read". Say which it is.
[ "$N" -gt 10 ] || {
  echo "FAIL: cargo tree returned $N crate(s) for mark1-verifier. The dependency graph was not"
  echo "      read, so this mechanism proved nothing. Check the package name and the flags above."
  exit 1
}
# The four crates a human typed into rust/verifier/Cargo.toml. If the graph resolved to
# something real but not to THIS crate's graph, the count check above still passes.
for d in mark1-verifier mark1-receipt clap serde_json; do
  grep -qx "$d" "$TMP/actual.txt" || {
    echo "FAIL: '$d' is a direct dependency in rust/verifier/Cargo.toml but is absent from the"
    echo "      resolved closure. This gate is reading the wrong graph."
    exit 1
  }
done

if closure_differs "$TMP/allowed.txt" "$TMP/actual.txt" "$TMP/closure.diff"; then
  echo "FAIL: mark1-verifier's dependency closure is not the audited one."
  sed -n '3,$p' "$TMP/closure.diff" | sed 's/^/        /'
  echo ""
  echo "        '+' = a crate now in the verifier's graph that nobody has audited. FR-SPINE-020"
  echo "              says this binary validates a chain with every Omium server unreachable, and"
  echo "              that is a property of its whole graph, not of the code you wrote. If the new"
  echo "              crate cannot open a socket, add it to the list above IN THE SAME PR and say"
  echo "              in the message why a customer auditing the verifier should accept it."
  echo "        '-' = a listed crate that is no longer a dependency. Remove it. A list that drifts"
  echo "              longer than the graph is how an allow list rots into permitting anything."
  FAILED=1
else
  echo "verifier_offline_gate: closure is exactly the $N audited crates."
fi

# Anti-vacuity for the comparator itself. Everything above is one `diff`, and a `diff` that
# silently succeeded — a broken pipeline, a sed that emptied both sides — is indistinguishable
# from a clean graph. So put a network crate in and require it to be caught, on this run.
printf 'reqwest\n' >> "$TMP/actual.txt"
sort -u -o "$TMP/actual.txt" "$TMP/actual.txt"
if ! closure_differs "$TMP/allowed.txt" "$TMP/actual.txt" "$TMP/selftest.diff"; then
  echo "FAIL: the closure comparator did not notice a synthetic 'reqwest' added to the graph."
  echo "      Whatever it reported above, it was not comparing anything."
  FAILED=1
else
  echo "verifier_offline_gate: comparator self-test OK (a synthetic 'reqwest' was rejected)."
fi

# ---------------------------------------------------------------------------------------------
# The probe. One 8-line program, serving as the positive control for BOTH remaining mechanisms:
# it must show socket symbols where the verifier shows none, and it must fail inside the
# namespace where the verifier succeeds. Same compiler, same host, same commands — so when the
# verifier comes out clean, "clean" has been shown to be a distinguishable outcome and not the
# only outcome these commands can produce.
#
# It binds a listener and connects to it, so it needs no port agreed in advance, no `nc`, and
# no reachable peer: the only thing that can stop it is the absence of a usable network stack.
# rustc directly, no Cargo manifest — this is not a crate and should not look like one.
echo "== building the network probe (positive control for 2 and 3) =="
cat > "$TMP/net_probe.rs" <<'EOF'
use std::net::{TcpListener, TcpStream};
fn main() {
    let l = match TcpListener::bind("127.0.0.1:0") {
        Ok(l) => l,
        Err(e) => { eprintln!("probe: bind failed: {e}"); std::process::exit(1); }
    };
    match TcpStream::connect(l.local_addr().expect("local_addr")) {
        Ok(_) => println!("probe: connected"),
        Err(e) => { eprintln!("probe: connect failed: {e}"); std::process::exit(1); }
    }
}
EOF
rustc -O -o "$TMP/net_probe" "$TMP/net_probe.rs"

# ---------------------------------------------------------------------------------------------
# 2 SYMBOLS — the linked binary imports no socket syscall.
# ---------------------------------------------------------------------------------------------
# Mechanism 1 reasons about manifests; this reasons about the artifact. A crate that opens a
# socket through std::net needs no dependency at all and would sail past the closure check —
# but it cannot reach the kernel without one of these libc symbols appearing in the import
# table, whatever it is named and whoever wrote it.
#
# Every name here is one that can ORIGINATE or ADDRESS a network endpoint. Deliberately absent:
# socketpair, sendmsg, recvmsg, recv, bind. std::process::Command imports the first four for the
# AF_UNIX pair it uses to report exec failure from the child, so matching them would fail this
# gate on any verifier that spawns a subprocess — for a reason that has nothing to do with the
# network. They are also not sufficient: none of them can produce a network fd without `socket`,
# and a verifier that reaches the network through a CHILD process leaves no symbol here at all.
# That case is mechanism 3's, and mechanism 3 does catch it — each mechanism owns one job.
#
# The (@|$) anchor is load-bearing: unanchored, `socket` matches `socketpair@GLIBC_2.2.5`.
NETSYMS='socket|connect|getaddrinfo|freeaddrinfo|gethostbyname|sendto|recvfrom'

echo "== 2 SYMBOLS =="
if ! command -v nm > /dev/null 2>&1; then
  PARTIAL="$PARTIAL
  - nm is not installed, so the shipped binary's import table was never read."
else
  # `nm -D` on a binary with no dynamic symbols (a fully static or stripped build) prints
  # nothing, and nothing contains no socket symbols — a pass that means the table was
  # unreadable, not that it was clean. Require both sides to be legible before believing either.
  nm -D --undefined-only "$BIN"        > "$TMP/bin.syms"  2>/dev/null || true
  nm -D --undefined-only "$TMP/net_probe" > "$TMP/probe.syms" 2>/dev/null || true
  BN=$(wc -l < "$TMP/bin.syms" | tr -d ' ')
  PROBE_HITS=$(grep -icE "^ +U ($NETSYMS)(@|$)" "$TMP/probe.syms" || true)

  if [ "$BN" -lt 5 ] || [ "$PROBE_HITS" -eq 0 ]; then
    # Either this build has no dynamic import table to read, or nm read one and the CONTROL
    # came out clean — and a control that cannot detect a program built to connect cannot
    # certify one that does not. Both are "we learned nothing", never "clean".
    PARTIAL="$PARTIAL
  - the import table proved unreadable: $BN undefined symbol(s) in $BIN and $PROBE_HITS
    network symbol(s) in a probe that provably connects. A static, stripped or non-ELF
    build reads this way, and so does a clean one — they are not distinguishable here."
  else
    HITS=$(grep -iE "^ +U ($NETSYMS)(@|$)" "$TMP/bin.syms" || true)
    if [ -n "$HITS" ]; then
      echo "FAIL: the shipped verifier imports socket syscalls:"
      printf '%s\n' "$HITS" | sed 's/^/        /'
      echo "        The offline guarantee is that this binary CANNOT reach a network, not that it"
      echo "        chooses not to. Whatever pulled these in has to come back out."
      FAILED=1
    else
      echo "verifier_offline_gate: $BIN imports none of /$NETSYMS/ across $BN undefined symbols;"
      echo "                       the probe imports $PROBE_HITS of them, so the check discriminates."
    fi
  fi
fi

# ---------------------------------------------------------------------------------------------
# 3 BLACKHOLE — the real verify, with every Omium endpoint (and every other one) unreachable.
# ---------------------------------------------------------------------------------------------
# `unshare -rn` gives an unprivileged network namespace holding one DOWN loopback and nothing
# else: no route, no address, no DNS. Every connect() in it returns ENETUNREACH. That is the
# strongest available reading of "with every Omium server unreachable" — it does not blackhole
# our endpoints, it blackholes all of them.
#
# The subject is the two Go end-to-end tests, not a hand-rolled invocation, because those are
# the tests FR-CLI-007 cites: this makes the cited evidence and the offline claim the same
# execution rather than two things that agree by assertion. They are compiled OUTSIDE the
# namespace (`go test -c`) — a Go build may fetch modules, and a module fetch failing inside
# the namespace would look exactly like the verifier trying to phone home.
#
# M1_REQUIRE_STORES=1 because those tests skip when they cannot build the verifier, and a skip
# inside a network namespace is the most convincing false green in this repo: zero connections
# observed is also what a test that ran nothing reports.
echo "== 3 BLACKHOLE =="
if ! command -v unshare > /dev/null 2>&1; then
  PARTIAL="$PARTIAL
  - unshare(1) is absent, so no run was observed with the network removed."
elif ! unshare -rn true > /dev/null 2>&1; then
  PARTIAL="$PARTIAL
  - this kernel refuses unprivileged network namespaces (Ubuntu's
    kernel.apparmor_restrict_unprivileged_userns=1 does this), so no run was observed with
    the network removed."
else
  # Control, first and in both directions. Outside: the probe connects. Inside: it must not.
  # One binary, one command, one difference — the namespace. If the probe connects inside it,
  # the namespace is not isolating anything and every result below would be meaningless.
  if ! "$TMP/net_probe" > /dev/null 2>&1; then
    PARTIAL="$PARTIAL
  - the probe could not connect to its own listener even OUTSIDE a namespace, so this host
    cannot tell a blackholed run from a normal one and the namespace result would mean nothing."
  elif unshare -rn "$TMP/net_probe" > /dev/null 2>&1; then
    echo "FAIL: the probe CONNECTED inside 'unshare -rn'. The namespace is not blackholing the"
    echo "      network, so a passing verify inside it would prove nothing at all."
    FAILED=1
  else
    echo "verifier_offline_gate: probe connects outside the namespace and gets ENETUNREACH inside,"
    echo "                       so the namespace demonstrably blackholes the network."
    ( cd go/mark1 && go test -c -o "$TMP/vr.test" ./internal/verifyreceipts ) || {
      echo "FAIL: could not compile the verifyreceipts test binary."
      exit 1
    }
    set +e
    ( cd go/mark1/internal/verifyreceipts && \
      M1_REQUIRE_STORES=1 unshare -rn "$TMP/vr.test" \
        -test.run 'TestEndToEndRealVerifier(ValidChain|TamperedChain)' -test.v ) > "$TMP/e2e.log" 2>&1
    RC=$?
    set -e
    if [ "$RC" -ne 0 ]; then
      echo "FAIL: the end-to-end verify did NOT pass with the network removed (exit $RC):"
      sed 's/^/        /' "$TMP/e2e.log"
      echo "        This is FR-SPINE-020's actual sentence failing. Either the verifier now needs"
      echo "        a network, or something it calls does."
      FAILED=1
    else
      # `-test.run` with a typo'd pattern selects nothing, prints "ok", and exits 0. The gate's
      # whole claim is that these two tests RAN here, so count the PASS lines rather than the
      # exit code — the same reason `just test-chaos` lists before it runs.
      PASSES=$(grep -c '^--- PASS: TestEndToEndRealVerifier' "$TMP/e2e.log" || true)
      SKIPS=$(grep -c '^--- SKIP:' "$TMP/e2e.log" || true)
      if [ "$PASSES" -ne 2 ] || [ "$SKIPS" -ne 0 ]; then
        echo "FAIL: expected both end-to-end verifier tests to PASS inside the namespace; got"
        echo "      $PASSES pass(es) and $SKIPS skip(s). A run that selected nothing exits 0 too."
        sed 's/^/        /' "$TMP/e2e.log"
        FAILED=1
      else
        echo "verifier_offline_gate: both end-to-end verifier tests passed with no reachable"
        echo "                       network — valid chain accepted, tampered chain named and"
        echo "                       rejected, entirely offline."
      fi
    fi
  fi
fi

# ---------------------------------------------------------------------------------------------
if [ "$FAILED" -ne 0 ]; then
  echo ""
  echo "FR-SPINE-020: 'a standalone open-source verifier must validate the chain, checkpoints,"
  echo "inclusion paths, and witness heads offline, with every Omium server unreachable.' That is"
  echo "the product's one falsifiable claim about itself. Do not weaken this gate to land a"
  echo "change; the guarantee is worth more than the change."
  exit 1
fi

if [ -n "$PARTIAL" ]; then
  # Green, but say what was NOT checked. Four dead gates in this repo's history printed OK.
  echo "verifier_offline_gate: PARTIAL — the dependency closure is exact, but:$PARTIAL" >&2

  # ...except in CI, where a PARTIAL is a SKIP, and a skipped mechanism backing a P0 row is
  # the exact false green this gate was written to remove. conformance/traceability.yaml cites
  # this script as the evidence for FR-SPINE-020's "with every Omium server unreachable"; if the
  # runner cannot produce that evidence the honest outcome is red, not a green with a footnote
  # nobody reads. Locally the same condition is only a notice, so a developer on a kernel with
  # unprivileged userns disabled still gets the two static mechanisms without a wall.
  #
  # GitHub Actions always sets CI=true. If this fires on the gates job, do NOT delete the
  # mechanism: enable unprivileged user namespaces on the runner
  # (sysctl kernel.apparmor_restrict_unprivileged_userns=0), or move this gate to a lane that
  # can run it. Deleting it puts the product's central claim back on an honour system.
  if [ -n "${CI:-}" ]; then
    echo "" >&2
    echo "FAIL: the above is a PARTIAL in CI (\$CI is set). The gates job is the lane that owes" >&2
    echo "      FR-SPINE-020 its 'every Omium server unreachable' evidence, and it did not" >&2
    echo "      produce it on this run. A mechanism that did not execute proves nothing, and" >&2
    echo "      exiting 0 here would let the traceability row cite a check that never ran." >&2
    exit 1
  fi

  echo "  Not a failure locally — the closure and symbol mechanisms above are unconditional." >&2
  echo "  This same condition is a hard failure in CI (see the comment at this line)." >&2
  exit 0
fi

echo "verifier_offline_gate: OK — closure exact and audited, no socket symbol in the shipped"
echo "                       binary, and the real end-to-end verify green with the network gone."
