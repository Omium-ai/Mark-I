# omium-mark1 — every verb in the repo. CI runs THESE recipes; if you're typing a raw
# cargo/go/uv/buf command that has a recipe, you're doing it wrong.

# bash, not PowerShell. Every recipe in this file is POSIX sh — `[ -n "$(find …)" ] || echo`,
# `|| [ $? -eq 5 ]`, `VAR=x cmd`, and direct calls to tools/ci/*.sh. PowerShell parses `[ -n`
# as a type literal, so the Windows CI jobs died with `ParserError: MissingTypename` inside
# `_go-src` — the tripwire recipe whose whole purpose is catching gates that pass by never
# executing — before `go build` was ever reached. Windows runners ship Git for Windows, so
# bash is on PATH. Verifiable only in CI: there is no Windows host in this workspace.
set windows-shell := ["bash", "-uc"]

# ---------- store contract (12 §11.4) ----------
# ONE set of env var names for the store-backed suites, defined once, exported to every recipe.
# `stores-up` provisions matching native binaries; CI exports the same names; a dev machine can
# point them at any Postgres/ClickHouse/MinIO it already has.
#
# M1_REQUIRE_STORES=1 INVERTS the estate's `pytest.mark.skipif(no DSN)` idiom: a missing or
# unreachable DSN is a HARD ERROR, and required suites assert zero skips (12 §0.3 mechanism 2).
# Green-because-skipped is the failure mode this repo exists to not repeat.
export M1_REQUIRE_STORES  := env_var_or_default("M1_REQUIRE_STORES", "1")
export M1_TEST_PG_DSN     := env_var_or_default("M1_TEST_PG_DSN", "postgres://mark1:mark1@127.0.0.1:5432/mark1_test")
# Migrations connect as a DIFFERENT, privileged role — the same split prod already has, where the
# Argo migration Job runs as the RDS master and the services connect as `*_app`. It is not a
# convenience: m1_060 creates `mark1_federation_worker` WITH BYPASSRLS, and PostgreSQL 16 lets
# only a BYPASSRLS role touch that attribute — in either direction, on CREATE and on ALTER alike.
# So the migrator must hold it and the suite role must not, and one DSN cannot be both. Making
# M1_TEST_PG_DSN privileged enough to migrate is precisely the estate's rds_superuser failure:
# every isolation assertion would then run from a role that cannot see RLS.
export M1_MIGRATE_PG_DSN  := env_var_or_default("M1_MIGRATE_PG_DSN", "postgres://m1_bootstrap@127.0.0.1:5432/mark1_test")
# `/?database=default`, not `/default`: ClickHouse's HTTP interface routes on handler names, not
# path segments, and answers a POST to `/default` with 404 ("Use / or /ping for health checks").
# The stores-up probe below reads that 404 as "not up yet" and waits out its full 60s, so the
# wrong path here does not misconfigure a client — it makes the whole store lane unable to start.
export M1_TEST_CH_DSN     := env_var_or_default("M1_TEST_CH_DSN", "http://127.0.0.1:8123/?database=default")
# 9002, not MinIO's usual 9000: ClickHouse's NATIVE port is 9000 and its client, its docs and
# this repo's ClickHouse migration lane all assume that default. Two conventional ports collide
# on one loopback and only one of them can move without breaking tools — so MinIO moves.
export M1_TEST_S3_ENDPOINT := env_var_or_default("M1_TEST_S3_ENDPOINT", "http://127.0.0.1:9002")

# ---------- tool pins (13 §9.5) ----------
# ci.yml pins GOLANGCI_VERSION, but `lint-go` resolved the binary from PATH and asserted
# nothing, so the pin bound CI and nothing else: 2.13.2 locally reports four gosec findings
# (one G703, three G115) that CI's 2.1.6 does not emit, and 2.1.6 reports zero. Both runs
# called themselves "lint-go" and disagreed about whether the repo was clean. A pin only one
# side checks is not a pin. ci.yml's GOLANGCI_VERSION is the only other copy of this number.
export M1_GOLANGCI_VERSION := env_var_or_default("M1_GOLANGCI_VERSION", "2.1.6")
# Same disease, second tool: the remote plugins in buf.gen.yaml are pinned, but the buf CLI
# that feeds them source-info is not, and CLI versions disagree about trailing-comment
# attachment. buf-setup-action's default (1.50.0) regenerated a different m1p.v1.rs than the
# 1.72.0 that produced the committed one, so gen-check went red on a tree nobody had edited.
# ci.yml's BUF_VERSION is the only other copy of this number.
export M1_BUF_VERSION := env_var_or_default("M1_BUF_VERSION", "1.72.0")

default: lint test

# ---------- codegen ----------

# Regenerate committed proto bindings and stage the Rust gen into m1p-wire.
gen:
    @v=$(buf --version 2>/dev/null | head -1); [ "$v" = "$M1_BUF_VERSION" ] || { echo "gen: buf '${v:-<not found>}' on PATH, but the pin is $M1_BUF_VERSION. Versions disagree about comment attachment in generated code, so this output is not what gen-check compares against. Fix: install buf $M1_BUF_VERSION (tools/bootstrap.sh)" >&2; exit 1; }
    cd proto && buf generate
    cp proto/gen/rust/m1p.v1.rs rust/m1p-wire/gen/m1p.v1.rs

# The freshness gate: committed gen must equal regenerated gen.
#
# Delegates instead of re-implementing the diff. The inline version checked `git diff` only,
# which cannot see a file that was never `git add`ed — so a NEW .proto whose generated output
# nobody committed passed this gate silently. gen_fresh.sh runs `just gen` itself and also
# checks `git ls-files --others`, hence no `gen` dependency here.
gen-check:
    tools/ci/gen_fresh.sh

# ---------- build ----------

build: build-rust build-go build-py

build-rust:
    cargo build --workspace --locked

# `go build ./...` and `go test ./...` treat "matched no packages" as a WARNING and still
# exit 0 — so over a module holding go.mod and nothing else, both recipes below report
# success having compiled and run nothing. Same failure as the ruff hole in lint-py and the
# empty-crate OK in override_pattern_gate: a gate that passes by never executing. One private
# recipe, called by both, so the tripwire cannot drift between build and test.
_go-src MOD:
    @[ -n "$(find go/{{MOD}} -name '*.go' -print -quit)" ] || echo "go/{{MOD}}: PARTIAL — zero .go files; './...' matched no packages and NOTHING was compiled or run" >&2

build-go: (_go-src "mark1d") (_go-src "mark1") (_go-src "controld")
    cd go/mark1d   && go build ./...
    cd go/mark1    && go build ./...
    cd go/controld && go build ./...

# --all-packages is load-bearing, not a flag someone added for convenience. The
# root is a virtual workspace anchor with no dependencies of its own, so a bare
# `uv sync --frozen` resolves to "no changes" and installs NOTHING -- leaving
# ruff and pytest absent and every `uv run` below silently broken. The most
# expensive casualty is the ruff banned-api no-OTel gate (§7.4), which would
# report success by never executing at all.
build-py:
    uv sync --frozen --all-packages

# Release-profile edge binaries for the host triple (packaging matrices live in release.yml).
build-edge:
    cargo build --release --locked -p mark1-proxy -p mark1-hookshim -p cortexd
    cd go/mark1d && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o ../../dist/mark1d ./cmd
    cd go/mark1  && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o ../../dist/mark1  ./cmd

# ---------- test ----------

test: test-rust test-go test-py conformance

test-rust:
    cargo test --workspace --locked --no-fail-fast

# Build-tag inventory: `go test ./...` below CANNOT see a tag-gated package — that is exactly
# how a suite goes silently missing, so every tag in the repo is listed here with the recipe
# that runs it. Adding a tag without adding it here is a review failure.
#   integration -> `just test-integration`      (in `just ci`; CI job `integration`)
#   chaos       -> `just test-chaos`            (in `just ci`; CI job `integration`, Linux-only
#                  per 12 §11.1 stage 2e). The ⚡ fast set is chaos_daemon_kill9 (spool writer)
#                  plus cmd/chaos_process_kill (mark1d, mark1-proxy and cortexd SIGKILLed under
#                  the real daemon).
#                  `just test-chaos-slow`       (nightly per 12 §6, not in `just ci`). The slow set:
#                  network partition (internal/uplink + cmd chaos_network_partition), clock skew /
#                  sleep-wake (internal/uplink chaos_clock_skew), disk-full (internal/spool
#                  chaos_disk_full{,_linux}), and the cloud legs in go/controld
#                  (internal/ingest chaos_cloud, internal/policydist chaos_tlog), which need the
#                  stores and carry `integration && chaos` so the test-integration tag gate still
#                  sees them.
#   soak        -> `just test-soak`             (nightly per 12 §2.2, not in `just ci`). The 7-day
#                  fail-static soak: internal/soak drives the real bundle client, uplink, spool and
#                  gate under one injected clock through a control-plane blackhole.
#
# PLATFORM tags hide suites from a CI LEG rather than from a recipe, and the inventory missed
# them entirely — which is how `go (windows-2022)` sat red-and-unread (D-BZ). They are listed
# here on the same terms: a tag nobody wrote down is a tag nobody audits.
#   unix   -> runs on the ubuntu/macos legs, NOT windows-2022. Everything genuinely tied to a
#             uid, a mode bit or an AF_UNIX path: fabric/listener_test.go (0600/0700 perms),
#             tailers/tailer_test.go (dev/ino identity), adapters/claudecode/shim_e2e_test.go,
#             and all of cmd/ (run() binds the fabric, which has no Windows listener — see
#             NFR-PORTABILITY-002 and D-CA). anchors/{catalog,runner,wire}_test.go carried it
#             only because their fake tool was a sh script; they are tag-free now (a .cmd on
#             windows) and their two mode-bit asserts are GOOS-guarded, so windows-2022 runs
#             the catalog, consent, runner and wire audit against the real AppContainer sandbox.
#   linux  -> anchors/sandbox_linux_test.go and sandbox_hardened_test.go; the namespace sandbox
#             is a Linux kernel feature. sandbox_helper.go and sandbox_posix_test.go are
#             `linux || darwin` (the re-exec helper, rlimits, AF_UNIX and one-way-valve probes).
#   darwin -> anchors/sandbox_darwin{,_test}.go (the sandbox-exec sandbox), sandbox_helper.go and
#             sandbox_posix_test.go (`linux || darwin`, above), sandbox_probe_test.go
#             (`linux || darwin || windows`: the portable probes, one file so a probe added on one
#             platform runs on all three), sandbox_other.go (`!linux && !darwin && !windows`: the
#             refusal for anything else). The probes run on the macos-14 leg with
#             M1_REQUIRE_SANDBOX=1, so a skipped probe there is a red leg.
#   windows -> internal/procattr/procattr_{windows,other}{,_test}.go; CREATE_NO_WINDOW on every
#             child the daemon spawns is a Win32 creation flag, so the Windows file carries the
#             attribute and its test, and the !windows pair asserts the no-op. Both halves run on
#             their own leg (windows-2022 and ubuntu/macos), so nothing is hidden from any leg.
#             anchors/sandbox_windows.go (the AppContainer + job-object sandbox) and
#             sandbox_appcontainer_test.go (its probes: named pipe denied, read outside the
#             grants denied, job caps, ACL grant idempotence) plus the shared
#             sandbox_probe_test.go run on windows-2022 with M1_REQUIRE_SANDBOX=1, the same
#             inversion as the other two legs: a skipped probe there is a red leg.
# Adding a platform tag to make a red leg green is the failure this row exists to catch: the
# test that cannot run on Windows should be the one whose SUBJECT is unix, never the one whose
# helper happened to live in a unix file (harness_test.go).
#
# Untagged Go tests, all three modules, no exclusion globs (12 §0.3 mechanism 1).
# The inventory above is a claim about tags in files that exist; `_go-src` is what stops
# it being made over a module with no files (see build-go).
test-go: (_go-src "mark1d") (_go-src "mark1") (_go-src "controld")
    cd go/mark1d   && go test ./...
    cd go/mark1    && go test ./...
    cd go/controld && go test ./...

# `-m "not integration"`: this recipe runs in CI's storeless `python` job, and
# M1_REQUIRE_STORES=1 (above) makes an unreachable DSN a hard failure BY DESIGN. Store-backed
# modules therefore must not be collected here — they belong to `test-integration`, which runs
# after `just stores-up`. This is the routing, not an exemption: every test deselected here is
# selected there, and `just ci` runs both.
test-py:
    uv run --frozen --all-packages -m pytest python/shared/mark1_receipts/tests -o asyncio_mode=auto
    uv run --frozen --all-packages -m pytest python/adjudicator/tests -o asyncio_mode=auto -m "not integration"
    uv run --frozen --all-packages -m pytest python/intel/tests -o asyncio_mode=auto -m "not integration"

# Cross-language conformance vectors: Rust ↔ Go ↔ Python must agree bit-identically.
conformance:
    tools/ci/conformance_crosslang.sh

# The ⚡ fast chaos set (12 §6.2). Two harnesses, both real SIGKILLs against real processes:
#   internal/spool chaos_daemon_kill9 — NFR-DURABILITY-002 / FR-SPINE-024: a spool writer killed
#     mid-append, recovery graded against the raw bytes.
#   cmd/chaos_process_kill            — NFR-AVAILABILITY-001: the assembled mark1d killed between
#     two hook invocations of a live mark1-hookshim session (hooks fail open inside the 08 §4.4
#     budgets, the ring drains on restart, Usage still arrives, Dropped{} audited off the wire);
#     the supervised mark1-proxy killed under a client mid-request, six times to FAILED (D-CM
#     revert + the proxy_failed bypass receipt); the supervised cortexd killed and the MCP wall
#     asserted back after backoff. Linux-only (build tag): it finds each child's pid through
#     /proc.
# Needs no stores. Needs the Rust toolchain: cmd/chaos_process_kill drives the REAL hookshim,
# proxy and cortexd binaries and runs `cargo build --locked` itself (a warm build is a no-op; the
# line below only makes the cold build a visible step instead of a slow-looking Go test).
#
# `-list` before `-run` because `-run` with no match prints "no tests to run" and exits 0, which
# is the false green this whole lane exists to prevent — and here it is one dropped `-tags chaos`
# away at all times, since the files are invisible to an untagged build BY DESIGN. The count is
# the exact number of named tests, so a rename or a file that stops selecting is a red, not a
# narrower green.
#
# `-count=1` because a cached chaos pass is not a chaos run: the whole content of this suite is
# fresh races between a process and a kill, and Go's test cache would happily replay one from a
# tree where the spool still worked.
test-chaos:
    cargo build -p mark1-hookshim -p mark1-proxy -p cortexd --locked
    @cd go/mark1d && n=$(go test -tags chaos -list '^TestChaosDaemonKill9$' ./internal/spool/ | grep -c '^TestChaosDaemonKill9$' || true); [ "$n" = "1" ] || { echo "test-chaos: the chaos harness did not select. 'go test -tags chaos -list' matched $n tests, want 1 — either the build tag stopped selecting chaos_kill9_test.go or the test was renamed. Running -run against that would print 'no tests to run' and exit 0." >&2; exit 1; }
    @cd go/mark1d && n=$(go test -tags chaos -list '^TestChaos(Mark1dKill9MidSession|ProxyKill9MidStream|CortexdKill9)$' ./cmd/ | grep -c '^TestChaos' || true); [ "$n" = "3" ] || { echo "test-chaos: the process-kill harness did not select. 'go test -tags chaos -list' matched $n tests in cmd/, want 3 — either the build tag stopped selecting chaos_process_kill_test.go or a leg was renamed. Running -run against that would print 'no tests to run' and exit 0." >&2; exit 1; }
    cd go/mark1d && go test -tags chaos -count=1 -run '^TestChaosDaemonKill9$' ./internal/spool/
    cd go/mark1d && go test -tags chaos -count=1 -v -run '^TestChaos(Mark1dKill9MidSession|ProxyKill9MidStream|CortexdKill9)$' ./cmd/

# The slow chaos set (12 §6.2 rows uplink_park_requeue / chaos_sleep_wake / skew_ordering_invariance /
# spool_billing_blocks_on_full / spool_disk_hardstop, and 12 §6.3's S3, ClickHouse and transparency-log
# rows). Edge legs need no stores; the controld legs need `just stores-up` and run under
# `-tags integration,chaos`. Same `-list` guard and `-count=1` reasoning as test-chaos.
#   internal/uplink  chaos_network_partition — F-22: real spool + real automaton under a black-holing
#     controld mid-load; ladder, PARKED and the network-change re-queue observed, Dropped{} exact.
#   cmd              chaos_network_partition — CON-007: the assembled daemon loses ingest AND the control
#     plane; capture and gating continue, last-known-good holds (304 on heal), every Usage lands once.
#   internal/uplink  chaos_clock_skew — F-43/F-44: capture, receipts, bundle and uplink on one injected
#     clock through ±hours jumps, a max_age crossing and a 10-minute sleep; seq/UUIDv7/chain intact.
#   internal/spool   chaos_disk_full — F-17/F-18/F-19 under concurrent load via the statfs seam, plus a
#     real 1 MiB tmpfs in an unprivileged user namespace (Linux; skips itself if the host refuses).
#   controld ingest  chaos_cloud — S3 cut mid-load (no ack without an object), ClickHouse cut mid-load
#     (acks hold, replay makes the ledger exact). controld policydist chaos_tlog — log key down:
#     publication halts, seq 1 keeps serving with its proof, continuity verifiable after the heal.
test-chaos-slow:
    @cd go/mark1d && n=$(go test -tags chaos -list '^TestChaos(NetworkPartitionUplink|ClockSkewAndSleepWake)$' ./internal/uplink/ | grep -c '^TestChaos' || true); [ "$n" = "2" ] || { echo "test-chaos-slow: internal/uplink matched $n chaos tests, want 2 — the build tag stopped selecting a chaos file or a test was renamed." >&2; exit 1; }
    @cd go/mark1d && n=$(go test -tags chaos -list '^TestChaos(SpoolCapUnderLoad|DiskHardStopUnderLoad|DiskHardStopTmpfs)$' ./internal/spool/ | grep -c '^TestChaos' || true); [ "$n" = "3" ] || { echo "test-chaos-slow: internal/spool matched $n chaos tests, want 3 — the build tag stopped selecting a chaos file or a test was renamed." >&2; exit 1; }
    @cd go/mark1d && n=$(go test -tags chaos -list '^TestChaosNetworkPartitionDaemon$' ./cmd/ | grep -c '^TestChaos' || true); [ "$n" = "1" ] || { echo "test-chaos-slow: cmd matched $n chaos tests, want 1 — the build tag stopped selecting chaos_network_partition_test.go or the test was renamed." >&2; exit 1; }
    @cd go/controld && n=$(go test -tags integration,chaos -list '^TestChaos(S3OutageNoFalseAck|CHOutageIngestUnaffected)$' ./internal/ingest/ | grep -c '^TestChaos' || true); [ "$n" = "2" ] || { echo "test-chaos-slow: controld/internal/ingest matched $n chaos tests, want 2." >&2; exit 1; }
    @cd go/controld && n=$(go test -tags integration,chaos -list '^TestChaosTlogOutagePublicationHalts$' ./internal/policydist/ | grep -c '^TestChaos' || true); [ "$n" = "1" ] || { echo "test-chaos-slow: controld/internal/policydist matched $n chaos tests, want 1." >&2; exit 1; }
    cd go/mark1d && go test -tags chaos -count=1 -v -run '^TestChaos(NetworkPartitionUplink|ClockSkewAndSleepWake)$' ./internal/uplink/
    cd go/mark1d && go test -tags chaos -count=1 -v -run '^TestChaos(SpoolCapUnderLoad|DiskHardStopUnderLoad|DiskHardStopTmpfs)$' ./internal/spool/
    cd go/mark1d && go test -tags chaos -count=1 -v -run '^TestChaosNetworkPartitionDaemon$' ./cmd/
    cd go/controld && go test -tags integration,chaos -count=1 -v -run '^TestChaos(S3OutageNoFalseAck|CHOutageIngestUnaffected)$' ./internal/ingest/
    cd go/controld && go test -tags integration,chaos -count=1 -v -run '^TestChaosTlogOutagePublicationHalts$' ./internal/policydist/

# The 7-day fail-static soak (12 §6.3 `bundle_maxage_builtins` + NFR-AVAILABILITY-003 / CON-007 chaos
# rows). One process, one injected clock, ~2.5M virtual timer events in ~15 s wall: the control plane
# goes dark 12 min into day 0 and returns on day 7; capture, the 08 §2.5 uploader automaton, the spool
# caps, the max_age edge and the drain are asserted tick by tick. Same `-list` guard and `-count=1`
# reasoning as test-chaos: the files are invisible to an untagged build BY DESIGN.
test-soak:
    @cd go/mark1d && n=$(go test -tags soak -list '^TestSoakSevenDayBlackhole$' ./internal/soak/ | grep -c '^TestSoakSevenDayBlackhole$' || true); [ "$n" = "1" ] || { echo "test-soak: the soak harness did not select. 'go test -tags soak -list' matched $n tests, want 1 — either the build tag stopped selecting internal/soak or the test was renamed. Running -run against that would print 'no tests to run' and exit 0." >&2; exit 1; }
    cd go/mark1d && go test -tags soak -count=1 -v -run '^TestSoakSevenDayBlackhole$' ./internal/soak/

# Store-backed suites, incl. the tag-gated Go integration suite. Real stores on EVERY PR
# (12 §11.4) — no Docker, no testcontainers, no skip-if-absent. Run `just stores-up` first.
# Per-suite pytest invocations: adjudicator and intel both export a top-level `app`
# package (06 §1.1); one pytest process caches whichever `app` imports first, so a
# combined run fails collection on the other suite.
# adjudicator now carries real `integration` marks (test_pg_stores.py), so its exit-5 escape
# is GONE: an empty selection there would mean the marker stopped matching and the RLS negative
# tests silently stopped running — the precise green-because-skipped failure this repo exists to
# not repeat. intel keeps the escape only while it has no marked suite; delete it when it does.
#
# The Go half is routed by a build tag, and six of the seven suites were missing it — so they
# compiled into the storeless `go` job's ./... set and hard-failed there on an absent DSN, while
# this lane ran one suite and called it integration coverage. The tag is the whole routing
# contract and nothing was checking it, so the gate below asserts it directly: a DSN-gated file
# without the tag is a file running in the wrong lane. It also catches a typo'd or negated tag,
# which is the same defect wearing a different mask.
#
# The alternation is the store-contract var PREFIXES, and it has to be maintained: splitting the
# migration DSN out of M1_TEST_PG_DSN dropped four harnesses out of a single-prefix selector
# without failing it, because the remaining files still matched. Adding a store-contract variable
# means adding its prefix here.
test-integration:
    uv run --frozen --all-packages -m pytest python/adjudicator/tests -o asyncio_mode=auto -m integration
    uv run --frozen --all-packages -m pytest python/intel/tests -o asyncio_mode=auto -m integration || [ $? -eq 5 ]
    @f=$(grep -rlE 'M1_TEST_|M1_MIGRATE_' --include='*_test.go' go/controld || true); [ -n "$f" ] || { echo "test-integration: no test file reads a store DSN at all — the Go integration lane has vanished" >&2; exit 1; }; u=$(grep -L '^//go:build integration' $f); [ -z "$u" ] || { echo "test-integration: DSN-gated file(s) missing '//go:build integration', so they run in the storeless lane instead of this one:" >&2; echo "$u" >&2; exit 1; }
    cd go/controld && go test -tags=integration ./...

# The gate above selects by CONTENT (reads a store DSN), not by the filename
# `integration_test.go`. It was the filename, and `smoke_crossservice_test.go` — which needs the
# rig and is named nothing like that — sailed past it. Files that reach the stores only through a
# tagged helper are a different case and need no rule here: they fail to typecheck in the storeless
# build, which is how that one was actually caught. Name conventions are not properties.
#
# `conformance/tenancy/` carries the specs; its conftest asserts zero skips under
# M1_REQUIRE_STORES=1, so "passed" cannot mean "did not run".
#
# Tenant-isolation negative tests (12 §4) — the required PR check the tenancy story rests on.
test-isolation:
    uv run --frozen --all-packages -m pytest conformance/tenancy -o asyncio_mode=auto

# The pinned hook bodies through the real mark1-hookshim and the pinned transcripts through the
# real mark1d, uplinked to a real controld over the store contract above, asserted from the cloud
# side (ClickHouse, m1_receipts, the landing prefix, querychoke) and verified offline by the real
# mark1-verifier. Fixture-fast — no live agent — so it rides every PR beside test-integration
# (12 §1.1: "the Phase-1 replay path also on PR"). Builds the binaries itself; needs go, cargo,
# psql and the ClickHouse client migrate-db.sh needs (CLICKHOUSE_CLIENT, or .stores/bin/clickhouse).
# Its conftest asserts zero skips under M1_REQUIRE_STORES=1, so "passed" cannot mean "did not run".
#
# The Phase-1 replay path end to end (12 §1.1 end-to-end row; 12 §12 Phase 1 item 1).
test-e2e:
    uv run --frozen --all-packages -m pytest conformance/e2e -o asyncio_mode=auto

# ---------- lint / fmt ----------

lint: lint-rust lint-go lint-py lint-proto gates

lint-rust:
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets --locked -- -D warnings
    cargo deny check

lint-go:
    @v=$(golangci-lint version 2>/dev/null | sed -n 's/.*has version v\{0,1\}\([0-9][0-9.]*\).*/\1/p' | head -1); [ "$v" = "$M1_GOLANGCI_VERSION" ] || { echo "lint-go: golangci-lint '${v:-<not found>}' on PATH, but the pin is $M1_GOLANGCI_VERSION. Versions disagree about what is clean, so this run is not the gate CI runs. Fix: go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v$M1_GOLANGCI_VERSION" >&2; exit 1; }
    # Non-mutating (exits 1 on drift), so the module contract is checked the way the code is.
    # Runs first: govulncheck on an untidy module scans requires nothing imports. D-CF — tidy
    # removed three direct requires for code never written, and nothing here could have held
    # them anyway: with no tools.go blank import, an "intentional" unused pin survives exactly
    # until the next tidy.
    cd go/mark1d    && go mod tidy -diff
    cd go/mark1     && go mod tidy -diff
    cd go/controld  && go mod tidy -diff
    cd proto/gen/go && go mod tidy -diff
    cd go/mark1d   && golangci-lint run
    cd go/mark1    && golangci-lint run
    cd go/controld && golangci-lint run
    cd go/mark1d   && govulncheck ./...
    cd go/mark1    && govulncheck ./...
    cd go/controld && govulncheck ./...

# Over an empty tree ruff prints "All checks passed!" and exits 0, so the no-OTel banned-api
# rule (§7.4) reports success by never executing — the same failure the --all-packages fix
# above closed, one layer up. Announced rather than hidden; the guard disarms itself the
# moment the first module lands, so it needs no allowlist to shorten later.
lint-py:
    @[ -n "$(find python -name '*.py' -print -quit)" ] || echo "lint-py: PARTIAL — zero .py files under python/; ruff scanned NOTHING and the banned-api no-OTel rule did not execute" >&2
    uv run --frozen --all-packages ruff format --check python
    uv run --frozen --all-packages ruff check python
    uv export --frozen --no-emit-workspace -o /tmp/mark1-reqs.txt && pip-audit -r /tmp/mark1-reqs.txt

lint-proto:
    buf lint proto
    buf breaking proto --against '.git#branch=main,subdir=proto'

# The design-enforcing custom gates (§7.5). Small scripts, zero tolerance.
#
# The first line is the list checking itself. A gate script that exists in tools/ci but is not
# invoked below runs nowhere, in no CI job, and reports nothing — which is indistinguishable
# from a green build and is precisely how this repo has lost gates before. Derived from the
# tree, so the next *_gate.sh is either wired here or this recipe fails on sight; it can never
# quietly sit unrun.
gates:
    @u=$(for g in tools/ci/*_gate.sh; do grep -q "^    $g$" justfile || echo "$g"; done); [ -z "$u" ] || { echo "gates: gate script(s) in tools/ci that this recipe never invokes — they run nowhere:" >&2; echo "$u" >&2; exit 1; }
    tools/ci/otel_gate.sh
    tools/ci/secret_type_gate.sh
    tools/ci/override_pattern_gate.sh
    tools/ci/build_tag_gate.sh
    tools/ci/shapley_gate.sh
    tools/ci/adr_signed_gate.sh
    tools/ci/vendor_binary_gate.sh
    tools/ci/ci_matrix_gate.sh
    tools/ci/verifier_offline_gate.sh
    tools/ci/buf_breaking_gate.sh
    tools/ci/tokenpath_deps_gate.sh
    tools/ci/raw_credential_gate.sh
    tools/ci/posture_gate.sh
    tools/ci/crush_reserved_gate.sh

# The requirement→test gate (12 §10.3). Deliberately NOT folded into `gates`: this one is built
# to go red the moment a requirement loses its test, and a red `gates` that could mean any of five
# unrelated invariants is a signal you learn to skim. It also needs all three toolchains, because
# checking that a test exists means asking the three test runners, not grepping for a name.
trace-check:
    uv run --frozen --all-packages python tools/trace-check

# Nightly, not per PR: it goes red when upstream moves, which no diff can fix. Exit 1 = a pin is
# past its limit (the LIMITS table at the top of the script), 2 = a lookup failed.
# Pin freshness (A4 §4): how far each conformance/hooks/<agent>/v* pin trails upstream (GitHub releases, npm, cursor.com).
pin-freshness:
    uv run --frozen --all-packages python tools/ci/pin_freshness.py

# The contract-sync rule (§10.3): a contract diff must carry its owning doc's diff.
#
# A recipe, not a raw script call in ci.yml, because §6.1's one claim for this file is that CI
# runs what a developer runs. CI passes the PR base SHA; the default is what you'd diff against
# before opening the PR.
contracts base="origin/main":
    BASE_REF={{base}} tools/ci/contracts_sync_check.sh

fmt:
    cargo fmt --all
    cd go/mark1d && gofmt -w . && cd ../mark1 && gofmt -w . && cd ../controld && gofmt -w .
    uv run --frozen --all-packages ruff format python
    uv run --frozen --all-packages ruff check --fix python

# ---------- fuzz / bench ----------

# Nightly toolchain; smoke duration in CI, long runs by hand or scheduled job.
fuzz duration="60":
    # Seed corpus = the frozen vectors (13 §11 row C2), passed as a second read-only dir so
    # libFuzzer's discoveries land in the local corpus dir, never in conformance/ (12 §3.4: frozen).
    cd rust/m1p-wire      && mkdir -p fuzz/corpus/frame_decode && cargo +nightly fuzz run frame_decode fuzz/corpus/frame_decode ../../conformance/vectors/m1pl -- -max_total_time={{duration}}
    cd rust/mark1-redact  && cargo +nightly fuzz run admit         -- -max_total_time={{duration}}
    cd rust/mark1-policy  && cargo +nightly fuzz run bundle_decode -- -max_total_time={{duration}}
    cd go/mark1d && go test -fuzz=FuzzSpoolRecordDecode -fuzztime={{duration}}s ./internal/spool
    cd go/mark1d && go test -fuzz=FuzzM1plFrameRead     -fuzztime={{duration}}s ./internal/fabric

# Absolute budgets are only meaningful on the pinned runner class (12 §7.2, docs/runbooks/bench-runner.md).
#
# Benches with CI thresholds (12 owns the numbers): proxy ≤1 ms median, redact ~100 MB/s, shim cold start ≤10 ms.
bench:
    cargo bench -p mark1-proxy -p mark1-redact
    cargo build --release --locked -p mark1-hookshim
    # The cold-start harness lands with the hookshim itself in C8. A missing script that a
    # `&&` chain quietly swallows is a gate reporting success by never executing — the exact
    # failure class this repo exists to not repeat — so the absence is announced, loudly.
    if [ -f tools/ci/shim_coldstart_bench.sh ]; then tools/ci/shim_coldstart_bench.sh; else echo "bench: SKIPPED — shim cold-start (12 §7.1: spawn→UDS write→exit, p50 ≤ 10 ms) was NOT measured; tools/ci/shim_coldstart_bench.sh does not exist yet (lands in C8)" >&2; fi

# ---------- db / dev loop ----------

# Apply core + service migrations to a target DSN (idempotent; safe to re-run).
#
# `migrations/` is BOTH engines' schema: the runner sends m1_ch_*.sql to a ClickHouse client and
# everything else to psql (see tools/migrate-db.sh). CLICKHOUSE_HOST is a hard precondition
# there — it refuses rather than skipping, because a "migrated" deployment missing its ledger
# tables is the failure this repo will not ship — but the connection actually made is whatever
# CLICKHOUSE_CLIENT names, since the pinned client reads only CLICKHOUSE_USER and
# CLICKHOUSE_PASSWORD from the environment. `just stores-up` prints both values on exit.
migrate dsn:
    DATABASE_URL={{dsn}} tools/migrate-db.sh migrations m1
    DATABASE_URL={{dsn}} tools/migrate-db.sh migrations/adjudicator adj

# No Docker, no testcontainers: the daemon dependency adds no fidelity and breaks on Docker-less
# runners. Idempotent. Nothing to export — the DSNs are the fixed values at the top of this file.
#
# Provision Postgres + ClickHouse + MinIO as native binaries under .stores/ (12 §11.4).
stores-up:
    #!/usr/bin/env bash
    set -euo pipefail
    # Pinned versions. A floating store version is a statement about *time* (§9.5).
    CH_VERSION="24.8.14.39"
    MINIO_VERSION="RELEASE.2024-11-07T00-52-20Z"
    ROOT="$(pwd)/.stores"
    BIN="$ROOT/bin"; mkdir -p "$BIN" "$ROOT/log"
    case "$(uname -s)" in
      Linux|Darwin) ;;
      *) echo "stores-up: POSIX hosts only (the store-backed lane is Linux in CI)" >&2; exit 1 ;;
    esac

    # --- Postgres: 15 when the host has it (the RDS pin prod runs, 09 §"Engine"), else the
    # newest installed. This used to be a lone hardcoded /usr/lib/postgresql/15/bin, which
    # stopped resolving the moment `ubuntu-latest` became 24.04 and the image shipped 16 —
    # the integration job then failed before starting a single store. Discovery, and the
    # chosen version is ECHOED, so "CI ran a different major than prod" is visible in the
    # log rather than inferred.
    PG_BIN="${PG_BIN:-}"
    if [ -z "$PG_BIN" ]; then
      for d in $(ls -d /usr/lib/postgresql/*/bin 2>/dev/null | sort -V); do
        if [ -x "$d/initdb" ]; then PG_BIN="$d"; fi
      done
      if [ -x /usr/lib/postgresql/15/bin/initdb ]; then PG_BIN=/usr/lib/postgresql/15/bin; fi
      if [ -z "$PG_BIN" ] && command -v initdb >/dev/null 2>&1; then
        PG_BIN="$(dirname "$(command -v initdb)")"
      fi
    fi
    if [ ! -x "${PG_BIN:-/nonexistent}/initdb" ]; then
      echo "stores-up: no PostgreSQL binaries found; set PG_BIN=" >&2; exit 1
    fi
    echo "stores-up: postgres $("$PG_BIN/initdb" --version | awk '{print $3}') from $PG_BIN" >&2
    printf '%s' "$PG_BIN" > "$ROOT/pg_bin"
    # initdb's -U role is a SUPERUSER, and a superuser inherits BYPASSRLS. Bootstrapping as
    # `mark1` therefore made the store contract's own DSN role bypass-capable, which makes
    # every tenant-isolation assertion in this repo unobservable from the suite that exists
    # to make it — the estate's rds_superuser lesson (61 FORCE-RLS tables rendered
    # decorative), re-imported through the test harness. So: bootstrap as m1_bootstrap and
    # hand the suite a role that cannot bypass anything.
    if ! "$PG_BIN/pg_isready" -h 127.0.0.1 -p 5432 >/dev/null 2>&1; then
      [ -f "$ROOT/pg/PG_VERSION" ] || {
        mkdir -p "$ROOT/pg"
        "$PG_BIN/initdb" -D "$ROOT/pg" -U m1_bootstrap --auth=trust --encoding=UTF8 >/dev/null
      }
      "$PG_BIN/pg_ctl" -D "$ROOT/pg" -l "$ROOT/log/pg.log" \
        -o "-h 127.0.0.1 -p 5432 -k $ROOT" -w start
    fi
    # A cluster initialized by the previous recipe has `mark1` as its bootstrap superuser and
    # no m1_bootstrap at all; stripping that role's own superuser needs a superuser that does
    # not exist there. Refuse with the remedy rather than silently running the whole store
    # lane against a role whose green means nothing. `.stores/` is scratch.
    if "$PG_BIN/psql" -h 127.0.0.1 -p 5432 -U mark1 -d postgres -qtAc \
         "SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user" \
         2>/dev/null | grep -qx t; then
      echo "stores-up: this cluster's \`mark1\` role is superuser/BYPASSRLS (initialized by the" >&2
      echo "  pre-2026-08-30 recipe). Tenant-isolation tests cannot observe RLS through it and" >&2
      echo "  hard-fail under M1_REQUIRE_STORES=1. Reprovision:  just stores-down && rm -rf .stores/pg && just stores-up" >&2
      exit 1
    fi
    # The suite role: owns the schema it migrates, but NOSUPERUSER NOBYPASSRLS. m1_021 and its
    # siblings declare FORCE ROW LEVEL SECURITY, so ownership does not exempt it either — which
    # is precisely what lets `test_rls_isolation_between_tenants` observe real enforcement.
    # CREATEROLE because m1_060 creates the `*_app` service roles and the migration died without
    # it; in prod that file is applied by the RDS master user, which has the attribute. It is not
    # a hole in the paragraph above: PG16 forbids a CREATEROLE role from granting an attribute it
    # does not itself hold, so `mark1` cannot mint a BYPASSRLS role, and FORCE RLS still binds the
    # roles it does mint. It is also what lets the tenancy suite SET ROLE into `*_app` — mark1 is
    # their admin by virtue of having created them.
    "$PG_BIN/psql" -h 127.0.0.1 -p 5432 -U m1_bootstrap -d postgres -qtAc \
      "SELECT 1 FROM pg_roles WHERE rolname='mark1'" | grep -qx 1 \
      || "$PG_BIN/psql" -h 127.0.0.1 -p 5432 -U m1_bootstrap -d postgres -v ON_ERROR_STOP=1 -qc \
           "CREATE ROLE mark1 LOGIN PASSWORD 'mark1'"
    # Applied unconditionally, so a cluster provisioned by an earlier version of this recipe
    # converges instead of silently keeping the old attribute set.
    "$PG_BIN/psql" -h 127.0.0.1 -p 5432 -U m1_bootstrap -d postgres -v ON_ERROR_STOP=1 -qc \
      "ALTER ROLE mark1 LOGIN CREATEDB CREATEROLE NOSUPERUSER NOBYPASSRLS"
    "$PG_BIN/createdb" -h 127.0.0.1 -p 5432 -U m1_bootstrap -O mark1 mark1_test 2>/dev/null || true
    # Migrations run as m1_bootstrap (see M1_MIGRATE_PG_DSN), so it — not mark1 — owns what they
    # create. Default privileges hand every future object to the suite role automatically; the
    # two ALL-objects grants cover a database migrated before this split existed. `mark1` gets
    # privileges, never ownership, so RLS binds it without relying on FORCE.
    "$PG_BIN/psql" -h 127.0.0.1 -p 5432 -U m1_bootstrap -d mark1_test -v ON_ERROR_STOP=1 -qc \
      "ALTER DEFAULT PRIVILEGES FOR ROLE m1_bootstrap IN SCHEMA public GRANT ALL ON TABLES TO mark1;
       ALTER DEFAULT PRIVILEGES FOR ROLE m1_bootstrap IN SCHEMA public GRANT ALL ON SEQUENCES TO mark1;
       ALTER DEFAULT PRIVILEGES FOR ROLE m1_bootstrap IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO mark1;
       GRANT ALL ON ALL TABLES IN SCHEMA public TO mark1;
       GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO mark1"

    # --- pgvector. m1_040's `error_signature halfvec(1024)` needs >= 0.7, and this lane failed
    # on two separate counts, either of which stops `just migrate` dead at m1_040 on every host
    # including the CI runner:
    #   1. nothing provisioned pgvector at all. Ubuntu's own archive stops at 0.6.0, which has
    #      no halfvec, so the distro package would not have been enough either — hence PGDG at
    #      0.8.6, the version deploy/compose already pins.
    #   2. `vector.control` carries no `trusted = true`, so CREATE EXTENSION requires a
    #      superuser — and the migration DSN role is deliberately NOSUPERUSER (see above).
    #      Creating it here as m1_bootstrap is exactly what RDS does for us in prod: the
    #      platform supplies the extension and the migration's IF NOT EXISTS is a no-op NOTICE.
    #      Keeping `mark1` unprivileged is the entire point of the role split, so the fix
    #      belongs on this side of the line, not in the migration.
    PGV_VERSION="0.8.6"
    PG_MAJOR="$("$PG_BIN/pg_config" --version | awk '{print $2}' | cut -d. -f1)"
    if ! "$PG_BIN/psql" -h 127.0.0.1 -p 5432 -U m1_bootstrap -d postgres -qtAc \
           "SELECT 1 FROM pg_available_extensions WHERE name = 'vector' AND default_version >= '0.7'" \
           | grep -qx 1; then
      ARCH="$(uname -m)"; [ "$ARCH" = "x86_64" ] && ARCH=amd64 || ARCH=arm64
      SUFFIX=""; [ -r /etc/os-release ] && SUFFIX="$(. /etc/os-release; echo "${VERSION_ID:-}")"
      URL="https://apt.postgresql.org/pub/repos/apt/pool/main/p/pgvector/postgresql-${PG_MAJOR}-pgvector_${PGV_VERSION}-1.pgdg${SUFFIX}%2B1_${ARCH}.deb"
      mkdir -p "$ROOT/pgvector"
      curl -fsSL -o "$ROOT/pgvector/pgvector.deb" "$URL" && dpkg -x "$ROOT/pgvector/pgvector.deb" "$ROOT/pgvector/x" || {
        echo "stores-up: could not fetch pgvector $PGV_VERSION for PostgreSQL $PG_MAJOR from" >&2
        echo "  $URL" >&2
        echo "  (only the Debian/Ubuntu deb path is automated). Install pgvector >= 0.7 for this" >&2
        echo "  server yourself and re-run; m1_040 needs halfvec and 0.6.x does not have it." >&2
        exit 1
      }
      # A PGDG build drops into a distro build of the same major: extension ABI is stable within
      # a PostgreSQL major, and vector.so links only libc and the server's own symbols.
      SHAREDIR="$("$PG_BIN/pg_config" --sharedir)"; PKGLIBDIR="$("$PG_BIN/pg_config" --pkglibdir)"
      CP="cp"; [ -w "$SHAREDIR/extension" ] && [ -w "$PKGLIBDIR" ] || CP="sudo cp"
      $CP "$ROOT/pgvector/x/usr/share/postgresql/$PG_MAJOR/extension/"vector* "$SHAREDIR/extension/"
      $CP "$ROOT/pgvector/x/usr/lib/postgresql/$PG_MAJOR/lib/vector.so" "$PKGLIBDIR/"
    fi
    # template1 as well as mark1_test: the Go integration harnesses each create their OWN scratch
    # database as the unprivileged suite role and run the migration tree into it, so a per-database
    # CREATE EXTENSION would need a superuser they deliberately are not. Seeding template1 is how a
    # fresh database inherits the extension — the local stand-in for RDS handing us pgvector. This
    # was previously done by hand on a dev box and went unrecorded, which is the reason it is a
    # line of the recipe now rather than a step in someone's shell history.
    for db in template1 mark1_test; do
      "$PG_BIN/psql" -h 127.0.0.1 -p 5432 -U m1_bootstrap -d "$db" -v ON_ERROR_STOP=1 \
        -qc "CREATE EXTENSION IF NOT EXISTS vector"
    done

    # --- ClickHouse: one static binary, pinned tarball ---
    if ! curl -fsS "$M1_TEST_CH_DSN" --data-binary "SELECT 1" >/dev/null 2>&1; then
      if [ ! -x "$BIN/clickhouse" ]; then
        ARCH="$(uname -m)"; [ "$ARCH" = "x86_64" ] && ARCH=amd64 || ARCH=arm64
        # The member is <pkg>/usr/bin/clickhouse — four components, so stripping three leaves the
        # bare filename and -C puts it straight in $BIN. Stripping two left "bin/clickhouse"
        # relative to $ROOT, which is already $BIN, and the mv that followed died on ENOENT.
        curl -fsSL "https://packages.clickhouse.com/tgz/stable/clickhouse-common-static-${CH_VERSION}-${ARCH}.tgz" \
          | tar -xz -C "$BIN" --strip-components=3 "clickhouse-common-static-${CH_VERSION}/usr/bin/clickhouse"
      fi
      mkdir -p "$ROOT/ch"
      # 07 §"async_insert" mandates the settings server-side in the m1p_ingest user's profile,
      # deliberately redundant with chconn's per-connection settings — and chconn's boot refusal
      # R3 (05 §1.2) now actually PROBES the server-side value on a settings-free connection, so
      # an unprovisioned store is correctly refused at boot. CH 24.8's compiled-in default is
      # async_insert=0 (verified), so a bare `clickhouse server` here is a store this repo's own
      # code must refuse: the lane provisions the profile or it isn't the lane.
      cat > "$ROOT/ch/config.xml" <<'CHCFG'
    <clickhouse>
      <logger><level>warning</level><console>1</console></logger>
      <listen_host>127.0.0.1</listen_host>
      <http_port>8123</http_port>
      <tcp_port>9000</tcp_port>
      <path>./data/</path>
      <users_config>users.xml</users_config>
      <!-- users.xml alone is READ-ONLY storage, so `CREATE USER` fails with "no writeable access
           storage in user directories" (code 514) — and the querychoke harness provisions a
           per-run reader/writer principal pair by SQL precisely to prove the confinement claim
           against real ClickHouse ACLs. Without a local_directory those tests cannot run at all,
           which is not the same thing as the confinement claim being unverified: it is worse,
           because the suite is cited as the proof. -->
      <user_directories>
        <users_xml><path>users.xml</path></users_xml>
        <local_directory><path>./access/</path></local_directory>
      </user_directories>
    </clickhouse>
    CHCFG
      cat > "$ROOT/ch/users.xml" <<'CHUSERS'
    <clickhouse>
      <profiles>
        <default>
          <async_insert>1</async_insert>
          <wait_for_async_insert>1</wait_for_async_insert>
        </default>
        <m1p_ingest>
          <async_insert>1</async_insert>
          <wait_for_async_insert>1</wait_for_async_insert>
        </m1p_ingest>
      </profiles>
      <users>
        <default>
          <password></password>
          <networks><ip>127.0.0.1</ip><ip>::1</ip></networks>
          <profile>default</profile>
          <quota>default</quota>
          <access_management>1</access_management>
        </default>
        <!-- mark1/mark1: local-dev constant like MinIO's minioadmin; never leaves a laptop or runner -->
        <m1p_ingest>
          <password>mark1</password>
          <networks><ip>127.0.0.1</ip><ip>::1</ip></networks>
          <profile>m1p_ingest</profile>
          <quota>default</quota>
        </m1p_ingest>
      </users>
      <quotas><default></default></quotas>
    </clickhouse>
    CHUSERS
      ( cd "$ROOT/ch" && nohup "$BIN/clickhouse" server --config-file="$ROOT/ch/config.xml" >"$ROOT/log/ch.log" 2>&1 & )
      # A bare `break`-only wait loop reports success by falling off the end. `just ci` then runs
      # with M1_REQUIRE_STORES=1 against a store that never started, and the failure surfaces as
      # a connection error inside some unrelated test instead of here.
      for i in $(seq 1 60); do
        curl -fsS "$M1_TEST_CH_DSN" --data-binary "SELECT 1" >/dev/null 2>&1 && break
        [ "$i" = 60 ] && { echo "stores-up: ClickHouse did not answer $M1_TEST_CH_DSN in 60s; see $ROOT/log/ch.log" >&2; exit 1; }
        sleep 1
      done
    fi

    # --- MinIO: one static binary. minioadmin/minioadmin is the estate's documented local-dev
    # constant (allowlisted in .gitleaks.toml); it never leaves a laptop or a job runner. ---
    if ! curl -fsS "$M1_TEST_S3_ENDPOINT/minio/health/live" >/dev/null 2>&1; then
      if [ ! -x "$BIN/minio" ]; then
        OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
        ARCH="$(uname -m)"; [ "$ARCH" = "x86_64" ] && ARCH=amd64 || ARCH=arm64
        # GitHub Releases, not dl.min.io: on 2026-09-15 dl.min.io answered 410 Gone for the
        # archive AND for latest -- MinIO stopped serving binaries there -- and the integration
        # lane died at fetch on a cold runner while every laptop with a cached .stores/bin/minio
        # stayed green (D-DY, again). The release asset is byte-identical to the old archive
        # object (same sha256), and the hash is now PINNED so a swapped or truncated download
        # cannot become the store the tenancy negatives run against. Only linux/amd64 has a hash
        # recorded; another triple refuses rather than trusting an unverified binary.
        ASSET="minio.${OS}-${ARCH}.${MINIO_VERSION}"
        case "${OS}-${ARCH}" in
          linux-amd64) MINIO_SHA256="c27873d791b56d33518de11f12c5bfae4be88ebac00e12c6dd0027b08123fd80" ;;
          *) echo "stores-up: no pinned sha256 for minio ${OS}-${ARCH}; add one from the release's .sha256sum asset" >&2; exit 1 ;;
        esac
        curl -fsSL -o "$BIN/minio" \
          "https://github.com/minio/minio/releases/download/${MINIO_VERSION}/${ASSET}"
        echo "${MINIO_SHA256}  $BIN/minio" | sha256sum -c - >/dev/null || {
          echo "stores-up: minio download does not match the pinned sha256; refusing to start a store from it" >&2
          rm -f "$BIN/minio"; exit 1
        }
        chmod +x "$BIN/minio"
      fi
      mkdir -p "$ROOT/s3"
      ( MINIO_ROOT_USER=minioadmin MINIO_ROOT_PASSWORD=minioadmin \
        nohup "$BIN/minio" server "$ROOT/s3" --address "${M1_TEST_S3_ENDPOINT#http://}" >"$ROOT/log/s3.log" 2>&1 & )
      for i in $(seq 1 60); do
        curl -fsS "$M1_TEST_S3_ENDPOINT/minio/health/live" >/dev/null 2>&1 && break
        [ "$i" = 60 ] && { echo "stores-up: MinIO did not answer $M1_TEST_S3_ENDPOINT in 60s; see $ROOT/log/s3.log" >&2; exit 1; }
        sleep 1
      done
    fi

    echo "stores-up: pg=$M1_TEST_PG_DSN ch=$M1_TEST_CH_DSN s3=$M1_TEST_S3_ENDPOINT"
    echo "stores-up: for \`just migrate\`, export CLICKHOUSE_HOST=127.0.0.1 CLICKHOUSE_CLIENT='$BIN/clickhouse client --host 127.0.0.1 --port 9000'"

stores-down:
    #!/usr/bin/env bash
    set -eu
    ROOT="$(pwd)/.stores"
    # stores-up records the version it actually chose; guessing a path here would stop the
    # wrong cluster (or none) on a host whose Postgres is not the one that was started.
    [ -d "$ROOT/pg" ] && "${PG_BIN:-$(cat "$ROOT/pg_bin" 2>/dev/null)}/pg_ctl" -D "$ROOT/pg" -m fast stop || true
    pkill -f "$ROOT/bin/clickhouse" || true
    pkill -f "$ROOT/bin/minio" || true

# CI uses `stores-up`, which needs no Docker.
#
# Local dev stack (postgres, clickhouse, minio, the three cloud services). DEV ONLY.
dev-up:
    docker compose -f deploy/compose/compose.yaml up -d

dev-down:
    docker compose -f deploy/compose/compose.yaml down -v

# ---------- supply chain ----------

sbom:
    mkdir -p dist
    syft dir:. -o cyclonedx-json > dist/sbom.cdx.json

# `test-integration` and `test-isolation` are IN this list deliberately. The estate's failure was
# a required suite living outside the canonical entrypoint; a tenant-isolation suite that `just ci`
# does not run is that failure shipped in the scaffold. Requires `just stores-up` first.
#
# `gates` and `conformance` are in the list for the same reason: ci.yml's `gates` job runs both,
# so leaving them out made `just ci` a weaker check than CI while claiming to be the same one.
#
# `test-chaos` needs no stores; it is next to the store lanes because ci.yml runs it in the
# `integration` job, and the two lists are only the same list while they stay in the same order.
#
# `test-e2e` follows `test-integration` for the same reason: ci.yml's `integration` job runs it
# right after that recipe, on the stores that job just provisioned.
#
# Everything a PR must pass, in the order CI runs it.
ci: gen-check lint test test-chaos test-integration test-e2e test-isolation gates conformance fuzz
