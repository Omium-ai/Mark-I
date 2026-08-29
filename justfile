# omium-mark1 — every verb in the repo. CI runs THESE recipes; if you're typing a raw
# cargo/go/uv/buf command that has a recipe, you're doing it wrong.

set windows-shell := ["powershell.exe", "-NoLogo", "-Command"]

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
# `/?database=default`, not `/default`: ClickHouse's HTTP interface routes on handler names, not
# path segments, and answers a POST to `/default` with 404 ("Use / or /ping for health checks").
# The stores-up probe below reads that 404 as "not up yet" and waits out its full 60s, so the
# wrong path here does not misconfigure a client — it makes the whole store lane unable to start.
export M1_TEST_CH_DSN     := env_var_or_default("M1_TEST_CH_DSN", "http://127.0.0.1:8123/?database=default")
# 9002, not MinIO's usual 9000: ClickHouse's NATIVE port is 9000 and its client, its docs and
# this repo's ClickHouse migration lane all assume that default. Two conventional ports collide
# on one loopback and only one of them can move without breaking tools — so MinIO moves.
export M1_TEST_S3_ENDPOINT := env_var_or_default("M1_TEST_S3_ENDPOINT", "http://127.0.0.1:9002")

default: lint test

# ---------- codegen ----------

# Regenerate committed proto bindings and stage the Rust gen into m1p-wire.
gen:
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
#   chaos       -> nightly + phase gates (12 §6); ⚡ fast set selected by the chaos harness
#
# Untagged Go tests, all three modules, no exclusion globs (12 §0.3 mechanism 1).
# The inventory above is a claim about tags in files that exist; `_go-src` is what stops
# it being made over a module with no files (see build-go).
test-go: (_go-src "mark1d") (_go-src "mark1") (_go-src "controld")
    cd go/mark1d   && go test ./...
    cd go/mark1    && go test ./...
    cd go/controld && go test ./...

test-py:
    uv run --frozen --all-packages -m pytest python/shared/mark1_receipts/tests -o asyncio_mode=auto
    uv run --frozen --all-packages -m pytest python/adjudicator/tests -o asyncio_mode=auto
    uv run --frozen --all-packages -m pytest python/intel/tests -o asyncio_mode=auto

# Cross-language conformance vectors: Rust ↔ Go ↔ Python must agree bit-identically.
conformance:
    tools/ci/conformance_crosslang.sh

# Store-backed suites, incl. the tag-gated Go integration suite. Real stores on EVERY PR
# (12 §11.4) — no Docker, no testcontainers, no skip-if-absent. Run `just stores-up` first.
test-integration:
    uv run --frozen --all-packages -m pytest python/adjudicator/tests python/intel/tests -o asyncio_mode=auto -m integration
    cd go/controld && go test -tags=integration ./...

# `conformance/tenancy/` carries the specs; its conftest asserts zero skips under
# M1_REQUIRE_STORES=1, so "passed" cannot mean "did not run".
#
# Tenant-isolation negative tests (12 §4) — the required PR check the tenancy story rests on.
test-isolation:
    uv run --frozen --all-packages -m pytest conformance/tenancy -o asyncio_mode=auto

# ---------- lint / fmt ----------

lint: lint-rust lint-go lint-py lint-proto gates

lint-rust:
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets --locked -- -D warnings
    cargo deny check

lint-go:
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
gates:
    tools/ci/otel_gate.sh
    tools/ci/secret_type_gate.sh
    tools/ci/override_pattern_gate.sh

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

# Absolute budgets are only meaningful on the pinned runner class (12 §7.2, bench/RUNNER.md).
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
# everything else to psql (see scripts/migrate-db.sh). CLICKHOUSE_HOST is a hard precondition
# there — it refuses rather than skipping, because a "migrated" deployment missing its ledger
# tables is the failure this repo will not ship — but the connection actually made is whatever
# CLICKHOUSE_CLIENT names, since the pinned client reads only CLICKHOUSE_USER and
# CLICKHOUSE_PASSWORD from the environment. `just stores-up` prints both values on exit.
migrate dsn:
    DATABASE_URL={{dsn}} scripts/migrate-db.sh migrations m1
    DATABASE_URL={{dsn}} scripts/migrate-db.sh python/adjudicator/migrations adj
    DATABASE_URL={{dsn}} scripts/migrate-db.sh python/intel/migrations in

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

    # --- Postgres 15: preinstalled on the GitHub Ubuntu runner; brew/apt elsewhere ---
    PG_BIN="${PG_BIN:-}"
    if [ -z "$PG_BIN" ]; then
      if [ -d /usr/lib/postgresql/15/bin ]; then PG_BIN=/usr/lib/postgresql/15/bin
      elif command -v initdb >/dev/null 2>&1; then PG_BIN="$(dirname "$(command -v initdb)")"
      else echo "stores-up: no PostgreSQL 15 binaries found; set PG_BIN=" >&2; exit 1; fi
    fi
    if ! "$PG_BIN/pg_isready" -h 127.0.0.1 -p 5432 >/dev/null 2>&1; then
      [ -f "$ROOT/pg/PG_VERSION" ] || {
        mkdir -p "$ROOT/pg"
        "$PG_BIN/initdb" -D "$ROOT/pg" -U mark1 --auth=trust --encoding=UTF8 >/dev/null
      }
      "$PG_BIN/pg_ctl" -D "$ROOT/pg" -l "$ROOT/log/pg.log" \
        -o "-h 127.0.0.1 -p 5432 -k $ROOT" -w start
      "$PG_BIN/createdb" -h 127.0.0.1 -p 5432 -U mark1 mark1_test 2>/dev/null || true
    fi

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
        curl -fsSL -o "$BIN/minio" \
          "https://dl.min.io/server/minio/release/${OS}-${ARCH}/archive/minio.${MINIO_VERSION}"
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
    [ -d "$ROOT/pg" ] && "${PG_BIN:-/usr/lib/postgresql/15/bin}/pg_ctl" -D "$ROOT/pg" -m fast stop || true
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
# Everything a PR must pass, in the order CI runs it.
ci: gen-check lint test test-integration test-isolation gates conformance fuzz
