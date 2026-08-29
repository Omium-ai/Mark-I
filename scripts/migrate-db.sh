#!/usr/bin/env bash
# =============================================================================
# omium-mark1 — migration runner (the estate's scripts/migrate-db.sh pattern, de-Dockerised)
# =============================================================================
# Applies the numbered, idempotent .sql files in ONE directory, in filename order, recording
# each in schema_migrations keyed "${service}__${filename}" — e.g.
#
#     m1__m1_002_receipt_chain.sql
#
# so a re-run skips what has already run and a RENAMED file is (correctly) treated as new.
# Three prefixes, one runner (13 §R-13.3):
#
#     scripts/migrate-db.sh migrations                     m1
#     scripts/migrate-db.sh python/adjudicator/migrations  adj
#     scripts/migrate-db.sh python/intel/migrations        in
#
# Usage:  DATABASE_URL=postgres://user:pass@host:port/db  scripts/migrate-db.sh <dir> <service>
# Flags:  --dry-run   print what would run, touch nothing
#
# -----------------------------------------------------------------------------
# TWO DIALECTS, ONE DIRECTORY, ONE LEDGER
# -----------------------------------------------------------------------------
# `migrations/` holds both engines' schema, and the split is by FILENAME because that is the
# rule the SQL files themselves declare (m1_ch_001_events.sql: "`m1_0NN_*.sql` run against RDS;
# `m1_ch_0NN_*.sql` run against the ClickHouse host … same Argo CD Sync-hook Job, two runners"):
#
#     m1_ch_*.sql  ->  clickhouse-client, connected from CLICKHOUSE_* (09 §4.2, DDL-only user)
#     everything   ->  psql
#
# Dispatching on the name rather than sniffing the contents keeps this a runner instead of a
# parser. Handing ClickHouse DDL to psql does not degrade — it aborts the whole run on a syntax
# error, so a single unfiltered `find` makes `just migrate` unusable rather than merely wrong.
#
# ONE ledger for both lanes, in Postgres: "applied" is a fact about the deployment, not about an
# engine, and the ledger has to be transactional and read-your-writes to be worth having — which
# is the same reason 07 puts the receipt chain there and not in ClickHouse. So the ClickHouse
# lane needs DATABASE_URL too; the prod Sync-hook Job holds both credentials already.
#
# NO TRANSACTION ON THE CLICKHOUSE LANE — ClickHouse has no DDL transactions, so a file that
# fails halfway leaves its earlier statements applied. That is why every statement in
# m1_ch_*.sql is `IF NOT EXISTS`: idempotency is load-bearing for re-runs there, not house style.
#
# In prod these same files run as an Argo CD PreSync hook Job connecting as the schema owner
# (05 §7). Runtime services never run migrations; that is the per-service-migration gap the
# estate closed and this repo does not reopen.
# =============================================================================

set -euo pipefail

DRY_RUN=false
ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN=true ;;
        -*)        echo "migrate-db: unknown option: $1" >&2; exit 2 ;;
        *)         ARGS+=("$1") ;;
    esac
    shift
done

if [[ ${#ARGS[@]} -ne 2 ]]; then
    echo "usage: DATABASE_URL=... $0 [--dry-run] <migrations-dir> <service-prefix>" >&2
    exit 2
fi

MIGRATIONS_DIR="${ARGS[0]}"
SERVICE="${ARGS[1]}"

: "${DATABASE_URL:?migrate-db: DATABASE_URL is required}"

[[ -d "$MIGRATIONS_DIR" ]] || { echo "migrate-db: no such directory: $MIGRATIONS_DIR" >&2; exit 1; }

# The service prefix is concatenated into a SQL literal below. Constrain it rather than quote it:
# a migration key is an identifier, not user input, and anything outside this class is a typo.
[[ "$SERVICE" =~ ^[a-z][a-z0-9_]{0,31}$ ]] || {
    echo "migrate-db: service prefix must match ^[a-z][a-z0-9_]{0,31}\$ (got: '$SERVICE')" >&2
    exit 2
}

command -v psql >/dev/null 2>&1 || { echo "migrate-db: psql not on PATH" >&2; exit 1; }

log()  { echo "[migrate-db] $*"; }
info() { echo "[migrate-db] → $*"; }
ok()   { echo "[migrate-db] ✓ $*"; }

psql_q() { psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -t -A -c "$1"; }

# ---------------------------------------------------------------------------
# ClickHouse lane preconditions — checked once, up front, and only if this directory actually
# contains ClickHouse files. A runner that discovers halfway through that it cannot finish has
# already half-applied the deployment.
# ---------------------------------------------------------------------------
# The client is overridable so the same script drives a local binary in prod and the dev
# container from compose (CLICKHOUSE_CLIENT="docker exec -i m1-ch clickhouse-client"), which is
# also why files are fed on stdin below rather than via --queries-file: a path is only visible
# to the client when the client shares this filesystem.
read -r -a CH_CLIENT <<< "${CLICKHOUSE_CLIENT:-clickhouse-client}"

ch_files_present=false
[[ -n "$(find "$MIGRATIONS_DIR" -maxdepth 1 -name 'm1_ch_*.sql' -print -quit)" ]] && ch_files_present=true

if $ch_files_present && ! $DRY_RUN; then
    command -v "${CH_CLIENT[0]}" >/dev/null 2>&1 || {
        echo "migrate-db: $MIGRATIONS_DIR contains ClickHouse migrations but '${CH_CLIENT[0]}' is not on PATH" >&2
        echo "migrate-db: set CLICKHOUSE_CLIENT, or install clickhouse-client. \`just stores-up\` already" >&2
        echo "migrate-db: fetched the multi-call binary: CLICKHOUSE_CLIENT=\".stores/bin/clickhouse client\"" >&2
        exit 1
    }
    # clickhouse-client silently defaults to localhost:9000. Requiring the host explicitly is what
    # stops a prod run whose CLICKHOUSE_HOST failed to inject from quietly applying the ledger's
    # DDL to whatever happens to be listening on the migration pod itself.
    : "${CLICKHOUSE_HOST:?migrate-db: CLICKHOUSE_HOST is required to apply m1_ch_*.sql (09 §4.2)}"
fi

# Credentials reach the client through its own CLICKHOUSE_USER / CLICKHOUSE_PASSWORD environment
# variables, never through argv — argv is world-readable in /proc.
apply_clickhouse() { "${CH_CLIENT[@]}" < "$1" > /dev/null; }

# --single-transaction: a failed migration leaves NOTHING behind, so a re-run starts from a
# known state instead of from a half-applied one. No ClickHouse equivalent exists; see the
# header.
apply_postgres() { psql "$DATABASE_URL" -v ON_ERROR_STOP=1 --single-transaction -f "$1" > /dev/null; }

# ---------------------------------------------------------------------------
# The ledger. Created here rather than in a migration: a runner that needs a migration to
# record migrations has a bootstrap hole.
# ---------------------------------------------------------------------------
if ! $DRY_RUN; then
    psql_q "CREATE TABLE IF NOT EXISTS schema_migrations (
                version    VARCHAR(255) PRIMARY KEY,
                applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );" > /dev/null
fi

migration_applied() {
    local version="$1" count
    count=$(psql_q "SELECT COUNT(*) FROM schema_migrations WHERE version = '${version}';" 2>/dev/null || echo 0)
    [[ "$count" -gt 0 ]]
}

log "Applying $MIGRATIONS_DIR as '$SERVICE'"

applied=0
skipped=0
found_any=false
# Read the file list on fd 3, never on stdin. On stdin, ANY command in the loop body that reads
# stdin — a client that slurps it, a wrapper, an ssh — swallows the rest of the list, and the
# loop then ends early and reports "done: 1 applied" with exit 0. A migration runner that
# silently applies a prefix of the schema is worse than one that fails.
while IFS= read -r sql_file <&3; do
    found_any=true
    filename="$(basename "$sql_file")"
    # The other half of the same SQL literal, held to the same rule as the service
    # prefix above. Parameterising is not the alternative it looks like: psql does
    # NOT expand :'var' inside -c, so the ledger queries would have to move to stdin
    # -- and stdin is where the file list deliberately is not.
    [[ "$filename" =~ ^[A-Za-z0-9._-]+$ ]] || {
        echo "migrate-db: migration filename must match ^[A-Za-z0-9._-]+\$ (got: '$filename')" >&2
        exit 2
    }
    version="${SERVICE}__${filename}"

    if ! $DRY_RUN && migration_applied "$version"; then
        info "SKIP (already applied): $version"
        skipped=$((skipped + 1))
        continue
    fi

    case "$filename" in
        m1_ch_*) engine=clickhouse ;;
        *)       engine=postgres ;;
    esac

    if $DRY_RUN; then
        info "[DRY RUN] would apply ($engine): $version"
        continue
    fi

    info "Applying ($engine): $version"
    "apply_${engine}" "$sql_file"
    psql_q "INSERT INTO schema_migrations (version) VALUES ('${version}') ON CONFLICT DO NOTHING;" > /dev/null
    ok "Applied: $version"
    applied=$((applied + 1))
    # LC_ALL=C: migration order is load-bearing, and a locale that collates punctuation
    # differently would silently reorder it.
done 3< <(find "$MIGRATIONS_DIR" -maxdepth 1 -name '*.sql' | LC_ALL=C sort)

if ! $found_any; then
    info "No .sql files in $MIGRATIONS_DIR"
fi

log "done: $applied applied, $skipped already present"
