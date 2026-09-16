#!/bin/sh
# adr_signed_gate.sh — the write paths 02 §12 gates on a signed ADR may only exist once the
# ADR's Status line reads Accepted (FR-SPINE-013: ClickHouse DDL behind ADR-0001; ADR-0010:
# the tvo_tenant_day rollup writer). The status is read from the document that owns it, the
# same way shapley_gate.sh reads ADR-0003, so a revert of a signature reds the build instead
# of quietly leaving DDL in the tree that the spec says cannot exist.
set -eu
cd "$(dirname "$0")/../.."

fail=0
check() {
  adr=$1; shift
  [ -f "$adr" ] || { echo "FAIL: $adr missing — cannot derive whether $* may exist"; fail=1; return; }
  status=$(sed -n 's/^- \*\*Status:\*\* *//p' "$adr" | head -1)
  case "$status" in
    Accepted*) ;;
    '') echo "FAIL: no '- **Status:**' line parsed from $adr"; fail=1 ;;
    *)  for f in "$@"; do
          [ -e "$f" ] && { echo "FAIL: $f exists while $adr reads '$status' (02 §12: signature before the first write)"; fail=1; }
        done ;;
  esac
}

# shellcheck disable=SC2046
check docs/adr/0001-clickhouse-ordering-key.md $(ls migrations/m1_ch_*.sql 2>/dev/null)
check docs/adr/0010-tvo-rollup-writer.md python/intel/app/tvo/rollup.py

[ "$fail" -eq 0 ] || exit 1
echo "adr_signed_gate: OK (ADR-0001 and ADR-0010 Accepted; gated write paths permitted)"
