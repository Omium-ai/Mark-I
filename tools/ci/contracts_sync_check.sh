#!/bin/sh
# contracts_sync_check.sh — if the diff touches a contract surface, it must also touch
# the owning contract document. BASE_REF is provided by ci.yml (the PR base SHA).
#
# The patterns are deliberately over-broad. The failure mode of this gate is a reviewer adding
# a one-line note to 07/08's changelog; the failure mode of the inverse gate is a silently
# drifted contract document. Over-trigger is the correct bias. (13 §10.3)
set -eu

if [ -z "${BASE_REF:-}" ]; then
  echo "FAIL: BASE_REF is unset. Set it to the PR base SHA/ref (ci.yml does this)."; exit 1
fi

cd "$(dirname "$0")/../.."
CHANGED=$(git diff --name-only "${BASE_REF}"...HEAD)
touches() { echo "$CHANGED" | grep -qE "$1"; }

echo "contracts_sync_check: $(echo "$CHANGED" | grep -c . ) file(s) changed since ${BASE_REF}"

if touches '^proto/m1p/' && ! touches '^docs/07-data-model\.md'; then
  echo "FAIL: proto change without docs/07-data-model.md in the same PR (00-README sync rule)"; exit 1
fi
if touches '^(migrations|python/adjudicator/migrations|python/intel/migrations)/' \
   && ! touches '^docs/07-data-model\.md'; then
  echo "FAIL: migration change without docs/07-data-model.md in the same PR"; exit 1
fi
if touches 'sections\.rs|policydist/catalog\.go|policy_compiler/' && ! touches '^docs/07-data-model\.md'; then
  echo "FAIL: bundle-section change without docs/07 in the same PR"; exit 1
fi
if touches 'errors?\.(rs|go|py)$|M1E-' && ! touches '^docs/08-api-contracts\.md'; then
  echo "FAIL: error-taxonomy change without docs/08-api-contracts.md in the same PR"; exit 1
fi
if touches '^go/mark1d/adapters/|^rust/mark1-hookshim/src/maps\.rs' && ! touches '^docs/08-api-contracts\.md'; then
  echo "FAIL: hook/adapter contract change without docs/08 in the same PR"; exit 1
fi
echo "contracts_sync_check: OK"
