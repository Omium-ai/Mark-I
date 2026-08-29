## What

<!-- One paragraph. Link the doc section or ADR this implements. -->

## Contract check (mechanically enforced by contracts_sync_check — this is the human half)

- [ ] No proto/message, table, bundle-section, error-code, or hook-payload change — OR —
- [ ] `docs/07-data-model.md` / `docs/08-api-contracts.md` updated **in this PR**

## Discipline

- [ ] No new direct dependency — OR — the dependency is named below with why the ladder
      (stdlib → existing dep → small code) doesn't hold
- [ ] No new `#[allow(clippy::unwrap_used)]` / lint suppression — OR — each carries a reason comment
- [ ] Failure postures of new paths stated (open/static/closed) and matched to 04/05's matrix
- [ ] Tests: the behavior this PR adds has the test 12 names (or this PR adds it)

## New dependency justification (if any)

<!-- name, version pin, license, transitive count, why not stdlib/existing -->
