# Nothing here is TBD any more (2026-09-17)

Every route the spec once marked *TBD* (§7.2) is implemented in `go/controld/internal/appapi`
and served by the daemon's control API; the fixtures in this directory are captured from
those implementations, not guessed. The contract the app treats as frozen is
`Mark1-GUI/src/shared/endpoints.ts` (zod on both IPC sides), reconciled against the daemon
fixtures here (local routes, exact) and controld's JSON Schemas (cloud routes, union). Spec
§7.1 was rewritten to the same truth. Routes added since the original list: memory actions
(`retire`/`pin`/`unpin`/`share`/`unshare`), `PUT /api/v1/consents`, per-agent
`pause`/`resume`, `provision`/`disable`, team `PUT`, receipts `export` (ndjson) and
`witness`, `shutdown`.

Still simplified in the fixtures: every tenant is single-regime (apikey/usd). §5.3's
mixed-regime split (two reports, never one) is real in controld but not modeled here.
