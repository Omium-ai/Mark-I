"""An in-memory querychoke speaking controld's exact wire, for httpx.MockTransport.

WHY this mock is strict (the wave-5 lesson, RECONCILIATION.md: stub-tested halves of one
contract drift unless one side's tests speak the other side's exact wire bytes — and
wave 7 re-proved it when run_write POSTed the write template to a route controld 403s
while this mock happily accepted it): every route, body-field set and response shape
below is transcribed from go/controld/internal/querychoke/module.go, and controld's own
test replays intel's body (testdata/rollup_write_body.json), locking both directions.

Reads: POST /api/v1/query {"template", "params"} → {"rows", "template_version"}; unknown
template → 400 {"error": {"code": "M1E-2008", …}} (the chokepoint refuses, it does not
improvise); a WRITE-shaped template on this surface → 403 M1E-1001 (module.go
handleQuery; 05 §6.3); missing bearer → 403 M1E-1001. Reads carry NO tenant slot —
tenancy is bound from verified claims (05 §6.2), and this mock refuses a client that
sends one.

Writes: POST /internal/v1/rollup/tvo_tenant_day — the ADR-0010 §2.2 internal seam. FLAT
body: module.go rollupRequest's exact field set (job_key + tenant_id + the 13 row
fields), bearer is the SERVICE credential, and the 200 ack is {"status": "written",
"job_key": …} — identical for a dedup-dropped re-run (idempotent by design; the no-op
signal belongs to the driving job's ledger, layer 1)."""

import json

import httpx

QUERY_PATH = "/api/v1/query"
ROLLUP_WRITE_PATH = "/internal/v1/rollup/tvo_tenant_day"
WRITE_TEMPLATE = "tvo_rollup_tenant_day"

# module.go rollupRequest, exact — a field intel adds or drops without controld
# shipping the same change goes red here.
ROLLUP_FIELDS = frozenset(
    {
        "job_key",
        "tenant_id",
        "day",
        "series",
        "tokens_total",
        "cost_usd",
        "tasks_verified",
        "tasks_unresolved",
        "retry_loop_tokens",
        "reexploration_tokens",
        "over_model_tokens",
        "observed_ms",
        "bypass_ms",
        "disabled_ms",
        "dropped_billing",
    }
)


class MockChoke:
    def __init__(self) -> None:
        # template -> rows list OR callable(params) -> rows list
        self.templates: dict = {}
        self.requests: list[tuple[str, dict, str | None]] = []
        self.rollup_store: dict[str, dict] = {}  # job_key -> body, dedupe-keyed
        self.fail_with: tuple[int, str, str] | None = None  # (status, code, message)

    def _error(self, status: int, code: str, message: str) -> httpx.Response:
        return httpx.Response(status, json={"error": {"code": code, "message": message}})

    def handler(self, request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        if request.url.path == ROLLUP_WRITE_PATH:
            return self._rollup_write(request)
        assert request.url.path == QUERY_PATH, request.url.path
        body = json.loads(request.content)
        assert set(body) == {"template", "params"}, body  # the §3.3 read body, exact
        template, params = body["template"], body["params"]
        auth = request.headers.get("authorization")
        self.requests.append((template, params, auth))

        # Tenancy is claims-bound for reads — a tenant inside params is undeclared
        # and Build refuses it (builder.go).
        assert "tenant_id" not in params, "tenant_id must never be a template param"

        if self.fail_with is not None:
            return self._error(*self.fail_with)
        if not auth or not auth.startswith("Bearer ") or auth == "Bearer ":
            return self._error(403, "M1E-1001", "caller lacks operator role")

        if template == WRITE_TEMPLATE:
            # module.go handleQuery, verbatim posture: the tenant query surface
            # refuses write-shaped templates — the rollup write belongs to the
            # internal seam above (05 §6.3).
            return self._error(
                403, "M1E-1001", "write-shaped templates are not executable on this surface"
            )
        if template not in self.templates:
            return self._error(400, "M1E-2008", "unknown query template")
        rows = self.templates[template]
        if callable(rows):
            rows = rows(params)
        return httpx.Response(200, json={"rows": rows, "template_version": f"{template}.v1"})

    def _rollup_write(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        assert set(body) == ROLLUP_FIELDS, set(body) ^ ROLLUP_FIELDS
        auth = request.headers.get("authorization")
        self.requests.append((WRITE_TEMPLATE, body, auth))
        if self.fail_with is not None:
            return self._error(*self.fail_with)
        if not auth or not auth.startswith("Bearer ") or auth == "Bearer ":
            return self._error(403, "M1E-1001", "service credential required")
        # ADR-0010 §3 physical layer: a repeated job_key's block is DROPPED, and the
        # ack is IDENTICAL to first-write (module.go: "a dedup-dropped re-run answers
        # 200 too — the no-op signal belongs to the driving job's ledger").
        self.rollup_store.setdefault(body["job_key"], body)
        return httpx.Response(200, json={"status": "written", "job_key": body["job_key"]})

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handler)

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=self.transport(), base_url="http://choke")
