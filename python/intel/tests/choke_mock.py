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
signal belongs to the driving job's ledger, layer 1).

Receipts: POST /internal/v1/receipts/append — receipts/append.go handleAppend, the ONE
writer of m1_receipts (m1_002 §5). Body {tenant_id, record_type, subject_id,
idempotency_key, payload}; a repeat under the same (tenant, record_type, idempotency_key)
answers the identical ack (m1_072); the ack is {receipt_id, seq, receipt_hash, payload}
with payload the canonical signed text. Fixture-locked both ways:
go/controld/internal/receipts/testdata/receipt_append_body.json."""

import hashlib
import json
import uuid

import httpx
from mark1_receipts import DOMAIN_PREFIX, canonical_json

QUERY_PATH = "/api/v1/query"
SERVICE_QUERY_PATH = (
    "/internal/v1/query"  # the driver's read surface: tenant_id in the body, service bearer
)
ROLLUP_WRITE_PATH = "/internal/v1/rollup/tvo_tenant_day"
WRITE_TEMPLATE = "tvo_rollup_tenant_day"
APPEND_PATH = "/internal/v1/receipts/append"
APPEND_FIELDS = frozenset({"tenant_id", "record_type", "subject_id", "idempotency_key", "payload"})
INTERNAL_RECORD_TYPES = frozenset(
    {"noise_certificate", "memory_admission", "bundle_publication", "corpus_export"}
)

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
        self.appended: list[dict] = []  # every accepted append body, in order
        self.receipts: dict[tuple[str, str, str], dict] = {}  # (tenant, type, key) -> ack
        self.append_fail_with: tuple[int, str, str] | None = None  # the chain-side failure

    def _error(self, status: int, code: str, message: str) -> httpx.Response:
        return httpx.Response(status, json={"error": {"code": code, "message": message}})

    def handler(self, request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        if request.url.path == ROLLUP_WRITE_PATH:
            return self._rollup_write(request)
        if request.url.path == APPEND_PATH:
            return self._receipt_append(request)
        assert request.url.path in (QUERY_PATH, SERVICE_QUERY_PATH), request.url.path
        body = json.loads(request.content)
        if request.url.path == SERVICE_QUERY_PATH:
            # module.go handleServiceQuery: tenant in the body, service credential as bearer
            assert set(body) == {"tenant_id", "template", "params"}, body
            assert body["tenant_id"], "a service read names its tenant"
        else:
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

    def _receipt_append(self, request: httpx.Request) -> httpx.Response:
        auth = request.headers.get("authorization")
        if not auth or not auth.startswith("Bearer ") or auth == "Bearer ":
            return self._error(403, "M1E-1001", "service credential required")
        body = json.loads(request.content)
        assert set(body) == APPEND_FIELDS, set(body) ^ APPEND_FIELDS
        assert body["record_type"] in INTERNAL_RECORD_TYPES, body["record_type"]
        assert uuid.UUID(body["subject_id"]) != uuid.UUID(int=0) and body["idempotency_key"]
        if self.append_fail_with is not None:
            return self._error(*self.append_fail_with)
        key = (body["tenant_id"], body["record_type"], body["idempotency_key"])
        if key not in self.receipts:
            seq = 1 + sum(1 for k in self.receipts if k[0] == body["tenant_id"])
            text = canonical_json(
                {
                    **body["payload"],
                    "v": 1,
                    "type": body["record_type"],
                    "tenant_id": body["tenant_id"],
                    "seq": seq,
                    "prev_receipt_hash": "00" * 32,
                    "issued_at": "2026-09-16T00:00:00Z",
                    "subject_id": body["subject_id"],
                }
            )
            self.appended.append(body)
            self.receipts[key] = {
                "receipt_id": str(uuid.uuid4()),
                "seq": seq,
                "receipt_hash": hashlib.sha256(DOMAIN_PREFIX + text.encode()).hexdigest(),
                "payload": text,
            }
        return httpx.Response(200, json=self.receipts[key])

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handler)

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=self.transport(), base_url="http://choke")
