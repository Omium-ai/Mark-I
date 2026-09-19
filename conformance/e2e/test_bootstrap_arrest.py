"""The headline moment, end to end on real binaries: a fresh tenant enrolls, controld publishes
its bootstrap bundle (stable seq 1) at that moment, the daemon pins the section keys from the
enrollment body, fetches and verifies the bundle (signatures, seq, tlog inclusion against the
head its proof targets), and a consented ruff anchor on a real defect drives the retry loop
through the real hookshim until the knee governor arrests it: BLOCK, BLOCK, then the Stop hook's
systemMessage, the daemon's `/v1/verify/events` arrest row and `event: arrest` on `/v1/events`.

Nothing seeds a verdict: every vote is ruff's own, every number the bootstrap's.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
import time
from pathlib import Path

import httpx
import pytest
from rig import CORPUS, REQUIRE_STORES, Rig, fail

KNEE_ATTEMPT = 3  # policydist/bootstrap.go: p1=0.5, γ=0.6, ρ=0.4 ⇒ first stopping row n=3


class ArrestRig(Rig):
    control: dict = {}
    stop_runs: dict[int, str] = {}
    arrest_frames: list[str] = []
    ack_row: dict = {}
    lkg: dict = {}
    verify_events: list[dict] = []

    def drive(self) -> None:
        self._dirs()
        self._build()
        self._stores()
        self._controld()
        self._enroll()
        self._defect_workspace()
        self._enable()
        # --policy-url: the dev seam until cmd/main.go fills it from enrollment.json's `server`.
        self._mark1d("--policy-url", self.controld_url)
        self._arm()
        self._await_bundle()
        self._retry_loop()
        self._await_votes()
        self._shutdown_mark1d()

    # ---- the workspace ruff really fails ------------------------------------
    def _defect_workspace(self) -> None:
        # A repo committed CLEAN, then the defect as the agent's uncommitted edit: the anchor's
        # verdict is about what git says was touched (a committed defect would be the repo's
        # baseline), and an attempt is a new state of the tree (votes.go record), so each retry
        # below edits the tracked file while the defect stays.
        (self.workspace / "pyproject.toml").write_text("[tool.ruff]\n")
        (self.workspace / "defect.py").write_text("x = 1\n")
        for args in (
            ["init", "-q"],
            ["add", "."],
            ["-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "-m", "clean"],
        ):
            r = subprocess.run(
                ["git", *args], cwd=self.workspace, capture_output=True, text=True, check=False
            )
            if r.returncode != 0:
                fail(f"git {args}: {r.stderr}")
        self._retry(0)
        ruff = shutil.which("ruff")
        if not ruff:
            fail(
                "ruff is not on PATH: the arrest proof needs a real consented anchor "
                "and refuses to fake one"
            )
        os.symlink(
            os.path.realpath(ruff), self.tmp / "bin" / "ruff"
        )  # the daemon's PATH is the rig's

    # ---- the control API (what the desktop app drives) -----------------------
    def _control(self) -> dict:
        if not self.control:
            self.control = json.loads((self.state / "run" / "control.json").read_text())
        return self.control

    def local(self, method: str, path: str, body: dict | None = None) -> httpx.Response:
        c = self._control()
        return httpx.request(
            method,
            f"http://127.0.0.1:{c['port']}{path}",
            json=body,
            headers={"Authorization": f"Bearer {c['token']}"},
            timeout=30,
        )

    def anchors(self) -> list[dict]:
        r = self.local("GET", "/v1/anchors", None)
        if r.status_code != 200:
            fail(f"GET /v1/anchors: {r.status_code} {r.text[:300]}")
        return r.json()

    def _arm(self) -> None:
        deadline = time.monotonic() + 30
        ruff = None
        while time.monotonic() < deadline and ruff is None:
            ruff = next((a for a in self.anchors() if a["id"] == "ruff@cat-1"), None)
            if ruff is None:
                time.sleep(0.25)
        if ruff is None:
            fail(
                f"the daemon never derived ruff@cat-1 for {self.workspace}:\n{self._tail_daemon()}"
            )
        r = self.local(
            "POST",
            "/v1/anchors/consent",
            {
                "project": str(self.workspace),
                "id": "ruff@cat-1",
                "exec_hash": ruff["exec_hash"],
                "consented": True,
            },
        )
        if r.status_code != 200:
            fail(f"consent: {r.status_code} {r.text[:300]}")
        r = self.local("PUT", "/v1/optins", {"stop_gate": True})
        if r.status_code != 200:
            fail(f"opt-in: {r.status_code} {r.text[:300]}")
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if next(a for a in self.anchors() if a["id"] == "ruff@cat-1").get("consented"):
                return
            time.sleep(0.25)
        fail(f"consent never reconciled into the catalog:\n{self._tail_daemon()}")

    def _tail_daemon(self) -> str:
        from rig import _tail

        return (
            f"--- mark1d ---\n{_tail(self.logs['mark1d'])}\n"
            f"--- controld ---\n{_tail(self.logs['controld'])}"
        )

    # ---- the bundle lands on the edge ----------------------------------------
    def _await_bundle(self) -> None:
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            rows = self.pg(
                "SELECT channel, seq, result, reject_code FROM bundle_acks "
                "WHERE device_id = $1 ORDER BY acked_at",
                self.device_id,
            )
            if rows:
                self.ack_row = rows[-1]
                if self.ack_row["result"] != "applied":
                    fail(f"the daemon refused the bootstrap bundle: {rows}\n{self._tail_daemon()}")
                meta = self.state / "policy" / "lkg.json"
                if meta.exists():
                    self.lkg = json.loads(meta.read_text())
                    return
            time.sleep(0.5)
        fail(f"no ACK for the bootstrap bundle within 60 s:\n{self._tail_daemon()}")

    # ---- the retry loop through the real shim ---------------------------------
    def _hook_body(self, event: str, **patch: object) -> bytes:
        d = json.loads((CORPUS / "hooks" / f"{event}.json").read_text())
        d.update(patch)
        return json.dumps(d).encode()

    def _retry(self, n: int) -> None:
        """The agent's n-th try: the tracked file changes, the F401 defect stays."""
        (self.workspace / "defect.py").write_text(f"import os\n# attempt {n}\n")

    def _runs(self) -> int:
        """Anchor runs so far: the runner keeps one evidence directory per run (evidence.Open)."""
        return len(list((self.state / "evidence").glob("*/ruff@cat-1-*")))

    def _stop(self) -> str:
        return self._fire_hook("Stop", self._hook_body("Stop")).stdout

    def _retry_loop(self) -> None:
        self._fire_hook("SessionStart")
        self._fire_hook("UserPromptSubmit")  # the human turn opens the task (ADR-0002 R1)
        for n in range(1, KNEE_ATTEMPT + 1):
            self._retry(n)
            self._fire_hook(
                "PostToolUse",
                self._hook_body("PostToolUse", tool_use_id=f"toolu_01E2EArrestAttempt{n:02d}"),
            )
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline and self._runs() < n:
                time.sleep(0.1)
            if self._runs() < n:
                fail(f"attempt {n}: ruff never ran after PostToolUse:\n{self._tail_daemon()}")
            if n == KNEE_ATTEMPT:
                listener = threading.Thread(target=self._listen_events, daemon=True)
                listener.start()
                time.sleep(0.5)
            want = "systemMessage" if n == KNEE_ATTEMPT else f"attempt {n}"
            deadline = time.monotonic() + 30
            out = ""
            while time.monotonic() < deadline:
                out = self._stop()
                if want in out:
                    break
                time.sleep(0.2)
            self.stop_runs[n] = out
            if want not in out:
                fail(
                    f"attempt {n}: Stop never answered with {want!r}; last stdout {out!r}\n"
                    f"{self._tail_daemon()}"
                )
        for _ in range(50):
            if self.arrest_frames:
                break
            time.sleep(0.1)
        self.verify_events = self.local("GET", "/v1/verify/events").json()

    def _listen_events(self) -> None:
        c = self._control()
        try:
            with httpx.stream(
                "GET",
                f"http://127.0.0.1:{c['port']}/v1/events",
                headers={"Authorization": f"Bearer {c['token']}"},
                timeout=httpx.Timeout(60, read=60),
            ) as r:
                event = None
                for line in r.iter_lines():
                    if line.startswith("event: "):
                        event = line[7:]
                    elif line.startswith("data: ") and event == "arrest":
                        self.arrest_frames.append(line[6:])
                        return
        except httpx.HTTPError:
            return

    def _await_votes(self) -> None:
        self._fire_hook("SessionEnd")
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            if self.landed().get("AnchorVote", 0) >= KNEE_ATTEMPT:
                return
            time.sleep(1)
        fail(f"anchor votes never landed on the ledger: {self.landed()}\n{self._tail_daemon()}")


@pytest.fixture(scope="module")
def arrest() -> ArrestRig:
    for var in ("M1_TEST_PG_DSN", "M1_MIGRATE_PG_DSN", "M1_TEST_CH_DSN", "M1_TEST_S3_ENDPOINT"):
        if not os.environ.get(var):
            msg = f"{var} is unset — run `just test-e2e`"
            if REQUIRE_STORES:
                pytest.fail(msg, pytrace=False)
            pytest.skip(msg)
    r = ArrestRig()
    try:
        r.drive()
    except BaseException:
        r.teardown()
        raise
    yield r
    r.teardown()


def test_enrollment_publishes_the_bootstrap_bundle(arrest: ArrestRig) -> None:
    """Enrollment minted stable seq 1 for the tenant: one catalog row, one tlog leaf, one
    bundle_publication receipt, and never a second seq 1."""
    rows = arrest.pg(
        "SELECT channel, seq, tlog_index, max_age FROM policy_bundles "
        "WHERE tenant_id = $1 ORDER BY seq",
        arrest.tenant_id,
    )
    assert [(r["channel"], r["seq"], r["tlog_index"]) for r in rows] == [("stable", 1, 0)], rows
    assert rows[0]["max_age"].days == 365
    head = arrest.pg(
        "SELECT head_seq FROM bundle_channel_heads WHERE tenant_id = $1 AND channel = 'stable'",
        arrest.tenant_id,
    )
    assert head[0]["head_seq"] == 1
    receipts = arrest.pg(
        "SELECT count(*) AS n FROM m1_receipts "
        "WHERE tenant_id = $1 AND record_type = 'bundle_publication'",
        arrest.tenant_id,
    )
    assert receipts[0]["n"] == 1
    leaves = arrest.pg(
        "SELECT kind FROM tlog_leaves WHERE tenant_id = $1 ORDER BY leaf_index", arrest.tenant_id
    )
    assert [r["kind"] for r in leaves][:1] == ["policy_bundle"]


def test_enrollment_pins_the_section_keys_on_the_edge(arrest: ArrestRig) -> None:
    """`mark1 enroll` wrote <state>/policy/keys.json from the ACTIVE body; the six pinned keys are
    the ring controld publishes on /.well-known/mark1-keys."""
    pinned = json.loads((arrest.state / "policy" / "keys.json").read_text())["bundle_section_keys"]
    assert sorted(k["section"] for k in pinned) == sorted(
        ["verify", "route", "memory", "cortex", "gates", "agent_maps"]
    )
    served = httpx.get(f"{arrest.controld_url}/.well-known/mark1-keys", timeout=30).json()
    assert {k["pubkey_hex"] for k in pinned} == {
        k["pubkey_hex"] for k in served["bundle_section_keys"]
    }
    assert "head" not in served["tlog"], "an anonymous read must not carry a tenant's log head"
    mode = (arrest.state / "policy" / "keys.json").stat().st_mode & 0o777
    assert mode == 0o600


def test_daemon_verified_and_applied_the_bootstrap(arrest: ArrestRig) -> None:
    """The edge ACKed `applied` for stable seq 1 and persisted it as last-known-good with the tlog
    head its inclusion proof targets (tree_size 1)."""
    assert (arrest.ack_row["channel"], arrest.ack_row["seq"], arrest.ack_row["result"]) == (
        "stable",
        1,
        "applied",
    )
    assert arrest.ack_row["reject_code"] is None
    assert arrest.lkg["seq"] == 1
    assert arrest.lkg["tlog_head_tree_size"] == 1
    assert (arrest.state / "policy" / "lkg.cbor").stat().st_size > 1000
    assert "policy bundle applied" in Path(arrest.logs["mark1d"]).read_text()


def test_retry_loop_is_arrested_at_the_knee(arrest: ArrestRig) -> None:
    """BLOCK below the knee (attempts 1, 2), the knee's systemMessage at attempt 3 — the fused
    verdict is ruff's own F401, the economics are the bootstrap's knee table."""
    for n in (1, 2):
        out = json.loads(arrest.stop_runs[n])
        assert out["decision"] == "block", out
        assert (
            f"attempt {n}" in out["reason"] and "verdict violated below the knee" in out["reason"]
        ), out
        assert "[evidence: ruff:F401" in out["reason"], out
    knee = json.loads(arrest.stop_runs[KNEE_ATTEMPT])
    assert "decision" not in knee, knee
    msg = knee["systemMessage"]
    assert msg.startswith("mark1 stop-gate: retry loop arrested at the knee — verdict violated"), (
        msg
    )
    assert (
        f"stop at attempt {KNEE_ATTEMPT}" in msg and "under quota" in msg and "ruff:F401" in msg
    ), msg


def test_arrest_is_on_the_daemons_verify_surface(arrest: ArrestRig) -> None:
    """/v1/verify/events holds the arrest row the desktop app renders, and /v1/events streamed
    it as `event: arrest` the moment the gate told the human."""
    arrests = [e for e in arrest.verify_events if e["type"] == "arrest"]
    assert len(arrests) == 1, arrest.verify_events
    assert arrest.arrest_frames, "no `event: arrest` frame arrived on /v1/events"
    row = json.loads(arrest.arrest_frames[0])
    assert row == arrests[0], (row, arrests[0])
    assert row["type"] == "arrest"
    assert row["attempt"] == KNEE_ATTEMPT
    assert (
        row["p_lcb"] == pytest.approx(0.18) and row["v"] == 1.0 and row["c_n"] == pytest.approx(0.2)
    )
    assert row["inequality"] == "0.180 * 1.00 <= 0.20"
    assert row["evidence_ref"].startswith("ruff:F401 errors=")
    assert row["session_id"] == "3f9c2e71-58d4-4b6a-9e2f-7a1c0d8b4e55"


def test_votes_landed_on_the_ledger(arrest: ArrestRig) -> None:
    """Every attempt's AnchorVote is a VIOLATED ruff@cat-1 vote on the cloud ledger."""
    rows = arrest.ch_query(f"""
        SELECT JSONExtractString(payload, 'anchor_id') AS anchor_id,
               JSONExtractString(payload, 'vote') AS vote, count() AS n
        FROM mark1.m1p_events
        WHERE tenant_id = toUUID('{arrest.tenant_id}') AND event_type = 'AnchorVote'
        GROUP BY anchor_id, vote""")
    assert rows and all(
        r["anchor_id"] == "ruff@cat-1" and r["vote"].endswith("VIOLATED") for r in rows
    ), rows
    assert sum(int(r["n"]) for r in rows) >= KNEE_ATTEMPT
