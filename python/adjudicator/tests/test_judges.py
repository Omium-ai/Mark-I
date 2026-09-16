"""Judge orchestration (06 §6): registry lockstep, client-side default, the consent-gated
cloud path, evidence-tier gating, and the refusal discipline (FR-VERIFY-015 /
NFR-PRIVACY-006 / FR-VERIFY-016 negatives)."""

import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from app.judges.cloud_path import CloudJudge, Consent, parse_verdict
from app.judges.specs import (
    _REGISTERED_JUDGES,
    JUDGE_REQUESTS_PATH,
    JUDGE_SPECS,
    ClientSideJudge,
    JudgeRefused,
    judges_refused_total,
    request_id_for,
)
from m1p.v1 import EvidenceTier, JudgeLocus, JudgeRequest, JudgeVote, Verdict

JID = "judge:grounded-rubric@1"
SPEC = JUDGE_SPECS[JID]
CONSENT = Consent(subprocessor="anthropic", region="us", max_tier="E0")
IDS = (uuid4(), uuid4(), uuid4(), uuid4())  # tenant, task, attempt, session
LOCK = (
    Path(__file__).resolve().parents[3]
    / "go/controld/internal/policydist/testdata/judge_request_body.json"
)


class FakeControld:
    """The controld fan-out route as the client sees it: records the POST, answers a status."""

    def __init__(self, status=200):
        self.calls, self._status = [], status

    async def post(self, url, *, json, headers):
        self.calls.append((url, json, headers))
        return SimpleNamespace(status_code=self._status, text='{"error":{"code":"M1E-2001"}}')


def client_side(http=None, base_url="http://controld:8080", token="intel-secret", profile="saas"):
    http = http or FakeControld()
    return ClientSideJudge(http, base_url, token, profile), http


class FakeClient:
    def __init__(self, reply="violated", stop="end_turn", geo="us"):
        self.calls, self._reply, self._stop, self._geo = [], reply, stop, geo
        self.messages = self

    async def create(self, **kw):
        self.calls.append(kw)
        return SimpleNamespace(
            content=[SimpleNamespace(type="text", text=self._reply)],
            stop_reason=self._stop,
            usage=SimpleNamespace(inference_geo=self._geo),
        )


def cloud(client=None, consent=CONSENT, profile="saas") -> tuple[CloudJudge, FakeClient]:
    client = client or FakeClient()

    async def consent_for(tenant_id, judge_id):
        return consent

    async def evidence_for(task_id, attempt_id, tier):
        return f"{tier} typed evidence for {task_id}"

    return CloudJudge(client, consent_for, evidence_for, profile), client


def test_registry_and_registered_set_are_the_same_fact():
    assert set(JUDGE_SPECS) == _REGISTERED_JUDGES
    for jid, spec in JUDGE_SPECS.items():
        assert jid == spec.judge_id and len(spec.confusion) == 4


def test_rubric_names_the_wire_vocabulary_verbatim():
    vocab = "|".join(v.name.lower() for v in Verdict if v.value)
    assert vocab == "satisfied|violated|refused|error"
    assert vocab in SPEC.rubric


async def test_client_side_default_emits_request_and_makes_no_cloud_call(monkeypatch):
    def boom(*a, **kw):
        raise AssertionError("cloud judge call on the default path")

    monkeypatch.setattr("anthropic.resources.messages.AsyncMessages.create", boom)
    judge, http = client_side()
    req = await judge.run(*IDS[:1], JID, *IDS[1:])
    assert isinstance(req, JudgeRequest)
    assert req.locus == JudgeLocus.CLIENT_SIDE
    assert (req.judge_id, req.model, req.tier) == (JID, SPEC.model, EvidenceTier.E0)
    assert (req.task_id, req.session_id) == (IDS[1].bytes, IDS[3].bytes)
    assert req.request_id == request_id_for(JID, IDS[1], IDS[2])
    assert not hasattr(req, "evidence") and not hasattr(req, "api_key")
    ((url, body, headers),) = http.calls
    assert url == "http://controld:8080" + JUDGE_REQUESTS_PATH
    assert headers == {"Authorization": "Bearer intel-secret"}
    assert body["tenant_id"] == str(IDS[0])
    assert body["request"]["requestId"] == req.request_id
    assert "evidence" not in body["request"] and "apiKey" not in body["request"]


async def test_client_side_default_posts_the_locked_body_and_makes_no_cloud_call(monkeypatch):
    """The Python third of the seam lock: `inputs` through the real client == `body`, byte
    for byte the shape controld's handler and mark1d's decoder are tested against."""
    monkeypatch.setattr(
        "anthropic.resources.messages.AsyncMessages.create",
        lambda *a, **kw: pytest.fail("cloud judge call on the default path"),
    )
    lock = json.loads(LOCK.read_text())
    i = {k: UUID(v) if k != "judge_id" else v for k, v in lock["inputs"].items()}
    judge, http = client_side()
    await judge.run(i["tenant_id"], i["judge_id"], i["task_id"], i["attempt_id"], i["session_id"])
    ((_, body, _),) = http.calls
    assert body == lock["body"]
    assert isinstance(body["request"]["tier"], int) and isinstance(body["request"]["locus"], int)


async def test_client_side_refuses_before_posting_without_controld_and_on_a_refused_post():
    judge, http = client_side(base_url="")
    with pytest.raises(JudgeRefused, match="refused_no_controld"):
        await judge.run(*IDS[:1], JID, *IDS[1:])
    judge, http = client_side(token="")
    with pytest.raises(JudgeRefused, match="refused_no_controld"):
        await judge.run(*IDS[:1], JID, *IDS[1:])
    assert http.calls == []
    judge, http = client_side(FakeControld(status=400))
    with pytest.raises(JudgeRefused, match="refused_dispatch_failed:400"):
        await judge.run(*IDS[:1], JID, *IDS[1:])
    assert len(http.calls) == 1
    judge, http = client_side()
    with pytest.raises(JudgeRefused, match="refused_unregistered_judge"):
        await judge.run(*IDS[:1], "judge:quantum-vibes@1", *IDS[1:])
    assert http.calls == []


def test_request_id_is_one_per_task_judge_attempt():
    a = request_id_for(JID, IDS[1], IDS[2])
    assert a == request_id_for(JID, IDS[1], IDS[2]) and UUID(a).version == 5
    assert a != request_id_for(JID, IDS[1], uuid4())
    assert a != request_id_for("judge:other@1", IDS[1], IDS[2])
    assert a != request_id_for(JID, uuid4(), IDS[2])


async def test_cloud_without_consent_is_refused_before_any_call():
    judge, client = cloud(consent=None)
    with pytest.raises(JudgeRefused) as e:
        await judge.run(*IDS[:1], JID, *IDS[1:])
    assert e.value.reason == "refused_no_cloud_consent"
    assert client.calls == []


@pytest.mark.parametrize(
    ("consent", "reason"),
    [
        (replace(CONSENT, region="global"), "refused_region_mismatch:us"),
        (replace(CONSENT, subprocessor="acme"), "refused_subprocessor_not_listed:anthropic"),
    ],
)
async def test_cloud_consent_naming_wrong_register_or_region_is_refused(consent, reason):
    judge, client = cloud(consent=consent)
    with pytest.raises(JudgeRefused) as e:
        await judge.run(*IDS[:1], JID, *IDS[1:])
    assert e.value.reason == reason
    assert client.calls == []


async def test_cloud_consented_call_pins_region_and_returns_wire_vote():
    judge, client = cloud()
    vote = await judge.run(*IDS[:1], JID, *IDS[1:])
    (kw,) = client.calls
    assert kw["model"] == SPEC.model and kw["inference_geo"] == "us"
    assert kw["system"][0]["cache_control"] == {"type": "ephemeral"}
    assert kw["messages"] == [{"role": "user", "content": f"E0 typed evidence for {IDS[1]}"}]
    assert isinstance(vote, JudgeVote)
    assert (vote.judge_id, vote.vote, vote.tier_used, vote.locus) == (
        JID,
        Verdict.VIOLATED,
        EvidenceTier.E0,
        JudgeLocus.CLOUD,
    )
    assert len(vote.rubric_hash) == 32


async def test_cloud_served_from_unpinned_region_yields_no_vote():
    judge, _ = cloud(FakeClient(geo="global"))
    with pytest.raises(JudgeRefused, match="refused_region_mismatch:us"):
        await judge.run(*IDS[:1], JID, *IDS[1:])


async def test_e2_is_gated_to_vpc_selfhost_and_never_cloud(monkeypatch):
    e2 = replace(SPEC, judge_id="judge:full-diff@1", evidence_tier="E2")
    monkeypatch.setitem(JUDGE_SPECS, e2.judge_id, e2)
    with pytest.raises(JudgeRefused, match="refused_tier_e2_outside_vpc_selfhost"):
        await client_side(profile="saas")[0].run(*IDS[:1], e2.judge_id, *IDS[1:])
    req = await client_side(profile="vpc")[0].run(*IDS[:1], e2.judge_id, *IDS[1:])
    assert req.tier == EvidenceTier.E2
    judge, client = cloud(profile="selfhost", consent=replace(CONSENT, max_tier="E1"))
    with pytest.raises(JudgeRefused, match="refused_tier_e2_never_cloud"):
        await judge.run(*IDS[:1], e2.judge_id, *IDS[1:])
    assert client.calls == []


async def test_cloud_tier_above_consent_is_refused(monkeypatch):
    e1 = replace(SPEC, judge_id="judge:hunks@1", evidence_tier="E1")
    monkeypatch.setitem(JUDGE_SPECS, e1.judge_id, e1)
    judge, client = cloud(consent=CONSENT)  # consented E0 only
    with pytest.raises(JudgeRefused, match="refused_tier_above_consent:E1"):
        await judge.run(*IDS[:1], e1.judge_id, *IDS[1:])
    assert client.calls == []


@pytest.mark.parametrize("runner", [client_side()[0], cloud()[0]])
async def test_unregistered_judge_is_refused_never_faked(runner):
    before = judges_refused_total["refused_unregistered_judge"]
    with pytest.raises(JudgeRefused) as e:
        await runner.run(*IDS[:1], "judge:quantum-vibes@1", *IDS[1:])
    assert e.value.reason == "refused_unregistered_judge:judge:quantum-vibes@1"
    assert judges_refused_total["refused_unregistered_judge"] == before + 1


@pytest.mark.parametrize(
    ("stop", "text", "want"),
    [
        ("end_turn", "Satisfied.", Verdict.SATISFIED),
        ("end_turn", "`violated`", Verdict.VIOLATED),
        ("refusal", "", Verdict.REFUSED),
        ("end_turn", "unspecified", Verdict.ERROR),
        ("end_turn", "looks fine to me", Verdict.ERROR),
        ("max_tokens", "", Verdict.ERROR),
    ],
)
def test_parse_verdict_never_guesses(stop, text, want):
    assert parse_verdict(stop, text) == want
