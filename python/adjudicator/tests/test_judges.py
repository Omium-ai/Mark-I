"""Judge orchestration (06 §6): registry lockstep, client-side default, the consent-gated
cloud path, evidence-tier gating, and the refusal discipline (FR-VERIFY-015 /
NFR-PRIVACY-006 / FR-VERIFY-016 negatives)."""

from dataclasses import replace
from types import SimpleNamespace
from uuid import uuid4

import pytest
from app.judges.cloud_path import CloudJudge, Consent, parse_verdict
from app.judges.specs import (
    _REGISTERED_JUDGES,
    JUDGE_SPECS,
    ClientSideJudge,
    JudgeRefused,
    JudgeRequest,
    judges_refused_total,
)
from m1p.v1 import EvidenceTier, JudgeLocus, JudgeVote, Verdict

JID = "judge:grounded-rubric@1"
SPEC = JUDGE_SPECS[JID]
CONSENT = Consent(subprocessor="anthropic", region="us", max_tier="E0")
IDS = (uuid4(), uuid4(), uuid4())  # tenant, task, attempt


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
    req = await ClientSideJudge().run(*IDS[:1], JID, *IDS[1:])
    assert isinstance(req, JudgeRequest)
    assert req.locus == JudgeLocus.CLIENT_SIDE
    assert (req.judge_id, req.model, req.evidence_tier) == (JID, SPEC.model, "E0")
    assert not hasattr(req, "evidence") and not hasattr(req, "api_key")


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
        await ClientSideJudge("saas").run(*IDS[:1], e2.judge_id, *IDS[1:])
    req = await ClientSideJudge("vpc").run(*IDS[:1], e2.judge_id, *IDS[1:])
    assert req.evidence_tier == "E2"
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


@pytest.mark.parametrize("runner", [ClientSideJudge(), cloud()[0]])
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
