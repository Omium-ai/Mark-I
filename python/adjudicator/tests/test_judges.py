"""Judge orchestration (06 §6): registry lockstep, client-side default, the consent-gated
cloud path, evidence-tier gating, and the refusal discipline (FR-VERIFY-015 /
NFR-PRIVACY-006 / FR-VERIFY-016 negatives)."""

import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

import pytest
from app.judges.cloud_path import Consent, admit, parse_verdict, vote_from
from app.judges.specs import (
    _REGISTERED_JUDGES,
    JUDGE_REQUESTS_PATH,
    JUDGE_SPECS,
    ClientSideJudge,
    JudgeRefused,
    at_tier,
    judges_refused_total,
    request_id_for,
)
from app.llm import Completion
from m1p.v1 import EvidenceTier, JudgeLocus, JudgeRequest, JudgeVote, Verdict

JID = "judge:grounded-rubric@1"  # the edge judge
SPEC = JUDGE_SPECS[JID]
CLOUD = JUDGE_SPECS["judge:grounded-rubric@2"]
CONSENT = Consent(subprocessor="nebius", region="global", max_tier="E0")
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


def test_registry_and_registered_set_are_the_same_fact():
    assert set(JUDGE_SPECS) == _REGISTERED_JUDGES
    for jid, spec in JUDGE_SPECS.items():
        assert jid == spec.judge_id and len(spec.confusion) == 4


def test_rubric_names_the_wire_vocabulary_verbatim():
    vocab = "|".join(v.name.lower() for v in Verdict if v.value)
    assert vocab == "satisfied|violated|refused|error"
    assert vocab in SPEC.rubric


def test_the_edge_judge_is_claude_on_the_customers_key_and_the_cloud_judge_is_pinned_glm():
    assert (SPEC.locus, SPEC.model) == ("edge", "claude-sonnet-5")
    assert (CLOUD.locus, CLOUD.model, CLOUD.subprocessor, CLOUD.region) == (
        "cloud",
        "zai-org/GLM-5.2",
        "nebius",
        "global",
    )


async def test_client_side_default_emits_request_and_makes_no_cloud_call():
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


async def test_client_side_default_posts_the_locked_body_and_makes_no_cloud_call():
    """The Python third of the seam lock: `inputs` through the real client == `body`, byte
    for byte the shape controld's handler and mark1d's decoder are tested against."""
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


async def test_the_cloud_judge_is_never_dispatched_to_an_edge():
    judge, http = client_side()
    with pytest.raises(JudgeRefused, match="refused_cloud_judge_at_edge"):
        await judge.run(*IDS[:1], CLOUD.judge_id, *IDS[1:])
    assert http.calls == []


def test_cloud_without_consent_is_refused():
    with pytest.raises(JudgeRefused) as e:
        admit(CLOUD, None)
    assert e.value.reason == "refused_no_cloud_consent"


@pytest.mark.parametrize(
    ("consent", "reason"),
    [
        (replace(CONSENT, region="us"), "refused_region_mismatch:global"),
        (replace(CONSENT, subprocessor="anthropic"), "refused_subprocessor_not_listed:nebius"),
    ],
)
def test_cloud_consent_naming_wrong_register_or_region_is_refused(consent, reason):
    with pytest.raises(JudgeRefused) as e:
        admit(CLOUD, consent)
    assert e.value.reason == reason


def test_cloud_reply_becomes_a_cloud_wire_vote_at_the_tier_it_read():
    reply = Completion("violated", "stop", CLOUD.model, 10, 1, 0)
    vote = vote_from(CLOUD, reply)
    assert isinstance(vote, JudgeVote)
    assert (vote.judge_id, vote.vote, vote.tier_used, vote.locus) == (
        CLOUD.judge_id,
        Verdict.VIOLATED,
        EvidenceTier.E1,
        JudgeLocus.CLOUD,
    )
    e0 = at_tier(CLOUD, "E0")
    assert (e0.evidence_tier, e0.rubric, e0.judge_id) == ("E0", CLOUD.e0_rubric, CLOUD.judge_id)
    fallback = vote_from(e0, reply)
    assert fallback.tier_used == EvidenceTier.E0 and fallback.rubric_hash != vote.rubric_hash
    assert at_tier(SPEC, "E0") is SPEC and at_tier(CLOUD, "E1") is CLOUD


async def test_e2_is_gated_to_vpc_selfhost_and_never_cloud(monkeypatch):
    e2 = replace(SPEC, judge_id="judge:full-diff@1", evidence_tier="E2")
    monkeypatch.setitem(JUDGE_SPECS, e2.judge_id, e2)
    with pytest.raises(JudgeRefused, match="refused_tier_e2_outside_vpc_selfhost"):
        await client_side(profile="saas")[0].run(*IDS[:1], e2.judge_id, *IDS[1:])
    req = await client_side(profile="vpc")[0].run(*IDS[:1], e2.judge_id, *IDS[1:])
    assert req.tier == EvidenceTier.E2
    with pytest.raises(JudgeRefused, match="refused_tier_e2_never_cloud"):
        admit(replace(CLOUD, evidence_tier="E2"), replace(CONSENT, max_tier="E1"))


def test_cloud_tier_above_consent_is_refused():
    with pytest.raises(JudgeRefused, match="refused_tier_above_consent:E1"):
        admit(replace(CLOUD, evidence_tier="E1"), CONSENT)  # consented E0 only


async def test_unregistered_judge_is_refused_never_faked():
    before = judges_refused_total["refused_unregistered_judge"]
    with pytest.raises(JudgeRefused) as e:
        await client_side()[0].run(*IDS[:1], "judge:quantum-vibes@1", *IDS[1:])
    assert e.value.reason == "refused_unregistered_judge:judge:quantum-vibes@1"
    assert judges_refused_total["refused_unregistered_judge"] == before + 1


@pytest.mark.parametrize(
    ("stop", "text", "want"),
    [
        ("end_turn", "Satisfied.", Verdict.SATISFIED),
        ("end_turn", "`violated`", Verdict.VIOLATED),
        ("refusal", "", Verdict.REFUSED),
        ("content_filter", "", Verdict.REFUSED),
        ("end_turn", "unspecified", Verdict.ERROR),
        ("end_turn", "looks fine to me", Verdict.ERROR),
        ("length", "", Verdict.ERROR),
    ],
)
def test_parse_verdict_never_guesses(stop, text, want):
    assert parse_verdict(stop, text) == want


def test_m1_100_seeds_the_cloud_judge_with_its_pinned_rubrics_and_groups():
    """The catalog row names exactly the spec's model, register key and both rubrics, E1 in group
    judge and the E0 fallback in syntactic; a rubric edit without a new version fails here."""
    import hashlib
    import re

    from app.registry.catalog import entry_from_row, group_of

    sql = (Path(__file__).parents[3] / "migrations" / "m1_100_cloud_judge_verifier.sql").read_text()
    literal = re.search(r"'(\{\"judge_id\":\"judge:grounded-rubric@2\".*?\})'::jsonb", sql)
    assert literal is not None
    definition = json.loads(literal.group(1))
    spec = JUDGE_SPECS["judge:grounded-rubric@2"]
    assert definition["rubric_sha256"] == hashlib.sha256(spec.rubric.encode()).hexdigest()
    assert spec.e0_rubric is not None
    e0_sha = hashlib.sha256(spec.e0_rubric.encode()).hexdigest()
    assert definition["e0_fallback"]["rubric_sha256"] == e0_sha
    assert (definition["model"], definition["subprocessor"], definition["region"]) == (
        spec.model,
        spec.subprocessor,
        spec.region,
    )
    assert definition["evidence_tier"] == spec.evidence_tier == "E1"
    assert "'judge:grounded-rubric', 'judge', 2," in sql
    entry = entry_from_row(
        {
            "id": uuid4(),
            "verifier_key": "judge:grounded-rubric",
            "version": 2,
            "kind": "judge",
            "definition": definition,
            "effective_execution_hash": None,
            "retired_at": None,
        }
    )
    assert entry.kind == "judge"
    assert group_of("judge", definition) == "judge"
    assert group_of("judge", definition, e0=True) == "syntactic"


def test_cloud_paths_name_what_the_subprocessor_register_says():
    """The judge spec and the cloud RM's settings are held to controld's register (10 §10.4), the
    rows the app's consent copy renders: a processor or region change without the register fails."""
    from app.rm.cloud import RmCloudSettings

    register = json.loads(
        (Path(__file__).parents[3] / "desktop/mock/fixtures/controld/register.json").read_text()
    )
    rows = {r["key"]: r for r in register}
    judge = rows["judge:grounded-rubric@2"]
    assert (judge["subprocessor"], judge["region"], judge["max_tier"]) == (
        CLOUD.subprocessor,
        CLOUD.region,
        CLOUD.evidence_tier,
    )
    rm, settings = rows[RmCloudSettings().model_id], RmCloudSettings()
    assert (rm["subprocessor"], rm["region"], rm["max_tier"]) == ("baseten", settings.region, "E1")


def test_service_device_is_controlds_and_speaks_for_no_device():
    from app.judges.cloud_path import SERVICE_DEVICE, task_tiers

    go = (
        Path(__file__).resolve().parents[3] / "go/controld/internal/ingest/service.go"
    ).read_text()
    name = go.split("ServiceDevice = uuid.NewSHA1(uuid.NameSpaceURL, []byte(")[1].split('"')[1]
    assert uuid5(NAMESPACE_URL, name) == SERVICE_DEVICE
    dev, task, lone = uuid4(), uuid4(), uuid4()
    rows = {
        task: [{"device_id": str(dev)}, {"device_id": str(SERVICE_DEVICE)}],
        lone: [{"device_id": SERVICE_DEVICE}],
    }
    assert task_tiers(rows, {dev: "E1"}) == {task: "E1"}
