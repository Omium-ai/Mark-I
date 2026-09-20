#!/usr/bin/env bash
# Chart self-check: lint, render, guard behaviour, kubeconform when present. Run from anywhere.
set -euo pipefail
cd "$(dirname "$0")"
out="$(mktemp -d)"; trap 'rm -rf "$out"' EXIT
T="helm template omium-mark1 . -n omium-mark1 --values values.prod.example.yaml"
fail() { echo "check: FAIL — $*" >&2; exit 1; }

helm lint . --values values.prod.example.yaml --quiet >/dev/null || fail "helm lint"
$T > "$out/r.yaml"

grep -q 'controld_app' "$out/r.yaml" || fail "controld role missing"
grep -q '^  suspend: false' "$out/r.yaml" || fail "CronJobs run for every directory tenant (m1_084) regardless of the pinned list"
grep -q -- '"--tenant", "all"' "$out/r.yaml" || fail "every CronJob enumerates the tenant directory"
grep -q 'WITNESS_' "$out/r.yaml" && fail "no WITNESS_* env without tenants"
grep -qE '[0-9]e\+[0-9]' "$out/r.yaml" && fail "big ints float-formatted (quote them in values)"
grep -q 'INTEL_PG_DSN' "$out/r.yaml" && grep -q '\$(MARK1_PG_PASSWORD)@' "$out/r.yaml" || fail "python DSN must expand the secret password"
grep -q '8DagfTCA4rt34IW7Oo2JKQ16Lh7zeX3jBTgcgnJfOxg' "$out/r.yaml" || fail "pinned JWKS kid missing"
grep -A1 'hook: Sync' "$out/r.yaml" | grep -q 'BeforeHookCreation' || fail "migrate Job must be a Sync hook recreated per sync"
python3 - "$out/r.yaml" <<'PY' || fail "wave/policy assertions"
import sys, yaml
docs = [d for d in yaml.safe_load_all(open(sys.argv[1])) if d]
wave = lambda d: int(d["metadata"].get("annotations", {}).get("argocd.argoproj.io/sync-wave", "0"))
by = lambda k: [d for d in docs if d["kind"] == k]
assert wave(by("Job")[0]) == 1 and wave(by("StatefulSet")[0]) == 0, "migrate Job must run after ClickHouse"
assert all(wave(d) == 2 for d in by("Deployment") + by("CronJob")), "workloads must follow the migrate Job"
dd = [d for d in by("NetworkPolicy") if d["metadata"]["name"] == "default-deny-all"][0]
assert sorted(dd["spec"]["policyTypes"]) == ["Egress", "Ingress"], "default-deny must cover both directions"
for d in by("Deployment") + by("StatefulSet") + by("Job") + by("CronJob"):
    tpl = d["spec"]["template"] if d["kind"] != "CronJob" else d["spec"]["jobTemplate"]["spec"]["template"]
    for c in tpl["spec"].get("initContainers", []) + tpl["spec"]["containers"]:
        assert c["securityContext"]["readOnlyRootFilesystem"] is True, f"{d['kind']}/{d['metadata']['name']} not read-only"
        assert ":latest" not in c["image"] and c["image"].rsplit(":", 1)[1], f"{c['image']} unpinned"
        for e in c.get("env", []):
            assert not any(k in e["name"] for k in ("PASSWORD", "SEED", "PEPPER", "TOKEN", "API_KEY")) or "valueFrom" in e, f"{e['name']} inlined"
ch = by("StatefulSet")[0]["spec"]["template"]["spec"]
vol = lambda c, path: [m["name"] for m in c["volumeMounts"] if m["mountPath"] == path][0]
assert vol(ch["initContainers"][0], "/users.d") == vol(ch["containers"][0], "/etc/clickhouse-server/users.d"), "users.d must be rendered into the volume the server reads"
assert by("HorizontalPodAutoscaler")[0]["spec"]["scaleTargetRef"]["name"] == "controld"
rules = [r["alert"] for g in by("PrometheusRule")[0]["spec"]["groups"] for r in g["rules"]]
assert "Mark1StructuralAssumptionBroken" in rules and by("PrometheusRule")[0]["metadata"]["labels"]["release"] == "kube-prometheus-stack"
PY

$T --set 'tenants={11111111-1111-1111-1111-111111111111,22222222-2222-2222-2222-222222222222}' \
   --set config.s3.witnessBucket=b > "$out/t.yaml"
grep -q 'value: "11111111-1111-1111-1111-111111111111,22222222-2222-2222-2222-222222222222"' "$out/t.yaml" || fail "WITNESS_TENANTS must be the comma-joined list"
grep -q '^  suspend: true' "$out/t.yaml" && fail "CronJobs must run once tenants exist"

$T --set controld.imageTag= >/dev/null 2>&1 && fail "empty imageTag must not render"
$T --set config.postgresql.host= >/dev/null 2>&1 && fail "empty postgres host must not render"

if command -v kubeconform >/dev/null; then
  kubeconform -strict -kubernetes-version 1.31.0 -schema-location default \
    -schema-location 'https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json' "$out/r.yaml" >/dev/null || fail "kubeconform"
fi
echo "check: ok"
