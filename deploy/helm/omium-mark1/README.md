# omium-mark1 Helm chart

Mark 1's cloud half, one release: `controld`, `mark1-intel`, `adjudicator`, an in-cluster single-replica
ClickHouse, the migration Job, the nightly/hourly CronJobs, PDBs, NetworkPolicies and the PrometheusRule.
Deployed by Argo CD (`omium-gitops/argocd-prod/omium-prod-mark1.yaml`, multi-source: this chart +
`omium-gitops/helm/values.prod.mark1.yaml`). `values.prod.example.yaml` is that overlay's worked example.

## Prerequisites the chart only references

| k8s Secret (ns `omium-mark1`, synced by ExternalSecrets from SM `omium/prod/…`) | keys |
|---|---|
| `mark1-db-service-credentials` | `controld_app`, `adjudicator_app`, `intel_app`, `mark1_federation_worker` — URL-safe (no `@ : / ? # %`): the Python DSNs are built by env expansion |
| `mark1-postgres-credentials` | `username`, `password` (the RDS master `rds!db-…` secret; migrate Job only) |
| `mark1-clickhouse` | `ingest_password`, `query_password`, `offboard_password`, `ddl_password` (hashes are computed in-pod; no `*_sha256` keys needed) |
| `mark1-signing-seeds` | `device_token_seed`, `server_chain_seed`, `bundle_section_seed` (32 B hex, distinct) |
| `mark1-hmac-pepper` | `pepper` |
| `mark1-service-token` | `token` |
| `mark1-anthropic` (optional) | `api_key` — `memory.extract` constructs `AsyncAnthropic()`; absent ⇒ that job parks |

IRSA roles (`serviceAccounts.*.roleArn`), the S3 buckets, the ECR repos `omium/mark1-{controld,intel,adjudicator,migrate}`
and the `mark1` database's host come from the Mark 1 Terraform root. Images are pinned by `<sha7>` — an empty
`imageTag` fails the render on purpose.

## Sync order

wave 0 ServiceAccounts, NetworkPolicies, ClickHouse (ConfigMap, headless Service, StatefulSet) → wave 1 `mark1-db-migrate`
(Argo `Sync` hook, `BeforeHookCreation`; a PreSync hook would run before ClickHouse exists on the first sync) →
wave 2 Deployments, Services, HPA, PDBs, CronJobs, PrometheusRule.

The migrate Job runs as the RDS master: `CREATE DATABASE mark1` if absent, then `tools/migrate-db.sh` over
`migrations/*.sql` (`m1`), `migrations/adjudicator/` (`adj`), and an empty `in` lane — `m1_ch_*.sql`
go to ClickHouse as `m1p_ddl`, everything else to Postgres, one `schema_migrations` ledger — then `ALTER ROLE … PASSWORD`
for the four runtime roles from `mark1-db-service-credentials`. Idempotent; re-runs report `0 applied`.
The image is `migrate/Dockerfile` (`postgres:15` + the ClickHouse binary + the runner + the SQL), built from the repo root
and tagged with the same `<sha7>` as the services.

## ClickHouse

`clickhouse/clickhouse-server:26.7` (the compose pin), uid 101, read-only root, `gp3` PVC (`clickhouse.storageSize`, 50Gi
default, expandable online). The four principals are rendered into `users.d/` by an init container from the synced Secret:
`m1p_ingest` (INSERT+SELECT on `mark1.*`, profile forces `async_insert=1, wait_for_async_insert=1` — controld's R3 probe),
`m1p_query` (SELECT, `readonly=2`, the 05 §6.5 cost guards as constraints), `m1p_offboard` (SELECT + ALTER DELETE), `m1p_ddl`
(ALL on `mark1.*`, migrate Job only). The `default` user is removed. Native 9000 for controld/migrate, `/ping` on 8123 for
probes, Prometheus on 9363 (pod-annotation scrape). Durability is the S3 replay log (09 §4.1); the EC2 module is the
recorded upgrade when the 09 §10.3 triggers fire.

## Tenants

`tenants:` is the static pilot list (05 §7.3 — no cross-tenant lister). It feeds `WITNESS_TENANTS` (with
`config.s3.witnessBucket`), the canary rollout controller and quarantine sweep in controld, and every CronJob's `--tenant`.
Empty ⇒ CronJobs are `suspend: true` and the witness bucket must stay unset (render fails otherwise, mirroring controld's R1).

## Check

`./check.sh` — lint, render, the guard behaviours, structural assertions, kubeconform when on PATH.
