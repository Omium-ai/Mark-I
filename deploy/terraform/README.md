# Mark 1 cloud — Terraform

Own root, own state, read-only coupling to the platform. Nothing here can write the platform state (09 §0: "Mark 1 changes nothing in Omium-platform").

| | |
|---|---|
| Root | `envs/prod/` (account `omium-prod` 965384155704, us-east-1) |
| State | `s3://omium-tfstate-169805602430/mark1/prod/terraform.tfstate`, lock table `omium-tf-locks`, backend profile `omium-mgmt` — same bucket/table/KMS key as the platform root, different key |
| Provider | `omium-prod` SSO profile, `aws ~> 5.60`, `random ~> 3.5`, Terraform ≥ 1.9 |
| Inputs | none required; every variable has an inline default (`variables.tf`), no tfvars |

## Plan / apply

```sh
aws sso login --sso-session omium          # both profiles share the session
cd deploy/terraform/envs/prod
terraform init                              # first run creates only the mark1/prod state key
terraform fmt -check -recursive ../..
terraform validate
terraform plan -lock-timeout=60s -out=mark1-prod.tfplan
terraform show mark1-prod.tfplan            # read it; expect adds only on a fresh account
terraform apply mark1-prod.tfplan
terraform output                            # feed helm/values.prod.mark1.yaml + gitops ExternalSecrets
```

Never run `plan`/`apply` in `Omium-platform/infrastructure/terraform/envs/prod` from this lane (a month of console drift lives there). The only platform-root command this lane ever needs is `terraform output`.

## What is read from the platform state (read-only)

`data.terraform_remote_state.platform` on `prod/terraform.tfstate`: `vpc_id`, `private_subnets`, `rds_endpoint`, `rds_master_user_secret_arn`. Re-exported under `output.platform` so the migrate Job and values files have one source.

Things the platform root does not export come from data sources against the live account, never from a second copy: the EKS cluster and its OIDC provider (`data.aws_eks_cluster` / `data.aws_iam_openid_connect_provider.eks`), the GitHub Actions OIDC provider (`data.aws_iam_openid_connect_provider.github`, the one `modules/github-oidc` created — do not create another), and the hand-made `omium/prod/mark1-token-signing-key` secret (`data.aws_secretsmanager_secret`; owned by auth-service, only its ARN is surfaced).

Postgres: pilot uses a `mark1` database on the existing `omium-prod-postgres` (no RDS resource here). ClickHouse: in-cluster StatefulSet, chart-owned. Neither appears in this root today.

## What it creates

- **KMS** `alias/mark1-personal` — the pooled key for `kind='personal'` tenants (ADR-0011). Key policy delegates to IAM; the three IRSA roles get `kms:Encrypt/Decrypt/GenerateDataKey*/DescribeKey` on it, conditioned on `kms:ViaService = s3.us-east-1.amazonaws.com`.
- **S3** (`modules/mark1-bucket`, default SSE-KMS under the pooled key with Bucket Keys on, versioning, public-access block, `DenyInsecureTransport`):

  | bucket | object lock | lifecycle |
  |---|---|---|
  | `omium-mark1-ingest-prod-<acct>` | GOVERNANCE 35 d default (bucket-wide, so quarantine objects carry 35 d too; the receipted 30 d sweep writes a delete marker, the lock holds the version until day 35) | GLACIER_IR at 90 d, expire 760 d, noncurrent 40 d; tag `class=quarantine` expires at 32 d |
  | `omium-mark1-corpus-prod-<acct>` | none | expire 400 d, noncurrent 30 d |
  | `omium-mark1-evidence-prod-<acct>` | none | expire 90 d, noncurrent 1 d |
  | `omium-mark1-witness-prod-<acct>` | COMPLIANCE 2 y default | none (abort stale multipart only) |

  **Object lock is creation-time only.** A bucket created without `object_lock_enabled` cannot be fixed without an AWS support case. Check the plan shows `object_lock_enabled = true` on ingest and witness before the first apply. controld's `WITNESS_RETAIN` sets an explicit per-object retain-until that overrides the 2 y default; set it to `17520h` in the values file or the heads get the code default of one year.

  The ingest bucket policy additionally carries the two Deny statements `s3land.VerifyTenantKMSDeny` string-matches at boot (R6): `DenyTenantPrefixWithoutMark1TenantKey` (PUT under `t/*` must name the pooled key ARN, `*alias/mark1-tenant-*` or `*alias/mark1-personal`) and `DenyPooledPersonalKeyOutsideTenantPrefix` (`NotResource t/*` + the pooled key). S3 evaluates `s3:x-amz-server-side-encryption-aws-kms-key-id` against the resolved key ARN, so the pooled key's ARN is listed alongside the alias patterns the probe needs.
- **IRSA** (`modules/mark1-irsa`, trust on the cluster OIDC provider with both `:sub` and `:aud`): `omium-prod-mark1-{controld,intel,adjudicator}-irsa` for ServiceAccounts `omium-mark1/{controld,mark1-intel,adjudicator}`. Policies are in `envs/prod/irsa.tf`, one statement per code path.
- **ECR** `omium/mark1-{controld,intel,adjudicator}` — IMMUTABLE, scan on push, untagged expire 14 d, keep last 20.
- **Release role** `omium-mark1-gha-release` — GitHub OIDC, subjects `repo:Omium-ai/Mark-I:ref:refs/heads/main` and `…:ref:refs/tags/edge/v*` (`var.github_release_subjects`), ECR push on the three repos only. Set repo variables `AWS_RELEASE_ROLE_ARN` = `output.gha_release_role_arn`, `AWS_REGION` = `us-east-1`.
- **Secrets Manager** `omium/prod/mark1-{db-service-credentials,clickhouse,signing-seeds,hmac-pepper,service-token}` — seeded once with real random values (`random_password` / `random_bytes`), `lifecycle { ignore_changes = [secret_string] }` afterwards.

## Post-apply checks

1. `aws s3api get-bucket-policy --bucket omium-mark1-ingest-prod-965384155704 --query Policy --output text | jq .` — both Deny Sids present. controld's boot is the real probe: it crashloops on R6 if they are missing.
2. Negative PUT (proves the alias-vs-ARN evaluation instead of assuming it), as the controld role or an admin:
   `aws s3api put-object --bucket omium-mark1-ingest-prod-965384155704 --key t/00000000-0000-0000-0000-000000000000/ingest/v1/probe --body /dev/null --server-side-encryption aws:kms --ssekms-key-id alias/aws/s3` → must be `AccessDenied`; the same PUT with `--ssekms-key-id alias/mark1-personal` → 200. Delete the probe object afterwards (delete marker; the version ages out with the lock).
3. `aws s3api get-object-lock-configuration --bucket …-witness-…` → `COMPLIANCE`, 2 years.
4. If `PutBucketPolicy` ever rejects `NotResource`, replace `DenyPooledPersonalKeyOutsideTenantPrefix` with the Resource-scoped form the e2e rig uses (`conformance/e2e/rig.py`): fold `*alias/mark1-personal` into the first statement's `StringNotLike` list and drop the second statement — the probe accepts both shapes.

## Rotating the seed secrets

Terraform owns the secret container and the first version only. Contents belong to whoever last set them; `terraform plan` will never show you a placeholder or revert a rotation. To rotate:

```sh
aws --profile omium-prod secretsmanager put-secret-value \
  --secret-id omium/prod/mark1-service-token \
  --secret-string "$(jq -nc --arg t "$(openssl rand -hex 24)" '{token:$t}')"
```

Keep every JSON key the consumers read (§2 of the cloud gap map): `mark1-db-service-credentials` {`controld_app`,`adjudicator_app`,`intel_app`,`mark1_federation_worker`} — after rotating, the migrate Job's `ALTER ROLE … PASSWORD` must run again; `mark1-clickhouse` {`ingest_password`,`query_password`,`offboard_password`,`ddl_password`, each `*_sha256` (`printf %s "$pw" | sha256sum`), `host`, `port`} — the `users.d` render reads the sha256 fields, so rotate both halves together; `mark1-signing-seeds` {`device_token_seed`,`server_chain_seed`,`bundle_section_seed`} — 32-byte hex each, distinct, and a chain-seed rotation is an ADR-0004 ceremony (cross-sign, publish the key set) not a value swap; `mark1-hmac-pepper` {`pepper`} — 32-byte hex, rotating it changes every tenant HMAC digest, do not rotate casually; `mark1-service-token` {`token`}.

ESO re-syncs within its refresh interval; restart the consumers (or let Reloader) so the pods pick up the new values. `describe-secret --query LastChangedDate` tells you whether a secret still holds the seed.

## Day-2 upgrade paths

- **ClickHouse on EC2** (09 §4.2): add `modules/mark1-clickhouse` (AL2023 via SSM alias, separate gp3 data volume, DLM snapshots, `clickhouse-backup` to `omium-backups-prod-…`, users rendered from `mark1-clickhouse` at boot) when storage passes 70 % after a PVC resize, sustained CPU > 70 %, or a report-availability SLA lands (09 §10.3). Only `CLICKHOUSE_ADDR` and `var.clickhouse_host` change on the Mark 1 side.
- **Per-org KMS keys** (09 §5.2): controld does not create them yet. When the enroll lane lands, controld's role gains `kms:CreateKey` (request-tag constrained) + `CreateAlias/TagResource/CreateGrant/RetireGrant/DescribeKey` on `alias/mark1-tenant-*`, and the ingest `DenyTenantPrefixWithoutMark1TenantKey` statement needs the org keys made recognisable: because S3 compares key ARNs, either the enroll flow appends each new key ARN to that statement (policy size cap ≈ 20 KB, fine for tens-to-hundreds of orgs) or the per-tenant check moves off the bucket policy. Until then org tenants cannot upload; the pilot is personal tenants only.
- **Dedicated RDS** (09 §3.1): `modules/mark1-rds` cloned from the platform's `modules/rds`, then repoint `POSTGRES_HOST` via values PR. Trigger: first external tenant or a contract with restore language.
- **KMS signing keys** (ADR-0004, P-256): created together with the controld KMS-signer change; the Ed25519 seeds in `mark1-signing-seeds` are the day-one custody and are retired at that ceremony.
- **`dl.omium.ai` feed bucket** and the `s3:PutObject` grant on the release role: lane G, needs the founder's Cloudflare record first.
