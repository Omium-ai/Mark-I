# Cloud images

Three images, one per cloud service (13 §8, §9.5). Build context is always the repo root.

| Image | Dockerfile | Runtime base | Ports | Entrypoint |
|---|---|---|---|---|
| `omium/mark1-controld` | `go/controld/Dockerfile` | `gcr.io/distroless/static-debian12:nonroot` | 8080 (`CONTROLD_PORT`), 9092 (`METRICS_PORT`: `/metrics` `/healthz` `/readyz`) | `/usr/local/bin/controld` |
| `omium/mark1-intel` | `python/intel/Dockerfile` | `python:3.12-slim-bookworm` | 8000 | `uvicorn app.main:app` |
| `omium/mark1-adjudicator` | `python/adjudicator/Dockerfile` | `python:3.12-slim-bookworm` | 8000 | `uvicorn app.main:app` |

All three run as uid 65532, carry no build tools, no `HEALTHCHECK` (kubelet probes), and label
`org.opencontainers.image.source` + `org.opencontainers.image.revision` (`--build-arg REVISION=<full sha>`).
CronJobs use the same Python images with `python -m app.jobs run ...` (06 §7); the venv is on `PATH`.

## Tags

`<registry>/omium/mark1-<svc>:<sha7>` and nothing else. The ECR repos are IMMUTABLE, so a floating tag
would be a permanent pin (13 §9.5). `<sha7>` = first seven hex of the main commit.

## Pipeline

`ci.yml` job `cloud-images`, on every push to `main` (PRs skip it; a skipped job satisfies branch
protection): build with buildx (`type=gha` cache per service) → load → `trivy` (`CRITICAL,HIGH`,
`--ignore-unfixed`, exit 1) → `docker push` → `attest-build-provenance` (pushed to the registry).
`release.yml` job `images` does not rebuild: it checks the `<sha7>` image for the tagged commit exists,
verifies its provenance (`gh attestation verify`), and rescans it with the release-day trivy DB.

Repo variables (lead sets them): `AWS_RELEASE_ROLE_ARN` = the `omium-mark1-gha-release` role
(Terraform, trusts `repo:Omium-ai/Mark-I:*`), `AWS_REGION` = `us-east-1`. With
`AWS_RELEASE_ROLE_ARN` empty the job is skipped and CI stays green. The role needs, on
`omium/mark1-*`: `ecr:GetAuthorizationToken`, `BatchCheckLayerAvailability`, `InitiateLayerUpload`,
`UploadLayerPart`, `CompleteLayerUpload`, `PutImage` (push + attestation referrer), `BatchGetImage`,
`GetDownloadUrlForLayer` (trivy and `manifest inspect` pull), `DescribeImages`. Attestations need the
org plan to allow them on an internal repo (`release.yml` already depends on this).

## Base images, and why these

- Go: `distroless/static` (not `cc`): `CGO_ENABLED=0`, no libc. 0 findings today. Builder pinned
  `golang:1.25.14-bookworm` with `GOTOOLCHAIN=local`, so a `go.mod` toolchain bump fails loudly
  instead of downloading a compiler mid-build.
- Python: `python:3.12-slim-bookworm` for builder and runtime (same interpreter path, so the venv
  built in one stage is valid in the other). Measured 2026-09-17 with trivy 0.74.0, fixed-only
  HIGH/CRITICAL: `-slim-bookworm` 3 (libpcre2), `-slim-trixie` 13 (3 CRITICAL in perl-base). Both lag
  stable-security, so the runtime stage runs `apt-get upgrade`; after it, bookworm scans clean.
  No distroless Python: Google ships 3.11 only. `uv` comes from `ghcr.io/astral-sh/uv:0.12.7` by
  `COPY --from` (uv 0.12.7 publishes no `-python3.12-bookworm-slim` tag, only trixie). `uv sync --frozen --no-dev
  --no-editable --package <name>`: `--no-editable` is load-bearing, the workspace members would
  otherwise be `.pth` links into the builder's tree.

## Local build

```sh
docker build -f python/intel/Dockerfile --build-arg REVISION=$(git rev-parse HEAD) -t omium/mark1-intel:dev .
trivy image --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 omium/mark1-intel:dev
```

Sizes on 2026-09-17: controld 35 MB, adjudicator 443 MB, intel 766 MB (pyarrow + duckdb + numpy + boto3).

## Not done

- Single arch (linux/amd64). Multi-arch needs `platforms:` + a manifest list, and `load: true` cannot
  do that; switch to push-then-scan-by-digest when arm64 nodes exist.
- No SBOM per image; `release.yml` produces source and package SBOMs only.
- No path filter: every main push builds all three (~5 min warm). Add `dorny/paths-filter` when the
  ECR lifecycle policy or the queue says so. Building every commit is what makes any main SHA pinnable.
