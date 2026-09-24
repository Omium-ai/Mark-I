# Mark 1

Mark 1 wraps coding agents (Claude Code first) to cut **tokens per verified outcome** (TVO). It
checks the agent's work with the project's own linters and tests, stops retry loops, records
every session as a signed receipt chain, and reports what the tokens bought. The desktop app lives
in [Mark-1-GUI](https://github.com/Omium-ai/Mark-1-GUI); this repository is everything else.

## Where things live

| Path | What it is | Language |
|---|---|---|
| `go/mark1d/` | The edge daemon: capture, anchors (sandboxed checks), verdict fusion, the Stop gate, spool, uplink | Go |
| `go/mark1/` | The `mark1` CLI (`enroll`, `enable`, `doctor`, `off`, `verify-receipts`) | Go |
| `go/controld/` | The cloud control plane: ingest, enroll, policy distribution, query chokepoint, app API | Go |
| `rust/mark1-hookshim/` | The static binary every agent hook calls | Rust |
| `rust/mark1-proxy/` | API-key-only wire proxy (never touches subscription traffic) | Rust |
| `rust/cortexd/` | Per-workspace repo map and MCP tools | Rust |
| `rust/verifier/` | Standalone offline receipt verifier (open source) | Rust |
| `rust/m1p-wire/`, `mark1-*` | Shared crates: framing, receipts, policy decode, redaction, frames | Rust |
| `python/adjudicator/` | Certification: gold labels, spectral Dawid-Skene, judges, noise certificates | Python |
| `python/intel/` | Nightly intelligence: TVO rollups, memory, policy compiler, corpus export | Python |
| `proto/` | `m1p.v1`, the one wire schema (generated code is committed) | protobuf |
| `migrations/` | Postgres (`m1_0NN`), ClickHouse (`m1_ch_0NN`) and `adjudicator/` (`adj_0NN`) migrations | SQL |
| `conformance/` | Cross-language test vectors, hook fixtures per agent version, traceability map | data |
| `desktop/mock/` | The desktop app's contract fixtures and mock server (the GUI's CI checks this out) | JSON |
| `deploy/` | Helm chart (Argo tracks `main`), images, Terraform (founder-applied), keys | |
| `tools/` | `bootstrap.sh`, `migrate-db.sh`, and `ci/` gate scripts | shell |
| `docs/` | Design record, ADRs, runbooks, history | |

## Working in it

```
tools/bootstrap.sh        # install and verify the pinned toolchain
just                      # lint + test, the local form of CI
just test-integration     # needs `just stores-up` (Postgres + ClickHouse + S3)
just gen                  # regenerate proto code after editing proto/
```

## Shipping

- **Cloud:** CI on `main` builds images tagged `<sha7>`; prod moves only when `omium-gitops`
  `helm/values.prod.mark1.yaml` pins that tag. The migrate Job runs on every sync.
- **Daemon:** tag `edge/vX.Y.Z` on a green `main` commit; `release.yml` builds five targets.
- **App:** Mark-1-GUI pins the daemon in `sidecar/VERSION` and tags `vX.Y.Z`; installers land on
  `dl.omium.ai/mark1/latest/`.

Design documents start at [`docs/README.md`](docs/README.md).
