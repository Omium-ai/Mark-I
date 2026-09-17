# The pinned bench runner

12 §7.1 states the performance budgets as **absolute numbers** — 1 ms, 10 ms, 80 MB/s, 1 µs. An
absolute number is only a fact about a specific machine. This file names that machine.

## The class

| | |
|---|---|
| Instance class | **c7i.2xlarge-equivalent** — 8 vCPU, 16 GiB, local NVMe, x86_64 |
| OS | Ubuntu 24.04 |
| Registration | GitHub self-hosted runner, label = the value of repo variable `MARK1_BENCH_RUNNER` |

Changing the class **re-baselines every budget in 12 §7.1, in the same PR**. A budget measured on
one machine and enforced on another is not a budget, it is a coin flip that happens to be green.

## Why a pinned machine at all

GitHub-hosted runners share hardware with whatever else is on the host. The observed spread on a
latency benchmark there is wider than several of our budgets, so a hosted number can neither pass
nor fail honestly. The 3-OS hosted matrix therefore runs the same benchmarks **report-only** — the
cross-OS numbers inform, they never block.

12 §7.2's anti-flake protocol (paired A/B, median-of-5, the 3×MAD-over-baseline band, one automatic
re-run) assumes a stable machine underneath. On a shared runner the MAD band widens until a real
regression fits inside it — the gate stops failing and stops meaning anything.

`bench/history/` accumulates one result set per release tag; the nightly drift check compares
against it, which only works if the samples come from the same hardware.

## The machine we have

`deploy/terraform/envs/prod/bench_runner.tf`: one c7i.2xlarge (Ubuntu 24.04, 100 GiB encrypted gp3
root — EBS on Nitro, not instance store; the baseline is measured on exactly this) in the prod VPC's
first private subnet, egress-only, instance profile with SSM only. Nothing else runs on it.

It is **stopped between runs**. `bench-runner.yml` starts it through `omium-mark1-gha-release`
(OIDC; trusts `main` and `edge/v*` tags only) before every `bench` job on a main push or a release,
and the box stops itself after 20 idle minutes (`runner-idle-stop.timer`). A weekly scheduled run
keeps it registered — GitHub deletes a runner that has been offline 14 days. PRs never wake it; they
get `bench-deferred`, and the main push after merge measures.

First boot (`bench_runner_cloud_init.sh`) reads a 1-hour registration token from SSM parameter
`/omium/mark1/bench-runner/registration-token` (written just before `terraform apply`, deleted after)
and installs the runner as a systemd service under `/opt/runner`, label `mark1-bench-c7i2xl`.

Repo variables: `MARK1_BENCH_RUNNER=mark1-bench-c7i2xl`, `MARK1_BENCH_INSTANCE_ID=<terraform output
bench_runner_instance_id>`. To rebuild the box: `terraform taint aws_instance.bench_runner`, write a
fresh token, apply, then delete the stale runner in repo settings.

## What the variable controls

| `MARK1_BENCH_RUNNER` | `ci.yml` | `release.yml` |
|---|---|---|
| set | main pushes: `bench-wake` starts the box, `bench` runs on it; `bench-gate` is red on a regression or a box that would not start. PRs: `bench-deferred` | `bench-wake` then `bench`; a regression blocks the release |
| empty | `bench-deferred` posts a loud warning; `bench-gate` passes *as deferred*, not as measured | `bench-preflight` **fails the release** |

That asymmetry is deliberate: an unowned machine must not block every merge in the repo, but
nothing ships without the budgets having been measured exactly once.

## Not yet measured

`bench_shim_dispatch`'s cold-start half (spawn→UDS write→exit, p50 ≤ 10 ms) needs
`tools/ci/shim_coldstart_bench.sh`, which lands with the hookshim in C8. Until then `just bench`
prints a SKIPPED line naming it. It is announced rather than silently absent, because a gate that
reports success by never executing is the failure this repo exists to not repeat.
