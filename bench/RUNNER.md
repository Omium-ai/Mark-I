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

## Registering it

1. Provision the class above. Nothing else may run on it — a co-tenant build is the noise source
   this whole file exists to remove.
2. Add it as a repo-level self-hosted runner with a distinct label, e.g. `mark1-bench-c7i2xl`.
3. Set the repo variable: `gh variable set MARK1_BENCH_RUNNER --body mark1-bench-c7i2xl`.

## What the variable controls

| `MARK1_BENCH_RUNNER` | `ci.yml` | `release.yml` |
|---|---|---|
| set | `bench` runs on the pinned runner; `bench-gate` is red on a regression | `bench` runs; a regression blocks the release |
| empty | `bench-deferred` posts a loud warning; `bench-gate` passes *as deferred*, not as measured | `bench-preflight` **fails the release** |

That asymmetry is deliberate: an unowned machine must not block every merge in the repo, but
nothing ships without the budgets having been measured exactly once.

## Not yet measured

`bench_shim_dispatch`'s cold-start half (spawn→UDS write→exit, p50 ≤ 10 ms) needs
`tools/ci/shim_coldstart_bench.sh`, which lands with the hookshim in C8. Until then `just bench`
prints a SKIPPED line naming it. It is announced rather than silently absent, because a gate that
reports success by never executing is the failure this repo exists to not repeat.
