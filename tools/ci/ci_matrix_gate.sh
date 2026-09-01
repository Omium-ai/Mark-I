#!/bin/sh
# ci_matrix_gate.sh — NFR-PORTABILITY-001. The CI workflow's own gating claims must be true.
#
# 02 §9 asks for two things: a 3-OS matrix on every PR, and "any red platform blocks merge".
# The second half is a GitHub branch-protection setting, which no in-repo artifact can read — so
# ci.yml carries the list of names that setting is supposed to hold, and this gate checks that
# every one of them is a check the workflow actually reports. That is the half that was wrong:
# the list named `rust` and `go`, both MATRIX jobs, whose checks report as `rust (ubuntu-24.04)`
# and friends. No check named `rust` had ever existed, so the setting could name it forever and
# gate nothing. A required check that never reports is not a strict gate, it is a typo with a
# green build behind it.
#
# It runs the comparison backwards too (D-CG's lesson: deriving from the tree catches what nobody
# wrote down, and is structurally incapable of catching what was written down and never built).
# Every check the workflow reports must be either required by name or consumed by a required
# job's `needs`, so a NEW job is un-gated until somebody decides which it is.
#
# The 3-OS rule is derived from the recipes a job runs, not from a list of job names. `go` losing
# its matrix would still be running `just test-go`, and that is what fails here.
set -eu
cd "$(dirname "$0")/../.."
exec uv run --frozen --all-packages python - <<'PY'
import pathlib
import re
import sys

import yaml

WF = pathlib.Path(".github/workflows/ci.yml")
# The three the edge ships to. 04 §11.5 documents per-OS SEMANTIC differences, so this is a
# correctness matrix, not a build matrix.
OSES = {"ubuntu-24.04", "macos-14", "windows-2022"}
# A job running any of these is compiling or testing code that ships to a customer machine.
EDGE_RECIPES = {"build-go", "test-go", "lint-go", "test-rust", "lint-rust"}

text = WF.read_text(encoding="utf-8")
doc = yaml.safe_load(text)
jobs = doc["jobs"]
bad = []

# PyYAML resolves the YAML 1.1 boolean `on` before it is ever a string key.
triggers = doc.get("on", doc.get(True))
if not isinstance(triggers, dict) or "pull_request" not in triggers:
    bad.append("ci.yml does not trigger on `pull_request`, so nothing below gates a PR at all")

lines = text.splitlines()
required = None
for i, ln in enumerate(lines):
    if ln.startswith("# required-checks:"):
        buf = ln.split(":", 1)[1]
        for cont in lines[i + 1 :]:
            if not re.match(r"^#\s{4,}\S", cont):
                break
            buf += " " + cont.lstrip("#").strip()
        required = [s.strip() for s in buf.split(",") if s.strip()]
        break
if required is None:
    print("ci_matrix_gate: ci.yml has no `# required-checks:` block — the branch-protection "
          "list it documents is then unverifiable and this gate checks nothing", file=sys.stderr)
    sys.exit(1)

# What GitHub will actually report, and from which job.
reported = {}
matrix_jobs = set()
for key, job in jobs.items():
    tmpl = job.get("name", key)
    oses = ((job.get("strategy") or {}).get("matrix") or {}).get("os")
    if oses:
        matrix_jobs.add(key)
        for o in oses:
            reported[tmpl.replace("${{ matrix.os }}", o)] = key
    else:
        reported[tmpl] = key

direct = set()
for name in required:
    key = reported.get(name)
    if key is None:
        bad.append(f"required check {name!r} is not a check this workflow reports; "
                   f"branch protection can name it but no run will ever satisfy it")
    elif key in matrix_jobs:
        bad.append(f"required check {name!r} is one leg of matrix job {key!r}; require an "
                   f"aggregate `needs:` job instead, or the other legs gate nothing")
    else:
        direct.add(key)

# Backwards: a job reaches merge-gating status directly, or through a required job's `needs`.
covered = set(direct)
frontier = list(direct)
while frontier:
    job = jobs[frontier.pop()]
    for dep in job.get("needs", []):
        if dep not in covered:
            covered.add(dep)
            frontier.append(dep)
for key in jobs:
    if key not in covered:
        bad.append(f"job {key!r} is neither in required-checks nor consumed by a required job's "
                   f"`needs`, so it can go red without blocking anything")

# The 3-OS rule, anchored to what a job RUNS.
seen_recipes = set()
for key, job in jobs.items():
    run = "\n".join(s["run"] for s in job.get("steps", []) if isinstance(s, dict) and "run" in s)
    recipes = set(re.findall(r"\bjust\s+([a-z0-9-]+)", run)) & EDGE_RECIPES
    if not recipes:
        continue
    seen_recipes |= recipes
    strategy = job.get("strategy") or {}
    oses = set((strategy.get("matrix") or {}).get("os") or [])
    if missing := OSES - oses:
        bad.append(f"job {key!r} runs {sorted(recipes)} but its matrix omits {sorted(missing)}; "
                   f"the edge ships to all three")
    if strategy.get("fail-fast", True):
        bad.append(f"job {key!r} is 3-OS but fail-fast is on, so the first red platform cancels "
                   f"the others and one run tells you about one platform")
if missing := EDGE_RECIPES - seen_recipes:
    bad.append(f"no job runs {sorted(missing)}; a recipe no CI job invokes is a local habit")

if bad:
    print("ci_matrix_gate: FAIL", file=sys.stderr)
    for b in bad:
        print(f"  - {b}", file=sys.stderr)
    sys.exit(1)
print(f"ci_matrix_gate: OK ({len(required)} required checks all report; "
      f"{len(jobs)} jobs all gated; 3-OS matrix intact)")
PY
