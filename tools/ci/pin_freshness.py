#!/usr/bin/env python3
"""pin_freshness — how far each adapter's newest pinned fixture trails upstream (A4 §4).

The pin list is `conformance/hooks/<agent>/v*` (the dirs ARE the pins, by the
`TestSupportedVersionsMatchTheFixtureTree` invariant). Upstream is the GitHub
releases API (codex, gemini, opencode, copilot), the npm registry (Claude Code)
and cursor.com's install script / download API (Cursor CLI / IDE). Prints one
markdown table; exits 1 when any adapter is more than its limit behind, 2 on a
lookup error. Nightly, not per PR: freshness is a fact about upstream, not the diff.
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.request
from datetime import datetime
from pathlib import Path

# adapter -> (pin dir, how many stable releases a pin may trail before the nightly goes red).
# The numbers are the audit's: codex ships ~every 2 days, opencode ~daily, the rest weekly-ish.
LIMITS = {
    "codex": 10,
    "opencode": 15,
    "gemini": 2,
    "copilot": 3,
    "claudecode": 5,
    "cursor-cli": 3,  # unit: weeks between builds (cursor.com exposes only the latest build)
    "cursor-ide": 1,  # unit: minor versions
}

GITHUB = {
    "codex": ("openai/codex", "rust-v{}"),
    "gemini": ("google-gemini/gemini-cli", "v{}"),
    "opencode": ("anomalyco/opencode", "v{}"),
    "copilot": ("github/copilot-cli", "v{}"),
}

ROOT = Path(__file__).resolve().parents[2]
HOOKS = ROOT / "conformance" / "hooks"


def fetch(url: str) -> bytes:
    headers = {"User-Agent": "omium-mark1 pin_freshness", "Accept": "application/vnd.github+json"}
    if "api.github.com" in url and os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = "Bearer " + os.environ["GITHUB_TOKEN"]
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=30) as r:  # noqa: S310
        return r.read()


def vtuple(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", v))


def pins(agent: str, prefix: str = "v") -> list[str]:
    d = HOOKS / agent
    if not d.is_dir():
        return []
    return sorted(
        (p.name[len(prefix) :] for p in d.iterdir() if p.is_dir() and p.name.startswith(prefix)),
        key=vtuple,
    )


def github_behind(repo: str, tag: str) -> tuple[str, int]:
    """(latest stable tag, stable releases newer than `tag`); pages until the pin is seen."""
    stable: list[dict] = []
    for page in range(1, 6):
        rel = json.loads(
            fetch(f"https://api.github.com/repos/{repo}/releases?per_page=100&page={page}")
        )
        if not rel:
            break
        stable += [r for r in rel if not r["prerelease"] and not r["draft"]]
        if any(r["tag_name"] == tag for r in rel):
            break
    stable.sort(key=lambda r: r["published_at"], reverse=True)
    if not stable:
        raise RuntimeError(f"{repo}: no stable releases returned")
    pinned = next((r for r in stable if r["tag_name"] == tag), None)
    if pinned is None:
        return stable[0]["tag_name"], len(stable)
    return stable[0]["tag_name"], sum(
        1 for r in stable if r["published_at"] > pinned["published_at"]
    )


def npm_behind(package: str, version: str) -> tuple[str, int]:
    meta = json.loads(fetch(f"https://registry.npmjs.org/{package}"))
    times = {
        v: t for v, t in meta["time"].items() if v not in ("created", "modified") and "-" not in v
    }
    latest = max(times, key=lambda v: times[v])
    if version not in times:
        return latest, len(times)
    return latest, sum(1 for t in times.values() if t > times[version])


def cursor_cli_behind(build: str) -> tuple[str, int]:
    script = fetch("https://cursor.com/install").decode()
    m = re.search(r"lab/(\d{4}\.\d{2}\.\d{2}-[0-9a-f]{7})", script)
    if not m:
        raise RuntimeError("cursor.com/install: no lab/<build> download URL found")
    latest = m.group(1)
    if latest == build:
        return latest, 0
    days = (
        datetime.strptime(latest[:10], "%Y.%m.%d") - datetime.strptime(build[:10], "%Y.%m.%d")
    ).days  # noqa: DTZ007
    return latest, max(1, -(-days // 7))


def cursor_ide_behind(version: str) -> tuple[str, int]:
    meta = json.loads(
        fetch("https://cursor.com/api/download?platform=win32-x64-user&releaseTrack=stable")
    )
    latest = meta["version"]
    lt, pt = vtuple(latest), vtuple(version)
    return latest, max(0, (lt[0] - pt[0]) * 100 + (lt[1] - pt[1]))


def main() -> int:
    rows, rc = [], 0
    for adapter, limit in LIMITS.items():
        agent = adapter.split("-")[0]
        pinned = pins(agent, "ide-" if adapter == "cursor-ide" else "v")
        if adapter == "cursor-cli":
            pinned = [p for p in pinned if re.match(r"\d{4}\.\d{2}\.\d{2}-", p)]
        if not pinned:
            rows.append((adapter, "(none)", "", "", limit, "no pin"))
            continue
        pin = pinned[-1]
        try:
            if adapter in GITHUB:
                repo, fmt = GITHUB[adapter]
                latest, behind = github_behind(repo, fmt.format(pin))
            elif adapter == "claudecode":
                latest, behind = npm_behind("@anthropic-ai/claude-code", pin)
            elif adapter == "cursor-cli":
                latest, behind = cursor_cli_behind(pin)
            else:
                latest, behind = cursor_ide_behind(pin)
        except Exception as e:  # noqa: BLE001
            rows.append((adapter, pin, "?", "?", limit, f"ERROR {e}"))
            rc = max(rc, 2)
            continue
        status = "ok" if behind <= limit else "STALE"
        if status == "STALE":
            rc = max(rc, 1)
        rows.append((adapter, pin, latest, behind, limit, status))
    table = ["| adapter | pinned | latest | behind | limit | status |", "|---|---|---|---|---|---|"]
    table += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    sys.stdout.write("\n".join(table) + "\n")
    return rc


if __name__ == "__main__":
    sys.exit(main())
