"""The structural claim behind reader.py, made a test: `mark1-intel` holds NO ClickHouse
driver anywhere in its dependency tree or imports — 05 §6 makes controld.querychoke the
only ClickHouse principal, and 08 §3.3's HTTP contract is intel's only ledger read path.
This is the Python twin of the Go depguard import-negative gate (13 §7.3)."""

import re
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
INTEL_APP = REPO_ROOT / "python" / "intel" / "app"

# Every ClickHouse client package on PyPI anyone has reached for; substring match on
# "clickhouse" additionally catches future renames of the mainline drivers.
FORBIDDEN = {"clickhouse-driver", "clickhouse-connect", "aiochclient", "asynch", "chdb"}

_IMPORT_RE = re.compile(
    r"^\s*(?:import|from)\s+(?:clickhouse\w*|aiochclient|asynch|chdb)\b", re.MULTILINE
)


def _dep_closure(lock: dict, root: str) -> set[str]:
    by_name = {p["name"]: p for p in lock["package"]}
    seen: set[str] = set()
    stack = [root]
    while stack:
        pkg = by_name.get(stack.pop())
        if pkg is None or pkg["name"] in seen:
            continue
        seen.add(pkg["name"])
        deps = [d["name"] for d in pkg.get("dependencies", [])]
        for group in pkg.get("dev-dependencies", {}).values():
            deps += [d["name"] for d in group]
        stack += deps
    return seen


def test_uv_lock_dependency_tree_has_no_clickhouse_driver():
    lock = tomllib.loads((REPO_ROOT / "uv.lock").read_text())
    closure = _dep_closure(lock, "mark1-intel")
    assert "mark1-intel" in closure  # the walk found the package at all
    offenders = {n for n in closure if "clickhouse" in n.lower()} | (closure & FORBIDDEN)
    assert not offenders, f"ClickHouse driver in intel's dependency tree: {offenders}"


def test_intel_source_never_imports_a_clickhouse_client():
    py_files = list(INTEL_APP.rglob("*.py"))
    assert py_files, "no sources found — the grep scanned nothing"
    offenders = [p for p in py_files if _IMPORT_RE.search(p.read_text())]
    assert not offenders, f"ClickHouse client import in: {offenders}"
