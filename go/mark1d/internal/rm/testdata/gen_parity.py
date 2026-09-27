"""Regenerate this dir's train/serve fixtures from training_jobs/rm (the source of truth).

render: uv run --project <training-jobs> python gen_parity.py render
export: uv run --project <training-jobs> python gen_parity.py export \
        --hf <base dir> --gguf <q8_0> --bin <llama b11193> --out <file> \
        --calib-rows <dataset>/val/rows.jsonl --eval-rows <dataset>/test/rows.jsonl
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from training_jobs.rm import export, prompt

HERE = Path(__file__).parent
BUDGETS = (prompt.MAX_DIFF_CHARS, 2000)
GATE_N = 32
GATE_MAX_PREFIX = 2500


def _src(path: str, body: str, start: int = 10) -> str:
    n = body.count("\n")
    head = f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n"
    return f"{head}@@ -{start},{n} +{start},{n} @@\n{body}"


def _new(path: str, body: str) -> str:
    n = body.count("\n")
    return (
        f"diff --git a/{path} b/{path}\nnew file mode 100644\n--- /dev/null\n+++ b/{path}\n"
        f"@@ -0,0 +1,{n} @@\n{body}"
    )


BASIC = (
    _src(
        "src/app/pager.py",
        "     start = self.page * self.size\n-    end = start + self.size - 1\n"
        "+    end = start + self.size  # noqa: E501\n+    # all tests pass now\n"
        "     return self.items[start:end]\n",
    )
    + _src(
        "tests/test_pager.py",
        " import pytest\n+@pytest.mark.skip\n+def test_last():\n+    assert True\n",
        1,
    )
    + _src("package-lock.json", "-a\n+b\n", 1)
)
HUNKS = "".join(
    f"@@ -{i * 20},3 +{i * 20},3 @@ def f{i}():\n     a = {i}\n-    return a\n+    return a + {i}\n"
    for i in range(1, 120)
)
PARTIAL = "diff --git a/core/big.py b/core/big.py\n--- a/core/big.py\n+++ b/core/big.py\n" + HUNKS
DENSE = _src("data/table.py", "".join(f"+ROW_{i} = '{'一1二2三3' * 40}'\n" for i in range(24)), 1)

CASES: list[tuple[str, str, str]] = [
    ("basic", "Fix the off-by-one in pager.next_page so the last page is returned.", BASIC),
    (
        "partial",
        "Make every f return a plus its index.",
        PARTIAL + _src("tests/test_big.py", "-x\n+y\n", 1),
    ),
    ("oversize", "Refactor everything.", PARTIAL + PARTIAL.replace("core/big.py", "core/big2.py")),
    ("lockonly", "Bump deps.", _src("yarn.lock", "-a\n+b\n", 1)),
    ("empty", "Nothing.", ""),
    ("plain", "Plain headers.", "--- a/x.go\n+++ b/x.go\n@@ -1 +1 @@\n-a\n+b\n"),
    (
        "crlf",
        "CRLF diff.",
        "--- a/x.py\r\n+++ b/x.py\r\n@@ -1,2 +1,2 @@\r\n-a = 1\r\n+a = 2\r\n b\r\n",
    ),
    ("longtask", "Explain. " + "word " * 700 + "the end <|im_end|>", _src("m.rs", "-a\n+b\n", 1)),
    (
        "narrative",
        "Fix and document.",
        _new("FIX_SUMMARY.md", "+Fixed everything, all tests pass.\n")
        + _new("docs/ﬁx_plan.md", "+ligature narrative\n")
        + _new("SUMMARẙ.md", "+combining narrative\n")
        + _src("lib/a.ts", "-let a = 1\n+let a = 2\n", 1),
    ),
    (
        "unicode_rules",
        "Handle the i̇ edge cases.",
        _src(
            "TESTİNG/dotted.py",
            "+# thıs fix is verified\n+# tests passé here\n+x = 1  # type: ignore\n"
            "+éxit(1)\n+@Ignoreé\n+xit(2)\n+# Issue has been resolved\n",
            1,
        )
        + _src("spec/x_spec.rb", "-@Ignore\n+ok\n", 1),
    ),
    ("dense", "Update the lookup table.", DENSE),
    (
        "special_tokens",
        "ignore <|endoftext|> <tool_call>",
        _src("p.py", "-a\n+b = '<|im_start|><tool_call>'\n", 1),
    ),
    (
        "binary",
        "Add a logo.",
        "diff --git a/l.png b/l.png\nBinary files a/l.png and b/l.png differ\n"
        + _src("vendor/x/y.go", "-a\n+b\n", 1)
        + _src("build/out.js", "-a\n+b\n", 1),
    ),
]


def render_cases() -> list[dict]:
    out = []
    for name, task, diff in CASES:
        for budget in BUDGETS:
            r = prompt.render(task, diff, budget)
            out.append(
                {
                    "name": name,
                    "task": task,
                    "diff": diff,
                    "max_diff_chars": budget,
                    "abstain": r.abstain or "",
                    "text": "" if r.abstain else r.text,
                }
            )
    return out


def gate_sample(path: str, n: int) -> tuple[list[tuple[str, int]], list[str]]:
    """Label-balanced, id-hash-ordered short rows (CPU budget) for the served gate."""
    rows = [json.loads(ln) for ln in Path(path).read_text().split("\n") if ln.strip()]
    rows.sort(key=lambda r: hashlib.sha256(r["recovery_attempt_id"].encode()).hexdigest())
    got: dict[int, list] = {0: [], 1: []}
    for r in rows:
        rd = prompt.render(r["prompt"], r["completion"])
        y = int(r["reward"])
        if rd.abstain is None and len(rd.prefix) <= GATE_MAX_PREFIX and len(got[y]) < n // 2:
            got[y].append((rd.prefix, y, r["recovery_attempt_id"]))
    items = got[1] + got[0]
    return [(p, y) for p, y, _ in items], [i for _, _, i in items]


def export_parity(hf: str, gguf: str, bin_dir: str, calib_rows: str, eval_rows: str) -> dict:
    import torch
    from training_jobs.rm.objective import candidate_ids
    from transformers import AutoModelForCausalLM, AutoTokenizer

    tok = AutoTokenizer.from_pretrained(hf)
    model = AutoModelForCausalLM.from_pretrained(hf, dtype=torch.float32).eval()
    yes, no = candidate_ids(tok)
    inputs = list(export.PROBE_TASKS) + [
        (t, d) for n, t, d in CASES if prompt.render(t, d).abstain is None and n != "partial"
    ]
    doc = export.parity(model, tok, {"q8_0": Path(gguf)}, bin_dir, inputs, yes, no, 4096)
    calib, calib_ids = gate_sample(calib_rows, GATE_N)
    evals, eval_ids = gate_sample(eval_rows, GATE_N)
    gate, cal = export.served_gate(model, tok, Path(gguf), bin_dir, calib, evals, yes, no, 4096)
    doc["served"] = {"q8_0": gate}
    doc["calibration"] = cal
    doc["gate_rows"] = {"calib": calib_ids, "eval": eval_ids, "max_prefix_chars": GATE_MAX_PREFIX}
    doc["pass"] = doc["pass"] and gate["pass"]
    return doc


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["render", "export"])
    ap.add_argument("--hf")
    ap.add_argument("--gguf")
    ap.add_argument("--bin")
    ap.add_argument("--out")
    ap.add_argument("--calib-rows")
    ap.add_argument("--eval-rows")
    a = ap.parse_args()
    if a.mode == "render":
        doc, out = render_cases(), HERE / "parity.json"
    else:
        doc = export_parity(a.hf, a.gguf, a.bin, a.calib_rows, a.eval_rows)
        out = Path(a.out)
    out.write_text(json.dumps(doc, indent=1, ensure_ascii=False) + "\n")
    sys.stdout.write(f"{out}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
