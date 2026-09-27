"""rm-input/v1 vendored verbatim from training_jobs/rm/prompt.py; test_rm_render.py pins it."""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from dataclasses import dataclass, field

TEMPLATE_VERSION = "rm-input/v1"
SUFFIX = "\n<|end|>\nIs this change a correct and complete solution to the task? Answer:"
TEMPLATE_SHA = hashlib.sha256((TEMPLATE_VERSION + SUFFIX).encode()).hexdigest()
YES = " yes"
NO = " no"
MAX_TASK_CHARS = 2700
TASK_HEAD = 1800
MAX_DIFF_CHARS = 9000
OVERSIZE_SRC_FRAC = 0.5

ABSTAIN_NO_CHANGE = "NO_CHANGE"
ABSTAIN_OVERSIZE = "OVERSIZE"

_LOCKFILES = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "cargo.lock",
    "poetry.lock",
    "pipfile.lock",
    "go.sum",
    "composer.lock",
    "gemfile.lock",
    "uv.lock",
    "npm-shrinkwrap.json",
}
_VENDOR_DIRS = {"vendor", "node_modules", "third_party", "dist", "build", "__pycache__", ".git"}
_BINARY_EXT = {
    "png",
    "jpg",
    "jpeg",
    "gif",
    "ico",
    "bmp",
    "pdf",
    "zip",
    "gz",
    "tgz",
    "bz2",
    "xz",
    "so",
    "dll",
    "exe",
    "dylib",
    "woff",
    "woff2",
    "ttf",
    "otf",
    "eot",
    "jar",
    "class",
    "pyc",
    "whl",
    "mp4",
    "mp3",
    "wav",
    "bin",
    "npy",
    "npz",
    "pkl",
    "parquet",
    "db",
    "sqlite",
}
_CONFIG_EXT = {
    "json",
    "yaml",
    "yml",
    "toml",
    "ini",
    "cfg",
    "conf",
    "xml",
    "gradle",
    "properties",
    "lock",
}
_CONFIG_NAMES = {
    "dockerfile",
    "makefile",
    "cmakelists.txt",
    ".gitignore",
    "setup.py",
    "setup.cfg",
    "tox.ini",
}
_DOC_EXT = {"md", "rst", "txt", "adoc"}
_NARRATIVE_RE = re.compile(
    r"(SUMMARY|NOTES|REPORT|CHANGES_|FIX_|IMPLEMENTATION|SOLUTION|VERIFICATION)"
)
_TEST_FILE_RE = re.compile(
    r"(^test_.*\.py$|_test\.(py|go|rs|rb|cc|cpp)$|\.(test|spec)\.[jt]sx?$|Tests?\.(java|kt|cs)$|_spec\.rb$)"
)
_TEST_DIRS = {"test", "tests", "__tests__", "spec", "specs", "testing"}
_LANG = {
    "py": "python",
    "js": "javascript",
    "jsx": "javascript",
    "mjs": "javascript",
    "ts": "typescript",
    "tsx": "typescript",
    "java": "java",
    "kt": "kotlin",
    "go": "go",
    "rs": "rust",
    "c": "c",
    "h": "c",
    "cc": "cpp",
    "cpp": "cpp",
    "cxx": "cpp",
    "hpp": "cpp",
    "cs": "csharp",
    "rb": "ruby",
    "php": "php",
    "scala": "scala",
    "swift": "swift",
    "sh": "shell",
    "sql": "sql",
    "hs": "haskell",
    "ml": "ocaml",
}
CLAIM_RE = re.compile(
    r"(?i)(all (the )?tests? (now )?pass|tests? (now )?pass(es|ed)?\b|"
    r"(this|the) (fix|change|patch|implementation) (is|has been) "
    r"(verified|confirmed|correct|tested)|"
    r"issue (is|has been) (now )?(fixed|resolved)|successfully (fixed|resolved|implemented)|"
    r"reviewer note|verified (correct|working)|fix verified)"
)
SUPPRESS_RE = re.compile(
    r"(noqa|type:\s*ignore|@ts-ignore|@ts-expect-error|eslint-disable|#\[allow\(|@SuppressWarnings|"
    r"pytest\.mark\.(skip|xfail)|unittest\.skip|@Disabled|@Ignore\b|\bxit\(|\.skip\()"
)


@dataclass
class FileDiff:
    path: str
    header: list[str] = field(default_factory=list)
    hunks: list[list[str]] = field(default_factory=list)
    new: bool = False
    binary: bool = False


@dataclass(frozen=True)
class Rendered:
    prefix: str
    abstain: str | None
    meta: dict

    @property
    def text(self) -> str:
        return self.prefix + SUFFIX


def _neutralize(s: str) -> str:
    return (s or "").replace("<|", "< |")


def _clean_path(p: str) -> str:
    p = p.split("\t")[0].strip()
    return p[2:] if p[:2] in ("a/", "b/") else p


def split_files(diff: str) -> list[FileDiff]:
    """Unified diff -> per-file sections (tolerant of git and plain ---/+++ headers)."""
    files: list[FileDiff] = []
    cur: FileDiff | None = None
    lines = (diff or "").splitlines()
    for i, line in enumerate(lines):
        nxt = lines[i + 1] if i + 1 < len(lines) else ""
        if line.startswith("diff --git "):
            cur = FileDiff(path=_clean_path(line.rsplit(" b/", 1)[-1]) if " b/" in line else "?")
            files.append(cur)
        elif line.startswith("--- ") and nxt.startswith("+++ "):
            if cur is None or cur.hunks:
                cur = FileDiff(path="?")
                files.append(cur)
            cur.header.append(line)
            if line[4:].strip() == "/dev/null":
                cur.new = True
        elif line.startswith("+++ ") and cur is not None and not cur.hunks:
            cur.header.append(line)
            if line[4:].strip() != "/dev/null":
                cur.path = _clean_path(line[4:])
        elif line.startswith("@@"):
            if cur is None:
                cur = FileDiff(path="?")
                files.append(cur)
            cur.hunks.append([line])
        elif cur is not None and cur.hunks and line[:1] in (" ", "+", "-", "\\", ""):
            cur.hunks[-1].append(line)
        elif cur is not None:
            if line.startswith("new file mode"):
                cur.new = True
            if line.startswith(("Binary files", "GIT binary patch")):
                cur.binary = True
    return files


def path_role(path: str, new: bool = False) -> str:
    parts = [p for p in path.lower().split("/") if p]
    base = parts[-1] if parts else ""
    ext = base.rsplit(".", 1)[-1] if "." in base else ""
    if (
        base in _LOCKFILES
        or _VENDOR_DIRS & set(parts[:-1])
        or ext in _BINARY_EXT
        or base.endswith(".min.js")
    ):
        return "drop"
    if new and ext in _DOC_EXT and _NARRATIVE_RE.search(path.rsplit("/", 1)[-1].upper()):
        return "narrative"
    if (
        _TEST_FILE_RE.search(path.rsplit("/", 1)[-1])
        or _TEST_DIRS & set(parts[:-1])
        or base == "conftest.py"
    ):
        return "test"
    if ext in _DOC_EXT:
        return "doc"
    if ext in _CONFIG_EXT or base in _CONFIG_NAMES:
        return "config"
    return "src"


def _short_path(path: str) -> str:
    return "/".join(path.split("/")[-2:])


def _truncate_task(task: str) -> tuple[str, bool]:
    task = _neutralize(task).strip()
    if len(task) <= MAX_TASK_CHARS:
        return task, False
    return task[:TASK_HEAD] + "\n[...]\n" + task[-(MAX_TASK_CHARS - TASK_HEAD) :], True


def _file_text(f: FileDiff, role: str, hunks: list[list[str]]) -> str:
    p = _short_path(f.path)
    head = [f"--- a/{p} [role={role}]", f"+++ b/{p}"]
    return "\n".join(head + [ln for h in hunks for ln in h])


def render(task: str, diff: str, max_diff_chars: int = MAX_DIFF_CHARS) -> Rendered:
    """(task, diff) -> the single RM input sequence; nothing else can reach the model."""
    task_text, task_trunc = _truncate_task(task)
    kept: list[tuple[int, FileDiff, str, list[list[str]]]] = []
    adds = dels = supp = 0
    roles: Counter = Counter()
    langs: Counter = Counter()
    for idx, f in enumerate(split_files(_neutralize(diff))):
        role = path_role(f.path, f.new)
        if role in ("drop", "narrative") or f.binary or not f.hunks:
            continue
        hunks = []
        for h in f.hunks:
            body = [h[0]]
            for ln in h[1:]:
                if ln.startswith("+") and CLAIM_RE.search(ln):
                    continue
                if ln.startswith("+"):
                    adds += 1
                    supp += bool(SUPPRESS_RE.search(ln))
                elif ln.startswith("-"):
                    dels += 1
                    supp -= bool(SUPPRESS_RE.search(ln))
                body.append(ln)
            hunks.append(body)
        roles[role] += 1
        if role == "src":
            ext = f.path.rsplit(".", 1)[-1].lower() if "." in f.path else ""
            langs[_LANG.get(ext, "other")] += 1
        kept.append((idx, f, role, hunks))
    if not kept or adds + dels == 0:
        return Rendered(prefix="", abstain=ABSTAIN_NO_CHANGE, meta={})

    budget = max_diff_chars
    chosen: dict[int, str] = {}
    src_total = src_kept = 0
    truncated = False
    order = {"src": 0, "test": 1, "config": 2, "doc": 3}
    for idx, f, role, hunks in sorted(kept, key=lambda k: (order[k[2]], k[0])):
        full = _file_text(f, role, hunks)
        src_total += len(full) if role == "src" else 0
        if len(full) <= budget:
            chosen[idx] = full
            budget -= len(full) + 1
            src_kept += len(full) if role == "src" else 0
            continue
        truncated = True
        part: list[list[str]] = []
        for h in hunks:
            if len(_file_text(f, role, part + [h])) > budget:
                break
            part.append(h)
        if part:
            txt = _file_text(f, role, part)
            chosen[idx] = txt
            budget -= len(txt) + 1
            src_kept += len(txt) if role == "src" else 0
    if src_total and (src_total - src_kept) / src_total > OVERSIZE_SRC_FRAC:
        return Rendered(prefix="", abstain=ABSTAIN_OVERSIZE, meta={})

    meta = {
        "lang": langs.most_common(1)[0][0] if langs else "none",
        "files": len(kept),
        "add": adds,
        "del": dels,
        "src_files": roles["src"],
        "test_files": roles["test"],
        "config_files": roles["config"] + roles["doc"],
        "test_touched": int(roles["test"] > 0),
        "suppression_delta": supp,
        "truncated": int(truncated or task_trunc),
    }
    meta_line = " ".join(f"{k}={v}" for k, v in meta.items())
    body = "\n".join(chosen[i] for i in sorted(chosen))
    prefix = f"<|task|>\n{task_text}\n<|meta|> {meta_line}\n<|diff|>\n{body}"
    return Rendered(prefix=prefix, abstain=None, meta=meta)


def language_of(diff: str) -> str:
    r = render("", diff)
    return r.meta.get("lang", "none") if r.abstain is None else "none"


def is_unified_diff(text: str) -> bool:
    t = text or ""
    return "@@" in t and ("\n+++ " in t or t.startswith("+++ ") or "diff --git" in t)
