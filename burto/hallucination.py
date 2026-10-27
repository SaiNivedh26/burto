"""
Burto Phase 2G — Hallucination steering.

Deterministic grounding checks that run before any LLM call.
Returns a STEER decision with a grounded correction when:
  - A file path does not exist (with fuzzy close-match suggestions)
  - A pip/npm package does not exist on PyPI/npm
  - A CLI flag is not in the binary's --help output
  - The agent is context-drifting (tracked via session error replay pattern)

All checks are cheap (<50 ms wall time). They run before the LLM stage.
"""
from __future__ import annotations

import difflib
import json
import logging
import os
import re
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
import urllib.request
import urllib.error

from burto.models import ActionEvaluation, Decision

log = logging.getLogger("burto.hallucination")

# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

@dataclass
class GroundingResult:
    steered: bool = False
    hallucination_type: str = ""        # file_not_found | pkg_not_found | flag_not_found | context_drift
    hallucinated_value: str = ""        # what the agent tried to use
    suggested_correction: str = ""      # grounded replacement text shown to agent
    suggested_value: str = ""           # closest real match
    check_name: str = ""


# ---------------------------------------------------------------------------
# File-path existence + fuzzy suggestion
# ---------------------------------------------------------------------------

_EXCLUDE_DIRS = {
    ".venv", "venv", ".env", "env", "node_modules", "__pycache__",
    ".git", ".hg", ".svn", "dist", "build", ".tox", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", ".eggs", "*.egg-info",
    ".burto", ".commandcode", ".claude",
}


def _project_file_list(project_root: str) -> list[str]:
    """Return all relative source file paths in the project (excludes generated dirs)."""
    root = Path(project_root)
    files: list[str] = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        # Skip any path that has an excluded directory component
        parts = p.relative_to(root).parts
        if any(part in _EXCLUDE_DIRS or part.endswith(".egg-info") for part in parts):
            continue
        # Skip compiled/generated file types
        if p.suffix in {".pyc", ".pyo", ".pyd", ".so", ".dylib", ".dll", ".class"}:
            continue
        try:
            files.append(str(p.relative_to(root)))
        except ValueError:
            pass
    return files


_file_list_cache: dict[str, tuple[float, list[str]]] = {}  # root → (ts, files)
_file_list_lock = threading.Lock()
_FILE_CACHE_TTL = 30.0  # seconds


def _get_project_files(project_root: str) -> list[str]:
    with _file_list_lock:
        cached = _file_list_cache.get(project_root)
        if cached and (time.time() - cached[0]) < _FILE_CACHE_TTL:
            return cached[1]
    files = _project_file_list(project_root)
    with _file_list_lock:
        _file_list_cache[project_root] = (time.time(), files)
    return files


def invalidate_file_cache(project_root: str) -> None:
    """Call after write_file/edit_file so steer checks see new files."""
    with _file_list_lock:
        _file_list_cache.pop(project_root, None)


def check_file_path(tool_name: str, tool_input: dict, project_root: str) -> GroundingResult:
    """Check whether the file path in a read/write/edit tool call actually exists."""
    result = GroundingResult()

    # Only apply to file-touching tools (normalize spaces, underscores, dashes)
    file_tools = {"read", "readfile", "view", "open", "write", "writefile",
                  "edit", "editfile", "strreplaceeditor", "createfile"}
    normalized = tool_name.lower().replace("_", "").replace("-", "").replace(" ", "")
    if normalized not in file_tools and not any(
        kw in normalized for kw in ("read", "write", "edit", "create", "view", "open")
    ):
        return result

    # Extract path
    path_str = None
    for key in ("file_path", "path", "filename", "target_file"):
        if key in tool_input:
            path_str = str(tool_input[key])
            break
    if not path_str:
        return result

    # Resolve absolute path
    if os.path.isabs(path_str):
        abs_path = Path(path_str)
    else:
        abs_path = Path(project_root) / path_str

    if abs_path.exists():
        return result  # file exists — no hallucination

    # Fuzzy-match against project tree
    rel_path = path_str.lstrip("/")
    project_files = _get_project_files(project_root)
    # Match on full relative path and basename separately
    matches = difflib.get_close_matches(rel_path, project_files, n=3, cutoff=0.45)
    if not matches:
        basename = Path(rel_path).name
        matches = difflib.get_close_matches(basename, [Path(f).name for f in project_files], n=3, cutoff=0.5)
        # Map back to full paths
        name_to_full = {Path(f).name: f for f in project_files}
        matches = [name_to_full.get(m, m) for m in matches]

    if matches:
        best = matches[0]
        others = ", ".join(matches[1:]) if len(matches) > 1 else ""
        correction_parts = [
            f"File `{path_str}` does not exist in this project.",
            f"Closest match: `{best}`",
        ]
        if others:
            correction_parts.append(f"Other similar files: {others}")
        correction_parts.append("Use the correct path and retry.")
        suggested = f"Use `{best}` instead."
    else:
        correction_parts = [
            f"File `{path_str}` does not exist in this project.",
            "No similar files found. List the directory first to find the correct path.",
        ]
        suggested = ""

    result.steered = True
    result.hallucination_type = "file_not_found"
    result.check_name = "file_exists"
    result.hallucinated_value = path_str
    result.suggested_correction = " ".join(correction_parts)
    result.suggested_value = matches[0] if matches else ""
    return result


# ---------------------------------------------------------------------------
# PyPI / npm package existence
# ---------------------------------------------------------------------------

_pkg_cache: dict[str, tuple[float, bool]] = {}  # name → (ts, exists)
_pkg_cache_lock = threading.Lock()
_PKG_CACHE_TTL = 86400 * 30  # 30 days


def _pypi_exists(name: str) -> bool:
    url = f"https://pypi.org/pypi/{name}/json"
    try:
        req = urllib.request.Request(url, method="HEAD")
        with urllib.request.urlopen(req, timeout=3):
            return True
    except urllib.error.HTTPError as e:
        return e.code != 404
    except Exception:
        return True  # network error → assume exists (fail open)


def _npm_exists(name: str) -> bool:
    url = f"https://registry.npmjs.org/{name}"
    try:
        req = urllib.request.Request(url, method="HEAD")
        with urllib.request.urlopen(req, timeout=3):
            return True
    except urllib.error.HTTPError as e:
        return e.code != 404
    except Exception:
        return True


def _pkg_exists(name: str, registry: str) -> bool:
    key = f"{registry}:{name}"
    with _pkg_cache_lock:
        cached = _pkg_cache.get(key)
        if cached and (time.time() - cached[0]) < _PKG_CACHE_TTL:
            return cached[1]
    exists = _pypi_exists(name) if registry == "pypi" else _npm_exists(name)
    with _pkg_cache_lock:
        _pkg_cache[key] = (time.time(), exists)
    return exists


_PIP_RE = re.compile(r"pip(?:3)?\s+install\s+([A-Za-z0-9_\-\.]+)", re.IGNORECASE)
_NPM_RE = re.compile(r"(?:npm|pnpm|yarn)\s+(?:install|add)\s+([A-Za-z0-9_\-\.@/]+)", re.IGNORECASE)

# Common hallucinated → real package corrections
_KNOWN_CORRECTIONS = {
    "python-jose-crypto": "python-jose",
    "pyjwt-crypto": "PyJWT",
    "jose": "python-jose",
    "bcrypt-py": "bcrypt",
    "fastapi-jwt": "python-jose",
    "sqlalchemy-async": "SQLAlchemy[asyncio]",
    "postgres": "psycopg2",
    "psql": "psycopg2",
}


def _is_shell_tool(tool_name: str, tool_input: dict) -> bool:
    """True for any tool that executes a shell command."""
    name = tool_name.lower().replace(" ", "_").replace("-", "_")
    # Named shell tools
    if name in {"bash", "shell", "run_command", "execute", "exec", "terminal",
                "run_bash", "run_shell", "execute_command", "computer"}:
        return True
    # Has a command/cmd key (cmdc sends tool_name=shell but also some agents use execute_command)
    if "command" in tool_input or "cmd" in tool_input:
        return True
    return False


def check_package(tool_name: str, tool_input: dict) -> GroundingResult:
    """Check pip install / npm install for non-existent packages."""
    result = GroundingResult()

    if not _is_shell_tool(tool_name, tool_input):
        return result

    cmd = tool_input.get("command", tool_input.get("cmd", ""))
    if not cmd:
        return result

    # pip
    m = _PIP_RE.search(cmd)
    if m:
        pkg = m.group(1)
        known_fix = _KNOWN_CORRECTIONS.get(pkg)
        if known_fix:
            result.steered = True
            result.hallucination_type = "pkg_not_found"
            result.check_name = "pkg_exists_pypi"
            result.hallucinated_value = pkg
            result.suggested_value = known_fix
            result.suggested_correction = (
                f"Package `{pkg}` does not exist on PyPI. "
                f"Did you mean `{known_fix}`? "
                f"Replace `{pkg}` with `{known_fix}` and retry."
            )
            return result
        if not _pkg_exists(pkg, "pypi"):
            result.steered = True
            result.hallucination_type = "pkg_not_found"
            result.check_name = "pkg_exists_pypi"
            result.hallucinated_value = pkg
            result.suggested_correction = (
                f"Package `{pkg}` does not exist on PyPI. "
                "Check the exact package name on https://pypi.org before installing."
            )
            return result

    # npm/pnpm/yarn
    m = _NPM_RE.search(cmd)
    if m:
        pkg = m.group(1).lstrip("@").split("@")[0]
        if not _pkg_exists(pkg, "npm"):
            result.steered = True
            result.hallucination_type = "pkg_not_found"
            result.check_name = "pkg_exists_npm"
            result.hallucinated_value = pkg
            result.suggested_correction = (
                f"Package `{pkg}` does not exist on npm. "
                "Verify the package name at https://npmjs.com before installing."
            )
            return result

    return result


# ---------------------------------------------------------------------------
# CLI flag existence
# ---------------------------------------------------------------------------

_flag_help_cache: dict[str, tuple[float, str]] = {}  # binary → (ts, help_text)
_flag_lock = threading.Lock()
_FLAG_CACHE_TTL = 3600.0  # 1 hour


def _get_help(binary: str) -> str:
    key = binary
    with _flag_lock:
        cached = _flag_help_cache.get(key)
        if cached and (time.time() - cached[0]) < _FLAG_CACHE_TTL:
            return cached[1]
    try:
        out = subprocess.run(
            [binary, "--help"], capture_output=True, text=True, timeout=5
        )
        text = out.stdout + out.stderr
    except Exception:
        text = ""
    with _flag_lock:
        _flag_help_cache[key] = (time.time(), text)
    return text


_LONG_FLAG_RE = re.compile(r"--([a-z][a-z0-9\-]+)")

# Binaries where flag checking is meaningful and safe to run --help on
_FLAG_CHECK_BINARIES = {"docker", "kubectl", "git", "alembic", "pytest", "pip",
                        "npm", "pnpm", "yarn", "terraform", "helm", "cargo"}


def check_flag(tool_name: str, tool_input: dict) -> GroundingResult:
    """Check whether a long --flag in a shell command is valid."""
    result = GroundingResult()

    if not _is_shell_tool(tool_name, tool_input):
        return result

    cmd = str(tool_input.get("command", tool_input.get("cmd", "")))
    if not cmd:
        return result

    binary = cmd.split()[0] if cmd.split() else ""
    if binary not in _FLAG_CHECK_BINARIES:
        return result

    flags = _LONG_FLAG_RE.findall(cmd)
    if not flags:
        return result

    help_text = _get_help(binary)
    if not help_text:
        return result  # can't get help — fail open

    for flag in flags:
        if f"--{flag}" not in help_text:
            # Fuzzy-match against known flags in help text
            known_flags = _LONG_FLAG_RE.findall(help_text)
            suggestions = difflib.get_close_matches(flag, known_flags, n=2, cutoff=0.6)
            if suggestions:
                correction = (
                    f"Flag `--{flag}` is not recognised by `{binary}`. "
                    f"Closest valid flags: {', '.join('--' + s for s in suggestions)}. "
                    "Check `{} --help` for all options.".format(binary)
                )
                suggested = f"--{suggestions[0]}"
            else:
                correction = (
                    f"Flag `--{flag}` is not recognised by `{binary}`. "
                    f"Run `{binary} --help` to see valid options."
                )
                suggested = ""
            result.steered = True
            result.hallucination_type = "flag_not_found"
            result.check_name = "flag_exists"
            result.hallucinated_value = f"--{flag}"
            result.suggested_correction = correction
            result.suggested_value = suggested
            return result  # stop at first bad flag

    return result


# ---------------------------------------------------------------------------
# Context drift detection (session-level)
# ---------------------------------------------------------------------------

# Tracks per-session: list of (tool_name, command_or_path, error_seen)
_session_errors: dict[str, list[dict]] = {}
_session_errors_lock = threading.Lock()


_FAILURE_RE = re.compile(
    r"(Error:|error:|Traceback|Exception:|FAILED|No such file|command not found|"
    r"not found|Permission denied|ModuleNotFoundError|SyntaxError|ImportError|"
    r"FileNotFoundError|returned non-zero|CalledProcessError)",
    re.IGNORECASE,
)


def _is_failure_response(tool_response: str) -> bool:
    return bool(_FAILURE_RE.search(tool_response[:2000])) if tool_response else False


def record_tool_error(session_id: str, tool_name: str, tool_input: dict) -> None:
    """
    Call after a tool result comes back with an error.
    (Currently called heuristically when we detect a repeated failed pattern.)
    """
    key = tool_name + ":" + json.dumps(tool_input, sort_keys=True)[:80]
    with _session_errors_lock:
        errors = _session_errors.setdefault(session_id, [])
        errors.append({"key": key, "ts": time.time()})


def check_retry_loop(session_id: str, tool_name: str, tool_input: dict) -> GroundingResult:
    """
    Detect when the agent is retrying the same failing tool call.
    If the same (tool_name, input_key) failed in the last 3 turns → STEER.
    """
    result = GroundingResult()
    key = tool_name + ":" + json.dumps(tool_input, sort_keys=True)[:80]
    with _session_errors_lock:
        errors = _session_errors.get(session_id, [])
    recent_matches = [e for e in errors[-10:] if e["key"] == key]
    if len(recent_matches) >= 2:
        result.steered = True
        result.hallucination_type = "context_drift"
        result.check_name = "retry_loop"
        result.hallucinated_value = key[:80]
        result.suggested_correction = (
            f"This exact action (`{tool_name}`) has already failed multiple times. "
            "Stop retrying — the approach is wrong. "
            "Re-read the task goal and try a fundamentally different approach."
        )
        return result
    return result


# ---------------------------------------------------------------------------
# Master grounding check — runs all checks in order
# ---------------------------------------------------------------------------

def run_grounding_checks(
    session_id: str,
    tool_name: str,
    tool_input: dict,
    project_root: str,
) -> GroundingResult:
    """
    Run all deterministic grounding checks.
    Returns the first non-trivial result (checks are ordered cheapest-first).
    """
    # 1. Retry-loop detection (pure in-memory, ~0ms)
    r = check_retry_loop(session_id, tool_name, tool_input)
    if r.steered:
        return r

    # 2. File path existence (filesystem stat, ~1ms)
    if project_root:
        r = check_file_path(tool_name, tool_input, project_root)
        if r.steered:
            return r

    # 3. Known hallucinated packages (dict lookup, ~0ms; HTTP for unknowns)
    r = check_package(tool_name, tool_input)
    if r.steered:
        return r

    # 4. CLI flag existence (binary --help once per session, ~100ms first call)
    r = check_flag(tool_name, tool_input)
    if r.steered:
        return r

    return GroundingResult()


# ---------------------------------------------------------------------------
# Convert GroundingResult → ActionEvaluation
# ---------------------------------------------------------------------------

def to_steer_evaluation(gr: GroundingResult) -> ActionEvaluation:
    from burto.models import ActionEvaluation, Decision
    return ActionEvaluation(
        decision=Decision.STEER,
        reasoning=gr.suggested_correction,
        confidence=0.95,
        impact="Agent is about to use a non-existent resource — intercepted before execution.",
        hallucination_type=gr.hallucination_type,
        correction=gr.suggested_correction,
        suggested_value=gr.suggested_value,
    )
