"""
Builds SessionContext from a live transcript + project directory.

Supports:
  - cmdc  transcript: type=message, message.role=user/assistant
  - Claude Code transcript: type=user/assistant, message.role=user/assistant
  - Cursor, Windsurf: graceful fallback (no transcript path)

Intent is inferred from the last N user turns — no explicit declaration needed.
Project structure is scanned from cwd and cached per session.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from functools import lru_cache

_SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv", "nvd",
    ".next", "dist", "build", "coverage", ".mypy_cache", ".pytest_cache",
    "vendor", "target", ".cargo",
}
_KEY_FILES = {
    "package.json", "pyproject.toml", "requirements.txt", "Cargo.toml",
    "go.mod", "pom.xml", "build.gradle", "Makefile", "Dockerfile",
    ".env.example", "docker-compose.yml", "tsconfig.json", "setup.py",
}
_MAX_TREE_FILES = 120
_MAX_USER_TURNS = 8


@dataclass
class SessionContext:
    session_id: str
    intent_summary: str          # inferred from conversation
    project_root: str
    project_tree: list[str]      # relative paths, condensed
    key_files: list[str]         # package.json, pyproject.toml, etc.
    recent_user_turns: list[str] # last N user messages
    source: str = "inferred"     # "inferred" | "explicit"
    explicit_scopes: list[str] = field(default_factory=list)


# Session cache: session_id → SessionContext
_cache: dict[str, SessionContext] = {}
# Track transcript sizes to detect new turns
_transcript_sizes: dict[str, int] = {}


def _transcript_changed(transcript_path: str | None, ctx: SessionContext) -> bool:
    """True if the transcript has grown since we last built context."""
    if not transcript_path:
        return False
    try:
        size = Path(transcript_path).stat().st_size
        last = _transcript_sizes.get(ctx.session_id, 0)
        if size != last:
            _transcript_sizes[ctx.session_id] = size
            return True
    except OSError:
        pass
    return False


def get_or_build(
    session_id: str,
    transcript_path: str | None,
    cwd: str,
    explicit_intent: str | None = None,
    explicit_scopes: list[str] | None = None,
) -> SessionContext:
    """Return cached context or build fresh. Explicit intent overrides inference."""
    cached = _cache.get(session_id)

    # Rebuild if transcript grew significantly (new turns arrived)
    if cached and not _transcript_changed(transcript_path, cached):
        # Still update with explicit overrides if provided
        if explicit_intent:
            cached.intent_summary = explicit_intent
            cached.source = "explicit"
            cached.explicit_scopes = explicit_scopes or []
        return cached

    user_turns = _extract_user_turns(transcript_path) if transcript_path else []
    tree, key_files = _scan_project(cwd)

    if explicit_intent:
        intent = explicit_intent
        source = "explicit"
    elif user_turns:
        intent = _summarise_intent(user_turns, tree)
        source = "inferred"
    else:
        intent = "General development task (no conversation history available)"
        source = "inferred"

    ctx = SessionContext(
        session_id=session_id,
        intent_summary=intent,
        project_root=cwd,
        project_tree=tree,
        key_files=key_files,
        recent_user_turns=user_turns[-_MAX_USER_TURNS:],
        source=source,
        explicit_scopes=explicit_scopes or [],
    )
    _cache[session_id] = ctx
    return ctx


def invalidate(session_id: str) -> None:
    _cache.pop(session_id, None)


# ── Transcript parsing ────────────────────────────────────────────────────────

def _extract_user_turns(transcript_path: str) -> list[str]:
    """Extract plain-text user messages from any supported JSONL transcript."""
    try:
        lines = Path(transcript_path).read_text().splitlines()
    except (OSError, IOError):
        return []

    turns: list[str] = []
    for raw in lines:
        raw = raw.strip()
        if not raw:
            continue
        try:
            d = json.loads(raw)
        except json.JSONDecodeError:
            continue

        text = _extract_text_from_entry(d)
        if text:
            turns.append(text)

    # Return last N non-empty turns
    return [t for t in turns if t.strip()][-_MAX_USER_TURNS * 3:]  # keep extra, trim later


def _extract_text_from_entry(d: dict) -> str | None:
    """
    Handles multiple transcript formats:
      cmdc:        {type: "message", message: {role: "user", content: [...]}}
      Claude Code: {type: "user", message: {role: "user", content: [...]}}
    """
    entry_type = d.get("type", "")

    # Skip non-message noise entries
    if entry_type in (
        "session", "custom-title", "agent-name", "mode", "atis-latch",
        "file-history-snapshot", "thinking", "tool_result",
    ):
        return None

    msg = d.get("message", d)
    role = msg.get("role", "")

    # Only user turns carry intent
    if role != "user" and entry_type != "user":
        return None

    content = msg.get("content", "")

    if isinstance(content, str):
        return content.strip() or None

    if isinstance(content, list):
        parts = []
        for item in content:
            if not isinstance(item, dict):
                continue
            if item.get("type") == "text":
                parts.append(item.get("text", "").strip())
            # Skip tool_result, thinking, images
        text = " ".join(p for p in parts if p)
        return text or None

    return None


# ── Project scanner ───────────────────────────────────────────────────────────

def _scan_project(cwd: str) -> tuple[list[str], list[str]]:
    root = Path(cwd)
    tree: list[str] = []
    key_files: list[str] = []

    try:
        for dirpath, dirnames, filenames in os.walk(root):
            # Prune skip dirs in-place so os.walk won't descend
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS and not d.startswith(".")]

            rel_dir = Path(dirpath).relative_to(root)

            for fname in sorted(filenames):
                if fname.startswith(".") and fname not in (".env.example",):
                    continue
                rel = str(rel_dir / fname) if str(rel_dir) != "." else fname
                tree.append(rel)
                if fname in _KEY_FILES:
                    key_files.append(rel)
                if len(tree) >= _MAX_TREE_FILES:
                    tree.append("... (truncated)")
                    return tree, key_files
    except PermissionError:
        pass

    return tree, key_files


# ── Intent summariser (lightweight, no LLM call) ─────────────────────────────

def _summarise_intent(turns: list[str], tree: list[str]) -> str:
    """
    Build a concise intent summary from the last few user turns.
    This is passed to the LLM as context — not the full conversation.
    """
    recent = turns[-_MAX_USER_TURNS:]
    # Truncate long turns (e.g. pasted code blocks)
    trimmed = [t[:300] if len(t) > 300 else t for t in recent]
    return " | ".join(trimmed)
