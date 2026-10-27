"""
Burto Phase 3 — Context Drift Monitor.

Ported directly from ironclaw/drift_monitor.rs (Rust → Python).
Recovery-based suppression model (NOT turn-count cooldown):
  - Suppression clears on specific recovery events, not after N turns.
  - Same interface ironclaw uses: record_tool_result(), check_stop_drift(), anchor_goal().

Four rules (matching ironclaw's merged PR — rework_churn was dropped):
  1. failure_spiral    — ≥4 consecutive failing tool calls
  2. repetition_loop   — same (tool, input-hash) ≥3 times in window-10
  3. tool_cycling      — ping-pong between 2 tools ≥6 calls (deduped by iteration)
  4. silence_drift     — ≥15 iterations without any text communication

Recovery events (clear suppression):
  - success result          → clears failure_spiral suppression
  - different tool used     → clears repetition_loop suppression
  - non-alternating call    → clears tool_cycling suppression
  - record_communication()  → clears silence_drift suppression

Tier 2: async Nebius Nano judges goal-distance on ambiguous signals.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger("burto.drift")


# ─── Result types ──────────────────────────────────────────────────────────────

@dataclass
class DriftSignal:
    rule: str
    severity: str           # "warn" | "steer"
    message: str
    goal_distance: float = 0.0
    details: dict = field(default_factory=dict)


@dataclass
class ToolRecord:
    tool_name: str
    input_hash: str
    success: bool
    iteration: int          # ironclaw: dedup cycling per iteration
    target_file: str = ""
    input_text: str = ""
    response_text: str = ""  # for drift explainer LLM context
    ts: float = field(default_factory=time.time)


# ─── Session state (matches ironclaw's SessionState fields) ────────────────────

class SessionState:
    def __init__(self, session_id: str):
        self.session_id = session_id
        self.goal_anchor: str = ""
        self.goal_keywords: set[str] = set()
        self.history: list[ToolRecord] = []
        self.iteration: int = 0                       # incremented per PostToolUse call
        self.iterations_since_communication: int = 0  # silence drift counter
        # Recovery-based suppression set (ironclaw: suppressed: HashSet<DriftCorrectionKind>)
        self.suppressed: set[str] = set()
        self.started_at: float = time.time()

    def add_record(self, r: ToolRecord) -> None:
        self.history.append(r)
        self.iteration += 1
        self.iterations_since_communication += 1

        # Recovery events — clear suppression (ironclaw semantics)
        if r.success:
            self.suppressed.discard("failure_spiral")
        # different-tool recovery for repetition_loop
        if self.history and len(self.history) >= 2:
            prev_tool = self.history[-2].tool_name
            if r.tool_name != prev_tool:
                self.suppressed.discard("repetition_loop")
        # non-alternating recovery for tool_cycling:
        # if last 3 tools are NOT strictly alternating, cycling suppression clears
        if len(self.history) >= 3:
            last3 = [h.tool_name for h in self.history[-3:]]
            if not (last3[0] != last3[1] and last3[1] != last3[2] and last3[0] == last3[2]):
                self.suppressed.discard("tool_cycling")

    def record_communication(self) -> None:
        """Called when tool response contains substantive text output (not just errors)."""
        self.iterations_since_communication = 0
        self.suppressed.discard("silence_drift")

    def is_suppressed(self, rule: str) -> bool:
        return rule in self.suppressed

    def suppress(self, rule: str) -> None:
        self.suppressed.add(rule)

    def recent(self, n: int = 10) -> list[ToolRecord]:
        return self.history[-n:]


# ─── Global session registry ───────────────────────────────────────────────────

_sessions: dict[str, SessionState] = {}
_sessions_lock = threading.Lock()


def _get_session(session_id: str) -> SessionState:
    with _sessions_lock:
        if session_id not in _sessions:
            _sessions[session_id] = SessionState(session_id)
        return _sessions[session_id]


def anchor_goal(session_id: str, goal_text: str) -> None:
    state = _get_session(session_id)
    state.goal_anchor = goal_text[:500]
    state.goal_keywords = _keywords(goal_text)
    log.info("drift anchor set session=%s keywords=%d", session_id, len(state.goal_keywords))


# ─── Error detection ──────────────────────────────────────────────────────────

_ERROR_PATTERNS = re.compile(
    r"(Error:|error:|Traceback|Exception:|FAILED|No such file|command not found|"
    r"not found|Permission denied|ModuleNotFoundError|SyntaxError|ImportError|"
    r"FileNotFoundError|NameError|TypeError|KeyError|AttributeError|"
    r"ENOENT|EACCES|exit code [1-9]|returned non-zero|CalledProcessError)",
    re.IGNORECASE,
)

_COMM_PATTERNS = re.compile(
    r"(successfully|wrote|created|passed|done|complete|updated|installed|running)",
    re.IGNORECASE,
)


def _is_failure(tool_response: str) -> bool:
    if not tool_response:
        return False
    return bool(_ERROR_PATTERNS.search(tool_response[:2000]))


def _has_substantive_output(tool_response: str) -> bool:
    """True if response looks like real communication, not just an error."""
    if not tool_response or len(tool_response) < 10:
        return False
    return bool(_COMM_PATTERNS.search(tool_response[:500]))


def _input_hash(tool_name: str, tool_input: dict) -> str:
    raw = json.dumps({"t": tool_name, "i": tool_input}, sort_keys=True)
    return hashlib.md5(raw.encode()).hexdigest()[:12]


def _extract_target_file(tool_name: str, tool_input: dict) -> str:
    n = tool_name.lower()
    if any(kw in n for kw in ("write", "edit", "create", "str_replace")):
        for key in ("file_path", "path", "filename", "target_file"):
            if key in tool_input:
                return str(tool_input[key])
    return ""


# ─── Four drift rules (from ironclaw merged PR) ────────────────────────────────

def _check_failure_spiral(state: SessionState) -> DriftSignal | None:
    """≥4 consecutive failures → spiral. Cleared on success recovery."""
    if state.is_suppressed("failure_spiral"):
        return None
    recent = state.recent(6)
    if len(recent) < 4:
        return None
    consecutive = 0
    for r in reversed(recent):
        if r.success:
            break
        consecutive += 1
    if consecutive >= 4:
        state.suppress("failure_spiral")
        return DriftSignal(
            rule="failure_spiral",
            severity="steer",
            goal_distance=0.8,
            message=(
                f"⚠️ BURTO/DRIFT [failure_spiral]: {consecutive} consecutive tool failures. "
                "The current approach is not working. "
                "Stop and reassess: read the error carefully, check environment setup, "
                "and try a fundamentally different approach to achieve the stated goal."
            ),
            details={"consecutive_failures": consecutive},
        )
    return None


def _check_repetition_loop(state: SessionState) -> DriftSignal | None:
    """Same (tool, input-hash) ≥3 times in last 10. Cleared on different-tool recovery."""
    if state.is_suppressed("repetition_loop"):
        return None
    window = state.recent(10)
    counts: dict[str, int] = {}
    for r in window:
        key = r.tool_name + ":" + r.input_hash
        counts[key] = counts.get(key, 0) + 1
    worst_key, worst_count = max(counts.items(), key=lambda x: x[1]) if counts else ("", 0)
    if worst_count >= 3:
        state.suppress("repetition_loop")
        return DriftSignal(
            rule="repetition_loop",
            severity="steer",
            goal_distance=0.7,
            message=(
                "⚠️ BURTO/DRIFT [repetition_loop]: This exact action has been attempted "
                f"{worst_count} times without progress. "
                "Stop retrying the same approach — re-read the goal and try a different strategy. "
                "Consider: listing the directory, reading an adjacent file, or asking for clarification."
            ),
            details={"key": worst_key, "count": worst_count},
        )
    return None


def _check_tool_cycling(state: SessionState) -> DriftSignal | None:
    """
    Ping-pong between 2 tools for ≥6 calls.
    ironclaw: deduplicate consecutive same-iteration records before checking.
    Cleared on non-alternating recovery.
    """
    if state.is_suppressed("tool_cycling"):
        return None
    recent = state.recent(8)
    if len(recent) < 6:
        return None

    # Dedup by iteration (ironclaw: skip consecutive same-iteration entries)
    deduped: list[ToolRecord] = []
    seen_iterations: set[int] = set()
    for r in recent:
        if r.iteration not in seen_iterations:
            seen_iterations.add(r.iteration)
            deduped.append(r)

    if len(deduped) < 6:
        return None

    tool_names = [r.tool_name.lower() for r in deduped[-6:]]
    unique_tools = set(tool_names)
    if len(unique_tools) == 2:
        # Check strict alternation: ABABAB pattern
        alternating = all(
            tool_names[i] != tool_names[i + 1]
            for i in range(len(tool_names) - 1)
        )
        if alternating:
            state.suppress("tool_cycling")
            t0, t1 = list(unique_tools)
            return DriftSignal(
                rule="tool_cycling",
                severity="warn",
                goal_distance=0.5,
                message=(
                    f"⚠️ BURTO/DRIFT [tool_cycling]: Oscillating between "
                    f"`{t0}` and `{t1}` for 6 calls with no progress. "
                    "This diagnostic loop pattern means the agent is stuck. "
                    "Try a write/edit action to make concrete progress toward the goal."
                ),
                details={"tools": list(unique_tools)},
            )
    return None


def _check_silence_drift(state: SessionState) -> DriftSignal | None:
    """
    ≥15 iterations without any text communication.
    ironclaw's 4th rule (replaced rework_churn in merged PR).
    Cleared when record_communication() is called.
    """
    if state.is_suppressed("silence_drift"):
        return None
    threshold = 15
    if state.iterations_since_communication >= threshold:
        state.suppress("silence_drift")
        return DriftSignal(
            rule="silence_drift",
            severity="warn",
            goal_distance=0.45,
            message=(
                f"⚠️ BURTO/DRIFT [silence_drift]: {state.iterations_since_communication} iterations "
                "without any substantive output or communication. "
                "The agent may be stuck in a silent loop. "
                "Consider producing output, running a test, or summarizing progress."
            ),
            details={"iterations_since_communication": state.iterations_since_communication},
        )
    return None


# ─── Keyword helpers ──────────────────────────────────────────────────────────

def _keywords(text: str) -> set[str]:
    words = re.findall(r"\b[a-zA-Z][a-zA-Z0-9_]{3,}\b", text.lower())
    stopwords = {"this", "that", "with", "from", "have", "will", "your", "when",
                 "what", "then", "than", "they", "them", "been", "into", "over",
                 "also", "just", "more", "some", "make", "file", "tool", "call"}
    return set(w for w in words if w not in stopwords)


# ─── Public API ───────────────────────────────────────────────────────────────

def record_tool_result(
    session_id: str,
    tool_name: str,
    tool_input: dict,
    tool_response: str,
) -> DriftSignal | None:
    """
    Called by PostToolUse hook. Records result and checks all 4 drift rules.
    Returns highest-severity DriftSignal, or None if no drift detected.
    """
    state = _get_session(session_id)

    rec = ToolRecord(
        tool_name=tool_name,
        input_hash=_input_hash(tool_name, tool_input),
        success=not _is_failure(tool_response),
        iteration=state.iteration,
        target_file=_extract_target_file(tool_name, tool_input),
        input_text=json.dumps(tool_input)[:300],
        response_text=tool_response[:300],
        ts=time.time(),
    )

    # Auto-anchor goal from first response if not yet set
    if not state.goal_anchor and len(state.history) == 0 and tool_response:
        _try_auto_anchor(state, tool_response)

    state.add_record(rec)

    # Record communication if tool response has substantive output (feeds silence rule)
    if _has_substantive_output(tool_response):
        state.record_communication()

    # Rules ordered: failure_spiral → repetition_loop → tool_cycling → silence_drift
    for check in [_check_failure_spiral, _check_repetition_loop, _check_tool_cycling, _check_silence_drift]:
        signal = check(state)
        if signal:
            log.info("drift rule=%s severity=%s session=%s", signal.rule, signal.severity, session_id)
            return signal
    return None


def _count_consecutive_failures(state: SessionState) -> int:
    """Count trailing consecutive failures, bypassing suppression (for stop-time check)."""
    count = 0
    for r in reversed(state.history):
        if r.success:
            break
        count += 1
    return count


def check_stop_drift(session_id: str, transcript_summary: str = "") -> DriftSignal | None:
    """
    Called by Stop hook. Returns signal if session looks fundamentally off-goal.
    Bypass suppression — we always recheck at stop time.
    """
    state = _get_session(session_id)
    if len(state.history) < 3:
        return None

    # Direct failure count (bypasses suppression for stop-time verdict)
    consecutive = _count_consecutive_failures(state)
    if consecutive >= 4:
        return DriftSignal(
            rule="stop_failure_spiral",
            severity="steer",
            goal_distance=0.8,
            message=(
                f"BURTO/STOP: Session ended with {consecutive} consecutive failures — task is not complete. "
                "Before finishing: resolve the last error, run the tests, "
                "and confirm the original goal is met."
            ),
        )

    # Silence at stop time
    if state.iterations_since_communication >= 10:
        return DriftSignal(
            rule="stop_silence_drift",
            severity="warn",
            goal_distance=0.4,
            message=(
                f"BURTO/STOP: {state.iterations_since_communication} iterations without output. "
                "Confirm the task is actually complete before stopping."
            ),
        )

    return None


def _try_auto_anchor(state: SessionState, first_response: str) -> None:
    task_patterns = [
        r"(?:task|goal|objective|implement|fix|add|create|build)[:\s]+(.{20,200})",
        r"(?:TODO|TASK)[:\s]+(.{20,200})",
    ]
    for pat in task_patterns:
        m = re.search(pat, first_response[:1000], re.IGNORECASE)
        if m:
            anchor = m.group(1).strip()
            state.goal_anchor = anchor
            state.goal_keywords = _keywords(anchor)
            log.info("drift auto-anchor session=%s text=%r", state.session_id, anchor[:60])
            return


def get_session_drift_summary(session_id: str) -> dict:
    """For dashboard / /drift/<session_id> endpoint."""
    state = _get_session(session_id)
    consecutive_failures = _count_consecutive_failures(state)
    return {
        "session_id": session_id,
        "iteration": state.iteration,
        "history_len": len(state.history),
        "goal_anchor": state.goal_anchor[:100] if state.goal_anchor else None,
        "consecutive_failures": consecutive_failures,
        "suppressed_rules": list(state.suppressed),
        "iterations_since_communication": state.iterations_since_communication,
    }
