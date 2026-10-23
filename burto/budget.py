from __future__ import annotations
from collections import defaultdict
from burto.models import BudgetEntry, Decision, ActionEvaluation

# session_id → list of entries
_budget: dict[str, list[BudgetEntry]] = defaultdict(list)

# session_id → set of file paths touched (for richer LLM context)
_files_touched: dict[str, set[str]] = defaultdict(set)


def record_file(session_id: str, path: str) -> None:
    _files_touched[session_id].add(path)


def get_files_touched(session_id: str) -> list[str]:
    return sorted(_files_touched[session_id])

# Heuristic: these tool names touch infra/network/env
_NETWORK_TOOLS = {"curl", "wget", "fetch", "requests"}
_INFRA_TOOLS = {"terraform", "kubectl", "aws", "gcloud", "az"}
_ENV_SIGNALS = {"env", "environ", "printenv", "$env", "process.env"}


def record(session_id: str, entry: BudgetEntry) -> None:
    _budget[session_id].append(entry)


def _cmd_str(tool_input: dict) -> str:
    return " ".join(str(v) for v in tool_input.values()).lower()


def check_anomalies(session_id: str, tool_name: str, tool_input: dict, intent_text: str) -> ActionEvaluation | None:
    """Return a BLOCK/ESCALATE evaluation if cumulative budget rules trigger, else None."""
    history = _budget[session_id]
    cmd = _cmd_str(tool_input)

    # Rule 1: network call + env access in same session → immediate block
    had_network = any(_cmd_str(e.tool_input) for e in history
                      if any(s in _cmd_str(e.tool_input) for s in _NETWORK_TOOLS))
    env_in_cmd = any(s in cmd for s in _ENV_SIGNALS)
    net_in_cmd = any(s in cmd for s in _NETWORK_TOOLS)

    if env_in_cmd and net_in_cmd:
        return ActionEvaluation(
            decision=Decision.BLOCK,
            reasoning="Command combines network access with environment variable exfiltration.",
            confidence=1.0,
        )

    if net_in_cmd and had_network and env_in_cmd:
        return ActionEvaluation(
            decision=Decision.BLOCK,
            reasoning="Session already has a network call; this command also reads env vars — likely exfiltration.",
            confidence=0.97,
        )

    # Rule 2: infra changes when intent is a bug fix
    bug_fix_keywords = {"fix", "bug", "patch", "hotfix", "issue", "error", "login"}
    is_bug_fix_intent = any(k in intent_text.lower() for k in bug_fix_keywords)
    if is_bug_fix_intent and any(s in cmd for s in _INFRA_TOOLS):
        return ActionEvaluation(
            decision=Decision.BLOCK,
            reasoning=f"Infra-level command detected during a bug-fix task. This exceeds the declared scope.",
            confidence=0.95,
        )

    # Rule 3: >5 file reads outside declared scope — handled upstream in evaluator
    return None


def get_history(session_id: str) -> list[BudgetEntry]:
    return _budget[session_id]


def clear(session_id: str) -> None:
    _budget.pop(session_id, None)
    _files_touched.pop(session_id, None)
