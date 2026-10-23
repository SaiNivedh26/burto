from __future__ import annotations
import json
import os
from dotenv import load_dotenv
from openai import OpenAI

from burto.models import ActionEvaluation, Decision, BudgetEntry
from burto.context_builder import SessionContext
from burto.prompts import (
    INTENT_EVAL_SYSTEM,
    DEVIL_ADVOCATE_SYSTEM,
    EVAL_SCHEMA,
    DEVIL_SCHEMA,
    build_eval_prompt,
    build_devil_prompt,
)
from burto import budget as budget_tracker

load_dotenv()

_client: OpenAI | None = None


def _get_client() -> OpenAI:
    global _client
    if _client is None:
        _client = OpenAI(
            base_url="https://api.studio.nebius.com/v1/",
            api_key=os.environ["nebius_api_key"],
        )
    return _client


_MODEL = "Qwen/Qwen3-30B-A3B-Instruct-2507"
_BLOCK_CERTAINTY_THRESHOLD = 0.9


def _history_summary(session_id: str) -> str:
    entries = budget_tracker.get_history(session_id)
    if not entries:
        return "none"
    return "; ".join(
        f"{e.tool_name}({json.dumps(e.tool_input)[:60]}) → {e.decision}"
        for e in entries[-5:]
    )


def _call_llm(system: str, user: str, schema: dict) -> dict:
    response = _get_client().chat.completions.create(
        model=_MODEL,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        temperature=0,
        max_tokens=400,
        response_format=schema,
        extra_body={"thinking": {"type": "disabled"}},
    )
    return json.loads(response.choices[0].message.content)


def _build_escalation_context(
    ctx: SessionContext,
    tool_name: str,
    tool_input: str,
    reasoning: str,
    impact: str,
    devil_reasoning: str | None = None,
) -> str:
    intent_line = ctx.intent_summary[:60]
    source_tag = " [explicit]" if ctx.source == "explicit" else " [inferred]"
    lines = [
        "┌─ BURTO ────────────────────────────────────────────────────┐",
        f"│ Task context{source_tag}: {intent_line}",
        f"│ Proposed     : {tool_name}({tool_input[:48]})",
        f"│ Why flagged  : {reasoning[:60]}",
        f"│ Impact       : {impact[:60]}",
    ]
    if devil_reasoning:
        lines.append(f"│ Possible legit: {devil_reasoning[:58]}")
    lines.append("│ → Blocked. Modify your request to proceed differently.")
    lines.append("└────────────────────────────────────────────────────────────┘")
    return "\n".join(lines)


_SHELL_TOOLS = {"bash", "shell", "run_command", "execute", "exec", "terminal"}


def _heuristic_check(session_id: str, tool_name: str, tool_input: dict) -> ActionEvaluation | None:
    """Fast deterministic checks that don't need LLM or context.
    Only applied to shell/command tools — NOT to file reads/writes where
    the content would produce false positives.
    """
    is_shell = (
        tool_name.lower() in _SHELL_TOOLS
        or "command" in tool_input
        or "cmd" in tool_input
    )
    if not is_shell:
        return None

    # Only examine the command string, not arbitrary values
    cmd = str(tool_input.get("command", tool_input.get("cmd", ""))).lower()

    _NET = {"curl", "wget", "http://", "https://"}
    _ENV = {"$(env)", "${env}", "printenv", "process.env", "/etc/passwd", "/etc/shadow"}
    _INFRA = {"terraform ", "kubectl ", "aws ", "gcloud ", "az "}

    net_in_cmd = any(s in cmd for s in _NET)
    env_in_cmd = any(s in cmd for s in _ENV)
    infra_in_cmd = any(s in cmd for s in _INFRA)

    if net_in_cmd and env_in_cmd:
        return ActionEvaluation(
            decision=Decision.BLOCK,
            reasoning="Combines network call with environment/secret access — classic exfiltration pattern.",
            confidence=1.0,
            impact="Sends credentials or env vars to an external host.",
        )

    if infra_in_cmd:
        return ActionEvaluation(
            decision=Decision.ESCALATE,
            reasoning="Infrastructure command detected — requires confirmation regardless of task.",
            confidence=0.92,
            impact="Could modify or destroy cloud resources, cluster state, or deployment config.",
        )

    # Writing outside the project root
    fp = tool_input.get("file_path") or tool_input.get("path", "")
    if fp and os.path.isabs(fp):
        from burto import context_builder
        pass  # will be checked in evaluate() with ctx

    return None


def _extract_file_path(tool_input: dict) -> str | None:
    for key in ("file_path", "path", "filename"):
        if key in tool_input:
            return str(tool_input[key])
    return None


def evaluate(ctx: SessionContext, tool_name: str, tool_input: dict) -> ActionEvaluation:
    fp = _extract_file_path(tool_input)
    if fp:
        budget_tracker.record_file(ctx.session_id, fp)

    # Stage 0: heuristic fast-path
    fast = _heuristic_check(ctx.session_id, tool_name, tool_input)
    if fast:
        if fast.decision != Decision.ALLOW:
            fast.escalation_context = _build_escalation_context(
                ctx, tool_name, json.dumps(tool_input),
                fast.reasoning, fast.impact or "",
            )
        budget_tracker.record(ctx.session_id, BudgetEntry(
            tool_name=tool_name, tool_input=tool_input, decision=fast.decision
        ))
        return fast

    # Stage 1: LLM evaluation with full conversation + project context
    history = _history_summary(ctx.session_id)
    files = budget_tracker.get_files_touched(ctx.session_id)
    tool_input_str = json.dumps(tool_input)

    # Build conversation string from recent user turns
    conversation = "\n".join(
        f"[turn {i+1}] {t}" for i, t in enumerate(ctx.recent_user_turns[-6:])
    )

    try:
        user_prompt = build_eval_prompt(
            conversation=conversation,
            project_root=ctx.project_root,
            project_tree=ctx.project_tree,
            key_files=ctx.key_files,
            tool_name=tool_name,
            tool_input=tool_input_str,
            history_summary=history,
            files_touched=files,
        )
        data = _call_llm(INTENT_EVAL_SYSTEM, user_prompt, EVAL_SCHEMA)
        decision = Decision(data["decision"])
        reasoning = data["reasoning"]
        confidence = float(data["confidence"])
        impact = data.get("impact", "Unknown impact.")
        devil_reasoning: str | None = None

        # Stage 2: uncertain BLOCK → devil's advocate cross-check
        if decision == Decision.BLOCK and confidence < _BLOCK_CERTAINTY_THRESHOLD:
            devil_prompt = build_devil_prompt(
                conversation=conversation,
                tool_name=tool_name,
                tool_input=tool_input_str,
                history_summary=history,
            )
            devil = _call_llm(DEVIL_ADVOCATE_SYSTEM, devil_prompt, DEVIL_SCHEMA)
            devil_reasoning = devil.get("reasoning")
            if devil.get("legitimate"):
                decision = Decision.ESCALATE
                reasoning = f"{reasoning} | Devil's advocate: {devil_reasoning}"
                confidence = 0.5
            else:
                confidence = min(confidence + 0.08, 1.0)

        result = ActionEvaluation(
            decision=decision,
            reasoning=reasoning,
            confidence=confidence,
            impact=impact,
        )
        if decision != Decision.ALLOW:
            result.escalation_context = _build_escalation_context(
                ctx, tool_name, tool_input_str, reasoning, impact, devil_reasoning
            )

    except Exception as exc:
        result = ActionEvaluation(
            decision=Decision.ESCALATE,
            reasoning=f"Evaluator error — human review required. ({exc})",
            confidence=0.5,
            impact="Unknown — evaluator failed to assess.",
            escalation_context=_build_escalation_context(
                ctx, tool_name, json.dumps(tool_input),
                f"Evaluator error: {exc}", "Unknown.",
            ),
        )

    budget_tracker.record(ctx.session_id, BudgetEntry(
        tool_name=tool_name, tool_input=tool_input, decision=result.decision
    ))
    return result
