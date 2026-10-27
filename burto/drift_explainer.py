"""
Burto — Drift Explainer.

When Tier 1 rules detect drift, this module calls Nebius to write a personalized
2-sentence explanation:
  (1) WHY the agent is specifically failing (referencing actual tool outputs)
  (2) The exact next step to get back on goal

This explanation replaces the generic template message and is injected into the
agent's reasoning context via PostToolUse additionalContext.

Model: Qwen/Qwen3-30B-A3B-Instruct-2507 (fast, ~1.5s, precise)
Fallback: template string if Nebius is unavailable or times out.
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import TYPE_CHECKING

log = logging.getLogger("burto.explainer")

_NEBIUS_MODEL = "Qwen/Qwen3-30B-A3B-Instruct-2507"
_NEBIUS_BASE  = "https://api.studio.nebius.com/v1"
_EXPLAIN_TIMEOUT = 8.0  # seconds — hook has 15s total

_SYSTEM_PROMPT = """\
You are Burto, a drift guard embedded in an AI coding agent session.
When the agent deviates from its stated goal, you write a precise 2-sentence injection:
  Sentence 1: What specific mistake the agent is making right now (reference actual tool names and error messages).
  Sentence 2: The exact concrete next action to take to get back on goal.

Output ONLY the 2 sentences. No preamble, no bullet points, no explanation of your reasoning.\
"""

_RULE_CONTEXT = {
    "failure_spiral":   "the agent is stuck in a failure spiral — same approach keeps failing",
    "repetition_loop":  "the agent is repeating the exact same action without progress",
    "tool_cycling":     "the agent is ping-ponging between tools without making a concrete change",
    "silence_drift":    "the agent has been running many iterations without producing any output",
}


def _build_user_message(
    goal: str,
    recent_history: list,
    rule: str,
    rule_details: dict,
) -> str:
    goal_str = (goal or "(no goal recorded)")[:300]

    # Format recent tool calls with success/failure marker
    history_lines: list[str] = []
    for r in recent_history[-8:]:
        marker = "✓" if r.success else "✗"
        input_snippet = getattr(r, "input_text", "")[:100]
        resp_snippet  = getattr(r, "response_text", "")[:180]
        history_lines.append(
            f"  {marker} {r.tool_name}({input_snippet})"
            + (f" → {resp_snippet}" if resp_snippet else "")
        )

    history_str = "\n".join(history_lines) or "  (no tool calls recorded)"

    # Describe what was detected
    rule_ctx = _RULE_CONTEXT.get(rule, rule)
    details_str = ""
    if "consecutive_failures" in rule_details:
        details_str = f"{rule_details['consecutive_failures']} consecutive failures"
    elif "count" in rule_details:
        details_str = f"same action attempted {rule_details['count']} times"
    elif "tools" in rule_details:
        details_str = f"oscillating between {rule_details['tools']}"
    elif "iterations_since_communication" in rule_details:
        details_str = f"{rule_details['iterations_since_communication']} iterations without output"

    return (
        f"GOAL: {goal_str}\n\n"
        f"RECENT TOOL CALLS (last {len(history_lines)}):\n{history_str}\n\n"
        f"DETECTED DRIFT: {rule_ctx}"
        + (f" — {details_str}" if details_str else "")
    )


async def explain_drift(
    goal: str,
    recent_history: list,
    rule: str,
    rule_details: dict,
) -> str | None:
    """
    Call Nebius to write a personalized explanation of why the agent is drifting.
    Returns the explanation string, or None if unavailable.
    """
    nebius_key = os.environ.get("nebius_api_key", "")
    if not nebius_key:
        return None

    try:
        from openai import AsyncOpenAI
        client = AsyncOpenAI(api_key=nebius_key, base_url=_NEBIUS_BASE)

        user_msg = _build_user_message(goal, recent_history, rule, rule_details)
        log.debug("drift explain prompt len=%d rule=%s", len(user_msg), rule)

        t0 = time.time()
        response = await asyncio.wait_for(
            client.chat.completions.create(
                model=_NEBIUS_MODEL,
                messages=[
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user",   "content": user_msg},
                ],
                max_tokens=150,
                temperature=0.15,
            ),
            timeout=_EXPLAIN_TIMEOUT,
        )
        elapsed = time.time() - t0
        explanation = response.choices[0].message.content.strip()
        log.info("drift explain ok rule=%s model=%s elapsed=%.2fs chars=%d",
                 rule, _NEBIUS_MODEL, elapsed, len(explanation))
        return explanation

    except asyncio.TimeoutError:
        log.warning("drift explain timed out (>%.1fs) rule=%s", _EXPLAIN_TIMEOUT, rule)
        return None
    except Exception as e:
        log.warning("drift explain failed rule=%s err=%s", rule, e)
        return None
