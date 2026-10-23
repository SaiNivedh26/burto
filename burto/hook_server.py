"""
Burto hook server.

Accepts the full PreToolUse payload from cmdc / Claude Code / any coding agent.
Infers task intent from the live transcript — no explicit declaration needed.
"""
from __future__ import annotations
import os
from dotenv import load_dotenv
from fastapi import FastAPI
from pydantic import BaseModel
from typing import Any

from burto import intent_registry, budget as budget_tracker
from burto import evaluator
from burto import context_builder
from burto.models import Decision, TaskIntent

load_dotenv()

app = FastAPI(title="burto")
DEFAULT_SESSION = "default"


# ── Payload models ────────────────────────────────────────────────────────────

class HookPayload(BaseModel):
    # Core (all agents)
    session_id: str = DEFAULT_SESSION
    tool_name: str
    tool_input: dict[str, Any] = {}
    # Context (cmdc + Claude Code send these)
    transcript_path: str | None = None
    cwd: str = "."
    # cmdc-specific extras (ignored but accepted)
    hook_event_name: str | None = None
    permission_mode: str | None = None
    tool_use_id: str | None = None
    tool_display_name: str | None = None


class HookResponse(BaseModel):
    decision: str
    reasoning: str
    confidence: float
    impact: str | None = None
    escalation_context: str | None = None
    intent_source: str = "inferred"   # "inferred" | "explicit"
    action: str                        # "proceed" | "block"


class IntentPayload(BaseModel):
    """Optional explicit override — agents don't need to call this."""
    intent: str
    allowed_scopes: list[str] = []
    session_id: str = DEFAULT_SESSION


# ── Routes ────────────────────────────────────────────────────────────────────

@app.post("/hook/pretooluse", response_model=HookResponse)
async def pretooluse(payload: HookPayload):
    # Check for explicit intent override (set via MCP tool or /intent endpoint)
    explicit = intent_registry.get_intent(payload.session_id)
    if explicit is None:
        explicit = intent_registry.get_intent(DEFAULT_SESSION)

    ctx = context_builder.get_or_build(
        session_id=payload.session_id,
        transcript_path=payload.transcript_path,
        cwd=payload.cwd if payload.cwd != "." else os.getcwd(),
        explicit_intent=explicit.intent if explicit else None,
        explicit_scopes=explicit.allowed_scopes if explicit else None,
    )

    result = evaluator.evaluate(ctx, payload.tool_name, payload.tool_input)
    action = "proceed" if result.decision == Decision.ALLOW else "block"

    return HookResponse(
        decision=result.decision,
        reasoning=result.reasoning,
        confidence=result.confidence,
        impact=result.impact,
        escalation_context=result.escalation_context,
        intent_source=ctx.source,
        action=action,
    )


@app.post("/intent")
async def set_intent(payload: IntentPayload):
    """Explicit intent override (optional — useful for demos or precise control)."""
    task = TaskIntent(
        intent=payload.intent,
        allowed_scopes=payload.allowed_scopes,
        session_id=payload.session_id,
    )
    intent_registry.set_intent(task)
    # Invalidate context cache so it rebuilds with the explicit intent
    context_builder.invalidate(payload.session_id)
    return {"status": "ok", "session_id": payload.session_id}


@app.delete("/intent/{session_id}")
async def clear_intent(session_id: str):
    intent_registry.clear_intent(session_id)
    budget_tracker.clear(session_id)
    context_builder.invalidate(session_id)
    return {"status": "cleared"}


@app.get("/status/{session_id}")
async def get_status(session_id: str):
    ctx = context_builder._cache.get(session_id)
    history = budget_tracker.get_history(session_id)
    return {
        "session_id": session_id,
        "intent": ctx.intent_summary if ctx else None,
        "intent_source": ctx.source if ctx else None,
        "project_root": ctx.project_root if ctx else None,
        "recent_turns": ctx.recent_user_turns[-3:] if ctx else [],
        "history": [{"tool": e.tool_name, "decision": e.decision} for e in history],
    }


@app.get("/health")
async def health():
    return {"status": "ok"}
