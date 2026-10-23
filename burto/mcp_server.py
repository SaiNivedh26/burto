"""
Burto MCP server.

burto_start_task  — optional explicit intent override
burto_get_status  — show inferred/explicit intent + action history
burto_clear_session — reset session
"""
from __future__ import annotations
import os
import httpx
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP

from burto import intent_registry, budget as budget_tracker, context_builder
from burto.models import TaskIntent

load_dotenv()

HOOK_SERVER_URL = os.environ.get("BURTO_URL", "http://localhost:8000")
mcp = FastMCP("burto")


def _sync_to_hook_server(task: TaskIntent) -> None:
    try:
        httpx.post(
            f"{HOOK_SERVER_URL}/intent",
            json={"intent": task.intent, "allowed_scopes": task.allowed_scopes, "session_id": task.session_id},
            timeout=2.0,
        )
    except Exception:
        pass


@mcp.tool()
def burto_start_task(intent: str, session_id: str = "default", allowed_scopes: list[str] = []) -> str:
    """
    Optionally declare an explicit task intent for this session.
    Burto will use this instead of inferring from the conversation.
    Useful when you want precise control over what burto considers in-scope.

    Args:
        intent: What you're working on. e.g. "Refactor the auth module to use JWT"
        session_id: Session identifier (use "default" unless managing multiple sessions)
        allowed_scopes: Optional path hints. Leave empty — burto infers scope from the project.
    """
    task = TaskIntent(intent=intent, allowed_scopes=allowed_scopes, session_id=session_id)
    intent_registry.set_intent(task)
    context_builder.invalidate(session_id)
    _sync_to_hook_server(task)
    return (
        f"[burto] Explicit intent set.\n"
        f"Intent : {intent}\n"
        f"Session: {session_id}\n"
        f"Note   : burto will now use this instead of inferring from conversation."
    )


@mcp.tool()
def burto_get_status(session_id: str = "default") -> str:
    """Show current intent (inferred or explicit) and recent action history."""
    try:
        resp = httpx.get(f"{HOOK_SERVER_URL}/status/{session_id}", timeout=2.0)
        d = resp.json()
        if d.get("intent"):
            lines = [
                f"Intent ({d.get('intent_source', '?')}): {d['intent']}",
                f"Project: {d.get('project_root', '?')}",
                f"Recent conversation turns:",
            ]
            for t in d.get("recent_turns", []):
                lines.append(f"  • {t[:80]}")
            lines.append(f"Actions ({len(d.get('history', []))}):")
            for e in d.get("history", [])[-8:]:
                lines.append(f"  {e['tool']} → {e['decision']}")
            return "\n".join(lines)
    except Exception:
        pass

    ctx = context_builder._cache.get(session_id)
    if not ctx:
        return f"[burto] No active session '{session_id}'. Run a tool call first."
    history = budget_tracker.get_history(session_id)
    lines = [
        f"Intent ({ctx.source}): {ctx.intent_summary[:80]}",
        f"Project: {ctx.project_root}",
        f"Actions ({len(history)}):",
    ]
    for e in history[-8:]:
        lines.append(f"  {e.tool_name} → {e.decision}")
    return "\n".join(lines)


@mcp.tool()
def burto_clear_session(session_id: str = "default") -> str:
    """Clear explicit intent and action history for a session."""
    intent_registry.clear_intent(session_id)
    budget_tracker.clear(session_id)
    context_builder.invalidate(session_id)
    try:
        httpx.delete(f"{HOOK_SERVER_URL}/intent/{session_id}", timeout=2.0)
    except Exception:
        pass
    return f"[burto] Session '{session_id}' cleared."


if __name__ == "__main__":
    mcp.run()
