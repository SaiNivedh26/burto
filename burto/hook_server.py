"""
Burto hook server.

Accepts the full PreToolUse payload from cmdc / Claude Code / any coding agent.
Infers task intent from the live transcript — no explicit declaration needed.
"""
from __future__ import annotations
import datetime
import json
import os
import urllib.parse
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse, Response
from jinja2 import Environment, FileSystemLoader
from pydantic import BaseModel
from typing import Any

from burto import intent_registry, budget as budget_tracker
from burto import evaluator
from burto import context_builder
from burto import store
from burto.models import Decision, TaskIntent

load_dotenv()

app = FastAPI(title="burto")

_TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "templates")
_jinja = Environment(loader=FileSystemLoader(_TEMPLATES_DIR), autoescape=True)


def _ts_filter(ts: float) -> str:
    try:
        return datetime.datetime.fromtimestamp(ts).strftime("%m/%d %H:%M:%S")
    except Exception:
        return str(ts)


_jinja.filters["ts"] = _ts_filter
_jinja.filters["urlencode"] = urllib.parse.quote


def _render(template_name: str, **ctx) -> HTMLResponse:
    html = _jinja.get_template(template_name).render(**ctx)
    return HTMLResponse(content=html)
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
    threat_context: str | None = None  # Tavily research, set on BLOCK candidates
    trace_id: str | None = None        # LangSmith trace for this evaluation
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
        threat_context=result.threat_context,
        trace_id=result.trace_id,
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


class SignalPayload(BaseModel):
    signal_type: str  # accept | reject | edit | prompt
    reason: str = ""
    label: str | None = None          # ALLOW | BLOCK | ESCALATE
    reasoning_label: str | None = None
    edited_tool_input: dict[str, Any] | None = None  # for edit signal


@app.post("/decisions/{decision_id}/approve")
async def approve_decision(decision_id: str, reason: str = ""):
    """Developer approves a blocked decision. Auto-allows the same action for 60s."""
    d = store.get_decision(decision_id)
    if not d:
        return JSONResponse({"error": "decision not found"}, status_code=404)
    store.approve_decision(decision_id, reason)
    # Create accept training example
    store.record_signal(
        decision_id=decision_id, signal_type="accept",
        override="allowed", override_reason=reason or "developer approved",
        project_root=d.get("project_root"), tool_name=d.get("tool_name"),
        tool_input=json.loads(d["tool_input"]) if d.get("tool_input") else {},
        label="ALLOW", reasoning_label=reason or "developer approved",
    )
    return {"status": "approved", "decision_id": decision_id,
            "auto_allow_window_s": 60, "tool_input_hash": d.get("tool_input_hash")}


@app.post("/decisions/{decision_id}/reject")
async def reject_decision(decision_id: str, reason: str = ""):
    """Developer explicitly confirms a block (signal_type=reject)."""
    d = store.get_decision(decision_id)
    if not d:
        return JSONResponse({"error": "decision not found"}, status_code=404)
    store.record_signal(
        decision_id=decision_id, signal_type="reject",
        override="re_blocked", override_reason=reason or "developer confirmed block",
        project_root=d.get("project_root"), tool_name=d.get("tool_name"),
        tool_input=json.loads(d["tool_input"]) if d.get("tool_input") else {},
        label="BLOCK", reasoning_label=reason or "developer confirmed block",
    )
    return {"status": "rejected", "decision_id": decision_id}


@app.post("/decisions/{decision_id}/signal")
async def record_signal(decision_id: str, payload: SignalPayload):
    """Record any of the four learning signals: accept/reject/edit/prompt."""
    d = store.get_decision(decision_id)
    if not d:
        return JSONResponse({"error": "decision not found"}, status_code=404)
    store.record_signal(
        decision_id=decision_id,
        signal_type=payload.signal_type,
        override=None,
        override_reason=payload.reason or None,
        project_root=d.get("project_root"),
        tool_name=d.get("tool_name"),
        tool_input=payload.edited_tool_input or (json.loads(d["tool_input"]) if d.get("tool_input") else {}),
        label=payload.label or d.get("decision"),
        reasoning_label=payload.reasoning_label or payload.reason or None,
    )
    return {"status": "ok", "signal_type": payload.signal_type, "decision_id": decision_id}


@app.get("/health")
async def health():
    return {"status": "ok"}


# ── Dashboard routes ──────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def dashboard_index():
    sessions = store.get_sessions(limit=100)
    return _render("index.html", sessions=sessions, active="home")


@app.get("/sessions/{session_id}", response_class=HTMLResponse)
async def dashboard_session(session_id: str):
    session = store.get_session(session_id)
    if not session:
        return HTMLResponse("<h2>Session not found</h2>", status_code=404)
    decisions = store.get_decisions_for_session(session_id)
    return _render("session.html", session=session, decisions=decisions)


@app.get("/projects", response_class=HTMLResponse)
async def dashboard_projects():
    projects = store.get_projects()
    stats_map = {p["root"]: store.get_project_stats(p["root"]) for p in projects}
    return _render("projects.html", projects=projects, stats_map=stats_map, active="projects")


@app.get("/projects/{root:path}/policy")
async def get_project_policy(root: str):
    """Return parsed policy or a starter template if none exists."""
    from burto import policy as policy_loader
    root = urllib.parse.unquote(root).removesuffix("/policy")
    from pathlib import Path
    policy_path = Path(root) / ".burto" / "policy.yaml"
    if policy_path.exists():
        pol = policy_loader.load_policy(root)
        return {
            "exists": True, "risk_tier": pol.risk_tier,
            "model_active": pol.model_active, "rule_count": len(pol.rules),
            "deny_by_default": pol.deny_by_default,
        }
    else:
        template = policy_loader.generate_policy_yaml(root)
        return {"exists": False, "template": template}


@app.post("/projects/{root:path}/analyze")
async def trigger_project_analysis(root: str):
    """
    Write .burto/CLAUDE.md skill file into the project.
    The coding agent will read it, analyze the codebase itself, and write policy.yaml.
    No burto LLM calls — analysis is done by the agent on its next session.
    """
    from burto import analyzer
    from pathlib import Path
    root = urllib.parse.unquote(root).removesuffix("/analyze")
    with analyzer._lock:
        analyzer._analyzed.discard(root)
    skill_path = Path(root) / ".burto" / "CLAUDE.md"
    wrote = analyzer.maybe_write_skill(root)
    return {
        "status": "skill_written" if wrote else "policy_already_exists",
        "project_root": root,
        "skill_path": str(skill_path),
        "next_step": "Start a cmdc/CC session in this project — the agent will read .burto/CLAUDE.md and generate policy.yaml automatically.",
    }


@app.get("/projects/{root:path}/model")
async def get_project_model(root: str):
    root = urllib.parse.unquote(root).removesuffix("/model")
    model = store.get_project_model(root)
    return {"project_root": root, "active_model": model}


@app.post("/projects/{root:path}/model-update")
async def set_project_model_form(root: str, model: str = "super"):
    """Form POST handler for dashboard model hot-swap."""
    root = urllib.parse.unquote(root).removesuffix("/model-update")
    valid_tiers = {"nano", "super", "ultra"}
    if model in valid_tiers:
        store.update_project_model(root, model)
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url=f"/projects/{urllib.parse.quote(root, safe='')}", status_code=303)


@app.put("/projects/{root:path}/model")
async def set_project_model(root: str, model: str):
    """Hot-swap the model tier for a project without server restart."""
    root = urllib.parse.unquote(root).removesuffix("/model")
    valid_tiers = {"nano", "super", "ultra"}
    if model not in valid_tiers and not model.startswith("ft:"):
        return JSONResponse(
            {"error": f"model must be one of {sorted(valid_tiers)} or 'ft:<id>'"},
            status_code=400,
        )
    store.update_project_model(root, model)
    return {"status": "updated", "project_root": root, "active_model": model}


@app.get("/projects/{root:path}/train", response_class=HTMLResponse)
async def dashboard_train(root: str):
    """Fine-tune pipeline dashboard page for a project."""
    from burto import finetune
    root = urllib.parse.unquote(root).removesuffix("/train")
    project = store.get_project(root)
    ds = finetune.build_dataset(root)
    examples = store.get_training_examples(root, limit=10000)
    with store._read_conn() as conn:
        runs = [dict(r) for r in conn.execute(
            "SELECT * FROM ft_runs WHERE project_root=? ORDER BY started_at DESC LIMIT 10", (root,)
        ).fetchall()]
    return _render("train.html", project=project or {"root": root, "name": root.split("/")[-1]},
                   ds=ds, runs=runs, total_examples=len(examples))


@app.post("/projects/{root:path}/train/export")
async def export_dataset(root: str):
    from burto import finetune
    root = urllib.parse.unquote(root).removesuffix("/train/export")
    path, count = finetune.export_jsonl(root)
    return {"status": "ok", "path": path, "example_count": count}


@app.post("/projects/{root:path}/train/submit")
async def submit_train(root: str, base_model: str = "nvidia/Nemotron-3_5-Lightning",
                       epochs: int = 3, lora_rank: int = 16):
    from burto import finetune
    root = urllib.parse.unquote(root).removesuffix("/train/submit")
    ds = finetune.build_dataset(root)
    if ds.example_count < 10:
        return JSONResponse({"error": f"only {ds.example_count} examples — need at least 10"}, status_code=400)
    path, _ = finetune.export_jsonl(root)
    ds = finetune.push_to_nebius(root, path, ds)
    config = finetune.TrainConfig(
        project_root=root, dataset_id=ds.id, base_model=base_model,
        epochs=epochs, lora_rank=lora_rank,
    )
    config.estimated_cost_usd = finetune.estimate_cost(config, ds.example_count)
    run = finetune.submit_sft_job(config, ds)
    return {"status": "submitted", "run_id": run.run_id, "job_id": run.nebius_job_id,
            "estimated_cost_usd": config.estimated_cost_usd}


@app.get("/projects/{root:path}/train/runs/{run_id}")
async def get_run_status(root: str, run_id: str):
    from burto import finetune
    status = finetune.poll_job(run_id)
    return {"run_id": status.run_id, "status": status.status,
            "tokens_used": status.tokens_used, "error": status.error}


@app.post("/projects/{root:path}/train/deploy/{run_id}")
async def deploy_run(root: str, run_id: str):
    from burto import finetune
    result = finetune.deploy_endpoint(run_id)
    return {"status": result.status, "endpoint_id": result.endpoint_id,
            "endpoint_url": result.endpoint_url, "error": result.error}


@app.get("/projects/{root:path}", response_class=HTMLResponse)
async def dashboard_project(root: str):
    root = urllib.parse.unquote(root)
    project = store.get_project(root)
    if not project:
        return HTMLResponse("<h2>Project not found</h2>", status_code=404)
    stats = store.get_project_stats(root)
    return _render("project.html", project=project, stats=stats)


@app.get("/export", response_class=HTMLResponse)
async def dashboard_export():
    from collections import Counter
    projects = store.get_projects()
    all_decisions = store.export_decisions()
    counts = Counter(d["project_root"] for d in all_decisions)
    for p in projects:
        p["decision_count"] = counts.get(p["root"], 0)
    return _render("export.html", projects=projects, total=len(all_decisions), active="export")


@app.get("/export/json")
async def export_json(project: str | None = None):
    rows = store.export_decisions(project_root=project)
    return JSONResponse(content=rows)


@app.get("/export/jsonl")
async def export_jsonl(project: str | None = None):
    rows = store.export_decisions(project_root=project)
    body = "\n".join(json.dumps(r) for r in rows)
    return Response(content=body, media_type="application/x-ndjson",
                    headers={"Content-Disposition": "attachment; filename=decisions.jsonl"})
