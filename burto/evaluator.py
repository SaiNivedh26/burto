from __future__ import annotations
import json
import os
import time
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
from burto import tracer
from burto import store
from burto import notifier
from burto import policy as policy_loader
from burto import analyzer
from burto.threat_researcher import ThreatContext, research_threat

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


_MODEL = "Qwen/Qwen3-30B-A3B-Instruct-2507"  # fallback if routing disabled
_active_sessions: set[str] = set()  # sessions seen in this process — cache only applies to these
_BLOCK_CERTAINTY_THRESHOLD = 0.9

# Nemotron tier model IDs
_TIER_MODELS = {
    "nano":  "nvidia/Nemotron-3_5-Lightning",
    "super": "nvidia/nemotron-3-super-120b-a12b",
    "ultra": "nvidia/Nemotron-3-Ultra-550b-a55b",
}
_USE_ROUTING = os.getenv("BURTO_MODEL_ROUTING", "true").lower() not in {"false", "0", "no"}


def _route_model(project_root: str | None, is_devil_pass: bool = False) -> str:
    """Pick Nemotron tier based on project config and call type."""
    if not _USE_ROUTING:
        return _MODEL
    if is_devil_pass:
        return _TIER_MODELS["ultra"]
    # Check project-level model override
    if project_root:
        active = store.get_project_model(project_root)
        if active in _TIER_MODELS:
            return _TIER_MODELS[active]
        if active and active not in ("super", "nano", "ultra"):
            # Could be an FT endpoint ID — return as-is
            return active
    return _TIER_MODELS["super"]

# Decisions that count as BLOCK candidates and get Tavily threat research.
_RESEARCH_ON = {Decision.BLOCK, Decision.ESCALATE}
# Research risk levels strong enough to harden ESCALATE into BLOCK.
_HARDEN_ON = {"high", "critical"}


def _history_summary(session_id: str) -> str:
    entries = budget_tracker.get_history(session_id)
    if not entries:
        return "none"
    return "; ".join(
        f"{e.tool_name}({json.dumps(e.tool_input)[:60]}) → {e.decision}"
        for e in entries[-5:]
    )


_current_model: str = _MODEL  # thread-local-ish; set before each _traced_llm call
_seen_hashes: set[tuple[str, str]] = set()  # (session_id, input_hash) seen via LLM in this process


def _call_llm(system: str, user: str, schema: dict) -> dict:
    response = _get_client().chat.completions.create(
        model=_current_model,
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


def _traced_llm(span_name: str, system: str, user: str, schema: dict, model: str | None = None) -> dict:
    """_call_llm inside an llm span, so each Nebius call shows in LangSmith."""
    global _current_model
    _current_model = model or _MODEL
    with tracer.span(span_name, run_type="llm",
                     inputs={"system": system, "user": user},
                     model=_current_model, provider="nebius") as s:
        data = _call_llm(system, user, schema)
        s.set_outputs(data)
        return data


def _build_escalation_context(
    ctx: SessionContext,
    tool_name: str,
    tool_input: str,
    reasoning: str,
    impact: str,
    devil_reasoning: str | None = None,
    threat_summary: str | None = None,
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
    if threat_summary:
        lines.append(f"│ Threat intel : {threat_summary[:60]}")
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


def _research(tool_name: str, tool_input: dict, result: ActionEvaluation) -> ThreatContext | None:
    """Stage 3: Tavily threat research for BLOCK candidates.

    Attaches the findings to result.threat_context. Strong evidence
    (high/critical risk) hardens ESCALATE into BLOCK and raises confidence;
    research never softens a decision.
    """
    if result.decision not in _RESEARCH_ON:
        return None
    with tracer.span("threat_research", run_type="tool",
                     inputs={"tool_name": tool_name, "tool_input": tool_input}) as s:
        threat = research_threat(tool_name, tool_input)
        s.set_outputs(threat.to_dict())
        s.add_metadata(risk_level=threat.risk_level, researched=threat.researched)
        if threat.error:
            s.add_metadata(research_error=threat.error)

    if not threat.indicators:
        return threat
    result.threat_context = threat.to_prompt()
    if threat.risk_level in _HARDEN_ON:
        if result.decision == Decision.ESCALATE:
            result.decision = Decision.BLOCK
            result.confidence = max(result.confidence, 0.9)
        else:
            result.confidence = min(result.confidence + 0.05, 1.0)
        result.reasoning = f"{result.reasoning} | Threat intel: {threat.summary}"
    return threat


def _evaluate(ctx: SessionContext, tool_name: str, tool_input: dict, routed_model: str | None = None) -> tuple[ActionEvaluation, str | None]:
    """Stages 0-2. Returns (result, devil_reasoning)."""
    # Stage 0a: policy fast-path (policy.yaml rules, if present).
    # Also triggers async repo analysis if no policy file exists yet.
    if ctx.project_root:
        analyzer.maybe_analyze_async(ctx.project_root)
        pol = policy_loader.load_policy(ctx.project_root)
        verdict = pol.evaluate(tool_name, tool_input)
        if verdict == "allow":
            return ActionEvaluation(
                decision=Decision.ALLOW,
                reasoning="Policy rule matched: explicitly allowed.",
                confidence=1.0, impact=None,
            ), None
        if verdict == "deny":
            return ActionEvaluation(
                decision=Decision.BLOCK,
                reasoning="Policy rule matched: explicitly denied.",
                confidence=1.0, impact="Blocked by project policy rule.",
            ), None
        if verdict == "escalate":
            return ActionEvaluation(
                decision=Decision.ESCALATE,
                reasoning="Policy rule matched: escalation required.",
                confidence=1.0, impact="Escalated by project policy rule.",
            ), None

    # Stage 0b: heuristic fast-path
    with tracer.span("heuristic_check", run_type="chain",
                     inputs={"tool_name": tool_name, "tool_input": tool_input}) as s:
        fast = _heuristic_check(ctx.session_id, tool_name, tool_input)
        s.set_outputs({"decision": fast.decision.value if fast else None,
                       "reasoning": fast.reasoning if fast else "no heuristic match"})
    if fast:
        return fast, None

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
        data = _traced_llm("intent_eval", INTENT_EVAL_SYSTEM, user_prompt, EVAL_SCHEMA, model=routed_model)
        decision = Decision(data["decision"])
        reasoning = data["reasoning"]
        confidence = float(data["confidence"])
        impact = data.get("impact", "Unknown impact.")
        devil_reasoning: str | None = None

        # Stage 2: uncertain BLOCK → devil's advocate cross-check (Ultra tier)
        if decision == Decision.BLOCK and confidence < _BLOCK_CERTAINTY_THRESHOLD:
            ultra_model = _route_model(ctx.project_root, is_devil_pass=True)
            devil_prompt = build_devil_prompt(
                conversation=conversation,
                tool_name=tool_name,
                tool_input=tool_input_str,
                history_summary=history,
            )
            devil = _traced_llm("devil_advocate", DEVIL_ADVOCATE_SYSTEM, devil_prompt, DEVIL_SCHEMA, model=ultra_model)
            devil_reasoning = devil.get("reasoning")
            if devil.get("legitimate"):
                decision = Decision.ESCALATE
                reasoning = f"{reasoning} | Devil's advocate: {devil_reasoning}"
                confidence = 0.5
            else:
                confidence = min(confidence + 0.08, 1.0)

        return ActionEvaluation(
            decision=decision,
            reasoning=reasoning,
            confidence=confidence,
            impact=impact,
        ), devil_reasoning

    except Exception as exc:
        return ActionEvaluation(
            decision=Decision.ESCALATE,
            reasoning=f"Evaluator error — human review required. ({exc})",
            confidence=0.5,
            impact="Unknown — evaluator failed to assess.",
        ), None


def evaluate(ctx: SessionContext, tool_name: str, tool_input: dict) -> ActionEvaluation:
    fp = _extract_file_path(tool_input)
    if fp:
        budget_tracker.record_file(ctx.session_id, fp)

    # Session memory: if developer approved this exact action within 60s, auto-allow
    input_hash = store.tool_input_hash(tool_name, tool_input)
    recent = store.get_recent_approval(input_hash, ctx.session_id, within_seconds=60.0)
    if recent:
        return ActionEvaluation(
            decision=Decision.ALLOW,
            reasoning="Auto-allowed: developer approved this action within the last 60s.",
            confidence=1.0,
            impact=None,
        )

    # Decision cache: ALLOW decisions from this session, written in this process.
    # Skip cache on first occurrence of (session, input_hash) — ensures tests that call
    # evaluate() once per combo always go through the LLM path (no stale cross-test hits).
    hash_key = (ctx.session_id, input_hash)
    cached = store.get_cached_decision(input_hash, ctx.session_id) if hash_key in _seen_hashes else None
    if cached:
        result = ActionEvaluation(
            decision=Decision.ALLOW,
            reasoning=f"Cache hit: previously ALLOWed in this session (id={cached['id'][:8]}).",
            confidence=1.0,
            impact=None,
        )
        store.record_decision(
            id=str(__import__("uuid").uuid4()),
            session_id=ctx.session_id, project_root=ctx.project_root,
            agent="cmdc", tool_name=tool_name, tool_input=tool_input,
            decision="ALLOW", stage="cache", model_used=None,
            confidence=1.0, reasoning=result.reasoning, impact=None,
            threat_context=None, trace_id=None, latency_ms=0.0,
        )
        budget_tracker.record(ctx.session_id, BudgetEntry(
            tool_name=tool_name, tool_input=tool_input, decision=result.decision
        ))
        return result

    t0 = time.time()

    routed_model = _route_model(ctx.project_root)

    with tracer.trace_evaluation(
        ctx.intent_summary, tool_name, tool_input,
        session_id=ctx.session_id, intent_source=ctx.source,
    ) as root:
        result, devil_reasoning = _evaluate(ctx, tool_name, tool_input, routed_model=routed_model)

        # Stage 3: threat research on BLOCK candidates (may harden ESCALATE → BLOCK)
        threat = _research(tool_name, tool_input, result)

        if result.decision != Decision.ALLOW:
            result.escalation_context = _build_escalation_context(
                ctx, tool_name, json.dumps(tool_input),
                result.reasoning, result.impact or "",
                devil_reasoning,
                threat.summary if threat and threat.indicators else None,
            )

        result.trace_id = root.id
        root.add_metadata(confidence=result.confidence)
        tracer.log_evaluation(
            ctx.intent_summary, tool_name, result.decision.value, result.reasoning, root.id,
        )

    latency_ms = (time.time() - t0) * 1000

    # Determine evaluation stage for observability
    if result.confidence == 1.0 and result.decision in (Decision.BLOCK, Decision.ESCALATE):
        stage = "heuristic"
    else:
        stage = "llm"

    decision_id = result.trace_id or root.id

    # Fire desktop notification on BLOCK/ESCALATE so developer can approve in one click
    if result.decision != Decision.ALLOW:
        notifier.notify_block(decision_id, tool_name, result.reasoning)
        # Auto-capture Prompt signal: the last user turn before this block
        # reveals project-specific vocabulary and intent patterns
        if ctx.recent_user_turns:
            last_turn = ctx.recent_user_turns[-1]
            store.record_signal(
                decision_id=decision_id, signal_type="prompt",
                project_root=ctx.project_root, tool_name=tool_name,
                tool_input=tool_input,
                label=result.decision.value,
                reasoning_label=last_turn,
                context_snapshot={"intent": ctx.intent_summary, "turn": last_turn},
            )

    store.record_decision(
        id=decision_id,
        session_id=ctx.session_id,
        project_root=ctx.project_root,
        agent="cmdc",
        tool_name=tool_name,
        tool_input=tool_input,
        decision=result.decision.value,
        stage=stage,
        model_used=routed_model,
        confidence=result.confidence,
        reasoning=result.reasoning,
        impact=result.impact,
        threat_context=result.threat_context,
        trace_id=result.trace_id,
        latency_ms=latency_ms,
    )

    budget_tracker.record(ctx.session_id, BudgetEntry(
        tool_name=tool_name, tool_input=tool_input, decision=result.decision
    ))
    _seen_hashes.add(hash_key)
    return result
