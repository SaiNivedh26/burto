from __future__ import annotations
from enum import Enum
from typing import Any
from pydantic import BaseModel


class Decision(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    ESCALATE = "ESCALATE"
    STEER = "STEER"  # hallucination caught — deny + inject correction


class TaskIntent(BaseModel):
    intent: str
    allowed_scopes: list[str] = []
    session_id: str


class ActionEvaluation(BaseModel):
    decision: Decision
    reasoning: str          # why this decision was made
    confidence: float
    impact: str | None = None           # what the command could actually do if run
    escalation_context: str | None = None  # structured context block shown to dev on ESCALATE
    threat_context: str | None = None   # Tavily threat intel (P1)
    trace_id: str | None = None         # LangSmith trace for this evaluation (P1)
    # STEER fields — populated only when decision == STEER
    hallucination_type: str | None = None   # file_not_found | pkg_not_found | flag_not_found | context_drift
    correction: str | None = None           # grounded correction text injected into agent context
    suggested_value: str | None = None      # the closest real match (file path, package name, etc.)


class ToolCall(BaseModel):
    tool_name: str
    tool_input: dict[str, Any]
    session_id: str


class BudgetEntry(BaseModel):
    tool_name: str
    tool_input: dict[str, Any]
    decision: Decision
