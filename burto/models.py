from __future__ import annotations
from enum import Enum
from typing import Any
from pydantic import BaseModel


class Decision(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    ESCALATE = "ESCALATE"


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


class ToolCall(BaseModel):
    tool_name: str
    tool_input: dict[str, Any]
    session_id: str


class BudgetEntry(BaseModel):
    tool_name: str
    tool_input: dict[str, Any]
    decision: Decision
