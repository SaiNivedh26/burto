from __future__ import annotations
from burto.models import TaskIntent

# In-memory store: session_id → TaskIntent
_registry: dict[str, TaskIntent] = {}


def set_intent(intent: TaskIntent) -> None:
    _registry[intent.session_id] = intent


def get_intent(session_id: str) -> TaskIntent | None:
    return _registry.get(session_id)


def clear_intent(session_id: str) -> None:
    _registry.pop(session_id, None)
