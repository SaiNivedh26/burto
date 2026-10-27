"""
LangSmith tracer for burto (issue #2).

One trace per evaluated tool call, grouped into a LangSmith *thread* per
burto session (metadata session_id), so a session reads like PLAN.md:

    session: <session_id>            (LangSmith Threads view)
      tool_call: Bash  -> BLOCK      (chain)  inputs: intent, action, args
      ├── heuristic_check            (chain)
      ├── intent_eval                (llm)    Nebius call
      ├── devil_advocate             (llm)    only for uncertain BLOCKs
      ├── threat_research            (tool)   Tavily, BLOCK/ESCALATE only
      └── decision                   (chain)  written by log_evaluation()

Interface contract (issue #2):
    def log_evaluation(intent: str, action: str, decision: str,
                       reasoning: str, span_id: str)

Plus helpers to build the tree:
    with trace_evaluation(intent, action, args) as root:   # root span
        with span("evaluator", run_type="llm") as s:       # child span
            ...
            s.set_outputs({...})
        log_evaluation(intent, action, "BLOCK", "why", root.id)

    @traced("evaluator", run_type="llm")    # decorator form
    def evaluate(...): ...

Backends
- LangSmith, when the 'langsmith' package is installed and an API key is set
  ('langsmith_api_key' as in CLAUDE.md, or LANGSMITH_API_KEY). Project:
  LANGSMITH_PROJECT (default "burto"). LANGSMITH_TRACING=false switches it off.
- Always also appends finished spans to a local JSONL file
  (TRACE_LOG_PATH, default ./traces/evaluations.jsonl) so the demo/dashboard
  works offline and you can 'python -m burto.tracer' to print recent trees.

Tracing never raises into the evaluator: every backend call is guarded.
"""

from __future__ import annotations

import contextvars
import functools
import inspect
import json
import logging
import os
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Callable, Iterator

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:  # pragma: no cover
    pass

# CLAUDE.md names the keys in lowercase; the LangSmith SDK reads uppercase.
if os.getenv("langsmith_api_key") and not os.getenv("LANGSMITH_API_KEY"):
    os.environ["LANGSMITH_API_KEY"] = os.environ["langsmith_api_key"]

log = logging.getLogger("burto.tracer")

PROJECT = os.getenv("LANGSMITH_PROJECT", "burto")
TRACE_LOG_PATH = os.getenv("TRACE_LOG_PATH", os.path.join("traces", "evaluations.jsonl"))


# --------------------------------------------------------------------------
# LangSmith backend (optional)
# --------------------------------------------------------------------------

def _langsmith_enabled() -> bool:
    if os.getenv("LANGSMITH_TRACING", os.getenv("LANGCHAIN_TRACING_V2", "true")).lower() in {"false", "0", "no"}:
        return False
    if not (os.getenv("LANGSMITH_API_KEY") or os.getenv("LANGCHAIN_API_KEY")):
        return False
    try:
        import langsmith  # noqa: F401
        return True
    except ImportError:
        return False


_client = None


def _ls_client():
    global _client
    if _client is None:
        from langsmith import Client
        _client = Client()
    return _client


def _safe(fn: Callable, *a, **kw):
    try:
        return fn(*a, **kw)
    except Exception as e:  # tracing must never break evaluation
        log.debug("tracer backend call failed: %s", e)
        return None


# --------------------------------------------------------------------------
# Span model
# --------------------------------------------------------------------------

_current: contextvars.ContextVar["Span | None"] = contextvars.ContextVar("current_span", default=None)
_registry: dict[str, "Span"] = {}
_registry_lock = threading.Lock()
_file_lock = threading.Lock()
_MAX_REGISTRY = 2000


def _jsonable(x: Any) -> Any:
    if hasattr(x, "to_dict"):
        try:
            return x.to_dict()
        except Exception:
            pass
    try:
        json.dumps(x)
        return x
    except TypeError:
        if isinstance(x, dict):
            return {str(k): _jsonable(v) for k, v in x.items()}
        if isinstance(x, (list, tuple, set)):
            return [_jsonable(v) for v in x]
        if hasattr(x, "__dict__"):
            return _jsonable(vars(x))
        return repr(x)


@dataclass
class Span:
    name: str
    run_type: str = "chain"
    inputs: dict = field(default_factory=dict)
    parent: "Span | None" = None
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    outputs: dict = field(default_factory=dict)
    metadata: dict = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    error: str | None = None
    start_time: float = field(default_factory=time.time)
    end_time: float | None = None
    children: list["Span"] = field(default_factory=list)
    _run: Any = None  # langsmith RunTree

    @property
    def trace_id(self) -> str:
        s = self
        while s.parent is not None:
            s = s.parent
        return s.id

    @property
    def duration_ms(self) -> int | None:
        return None if self.end_time is None else int((self.end_time - self.start_time) * 1000)

    # ---- mutation helpers -------------------------------------------------
    def set_outputs(self, outputs: dict | Any) -> "Span":
        self.outputs.update(outputs if isinstance(outputs, dict) else {"output": outputs})
        return self

    def add_metadata(self, **kw) -> "Span":
        self.metadata.update(kw)
        if self._run is not None:
            _safe(self._run.add_metadata, _jsonable(kw))
        return self

    def add_tags(self, *tags: str) -> "Span":
        new = [t for t in tags if t not in self.tags]
        self.tags.extend(new)
        if self._run is not None and new:
            _safe(self._run.add_tags, new)
        return self

    # ---- lifecycle --------------------------------------------------------
    def _start(self) -> None:
        if self.parent:
            self.parent.children.append(self)
        with _registry_lock:
            _registry[self.id] = self
            if len(_registry) > _MAX_REGISTRY:
                # drop oldest finished root traces
                for k in list(_registry)[: len(_registry) - _MAX_REGISTRY]:
                    if _registry[k].end_time is not None:
                        _registry.pop(k, None)
        if not _langsmith_enabled():
            return
        if self.parent is not None and self.parent._run is not None:
            run = _safe(self.parent._run.create_child, name=self.name, run_type=self.run_type,
                        inputs=_jsonable(self.inputs), run_id=uuid.UUID(self.id))
            if run is None:  # older SDKs without run_id kwarg
                run = _safe(self.parent._run.create_child, name=self.name,
                            run_type=self.run_type, inputs=_jsonable(self.inputs))
        else:
            from langsmith.run_trees import RunTree
            run = _safe(RunTree, id=uuid.UUID(self.id), name=self.name, run_type=self.run_type,
                        inputs=_jsonable(self.inputs), project_name=PROJECT,
                        tags=list(self.tags), extra={"metadata": _jsonable(self.metadata)})
        if run is not None:
            self._run = run
            self.id = str(run.id)  # keep ids in sync if the SDK chose its own
            with _registry_lock:
                _registry[self.id] = self
            _safe(run.post)

    def end(self, outputs: dict | None = None, error: str | None = None) -> None:
        if self.end_time is not None:
            return
        if outputs:
            self.set_outputs(outputs)
        if error:
            self.error = error
        self.end_time = time.time()
        if self._run is not None:
            _safe(self._run.end, outputs=_jsonable(self.outputs), error=self.error)
            _safe(self._run.patch)
        _write_local(self)

    def to_dict(self, recursive: bool = True) -> dict:
        d = {
            "id": self.id, "trace_id": self.trace_id,
            "parent_id": self.parent.id if self.parent else None,
            "name": self.name, "run_type": self.run_type,
            "inputs": _jsonable(self.inputs), "outputs": _jsonable(self.outputs),
            "metadata": _jsonable(self.metadata), "tags": self.tags,
            "error": self.error, "start_time": self.start_time,
            "end_time": self.end_time, "duration_ms": self.duration_ms,
        }
        if recursive:
            d["children"] = [c.to_dict() for c in self.children]
        return d

    def tree(self, indent: int = 0) -> str:
        bits = [f"{'  ' * indent}{'└─ ' if indent else ''}{self.name} ({self.run_type})"]
        if self.duration_ms is not None:
            bits[0] += f" {self.duration_ms}ms"
        if "decision" in self.outputs:
            bits[0] += f" -> {self.outputs['decision']}"
        if self.error:
            bits[0] += f" ERROR: {self.error}"
        for c in self.children:
            bits.append(c.tree(indent + 1))
        return "\n".join(bits)


def _write_local(s: Span) -> None:
    if os.getenv("TRACE_LOG_PATH", TRACE_LOG_PATH).lower() in {"", "off", "none"}:
        return
    path = os.getenv("TRACE_LOG_PATH", TRACE_LOG_PATH)
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        line = json.dumps(s.to_dict(recursive=False), default=str)
        with _file_lock, open(path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception as e:
        log.debug("local trace write failed: %s", e)


# --------------------------------------------------------------------------
# Public helpers
# --------------------------------------------------------------------------

def current_span() -> Span | None:
    return _current.get()


def get_span(span_id: str) -> Span | None:
    return _registry.get(span_id)


_USE_CURRENT = object()


@contextmanager
def span(name: str, run_type: str = "chain", inputs: dict | None = None,
         parent: "Span | str | None | object" = _USE_CURRENT, **metadata) -> Iterator[Span]:
    """Open a child span under 'parent' (default: the current span; None = new root)."""
    if parent is _USE_CURRENT:
        parent = _current.get()
    elif isinstance(parent, str):
        parent = get_span(parent)
    s = Span(name=name, run_type=run_type, inputs=inputs or {},
             parent=parent, metadata=metadata)
    s._start()
    token = _current.set(s)
    try:
        yield s
    except Exception as e:
        s.end(error=f"{type(e).__name__}: {e}")
        raise
    finally:
        _current.reset(token)
        s.end()


@contextmanager
def trace_evaluation(intent: str, action: str, args: dict | None = None,
                     session_id: str | None = None, **metadata) -> Iterator[Span]:
    """Root span for one evaluated tool call. Yields the span; '.id' is the span_id.

    session_id goes into metadata, which LangSmith uses to group the
    session's tool calls into one thread.
    """
    if session_id:
        metadata.setdefault("session_id", session_id)
    with span(f"tool_call: {action}", run_type="chain",
              inputs={"intent": intent, "action": action, "args": args or {}},
              parent=None, **metadata) as root:
        yield root


def traced(name: str | None = None, run_type: str = "chain"):
    """Decorator: run the function inside a child span of the current span."""
    def deco(fn):
        span_name = name or fn.__name__
        sig = inspect.signature(fn)

        def _inputs(a, kw):
            try:
                b = sig.bind_partial(*a, **kw)
                return {k: v for k, v in b.arguments.items() if k not in {"self", "cls"}}
            except TypeError:
                return {"args": a, "kwargs": kw}

        if inspect.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def awrapper(*a, **kw):
                with span(span_name, run_type=run_type, inputs=_inputs(a, kw)) as s:
                    out = await fn(*a, **kw)
                    s.set_outputs(out)
                    return out
            return awrapper

        @functools.wraps(fn)
        def wrapper(*a, **kw):
            with span(span_name, run_type=run_type, inputs=_inputs(a, kw)) as s:
                out = fn(*a, **kw)
                s.set_outputs(out)
                return out
        return wrapper
    return deco


def log_evaluation(intent: str, action: str, decision: str, reasoning: str, span_id: str) -> str:
    """Record the evaluator's final decision on the trace identified by span_id.

    - Adds a 'decision' child span under span_id with the decision + reasoning.
    - Copies decision/reasoning onto the parent span's outputs and tags it
      'decision:<DECISION>' so you can filter BLOCKs in LangSmith.
    - Sends LangSmith feedback (key "decision") for the dashboard.
    If span_id is unknown (e.g. evaluator made its own id), a standalone
    trace is created and tagged with that external id.
    Returns the id of the decision span. Never raises.
    """
    try:
        decision = (decision or "UNKNOWN").upper()
        parent = get_span(span_id) if span_id else None
        if parent is None:
            with trace_evaluation(intent, action, external_span_id=span_id) as parent:
                return _log_on(parent, intent, action, decision, reasoning)
        return _log_on(parent, intent, action, decision, reasoning)
    except Exception as e:  # pragma: no cover - defensive
        log.debug("log_evaluation failed: %s", e)
        return ""


def _log_on(parent: Span, intent: str, action: str, decision: str, reasoning: str) -> str:
    with span("decision", run_type="chain", parent=parent,
              inputs={"intent": intent, "action": action}) as d:
        d.set_outputs({"decision": decision, "reasoning": reasoning})
        d.add_tags(f"decision:{decision}")
    parent.set_outputs({"decision": decision, "reasoning": reasoning})
    parent.add_tags(f"decision:{decision}")
    parent.add_metadata(decision=decision)
    if parent._run is not None:
        root = parent
        while root.parent is not None:
            root = root.parent
        _safe(lambda: _ls_client().create_feedback(
            run_id=uuid.UUID(root.id), key="decision", value=decision,
            score=0.0 if decision == "BLOCK" else 1.0, comment=(reasoning or "")[:2000]))
    return d.id


def read_local_traces(path: str | None = None, limit: int = 50) -> list[dict]:
    """Rebuild recent trace trees from the local JSONL log (for dashboards)."""
    path = path or os.getenv("TRACE_LOG_PATH", TRACE_LOG_PATH)
    if not os.path.exists(path):
        return []
    rows = [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]
    by_id = {r["id"]: {**r, "children": []} for r in rows}
    roots = []
    for r in by_id.values():
        p = by_id.get(r["parent_id"]) if r["parent_id"] else None
        (p["children"] if p else roots).append(r)
    for r in by_id.values():
        r["children"].sort(key=lambda c: c["start_time"])
    roots.sort(key=lambda r: r["start_time"], reverse=True)
    return roots[:limit]


if __name__ == "__main__":
    def _show(n: dict, i: int = 0):
        dec = n.get("outputs", {}).get("decision")
        print(f"{'  ' * i}{'└─ ' if i else ''}{n['name']} ({n['run_type']}) "
              f"{n.get('duration_ms')}ms{' -> ' + dec if dec else ''}")
        for c in n["children"]:
            _show(c, i + 1)
    for t in read_local_traces(limit=10):
        _show(t)
        print()
