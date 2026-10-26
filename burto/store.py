"""
Burto SQLite decision store — Phase 2A.

Persists every evaluation to a local SQLite database.
All writes are fire-and-forget on a background thread so the hot path is never blocked.

DB location: BURTO_DB_PATH env var, default ~/.burto/burto.db
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import queue
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

log = logging.getLogger("burto.store")

# ---------------------------------------------------------------------------
# DB path
# ---------------------------------------------------------------------------

def _db_path() -> Path:
    p = os.getenv("BURTO_DB_PATH")
    if p:
        return Path(p)
    default = Path.home() / ".burto" / "burto.db"
    default.parent.mkdir(parents=True, exist_ok=True)
    return default


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS decisions (
    id                  TEXT PRIMARY KEY,
    ts                  REAL NOT NULL,
    session_id          TEXT NOT NULL,
    project_root        TEXT,
    agent               TEXT,
    tool_name           TEXT NOT NULL,
    tool_input          TEXT,
    tool_input_hash     TEXT,
    decision            TEXT NOT NULL,
    stage               TEXT,
    model_used          TEXT,
    confidence          REAL,
    reasoning           TEXT,
    impact              TEXT,
    threat_context      TEXT,
    trace_id            TEXT,
    latency_ms          REAL,
    prompt_tokens       INTEGER,
    completion_tokens   INTEGER,
    cost_usd            REAL,
    signal_type         TEXT,
    override            TEXT,
    override_reason     TEXT,
    override_at         REAL
);

CREATE TABLE IF NOT EXISTS sessions (
    id              TEXT PRIMARY KEY,
    project_root    TEXT,
    agent           TEXT,
    started_at      REAL,
    ended_at        REAL,
    intent_summary  TEXT,
    user_turn_count INTEGER DEFAULT 0,
    action_count    INTEGER DEFAULT 0,
    blocked_count   INTEGER DEFAULT 0,
    override_count  INTEGER DEFAULT 0,
    active_model    TEXT DEFAULT 'super'
);

CREATE TABLE IF NOT EXISTS projects (
    root            TEXT PRIMARY KEY,
    name            TEXT,
    first_seen      REAL,
    last_active     REAL,
    session_count   INTEGER DEFAULT 0,
    policy_file_path TEXT,
    risk_tier       TEXT DEFAULT 'standard',
    active_model    TEXT DEFAULT 'super',
    ft_model_id     TEXT,
    ft_training_runs INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS learned_patterns (
    id                  TEXT PRIMARY KEY,
    project_root        TEXT NOT NULL,
    pattern_signature   TEXT NOT NULL,
    pattern_desc        TEXT,
    evidence_decision_ids TEXT,
    confidence          REAL,
    action              TEXT,
    created_at          REAL,
    source              TEXT
);

CREATE TABLE IF NOT EXISTS training_examples (
    id              TEXT PRIMARY KEY,
    project_root    TEXT,
    created_at      REAL,
    signal_type     TEXT,
    context_snapshot TEXT,
    tool_name       TEXT,
    tool_input      TEXT,
    label           TEXT,
    reasoning_label TEXT,
    used_in_ft_run  TEXT
);

CREATE TABLE IF NOT EXISTS datasets (
    id                      TEXT PRIMARY KEY,
    project_root            TEXT,
    created_at              REAL,
    example_count           INTEGER,
    class_distribution_json TEXT,
    signal_mix_json         TEXT,
    nebius_dataset_id       TEXT,
    nebius_storage_uri      TEXT,
    version_label           TEXT
);

CREATE TABLE IF NOT EXISTS ft_runs (
    id                  TEXT PRIMARY KEY,
    project_root        TEXT,
    dataset_id          TEXT,
    started_at          REAL,
    finished_at         REAL,
    base_model          TEXT,
    lora_rank           INTEGER,
    lora_alpha          REAL,
    epochs              INTEGER,
    lr                  REAL,
    batch_size          INTEGER,
    status              TEXT,
    nebius_job_id       TEXT,
    loss_curve_json     TEXT,
    tokens_used         INTEGER,
    cost_usd            REAL,
    endpoint_id         TEXT,
    endpoint_url        TEXT,
    eval_metrics_json   TEXT
);

CREATE INDEX IF NOT EXISTS decisions_session ON decisions(session_id);
CREATE INDEX IF NOT EXISTS decisions_project ON decisions(project_root);
CREATE INDEX IF NOT EXISTS decisions_ts ON decisions(ts);
CREATE INDEX IF NOT EXISTS decisions_decision ON decisions(decision);
CREATE INDEX IF NOT EXISTS training_examples_project ON training_examples(project_root);
"""


# ---------------------------------------------------------------------------
# Background writer
# ---------------------------------------------------------------------------

@dataclass
class _WriteOp:
    sql: str
    params: tuple


_write_queue: queue.Queue[_WriteOp | None] = queue.Queue()
_worker_started = False
_worker_lock = threading.Lock()


def _writer_loop(db_path: Path) -> None:
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.executescript(_SCHEMA)
    conn.commit()
    while True:
        op = _write_queue.get()
        if op is None:  # sentinel — stop
            break
        try:
            conn.execute(op.sql, op.params)
            conn.commit()
        except Exception as e:
            log.warning("store write error: %s | sql=%s", e, op.sql[:80])
    conn.close()


def _ensure_writer() -> None:
    global _worker_started
    with _worker_lock:
        if _worker_started:
            return
        p = _db_path()
        t = threading.Thread(target=_writer_loop, args=(p,), daemon=True, name="burto-store")
        t.start()
        _worker_started = True


def _enqueue(sql: str, params: tuple) -> None:
    _ensure_writer()
    _write_queue.put(_WriteOp(sql=sql, params=params))


# ---------------------------------------------------------------------------
# Read connection (synchronous, for dashboard queries)
# ---------------------------------------------------------------------------

@contextmanager
def _read_conn():
    p = _db_path()
    # Ensure schema exists on first read
    conn = sqlite3.connect(str(p), check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.row_factory = sqlite3.Row
    conn.executescript(_SCHEMA)
    conn.commit()
    try:
        yield conn
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Public write API
# ---------------------------------------------------------------------------

def tool_input_hash(tool_name: str, tool_input: dict) -> str:
    """Stable hash for cache keying and duplicate detection."""
    key = json.dumps({"tool": tool_name, "input": tool_input}, sort_keys=True)
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def record_decision(
    *,
    id: str,
    session_id: str,
    project_root: str,
    agent: str,
    tool_name: str,
    tool_input: dict,
    decision: str,
    stage: str,
    model_used: str | None,
    confidence: float,
    reasoning: str,
    impact: str | None,
    threat_context: str | None,
    trace_id: str | None,
    latency_ms: float | None,
) -> None:
    _enqueue(
        """INSERT OR REPLACE INTO decisions
           (id, ts, session_id, project_root, agent, tool_name, tool_input,
            tool_input_hash, decision, stage, model_used, confidence, reasoning,
            impact, threat_context, trace_id, latency_ms)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            id, time.time(), session_id, project_root, agent,
            tool_name, json.dumps(tool_input), tool_input_hash(tool_name, tool_input),
            decision, stage, model_used, confidence, reasoning,
            impact, threat_context, trace_id, latency_ms,
        ),
    )
    upsert_session(session_id=session_id, project_root=project_root, agent=agent,
                   decision=decision)
    upsert_project(project_root=project_root)


def upsert_session(*, session_id: str, project_root: str, agent: str, decision: str) -> None:
    _enqueue(
        """INSERT INTO sessions (id, project_root, agent, started_at, action_count, blocked_count)
           VALUES (?,?,?,?,1,?)
           ON CONFLICT(id) DO UPDATE SET
               action_count  = action_count + 1,
               blocked_count = blocked_count + (CASE WHEN excluded.blocked_count > 0 THEN 1 ELSE 0 END)""",
        (session_id, project_root, agent, time.time(), 1 if decision != "ALLOW" else 0),
    )


def upsert_project(*, project_root: str) -> None:
    _enqueue(
        """INSERT INTO projects (root, name, first_seen, last_active, session_count)
           VALUES (?,?,?,?,1)
           ON CONFLICT(root) DO UPDATE SET
               last_active   = excluded.last_active,
               session_count = session_count""",
        (project_root, Path(project_root).name, time.time(), time.time()),
    )


def record_signal(
    *,
    decision_id: str,
    signal_type: str,
    override: str | None = None,
    override_reason: str | None = None,
    project_root: str | None = None,
    tool_name: str | None = None,
    tool_input: dict | None = None,
    label: str | None = None,
    reasoning_label: str | None = None,
    context_snapshot: dict | None = None,
) -> None:
    """Record a developer feedback signal on an existing decision."""
    import uuid
    # Update the decision row
    _enqueue(
        """UPDATE decisions SET signal_type=?, override=?, override_reason=?, override_at=?
           WHERE id=?""",
        (signal_type, override, override_reason, time.time(), decision_id),
    )
    if signal_type in ("accept", "reject", "edit", "prompt") and label:
        _enqueue(
            """INSERT INTO training_examples
               (id, project_root, created_at, signal_type, context_snapshot,
                tool_name, tool_input, label, reasoning_label)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                str(uuid.uuid4()), project_root, time.time(), signal_type,
                json.dumps(context_snapshot or {}),
                tool_name, json.dumps(tool_input or {}), label, reasoning_label,
            ),
        )
    if signal_type in ("accept", "reject"):
        _enqueue(
            "UPDATE sessions SET override_count = override_count + 1 WHERE id = (SELECT session_id FROM decisions WHERE id=?)",
            (decision_id,),
        )


# ---------------------------------------------------------------------------
# Public read API (used by dashboard)
# ---------------------------------------------------------------------------

def get_sessions(limit: int = 50) -> list[dict]:
    with _read_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM sessions ORDER BY started_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


def get_session(session_id: str) -> dict | None:
    with _read_conn() as conn:
        row = conn.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
        return dict(row) if row else None


def get_decisions_for_session(session_id: str) -> list[dict]:
    with _read_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM decisions WHERE session_id=? ORDER BY ts DESC", (session_id,)
        ).fetchall()
        return [dict(r) for r in rows]


def get_decision(decision_id: str) -> dict | None:
    with _read_conn() as conn:
        row = conn.execute("SELECT * FROM decisions WHERE id=?", (decision_id,)).fetchone()
        return dict(row) if row else None


def get_projects() -> list[dict]:
    with _read_conn() as conn:
        rows = conn.execute("SELECT * FROM projects ORDER BY last_active DESC").fetchall()
        return [dict(r) for r in rows]


def get_project(root: str) -> dict | None:
    with _read_conn() as conn:
        row = conn.execute("SELECT * FROM projects WHERE root=?", (root,)).fetchone()
        return dict(row) if row else None


def get_project_stats(root: str) -> dict:
    with _read_conn() as conn:
        total = conn.execute(
            "SELECT COUNT(*) FROM decisions WHERE project_root=?", (root,)
        ).fetchone()[0]
        blocked = conn.execute(
            "SELECT COUNT(*) FROM decisions WHERE project_root=? AND decision != 'ALLOW'", (root,)
        ).fetchone()[0]
        overrides = conn.execute(
            "SELECT COUNT(*) FROM decisions WHERE project_root=? AND signal_type IN ('accept','reject')", (root,)
        ).fetchone()[0]
        top_blocks = conn.execute(
            """SELECT tool_name, tool_input, COUNT(*) as cnt
               FROM decisions WHERE project_root=? AND decision != 'ALLOW'
               GROUP BY tool_input_hash ORDER BY cnt DESC LIMIT 10""",
            (root,),
        ).fetchall()
        latency = conn.execute(
            "SELECT AVG(latency_ms), MAX(latency_ms) FROM decisions WHERE project_root=? AND latency_ms IS NOT NULL",
            (root,),
        ).fetchone()
        return {
            "total": total,
            "blocked": blocked,
            "block_rate": round(blocked / total, 3) if total else 0,
            "overrides": overrides,
            "override_rate": round(overrides / max(blocked, 1), 3),
            "top_blocks": [dict(r) for r in top_blocks],
            "latency_avg_ms": round(latency[0] or 0, 1),
            "latency_max_ms": round(latency[1] or 0, 1),
        }


def get_training_examples(project_root: str, limit: int = 1000) -> list[dict]:
    with _read_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM training_examples WHERE project_root=? ORDER BY created_at DESC LIMIT ?",
            (project_root, limit),
        ).fetchall()
        return [dict(r) for r in rows]


def export_decisions(
    project_root: str | None = None,
    from_ts: float | None = None,
    to_ts: float | None = None,
) -> list[dict]:
    with _read_conn() as conn:
        clauses, params = [], []
        if project_root:
            clauses.append("project_root=?"); params.append(project_root)
        if from_ts:
            clauses.append("ts>=?"); params.append(from_ts)
        if to_ts:
            clauses.append("ts<=?"); params.append(to_ts)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        rows = conn.execute(
            f"SELECT * FROM decisions {where} ORDER BY ts DESC", params
        ).fetchall()
        return [dict(r) for r in rows]


def get_cached_decision(tool_input_hash: str, session_id: str) -> dict | None:
    """Return a previous ALLOW decision for this hash in this session (cache hit)."""
    with _read_conn() as conn:
        row = conn.execute(
            """SELECT * FROM decisions
               WHERE tool_input_hash=? AND session_id=? AND decision='ALLOW'
               ORDER BY ts DESC LIMIT 1""",
            (tool_input_hash, session_id),
        ).fetchone()
        return dict(row) if row else None


def approve_decision(decision_id: str, reason: str = "") -> None:
    """Mark a blocked decision as developer-approved. Sets override=allowed."""
    _enqueue(
        "UPDATE decisions SET signal_type='accept', override='allowed', override_reason=?, override_at=? WHERE id=?",
        (reason or "developer approved", time.time(), decision_id),
    )
    # Also bump override_count on the session
    _enqueue(
        "UPDATE sessions SET override_count = override_count + 1 WHERE id = (SELECT session_id FROM decisions WHERE id=?)",
        (decision_id,),
    )


def get_recent_approval(tool_input_hash: str, session_id: str, within_seconds: float = 60.0) -> dict | None:
    """Return the most recent approved decision for this hash in this session, if within window."""
    cutoff = time.time() - within_seconds
    with _read_conn() as conn:
        row = conn.execute(
            """SELECT * FROM decisions
               WHERE tool_input_hash=? AND session_id=?
                 AND override='allowed' AND override_at >= ?
               ORDER BY override_at DESC LIMIT 1""",
            (tool_input_hash, session_id, cutoff),
        ).fetchone()
        return dict(row) if row else None


def update_project_model(project_root: str, model: str) -> None:
    _enqueue(
        "UPDATE projects SET active_model=? WHERE root=?",
        (model, project_root),
    )


def get_project_model(project_root: str) -> str:
    with _read_conn() as conn:
        row = conn.execute(
            "SELECT active_model FROM projects WHERE root=?", (project_root,)
        ).fetchone()
        return row[0] if row else "super"
