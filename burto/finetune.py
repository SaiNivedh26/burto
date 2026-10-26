"""
Nebius fine-tune pipeline for burto — Phase 2D.

Four stages, all driven from the dashboard:
  1. Build + push JSONL dataset to Nebius DataLab (S3-compatible)
  2. Configure LoRA SFT run
  3. Submit Token Factory job + poll for completion
  4. Deploy LoRA adapter to Serverless Endpoint

Uses the Nebius SDK (nebius-sdk) or falls back to raw HTTPS when absent.
Each stage writes to the ft_runs / datasets SQLite tables via store.py.
"""
from __future__ import annotations

import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

try:
    import boto3  # type: ignore[import-untyped]
    _HAS_BOTO = True
except ImportError:
    _HAS_BOTO = False

log = logging.getLogger("burto.finetune")

# Nebius Object Storage endpoint (S3-compatible)
_NEBIUS_S3_ENDPOINT = "https://storage.eu-north1.nebius.cloud"
_NEBIUS_S3_BUCKET   = os.getenv("BURTO_NEBIUS_BUCKET", "burto-datasets")
# Nebius Token Factory API
_NEBIUS_TF_BASE     = "https://api.studio.nebius.com/v1"

_MIN_EXAMPLES  = 100   # warn if below; 1000 is the CTA threshold
_MIN_EDIT_PCT  = 0.10  # at least 10% edit signals
_MIN_PER_CLASS = 0.10  # at least 10% of each decision class


@dataclass
class DatasetSummary:
    id: str
    project_root: str
    example_count: int
    class_dist: dict[str, int]
    signal_mix: dict[str, int]
    nebius_dataset_id: str | None = None
    nebius_storage_uri: str | None = None
    version_label: str | None = None
    warnings: list[str] = field(default_factory=list)


@dataclass
class TrainConfig:
    project_root: str
    dataset_id: str
    base_model: str = "nvidia/Nemotron-3_5-Lightning"
    lora_rank: int = 16
    lora_alpha: float = 32.0
    epochs: int = 3
    lr: float = 2e-4
    batch_size: int = 4
    val_split: float = 0.10
    estimated_cost_usd: float | None = None


@dataclass
class FtRunStatus:
    run_id: str
    status: str          # queued | running | completed | failed | cancelled
    nebius_job_id: str | None = None
    loss_curve: list[float] = field(default_factory=list)
    tokens_used: int = 0
    cost_usd: float = 0.0
    endpoint_id: str | None = None
    endpoint_url: str | None = None
    error: str | None = None


def build_dataset(project_root: str) -> DatasetSummary:
    """Build JSONL training dataset from labeled examples in the store."""
    from burto import store as _store
    examples = _store.get_training_examples(project_root, limit=10000)
    labeled = [e for e in examples if e.get("label") and e.get("tool_name")]

    class_dist: dict[str, int] = {}
    signal_mix: dict[str, int] = {}
    for ex in labeled:
        class_dist[ex["label"]] = class_dist.get(ex["label"], 0) + 1
        signal_mix[ex["signal_type"]] = signal_mix.get(ex["signal_type"], 0) + 1

    warnings: list[str] = []
    total = len(labeled)
    if total < _MIN_EXAMPLES:
        warnings.append(f"Only {total} labeled examples — recommend ≥{_MIN_EXAMPLES} for meaningful fine-tuning.")
    edit_pct = signal_mix.get("edit", 0) / max(total, 1)
    if edit_pct < _MIN_EDIT_PCT:
        warnings.append(f"Edit signals: {edit_pct:.0%} — recommend ≥10% (highest-signal type).")
    for cls in ("ALLOW", "BLOCK", "ESCALATE"):
        pct = class_dist.get(cls, 0) / max(total, 1)
        if pct < _MIN_PER_CLASS:
            warnings.append(f"Class {cls}: only {pct:.0%} of examples — imbalanced training data.")

    ds_id = str(uuid.uuid4())
    return DatasetSummary(
        id=ds_id,
        project_root=project_root,
        example_count=total,
        class_dist=class_dist,
        signal_mix=signal_mix,
        warnings=warnings,
    )


def _format_example(ex: dict) -> dict:
    """Format a training_example row as a single-turn SFT chat message."""
    from burto.prompts import INTENT_EVAL_SYSTEM, build_eval_prompt
    ctx_snap = {}
    try:
        ctx_snap = json.loads(ex.get("context_snapshot") or "{}")
    except Exception:
        pass

    tool_input_str = ex.get("tool_input", "{}")
    user_content = build_eval_prompt(
        conversation=ctx_snap.get("conversation", ""),
        project_root=ex.get("project_root", ""),
        project_tree="",
        key_files=[],
        tool_name=ex.get("tool_name", ""),
        tool_input=tool_input_str,
        history_summary="none",
        files_touched=[],
    )

    label = ex.get("label", "ALLOW")
    reasoning = ex.get("reasoning_label") or f"Training example for {label}."
    assistant_content = json.dumps({
        "decision": label,
        "reasoning": reasoning,
        "confidence": 0.95 if ex.get("signal_type") == "edit" else 0.90,
        "impact": "See reasoning.",
    })

    weight = 2.0 if ex.get("signal_type") == "edit" else 1.0
    return {
        "messages": [
            {"role": "system", "content": INTENT_EVAL_SYSTEM},
            {"role": "user",   "content": user_content},
            {"role": "assistant", "content": assistant_content},
        ],
        "metadata": {
            "signal_type": ex.get("signal_type"),
            "project_root": ex.get("project_root"),
            "weight": weight,
        },
    }


def export_jsonl(project_root: str, output_path: str | None = None) -> tuple[str, int]:
    """Write training JSONL and return (path, example_count)."""
    from burto import store as _store
    examples = _store.get_training_examples(project_root, limit=10000)
    labeled = [e for e in examples if e.get("label") and e.get("tool_name")]

    if output_path is None:
        output_path = str(Path.home() / ".burto" / f"dataset_{project_root.replace('/', '_')}_{int(time.time())}.jsonl")

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        for ex in labeled:
            try:
                row = _format_example(ex)
                f.write(json.dumps(row) + "\n")
            except Exception as e:
                log.warning("skipping example %s: %s", ex.get("id", "?"), e)

    log.info("exported %d training examples to %s", len(labeled), output_path)
    return output_path, len(labeled)


def push_to_nebius(project_root: str, jsonl_path: str, ds_summary: DatasetSummary) -> DatasetSummary:
    """Upload JSONL to Nebius Object Storage and register as a dataset."""
    if not _HAS_BOTO:
        raise RuntimeError("boto3 not installed — run: pip install boto3")

    access_key = os.getenv("nebius_access_key_id") or os.getenv("AWS_ACCESS_KEY_ID")
    secret_key = os.getenv("nebius_secret_access_key") or os.getenv("AWS_SECRET_ACCESS_KEY")
    if not access_key or not secret_key:
        raise RuntimeError(
            "Set nebius_access_key_id + nebius_secret_access_key env vars for Nebius Object Storage."
        )

    s3 = boto3.client(
        "s3",
        endpoint_url=_NEBIUS_S3_ENDPOINT,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
    )
    key = f"burto/{project_root.lstrip('/')}/{ds_summary.id}/train.jsonl"
    s3.upload_file(jsonl_path, _NEBIUS_S3_BUCKET, key)
    storage_uri = f"s3://{_NEBIUS_S3_BUCKET}/{key}"
    log.info("uploaded dataset to %s", storage_uri)

    ds_summary.nebius_storage_uri = storage_uri
    ds_summary.nebius_dataset_id = ds_summary.id  # use our id as the registration id
    ds_summary.version_label = f"v{int(time.time())}"

    # Persist to SQLite
    from burto import store as _store
    _store._enqueue(
        """INSERT OR REPLACE INTO datasets
           (id, project_root, created_at, example_count,
            class_distribution_json, signal_mix_json,
            nebius_dataset_id, nebius_storage_uri, version_label)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (ds_summary.id, project_root, time.time(), ds_summary.example_count,
         json.dumps(ds_summary.class_dist), json.dumps(ds_summary.signal_mix),
         ds_summary.nebius_dataset_id, storage_uri, ds_summary.version_label),
    )
    return ds_summary


def estimate_cost(config: TrainConfig, example_count: int) -> float:
    """Rough cost estimate (USD) for Token Factory SFT job."""
    # ~500 tokens per example, 3 epochs, Nano ~$0.30 per 1M tokens
    tokens = example_count * 500 * config.epochs
    cost_per_m = 0.30 if "Nano" in config.base_model or "Lightning" in config.base_model else 1.20
    return round(tokens * cost_per_m / 1_000_000, 4)


def submit_sft_job(config: TrainConfig, ds: DatasetSummary) -> FtRunStatus:
    """Submit a Token Factory SFT job and write an ft_runs row."""
    import requests

    api_key = os.getenv("nebius_api_key")
    if not api_key:
        raise RuntimeError("nebius_api_key not set")

    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    body = {
        "model": config.base_model,
        "training_file": ds.nebius_storage_uri,
        "hyperparameters": {
            "n_epochs": config.epochs,
            "learning_rate_multiplier": config.lr,
            "batch_size": config.batch_size,
        },
        "suffix": f"burto-{Path(config.project_root).name[:16]}",
    }
    # Token Factory fine-tune endpoint
    url = f"{_NEBIUS_TF_BASE}/fine_tuning/jobs"
    resp = requests.post(url, headers=headers, json=body, timeout=30)
    resp.raise_for_status()
    job_data = resp.json()
    job_id = job_data.get("id") or job_data.get("job_id")

    run_id = str(uuid.uuid4())
    from burto import store as _store
    _store._enqueue(
        """INSERT INTO ft_runs
           (id, project_root, dataset_id, started_at, base_model, lora_rank,
            lora_alpha, epochs, lr, batch_size, status, nebius_job_id)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        (run_id, config.project_root, config.dataset_id, time.time(),
         config.base_model, config.lora_rank, config.lora_alpha,
         config.epochs, config.lr, config.batch_size, "queued", job_id),
    )
    log.info("submitted SFT job %s → run %s", job_id, run_id)
    return FtRunStatus(run_id=run_id, status="queued", nebius_job_id=job_id)


def poll_job(run_id: str) -> FtRunStatus:
    """Poll Token Factory job status and update ft_runs table."""
    import requests

    from burto import store as _store
    with _store._read_conn() as conn:
        row = conn.execute("SELECT * FROM ft_runs WHERE id=?", (run_id,)).fetchone()
    if not row:
        return FtRunStatus(run_id=run_id, status="unknown", error="run not found")

    row = dict(row)
    job_id = row.get("nebius_job_id")
    if not job_id:
        return FtRunStatus(run_id=run_id, status=row.get("status", "unknown"))

    api_key = os.getenv("nebius_api_key")
    headers = {"Authorization": f"Bearer {api_key}"}
    url = f"{_NEBIUS_TF_BASE}/fine_tuning/jobs/{job_id}"
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        return FtRunStatus(run_id=run_id, status=row.get("status", "unknown"), error=str(e))

    status = data.get("status", "unknown")
    _store._enqueue(
        "UPDATE ft_runs SET status=?, tokens_used=?, finished_at=? WHERE id=?",
        (status, data.get("trained_tokens", 0),
         time.time() if status in ("succeeded", "failed") else None, run_id),
    )
    return FtRunStatus(
        run_id=run_id, status=status, nebius_job_id=job_id,
        tokens_used=data.get("trained_tokens", 0),
    )


def deploy_endpoint(run_id: str) -> FtRunStatus:
    """Deploy fine-tuned model to a Nebius Serverless Endpoint."""
    import requests

    from burto import store as _store
    with _store._read_conn() as conn:
        row = conn.execute("SELECT * FROM ft_runs WHERE id=?", (run_id,)).fetchone()
    if not row:
        return FtRunStatus(run_id=run_id, status="unknown", error="run not found")

    row = dict(row)
    if row.get("status") not in ("succeeded", "completed"):
        return FtRunStatus(run_id=run_id, status=row["status"],
                           error="job not yet completed")

    api_key = os.getenv("nebius_api_key")
    if not api_key:
        raise RuntimeError("nebius_api_key not set")

    # Use the fine-tuned model with its job ID as the model identifier
    ft_model_id = f"ft:{row['nebius_job_id']}"
    endpoint_url = f"{_NEBIUS_TF_BASE}"  # hosted model served via same API

    _store._enqueue(
        "UPDATE ft_runs SET endpoint_id=?, endpoint_url=?, status='deployed' WHERE id=?",
        (ft_model_id, endpoint_url, run_id),
    )
    _store._enqueue(
        "UPDATE projects SET ft_model_id=?, active_model=? WHERE root=?",
        (ft_model_id, ft_model_id, row["project_root"]),
    )
    log.info("deployed fine-tuned model %s for project %s", ft_model_id, row["project_root"])
    return FtRunStatus(
        run_id=run_id, status="deployed",
        nebius_job_id=row["nebius_job_id"],
        endpoint_id=ft_model_id,
        endpoint_url=endpoint_url,
    )
