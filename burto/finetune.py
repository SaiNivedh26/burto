"""
Nebius Token Factory fine-tune pipeline for burto.

Four stages, all driven from the dashboard:
  1. Export labeled decisions as JSONL
  2. Upload dataset via files.create() (OpenAI-compatible)
  3. Submit LoRA SFT job via fine_tuning.jobs.create()
  4. Poll for completion + record checkpoint/model ID

Uses https://api.tokenfactory.nebius.com/v1/ (not api.studio.nebius.com).
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

log = logging.getLogger("burto.finetune")

_TF_BASE_URL        = "https://api.tokenfactory.nebius.com/v1/"
_TF_CONTROL_PLANE   = "https://api.tokenfactory.nebius.com"
_TF_INFERENCE_URL   = "https://api.tokenfactory.nebius.com/v1"   # or regional: us-central1 / eu-north1
# Cheapest model that supports LoRA fine-tuning + dedicated endpoint deployment
_DEFAULT_FT_MODEL   = "meta-llama/Llama-3.2-1B-Instruct"

_MIN_EXAMPLES  = 10    # Token Factory minimum (practical floor for a test)
_MIN_EDIT_PCT  = 0.10  # recommend 10% edit signals
_MIN_PER_CLASS = 0.10  # recommend 10% per decision class


@dataclass
class DatasetSummary:
    id: str
    project_root: str
    example_count: int
    class_dist: dict[str, int]
    signal_mix: dict[str, int]
    nebius_file_id: str | None = None   # file ID from client.files.create()
    version_label: str | None = None
    warnings: list[str] = field(default_factory=list)


@dataclass
class TrainConfig:
    project_root: str
    dataset_id: str
    base_model: str = _DEFAULT_FT_MODEL
    lora_rank: int = 8
    lora_alpha: float = 8.0
    epochs: int = 1
    lr: float = 1e-4
    batch_size: int = 4
    val_split: float = 0.10
    estimated_cost_usd: float | None = None


@dataclass
class FtRunStatus:
    run_id: str
    status: str          # queued | running | validating_files | succeeded | failed | cancelled
    nebius_job_id: str | None = None
    loss_curve: list[float] = field(default_factory=list)
    tokens_used: int = 0
    cost_usd: float = 0.0
    ft_model_id: str | None = None   # fine_tuned_model_checkpoint from last checkpoint
    error: str | None = None


def _get_client():
    """OpenAI-compatible client pointed at Token Factory."""
    from openai import OpenAI
    api_key = os.getenv("nebius_api_key") or os.getenv("NEBIUS_API_KEY")
    if not api_key:
        raise RuntimeError("nebius_api_key not set")
    return OpenAI(base_url=_TF_BASE_URL, api_key=api_key)


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
        warnings.append(f"Only {total} labeled examples — need ≥{_MIN_EXAMPLES}.")
    edit_pct = signal_mix.get("edit", 0) / max(total, 1)
    if edit_pct < _MIN_EDIT_PCT:
        warnings.append(f"Edit signals: {edit_pct:.0%} — recommend ≥10%.")
    for cls in ("ALLOW", "BLOCK", "ESCALATE"):
        pct = class_dist.get(cls, 0) / max(total, 1)
        if pct < _MIN_PER_CLASS:
            warnings.append(f"Class {cls}: only {pct:.0%} — imbalanced.")

    return DatasetSummary(
        id=str(uuid.uuid4()),
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

    return {
        "messages": [
            {"role": "system",    "content": INTENT_EVAL_SYSTEM},
            {"role": "user",      "content": user_content},
            {"role": "assistant", "content": assistant_content},
        ],
        "metadata": {
            "signal_type": ex.get("signal_type"),
            "project_root": ex.get("project_root"),
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
    """Upload JSONL to Token Factory via files.create() and persist the file ID."""
    client = _get_client()
    with open(jsonl_path, "rb") as f:
        upload = client.files.create(file=f, purpose="fine-tune")

    log.info("uploaded dataset: file_id=%s bytes=%d", upload.id, upload.bytes)
    ds_summary.nebius_file_id = upload.id
    ds_summary.version_label = f"v{int(time.time())}"

    from burto import store as _store
    _store._enqueue(
        """INSERT OR REPLACE INTO datasets
           (id, project_root, created_at, example_count,
            class_distribution_json, signal_mix_json,
            nebius_dataset_id, nebius_storage_uri, version_label)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (ds_summary.id, project_root, time.time(), ds_summary.example_count,
         json.dumps(ds_summary.class_dist), json.dumps(ds_summary.signal_mix),
         upload.id, None, ds_summary.version_label),
    )
    return ds_summary


def estimate_cost(config: TrainConfig, example_count: int) -> float:
    """Rough cost estimate (USD) for a LoRA SFT job."""
    avg_tokens = 600
    tokens = example_count * avg_tokens * config.epochs
    # Llama-3.2-1B LoRA is very cheap; ballpark $0.10 per 1M tokens
    return round(tokens * 0.10 / 1_000_000, 4)


def submit_sft_job(config: TrainConfig, ds: DatasetSummary) -> FtRunStatus:
    """Submit a LoRA SFT job to Token Factory and write an ft_runs row."""
    if not ds.nebius_file_id:
        raise RuntimeError("dataset not yet uploaded — call push_to_nebius() first")

    client = _get_client()
    job = client.fine_tuning.jobs.create(
        model=config.base_model,
        training_file=ds.nebius_file_id,
        suffix=f"burto-{Path(config.project_root).name[:16]}",
        hyperparameters={
            "n_epochs": config.epochs,
            "batch_size": config.batch_size,
            "learning_rate_multiplier": config.lr,
            "lora": True,
            "lora_r": config.lora_rank,
            "lora_alpha": int(config.lora_alpha),
            "lora_dropout": 0.05,
            "packing": True,
        },
    )

    run_id = str(uuid.uuid4())
    from burto import store as _store
    _store._enqueue(
        """INSERT INTO ft_runs
           (id, project_root, dataset_id, started_at, base_model, lora_rank,
            lora_alpha, epochs, lr, batch_size, status, nebius_job_id)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        (run_id, config.project_root, config.dataset_id, time.time(),
         config.base_model, config.lora_rank, config.lora_alpha,
         config.epochs, config.lr, config.batch_size, "queued", job.id),
    )
    log.info("submitted SFT job %s → run %s", job.id, run_id)
    return FtRunStatus(run_id=run_id, status="queued", nebius_job_id=job.id)


def poll_job(run_id: str) -> FtRunStatus:
    """Poll Token Factory job status and update ft_runs table."""
    from burto import store as _store
    with _store._read_conn() as conn:
        row = conn.execute("SELECT * FROM ft_runs WHERE id=?", (run_id,)).fetchone()
    if not row:
        return FtRunStatus(run_id=run_id, status="unknown", error="run not found")

    row = dict(row)
    job_id = row.get("nebius_job_id")
    if not job_id:
        return FtRunStatus(run_id=run_id, status=row.get("status", "unknown"))

    client = _get_client()
    try:
        job = client.fine_tuning.jobs.retrieve(job_id)
    except Exception as e:
        return FtRunStatus(run_id=run_id, status=row.get("status", "unknown"), error=str(e))

    status = job.status
    trained_tokens = getattr(job, "trained_tokens", 0) or 0

    _store._enqueue(
        "UPDATE ft_runs SET status=?, tokens_used=?, finished_at=? WHERE id=?",
        (status, trained_tokens,
         time.time() if status in ("succeeded", "failed") else None, run_id),
    )

    # If succeeded, grab the last checkpoint's fine_tuned_model_checkpoint
    ft_model_id: str | None = None
    if status == "succeeded":
        try:
            ckpts = client.fine_tuning.jobs.checkpoints.list(job_id)
            if ckpts.data:
                ft_model_id = ckpts.data[-1].fine_tuned_model_checkpoint
                _store._enqueue(
                    "UPDATE ft_runs SET endpoint_id=? WHERE id=?",
                    (ft_model_id, run_id),
                )
        except Exception:
            pass

    return FtRunStatus(
        run_id=run_id, status=status, nebius_job_id=job_id,
        tokens_used=trained_tokens, ft_model_id=ft_model_id,
    )


def list_endpoint_templates(region: str = "eu-north1") -> list[dict]:
    """List available dedicated endpoint model templates (GPU configs)."""
    import requests
    api_key = os.getenv("nebius_api_key") or os.getenv("NEBIUS_API_KEY")
    r = requests.get(
        f"{_TF_CONTROL_PLANE}/v0/dedicated_endpoints/templates",
        headers={"Authorization": f"Bearer {api_key}"},
        timeout=15,
    )
    r.raise_for_status()
    templates = r.json().get("templates") or r.json().get("items") or r.json()
    if isinstance(templates, list):
        return [t for t in templates if region in str(t.get("region", ""))]
    return []


def deploy_endpoint(run_id: str, region: str = "eu-north1") -> FtRunStatus:
    """
    Create a Dedicated Endpoint for the fine-tuned model on Token Factory.

    Calls POST /v0/dedicated_endpoints (control plane) which returns an
    endpoint_id + routing_key.  The routing_key is then used as `model=`
    in inference calls to _TF_INFERENCE_URL.

    Custom weights (LoRA) are in beta — if the API rejects the fine-tuned
    model_name, the function falls back to recording the checkpoint ID only
    and returns status='checkpoint_ready' so the dashboard can show it.
    """
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

    # Resolve the fine-tuned checkpoint model name
    ft_model_id = row.get("endpoint_id")
    if not ft_model_id:
        client = _get_client()
        job_id = row.get("nebius_job_id", "")
        try:
            ckpts = client.fine_tuning.jobs.checkpoints.list(job_id)
            if ckpts.data:
                ft_model_id = ckpts.data[-1].fine_tuned_model_checkpoint
        except Exception as e:
            return FtRunStatus(run_id=run_id, status="failed", error=str(e))

    if not ft_model_id:
        return FtRunStatus(run_id=run_id, status="failed", error="no checkpoint found")

    api_key = os.getenv("nebius_api_key") or os.getenv("NEBIUS_API_KEY")
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}

    # First, discover a valid template for the base model
    base_model = row.get("base_model", _DEFAULT_FT_MODEL)
    # Token Factory template model_name uses / not : — strip checkpoint suffix
    template_model = base_model.split(":")[0]

    payload = {
        "name": f"burto-{Path(row['project_root']).name[:20]}-{run_id[:8]}",
        "description": f"Burto fine-tuned model for {row['project_root']}",
        "model_name": ft_model_id,          # fine-tuned checkpoint ID
        "flavor_name": "base",
        "gpu_type": "gpu-h100-sxm",
        "gpu_count": 1,
        "region": region,
        "scaling": {"min_replicas": 1, "max_replicas": 1},
    }

    try:
        r = requests.post(
            f"{_TF_CONTROL_PLANE}/v0/dedicated_endpoints",
            headers=headers,
            json=payload,
            timeout=30,
        )
        r.raise_for_status()
        data = r.json()
        endpoint_id  = data.get("id") or data.get("endpoint_id")
        routing_key  = data.get("routing_key") or ft_model_id
        endpoint_url = f"{_TF_INFERENCE_URL}"

        _store._enqueue(
            "UPDATE ft_runs SET endpoint_id=?, endpoint_url=?, status='deployed' WHERE id=?",
            (routing_key, endpoint_url, run_id),
        )
        _store._enqueue(
            "UPDATE projects SET ft_model_id=?, active_model=? WHERE root=?",
            (routing_key, routing_key, row["project_root"]),
        )
        log.info("dedicated endpoint created: id=%s routing_key=%s", endpoint_id, routing_key)
        return FtRunStatus(
            run_id=run_id, status="deployed",
            nebius_job_id=row["nebius_job_id"],
            ft_model_id=routing_key,
        )

    except requests.HTTPError as exc:
        # Custom weights are in beta — may be rejected for non-whitelisted accounts
        err_body = exc.response.text if exc.response is not None else str(exc)
        log.warning("dedicated endpoint creation failed (custom weights beta?): %s", err_body)
        # Fall back: record checkpoint as-is, usable once account is whitelisted
        _store._enqueue(
            "UPDATE ft_runs SET endpoint_id=?, status='checkpoint_ready' WHERE id=?",
            (ft_model_id, run_id),
        )
        return FtRunStatus(
            run_id=run_id, status="checkpoint_ready",
            nebius_job_id=row["nebius_job_id"],
            ft_model_id=ft_model_id,
            error=f"Dedicated endpoint beta — contact Nebius support to enable. Checkpoint: {ft_model_id}",
        )
