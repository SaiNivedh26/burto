"""
Auto-analyzes a project repo on first encounter and writes .burto/policy.yaml.
Called async from evaluate() so it never blocks the hot path.
"""
from __future__ import annotations

import logging
import os
import threading
from pathlib import Path

log = logging.getLogger("burto.analyzer")

_analyzed: set[str] = set()
_lock = threading.Lock()


def maybe_analyze_async(project_root: str) -> None:
    """Trigger background analysis if this project has no policy file yet."""
    if not project_root:
        return
    policy_path = Path(project_root) / ".burto" / "policy.yaml"
    if policy_path.exists():
        return
    with _lock:
        if project_root in _analyzed:
            return
        _analyzed.add(project_root)
    t = threading.Thread(target=_analyze_and_write, args=(project_root,), daemon=True, name="burto-analyzer")
    t.start()


def _analyze_and_write(project_root: str) -> None:
    try:
        findings = _scan_repo(project_root)
        yaml_text = _call_llm_for_policy(project_root, findings)
        _write_policy(project_root, yaml_text)
        log.info("auto-generated .burto/policy.yaml for %s (risk_tier=%s)",
                 project_root, findings.get("risk_tier"))
    except Exception as exc:
        log.warning("auto-analysis failed for %s: %s", project_root, exc)


# ---------------------------------------------------------------------------
# Repo scanner
# ---------------------------------------------------------------------------

_INFRA_DIRS = {"terraform", "infra", "k8s", "kubernetes", "helm", "pulumi", "cdk", "ansible"}
_LANG_FILES = {
    "pyproject.toml": "python", "requirements.txt": "python", "setup.py": "python",
    "package.json": "javascript", "go.mod": "go", "Cargo.toml": "rust",
    "pom.xml": "java", "build.gradle": "java",
}


def _scan_repo(project_root: str) -> dict:
    root = Path(project_root)
    findings: dict = {
        "project_name": root.name,
        "has_infra": False,
        "has_prod_config": False,
        "has_secrets": False,
        "has_ci": False,
        "has_docker": False,
        "has_db_migrations": False,
        "languages": [],
        "sensitive_paths": [],
        "risk_tier": "standard",
    }

    # Top-level scan
    try:
        for entry in root.iterdir():
            name = entry.name.lower()
            if name in _INFRA_DIRS and entry.is_dir():
                findings["has_infra"] = True
                findings["sensitive_paths"].append(str(entry.relative_to(root)))
            if name in (".github", ".gitlab-ci.yml", ".circleci", "Jenkinsfile"):
                findings["has_ci"] = True
            if name in ("dockerfile", "docker-compose.yml", "docker-compose.yaml", ".dockerignore"):
                findings["has_docker"] = True
            if name in _LANG_FILES:
                lang = _LANG_FILES[name]
                if lang not in findings["languages"]:
                    findings["languages"].append(lang)
            if name in (".env", ".env.local", ".env.production", ".env.staging"):
                findings["has_secrets"] = True
            if name in ("secrets", "credentials", "keys", "certs") and entry.is_dir():
                findings["has_secrets"] = True
                findings["sensitive_paths"].append(str(entry.relative_to(root)))
            if name in ("migrations", "alembic", "db") and entry.is_dir():
                findings["has_db_migrations"] = True
    except PermissionError:
        pass

    # Shallow glob for production config
    for pattern in ("config/prod*", "config/production*", "configs/prod*"):
        for match in root.glob(pattern):
            findings["has_prod_config"] = True
            sp = str(match.relative_to(root))
            if sp not in findings["sensitive_paths"]:
                findings["sensitive_paths"].append(sp)

    # Risk score → tier
    score = (
        findings["has_infra"] * 2
        + findings["has_prod_config"] * 2
        + findings["has_secrets"] * 2
        + findings["has_ci"]
        + findings["has_db_migrations"]
    )
    findings["risk_tier"] = "high" if score >= 4 else ("standard" if score >= 1 else "low")
    return findings


# ---------------------------------------------------------------------------
# Policy generation
# ---------------------------------------------------------------------------

def _call_llm_for_policy(project_root: str, findings: dict) -> str:
    try:
        from openai import OpenAI

        client = OpenAI(
            api_key=os.environ["nebius_api_key"],
            base_url="https://api.studio.nebius.com/v1/",
        )

        sensitive_summary = ", ".join(findings["sensitive_paths"][:5]) or "none detected"
        lang_summary = ", ".join(findings["languages"]) or "unknown"

        prompt = f"""You are Burto, a security guard for AI coding agents.
Generate a .burto/policy.yaml for this project. Use ONLY this exact YAML schema:

version: 1
risk_tier: standard   # low | standard | high
model:
  active: super       # nano | super | ultra

allow:
  - tool: shell       # must be exactly: shell, write, read, edit, or *
    command_prefix: "pytest"      # optional: command starts-with match
    reason: "..."
  - tool: shell
    command_regex: "..."          # optional: regex match on full command (not both prefix and regex)
    reason: "..."
  - tool: write
    path_glob: "tests/**"         # optional: fnmatch glob on file path
    reason: "..."

deny:
  - tool: write
    path_glob: "config/prod*"
    reason: "..."

escalate:
  - tool: shell
    command_regex: "terraform"
    reason: "..."

Rules: every entry needs `tool` and `reason`. Use `command_prefix` OR `command_regex`, not both.

Project:
  name: {findings['project_name']}
  languages: {lang_summary}
  has_infra: {findings['has_infra']}
  has_prod_config: {findings['has_prod_config']}
  has_secrets: {findings['has_secrets']}
  has_ci: {findings['has_ci']}
  has_db_migrations: {findings['has_db_migrations']}
  sensitive_paths: {sensitive_summary}
  risk_tier: {findings['risk_tier']}

Output ONLY valid YAML. No markdown fences. First line must be: # Auto-generated by Burto"""

        resp = client.chat.completions.create(
            model="Qwen/Qwen3-235B-A22B-Instruct-2507",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=1400,
            temperature=0.2,
        )
        return resp.choices[0].message.content.strip()

    except Exception as exc:
        log.warning("LLM policy generation failed, using template: %s", exc)
        return _template_policy(findings)


def _template_policy(findings: dict) -> str:
    risk = findings["risk_tier"]
    model = "super" if risk in ("standard", "high") else "nano"

    deny_extra = ""
    if findings["has_prod_config"]:
        deny_extra += '\n  - tool: write\n    path_glob: "config/prod*"\n    reason: "production config — write requires explicit user instruction"'
    if findings["has_secrets"]:
        deny_extra += '\n  - tool: write\n    path_glob: "**/.env*"\n    reason: "env/secrets files are off-limits"'

    escalate_extra = ""
    if findings["has_infra"]:
        escalate_extra += '\n  - tool: shell\n    command_regex: ".*(terraform|pulumi|kubectl|helm).*"\n    reason: "infra commands — confirm before running"'
    if findings["has_db_migrations"]:
        escalate_extra += '\n  - tool: shell\n    command_regex: ".*(migrate|alembic).*(upgrade|downgrade).*"\n    reason: "db migrations need explicit confirmation"'

    return f"""# Auto-generated by Burto — review and commit to version-control
# Project: {findings['project_name']} | Risk tier: {risk}
version: 1
risk_tier: {risk}
model:
  active: {model}

allow:
  - tool: shell
    command_prefix: "pytest"
  - tool: shell
    command_prefix: "git "
  - tool: shell
    command_regex: "^(pip|pip3|npm|yarn|pnpm) (install|add)"
  - tool: read
    reason: "reading source files is always safe"

deny:
  - tool: shell
    command_regex: ".*(curl|wget).*\\$\\(.*\\).*"
    reason: "command injection / env exfil"{deny_extra}

escalate:{escalate_extra or chr(10) + "  # no infra-specific escalations detected"}
  - tool: shell
    command_regex: ".*(aws |gcloud |az ).*"
    reason: "cloud CLI commands need confirmation"
"""


def _write_policy(project_root: str, yaml_text: str) -> None:
    burto_dir = Path(project_root) / ".burto"
    burto_dir.mkdir(exist_ok=True)
    policy_path = burto_dir / "policy.yaml"
    policy_path.write_text(yaml_text, encoding="utf-8")
