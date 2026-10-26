"""
.burto/policy.yaml per-project allow/deny/escalate rules.

Evaluated before the LLM — policy decisions win immediately.
File is read on first access then cached with mtime-based invalidation.
"""
from __future__ import annotations

import fnmatch
import json
import logging
import os
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore[assignment]

log = logging.getLogger("burto.policy")

_POLICY_FILENAME = ".burto/policy.yaml"

# High-risk project: deny-by-default on writes to sensitive dirs
_HIGH_RISK_DENY_GLOBS = [
    "config/prod*", "config/production*", "infra/**", ".github/**",
    "secrets/**", "**/*.env", "**/.env*",
]

# Default per-tier rules (used when no policy.yaml exists)
_TIER_DEFAULTS = {
    "low":      {"model": "nano",  "deny_by_default": False},
    "standard": {"model": "super", "deny_by_default": False},
    "high":     {"model": "super", "deny_by_default": True},
}


@dataclass
class PolicyRule:
    tool: str           # shell | write | read | edit | *
    action: str         # allow | deny | escalate
    command_prefix: str | None = None
    command_regex: str | None = None
    path_glob: str | None = None
    _compiled_re: Any = field(default=None, repr=False, compare=False)

    def __post_init__(self):
        if self.command_regex:
            try:
                self._compiled_re = re.compile(self.command_regex, re.IGNORECASE)
            except re.error:
                log.warning("invalid command_regex in policy: %s", self.command_regex)

    def matches(self, tool_name: str, tool_input: dict) -> bool:
        if self.tool not in ("*", tool_name.lower()):
            # Also match broad categories: shell, write, read, edit
            if self.tool == "shell" and not _is_shell(tool_name):
                return False
            elif self.tool in ("write", "read", "edit") and self.tool not in tool_name.lower():
                return False

        # Shell-level command matching
        if self.command_prefix or self.command_regex:
            cmd = str(tool_input.get("command", tool_input.get("cmd", ""))).strip()
            if self.command_prefix and not cmd.startswith(self.command_prefix):
                return False
            if self._compiled_re and not self._compiled_re.search(cmd):
                return False

        # Path matching
        if self.path_glob:
            fp = str(tool_input.get("file_path", tool_input.get("path", "")))
            if not fp or not fnmatch.fnmatch(fp, self.path_glob):
                return False

        return True


def _is_shell(tool_name: str) -> bool:
    _SHELL = {"bash", "shell", "run_command", "execute", "exec", "terminal", "shell_command"}
    return tool_name.lower() in _SHELL or "shell" in tool_name.lower() or "command" in tool_name.lower()


@dataclass
class Policy:
    risk_tier: str = "standard"
    model_active: str = "super"
    rules: list[PolicyRule] = field(default_factory=list)
    deny_by_default: bool = False
    raw: dict = field(default_factory=dict, repr=False, compare=False)

    def evaluate(self, tool_name: str, tool_input: dict) -> str | None:
        """Return 'allow', 'deny', 'escalate', or None (no policy match → use LLM)."""
        for rule in self.rules:
            if rule.matches(tool_name, tool_input):
                return rule.action
        if self.deny_by_default and not _is_shell(tool_name) and "write" in tool_name.lower():
            return "deny"
        return None


_CACHE: dict[str, tuple[Policy, float]] = {}  # project_root → (policy, mtime)
_CACHE_LOCK = threading.Lock()


def load_policy(project_root: str) -> Policy:
    """Load and cache .burto/policy.yaml for the project; fallback to defaults."""
    path = Path(project_root) / _POLICY_FILENAME
    with _CACHE_LOCK:
        existing = _CACHE.get(project_root)
        mtime = path.stat().st_mtime if path.exists() else -1.0
        if existing and existing[1] == mtime:
            return existing[0]
        p = _parse(path, project_root)
        _CACHE[project_root] = (p, mtime)
    return p


def _parse(path: Path, project_root: str) -> Policy:
    if not path.exists() or yaml is None:
        return _default_policy(project_root)
    try:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except Exception as e:
        log.warning("failed to parse %s: %s", path, e)
        return _default_policy(project_root)

    risk_tier = data.get("risk_tier", "standard")
    model_cfg = data.get("model", {})
    model_active = model_cfg.get("active", "super") if isinstance(model_cfg, dict) else str(model_cfg)
    tier_defaults = _TIER_DEFAULTS.get(risk_tier, _TIER_DEFAULTS["standard"])
    deny_by_default = data.get("deny_by_default", tier_defaults["deny_by_default"])

    rules: list[PolicyRule] = []
    for action_key in ("allow", "deny", "escalate"):
        for raw_rule in data.get(action_key, []):
            try:
                # `pattern` is a user-friendly alias: substring match compiled to regex
                pattern = raw_rule.get("pattern")
                cmd_regex = raw_rule.get("command_regex") or (re.escape(pattern) if pattern else None)
                rules.append(PolicyRule(
                    tool=raw_rule.get("tool", "*"),
                    action=action_key,
                    command_prefix=raw_rule.get("command_prefix"),
                    command_regex=cmd_regex,
                    path_glob=raw_rule.get("path_glob"),
                ))
            except Exception as e:
                log.warning("invalid policy rule %s: %s", raw_rule, e)

    return Policy(
        risk_tier=risk_tier,
        model_active=model_active,
        rules=rules,
        deny_by_default=deny_by_default,
        raw=data,
    )


def _default_policy(project_root: str) -> Policy:
    return Policy(risk_tier="standard", model_active="super")


def generate_policy_yaml(project_root: str) -> str:
    """Generate a starter .burto/policy.yaml for the project (not written; developer commits)."""
    return f"""# Burto policy for {Path(project_root).name}
# Generated by burto — edit and commit to version-control.
version: 1
risk_tier: standard   # low | standard | high
model:
  active: super       # nano | super | ultra | ft:<endpoint-id>
  override_on_devil: ultra

# Explicit allow rules — evaluated BEFORE the LLM
allow:
  - {{ tool: shell, command_prefix: "pytest " }}
  - {{ tool: shell, command_prefix: "git " }}
  - {{ tool: shell, command_prefix: "npm " }}
  - {{ tool: read }}   # reads are generally safe

# Explicit deny rules
deny:
  - {{ tool: shell, command_regex: ".*(curl|wget).*\\\\$\\\\(.*\\\\).*" }}
  - {{ tool: write, path_glob: "config/prod*" }}
  - {{ tool: write, path_glob: "**/.env*" }}

# Escalate to human before proceeding
escalate:
  - {{ tool: shell, command_regex: ".*(terraform|kubectl|aws |gcloud |az ).*" }}
  - {{ tool: write, path_glob: "**/.github/**" }}
"""
