# Burto

Intent-scoped security guard for AI coding agents. Intercepts every tool call, infers what the developer is actually working on from the live conversation transcript, and blocks actions that fall outside that scope — without requiring any explicit task declaration.

```
developer prompt → coding agent → tool call
                                      ↓
                               burto hook fires
                                      ↓
                        reads transcript + project tree
                                      ↓
                         heuristic check (fast, no LLM)
                                      ↓
                         Agent evaluation (Nebius/Qwen3)
                                      ↓
                          ALLOW / ESCALATE / BLOCK
```

---

## Prerequisites

Install dependencies into the project virtualenv:

```bash
python3 -m venv nvd
source nvd/bin/activate
pip install -e .
```

Required environment variables (loaded via `.env` or set in shell):

```
nebius_api_key=...
langsmith_api_key=...   # optional, for audit tracing
tavily_api_key=...      # optional, for threat research
```

---

## Start the servers

Two processes must be running before connecting any coding agent.

**1. Hook server** — receives PreToolUse payloads and returns allow/deny decisions:

```bash
cd /home/sai-nivedh-26/nvidia-hack
PYTHONPATH=. nvd/bin/python -m uvicorn burto.hook_server:app --port 8000
```

Health check:

```bash
curl http://localhost:8000/health
```

**2. MCP server** — started automatically by the coding agent via stdio (configured in `.mcp.json`). No separate launch needed.

---

## Integrate with Command Code (cmdc)

Place these two files at your project root. cmdc picks them up automatically on startup.

**`.commandcode/settings.json`** — wires the PreToolUse hook:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "shell|write|edit|read",
        "hooks": [
          {
            "type": "command",
            "command": "/home/sai-nivedh-26/nvidia-hack/.commandcode/hooks/burto.sh",
            "timeout": 15
          }
        ]
      }
    ]
  }
}
```

**`.mcp.json`** — wires the burto MCP server (optional: gives the agent `burto_start_task`, `burto_get_status`, `burto_clear_session` tools):

```json
{
  "mcpServers": {
    "burto": {
      "transport": "stdio",
      "enabled": true,
      "command": "/home/sai-nivedh-26/nvidia-hack/nvd/bin/python",
      "args": ["/home/sai-nivedh-26/nvidia-hack/burto/mcp_server.py"],
      "env": {
        "PYTHONPATH": "/home/sai-nivedh-26/nvidia-hack"
      }
    }
  }
}
```

Then launch cmdc from your project directory:

```bash
cd your-project/
cmdc
```

---

## Integrate with Claude Code

**`.claude/settings.json`** — same structure, different tool matcher syntax:

```json
{
  "mcpServers": {
    "burto": {
      "type": "stdio",
      "command": "/home/sai-nivedh-26/nvidia-hack/nvd/bin/python",
      "args": ["/home/sai-nivedh-26/nvidia-hack/burto/mcp_server.py"],
      "env": { "PYTHONPATH": "/home/sai-nivedh-26/nvidia-hack" }
    }
  },
  "hooks": {
    "PreToolUse": [
      {
        "matcher": ".*",
        "hooks": [
          {
            "type": "command",
            "command": "/home/sai-nivedh-26/nvidia-hack/claude_code_hooks/pretooluse.sh"
          }
        ]
      }
    ]
  }
}
```

---

## Integrate with any other agent

Any agent that supports PreToolUse hooks works. The hook script reads a JSON payload from stdin and writes a JSON decision to stdout.

**Minimum hook script** (adapt path as needed):

```bash
#!/usr/bin/env bash
INPUT=$(cat)
RESPONSE=$(printf '%s' "$INPUT" | curl -sf -X POST http://localhost:8000/hook/pretooluse \
  -H "Content-Type: application/json" -d @- 2>/dev/null)
ACTION=$(printf '%s' "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('action','proceed'))")
[ "$ACTION" = "block" ] && exit 2
exit 0
```

**Payload burto expects on stdin:**

```json
{
  "session_id": "<stable session id>",
  "tool_name": "<tool name>",
  "tool_input": {},
  "transcript_path": "<absolute path to JSONL transcript>",
  "cwd": "<project working directory>"
}
```

If the agent doesn't provide a transcript, burto falls back to "general development task" context and evaluates based on project structure alone.

---

## Test the setup

**Unit tests — core engine (no server needed):**

```bash
cd /home/sai-nivedh-26/nvidia-hack
PYTHONPATH=. nvd/bin/python test_core.py
```

**Hook integration tests — requires hook server running:**

```bash
cd /home/sai-nivedh-26/nvidia-hack/test-codebase
bash tests/hook_test.sh
```

**Live cmdc test — interactive:**

```bash
cd /home/sai-nivedh-26/nvidia-hack/test-codebase
cmdc
# Try: "update the production config to enable debug mode"
# Expected: reads allowed, write to config/production.yaml blocked by burto
```

---

## How decisions are made

| Stage | Mechanism | Latency |
|-------|-----------|---------|
| 0 | Heuristic (env exfil, infra commands) | ~0 ms |
| 1 | LLM — conversation + project tree (Qwen3-30B via Nebius) | ~1–2 s |
| 2 | Devil's advocate cross-check (uncertain BLOCKs only) | ~1–2 s |

Decisions: `ALLOW` proceeds silently. `BLOCK` and `ESCALATE` surface a context box to the developer showing task context, proposed action, why it was flagged, and impact.

Bypass for trusted sessions: set `BURTO_BYPASS=1` in the hook process environment.

---

## Project layout

```
burto/
  hook_server.py      — FastAPI server, receives hook payloads
  mcp_server.py       — MCP server (burto_start_task, status, clear)
  evaluator.py        — heuristic + LLM evaluation pipeline
  context_builder.py  — reads live transcript, scans project tree
  prompts.py          — system prompts and JSON schemas
  models.py           — Pydantic types
  budget.py           — per-session action history

.commandcode/
  hooks/burto.sh      — cmdc PreToolUse hook (cmdc JSON output format)

claude_code_hooks/
  pretooluse.sh       — Claude Code PreToolUse hook

test-codebase/        — isolated test project for cmdc integration tests
  .commandcode/settings.json
  .mcp.json
  tests/hook_test.sh
```


## Output

![op](assets/op.png)