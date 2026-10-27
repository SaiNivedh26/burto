# Burto — Setup Guide

Burto is a security guard that intercepts AI coding agent tool calls in real-time.
It detects hallucinations, prompt injection, goal drift, and dangerous commands —
then steers the agent back on track instead of just blocking it.

Supports any agent that uses Claude Code–style hooks: **Claude Code**, **OpenCode**,
and any tool that calls a hook script on PreToolUse / PostToolUse / Stop / SessionStart.

---

## Prerequisites

- Python 3.12+
- `curl` and `python3` available in PATH (used by the hook script)
- A Nebius AI Studio API key → [studio.nebius.com](https://studio.nebius.com)

---

## 1. Install

```bash
git clone <this-repo>
cd burto-project

python3 -m venv .venv
source .venv/bin/activate

pip install -e .
```

---

## 2. Configure environment

Create a `.env` file in the project root (never committed):

```bash
nebius_api_key=your_nebius_key_here

# Optional — for LangSmith tracing
langsmith_api_key=your_langsmith_key_here

# Optional — for Tavily web search in threat research
tavily_api_key=your_tavily_key_here
```

---

## 3. Start the server

```bash
source .venv/bin/activate
uvicorn burto.hook_server:app --host 0.0.0.0 --port 8000
```

Verify it's running:

```bash
curl http://localhost:8000/health
# → {"status":"ok"}
```

Dashboard: [http://localhost:8000](http://localhost:8000)

---

## 4. Wire up your coding agent

### Claude Code

Copy the hook script to your project:

```bash
mkdir -p your-project/.claude
cp /path/to/burto/.commandcode/hooks/burto.sh your-project/.claude/burto.sh
chmod +x your-project/.claude/burto.sh
```

Create `.claude/settings.json` in your project:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": ".*",
        "hooks": [
          {
            "type": "command",
            "command": "/absolute/path/to/your-project/.claude/burto.sh",
            "timeout": 15
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": ".*",
        "hooks": [
          {
            "type": "command",
            "command": "/absolute/path/to/your-project/.claude/burto.sh",
            "timeout": 15
          }
        ]
      }
    ],
    "Stop": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "/absolute/path/to/your-project/.claude/burto.sh",
            "timeout": 10
          }
        ]
      }
    ],
    "SessionStart": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "/absolute/path/to/your-project/.claude/burto.sh",
            "timeout": 10
          }
        ]
      }
    ]
  }
}
```

Then run Claude Code from inside your project:

```bash
cd your-project
claude
```

### OpenCode

OpenCode supports the same hook interface. Add to your `opencode.json`:

```json
{
  "hooks": {
    "before_tool": "/absolute/path/to/.claude/burto.sh",
    "after_tool":  "/absolute/path/to/.claude/burto.sh"
  }
}
```

> The hook script auto-detects the event type from the JSON payload on stdin,
> so the same script works for all hook events.

---

## 5. Environment variables for the hook script

| Variable | Default | Purpose |
|---|---|---|
| `BURTO_URL` | `http://localhost:8000` | Burto server address |
| `BURTO_BYPASS` | `0` | Set to `1` to disable Burto without removing the hooks |

Example — point at a remote Burto instance:

```bash
export BURTO_URL=http://your-server:8000
claude
```

---

## 6. What Burto intercepts

| Scenario | Hook | Action |
|---|---|---|
| Agent writes to a non-existent file | PreToolUse | STEER — provides closest real path |
| Agent installs a non-existent package | PreToolUse | STEER — flags hallucinated package name |
| Bash command with prompt injection | PreToolUse | BLOCK — injection rail (Nebius Nano) |
| Destructive command (`rm -rf /`) | PreToolUse | BLOCK — heuristic + LLM |
| Data exfiltration via curl pipe | PreToolUse | BLOCK — heuristic |
| Same tool called 3× without progress | PostToolUse | STEER — repetition_loop drift nudge |
| 4+ consecutive tool failures | PostToolUse | STEER — failure_spiral drift nudge |
| Session completes with unresolved drift | Stop | BLOCK — with LLM explanation |

---

## 7. Dashboard

Open [http://localhost:8000](http://localhost:8000) after any agent session to see:

- Per-session hallucination timeline (file, package, flag hallucinations)
- Drift timeline (repetition_loop, failure_spiral, tool_cycling)
- Full decision log with reasoning and latency
- One-click approve for blocked actions

---

## 8. Disable / bypass

To run a session without Burto intercepting:

```bash
BURTO_BYPASS=1 claude
```

To remove hooks entirely, delete `.claude/settings.json` from your project.
