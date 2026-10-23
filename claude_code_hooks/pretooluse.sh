#!/usr/bin/env bash
# Burto PreToolUse hook — cmdc, Claude Code, and any agent that sends PreToolUse.
# Reads the full hook payload from stdin, forwards to burto hook server.
# Exits 2 to block; prints escalation context to stderr.

BURTO_URL="${BURTO_URL:-http://localhost:8000}"
[ "${BURTO_BYPASS:-0}" = "1" ] && exit 0

INPUT=$(cat)

# Normalise payload: keep all fields burto understands, pass them through
PAYLOAD=$(echo "$INPUT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
out = {
    'session_id':      d.get('session_id', 'default'),
    'tool_name':       d.get('tool_name', d.get('name', 'unknown')),
    'tool_input':      d.get('tool_input', d.get('input', {})),
    'transcript_path': d.get('transcript_path'),
    'cwd':             d.get('cwd', '.'),
    'hook_event_name': d.get('hook_event_name'),
    'permission_mode': d.get('permission_mode'),
}
print(json.dumps(out))
" 2>/dev/null)

[ -z "$PAYLOAD" ] && exit 0

RESPONSE=$(echo "$PAYLOAD" | curl -sf -X POST \
  "$BURTO_URL/hook/pretooluse" \
  -H "Content-Type: application/json" \
  -d @- 2>/dev/null)

if [ $? -ne 0 ]; then
  # Server unreachable — fail open
  exit 0
fi

ACTION=$(echo "$RESPONSE"   | python3 -c "import sys,json; print(json.load(sys.stdin).get('action','proceed'))" 2>/dev/null)
CTX=$(echo "$RESPONSE"      | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('escalation_context') or '')" 2>/dev/null)
DECISION=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('decision','ALLOW'))" 2>/dev/null)
REASONING=$(echo "$RESPONSE"| python3 -c "import sys,json; print(json.load(sys.stdin).get('reasoning',''))" 2>/dev/null)
IMPACT=$(echo "$RESPONSE"   | python3 -c "import sys,json; print(json.load(sys.stdin).get('impact') or '')" 2>/dev/null)
SOURCE=$(echo "$RESPONSE"   | python3 -c "import sys,json; print(json.load(sys.stdin).get('intent_source','inferred'))" 2>/dev/null)

if [ "$ACTION" = "block" ]; then
  echo "" >&2
  if [ -n "$CTX" ]; then
    echo "$CTX" >&2
  else
    echo "[burto/$SOURCE] $DECISION: $REASONING" >&2
    [ -n "$IMPACT" ] && echo "[burto] Impact: $IMPACT" >&2
  fi
  echo "" >&2
  exit 2
fi

exit 0
