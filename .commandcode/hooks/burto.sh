#!/usr/bin/env bash
# Burto PreToolUse hook for cmdc (Command Code).
# Reads the hook payload from stdin, forwards to burto hook server,
# and outputs the proper cmdc JSON format on stdout.

BURTO_URL="${BURTO_URL:-http://localhost:8000}"
[ "${BURTO_BYPASS:-0}" = "1" ] && exit 0

INPUT=$(cat)

# Build the burto payload from cmdc's stdin fields.
PAYLOAD=$(printf '%s' "$INPUT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
out = {
    'session_id':      d.get('session_id', 'default'),
    'tool_name':       d.get('tool_name', 'unknown'),
    'tool_input':      d.get('tool_input', {}),
    'transcript_path': d.get('transcript_path'),
    'cwd':             d.get('cwd', '.'),
    'hook_event_name': d.get('hook_event_name'),
    'permission_mode': d.get('permission_mode'),
}
print(json.dumps(out))
" 2>/dev/null)

# If payload parsing failed, allow the action (fail open).
[ -z "$PAYLOAD" ] && exit 0

RESPONSE=$(printf '%s' "$PAYLOAD" | curl -sf -X POST \
  "$BURTO_URL/hook/pretooluse" \
  -H "Content-Type: application/json" \
  -d @- 2>/dev/null)

# Server unreachable — fail open.
[ $? -ne 0 ] && exit 0
[ -z "$RESPONSE" ] && exit 0

# Parse response fields.
ACTION=$(printf '%s' "$RESPONSE"    | python3 -c "import sys,json; print(json.load(sys.stdin).get('action','proceed'))" 2>/dev/null)
CTX=$(printf '%s' "$RESPONSE"       | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('escalation_context') or '')" 2>/dev/null)
REASONING=$(printf '%s' "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('reasoning',''))" 2>/dev/null)
SOURCE=$(printf '%s' "$RESPONSE"    | python3 -c "import sys,json; print(json.load(sys.stdin).get('intent_source','inferred'))" 2>/dev/null)

if [ "$ACTION" = "block" ]; then
  # Build the deny reason — include escalation context if available.
  if [ -n "$CTX" ]; then
    REASON="$CTX"
  else
    REASON="[burto/$SOURCE] BLOCKED: $REASONING"
  fi

  # Print the escalation box directly to the terminal via stderr.
  # cmdc may render permissionDecisionReason, but stderr is always visible.
  printf '\n\033[33m%s\033[0m\n' "$REASON" >&2

  # Output cmdc-format JSON with deny decision.
  python3 -c "
import json, sys
reason = sys.argv[1]
print(json.dumps({
    'hookSpecificOutput': {
        'hookEventName': 'PreToolUse',
        'permissionDecision': 'deny',
        'permissionDecisionReason': reason,
    }
}))
" "$REASON"
  exit 0
fi

# Allow — output valid cmdc JSON.
python3 -c "
import json
print(json.dumps({
    'hookSpecificOutput': {
        'hookEventName': 'PreToolUse',
        'permissionDecision': 'allow',
    }
}))
"
exit 0
