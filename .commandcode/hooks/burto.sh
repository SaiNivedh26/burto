#!/usr/bin/env bash
# Burto hook dispatcher for cmdc (Command Code).
# Handles: PreToolUse, PostToolUse, Stop, SessionStart
# Reads hook payload from stdin, routes to the appropriate burto endpoint.

BURTO_URL="${BURTO_URL:-http://localhost:8000}"
[ "${BURTO_BYPASS:-0}" = "1" ] && exit 0

INPUT=$(cat)

# Detect hook event type
EVENT=$(printf '%s' "$INPUT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(d.get('hook_event_name', 'PreToolUse'))
" 2>/dev/null)
EVENT="${EVENT:-PreToolUse}"

# ── SessionStart ────────────────────────────────────────────────────────────────
if [ "$EVENT" = "SessionStart" ]; then
  PAYLOAD=$(printf '%s' "$INPUT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(json.dumps({
    'session_id':      d.get('session_id', 'default'),
    'transcript_path': d.get('transcript_path'),
    'cwd':             d.get('cwd', '.'),
    'hook_event_name': 'SessionStart',
}))
" 2>/dev/null)
  [ -n "$PAYLOAD" ] && printf '%s' "$PAYLOAD" | curl -sf -X POST \
    "$BURTO_URL/hook/sessionstart" -H "Content-Type: application/json" -d @- >/dev/null 2>&1
  exit 0
fi

# ── PostToolUse ────────────────────────────────────────────────────────────────
if [ "$EVENT" = "PostToolUse" ]; then
  PAYLOAD=$(printf '%s' "$INPUT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
# tool_response can be a string or a structured object
response = d.get('tool_response', '')
if isinstance(response, dict) or isinstance(response, list):
    response = json.dumps(response)
print(json.dumps({
    'session_id':      d.get('session_id', 'default'),
    'tool_name':       d.get('tool_name', 'unknown'),
    'tool_input':      d.get('tool_input', {}),
    'tool_response':   str(response)[:3000],
    'transcript_path': d.get('transcript_path'),
    'cwd':             d.get('cwd', '.'),
    'hook_event_name': 'PostToolUse',
}))
" 2>/dev/null)
  [ -z "$PAYLOAD" ] && exit 0

  RESPONSE=$(printf '%s' "$PAYLOAD" | curl -sf -X POST \
    "$BURTO_URL/hook/posttooluse" \
    -H "Content-Type: application/json" \
    -d @- 2>/dev/null)
  [ $? -ne 0 ] && exit 0
  [ -z "$RESPONSE" ] && exit 0

  # Check if there's an additionalContext nudge to inject
  NUDGE=$(printf '%s' "$RESPONSE" | python3 -c "
import sys, json
d = json.load(sys.stdin)
out = d.get('hookSpecificOutput', {})
print(out.get('additionalContext') or '')
" 2>/dev/null)

  if [ -n "$NUDGE" ]; then
    # Print drift warning to developer terminal via stderr
    printf '\n\033[33m╔══════════════════════════════════════════════════════════════╗\033[0m\n' >&2
    printf '\033[33m║  BURTO DRIFT DETECTED                                        ║\033[0m\n' >&2
    printf '\033[33m╚══════════════════════════════════════════════════════════════╝\033[0m\n' >&2
    printf '\033[33m%s\033[0m\n' "$NUDGE" >&2

    # Output additionalContext so the agent sees the nudge in its next reasoning step
    python3 -c "
import json, sys
nudge = sys.argv[1]
print(json.dumps({
    'hookSpecificOutput': {
        'hookEventName': 'PostToolUse',
        'additionalContext': nudge,
    }
}))
" "$NUDGE"
    exit 0
  fi

  # No drift — allow normally (empty hookSpecificOutput is fine)
  exit 0
fi

# ── Stop ────────────────────────────────────────────────────────────────────────
if [ "$EVENT" = "Stop" ]; then
  PAYLOAD=$(printf '%s' "$INPUT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(json.dumps({
    'session_id':        d.get('session_id', 'default'),
    'transcript_path':   d.get('transcript_path'),
    'cwd':               d.get('cwd', '.'),
    'stop_hook_active':  bool(d.get('stop_hook_active', False)),
    'hook_event_name':   'Stop',
}))
" 2>/dev/null)
  [ -z "$PAYLOAD" ] && exit 0

  RESPONSE=$(printf '%s' "$PAYLOAD" | curl -sf -X POST \
    "$BURTO_URL/hook/stop" \
    -H "Content-Type: application/json" \
    -d @- 2>/dev/null)
  [ $? -ne 0 ] && exit 0
  [ -z "$RESPONSE" ] && exit 0

  STOP_DECISION=$(printf '%s' "$RESPONSE" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(d.get('hookSpecificOutput', {}).get('decision', 'allow'))
" 2>/dev/null)

  STOP_REASON=$(printf '%s' "$RESPONSE" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(d.get('hookSpecificOutput', {}).get('reason', '') or '')
" 2>/dev/null)

  if [ "$STOP_DECISION" = "block" ]; then
    printf '\n\033[31m╔══════════════════════════════════════════════════════════════╗\033[0m\n' >&2
    printf '\033[31m║  BURTO STOP BLOCKED — goal drift at turn boundary            ║\033[0m\n' >&2
    printf '\033[31m╚══════════════════════════════════════════════════════════════╝\033[0m\n' >&2
    printf '\033[31m%s\033[0m\n' "$STOP_REASON" >&2

    python3 -c "
import json, sys
reason = sys.argv[1]
print(json.dumps({
    'hookSpecificOutput': {
        'hookEventName': 'Stop',
        'decision': 'block',
        'reason': reason,
    }
}))
" "$STOP_REASON"
    exit 0
  fi

  exit 0
fi

# ── PreToolUse (default) ───────────────────────────────────────────────────────
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

[ -z "$PAYLOAD" ] && exit 0

RESPONSE=$(printf '%s' "$PAYLOAD" | curl -sf -X POST \
  "$BURTO_URL/hook/pretooluse" \
  -H "Content-Type: application/json" \
  -d @- 2>/dev/null)

[ $? -ne 0 ] && exit 0
[ -z "$RESPONSE" ] && exit 0

ACTION=$(printf '%s' "$RESPONSE"     | python3 -c "import sys,json; print(json.load(sys.stdin).get('action','proceed'))" 2>/dev/null)
DECISION=$(printf '%s' "$RESPONSE"   | python3 -c "import sys,json; print(json.load(sys.stdin).get('decision','ALLOW'))" 2>/dev/null)
CTX=$(printf '%s' "$RESPONSE"        | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('escalation_context') or '')" 2>/dev/null)
REASONING=$(printf '%s' "$RESPONSE"  | python3 -c "import sys,json; print(json.load(sys.stdin).get('reasoning',''))" 2>/dev/null)
SOURCE=$(printf '%s' "$RESPONSE"     | python3 -c "import sys,json; print(json.load(sys.stdin).get('intent_source','inferred'))" 2>/dev/null)
CORRECTION=$(printf '%s' "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('correction') or '')" 2>/dev/null)
HALL_TYPE=$(printf '%s' "$RESPONSE"  | python3 -c "import sys,json; print(json.load(sys.stdin).get('hallucination_type') or '')" 2>/dev/null)

if [ "$ACTION" = "block" ]; then
  if [ "$DECISION" = "STEER" ]; then
    STEER_MSG="[burto/STEER] Hallucination intercepted (${HALL_TYPE}): ${CORRECTION}"

    printf '\n\033[36m╔══════════════════════════════════════════════════════════════╗\033[0m\n' >&2
    printf '\033[36m║  BURTO STEER — hallucination intercepted                     ║\033[0m\n' >&2
    printf '\033[36m║  Type     : %-50s║\033[0m\n' "${HALL_TYPE}" >&2
    printf '\033[36m║  Correction:                                                 ║\033[0m\n' >&2
    printf '\033[36m║  %-60s║\033[0m\n' "${CORRECTION:0:60}" >&2
    printf '\033[36m╚══════════════════════════════════════════════════════════════╝\033[0m\n' >&2

    python3 -c "
import json, sys
correction = sys.argv[1]
hall_type  = sys.argv[2]
msg = '[burto/STEER] ' + hall_type + ': ' + correction
print(json.dumps({
    'hookSpecificOutput': {
        'hookEventName': 'PreToolUse',
        'permissionDecision': 'deny',
        'permissionDecisionReason': msg,
    }
}))
" "$CORRECTION" "$HALL_TYPE"
    exit 0
  fi

  if [ -n "$CTX" ]; then
    REASON="$CTX"
  else
    REASON="[burto/$SOURCE] BLOCKED: $REASONING"
  fi

  printf '\n\033[33m%s\033[0m\n' "$REASON" >&2

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
