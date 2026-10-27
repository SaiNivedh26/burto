#!/usr/bin/env bash
# =============================================================================
# Burto Phase 2 integration tests — exercises every Phase 2 feature through
# the real hook endpoint (no mocking). Requires burto server on :8000 and
# a live nebius_api_key env var.
#
# Run from test-codebase/:
#   bash tests/phase2_integration_test.sh
#
# NOTE: Uses printf '%s' instead of echo to pipe JSON — this system's echo
# interprets \n escape sequences, corrupting JSON strings in responses.
# =============================================================================

set -uo pipefail

HOOK_URL="http://localhost:8000"
PASS=0
FAIL=0
CWD="$(cd "$(dirname "$0")/.." && pwd)"   # test-codebase root
SESSION="p2-integ-$(date +%s)"
# Separate session IDs for groups that test blocking — they must not share
# state with the main session (cache + session-memory would make blocks disappear).
SESSION_BLOCK="p2-block-$(date +%s)"
SESSION_POLICY="p2-policy-$(date +%s)"
TRANSCRIPT="/tmp/burto_p2_transcript_$$.jsonl"

# ── Color helpers ─────────────────────────────────────────────────────────────
green()  { printf "\033[32m  PASS\033[0m  %s\n" "$*"; }
red()    { printf "\033[31m  FAIL\033[0m  %s\n" "$*"; }
header() { printf "\n=== %s ===\n" "$*"; }

pass() { green "$1"; PASS=$((PASS+1)); }
fail() { red   "$1"; FAIL=$((FAIL+1)); }

assert_eq() {
  local label="$1" expected="$2" got="$3"
  [ "$got" = "$expected" ] && pass "$label (→ $got)" || fail "$label (expected '$expected', got '$got')"
}

assert_contains() {
  local label="$1" needle="$2" haystack="$3"
  printf '%s' "$haystack" | grep -q "$needle" \
    && pass "$label" \
    || fail "$label (needle='$needle' not found)"
}

assert_http() {
  local label="$1" code="$2" got="$3"
  [ "$got" = "$code" ] && pass "$label (HTTP $got)" || fail "$label (expected HTTP $code, got '$got')"
}

# ── Preflight ─────────────────────────────────────────────────────────────────
if ! curl -sf "$HOOK_URL/health" > /dev/null 2>&1; then
  printf "ERROR: Burto server not running on :8000\n"
  printf "  cd /home/sai-nivedh-26/nvidia-hack\n"
  printf "  PYTHONPATH=. nvd/bin/python -m uvicorn burto.hook_server:app --port 8000\n"
  exit 1
fi

if [ -z "${nebius_api_key:-}" ]; then
  printf "ERROR: nebius_api_key env var not set\n"
  printf "  set -a && source /home/sai-nivedh-26/nvidia-hack/.env && set +a\n"
  exit 1
fi

pass "Burto server reachable at $HOOK_URL"

# ── Transcript helper ─────────────────────────────────────────────────────────
write_transcript() {
  : > "$TRANSCRIPT"
  for turn in "$@"; do
    printf '{"type":"message","message":{"role":"user","content":[{"type":"text","text":"%s"}]}}\n' "$turn" >> "$TRANSCRIPT"
  done
}

# ── hook_call: POST payload, return raw JSON response ────────────────────────
# Optional 3rd arg overrides the session_id (for isolated block tests).
# IMPORTANT: Use printf '%s' (not echo) to pipe response — this system's echo
# interprets \n which corrupts JSON strings containing newlines.
hook_call() {
  local tool_name="$1"
  local tool_input_json="$2"
  local use_session="${3:-$SESSION}"
  python3 - <<PYEOF
import json, urllib.request, sys

payload = {
    "session_id":      "${use_session}",
    "transcript_path": "${TRANSCRIPT}",
    "cwd":             "${CWD}",
    "hook_event_name": "PreToolUse",
    "permission_mode": "default",
    "tool_name":       "${tool_name}",
    "tool_input":      json.loads("""${tool_input_json}"""),
}
req = urllib.request.Request(
    "${HOOK_URL}/hook/pretooluse",
    data=json.dumps(payload).encode(),
    headers={"Content-Type": "application/json"},
    method="POST",
)
try:
    with urllib.request.urlopen(req, timeout=45) as r:
        sys.stdout.buffer.write(r.read())
        sys.stdout.buffer.write(b"\n")
except urllib.error.HTTPError as e:
    sys.stdout.buffer.write(e.read())
    sys.stdout.buffer.write(b"\n")
PYEOF
}

# Extract a field from a JSON response captured in a variable.
# Uses printf '%s' to avoid echo mangling \n sequences.
jq_field() {
  local resp="$1" field="$2" default="${3:-}"
  printf '%s' "$resp" | python3 -c \
    "import sys,json; d=json.load(sys.stdin); print(d.get('${field}') or '${default}')" 2>/dev/null \
    || printf '%s' "$default"
}

# ── API helpers ───────────────────────────────────────────────────────────────
api_get_code() { curl -s -o /dev/null -w "%{http_code}" "${HOOK_URL}${1}"; }
api_get_body() { curl -sf "${HOOK_URL}${1}"; }
api_post()     { curl -sf -X POST "${HOOK_URL}${1}" -H "Content-Type: application/json" -d "${2:-{}}"; }
api_put()      { curl -sf -X PUT "${HOOK_URL}${1}?model=${2}"; }


# =============================================================================
# Group 1 — Dashboard routes (2A)
# =============================================================================
header "Group 1: Dashboard routes (2A)"

assert_http "GET / (sessions index)"   "200" "$(api_get_code /)"
assert_http "GET /projects"            "200" "$(api_get_code /projects)"
assert_http "GET /export"              "200" "$(api_get_code /export)"
assert_http "GET /export/json"         "200" "$(api_get_code /export/json)"
assert_http "GET /health"              "200" "$(api_get_code /health)"


# =============================================================================
# Group 2 — Real LLM call + SQLite persistence (2A + 2C)
# =============================================================================
header "Group 2: Real Nebius LLM call + store persistence"

write_transcript \
  "fix the failing unit tests in the auth module" \
  "run pytest on the test suite to see what is broken"

SAFE_RESP=$(hook_call "Bash" '{"command":"pytest tests/ -v"}')
SAFE_ACTION=$(jq_field "$SAFE_RESP" "action" "")
SAFE_TRACE=$(jq_field "$SAFE_RESP" "trace_id" "")

assert_eq  "safe pytest → allow" "proceed" "$SAFE_ACTION"
[ -n "$SAFE_TRACE" ] \
  && pass "trace_id set — real LangSmith trace: $SAFE_TRACE" \
  || fail "trace_id missing — LLM path not taken"

sleep 0.5
SESSIONS_BODY=$(api_get_body "/export/json")
assert_contains "decision recorded in SQLite" "$SESSION" "$SESSIONS_BODY"


# =============================================================================
# Group 3 — Session memory 60s window (2E)
# =============================================================================
header "Group 3: Session memory — approve a block → auto-allow within 60s"

write_transcript \
  "fix the login endpoint returning 401" \
  "deploy changes to the kubernetes cluster"

# Use an infra command — guaranteed ESCALATE/BLOCK via heuristic (no LLM needed)
BLOCK_CMD='{"command":"kubectl apply -f manifests/deployment.yaml"}'
BLOCK_RESP=$(hook_call "Bash" "$BLOCK_CMD" "$SESSION_BLOCK")
BLOCK_ACTION=$(jq_field "$BLOCK_RESP" "action" "")
DECISION_ID=$(jq_field "$BLOCK_RESP" "trace_id" "")

assert_eq "infra command → block" "block" "$BLOCK_ACTION"

sleep 1  # let background writer flush decision to SQLite before approve
if [ -n "$DECISION_ID" ]; then
  APPROVE_RESP=$(api_post "/decisions/$DECISION_ID/approve" '{}')
  assert_contains "approve endpoint returns status" "approved" "$APPROVE_RESP"

  sleep 0.3
  AUTO_RESP=$(hook_call "Bash" "$BLOCK_CMD" "$SESSION_BLOCK")
  AUTO_ACTION=$(jq_field "$AUTO_RESP" "action" "")
  AUTO_REASON=$(jq_field "$AUTO_RESP" "reasoning" "")
  assert_eq  "same command within 60s → auto-allow (session memory)" "proceed" "$AUTO_ACTION"
  assert_contains "reasoning mentions Auto-allowed" "Auto-allowed" "$AUTO_REASON"
else
  fail "no trace_id returned from block — cannot test session memory"
fi


# =============================================================================
# Group 4 — Decision cache (2B.1)
# =============================================================================
header "Group 4: Decision cache — same (session, input) 2nd call"

write_transcript "run the test suite again after fixing the import"

CACHE_CMD='{"command":"pytest tests/ -q --tb=short"}'
FIRST_RESP=$(hook_call "Bash" "$CACHE_CMD")

sleep 0.3

SECOND_RESP=$(hook_call "Bash" "$CACHE_CMD")
SECOND_ACTION=$(jq_field "$SECOND_RESP" "action" "")
SECOND_REASON=$(jq_field "$SECOND_RESP" "reasoning" "")

assert_eq "cache hit → still allow" "proceed" "$SECOND_ACTION"
assert_contains "cache hit reasoning" "Cache hit" "$SECOND_REASON"


# =============================================================================
# Group 5 — Four signals (2B)
# =============================================================================
header "Group 5: Four signals written to store"

if [ -n "${DECISION_ID:-}" ]; then
  REJECT=$(api_post "/decisions/$DECISION_ID/reject" '{}')
  assert_contains "reject signal" "rejected" "$REJECT"

  EDIT=$(curl -sf -X POST "$HOOK_URL/decisions/$DECISION_ID/signal" \
    -H "Content-Type: application/json" \
    -d '{"signal_type":"edit","label":"ALLOW","reasoning_label":"developer changed to dev config","edited_tool_input":{"file_path":"config/development.yaml","content":"debug: true"}}')
  assert_contains "edit signal" "ok" "$EDIT"

  PROMPT=$(curl -sf -X POST "$HOOK_URL/decisions/$DECISION_ID/signal" \
    -H "Content-Type: application/json" \
    -d '{"signal_type":"prompt","label":"BLOCK","reasoning_label":"user was debugging prod config"}')
  assert_contains "prompt signal" "ok" "$PROMPT"

  sleep 0.5
  EXPORT=$(api_get_body "/export/json")
  COUNT=$(printf '%s' "$EXPORT" | python3 -c \
    "import sys,json; rows=json.load(sys.stdin); print(len([r for r in rows if r.get('session_id')=='${SESSION}']))" 2>/dev/null)
  [ "${COUNT:-0}" -gt 0 ] \
    && pass "decisions with signals visible in export ($COUNT rows for this session)" \
    || fail "no decisions found for session $SESSION in export"
else
  fail "skipping signal tests — no DECISION_ID from group 3"
fi


# =============================================================================
# Group 6 — Nemotron model routing hot-swap (2C)
# =============================================================================
header "Group 6: Nemotron model routing — hot-swap via API"

# URL-encode the CWD path
CWD_ENC=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${CWD}', safe=''))")

# Upsert project first (needs at least one decision for the project to exist)
MODEL_BEFORE=$(api_get_body "/projects/${CWD_ENC}/model" 2>/dev/null \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('active_model',''))" 2>/dev/null \
  || printf "unknown")

# Hot-swap to nano
SWAP=$(api_put "/projects/${CWD_ENC}/model" "nano")
sleep 0.3
MODEL_AFTER=$(api_get_body "/projects/${CWD_ENC}/model" 2>/dev/null \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('active_model',''))" 2>/dev/null \
  || printf "unknown")
assert_eq "model hot-swapped to nano" "nano" "$MODEL_AFTER"

write_transcript "run a quick syntax check"
NANO_RESP=$(hook_call "Bash" '{"command":"python3 -m py_compile src/auth/jwt.py"}')
NANO_ACTION=$(jq_field "$NANO_RESP" "action" "")
assert_eq "call with nano routing succeeds" "proceed" "$NANO_ACTION"

# Restore to super
api_put "/projects/${CWD_ENC}/model" "super" > /dev/null 2>&1
pass "model restored to super"


# =============================================================================
# Group 7 — policy.yaml fast-path (2F)
# =============================================================================
header "Group 7: policy.yaml — allow/deny rules evaluated before LLM"

BURTO_DIR="$CWD/.burto"
POLICY_FILE="$BURTO_DIR/policy.yaml"
mkdir -p "$BURTO_DIR"

cat > "$POLICY_FILE" <<'YAML'
risk_tier: standard
model_active: super

allow:
  - tool: Bash
    pattern: "pytest"
    reason: "test commands always allowed"

deny:
  - tool: Bash
    pattern: "rm -rf"
    reason: "destructive delete blocked by policy"
YAML

write_transcript "run tests and clean up"

POL_ALLOW_RESP=$(hook_call "Bash" '{"command":"pytest tests/ -q"}' "$SESSION_POLICY")
POL_ALLOW_ACTION=$(jq_field "$POL_ALLOW_RESP" "action" "")
POL_ALLOW_REASON=$(jq_field "$POL_ALLOW_RESP" "reasoning" "")
assert_eq "policy allow rule → proceed" "proceed" "$POL_ALLOW_ACTION"
assert_contains "policy allow reasoning says Policy rule matched" "Policy rule matched" "$POL_ALLOW_REASON"

POL_DENY_RESP=$(hook_call "Bash" '{"command":"rm -rf /tmp/junk"}' "$SESSION_POLICY")
POL_DENY_ACTION=$(jq_field "$POL_DENY_RESP" "action" "")
POL_DENY_REASON=$(jq_field "$POL_DENY_RESP" "reasoning" "")
assert_eq "policy deny rule → block" "block" "$POL_DENY_ACTION"
assert_contains "policy deny reasoning says Policy rule matched" "Policy rule matched" "$POL_DENY_REASON"

POLICY_API=$(api_get_body "/projects/${CWD_ENC}/policy")
assert_contains "policy API returns rule_count" "rule_count" "$POLICY_API"

rm -f "$POLICY_FILE"
rmdir "$BURTO_DIR" 2>/dev/null || true


# =============================================================================
# Group 8 — Dashboard shows test session
# =============================================================================
header "Group 8: Dashboard shows this test session"

sleep 0.8
INDEX=$(api_get_body "/")
assert_contains "session on dashboard index" "$SESSION" "$INDEX"

assert_http "session detail page" "200" "$(api_get_code /sessions/$SESSION)"


# =============================================================================
# Results
# =============================================================================
rm -f "$TRANSCRIPT"
printf "\n─────────────────────────────────────────────\n"
printf "  %d passed, %d failed\n" "$PASS" "$FAIL"
printf "─────────────────────────────────────────────\n"

if [ "$FAIL" -gt 0 ]; then
  printf "\nRe-run with verbose output:\n"
  printf "  bash tests/phase2_integration_test.sh 2>&1 | tee /tmp/p2_run.log\n"
fi

[ "$FAIL" -eq 0 ] && exit 0 || exit 1
