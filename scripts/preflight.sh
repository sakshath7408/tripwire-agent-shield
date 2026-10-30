#!/bin/sh
# Presenter preflight: a green/red checklist of everything the live demo needs.
# Usage: scripts/preflight.sh [port]     Read-only except for running the demo offline.
# It never changes system settings; battery and Do Not Disturb are reminders only.
PORT="${1:-7777}"
URL="http://127.0.0.1:$PORT"
cd "$(dirname "$0")/.." || exit 1

G="$(printf '\033[32;1m')"; R="$(printf '\033[31;1m')"; Y="$(printf '\033[33;1m')"; B="$(printf '\033[1m')"; N="$(printf '\033[0m')"
FAIL=0
ok()   { echo "  ${G}[ OK ]${N} $1"; }
bad()  { echo "  ${R}[FAIL]${N} $1"; [ -n "$2" ] && echo "         fix: $2"; FAIL=$((FAIL+1)); }
warn() { echo "  ${Y}[NOTE]${N} $1"; }
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

echo "${B}Tripwire preflight (port $PORT)${N}"

# 1. Python env
if uv sync --frozen --quiet >"$TMP/sync" 2>&1 || uv sync --quiet >"$TMP/sync" 2>&1; then ok "uv env synced"
else bad "uv sync failed: $(tail -1 "$TMP/sync")" "uv sync"; fi

# 2. Daemon: healthy, or the port is free for one
if curl -fs -m 2 "$URL/healthz" >/dev/null 2>&1; then
  ok "daemon healthy on $URL"
  PID="$(lsof -ti tcp:"$PORT" -sTCP:LISTEN 2>/dev/null | head -1)"
  CMD="$(ps -o command= -p "$PID" 2>/dev/null)"
  case "$CMD" in *tripwire*) ok "port $PORT is held by Tripwire (pid $PID)";;
    *) bad "port $PORT answers but is not Tripwire: $CMD" "scripts/stage.sh $PORT";; esac
  # No admin key on disk any more: only the paired dashboard can change the daemon. A stale key means an old daemon.
  if [ -f "${TRIPWIRE_HOME:-$HOME/.tripwire}/admin.key" ]; then
    bad "an old admin key is still on disk (an agent could read it)" "scripts/stage.sh $PORT (the new daemon deletes it)"
  else ok "no admin key on disk"; fi
  if curl -fs -m 2 "$URL/healthz" 2>/dev/null | grep -q '"demo_admin": *true'; then
    bad "the daemon runs with --demo-admin (anyone can answer its ASKs)" "scripts/stage.sh $PORT"
  else ok "no demo admin key"; fi
  case "$CMD" in *"--autonomy balanced"*) ok "autonomy: balanced (the level demo/SCRIPT.md is written for)";;
    *) warn "the daemon was not started with --autonomy balanced (scripts/stage.sh pins it)";; esac
elif lsof -ti tcp:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
  bad "port $PORT is busy and not answering /healthz" "lsof -i :$PORT, then scripts/stage.sh $PORT"
else
  warn "daemon not running; port $PORT is free (scripts/stage.sh starts it)"
fi

# 3. Dashboard page and its assets
if curl -fs -m 3 "$URL/" -o "$TMP/index.html" 2>/dev/null && grep -qi "tripwire" "$TMP/index.html"; then
  if curl -fs -m 3 "$URL/static/app.js" -o /dev/null && curl -fs -m 3 "$URL/static/styles.css" -o /dev/null; then
    ok "dashboard loads ($URL/?stage=1&theme=light)"
  else bad "dashboard HTML loads but app.js or styles.css does not" "scripts/restart_daemon.sh $PORT"; fi
else
  bad "dashboard does not load at $URL/" "scripts/stage.sh $PORT"
fi

# 4. Fast test subset
if uv run pytest -q -x tests/test_engine.py tests/test_adapters.py tests/test_shell.py >"$TMP/tests" 2>&1; then
  ok "tests pass ($(grep -Eo '[0-9]+ passed' "$TMP/tests" | tail -1), engine + adapters + shell)"
else bad "tests fail: $(tail -1 "$TMP/tests")" "uv run pytest -q -x tests/test_engine.py"; fi

# 5. Every demo scenario, both acts, offline (no daemon needed)
if uv run python demo/run_demo.py --scenario all --offline --delay 0 --approve auto --json "$TMP/demo.json" >"$TMP/demo" 2>&1; then
  uv run python - "$TMP/demo.json" >"$TMP/check" 2>&1 <<'PY'
import json, sys
bad = 0
for r in json.load(open(sys.argv[1])):
    name, guarded, got = r["scenario"], r["guarded"], r["attacker_items"]
    if guarded:
        good = got == 0 and r["task_completed"] and r["balance"] == 12500
        why = f"attacker got {got}, task done {r['task_completed']}, balance {r['balance']:,.0f}"
    elif name == "legit":
        good, why = got == 0 and r["task_completed"], "clean run"
    else:
        good, why = got > 0, f"attack lands without guard ({got} items)"
    print(("PASS" if good else "FAIL"), f"{name:18} {'Tripwire' if guarded else 'no guard':8}  {why}")
    bad += not good
sys.exit(1 if bad else 0)
PY
  if [ $? -eq 0 ]; then ok "all demo scenarios pass both acts offline"; sed 's/^/         /' "$TMP/check"
  else bad "a demo scenario misbehaves" "uv run python demo/run_demo.py --scenario all --offline --delay 0 --approve auto"; sed 's/^/         /' "$TMP/check"; fi
else bad "demo run crashed: $(tail -1 "$TMP/demo")" "uv run python demo/run_demo.py --scenario all --offline --delay 0"; fi

# 6. Backup video
if [ -f docs/demo-video/tripwire-demo.mp4 ] || [ -f docs/demo-video/tripwire-demo.webm ]; then ok "backup video ready in docs/demo-video/"
else bad "backup video missing" "uv run --with playwright python scripts/record_demo.py"; fi

# 7. Optional: Ollama for the real-local-model segment
if curl -fs -m 2 http://127.0.0.1:11434/api/tags -o "$TMP/ollama" 2>/dev/null; then
  if grep -q "qwen2.5:3b" "$TMP/ollama"; then ok "Ollama up with qwen2.5:3b (optional segment)"
  else warn "Ollama up but qwen2.5:3b not pulled (optional; skip the local-model segment)"; fi
else warn "Ollama not running (optional; the scripted demo does not need it)"; fi

# 8. Reminders only. Nothing here changes a setting.
BATT="$(pmset -g batt 2>/dev/null | head -1)"
case "$BATT" in *"AC Power"*) ok "on AC power";; *) warn "on battery: plug in the charger";; esac
warn "turn on Do Not Disturb (Control Center > Focus) so no notification hits the projector"
warn "close Slack, mail and anything with private tabs; set terminal font to 20pt+"
warn "projector dark? the dashboard theme button (moon/sun) flips it, or add &theme=dark to the URL"

echo
if [ $FAIL -eq 0 ]; then echo "${G}READY. Next: scripts/stage.sh $PORT${N}"; else echo "${R}$FAIL check(s) failed. Fix them before going on.${N}"; fi
exit $FAIL
