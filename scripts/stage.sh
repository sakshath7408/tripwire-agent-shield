#!/bin/sh
# One command before going on stage: clean daemon, empty dashboard, empty attacker inbox,
# dashboard open in presenter mode, and the exact commands to type next.
# Usage: scripts/stage.sh [port]        (NO_OPEN=1 skips opening the browser)
PORT="${1:-7777}"
URL="http://127.0.0.1:$PORT"
cd "$(dirname "$0")/.." || exit 1

G="$(printf '\033[32;1m')"; R="$(printf '\033[31;1m')"; B="$(printf '\033[1m')"; D="$(printf '\033[2m')"; N="$(printf '\033[0m')"

echo "${B}1. Restarting Tripwire on port $PORT${N}"
scripts/restart_daemon.sh "$PORT" || { echo "${R}Daemon did not start. Run: lsof -i :$PORT  then try a different port: scripts/stage.sh 7778${N}"; exit 1; }

echo "${B}2. Resetting the dashboard and the attacker's inbox${N}"
# Mutating endpoints need the per-install token the daemon wrote on start (TRIPWIRE_TOKEN wins, like the clients).
TOKEN="${TRIPWIRE_TOKEN:-$(cat "${TRIPWIRE_HOME:-$HOME/.tripwire}/token" 2>/dev/null)}"
[ -n "$TOKEN" ] || { echo "${R}No token at ${TRIPWIRE_HOME:-$HOME/.tripwire}/token. Is TRIPWIRE_HOME the same as the daemon's?${N}"; exit 1; }
curl -fs -X POST -H "X-Tripwire-Token: $TOKEN" "$URL/v1/reset" >/dev/null || { echo "${R}Reset failed (wrong token? the daemon and this shell must share TRIPWIRE_HOME)${N}"; exit 1; }
printf '[]' > demo/world/attacker_drop.json
echo "   ${G}clean${N}"

# The level is saved across restarts, so a rehearsal in strict would silently change the show. Pin it.
LEVEL="${AUTONOMY:-balanced}"
echo "${B}   Autonomy: $LEVEL${N} ${D}(AUTONOMY=strict scripts/stage.sh to change)${N}"
curl -fs -X PUT -H "X-Tripwire-Token: $TOKEN" -H "Content-Type: application/json" -d "{\"autonomy\": \"$LEVEL\"}" \
  "$URL/v1/settings" >/dev/null || { echo "${R}Could not set autonomy to $LEVEL${N}"; exit 1; }
# Learned rules survive a reset. They are yours, so list them instead of deleting them.
RULES="$(curl -fs -H "X-Tripwire-Token: $TOKEN" "$URL/v1/rules" 2>/dev/null)"
case "$RULES" in ""|"[]") echo "   ${G}no learned rules${N}";;
  *) echo "   ${R}learned rules exist; they can change what the demo asks. Check the dashboard's Learned rules:${N}"
     echo "$RULES" | head -c 400; echo;; esac

echo "${B}3. Opening the dashboard in presenter mode${N}"
# The dashboard pairs with a one-time code (no header or cookie trick can get it). Mint one for this browser.
CODE="$(curl -fs -X POST -H "X-Tripwire-Token: $TOKEN" "$URL/v1/pair/new" | sed -n 's/.*"code": *"\([^"]*\)".*/\1/p')"
DASH="$URL/?stage=1&theme=light#pair=$CODE"
if [ -z "$NO_OPEN" ]; then open "$DASH" 2>/dev/null || xdg-open "$DASH" 2>/dev/null || echo "   open $DASH by hand"; fi
echo "   $DASH"

EXTRA=""; [ "$PORT" != "7777" ] && EXTRA=" --url $URL"
cat <<EOF

${B}4. Next commands${N} ${D}(big font, attacker view next to the agent terminal)${N}

  ${B}Terminal 2, attacker's inbox (start now, leave it running):${N}
    uv run python demo/attacker_view.py --watch

  ${B}Act 1, no guard (the attack works):${N}
    uv run python demo/run_demo.py --scenario injected-doc --no-guard --delay 1

  ${B}Act 2, with Tripwire${N} ${D}(no cards appear: it blocks the attack on its own)${N}${B}:${N}
    uv run python demo/run_demo.py --scenario injected-doc --guard-only --delay 1 --approve dashboard$EXTRA

  ${B}It asks once${N} ${D}(card: saving the summary. Click "Always allow this"; it allows once, refuses to learn)${N}${B}:${N}
    uv run python demo/run_demo.py --scenario beyond-permission --guard-only --delay 0.6 --approve dashboard$EXTRA

  ${B}Proof:${N}
    cat bench/results/matrix.md

  ${B}If anything breaks:${N}
    uv run python demo/run_demo.py --scenario all --offline --delay 0 --approve auto
    Backup video: open docs/demo-video/tripwire-demo.mp4

EOF
