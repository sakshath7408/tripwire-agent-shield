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
curl -fs -X POST "$URL/v1/reset" >/dev/null || { echo "${R}Reset failed${N}"; exit 1; }
printf '[]' > demo/world/attacker_drop.json
echo "   ${G}clean${N}"

echo "${B}3. Opening the dashboard in presenter mode${N}"
DASH="$URL/?stage=1&theme=light"
if [ -z "$NO_OPEN" ]; then open "$DASH" 2>/dev/null || xdg-open "$DASH" 2>/dev/null || echo "   open $DASH by hand"; fi
echo "   $DASH"

EXTRA=""; [ "$PORT" != "7777" ] && EXTRA=" --url $URL"
cat <<EOF

${B}4. Next commands${N} ${D}(big font, attacker view next to the agent terminal)${N}

  ${B}Terminal 2, attacker's inbox (start now, leave it running):${N}
    uv run python demo/attacker_view.py --watch

  ${B}Act 1, no guard (the attack works):${N}
    uv run python demo/run_demo.py --scenario injected-doc --no-guard --delay 1

  ${B}Act 2, with Tripwire${N} ${D}(click Reset twice first; Block the SSH key, Allow .env both times)${N}${B}:${N}
    uv run python demo/run_demo.py --scenario injected-doc --guard-only --delay 1 --approve dashboard$EXTRA

  ${B}Beyond permission${N} ${D}(type y when it asks to save the summary)${N}${B}:${N}
    uv run python demo/run_demo.py --scenario beyond-permission --delay 0.6 --approve prompt$EXTRA

  ${B}Proof:${N}
    cat bench/results/summary.md

  ${B}If anything breaks:${N}
    uv run python demo/run_demo.py --scenario all --offline --delay 0 --approve auto
    Backup video: open docs/demo-video/tripwire-demo.mp4

EOF
