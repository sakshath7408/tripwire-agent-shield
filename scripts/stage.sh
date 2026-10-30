#!/bin/sh
# One command before going on stage: clean daemon, empty dashboard, empty attacker inbox,
# dashboard open in presenter mode, and the exact commands to type next.
# Usage: scripts/stage.sh [port]        (NO_OPEN=1 skips opening the browser)
PORT="${1:-7777}"
URL="http://127.0.0.1:$PORT"
cd "$(dirname "$0")/.." || exit 1

G="$(printf '\033[32;1m')"; R="$(printf '\033[31;1m')"; B="$(printf '\033[1m')"; D="$(printf '\033[2m')"; N="$(printf '\033[0m')"

# The level is saved across restarts, so a rehearsal in strict would silently change the show. Pin it.
LEVEL="${AUTONOMY:-balanced}"
echo "${B}1. Restarting Tripwire on port $PORT with an empty view${N} ${D}(autonomy: $LEVEL; AUTONOMY=strict scripts/stage.sh to change)${N}"
# There is no admin key to script against any more: the daemon itself starts clean (--clear-view, attacks stay
# remembered) at the pinned level, and prints a one-time presenter link straight to this terminal.
scripts/restart_daemon.sh "$PORT" --clear-view --autonomy "$LEVEL" --link-path "/?stage=1&theme=light" \
  || { echo "${R}Daemon did not start. Run: lsof -i :$PORT  then try a different port: scripts/stage.sh 7778${N}"; exit 1; }

echo "${B}2. Emptying the attacker's inbox${N}"
printf '[]' > demo/world/attacker_drop.json
echo "   ${G}clean${N}"
# Learned rules survive a reset. They are yours, so list them instead of deleting them.
RULES="$(grep -c '^- ' "${TRIPWIRE_HOME:-$HOME/.tripwire}/learned.yaml" 2>/dev/null)"
case "$RULES" in ""|0) echo "   ${G}no learned rules${N}";;
  *) echo "   ${R}$RULES learned rule(s) exist; they can change what the demo asks. Check the dashboard's Learned rules.${N}";; esac

echo "${B}3. Opening the dashboard in presenter mode${N}"
DASH="$URL/?stage=1&theme=light"
echo "   If this browser is not paired yet, Cmd-click the one-time link printed above (it opens presenter mode)."
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
