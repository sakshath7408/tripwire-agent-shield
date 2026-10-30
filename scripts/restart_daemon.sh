#!/bin/sh
# Restart the Tripwire daemon cleanly: wait for the old one to free the port before starting,
# then wait for the new one to answer. Usage: scripts/restart_daemon.sh [port] [extra serve flags...]
# Run from your own terminal, it prints a one-time dashboard link there (straight to the terminal, never to the
# log, so an agent can't read it). Run without a terminal (an agent, cron), no link is printed anywhere.
PORT="${1:-7777}"
[ $# -gt 0 ] && shift
cd "$(dirname "$0")/.." || exit 1
pkill -f "tripwire serve --port $PORT" 2>/dev/null
i=0; while lsof -ti tcp:"$PORT" >/dev/null 2>&1 && [ $i -lt 50 ]; do sleep 0.2; i=$((i+1)); done
umask 077  # the log is for you, not for other users or a world-readable /tmp
# fd 3 is this script's own stdout: the daemon writes the link there only if it is a real terminal.
nohup .venv/bin/tripwire serve --port "$PORT" --link-fd 3 "$@" 3>&1 > "/tmp/tripwire-$PORT.log" 2>&1 &
i=0; until curl -fs "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1; do
  sleep 0.2; i=$((i+1)); [ $i -ge 100 ] && { echo "Tripwire did not start, see /tmp/tripwire-$PORT.log"; exit 1; }
done
echo "Tripwire running on http://127.0.0.1:$PORT"
