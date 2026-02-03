#!/usr/bin/env bash
set -Eeuo pipefail

# paqet-watchdog.sh
# Cron runs this every 1 minute.
# If paqet process is not running OR screen missing OR runtime tail shows "Killed", restart.

MODE="${1:-}"
SCREEN_NAME="${2:-}"
BIN="${3:-}"
CFG="${4:-}"
RUNTIME_LOG="${5:-/root/paqet-runtime.log}"

ts(){ date +"%Y-%m-%d %H:%M:%S"; }
log(){ echo "$(ts) [WD] $*" >> /root/paqet-watchdog.log; }

screen_exists() { screen -ls 2>/dev/null | grep -q "[[:space:]]${SCREEN_NAME}[[:space:]]"; }
proc_running() { pgrep -fa "${BIN} run -c ${CFG}" >/dev/null 2>&1; }
last_line_killed() { tail -n 3 "$RUNTIME_LOG" 2>/dev/null | grep -qi "killed"; }

restart() {
  log "Restarting... mode=${MODE} screen=${SCREEN_NAME}"

  screen -wipe >/dev/null 2>&1 || true

  if screen_exists; then
    screen -S "$SCREEN_NAME" -X quit >/dev/null 2>&1 || true
    sleep 1
  fi

  screen -dmS "$SCREEN_NAME" bash -lc "
    cd /root
    echo '--- '\"\$(ts)\"' RESTART ${MODE} ---' >> '${RUNTIME_LOG}'
    chmod +x '${BIN}'
    '${BIN}' run -c '${CFG}' 2>&1 | tee -a '${RUNTIME_LOG}'
    echo '--- '\"\$(ts)\"' STOP ${MODE} (process ended) ---' >> '${RUNTIME_LOG}'
    sleep 2
  "

  log "Restart triggered."
}

main(){
  if [[ -z "$MODE" || -z "$SCREEN_NAME" || -z "$BIN" || -z "$CFG" ]]; then
    log "Invalid args. Usage: paqet-watchdog.sh <server|client> <screen_name> <bin_path> <cfg_path> <runtime_log>"
    exit 0
  fi

  if proc_running; then
    exit 0
  fi

  if ! screen_exists; then
    log "Screen missing. Restart needed."
    restart
    exit 0
  fi

  if last_line_killed; then
    log "Detected 'Killed' in runtime log tail. Restart needed."
    restart
    exit 0
  fi

  log "Process not running. Restart needed."
  restart
}

main
