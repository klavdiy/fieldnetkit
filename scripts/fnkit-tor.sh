#!/usr/bin/env bash
# Local Tor for FNkit — SOCKS 127.0.0.1:9050, optional obfs4 bridges.
# Usage: ./scripts/fnkit-tor.sh {start|start-bridges|stop|status}
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DATA_DIR="$REPO_ROOT/data"
CONFIG_DIR="$DATA_DIR/config"
TOR_DAEMON_DIR="$DATA_DIR/cache/tor_daemon"
TORRC="$CONFIG_DIR/tor/fnkit-torrc"
PIDFILE="$TOR_DAEMON_DIR/tor.pid"
BRIDGES_FILE="$CONFIG_DIR/tor_bridges.txt"
SOCKS_HOST="127.0.0.1"
SOCKS_PORT="9050"

find_tor() {
  if command -v tor >/dev/null 2>&1; then
    command -v tor
    return 0
  fi
  if [[ "$(uname -s)" == "Darwin" ]] && command -v brew >/dev/null 2>&1; then
    local p
    p="$(brew --prefix tor 2>/dev/null)/bin/tor" || true
    if [[ -x "$p" ]]; then
      echo "$p"
      return 0
    fi
  fi
  return 1
}

find_obfs4proxy() {
  if command -v obfs4proxy >/dev/null 2>&1; then
    command -v obfs4proxy
    return 0
  fi
  if [[ "$(uname -s)" == "Darwin" ]] && command -v brew >/dev/null 2>&1; then
    local p
    p="$(brew --prefix obfs4proxy 2>/dev/null)/bin/obfs4proxy" || true
    if [[ -x "$p" ]]; then
      echo "$p"
      return 0
    fi
  fi
  return 1
}

socks_up() {
  if command -v nc >/dev/null 2>&1; then
    nc -z "$SOCKS_HOST" "$SOCKS_PORT" 2>/dev/null
    return $?
  fi
  (echo >/dev/tcp/"$SOCKS_HOST"/"$SOCKS_PORT") >/dev/null 2>&1
}

write_torrc() {
  local use_bridges="${1:-0}"
  mkdir -p "$CONFIG_DIR/tor" "$TOR_DAEMON_DIR"
  cat >"$TORRC" <<EOF
# FNkit local Tor (not system-wide)
SocksPort ${SOCKS_HOST}:${SOCKS_PORT}
DataDirectory ${TOR_DAEMON_DIR}
PidFile ${PIDFILE}
Log notice file ${TOR_DAEMON_DIR}/tor.log
AvoidDiskWrites 1
EOF
  if [[ -n "${FNKIT_TOR_EXIT_NODES:-}" ]]; then
    echo "ExitNodes ${FNKIT_TOR_EXIT_NODES}" >>"$TORRC"
    echo "StrictNodes 1" >>"$TORRC"
  fi
  if [[ "$use_bridges" == "1" && -f "$BRIDGES_FILE" ]]; then
    echo "UseBridges 1" >>"$TORRC"
    if grep -qi obfs4 "$BRIDGES_FILE" 2>/dev/null; then
      local obfs
      if obfs="$(find_obfs4proxy)"; then
        echo "ClientTransportPlugin obfs4 exec ${obfs}" >>"$TORRC"
      else
        echo "[fnkit-tor] warning: obfs4 bridges in file but obfs4proxy not found (brew install obfs4proxy)" >&2
      fi
    fi
    grep -v '^[[:space:]]*#' "$BRIDGES_FILE" | grep -v '^[[:space:]]*$' >>"$TORRC"
  fi
}

start_tor() {
  local mode="${1:-start}"
  local use_bridges=0
  if [[ "$mode" == "start-bridges" ]]; then
    use_bridges=1
  fi
  if socks_up; then
    echo "[fnkit-tor] SOCKS already listening on ${SOCKS_HOST}:${SOCKS_PORT}"
    return 0
  fi
  local torbin
  torbin="$(find_tor)" || {
    echo "[fnkit-tor] tor not found. Install: brew install tor  |  apt install tor" >&2
    exit 1
  }
  if [[ -f "$PIDFILE" ]]; then
    local oldpid
    oldpid="$(cat "$PIDFILE" 2>/dev/null || true)"
    if [[ -n "$oldpid" ]] && kill -0 "$oldpid" 2>/dev/null; then
      echo "[fnkit-tor] Tor already running (pid $oldpid)"
      return 0
    fi
    rm -f "$PIDFILE"
  fi
  write_torrc "$use_bridges"
  echo "[fnkit-tor] Starting Tor ($torbin)…"
  "$torbin" -f "$TORRC" &
  local i=0
  while ! socks_up; do
    sleep 1
    i=$((i + 1))
    if [[ $i -ge 90 ]]; then
      echo "[fnkit-tor] Timeout waiting for SOCKS (see ${TOR_DAEMON_DIR}/tor.log)" >&2
      exit 1
    fi
  done
  echo "[fnkit-tor] SOCKS ready at ${SOCKS_HOST}:${SOCKS_PORT}"
  if [[ "$use_bridges" == "0" ]]; then
    echo "[fnkit-tor] Tip: if direct Tor is blocked, add bridges to ${BRIDGES_FILE} and run: $0 start-bridges"
  fi
}

stop_tor() {
  if [[ -f "$PIDFILE" ]]; then
    local pid
    pid="$(cat "$PIDFILE" 2>/dev/null || true)"
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      sleep 1
      kill -9 "$pid" 2>/dev/null || true
      echo "[fnkit-tor] Stopped Tor (pid $pid)"
    fi
    rm -f "$PIDFILE"
  else
    pkill -f "tor -f ${TORRC}" 2>/dev/null || true
    echo "[fnkit-tor] No pidfile; attempted pattern stop"
  fi
}

status_tor() {
  echo "SOCKS ${SOCKS_HOST}:${SOCKS_PORT}: $(socks_up && echo up || echo down)"
  if [[ -f "$PIDFILE" ]]; then
    echo "Pidfile: $(cat "$PIDFILE" 2>/dev/null || echo '?')"
  fi
  if [[ -f "$TOR_DAEMON_DIR/tor.log" ]]; then
    echo "Log tail:"
    tail -n 5 "$TOR_DAEMON_DIR/tor.log" 2>/dev/null || true
  fi
  if [[ -f "$BRIDGES_FILE" ]]; then
    echo "Bridges file: present ($BRIDGES_FILE)"
  else
    echo "Bridges file: missing (copy from tor_bridges.txt.example)"
  fi
}

ACTION="${1:-status}"
case "$ACTION" in
  start) start_tor start ;;
  start-bridges) start_tor start-bridges ;;
  stop) stop_tor ;;
  status) status_tor ;;
  *)
    echo "Usage: $0 {start|start-bridges|stop|status}" >&2
    exit 2
    ;;
esac
