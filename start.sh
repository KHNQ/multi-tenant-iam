#!/usr/bin/env bash
#
# Boots the whole IAM stack in dependency order:
#
#   Redis (:7000) -> Service Registry (:3001) -> LLM (:8080) -> Vision (:8081) -> Gateway (:3000)
#
# The order matters: the mock services self-register with the registry at
# startup, and the gateway pulls its routing table from the registry on boot.
#
# Usage:
#   ./start.sh            start everything (detached) and wait until healthy
#   ./start.sh stop       stop the four node servers
#   ./start.sh restart    stop, then start
#   ./start.sh status     show what is currently up
#   ./start.sh logs       tail the combined structured log
#
# Three settings have no default and must be supplied — exported, or in a .env
# file next to this script (see .env.example):
#   JWT_SECRET                  the gateway's token signing key
#   UPSTREAM_ALLOWED_CIDRS      the networks services may be registered in and
#                               proxied to
#   REGISTRY_ENROLLMENT_TOKEN   what the mock services present to register
#                               themselves with the registry
#
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN_DIR="$ROOT/.run"
LOG_DIR="$ROOT/logs"
REDIS_PORT="${REDIS_PORT:-7000}"

mkdir -p "$RUN_DIR" "$LOG_DIR"
cd "$ROOT" || exit 1

# Local, untracked configuration. Anything already exported wins, so a real
# deployment can inject its secrets however it normally does.
if [[ -f "$ROOT/.env" ]]; then
  while IFS= read -r line || [[ -n "$line" ]]; do
    key="${line%%=*}"
    [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || continue   # comments, blanks
    [[ -n "${!key+x}" ]] || export "$key=${line#*=}"
  done <"$ROOT/.env"
fi

INITIAL_ADMIN_PASSWORD_FILE="${INITIAL_ADMIN_PASSWORD_FILE:-$RUN_DIR/initial-admin-password}"
export INITIAL_ADMIN_PASSWORD_FILE

# name | script | port | readiness URL | marker that must appear in the response
#
# The marker matters: an unrelated dev server squatting on one of these ports
# will happily return 200 for any path, so "it answered" is not proof that the
# thing answering is ours.
SERVICES=(
  "registry|src/registery.js|3001|http://localhost:3001/health|registeredServices"
  "llm|src/llm.reg.js|8080|http://localhost:8080/catalog|ai_team"
  "vision|src/vision.reg.js|8081|http://localhost:8081/catalog|cv_team"
  "gateway|src/main.reg.js|3000|http://localhost:3000/docs.json|openapi"
)

BOLD=$'\033[1m'; DIM=$'\033[2m'; GREEN=$'\033[32m'; RED=$'\033[31m'
YELLOW=$'\033[33m'; CYAN=$'\033[36m'; RESET=$'\033[0m'

ok()   { printf "  %s✔%s %s\n" "$GREEN" "$RESET" "$1"; }
warn() { printf "  %s!%s %s\n" "$YELLOW" "$RESET" "$1"; }
fail() { printf "  %s✘%s %s\n" "$RED" "$RESET" "$1"; }
step() { printf "\n%s%s%s\n" "$BOLD" "$1" "$RESET"; }

# --- helpers ----------------------------------------------------------------

pid_file() { echo "$RUN_DIR/$1.pid"; }

# A pid file can outlive its process (crash, kill -9, reboot). Treat it as
# authoritative only if the pid is still alive.
running_pid() {
  local f; f="$(pid_file "$1")"
  [[ -f "$f" ]] || return 1
  local pid; pid="$(cat "$f" 2>/dev/null)"
  [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null || return 1
  echo "$pid"
}

# Is *our* service answering here? Body must contain the expected marker.
service_alive() {
  local url="$1" marker="$2"
  curl -fsS --max-time 2 "$url" 2>/dev/null | grep -q "$marker"
}

# Anything at all bound to this port? curl exits 7 on connection refused.
port_busy() {
  curl -s -o /dev/null --max-time 1 "http://localhost:$1/" 2>/dev/null
  [[ $? -ne 7 ]]
}

wait_for_service() {
  local url="$1" marker="$2" tries="${3:-60}"
  for ((i = 0; i < tries; i++)); do
    service_alive "$url" "$marker" && return 0
    sleep 0.25
  done
  return 1
}

# --- redis ------------------------------------------------------------------

ensure_redis() {
  step "Redis"
  if redis-cli -p "$REDIS_PORT" ping >/dev/null 2>&1; then
    ok "already running on port $REDIS_PORT"
    return 0
  fi

  if ! command -v redis-server >/dev/null 2>&1; then
    fail "redis-server not found on PATH — install Redis, or start it yourself on port $REDIS_PORT"
    return 1
  fi

  warn "not running — starting redis-server on port $REDIS_PORT"
  redis-server --port "$REDIS_PORT" --daemonize yes --logfile "$LOG_DIR/redis.log" \
    || { fail "redis-server failed to start (see $LOG_DIR/redis.log)"; return 1; }

  for ((i = 0; i < 20; i++)); do
    redis-cli -p "$REDIS_PORT" ping >/dev/null 2>&1 && { ok "started on port $REDIS_PORT"; return 0; }
    sleep 0.25
  done
  fail "redis did not answer PING within 5s"
  return 1
}

# --- node servers -----------------------------------------------------------

start_one() {
  local name="$1" script="$2" port="$3" url="$4" marker="$5"

  if running_pid "$name" >/dev/null; then
    ok "$name already running (pid $(running_pid "$name"), port $port)"
    return 0
  fi

  # An orphan from a previous run whose pid file we lost: it's genuinely our
  # service, so leave it be rather than fighting it for the port.
  if service_alive "$url" "$marker"; then
    warn "$name already up on port $port (not started by this script) — leaving it alone"
    return 0
  fi

  # Port taken by something that is *not* ours. Node would fail with EADDRINUSE
  # a second from now; saying it here is clearer.
  if port_busy "$port"; then
    fail "$name cannot start — port $port is occupied by another process:"
    ss -ltnp 2>/dev/null | grep ":$port " | sed 's/^/      /'
    printf "      %sfree that port and try again (this port is hard-coded in %s).%s\n" "$DIM" "$script" "$RESET"
    return 1
  fi

  local boot_log="$LOG_DIR/boot-$name.log"
  # Background `node` directly — no subshell, no `&&` list. Chaining anything
  # before it makes `$!` the pid of the intermediate subshell rather than of
  # node itself, and then `stop` kills a wrapper while the server lives on.
  nohup node "$script" >"$boot_log" 2>&1 &
  local pid=$!
  echo "$pid" >"$(pid_file "$name")"

  if wait_for_service "$url" "$marker" 60; then
    ok "$name up on port $port (pid $pid)"
    return 0
  fi

  fail "$name failed to become ready on port $port — last lines of $boot_log:"
  tail -n 15 "$boot_log" | sed 's/^/      /'
  return 1
}

# Three settings have no built-in value, on purpose — each default would be a
# secret printed in this repository, or a rule that allows the one thing it is
# there to prevent. Checked here, together, so the reason is the first thing
# printed rather than something to dig out of a boot log after half the stack
# has come up, and so a first run reports everything that is missing at once.
require_configuration() {
  local missing=0
  problem() {
    [[ $missing -eq 0 ]] && step "Configuration"
    missing=1
    fail "$1"
    printf "        %s\n" "$2"
  }

  # The gateway refuses to boot without a signing key.
  if [[ -z "${JWT_SECRET:-}" ]]; then
    problem "JWT_SECRET is not set — the gateway has no default signing key and will not start without one" \
      'echo "JWT_SECRET=$(openssl rand -base64 48)" >> .env'
  elif [[ ${#JWT_SECRET} -lt 32 ]]; then
    problem "JWT_SECRET is too short (${#JWT_SECRET} chars) — it must be at least 32" \
      'echo "JWT_SECRET=$(openssl rand -base64 48)" >> .env'
  fi

  # Nothing is reachable through the gateway, and nothing can be registered,
  # until somebody says which networks services live in. The convenient
  # default (loopback) is exactly where Redis and the registry are.
  if [[ -z "${UPSTREAM_ALLOWED_CIDRS:-}" ]]; then
    problem "UPSTREAM_ALLOWED_CIDRS is not set — the registry and gateway would refuse every service destination" \
      'echo "UPSTREAM_ALLOWED_CIDRS=127.0.0.0/8,::1/128" >> .env     # this local stack only'
  fi

  # The registry creates records only for callers it can authenticate. The
  # mock services in this stack register themselves, so they need the
  # enrollment token — and so does the registry, to recognise it.
  if [[ -z "${REGISTRY_ENROLLMENT_TOKEN:-}" ]]; then
    problem "REGISTRY_ENROLLMENT_TOKEN is not set — the mock services could not register themselves" \
      'echo "REGISTRY_ENROLLMENT_TOKEN=$(openssl rand -hex 32)" >> .env'
  elif [[ ${#REGISTRY_ENROLLMENT_TOKEN} -lt 32 ]]; then
    problem "REGISTRY_ENROLLMENT_TOKEN is too short (${#REGISTRY_ENROLLMENT_TOKEN} chars) — it must be at least 32" \
      'echo "REGISTRY_ENROLLMENT_TOKEN=$(openssl rand -hex 32)" >> .env'
  fi

  if [[ $missing -ne 0 ]]; then
    printf "\n      %sthese go in .env (untracked) or the environment — see .env.example%s\n" "$DIM" "$RESET"
    return 1
  fi
}

start_all() {
  require_configuration || exit 1
  ensure_redis || exit 1

  step "Services"
  for entry in "${SERVICES[@]}"; do
    IFS='|' read -r name script port url marker <<<"$entry"
    start_one "$name" "$script" "$port" "$url" "$marker" || {
      fail "boot aborted at '$name'"
      exit 1
    }
  done

  step "Ready"
  cat <<EOF
  ${CYAN}Console${RESET}         http://localhost:3000/    ${DIM}(one sign-in; panels follow your account)${RESET}
  ${CYAN}API docs${RESET}        http://localhost:3000/docs
  ${CYAN}Registry${RESET}        http://localhost:3001/services
EOF
  # Present only until the initial admin has replaced their one-time password.
  if [[ -f "$INITIAL_ADMIN_PASSWORD_FILE" ]]; then
    printf "  %sFirst login%s     user 'admin', one-time password in %s\n" \
      "$CYAN" "$RESET" "${INITIAL_ADMIN_PASSWORD_FILE#"$ROOT"/}"
    printf "                  %s(must be changed at first login; the file is removed once it has been)%s\n" \
      "$DIM" "$RESET"
  fi
  cat <<EOF

  ${DIM}run tests:${RESET}      ADMIN_PASSWORD=<admin password> npm run e2e   ${DIM}(or put ADMIN_PASSWORD in .env)${RESET}
  ${DIM}check routes:${RESET}   ADMIN_PASSWORD=<admin password> npm run check:endpoints
  ${DIM}tail logs:${RESET}      ./start.sh logs
  ${DIM}shut down:${RESET}      ./start.sh stop
EOF
}

stop_all() {
  step "Stopping"
  local any=0
  # Reverse order: gateway first, registry last, so nothing is proxying to a
  # service that just vanished.
  for ((i = ${#SERVICES[@]} - 1; i >= 0; i--)); do
    IFS='|' read -r name _ port url marker <<<"${SERVICES[$i]}"
    local pid
    if pid="$(running_pid "$name")"; then
      kill "$pid" 2>/dev/null
      for ((t = 0; t < 20; t++)); do
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.25
      done
      kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null
      any=1
      # Don't just trust the kill — confirm the port actually went quiet.
      if service_alive "$url" "$marker"; then
        fail "$name still answering on port $port after killing pid $pid"
      else
        ok "$name stopped (was pid $pid, port $port)"
      fi
    elif service_alive "$url" "$marker"; then
      warn "$name is up on port $port but was not started by this script — not touching it"
    else
      printf "  %s·%s %s not running\n" "$DIM" "$RESET" "$name"
    fi
    rm -f "$(pid_file "$name")"
  done
  [[ $any -eq 0 ]] && warn "nothing was running"
  printf "\n  %sRedis was left running on port %s.%s\n" "$DIM" "$REDIS_PORT" "$RESET"
}

status_all() {
  step "Status"
  if redis-cli -p "$REDIS_PORT" ping >/dev/null 2>&1; then
    ok "redis    port $REDIS_PORT"
  else
    fail "redis    port $REDIS_PORT — not responding"
  fi
  for entry in "${SERVICES[@]}"; do
    IFS='|' read -r name _ port url marker <<<"$entry"
    local pid
    if pid="$(running_pid "$name")" && service_alive "$url" "$marker"; then
      ok "$(printf '%-8s' "$name") port $port (pid $pid)"
    elif service_alive "$url" "$marker"; then
      warn "$(printf '%-8s' "$name") port $port — up, but not started by this script"
    elif port_busy "$port"; then
      fail "$(printf '%-8s' "$name") port $port — occupied by a different process"
    else
      fail "$(printf '%-8s' "$name") port $port — down"
    fi
  done
  echo
}

case "${1:-start}" in
  start)   start_all ;;
  stop)    stop_all ;;
  restart) stop_all; start_all ;;
  status)  status_all ;;
  logs)    tail -f "$LOG_DIR/combined-$(date +%Y-%m-%d).log" ;;
  *)
    echo "usage: $0 {start|stop|restart|status|logs}" >&2
    exit 1
    ;;
esac
