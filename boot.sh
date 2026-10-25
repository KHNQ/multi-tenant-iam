#!/usr/bin/env bash
#
# Boots the whole system on this machine and leaves it ready to try by hand:
# Redis, the service registry, the two mock services, the gateway with the
# failover identity provider and the administration console (/ui/) — plus,
# depending on the profile, a stand-in Keycloak and test data.
#
#   ./boot.sh                 demo profile (default): no Keycloak; this system is the
#                             primary IdP; demo tenants samta and tenant-alpha are seeded
#   ./boot.sh failover        a stand-in Keycloak (port 8180) is synchronised in standby
#                             mode, its password hashes imported; stop it to see failover
#   ./boot.sh keycloak        your real Keycloak, from KEYCLOAK_* in .env, in standby mode
#
#   ./boot.sh status          what is running, and the identity provider's mode
#   ./boot.sh stop            stop every process this script (or start.sh) started
#   ./boot.sh logs            follow the combined structured log
#   ./boot.sh idp <command>   the operator CLI (npm run idp) against the running profile,
#                             e.g. ./boot.sh idp mode standby, ./boot.sh idp rotate-key samta
#   ./boot.sh keycloak-stop   failover profile: shut the stand-in Keycloak down (an outage)
#   ./boot.sh keycloak-start  ... and bring it back
#   ./boot.sh reset <profile> --yes
#                             stop, and wipe that profile's data (its Redis database)
#
# Each profile keeps its data in its own Redis database (demo 1, failover 2,
# keycloak 3) on the Redis at REDIS_PORT (default 7000), so they never mix with
# each other or with what start.sh and the e2e suite keep in database 0.
#
# Settings come from .env (created, or completed, with generated secrets if
# needed); anything exported in the environment wins. GATEWAY_PORT picks the
# gateway's port (default: PORT from .env, else 3000, else the first free port
# from 3100 if 3000 is taken by something else).

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT" || exit 1
RUN_DIR="$ROOT/.run"
LOG_DIR="$ROOT/logs"
REDIS_PORT="${REDIS_PORT:-7000}"
FAKE_KEYCLOAK_PORT="${FAKE_KEYCLOAK_PORT:-8180}"
PROFILE_FILE="$RUN_DIR/boot-profile"
mkdir -p "$RUN_DIR" "$LOG_DIR"
chmod 700 "$RUN_DIR" 2>/dev/null

BOLD=$'\033[1m'; DIM=$'\033[2m'; GREEN=$'\033[32m'; RED=$'\033[31m'
YELLOW=$'\033[33m'; CYAN=$'\033[36m'; RESET=$'\033[0m'

ok()   { printf "  %s✔%s %s\n" "$GREEN" "$RESET" "$1"; }
warn() { printf "  %s!%s %s\n" "$YELLOW" "$RESET" "$1"; }
fail() { printf "  %s✘%s %s\n" "$RED" "$RESET" "$1"; }
info() { printf "    %s%s%s\n" "$DIM" "$1" "$RESET"; }
step() { printf "\n%s%s%s\n" "$BOLD" "$1" "$RESET"; }
die()  { fail "$1"; exit 1; }

random_secret() { openssl rand -base64 48 2>/dev/null | tr -d '\n' || node -e "process.stdout.write(require('crypto').randomBytes(48).toString('base64'))"; }
random_hex()    { openssl rand -hex 32 2>/dev/null || node -e "process.stdout.write(require('crypto').randomBytes(32).toString('hex'))"; }

profile_db() {
  case "$1" in
    demo) echo 1 ;; failover) echo 2 ;; keycloak) echo 3 ;;
    *) return 1 ;;
  esac
}

# ── processes ──────────────────────────────────────────────────────────────
# Pid files share start.sh's names, so either script can stop what the other started.

pid_file() { echo "$RUN_DIR/$1.pid"; }

running_pid() {
  local f; f="$(pid_file "$1")"
  [[ -f "$f" ]] || return 1
  local pid; pid="$(cat "$f" 2>/dev/null)"
  [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null || return 1
  echo "$pid"
}

port_busy() {
  if command -v lsof >/dev/null 2>&1; then
    lsof -nP -iTCP:"$1" -sTCP:LISTEN -t >/dev/null 2>&1
  else
    curl -s -o /dev/null --max-time 1 "http://127.0.0.1:$1/" 2>/dev/null
    [[ $? -ne 7 ]]
  fi
}

who_listens() {
  command -v lsof >/dev/null 2>&1 && lsof -nP -iTCP:"$1" -sTCP:LISTEN 2>/dev/null | tail -n +2 | awk '{print $1" (pid "$2")"}' | head -1
}

wait_for() {
  local url="$1" marker="$2" tries="${3:-80}"
  for ((i = 0; i < tries; i++)); do
    curl -fsS --max-time 2 "$url" 2>/dev/null | grep -q "$marker" && return 0
    sleep 0.25
  done
  return 1
}

stop_one() {
  local name="$1" pid
  pid="$(running_pid "$name")" || { rm -f "$(pid_file "$name")"; return 1; }
  kill "$pid" 2>/dev/null
  for ((i = 0; i < 40; i++)); do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
  kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null
  rm -f "$(pid_file "$name")"
  ok "stopped $name (pid $pid)"
}

# start_one <name> <port> <readiness url> <marker> <command...>
start_one() {
  local name="$1" port="$2" url="$3" marker="$4"; shift 4
  if port_busy "$port"; then
    fail "$name cannot start: port $port is taken by $(who_listens "$port" || echo 'another process')"
    return 1
  fi
  local log="$LOG_DIR/boot-$name.log"
  # The command runs in place of nohup (no subshell), so $! is the server's own pid.
  nohup "$@" >"$log" 2>&1 &
  local pid=$!
  echo "$pid" >"$(pid_file "$name")"
  if wait_for "$url" "$marker" 120; then
    ok "$name up on port $port (pid $pid)"
    return 0
  fi
  fail "$name did not become ready on port $port — last lines of ${log#"$ROOT"/}:"
  tail -n 20 "$log" | sed 's/^/      /'
  return 1
}

stop_all() {
  step "Stopping"
  local any=0
  for name in gateway vision llm registry fake-keycloak; do
    stop_one "$name" && any=1
  done
  [[ $any -eq 0 ]] && info "nothing was running"
  info "Redis on port $REDIS_PORT is left running (it holds the data); stop it with: redis-cli -p $REDIS_PORT shutdown"
}

# ── configuration ──────────────────────────────────────────────────────────

# Anything already exported wins over .env, as in start.sh.
load_env() {
  [[ -f "$ROOT/.env" ]] || return 0
  while IFS= read -r line || [[ -n "$line" ]]; do
    local key="${line%%=*}"
    [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || continue
    [[ -n "${!key+x}" ]] || export "$key=${line#*=}"
  done <"$ROOT/.env"
}

ensure_env_file() {
  step "Configuration"
  local created=0
  if [[ ! -f "$ROOT/.env" ]]; then
    (umask 077; : >"$ROOT/.env")
    created=1
  fi
  local added=()
  if ! grep -q '^JWT_SECRET=..*' "$ROOT/.env"; then
    printf '\n# generated by boot.sh\nJWT_SECRET=%s\n' "$(random_secret)" >>"$ROOT/.env"; added+=(JWT_SECRET)
  fi
  if ! grep -q '^REGISTRY_ENROLLMENT_TOKEN=..*' "$ROOT/.env"; then
    printf 'REGISTRY_ENROLLMENT_TOKEN=%s\n' "$(random_hex)" >>"$ROOT/.env"; added+=(REGISTRY_ENROLLMENT_TOKEN)
  fi
  if ! grep -q '^UPSTREAM_ALLOWED_CIDRS=..*' "$ROOT/.env"; then
    printf 'UPSTREAM_ALLOWED_CIDRS=127.0.0.0/8,::1/128\n' >>"$ROOT/.env"; added+=(UPSTREAM_ALLOWED_CIDRS)
  fi
  chmod 600 "$ROOT/.env" 2>/dev/null
  if [[ $created -eq 1 ]]; then ok "created .env with generated secrets (mode 0600)"
  elif [[ ${#added[@]} -gt 0 ]]; then ok "added to .env: ${added[*]}"
  else ok ".env present"; fi

  load_env

  [[ ${#JWT_SECRET} -ge 32 ]] || die "JWT_SECRET in .env is shorter than 32 characters — replace it: openssl rand -base64 48"
  # The mock services register themselves as http://localhost:…, which resolves to ::1 on many systems.
  if [[ "$UPSTREAM_ALLOWED_CIDRS" == *127.0.0* && "$UPSTREAM_ALLOWED_CIDRS" != *::1* ]]; then
    export UPSTREAM_ALLOWED_CIDRS="$UPSTREAM_ALLOWED_CIDRS,::1/128"
    info "UPSTREAM_ALLOWED_CIDRS: ::1/128 added for this run (the mock services resolve as ::1)"
  fi
}

check_tools() {
  step "Prerequisites"
  command -v node >/dev/null 2>&1 || die "node is not installed (Node.js 22 is expected)"
  local major; major="$(node -p 'process.versions.node.split(".")[0]')"
  [[ "$major" -ge 20 ]] || die "Node.js $major is too old — 22 is expected (20.12 at least)"
  ok "node $(node -v)"
  command -v npm >/dev/null 2>&1 || die "npm is not installed"
  command -v curl >/dev/null 2>&1 || die "curl is not installed"
  command -v redis-cli >/dev/null 2>&1 || die "redis-cli is not installed (install Redis, e.g. brew install redis)"
  ok "npm, curl and redis-cli found"
}

install_dependencies() {
  step "Dependencies"
  if [[ ! -d node_modules || package-lock.json -nt node_modules/.package-lock.json ]]; then
    info "installing backend packages (npm ci)…"
    npm ci --no-audit --no-fund >"$LOG_DIR/boot-npm.log" 2>&1 || { tail -n 20 "$LOG_DIR/boot-npm.log"; die "npm ci failed (see logs/boot-npm.log)"; }
    ok "backend packages installed"
  else
    ok "backend packages up to date"
  fi
  if [[ ! -d frontend/node_modules || frontend/package-lock.json -nt frontend/node_modules/.package-lock.json ]]; then
    info "installing console packages (npm ci in frontend/)…"
    npm --prefix frontend ci --no-audit --no-fund >"$LOG_DIR/boot-npm-frontend.log" 2>&1 \
      || { tail -n 20 "$LOG_DIR/boot-npm-frontend.log"; die "npm ci in frontend/ failed (see logs/boot-npm-frontend.log)"; }
    ok "console packages installed"
  else
    ok "console packages up to date"
  fi
}

build_console() {
  local index="frontend/dist/index.html"
  if [[ -f "$index" && -z "$(find frontend/src frontend/index.html frontend/vite.config.js frontend/public -newer "$index" -print -quit 2>/dev/null)" ]]; then
    ok "console build up to date (frontend/dist)"
    return 0
  fi
  info "building the console (vite build)…"
  npm --prefix frontend run build >"$LOG_DIR/boot-build.log" 2>&1 \
    || { tail -n 20 "$LOG_DIR/boot-build.log"; die "the console build failed (see logs/boot-build.log)"; }
  ok "console built into frontend/dist (served at /ui/)"
}

ensure_redis() {
  step "Redis"
  if redis-cli -p "$REDIS_PORT" ping >/dev/null 2>&1; then
    ok "running on port $REDIS_PORT"
    return 0
  fi
  if port_busy "$REDIS_PORT"; then
    die "port $REDIS_PORT is taken by $(who_listens "$REDIS_PORT" || echo 'something') that is not Redis — set REDIS_PORT"
  fi
  command -v redis-server >/dev/null 2>&1 || die "redis-server is not installed and nothing runs on port $REDIS_PORT (e.g. brew install redis)"
  redis-server --port "$REDIS_PORT" --daemonize yes --dir "$RUN_DIR" --appendonly yes \
    --logfile "$LOG_DIR/redis.log" >/dev/null 2>&1 || die "redis-server failed to start (see logs/redis.log)"
  for ((i = 0; i < 40; i++)); do
    redis-cli -p "$REDIS_PORT" ping >/dev/null 2>&1 && { ok "started on port $REDIS_PORT (data in .run/, append-only file on)"; return 0; }
    sleep 0.25
  done
  die "Redis did not answer on port $REDIS_PORT"
}

choose_gateway_port() {
  local wanted="${GATEWAY_PORT:-${PORT:-3000}}"
  if ! port_busy "$wanted"; then GW_PORT="$wanted"; return 0; fi
  if [[ -n "${GATEWAY_PORT:-}" ]]; then
    die "GATEWAY_PORT $wanted is taken by $(who_listens "$wanted" || echo 'another process')"
  fi
  for ((p = 3100; p < 3200; p++)); do
    if ! port_busy "$p"; then
      warn "port $wanted is taken by $(who_listens "$wanted" || echo 'another process') — the gateway uses $p instead"
      GW_PORT="$p"
      return 0
    fi
  done
  die "no free port between 3100 and 3199 for the gateway — set GATEWAY_PORT"
}

# The environment of every process, for the chosen profile.
configure_profile() {
  local profile="$1" db
  db="$(profile_db "$profile")" || die "unknown profile '$profile' (demo, failover or keycloak)"
  PROFILE_RUN="$RUN_DIR/boot/$profile"
  mkdir -p "$PROFILE_RUN"
  chmod 700 "$PROFILE_RUN"

  export REDIS_URL="redis://localhost:$REDIS_PORT/$db"
  export REGISTRY_URL="http://localhost:3001"
  export LOG_DIR
  export INITIAL_ADMIN_PASSWORD_FILE="$PROFILE_RUN/initial-admin-password"
  export IDP_BOOTSTRAP_PASSWORD_FILE="$PROFILE_RUN/initial-console-admin-password"
  export SERVICE_TOKEN_DIR="$PROFILE_RUN/service-tokens"
  # PORT is passed to each process explicitly: the registry reads it too.
  unset PORT
  # The issuer and the console's callback are on PUBLIC_URL. A local one must
  # name the port the gateway really listens on; a real host name (behind a
  # proxy) is left as configured.
  if [[ -z "${PUBLIC_URL:-}" ]]; then
    export PUBLIC_URL="http://localhost:$GW_PORT"
  elif [[ "$PUBLIC_URL" =~ ^http://(localhost|127\.0\.0\.1)(:[0-9]+)?/?$ && "${PUBLIC_URL%/}" != "http://localhost:$GW_PORT" ]]; then
    warn "PUBLIC_URL in .env ($PUBLIC_URL) is not this gateway's address — using http://localhost:$GW_PORT for this run"
    export PUBLIC_URL="http://localhost:$GW_PORT"
  fi
  PUBLIC_URL="${PUBLIC_URL%/}"
  # The BFF reaches this process's own token endpoint over loopback.
  export IDP_INTERNAL_URL="http://127.0.0.1:$GW_PORT"

  case "$profile" in
    demo)
      unset KEYCLOAK_URL KEYCLOAK_SYNC_CLIENT_ID KEYCLOAK_SYNC_CLIENT_SECRET IDP_MODE
      ;;
    failover)
      export KEYCLOAK_URL="http://127.0.0.1:$FAKE_KEYCLOAK_PORT"
      export KEYCLOAK_SYNC_TOKEN_REALM=master
      export KEYCLOAK_SYNC_CLIENT_ID=iam-failover-sync
      export KEYCLOAK_SYNC_CLIENT_SECRET=stand-in-sync-secret
      export KEYCLOAK_SYNC_REALMS="platform,samta,tenant-alpha"
      export KEYCLOAK_SYNC_INTERVAL_SECONDS="${KEYCLOAK_SYNC_INTERVAL_SECONDS:-60}"
      export IDP_MODE=standby
      export MAPDASHBOARD_PERMISSION_CATALOG_URL="http://127.0.0.1:$FAKE_KEYCLOAK_PORT/mapdashboard/permissions/catalog"
      [[ -f "$PROFILE_RUN/import-token" ]] || (umask 077; random_hex >"$PROFILE_RUN/import-token")
      export IDP_CREDENTIAL_IMPORT_TOKEN="$(cat "$PROFILE_RUN/import-token")"
      export IDP_CREDENTIAL_IMPORT_ALLOWED_CIDRS="127.0.0.1/32,::1/128"
      ;;
    keycloak)
      for key in KEYCLOAK_URL KEYCLOAK_SYNC_CLIENT_ID KEYCLOAK_SYNC_CLIENT_SECRET; do
        [[ -n "${!key:-}" ]] || die "$key is not set — the keycloak profile reads your Keycloak from .env (see .env.example and docs/failover-idp.md)"
      done
      export IDP_MODE="${IDP_MODE:-standby}"
      if [[ -z "${IDP_CREDENTIAL_IMPORT_TOKEN:-}" ]]; then
        [[ -f "$PROFILE_RUN/import-token" ]] || (umask 077; random_hex >"$PROFILE_RUN/import-token")
        export IDP_CREDENTIAL_IMPORT_TOKEN="$(cat "$PROFILE_RUN/import-token")"
      fi
      export IDP_CREDENTIAL_IMPORT_ALLOWED_CIDRS="${IDP_CREDENTIAL_IMPORT_ALLOWED_CIDRS:-127.0.0.1/32,::1/128}"
      ;;
  esac
  echo "$profile $GW_PORT" >"$PROFILE_FILE"
}

idp_cli() { node src/idp/cli.js "$@"; }

# ── the boot ───────────────────────────────────────────────────────────────

start_services() {
  local profile="$1"
  if [[ "$profile" == failover ]]; then
    start_one fake-keycloak "$FAKE_KEYCLOAK_PORT" "http://127.0.0.1:$FAKE_KEYCLOAK_PORT/health" '"UP"' \
      env FAKE_KEYCLOAK_PORT="$FAKE_KEYCLOAK_PORT" node test/idp/fake-keycloak.js || return 1
  fi
  start_one registry 3001 "http://localhost:3001/health" registeredServices env PORT=3001 node src/registery.js || return 1
  start_one llm 8080 "http://localhost:8080/catalog" ai_team node src/llm.reg.js || return 1
  start_one vision 8081 "http://localhost:8081/catalog" cv_team node src/vision.reg.js || return 1
  start_one gateway "$GW_PORT" "http://127.0.0.1:$GW_PORT/health/ready" '"status":"UP"' env PORT="$GW_PORT" node src/main.reg.js || return 1
}

wait_for_sync() {
  local seconds="$1"
  info "waiting for the first synchronisation…"
  for ((i = 0; i < seconds * 2; i++)); do
    if curl -s --max-time 2 "http://127.0.0.1:$GW_PORT/health/sync" | node -e '
      let s = ""; process.stdin.on("data", (c) => s += c).on("end", () => {
        try {
          const realms = JSON.parse(s).realms || {};
          const synced = Object.values(realms).filter((r) => r.source === "sync");
          process.exit(synced.length > 0 && synced.every((r) => r.ok) ? 0 : 1);
        } catch { process.exit(1); }
      });' 2>/dev/null; then
      return 0
    fi
    sleep 0.5
  done
  return 1
}

prepare_demo() {
  step "Test data (demo)"
  local mode
  mode="$(idp_cli mode 2>/dev/null | node -pe 'JSON.parse(require("fs").readFileSync(0)).mode' 2>/dev/null)"
  if [[ "$mode" != primary ]]; then
    idp_cli mode primary >/dev/null 2>&1 && ok "operating mode set to primary (demo profile)"
  fi
  if [[ "$(redis-cli -p "$REDIS_PORT" -n "$(profile_db demo)" exists idp:realm:samta)" != 1 ]]; then
    (umask 077; idp_cli seed-demo 2>/dev/null | grep -v '^\[idp-cli\]' >"$PROFILE_RUN/demo-accounts.txt")
    ok "demo tenants samta and tenant-alpha created"
  else
    ok "demo tenants already present"
  fi
}

prepare_failover() {
  step "Test data (failover)"
  local mode
  mode="$(idp_cli mode 2>/dev/null | node -pe 'JSON.parse(require("fs").readFileSync(0)).mode' 2>/dev/null)"
  if [[ "$mode" != standby ]]; then
    idp_cli mode standby >/dev/null 2>&1 && ok "operating mode set back to standby (synchronisation runs only in standby)"
  fi
  wait_for_sync 90 || { fail "the first synchronisation did not complete — see logs/boot-gateway.log"; return 1; }
  ok "realms synchronised from the stand-in Keycloak"
  local result
  result="$(curl -fsS "http://127.0.0.1:$FAKE_KEYCLOAK_PORT/export/credentials" \
    | curl -fsS -X POST "http://127.0.0.1:$GW_PORT/admin/sync/credentials" \
        -H "Authorization: Bearer $IDP_CREDENTIAL_IMPORT_TOKEN" -H 'Content-Type: application/json' --data-binary @-)" \
    || { fail "importing password hashes failed"; return 1; }
  ok "password hashes imported: $(echo "$result" | node -pe 'const r=JSON.parse(require("fs").readFileSync(0)); `${r.imported} imported, ${r.unchanged} unchanged, ${r.rejected.length} rejected`')"
  # Secrets are never copied from Keycloak: this system issues its own (spec 7.4).
  {
    echo "# Client secrets issued by this system (failover profile). Re-issued on every ./boot.sh failover."
    echo "samta / samta-mapdashboard-web-poc     $(idp_cli client-secret samta samta-mapdashboard-web-poc 2>/dev/null | tail -n 1)"
    echo "tenant-alpha / tenant-alpha.wiztest-svc $(idp_cli client-secret tenant-alpha tenant-alpha.wiztest-svc 2>/dev/null | tail -n 1)"
  } >"$PROFILE_RUN/client-secrets.txt"
  chmod 600 "$PROFILE_RUN/client-secrets.txt"
  ok "client secrets issued for MapDashboard and the wiztest service account"
}

prepare_keycloak() {
  step "Synchronisation (keycloak)"
  if wait_for_sync 120; then
    ok "realms synchronised from $KEYCLOAK_URL"
  else
    warn "no successful synchronisation yet — check KEYCLOAK_* and logs/boot-gateway.log (./boot.sh status shows the error)"
  fi
  info "password hashes: POST your export to http://127.0.0.1:$GW_PORT/admin/sync/credentials"
  info "  with  Authorization: Bearer \$(cat ${PROFILE_RUN#"$ROOT"/}/import-token)   (docs/failover-idp.md)"
}

summary() {
  local profile="$1" base="$PUBLIC_URL"
  step "Ready — profile $profile"
  printf "  %sConsole%s           %s/ui/\n" "$CYAN" "$RESET" "$base"
  case "$profile" in
    demo)
      if [[ -f "$IDP_BOOTSTRAP_PASSWORD_FILE" ]]; then
        printf "  %sConsole admin%s     padmin — one-time password: cat %s\n" "$CYAN" "$RESET" "${IDP_BOOTSTRAP_PASSWORD_FILE#"$ROOT"/}"
        info "                    (you choose a new one at the first sign-in)"
      else
        printf "  %sConsole admin%s     padmin — the password you chose at the first sign-in\n" "$CYAN" "$RESET"
      fi
      printf "  %sTenant admin%s      tadmin (tenant-alpha) — see the demo accounts below\n" "$CYAN" "$RESET"
      if [[ -s "$PROFILE_RUN/demo-accounts.txt" ]]; then
        printf "  %sDemo accounts%s     %s\n" "$CYAN" "$RESET" "${PROFILE_RUN#"$ROOT"/}/demo-accounts.txt"
        sed 's/^/                      /' "$PROFILE_RUN/demo-accounts.txt" | grep -v 'Demo realms ready'
      fi
      info "Mode: primary — everything is editable. Try: ./boot.sh idp mode standby   (banner + read-only console)"
      ;;
    failover)
      printf "  %sAccounts%s          every password is <Username>-Passw0rd-1\n" "$CYAN" "$RESET"
      cat <<EOF
                      platform      padmin / Padmin-Passw0rd-1 (platform admin), tadmin / Tadmin-Passw0rd-1 (tenant-alpha admin)
                      samta         operator1 / Operator1-Passw0rd-1 (MapDashboard operator), noroles / Noroles-Passw0rd-1
                      tenant-alpha  alice / Alice-Passw0rd-1, bob / Bob-Passw0rd-1
EOF
      printf "  %sClient secrets%s    %s\n" "$CYAN" "$RESET" "${PROFILE_RUN#"$ROOT"/}/client-secrets.txt"
      printf "  %sStand-in Keycloak%s http://127.0.0.1:%s   (synchronised every %ss)\n" "$CYAN" "$RESET" "$FAKE_KEYCLOAK_PORT" "$KEYCLOAK_SYNC_INTERVAL_SECONDS"
      info "Mode: standby — the console shows the backup-system banner and is read-only."
      info "Simulate the outage:  ./boot.sh keycloak-stop    (sign-in keeps working; /health/sync turns stale)"
      info "Bring it back:        ./boot.sh keycloak-start"
      ;;
    keycloak)
      printf "  %sPrimary IdP%s       %s\n" "$CYAN" "$RESET" "$KEYCLOAK_URL"
      info "Sign in to the console with a platform-realm account whose password hash you imported."
      ;;
  esac
  cat <<EOF

  ${CYAN}OIDC (per realm)${RESET}  $base/realms/<realm>/.well-known/openid-configuration
                    e.g. $base/realms/samta/.well-known/openid-configuration
  ${CYAN}Health${RESET}            $base/health/ready   $base/health/sync
  ${CYAN}Gateway console${RESET}   $base/          ${DIM}(the original gateway console; user 'admin')${RESET}
  ${CYAN}API docs${RESET}          $base/docs
EOF
  [[ -f "$INITIAL_ADMIN_PASSWORD_FILE" ]] && info "gateway 'admin' one-time password: cat ${INITIAL_ADMIN_PASSWORD_FILE#"$ROOT"/}"
  cat <<EOF

  ${DIM}operator CLI:${RESET}      ./boot.sh idp help         ${DIM}(mode, keys, client secrets, users… for this profile)${RESET}
  ${DIM}automated tests:${RESET}   npm test && npm run test:idp && npm --prefix frontend test
  ${DIM}status / logs:${RESET}     ./boot.sh status    ./boot.sh logs
  ${DIM}shut down:${RESET}         ./boot.sh stop
EOF
}

boot() {
  local profile="$1" db
  db="$(profile_db "$profile")" || die "unknown profile '$profile' (demo, failover or keycloak)"
  printf "%sBooting the IAM gateway, failover IdP and console — profile %s%s\n" "$BOLD" "$profile" "$RESET"
  check_tools
  ensure_env_file
  install_dependencies
  build_console
  ensure_redis

  # A clean start every time, so the profile's settings are the ones in force.
  local had=0
  for name in gateway vision llm registry fake-keycloak; do running_pid "$name" >/dev/null && had=1; done
  if [[ $had -eq 1 ]]; then stop_all; fi

  step "Services (profile: $profile, Redis database $db)"
  choose_gateway_port
  configure_profile "$profile"
  start_services "$profile" || { fail "boot aborted — ./boot.sh stop cleans up what did start"; exit 1; }

  case "$profile" in
    demo) prepare_demo ;;
    failover) prepare_failover || exit 1 ;;
    keycloak) prepare_keycloak ;;
  esac
  summary "$profile"
}

status() {
  step "Processes"
  for name in fake-keycloak registry llm vision gateway; do
    local pid
    if pid="$(running_pid "$name")"; then ok "$name running (pid $pid)"; else info "$name not running"; fi
  done
  if redis-cli -p "$REDIS_PORT" ping >/dev/null 2>&1; then ok "redis running on port $REDIS_PORT"; else info "redis not running on port $REDIS_PORT"; fi
  if [[ -f "$PROFILE_FILE" ]]; then
    local profile port
    read -r profile port <"$PROFILE_FILE"
    step "Identity provider (profile $profile, http://localhost:$port)"
    curl -s --max-time 3 "http://127.0.0.1:$port/health/sync" | node -e '
      let s = ""; process.stdin.on("data", (c) => s += c).on("end", () => {
        try {
          const h = JSON.parse(s);
          console.log(`  mode ${h.mode}, sync ${h.syncConfigured ? (h.stale ? "STALE" : "ok") : "not configured"}, last success ${h.lastSuccessfulSync || "never"}`);
          for (const [name, r] of Object.entries(h.realms)) console.log(`    ${name.padEnd(14)} ${r.source.padEnd(6)} ${String(r.users).padStart(3)} users  ${r.source === "sync" ? (r.ok ? "ok" : `FAILED ${r.error || ""}`) : ""}`);
        } catch { console.log("  the gateway is not answering"); }
      });'
  fi
}

reset_profile() {
  local profile="${1:-}" confirm="${2:-}" db
  db="$(profile_db "$profile")" || die "usage: ./boot.sh reset <demo|failover|keycloak> --yes"
  [[ "$confirm" == --yes ]] || die "this deletes every user, client, key and session of the $profile profile — repeat with --yes"
  stop_all
  if redis-cli -p "$REDIS_PORT" ping >/dev/null 2>&1; then
    redis-cli -p "$REDIS_PORT" -n "$db" flushdb >/dev/null && ok "Redis database $db ($profile) emptied"
  fi
  rm -rf "$RUN_DIR/boot/$profile" && ok "removed .run/boot/$profile"
}

case "${1:-demo}" in
  demo|failover|keycloak) boot "${1:-demo}" ;;
  stop) stop_all ;;
  status) status ;;
  logs) tail -f "$LOG_DIR/combined-$(date +%Y-%m-%d).log" ;;
  keycloak-stop)
    stop_one fake-keycloak || info "the stand-in Keycloak was not running"
    info "the failover system keeps serving sign-in; watch /health/sync turn stale"
    ;;
  keycloak-start)
    start_one fake-keycloak "$FAKE_KEYCLOAK_PORT" "http://127.0.0.1:$FAKE_KEYCLOAK_PORT/health" '"UP"' \
      env FAKE_KEYCLOAK_PORT="$FAKE_KEYCLOAK_PORT" node test/idp/fake-keycloak.js
    ;;
  reset) reset_profile "${2:-}" "${3:-}" ;;
  idp)
    shift
    [[ -f "$PROFILE_FILE" ]] || die "nothing has been booted yet — run ./boot.sh first"
    read -r current _ <"$PROFILE_FILE"
    load_env
    export REDIS_URL="redis://localhost:$REDIS_PORT/$(profile_db "$current")"
    node src/idp/cli.js "$@"
    ;;
  -h|--help|help) sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//' ;;
  *) die "unknown command '$1' — try ./boot.sh help" ;;
esac
