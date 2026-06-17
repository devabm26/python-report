#!/usr/bin/env bash
# ============================================================
# run_local.sh — Run the Thoughts Dashboard locally
#
# Prerequisites:
#   - oc login already done (used to port-forward to the cluster DB)
#   - pip install -r requirements.txt already done
#
# Usage:
#   chmod +x run_local.sh
#   ./run_local.sh
#
# What this script does:
#   1. Port-forwards the cluster PostgreSQL to localhost:5432
#   2. Sets all required environment variables (credentials via oc secret)
#   3. Starts the Flask app on http://localhost:8000
#   4. Cleans up the port-forward on exit (Ctrl+C)
# ============================================================

set -euo pipefail

# ── Config ──────────────────────────────────────────────────────────────────
NAMESPACE="${NAMESPACE:-thoughts-app}"
DB_SERVICE="postgresql"
LOCAL_PORT="5432"
APP_PORT="8000"
SECRET_NAME="${DB_SECRET_NAME:-postgresql}"   # k8s secret holding DB creds

# ── Colours ─────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()    { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# ── Cleanup on exit ─────────────────────────────────────────────────────────
PF_PID=""
cleanup() {
    echo ""
    info "Shutting down..."
    if [[ -n "$PF_PID" ]] && kill -0 "$PF_PID" 2>/dev/null; then
        kill "$PF_PID" 2>/dev/null || true
        info "Port-forward stopped (PID $PF_PID)"
    fi
}
trap cleanup EXIT INT TERM

# ── 1. Verify oc login ───────────────────────────────────────────────────────
info "Checking OpenShift login..."
if ! oc whoami &>/dev/null; then
    error "Not logged in to OpenShift. Run: oc login <cluster-url>"
    exit 1
fi
CURRENT_USER=$(oc whoami)
info "Logged in as: ${CURRENT_USER}"

# ── 2. Check namespace ───────────────────────────────────────────────────────
info "Verifying namespace '${NAMESPACE}'..."
if ! oc get namespace "${NAMESPACE}" &>/dev/null; then
    error "Namespace '${NAMESPACE}' not found."
    error "Override with: NAMESPACE=<name> ./run_local.sh"
    exit 1
fi

# ── 3. Read DB credentials from the cluster secret ───────────────────────────
info "Reading database credentials from secret '${SECRET_NAME}' in '${NAMESPACE}'..."

# Try to fetch each field; fall back gracefully with a clear error
get_secret_field() {
    local field="$1"
    local value
    value=$(oc get secret "${SECRET_NAME}" -n "${NAMESPACE}" \
        -o jsonpath="{.data.${field}}" 2>/dev/null | base64 -d 2>/dev/null || true)
    echo "${value}"
}

DB_PASSWORD_VAL=$(get_secret_field "database-password")
DB_USER_VAL=$(get_secret_field "database-user")
DB_NAME_VAL=$(get_secret_field "database-name")

# If secret fields were empty, fall back to known defaults from db_metadata.txt
# (values typed by the user, not hardcoded by the app itself)
DB_USER_VAL="${DB_USER_VAL:-thoughts}"
DB_NAME_VAL="${DB_NAME_VAL:-thoughts}"

if [[ -z "${DB_PASSWORD_VAL}" ]]; then
    # Secret didn't yield a password — prompt the user
    warn "Could not read 'database-password' from secret '${SECRET_NAME}'."
    warn "Available secrets in namespace:"
    oc get secrets -n "${NAMESPACE}" --no-headers -o custom-columns="NAME:.metadata.name" 2>/dev/null | head -20 || true
    echo ""
    read -rsp "Enter DB password for user '${DB_USER_VAL}': " DB_PASSWORD_VAL
    echo ""
    if [[ -z "${DB_PASSWORD_VAL}" ]]; then
        error "DB_PASSWORD cannot be empty."
        exit 1
    fi
fi

info "DB user: ${DB_USER_VAL}  |  DB name: ${DB_NAME_VAL}  |  password: (set)"

# ── 4. Check local port availability ────────────────────────────────────────
if lsof -i ":${LOCAL_PORT}" &>/dev/null 2>&1; then
    warn "Port ${LOCAL_PORT} already in use — assuming an existing port-forward or local PG."
    warn "Skipping port-forward; connecting to localhost:${LOCAL_PORT} directly."
    PF_PID=""
else
    # ── 5. Start port-forward ────────────────────────────────────────────────
    info "Starting port-forward: localhost:${LOCAL_PORT} → ${DB_SERVICE}.${NAMESPACE}:5432"
    oc port-forward "svc/${DB_SERVICE}" "${LOCAL_PORT}:5432" -n "${NAMESPACE}" &>/tmp/pf.log &
    PF_PID=$!

    # Wait for port-forward to be ready
    info "Waiting for port-forward to be ready..."
    for i in $(seq 1 15); do
        if lsof -i ":${LOCAL_PORT}" &>/dev/null 2>&1 || \
           grep -q "Forwarding from" /tmp/pf.log 2>/dev/null; then
            break
        fi
        if ! kill -0 "${PF_PID}" 2>/dev/null; then
            error "Port-forward process died. Check /tmp/pf.log:"
            cat /tmp/pf.log >&2
            exit 1
        fi
        sleep 1
    done
    info "Port-forward active (PID ${PF_PID})"
fi

# ── 6. Check Python deps ────────────────────────────────────────────────────
info "Checking Python dependencies..."
if ! python -c "import flask, psycopg2, flask_wtf, dotenv" &>/dev/null; then
    info "Installing dependencies from requirements.txt..."
    pip install -q -r requirements.txt
fi

# ── 7. Generate a strong SECRET_KEY for this session ────────────────────────
SESSION_SECRET=$(python -c "import secrets; print(secrets.token_hex(32))")

# ── 8. Export environment variables ─────────────────────────────────────────
export DB_HOST="localhost"
export DB_PORT="${LOCAL_PORT}"
export DB_NAME="${DB_NAME_VAL}"
export DB_USER="${DB_USER_VAL}"
export DB_PASSWORD="${DB_PASSWORD_VAL}"
export SECRET_KEY="${SESSION_SECRET}"
export FLASK_DEBUG="true"
export PORT="${APP_PORT}"

info "Environment configured:"
info "  DB_HOST    = ${DB_HOST}"
info "  DB_PORT    = ${DB_PORT}"
info "  DB_NAME    = ${DB_NAME}"
info "  DB_USER    = ${DB_USER}"
info "  DB_PASSWORD= (set, not shown)"
info "  SECRET_KEY = (generated, not shown)"
info "  FLASK_DEBUG= ${FLASK_DEBUG}"
echo ""

# ── 9. Launch the app ────────────────────────────────────────────────────────
info "Starting Thoughts Dashboard on http://localhost:${APP_PORT}"
info "Press Ctrl+C to stop."
echo ""

cd "$(dirname "$0")"
python -m src.app
