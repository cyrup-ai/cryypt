#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VAULT_BIN="${SCRIPT_DIR}/../../target/release/vault"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

fail() { echo -e "${RED}❌ $*${NC}"; exit 1; }
pass() { echo -e "${GREEN}✅ $*${NC}"; }
info() { echo -e "${YELLOW}ℹ️  $*${NC}"; }

require_bin() {
  command -v "$1" >/dev/null 2>&1 || fail "Missing required binary: $1"
}

require_file() { [[ -f "$1" ]] || fail "Expected file not found: $1"; }
require_dir() { [[ -d "$1" ]] || fail "Expected directory not found: $1"; }

json_get() { # json_get '<json>' 'field'
  python3 - <<'PY' "$1" "$2"
import json,sys
obj=json.loads(sys.argv[1])
key=sys.argv[2]
val=obj
for part in key.split('.'):
  if isinstance(val, dict) and part in val:
    val=val[part]
  else:
    print('')
    sys.exit(0)
print(val if isinstance(val,str) else json.dumps(val))
PY
}

mktempd() {
  mktemp -d 2>/dev/null || mktemp -d -t 'cryypt_vault_e2e'
}

# Isolate environment
ROOT_TMP="$(mktempd)"; trap 'rm -rf "$ROOT_TMP"' EXIT
WORKDIR="${ROOT_TMP}/work"; mkdir -p "$WORKDIR"
export XDG_CONFIG_HOME="${ROOT_TMP}/xdg"
# Preserve real HOME so macOS login keychain is available
mkdir -p "$XDG_CONFIG_HOME"

info "Using temp ROOT: $ROOT_TMP"
info "VAULT_BIN: $VAULT_BIN"
require_file "$VAULT_BIN"

run() { # run <desc> <command...>
  local desc="$1"; shift
  echo "---"; info "$desc"; set +e; OUTPUT=$("$@" 2>&1); STATUS=$?; set -e
  echo "$OUTPUT"
  [[ $STATUS -eq 0 ]] || fail "$desc failed with status $STATUS"
}

run_json() { # run_json <desc> <command...>
  local desc="$1"; shift
  echo "---"; info "$desc"; set +e; RAW=$("$@" 2>&1); STATUS=$?; set -e
  echo "$RAW"
  # Some commands may print multiple JSON lines; take the LAST valid JSON object
  local LAST_JSON
  LAST_JSON=$(python3 - <<'PY' "$RAW"
import json,sys
raw=sys.argv[1]
last=None
for line in raw.splitlines():
    line=line.strip()
    if not line:
        continue
    try:
        obj=json.loads(line)
        last=line
    except Exception:
        pass
if last is None:
    print('')
    sys.exit(1)
print(last)
PY
  ) || fail "$desc did not output valid JSON"
  [[ $STATUS -eq 0 ]] || fail "$desc failed with status $STATUS"
  JSON_OUT="$LAST_JSON"
}

# Generate PQCrypto keys in keychain
run "Rotate PQ keys (setup)" \
  "$VAULT_BIN" --json rotate-keys --namespace pq_armor --force

# 1) NEW - default XDG path and custom path
DEFAULT_BASE="${XDG_CONFIG_HOME}/cryypt/cryypt"
run "vault new (default XDG path)" \
  "$VAULT_BIN" new --passphrase "passA"
require_dir "${DEFAULT_BASE}.db"

CUSTOM_BASE="${WORKDIR}/myvault"
run_json "vault new (custom path, JSON)" \
  "$VAULT_BIN" --json new --vault-path "$CUSTOM_BASE" --passphrase "passB"
[[ "$(json_get "$JSON_OUT" success)" == "true" ]] || fail "new custom JSON success!=true"
require_dir "${CUSTOM_BASE}.db"

# 2) CRUD with and without namespace
run "put (no namespace)" \
  "$VAULT_BIN" --vault-path "$CUSTOM_BASE" --passphrase "passB" put alpha "A1"
run "get (no namespace)" \
  "$VAULT_BIN" --vault-path "$CUSTOM_BASE" --passphrase "passB" get alpha | grep -q "A1"
run "put (namespace ns1)" \
  "$VAULT_BIN" --vault-path "$CUSTOM_BASE" --passphrase "passB" --json put --namespace ns1 beta "B2"
run "list namespaces" \
  "$VAULT_BIN" --vault-path "$CUSTOM_BASE" --passphrase "passB" list --namespaces
run "list from ns1" \
  "$VAULT_BIN" --vault-path "$CUSTOM_BASE" --passphrase "passB" list --namespace ns1
run "find regex" \
  "$VAULT_BIN" --vault-path "$CUSTOM_BASE" --passphrase "passB" find "^a" # matches alpha
run "delete key" \
  "$VAULT_BIN" --vault-path "$CUSTOM_BASE" --passphrase "passB" delete alpha

# 3) SAVE and persistence
run "save" \
  "$VAULT_BIN" --vault-path "$CUSTOM_BASE" --passphrase "passB" save
# Verify persistence: namespaced key should still be present after new process
run "get after fresh process (namespaced)" \
  "$VAULT_BIN" --vault-path "$CUSTOM_BASE" --passphrase "passB" get --namespace ns1 beta
# And confirm non-namespaced lookup fails (expected)
set +e; "$VAULT_BIN" --vault-path "$CUSTOM_BASE" --passphrase "passB" get beta >/dev/null 2>&1; [[ $? -ne 0 ]] || fail "unexpected success getting non-namespaced key after restart"; set -e

# 4) LOGIN prior to CHANGE PASSPHRASE (required for authenticated operation)
run_json "login before change-passphrase (JSON)" \
  "$VAULT_BIN" --json --vault-path "$CUSTOM_BASE" login --passphrase "passB" --expires-in 1
JWT_TOKEN_CP="$(json_get "$JSON_OUT" token || true)"
[[ -n "${JWT_TOKEN_CP:-}" ]] && export VAULT_JWT="$JWT_TOKEN_CP"

# 5) CHANGE PASSPHRASE
run "change-passphrase" \
  "$VAULT_BIN" --vault-path "$CUSTOM_BASE" change-passphrase --old-passphrase "passB" --new-passphrase "passC"
# Old should fail; we expect an error and do not fail script here, just assert it fails
set +e; "$VAULT_BIN" --vault-path "$CUSTOM_BASE" --passphrase "passB" get --namespace ns1 beta >/dev/null 2>&1; [[ $? -ne 0 ]] || fail "old passphrase unexpectedly worked"; set -e
run "get with new passphrase" \
  "$VAULT_BIN" --vault-path "$CUSTOM_BASE" --passphrase "passC" get --namespace ns1 beta

# 5) LOGIN (JWT) and RUN
run_json "login (JSON)" \
  "$VAULT_BIN" --json --vault-path "$CUSTOM_BASE" login --passphrase "passC" --expires-in 1
JWT_TOKEN="$(json_get "$JSON_OUT" token || true)"
[[ -n "${JWT_TOKEN:-}" ]] || info "JWT not present in JSON; continuing with passphrase for ops"
# If token present, test VAULT_JWT and --jwt paths
if [[ -n "${JWT_TOKEN:-}" ]]; then
  export VAULT_JWT="$JWT_TOKEN"
  run "run with VAULT_JWT env" \
    "$VAULT_BIN" --vault-path "$CUSTOM_BASE" run printf "ok"
  run "run with --jwt flag" \
    "$VAULT_BIN" --vault-path "$CUSTOM_BASE" --jwt "$JWT_TOKEN" run printf "ok"
fi

# 6) LOGOUT
run "logout" \
  "$VAULT_BIN" --vault-path "$CUSTOM_BASE" logout

# 7) LOCK/UNLOCK (PQ armor) on FILE-BASED vault (separate path)
FILE_BASE="${WORKDIR}/filevault"
DB_FILE="${FILE_BASE}.db"
echo "plain db content" > "$DB_FILE"
run "lock (file-based)" \
  "$VAULT_BIN" --json lock --vault-path "$FILE_BASE" --keychain-namespace pq_armor
require_file "${FILE_BASE}.vault"; [[ ! -f "$DB_FILE" ]] || fail ".db not removed after lock"
run "unlock (file-based)" \
  "$VAULT_BIN" --json unlock --vault-path "$FILE_BASE" --keychain-namespace pq_armor
require_file "$DB_FILE"; [[ ! -f "${FILE_BASE}.vault" ]] || fail ".vault not removed after unlock"
grep -q "plain db content" "$DB_FILE" || fail "file content mismatch after unlock"

# 8) ROTATE-KEYS (re-armor validation)
# Create another armor and rotate
run "lock again (file-based)" \
  "$VAULT_BIN" lock --vault-path "$FILE_BASE" --keychain-namespace pq_armor
run "rotate-keys (re-encrypt)" \
  "$VAULT_BIN" --json rotate-keys --namespace pq_armor --force
# After rotation, ensure unlock still works
run "unlock after rotation" \
  "$VAULT_BIN" unlock --vault-path "$FILE_BASE" --keychain-namespace pq_armor

pass "All CLI E2E tests passed"
