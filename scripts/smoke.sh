#!/usr/bin/env bash
# End-to-end smoke test against a freshly started instance.
#
# It deliberately asserts the *contract* (shapes, status codes, headers) rather
# than upstream data, because registry contents change constantly but the API
# contract must not.
set -euo pipefail

BIN=${BIN:-./bin/whois2api}
PORT=${PORT:-18080}
BASE="http://127.0.0.1:${PORT}"
DATADIR=$(mktemp -d)
TOKEN="smoke-token-$$"
LOGFILE=$(mktemp)
PID=""

cleanup() {
  [ -n "$PID" ] && kill "$PID" 2>/dev/null || true
  rm -rf "$DATADIR" "$LOGFILE"
}
trap cleanup EXIT

fail() { printf '  FAIL %s\n' "$1" >&2; exit 1; }
pass() { printf '  ok   %s\n' "$1"; }

printf 'starting %s on :%s\n' "$BIN" "$PORT"
W2A_LISTEN="127.0.0.1:${PORT}" \
W2A_DATA_DIR="$DATADIR" \
W2A_TOKENS="$TOKEN" \
W2A_RATE_LIMIT=10000 \
  "$BIN" >"$LOGFILE" 2>&1 &
PID=$!

for _ in $(seq 1 60); do
  if curl -fsS -m 1 "$BASE/api/v1/health" >/dev/null 2>&1; then break; fi
  sleep 0.25
done
curl -fsS -m 2 "$BASE/api/v1/health" >/dev/null || { cat "$LOGFILE"; fail "server did not become healthy"; }
pass "server is healthy"

# Health must never require a token, or orchestration probes break.
curl -fsS -m 2 "$BASE/api/v1/health" | grep -q '"ok"' || fail "health payload"
pass "health is unauthenticated"

status=$(curl -s -o /dev/null -w '%{http_code}' -m 5 "$BASE/api/v1/domain/example.com")
[ "$status" = "401" ] || fail "unauthenticated lookup returned $status, want 401"
pass "auth is enforced"

auth=(-H "Authorization: Bearer $TOKEN")

code=$(curl -s -o /dev/null -w '%{http_code}' -m 20 "${auth[@]}" "$BASE/api/v1/domain/example.com")
[ "$code" = "200" ] || fail "authorized lookup returned $code"
pass "authorized lookup works"

body=$(curl -s -m 20 "${auth[@]}" "$BASE/api/v1/domain/example.com")
printf '%s' "$body" | grep -q '"domain"' || fail "response missing domain object"
printf '%s' "$body" | grep -qE '"status":"(registered|available|unknown)"' || fail "verdict has no valid value"
pass "verdict uses the three-state vocabulary"

code=$(curl -s -o /dev/null -w '%{http_code}' -m 10 "${auth[@]}" "$BASE/api/v1/domain/not%20a%20domain")
[ "$code" = "400" ] || fail "invalid domain returned $code, want 400"
pass "invalid input rejected"

code=$(curl -s -o /dev/null -w '%{http_code}' -m 10 -X DELETE "${auth[@]}" "$BASE/api/v1/domain/example.com")
[ "$code" = "405" ] || fail "wrong method returned $code, want 405"
pass "wrong method returns 405"

code=$(curl -s -o /dev/null -w '%{http_code}' -m 10 -X POST "${auth[@]}" \
  -H 'Content-Type: application/json' -d '{"domains":["example.com"]}' "$BASE/api/v1/batch")
[ "$code" = "200" ] || fail "batch returned $code"
pass "batch endpoint works"

# Security headers must be present on the HTML page too.
headers=$(curl -s -D - -o /dev/null -m 5 "$BASE/")
printf '%s' "$headers" | grep -qi 'X-Content-Type-Options: nosniff' || fail "missing nosniff"
printf '%s' "$headers" | grep -qi 'Content-Security-Policy' || fail "missing CSP"
pass "security headers present"

curl -fsS -m 5 "$BASE/" | grep -q 'Whois2Api' || fail "index page"
curl -fsS -m 5 "$BASE/static/logo.svg" | grep -q '<svg' || fail "logo asset"
pass "UI and assets served"

# Graceful shutdown: the process must exit 0 and leave a valid database.
kill -TERM "$PID"
for _ in $(seq 1 40); do
  if ! kill -0 "$PID" 2>/dev/null; then break; fi
  sleep 0.25
done
if kill -0 "$PID" 2>/dev/null; then fail "server did not shut down"; fi
PID=""
[ -f "$DATADIR/whois2api.db" ] || fail "cache database missing"
pass "graceful shutdown with persistent cache"

printf '\nsmoke test passed\n'
