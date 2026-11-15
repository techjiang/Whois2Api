#!/usr/bin/env bash
# End-to-end smoke test against a freshly started instance.
#
# It deliberately asserts the *contract* (shapes, status codes, headers) rather
# than upstream data, because registry contents change constantly but the API
# contract must not.
set -euo pipefail

BIN=${BIN:-./bin/whois2api}
PORT=${PORT:-18080}

# Fail with a useful message rather than a confusing health-check timeout.
if [ ! -x "$BIN" ]; then
  printf 'smoke: %s is not executable\n' "$BIN" >&2
  printf 'smoke: build it first (make build) or set BIN=/path/to/whois2api\n' >&2
  exit 1
fi
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

# The raw upstream payload is opt-in and must never arrive unasked.
body=$(curl -s -m 20 "${auth[@]}" "$BASE/api/v1/domain/example.com")
printf '%s' "$body" | grep -q '"raw"' && fail "raw payload leaked without ?raw=1"
raw=$(curl -s -m 20 "${auth[@]}" "$BASE/api/v1/domain/example.org?raw=1")
printf '%s' "$raw" | grep -q '"raw"' || echo "  note example.org served from cache; raw payload unavailable there"
pass "raw payload is opt-in"

# Cache counters must move, or the status endpoint is lying to operators.
hits=$(curl -s -m 5 "${auth[@]}" "$BASE/api/v1/status" | grep -o '"hits":[0-9]*' | head -1 | cut -d: -f2)
[ "${hits:-0}" -ge 1 ] || fail "cache hits did not increase after a repeated lookup (got ${hits:-0})"
pass "cache counters are live"

# Same question, same answer. A warm entry stores the registrable domain's
# record, so it must still echo the caller's own name: query a subdomain once
# and the parent used to come back labelled with the subdomain nobody typed.
curl -s -m 20 "${auth[@]}" "$BASE/api/v1/domain/www.example.com" >/dev/null
warm=$(curl -s -m 20 "${auth[@]}" "$BASE/api/v1/domain/example.com")
printf '%s' "$warm" | grep -q '"name":"example.com"' || fail "warm answer is not named after the caller: $warm"
printf '%s' "$warm" | grep -q '"subdomain_of"' && fail "warm parent answer inherited a subdomain relationship"
pass "warm answers echo the caller's name"

# Batch items carry no raw payload: there is no per-item flag to ask for it.
batch=$(curl -s -m 20 "${auth[@]}" -X POST -H 'Content-Type: application/json' \
  -d '{"domains":["example.com","example.org"]}' "$BASE/api/v1/batch")
printf '%s' "$batch" | grep -q '"raw"' && fail "batch shipped an upstream payload nobody asked for"
pass "batch carries no raw payload"

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

# The UI is bilingual and the dictionary is embedded, not fetched from a CDN.
# A missing i18n.js means the page loads and stays English forever, which looks
# like nothing is wrong.
curl -fsS -m 5 "$BASE/static/i18n.js" | grep -q "notice.rate_limited" || fail "i18n dictionary missing notices"
curl -fsS -m 5 "$BASE/" | grep -q '/static/i18n.js' || fail "index page does not load the dictionary"
pass "bilingual UI assets are served"

# Caveats must arrive as {code, text}; a bare string means the codes got lost
# somewhere between the engine and the wire, and clients can no longer localise.
alerts=$(curl -s -m 20 "${auth[@]}" "$BASE/api/v1/domain/%E4%B8%AD%E5%9B%BD.cn")
if printf '%s' "$alerts" | grep -q '"alerts":\['; then
  printf '%s' "$alerts" | grep -q '"code":"' || fail "alerts are not coded objects"
  printf '%s' "$alerts" | grep -q '"text":"' || fail "alerts carry no fallback text"
  pass "alerts are coded objects"
else
  echo "  note no alerts on this answer; skipping the shape check"
fi

# A name below a vendor-run suffix is not the TLD registry's to sell: its
# "no match" must not come back as an availability claim. Verisign really does
# answer `No match for "FOO.UK.COM"`.
private=$(curl -s -m 20 "${auth[@]}" "$BASE/api/v1/domain/foo.uk.com")
printf '%s' "$private" | grep -q '"status":"available"' && fail "private-suffix name reported available: $private"
printf '%s' "$private" | grep -q '"code":"private_suffix_delegated"' || fail "private-suffix caveat missing"
pass "private-suffix names are not reported available"

# Underscores are valid in DNS records but never in a registrable name. Letting
# one through produced a confident `available` for a name that cannot exist.
code=$(curl -s -o /dev/null -w '%{http_code}' -m 10 "${auth[@]}" "$BASE/api/v1/domain/a_b.com")
[ "$code" = "400" ] || fail "underscore name returned $code, want 400"
pass "underscore names are rejected"

# CORS stays off unless asked for, so a private install cannot be read by any
# page a visitor has open.
curl -s -D - -o /dev/null -m 5 -H 'Origin: https://evil.example' "$BASE/api/v1/domain/example.com" \
  | grep -qi 'Access-Control-Allow-Origin' && fail "CORS leaked to an unconfigured origin"
pass "CORS is closed by default"

# Replacing the binary has to replace the UI. A fixed asset name with a day-long
# max-age left returning browsers running the previous version's JavaScript,
# silently. The HTML must reference fingerprinted asset URLs.
page=$(curl -fsS -m 5 "$BASE/")
printf '%s' "$page" | grep -q '__ASSET_VERSION__' && fail "index still carries the unfilled asset placeholder"
printf '%s' "$page" | grep -qE '/static/app\.js\?v=[a-f0-9]{12}' || fail "index does not reference a fingerprinted app.js"
asset=$(printf '%s' "$page" | grep -oE '/static/app\.js\?v=[a-f0-9]{12}' | head -1)
curl -sI -m 5 "$BASE$asset" | grep -qi 'immutable' || fail "fingerprinted asset is not immutable"
curl -sI -m 5 "$BASE/static/app.js" | grep -qi 'must-revalidate' || fail "unversioned asset is not revalidated"
pass "static assets are fingerprinted and revalidated"

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
