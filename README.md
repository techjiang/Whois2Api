<p align="center">
  <img src="web/logo.svg" alt="" width="88" height="88">
</p>

<h1 align="center">Whois2Api</h1>

<p align="center">
  A self-hosted domain WHOIS/RDAP API that refuses to guess.<br>
  One binary. One data file. Install in a minute, move it in a minute.
</p>

<p align="center">
  <a href="#quick-start">Quick start</a> ·
  <a href="#the-design-bet">Design</a> ·
  <a href="#api">API</a> ·
  <a href="#configuration">Configuration</a> ·
  <a href="#backup-and-migration">Backup</a>
</p>

---

## Why another WHOIS API

Most self-hosted WHOIS tools share one dangerous bug: when a registry is slow,
rate-limits them, or answers in a dialect they do not parse, they return
**"available"**. For a domain investor that means a false buying signal; for a
security team it means a false all-clear.

Whois2Api is built around the opposite rule:

> If no registry gave an affirmative answer, say **unknown**. Never guess.

Two concrete traps it handles, both verified against live registries:

| Case | Naive behaviour | Whois2Api |
|---|---|---|
| `www.google.com` | Registry says "No match for WWW.GOOGLE.COM" → **available** (wrong: you cannot register it) | Reduces to `google.com`, reports `registered`, explains the subdomain |
| `.io` / `.me` / `.ai` registered records | Legal footer contains "rate limited" / "not permitted" → **unknown** or wrong | Anchored matching ignores disclaimers; reports `registered` |
| `.hk` registered record | Body says "**not** available for registration" → **available** (inverted) | Phrase-aware rules report `registered` |
| `.ca` / `.nz` / `.kr` restricted names | Error response → **available** | Reports `registered` with a "restricted" note |

## Quick start

### Docker (recommended)

```bash
docker run -d --name whois2api \
  -p 8080:8080 \
  -v whois2api-data:/data \
  whois2api:latest
```

Open <http://localhost:8080>.

### Binary

```bash
curl -fsSL https://github.com/asoe/whois2api/releases/latest/download/whois2api-linux-amd64 -o whois2api
chmod +x whois2api
./whois2api
```

That is the whole installation. There is no database server to run, no migration
step, and no configuration file to write.

### From source

```bash
git clone https://github.com/asoe/whois2api && cd whois2api
make build && ./bin/whois2api
```

## The design bet

Three decisions carry this project.

### 1. A three-state verdict, with confidence

`registered`, `available`, `unknown`. `available` requires an **affirmative**
"no such object" from a registry. A timeout, a throttle, a block, or an
unparseable body is `unknown`, every time. Each answer also carries a
`confidence` score and the per-channel timings that produced it, so callers can
judge for themselves.

### 2. Race the protocols, then pick by evidence

RDAP (structured JSON) and WHOIS (port 43 text) are queried **in parallel**, not
as a sequential fallback. The first definitive answer wins after a short grace
window, so a fast registry stays fast (~200-400 ms typical) while a slow or
broken one cannot hold the request hostage.

"First answer" is not "fastest answer": results are ranked by evidentiary
strength. A rapid `not found` from a throttled endpoint never outranks a slow,
authoritative record.

### 3. Honest parsing, learned from live registries

The WHOIS classifier is not written from imagination. It is trained and
regression-tested against **192 real responses** captured from production
registry servers (in [`testdata/whois/`](testdata/whois)), spanning:

- comment dialects: `%`, `%%`, `#`, `*`, `[ ]` banners
- "not found" phrasings in English, Spanish, Korean and Japanese
- deliberate traps, including `.hk`'s inverted "not available" and `.io`'s legal
  footers that mention rate limiting
- registries that withhold records (`.ca`, `.nz`, `.kr`, `.om`)

The route table for all **1372 TLDs** is generated from the IANA root database,
with the 876 WHOIS hosts and 1203 RDAP endpoints verified against live servers.

## Features

**Operations**
- Single static binary, zero dependencies, ~7 MB
- Entire state is one bbolt file — back up by copying it
- Graceful shutdown, structured JSON logs, `healthcheck` subcommand
- Multi-arch-friendly, runs read-only in Docker as non-root

**Performance**
- RDAP ∥ WHOIS racing; typical answer 200-400 ms, cached answers <1 ms
- Embedded key/value cache with per-channel TTLs
- **Stale-while-revalidate**: expired entries are served instantly while one
  background refresh runs
- **Singleflight collapse**: 100 concurrent requests for one domain produce
  exactly one upstream query, so a busy install never gets itself throttled
- Learned per-server query preferences (e.g. JPRS went from 3.4 s to 0.2 s)

**Interface**
- Bilingual UI (Chinese / English): switches in one click, remembers the
  choice, and follows the browser's language on first visit
- Notices and errors carry stable codes, so a client can render them in any
  language instead of shipping English prose to its users
- Light and dark themes, no CSS framework, no web fonts, no build step

**Correctness**
- IDN/Unicode input, punycode output, correct eTLD+1 via the Public Suffix List
- Passes the official publicsuffix.org reference suite (98 cases)
- Subdomain queries resolve to the registrable domain and are never reported
  as available
- DNS corroboration as a secondary signal (never overrides a registry)
- Expiry warnings and registry-withheld detection

**Security**
- Optional bearer tokens with constant-time comparison
- Sharded token-bucket rate limiting, `Retry-After` on 429
- `X-Forwarded-For` honoured only from configured trusted proxies
- Strict CSP, `nosniff`, `no-referrer`, frame denial
- Panic recovery; no internal error details or IPs leak to clients
- Input validation against path traversal; bounded request/response sizes

## API

### Look up one domain

```bash
curl -s "http://localhost:8080/api/v1/domain/example.com"
```

```json
{
  "domain": {
    "name": "example.com",
    "input": "example.com",
    "query_target": "example.com",
    "tld": "com",
    "suffix": "com",
    "registrable": "example.com",
    "status": "registered",
    "confidence": 95,
    "source": "rdap",
    "registrar": "RESERVED-Internet Assigned Numbers Authority",
    "created_at": "1995-08-14T04:00:00Z",
    "expires_at": "2025-08-13T04:00:00Z",
    "days_until_expiry": 120,
    "statuses": [{"code": "client delete prohibited", "url": "https://icann.org/epp#clientdeleteprohibited"}],
    "name_servers": ["a.iana-servers.net", "b.iana-servers.net"],
    "dnssec": "signed",
    "dns_resolves": true,
    "alerts": []
  },
  "meta": {
    "cached": false,
    "total_ms": 312,
    "channels": [
      {"channel": "whois", "ms": 188, "ok": true},
      {"channel": "rdap", "ms": 310, "ok": true}
    ]
  }
}
```

`GET /api/v1/whois/{name}` is an alias that more people guess correctly.

`alerts` (and `meta.warnings`) are objects, not strings: `{"code": "...",
"text": "..."}`. `code` is stable and is what you translate or branch on;
`text` is the English wording, used as a fallback. Full code list in
[docs/CLIENT.md](docs/CLIENT.md#alerts-and-metawarnings).

### Batch

```bash
curl -s -X POST "http://localhost:8080/api/v1/batch" \
  -H 'Content-Type: application/json' \
  -d '{"domains":["example.com","example.org","example.net"]}'
```

Batch cap defaults to 20 (`W2A_MAX_BATCH`). Per-item errors do not fail the
request, results come back in the order you sent them, and items are resolved
concurrently (8 at a time) — a batch of 20 uncached domains costs roughly one
registry round-trip, not twenty.

### Seeing the raw registry answer

Add `?raw=1` to get the upstream payload that produced the verdict — the actual
WHOIS text or RDAP JSON. It is off by default because it triples the response
size and nobody reading a verdict wants a legal footer.

```bash
curl -s "http://localhost:8080/api/v1/domain/example.com?raw=1" | jq -r '.domain.raw'
```

Raw payloads are never written to the cache — that would multiply every entry's
size for a field almost nobody asks for. A cached answer therefore says so in
`meta.warnings` and points at the fix: add `&fresh=1` to bypass the cache and
ask the registry again.

### Other endpoints

| Endpoint | Purpose |
|---|---|
| `GET /api/v1/status` | Version, uptime, TLD coverage, live cache hit/miss counters |
| `GET /api/v1/health` | Liveness; never requires auth |
| `GET /api/v1/tlds` | Every supported TLD |

### Error shape

Every failure uses one envelope, with a machine-readable `code` and an
actionable `hint`:

```json
{"error": {"code": "invalid_domain", "message": "That does not look like a valid domain name.", "hint": "Send a registrable name such as example.com; IDNs are accepted."}}
```

| Status | Codes |
|---|---|
| 400 | `invalid_domain`, `bad_request`, `too_many_items` |
| 401 | `unauthorized` |
| 404 | `unsupported_tld` |
| 405 | `method_not_allowed` |
| 429 | `rate_limited` |
| 500 | `internal_error` |
| 504 | `upstream_unavailable` |

Codes are stable and never renamed; a client may branch on them without
parsing the English prose.

## Language support

The API speaks English (`text` / `message` / `hint` are English), and codes are
the localisable part. The bundled UI ships Chinese and English; adding a third
language is one block in `web/i18n.js`, and `go test ./internal/api` will list
any code you forgot to translate.

Notice codes live in `internal/model/model.go` as named constants
(`model.NoticeRateLimited`, …) so a typo in a caveat is a compile error rather
than a string that silently stops being translated.

## Configuration

Every setting has a working default; environment variables are optional.

| Variable | Default | Meaning |
|---|---|---|
| `W2A_LISTEN` | `:8080` | Bind address |
| `W2A_DATA_DIR` | `./data` | Where the cache database lives |
| `W2A_TOKENS` | *(empty)* | Comma-separated tokens; empty disables auth |
| `W2A_RATE_LIMIT` | `300` | Requests/minute/client; `0` disables |
| `W2A_RATE_BURST` | `60` | Burst allowance |
| `W2A_CACHE_TTL` | `30m` | Lifetime of a registered answer |
| `W2A_NEGATIVE_TTL` | `5m` | Lifetime of an available answer |
| `W2A_STALE_TTL` | `24h` | Window for stale-while-revalidate |
| `W2A_RDAP_TIMEOUT` | `6s` | Per-RDAP request |
| `W2A_WHOIS_TIMEOUT` | `8s` | Per-WHOIS exchange |
| `W2A_TOTAL_TIMEOUT` | `12s` | Whole lookup |
| `W2A_MAX_BATCH` | `20` | Batch size cap |
| `W2A_TRUSTED_PROXIES` | *(none)* | CIDRs allowed to set `X-Forwarded-For` |
| `W2A_REFRESH_TABLE` | `false` | Fetch the IANA TLD table on boot |
| `W2A_RDAP_ONLY` | `false` | Skip WHOIS entirely |
| `W2A_WHOIS_FIRST` | `false` | Prefer WHOIS when both agree |
| `W2A_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |

Invalid values fail at startup with a message naming the offending variable.

### Running behind a proxy

Only set this when a reverse proxy you control terminates the connection.
Without it, `X-Forwarded-For` is ignored — otherwise any client could bypass
rate limits by forging the header.

```bash
W2A_TRUSTED_PROXIES=10.0.0.0/8,172.16.0.0/12
```

## Backup and migration

All persistent state is a single file: `$W2A_DATA_DIR/whois2api.db`.

```bash
# Back up (safe while running: bbolt supports hot copies)
docker run --rm -v whois2api-data:/data -v "$PWD":/backup alpine \
  cp /data/whois2api.db /backup/whois2api-$(date +%F).db

# Restore on another machine
docker run -d --name whois2api -p 8080:8080 \
  -v "$PWD/whois2api-2025-01-01.db":/data/whois2api.db \
  whois2api:latest
```

The cache is disposable: delete the file and the service rebuilds it by
querying registries. Nothing else needs migrating.

## Development

```bash
make help      # list targets
make test      # unit + integration tests
make race      # race detector (needs gcc)
make smoke     # end-to-end test against a real instance
make lint      # gofmt + go vet
make assets    # re-encode PNG logos from web/logo.svg
```

### Test philosophy

The interesting tests are behavioural, not line-coverage exercises:

- `internal/parse` runs the classifier over 192 live registry responses and
  fails on any **confident wrong** verdict
- `internal/tld` runs the official publicsuffix.org reference suite
- `internal/lookup` proves subdomain reduction, cache sharing, singleflight
  collapse, and stale-while-revalidate using a deterministic fake upstream
- `internal/api` covers auth, rate limiting, body limits, path traversal and
  panic recovery
- `scripts/smoke.sh` asserts the deployed contract end to end

```bash
go test ./...              # 70 test functions, ~3s
bash scripts/smoke.sh      # full-stack smoke test
```

## License

MIT
