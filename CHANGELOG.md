# Changelog

All notable changes are recorded here. This project follows
[Semantic Versioning](https://semver.org/).

## [1.1.0] — 2025-11-15

Hardening pass over the v1.0.0 release. Everything here came from running the
binary and reading its own output, not from re-reading the code.

### Fixed

- **Cache hit/miss counters were never incremented.** `bumpHit`/`bumpMiss`
  existed but nothing called them, so `GET /api/v1/status` reported `hits: 0`
  forever, even on a fully warm cache — the one signal an operator uses to
  confirm caching works was dead. `Get` now counts both, `Peek` covers the
  singleflight re-check so de-duplication does not double every miss, and stale
  serves are counted separately.
- **A subdomain lookup could poison the parent's cached verdict.** The
  "a subdomain is never `available`" rewrite ran inside the engine, so it was
  written into the entry keyed by the registrable domain. Once anyone asked for
  `www.some-free-domain.com`, the next lookup of `some-free-domain.com` returned
  `registered` for a name that was actually for sale. The rewrite now happens in
  the per-request view (`present`) and never reaches storage.
- **Batch lookups were serial.** 20 uncached domains meant 20 registry
  round-trips end to end, so the documented cap was unusable in practice. Items
  now resolve 8 at a time; a 4-domain batch dropped from ~2.4 s to 0.6 s against
  live registries.
- **The rate limiter was not sharded.** The comment claimed a sharded map with
  per-bucket locks; the code took one global mutex for every client on every
  request. Now genuinely sharded (16 shards, per-shard lock).

### Added

- **`?raw=1`** returns the upstream payload that produced the verdict (WHOIS
  text or RDAP JSON), capped at 16 KiB. Never written to the cache: a cached
  answer explains the empty field in `meta.warnings` instead of looking like a
  silent registry. When the winning channel has no payload (RDAP 404 with an
  empty body), the sibling channel's payload is used.
- **UI: copy JSON and view raw response** buttons on every result, in both
  themes. The raw view is only offered for fresh answers, since cached ones have
  no payload to show.
- Regression tests for all of the above, including one that fails if the
  subdomain rewrite ever moves back into the engine.

## [1.0.0] — 2025-11-15

First release.

### Added

**Lookup engine**
- Parallel RDAP + WHOIS racing with evidence-based answer ranking, so a fast
  but wrong channel can never beat a slow authoritative one
- Three-state verdict (`registered` / `available` / `unknown`) with an explicit
  confidence score — a refusal is never reported as availability
- Subdomain input is reduced to its registrable domain and never reported as
  available
- IDN/Unicode input with punycode queries; eTLD+1 via the Public Suffix List
- DNS corroboration as a secondary signal, never an override
- Expiry warnings and detection of registries that withhold records

**Parsing**
- WHOIS classifier trained and regression-tested against 192 live registry
  responses covering `%`/`%%`/`#`/`*`/`[ ]` dialects, English/Spanish/Korean/
  Japanese not-found phrasings, and deliberate traps
- Handles `.hk`'s inverted "not available for registration" and quota token,
  `.io`/`.me`/`.ai` legal footers that mention rate limiting, and `.ca`/`.nz`/
  `.kr` restricted responses
- RDAP JSON parsing for statuses, events, nameservers, DNSSEC and vCard
  entities

**Routing**
- Embedded route table for 1372 TLDs generated from the IANA root database
  (876 WHOIS servers, 1203 RDAP endpoints), all verified against live servers
- Optional boot-time refresh from IANA with graceful fallback
- Learned per-server query forms (JPRS: 3.4 s → 0.2 s)

**Performance**
- Embedded bbolt cache, single file, no external service
- Stale-while-revalidate so users never wait on an expired entry
- Singleflight collapse: concurrent identical lookups cause one upstream query
- Typical answer 200-400 ms cold, under 1 ms warm

**Operations**
- Single static binary, no CGO, no runtime dependencies
- Optional bearer tokens with constant-time comparison
- Sharded token-bucket rate limiting with `Retry-After`
- Strict security headers, panic recovery, path-traversal and body-size limits
- Structured JSON logs, `healthcheck` subcommand, graceful shutdown
- Docker image running as non-root with a read-only root filesystem
- Web UI with light/dark themes, accessible markup, and no external assets

### Fixed during development

- Public Suffix List matcher rejected Unicode rules; fixed and now passes the
  official publicsuffix.org reference suite
- WHOIS response cap could exceed its limit by one chunk
- Learned query-form index was stored from a reordered slice, causing the slow
  form to be retried on every subsequent query
- Timeout validation errors did not name the offending variable
- Status chips in the UI inherited default link styling
