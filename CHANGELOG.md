# Changelog

All notable changes are recorded here. This project follows
[Semantic Versioning](https://semver.org/).

## [1.2.1] — 2025-11-15

Same domain, same answer. This release fixes the cases where the response
depended on state the caller cannot see — whether the entry was warm, and who
happened to fill it first.

Every fix below was found by running the binary and comparing two responses to
the same question, not by reading the code.

### Fixed

- **A warm answer dropped caveats a cold one reported.** `registered_without_dns`
  (and `dns_resolves_but_available`, `expires_within_30_days`, …) were computed
  once at lookup time and then stripped by `storageView` along with everything
  else per-request. Ask about a dead-but-registered name twice and the second
  answer quietly omitted the warning. Alerts are now split into two kinds:
  registry facts, which are cached, and per-request observations (DNS probe,
  expiry countdown, subdomain rewrite), which are re-derived on every read.
- **A subdomain query renamed its parent.** The cache entry stores the name of
  whichever query filled it; `present()` copied that name into the response. One
  lookup of `deep.sub.example.org` and every later answer about `example.org`
  came back titled `deep.sub.example.org` — a name the caller never typed, for a
  record that is about the parent.
- **A dead subdomain could cache "no DNS" for a live parent.** The DNS probe
  measured the caller's exact name but the result was stored in an entry keyed
  by the registrable domain, so `no-such-sub.example.org` stored
  `dns_resolves: false` for `example.org`. The probe now measures the
  registrable domain, which is what the entry describes.
- **`/api/v1/batch` shipped upstream payloads nobody asked for.** The raw WHOIS
  text / RDAP JSON is opt-in via `?raw=1` on the single-domain endpoint, but a
  batch has no such flag — and still returned the payload. A cold five-domain
  batch answered with ~11 KB of registry text; the same five names warm answered
  with 1.8 KB. Batch responses now carry no payload.
- **`?fresh=1` counted as a cache hit.** The bypass read the entry (incrementing
  `hits`) and then ignored it, so `/api/v1/status` reported hits for answers that
  were by definition not served from cache. Three forced refreshes showed three
  hits.

### Fixed (UI)

- **Switching language threw away the raw-payload panel.** The card is rebuilt
  on a language switch, which dropped the panel the reader had opened; the
  button then offered to fetch it again from a registry we had already asked.
  The payload and its open state now live outside the DOM and are restored.
  Collapsing the panel by hand is remembered too — `toggle` is dispatched as a
  queued task, so a panel torn down by the rebuild reported `open: false` after
  the new card was already built and slammed the state shut.
- **"原始 upstream 响应"** — the channel name was interpolated raw. Channel names
  are now dictionary keys, and a test fails if any of them is missing.
- **`DNS 解析` on a subdomain card** now names the domain that was actually
  probed (`DNS 解析（iana.org）`), because the answer is about the registrable
  domain, not the name in the title.

### Fixed (tests)

- **A data race in the API test fake.** `fakeUpstream.calls` was a plain `int`
  incremented from every batch goroutine. `go test -race` had never actually run
  on this project — the earlier note about a missing C toolchain was accurate at
  the time, and it hid this. The counter is atomic now, and `-race` is green on
  the whole tree.

### Added

- Tests for the invariants these bugs violated: cold and warm answers to the
  same question are identical; a parent lookup after a subdomain lookup does not
  inherit the subdomain's name; only registry facts are cached; a batch never
  ships a payload; a bypass is not a hit.

## [1.2.0] — 2025-11-15

The UI is now bilingual (Chinese and English). Doing it the obvious way — running
a find-and-replace over the English strings in the frontend — would have been
the same class of mistake this project exists to avoid: a translation that
silently drifts from its source. So the API changed first, and the UI became a
renderer.

### Changed

- **`alerts` and `meta.warnings` are now `{code, text}` objects, not bare
  strings.** `code` is a stable identifier (`rate_limited`,
  `registered_without_dns`, …) and `text` is the canonical English wording.
  Clients localise on the code and fall back to the text, so editing an English
  sentence can no longer leave a Chinese reader with English in the middle of a
  card. This is a breaking change to a field that used to be `[]string` — the
  only one in this release, and the reason it is a minor bump rather than a
  patch.
- **Notice severity is derived from the code**, not from pattern-matching the
  English prose (`/not|expired|refus|rate/i`), which would have broken the
  moment the wording or the language changed.

### Added

- **Bilingual UI.** Chinese and English, switched with one button in the header,
  persisted in `localStorage`, and defaulted from `navigator.languages` — so a
  `zh-CN` browser opens in Chinese without anyone clicking anything.
- **Switching language re-renders the card on screen**, not just the static
  chrome. The last result and the last error are kept for exactly this reason;
  otherwise a visitor who flips language mid-investigation gets a half-Chinese
  page.
- **Every notice and error code has a translation in every language**, enforced
  by a test that reads the dictionary out of the embedded assets. An untranslated
  code is a failure, not a stylistic nit.
- **A test that fails when the English dictionary contains CJK text.** A
  screenshot caught `Cached 63 秒 ago` in the English UI; this catches it in CI
  instead of in a review.
- **A test that fails when `web/` and `internal/api/assets/` disagree.** They are
  duplicates by design (embedding needs the files under the package), and the
  failure mode is silent: you edit `web/app.js`, rebuild, and nothing changes.

### Fixed

- **A cached answer for a subdomain was titled with the parent name.** The card
  heading used `domain.name`, which for a cached entry is the registrable key,
  so looking up `www.example.com` produced a card headed `example.com` — a name
  nobody typed. The heading now shows the name as entered and keeps the ASCII
  form as a secondary label for IDN input.
- **A cache hit reported "Answered in 0 ms".** No registry round-trip happened,
  so there was no duration to report; the timer looked broken. Cache hits now
  report the entry's age (`缓存命中，2 分钟前写入` / `From cache (written 2 min
  ago)`), and stale serves say which they are.
- **The UI no longer makes a wasted `/api/v1/health` request** on every load. It
  read nothing from it — the version comes from `/api/v1/status`.

### Notes

- The API is still English-first: `text` is English, `code` is the contract. If
  you want a third language in the UI, add a block to `web/i18n.js`; the tests
  will tell you which codes you missed.
- Registry data (registrar names, EPP status codes, raw payloads) is never
  translated. Inventing Chinese names for registrars would be worse than showing
  the registry's own field.

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
