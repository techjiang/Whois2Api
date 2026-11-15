# Architecture

A tour of the decisions and the reasons behind them.

```
cmd/whois2api      wiring, subcommands, graceful shutdown
internal/config    env parsing + cross-field validation
internal/tld       Public Suffix List + IANA-generated route table
internal/lookup    target normalization, protocol racing, verdict synthesis
internal/parse     WHOIS text and RDAP JSON -> structured fields + verdicts
internal/upstream  RDAP (HTTP) and WHOIS (port 43) clients
internal/cache     bbolt-backed result store
internal/api       HTTP surface, auth, rate limiting, embedded UI
```

Dependencies flow one way: `api -> lookup -> {parse, upstream, cache, tld}`.
Nothing in `lookup` imports `api`, so the engine is testable without HTTP.

## 1. Normalization comes first

```
"WWW.Example.CO.UK."  ->  ascii   "www.example.co.uk"
                          query   "example.co.uk"   (registrable domain)
                          suffix  "co.uk"
```

Registries only answer for the registrable domain. Asking Verisign about
`www.google.com` yields `No match for "WWW.GOOGLE.COM"` — literally true, and
completely misleading. Normalizing up front means we never ask the wrong
question, and the caller still sees their own input echoed back in `input`.

The Public Suffix List decides where the registrable boundary is, which is why
`foo.github.io` is treated as its own registrable domain (the PRIVATE section
declares `github.io` a suffix) while `github.io` itself is a valid query target.

## 2. Two protocols, one race

```go
go e.rdap.Query(...)   // structured JSON, HTTP
go e.whois.Query(...)  // unstructured text, TCP :43
```

Both start immediately. The engine returns as soon as one produces a
definitive answer, after a 300 ms grace window during which the loser can still
contribute corroboration.

Why race rather than fall back:

- Sequential fallback pays the sum of both latencies.
- Registries are individually flaky. Racing gives two independent chances.
- The two channels disagree in informative ways (see §4).

### Ranking, not arrival order

`choose()` scores answers by evidentiary strength:

| Outcome | Score |
|---|---|
| found | 100 |
| not found | 90 |
| restricted | 85 |
| rate limited / blocked | 10 |
| unusable | 0 |

A 40 ms `not found` from a throttled endpoint loses to a 900 ms authoritative
record. Ties break toward RDAP (structured input is less likely misparsed),
then toward lower latency.

## 3. Classification is the safety-critical part

`parse.Classify` is a small state machine over normalized lines. Order matters
enormously:

1. **Refusals** (rate limit, block, policy veto) — checked first, anchored to
   line start, only on the first 8 lines.
2. **Restricted** ("exists but withheld") — checked before availability.
3. **Affirmative "no such object"** phrases.
4. **Record-shaped structures** -> found.
5. Everything else -> **unusable**, which the service surfaces as `unknown`.

### Why anchoring is not pedantry

A registered `.io` record ends with a multi-paragraph legal notice containing
the sentence *"Queries to the Whois services are rate limited."* A substring
search for `rate limit` classifies **every registered .io domain** as throttled.
The same notice says *"It is not permitted to use this data"*, so a substring
search for `not permitted` marks them blocked.

Anchoring to the beginning of a line and scanning only the head of the response
avoids this without special-casing any registry.

### The corpus is the specification

`testdata/whois/` holds 192 captured responses: `<tld>.yes.txt` for a registered
name, `<tld>.no.txt` for one the registry explicitly reported absent. The test
asserts the classifier never produces a **confident wrong** verdict. Refusals and
genuinely unparseable dialects are counted and reported, not failed — reporting
`unknown` is the correct behaviour for them.

This corpus found real bugs during development:

- `.hk` returns *"This domain is currently not available for registration"* for
  a **registered** name. Substring matching on "available" inverts the verdict.
- `.ca`, `.nz`, `.kr` answer with `Error code: 01044 ... usage restrictions` for
  names that exist. Treating the error as "free" is dangerously wrong.
- `.sl` and `.sr` put `No Object Found` in a *field value*
  (`Domain Status: No Object Found`), so the phrase must be matched in place,
  not only at line start.
- `.cn` answers *"Queried interval is too short"* (throttle) and *"the Domain
  Name you apply can not be registered online"* (policy veto) — neither is an
  availability statement.

## 4. DNS as a second opinion, never a verdict

After the registry answer, the engine resolves the name. This is used to:

- explain contradictions (`available` but resolves → wildcard DNS or a lagging
  registry view)
- add confidence when registries gave nothing (`unknown` but resolves → almost
  certainly registered, confidence raised to 35)
- note parked domains (`registered` but no addresses)

DNS never overrides a definitive registry answer, because a registry record is
the authority and DNS state changes by the minute.

## 5. Cache design

```
lookup(key):
  fresh?          -> return immediately               (0 upstream calls)
  stale but in
  stale window?   -> return stale + refresh in bg     (0 upstream calls)
  else            -> singleflight(key) { query, store }
```

Three properties matter:

**Singleflight collapse.** A hundred simultaneous requests for one domain issue
one upstream query. Without this, a traffic spike makes the install look like an
abuser and gets it throttled by registries — which then produces `unknown`
answers for everyone. This is a correctness feature, not just an optimisation.

**Stale-while-revalidate.** Users never wait on a slow registry for a name that
was recently looked up. One background refresh runs per key.

**Unknown is not cached.** A transient upstream failure must not be pinned for
the whole TTL.

**The cache stores the registry answer, not the caller's question.** A view
layer (`present`) layers per-request facts on top of a cached record: the name
the caller typed, the subdomain relationship, a recomputed expiry countdown,
and the raw payload. Anything request-shaped is stripped by `storageView`
before the write. Getting this backwards is subtle and expensive — when the
"a subdomain is never available" rewrite lived in the engine, it wrote
`registered` into the entry shared with a genuinely available parent, so the
next lookup of the parent reported a for-sale domain as taken.

**Cache counters are wired at the store, not the caller.** `Get` counts a hit
or a miss; the singleflight re-check uses `Peek` so de-duplication does not
double the miss count. Stale serves are counted separately. A status endpoint
that reports `hits: 0` on a warm cache is worse than no status endpoint. `available` uses a much shorter TTL (5 min default) than
`registered` (30 min), because availability changes faster and a stale
"available" is the expensive kind of wrong.

The store is bbolt: a single file, crash-safe, no server, no CGO. "Back up the
install" is "copy one file".

## 6. Concurrency and shutdown

- Every request carries a context with a total timeout; a hung registry cannot
  pin a goroutine indefinitely.
- Batch lookups fan out with a bounded worker pool (8 in flight) and write
  results back by index, so a 20-domain batch costs about one registry
  round-trip instead of twenty while the response keeps the caller's order.
- The race uses a buffered channel sized to the number of launched goroutines,
  so an early return never leaks a sender.
- WHOIS reads use a per-chunk idle deadline (there is no length prefix on port
  43; idleness is the only reliable end-of-response signal) plus a hard 512 KiB
  cap.
- RDAP bodies are capped at 2 MiB and drained so connections are reusable.
- Shutdown: stop accepting, drain in-flight requests for up to 15 s, then close
  the database.

## 7. What is deliberately NOT here

- **No external queue or database.** Every dependency is a liability for the
  "a beginner can run this" goal.
- **No registrar-level WHOIS follow-up.** Querying `whois.markmonitor.com` for
  registrant details is a separate, rate-limited, often-redacted domain of
  problems; the registry record is the reliable source.
- **No scraping.** Only the two protocols designed for machine queries.
- **No "availability score" heuristics.** A number between 0 and 1 would invite
  people to trust guesses. Three states plus an explicit confidence bucket is
  honest about what is known.
