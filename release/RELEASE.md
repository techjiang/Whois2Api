# Whois2Api v1.3.0

**Release date:** 2025-11-15
**Commit:** b60f3d6
**License:** MIT

A self-hosted domain WHOIS/RDAP API that refuses to guess. One binary, one data
file — install in a minute, move it in a minute.

---

## Why this release matters

This is the shipping build. Every change in it came from querying live
registries with the real binary and reading what came back — not from reading
the code. Two of the four fixes are **verdict errors**, the exact category this
project exists to eliminate.

## What was fixed

### 1. A name under a vendor-run suffix was reported `available`

Verisign really does answer:

```
$ whois foo.uk.com
No match for "FOO.UK.COM".
```

Literally correct, and completely wrong as a verdict: `.com`'s registry does not
administer names under `uk.com`. A tool that pattern-matches "no match" tells you
a name is free to register when nobody can register it. Same for
`a.b.github.io`, `x.s3.amazonaws.com`, and every other PRIVATE-section suffix.

Now: the PSL tracks which rules came from the PRIVATE section, and a name
strictly below one of them comes back `unknown` with a
`private_suffix_delegated` caveat. The suffix *itself* (`github.io`, `uk.com`)
does have a real registry record and is queried normally.

### 2. `a_b.com` was reported `available`

An underscore is legal in a DNS record (`_dmarc.example.com`) but never in a
registrable name. The name went upstream as typed, the registry answered "no
match" because no such name can exist, and the answer came back `available` with
95% confidence. Underscores are now rejected at normalization with
`invalid_domain`.

### 3. The API was unreachable from browser clients

No CORS headers at all, and `OPTIONS` fell through to a 405 — so
`POST /api/v1/batch` could not be called from any page this process did not
serve. CORS is now configurable via `W2A_CORS_ORIGINS`, **off by default** so a
private install cannot be read by every page a visitor has open. Preflight is
answered for allowed origins only.

### 4. Module path

The Go module is now `github.com/techjiang/Whois2Api`, matching where the project
is published.

### Plus a copy fix

The error heading interpolated the raw input into a sentence, producing
"Could not look up not a domain". The input is now quoted.

## Install

### Binary

```bash
curl -fsSL https://github.com/techjiang/Whois2Api/releases/latest/download/whois2api-linux-amd64 -o whois2api
chmod +x whois2api
./whois2api
```

Open <http://localhost:8080>.

### Docker

```bash
docker run -d --name whois2api \
  -p 8080:8080 \
  -v whois2api-data:/data \
  whois2api:1.3.0
```

### From source

```bash
git clone https://github.com/techjiang/Whois2Api && cd Whois2Api
make build && ./bin/whois2api
```

## Artifacts

| File | Platform |
|---|---|
| `whois2api-linux-amd64` | Linux x86-64 |
| `whois2api-linux-arm64` | Linux ARM64 (Raspberry Pi 4/5, ARM servers) |
| `whois2api-linux-arm` | Linux ARMv7 (Pi 2/3, older ARM boards) |
| `whois2api-linux-386` | Linux x86 32-bit |
| `whois2api-darwin-amd64` | macOS Intel |
| `whois2api-darwin-arm64` | macOS Apple Silicon |
| `whois2api-windows-amd64.exe` | Windows x86-64 |
| `SHA256SUMS.txt` | Checksums for all of the above |

All binaries are static (`CGO_ENABLED=0`), stripped, and need no runtime.

Verify a download:

```bash
sha256sum -c SHA256SUMS.txt --ignore-missing
```

## Verification

- `gofmt -l .` clean, `go vet ./...` clean
- `go test -race ./...` green on all 7 packages
- `scripts/smoke.sh` passes, including three new assertions: private-suffix
  names are not reported available, underscore names are rejected, and CORS is
  closed by default
- Checked by hand against live registries: `registered` / `available` /
  `unknown` / subdomain / private suffix / IDN / invalid input, in both themes,
  Chinese and English, at 1100 px and 390 px (no horizontal overflow, no page
  errors)

## The three verdicts

| Verdict | Meaning |
|---|---|
| `registered` | An authoritative registry returned a record for the name |
| `available` | A registry **explicitly** said the name does not exist |
| `unknown` | Refused, throttled, timed out, or answered in a dialect this build does not model |

`unknown` is not a green light. Treating it as available is the bug this service
exists to prevent.

## Upgrading from 1.2.x

Drop-in. `W2A_CORS_ORIGINS` is new and defaults to off, and the notice code
`private_suffix_delegated` is additive — clients that do not know it fall back to
the English `text`. The cache schema is unchanged; keep your `whois2api.db`.
