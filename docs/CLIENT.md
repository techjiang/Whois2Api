# Client recipes

Practical examples for the common languages, plus the response semantics worth
knowing before you build on top.

## The one rule

`status` is a three-state value. Only `available` means "you can register this".
`unknown` means "no registry told us", which is **not** a green light:

```python
if result["domain"]["status"] == "available":
    register(...)
elif result["domain"]["status"] == "registered":
    pass
else:
    # Do not treat this as available. Back off and retry later.
    schedule_retry()
```

Treating `unknown` as available is the bug this service exists to prevent.

## Python

```python
import requests

BASE = "http://localhost:8080"
TOKEN = None  # set if W2A_TOKENS is configured

def lookup(domain: str) -> dict:
    headers = {"Authorization": f"Bearer {TOKEN}"} if TOKEN else {}
    r = requests.get(f"{BASE}/api/v1/domain/{domain}", headers=headers, timeout=30)
    if r.status_code == 429:
        raise RuntimeError(f"rate limited; retry after {r.headers.get('Retry-After')}s")
    r.raise_for_status()
    return r.json()["domain"]

for name in ["example.com", "example.org"]:
    d = lookup(name)
    expiry = d.get("expires_at", "?")
    print(f"{name:20} {d['status']:10} expires {expiry}")
```

Bulk with the batch endpoint:

```python
def batch(domains: list[str]) -> list[dict]:
    r = requests.post(f"{BASE}/api/v1/batch", json={"domains": domains}, timeout=60)
    r.raise_for_status()
    return r.json()["results"]
```

## Node.js

```js
const BASE = 'http://localhost:8080';

async function lookup(domain) {
  const res = await fetch(`${BASE}/api/v1/domain/${encodeURIComponent(domain)}`);
  const body = await res.json();
  if (!res.ok) throw new Error(`${body.error.code}: ${body.error.message}`);
  return body.domain;
}

const d = await lookup('example.com');
console.log(d.name, d.status, d.confidence, d.registrar);
```

## Go

```go
type domainResult struct {
	Domain struct {
		Name      string `json:"name"`
		Status    string `json:"status"`
		Registrar string `json:"registrar"`
		ExpiresAt string `json:"expires_at"`
	} `json:"domain"`
}

func lookup(ctx context.Context, base, name string) (*domainResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		base+"/api/v1/domain/"+url.PathEscape(name), nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("lookup %s: status %d", name, resp.StatusCode)
	}
	var out domainResult
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}
```

## curl and jq

```bash
# Just the verdict
curl -s "http://localhost:8080/api/v1/domain/example.com" | jq -r '.domain.status'

# Domains expiring within 30 days
curl -s -X POST "http://localhost:8080/api/v1/batch" \
  -H 'Content-Type: application/json' \
  -d '{"domains":["a.com","b.com","c.com"]}' \
  | jq -r '.results[] | select(.domain.days_until_expiry != null and .domain.days_until_expiry < 30)
           | "\(.domain.name) \(.domain.days_until_expiry)"'

# Which channel answered, and how fast
curl -s "http://localhost:8080/api/v1/domain/example.com" | jq '.meta.channels'
```

## Handling responses

### `confidence`

| Value | Meaning |
|---|---|
| 95 | A registry (and usually both protocols) gave a definitive answer |
| 80 | One authoritative answer, or a record withheld by the registry |
| 35 | No registry answer; DNS resolution suggests the name is taken |
| 0 | Nothing usable; treat as unknown |

### `alerts` and `meta.warnings`

Structured notices explaining unusual findings. Each one is `{code, text}`:

```json
"alerts": [
  {"code": "registered_without_dns",
   "text": "Registered but currently has no address records (parked or not yet configured)."}
]
```

`code` is the contract — branch and localise on it. `text` is the canonical
English wording, and the fallback when your client does not know the code. That
split exists so a copy edit to the English sentence cannot silently leave your
Chinese (or Japanese, or German) UI showing English.

Codes currently emitted:

| Code | Meaning |
|---|---|
| `registry_withheld` | The registry confirms the name exists but withholds the record |
| `rate_limited` | The registry throttled this query; retry shortly |
| `blocked` | The registry refused the query by access policy |
| `dns_resolves_but_available` | Registry says free, DNS says it resolves (wildcard or lag) |
| `registered_without_dns` | Registered but no address records right now |
| `unknown_but_dns` | No registry answer, but the name resolves — almost certainly taken |
| `private_suffix_delegated` | The name sits below a vendor-run suffix (`github.io`, `uk.com`); the TLD registry cannot answer for it |
| `subdomain_parent_available` | You asked about a subdomain; only the registrable parent is registrable |
| `expired` | Registration has expired |
| `expires_within_7_days` / `expires_within_30_days` | Renewal risk |
| `stale_served` | Served from cache while a background refresh runs |
| `no_answer_no_dns` | No registry answer and no DNS records; availability unconfirmed |
| `cached_without_raw` | You asked for `?raw=1`, but cached entries carry no payload |
| `no_upstream_payload` | The registry answered without a payload this build can show |

New codes are additive; existing ones are never renamed. Treat an unknown code
as `text` and carry on — that is what the bundled UI does.

### `meta.channels`

Per-protocol timings and failures. When a result is `unknown`, this tells you
why:

```json
"channels": [
  {"channel": "whois", "ms": 183, "ok": false, "error": "whois: timeout"},
  {"channel": "rdap", "ms": 0, "ok": false, "error": "rdap: transport error"}
]
```

### Caching

`meta.cached` is true when the answer came from the embedded cache.
`meta.stale` means it was served while a background refresh runs — the data may
be slightly old but no request waited for a registry.

## Retry strategy

The service already retries and caches. Your client should retry only on:

- **429** — honour `Retry-After`
- **504** — registries were slow; back off with jitter
- **5xx** — back off

Do not retry **400** (invalid domain) or **404** (unsupported TLD): the answer
will not change.

```python
import time, random

def lookup_with_retry(domain, attempts=3):
    for i in range(attempts):
        try:
            return lookup(domain)
        except Exception as e:
            if i == attempts - 1:
                raise
            time.sleep((2 ** i) + random.random())
```

## Parsing IDN results

`name` is always ASCII (punycode). `unicode` is present when the input was an
internationalized name:

```json
{"name": "xn--fiqs8s.cn", "unicode": "中国.cn", "status": "registered"}
```

Display `unicode` to humans, and use `name` as a cache or database key.
