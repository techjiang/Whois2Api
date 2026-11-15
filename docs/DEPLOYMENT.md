# Deployment

## Requirements

- Any Linux/amd64, Linux/arm64, macOS, or Windows host
- Outbound TCP 43 (WHOIS) and TCP 443 (RDAP)
- ~20 MB disk for the binary, plus the cache database

No inbound ports except the HTTP one you choose.

## Docker

```bash
docker run -d --name whois2api \
  -p 8080:8080 \
  -e W2A_TOKENS="$(openssl rand -hex 24)" \
  -v whois2api-data:/data \
  --restart unless-stopped \
  whois2api:latest
```

The image runs as UID 10001, drops all capabilities, and is designed to work
with a read-only root filesystem:

```bash
docker run -d --name whois2api \
  -p 8080:8080 \
  --read-only --tmpfs /tmp \
  --cap-drop ALL --security-opt no-new-privileges \
  -v whois2api-data:/data \
  whois2api:latest
```

### Compose

```bash
docker compose up -d
docker compose logs -f
```

## systemd

```ini
# /etc/systemd/system/whois2api.service
[Unit]
Description=Whois2Api domain lookup API
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=whois2api
Group=whois2api
ExecStart=/usr/local/bin/whois2api
Environment=W2A_LISTEN=127.0.0.1:8080
Environment=W2A_DATA_DIR=/var/lib/whois2api
EnvironmentFile=-/etc/whois2api.env
Restart=on-failure
RestartSec=3

# Hardening: the service only needs the data directory and outbound sockets.
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
ReadWritePaths=/var/lib/whois2api

[Install]
WantedBy=multi-user.target
```

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin whois2api
sudo install -d -o whois2api -g whois2api /var/lib/whois2api
sudo install -m 0755 whois2api /usr/local/bin/whois2api
sudo systemctl enable --now whois2api
```

Put secrets in `/etc/whois2api.env` (mode 0600):

```
W2A_TOKENS=replace-with-a-long-random-token
```

## Reverse proxy (nginx)

```nginx
server {
    listen 443 ssl http2;
    server_name whois.example.com;

    ssl_certificate     /etc/letsencrypt/live/whois.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/whois.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 30s;
    }
}
```

Then tell Whois2Api to trust the proxy so per-client rate limits are accurate:

```
W2A_TRUSTED_PROXIES=127.0.0.1/32
```

**Never** set `W2A_TRUSTED_PROXIES` to a wide range that includes untrusted
clients: `X-Forwarded-For` is client-controlled, and trusting it broadly lets
anyone dodge the rate limiter.

## Caddy

```
whois.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

Caddy sets `X-Forwarded-For` automatically; add
`W2A_TRUSTED_PROXIES=127.0.0.1/32` (or the Docker bridge subnet).

## Health and readiness

`GET /api/v1/health` is deliberately unauthenticated and does not touch the
network, so it is safe to poll frequently.

```bash
whois2api healthcheck; echo $?   # 0 healthy, 1 otherwise
```

The Docker image sets this as its `HEALTHCHECK`.

## Tuning

### Rate limits

Default 300 req/min with bursts of 60. For a busy install, raise it to match
what your upstream behaviour tolerates, but keep in mind the service already
collapses duplicates and caches aggressively:

```
W2A_RATE_LIMIT=600
W2A_RATE_BURST=120
```

Set `W2A_RATE_LIMIT=0` only on a trusted private network.

### Cache lifetimes

| Answer | Default | Raise when | Lower when |
|---|---|---|---|
| `registered` | 30m | domains are mostly stable | you need recent registrar changes |
| `available` | 5m | mostly stability | checking whether a name was just taken |

Raise `W2A_STALE_TTL` if you would rather serve a slightly old answer than make
anyone wait.

### Fresh TLD data

The binary embeds an IANA-generated table for 1372 TLDs. To refresh at boot:

```bash
W2A_REFRESH_TABLE=true
```

A failed refresh is non-fatal: the embedded table is used and a warning is
logged. New TLDs appear here without upgrading the binary.

## Monitoring

`GET /api/v1/status` returns counters suitable for scraping:

```json
{
  "version": "v1.0.0",
  "uptime_seconds": 86400,
  "tld_table": {"total": 1372, "whois": 876, "rdap": 1203, "source": "embedded"},
  "cache": {"hits": 1200, "misses": 40, "stale_hits": 12, "entries": 830},
  "rate_limit_per_minute": 300,
  "auth_mode": "token"
}
```

Useful signals:

- **`cache.hits` / (`hits` + `misses`)** — cache hit ratio; should climb above
  95% under steady traffic
- **`cache.entries`** — should stabilise, not grow without bound
- **`stale_hits`** — rising means upstreams are slow relative to your TTL

Logs are JSON on stdout; ship them with whatever agent you already run. Each
request logs method, path, status and duration at `debug`.

## Upgrades

```bash
docker pull whois2api:latest
docker compose up -d      # recreates the container, keeps the volume
```

The cache format is versioned; unknown entries are treated as misses and
rebuilt, so a downgrade is also safe.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Many `unknown` results | Egress blocked on port 43, or you are heavily throttled | Check `meta.channels[].error`; try `W2A_RDAP_ONLY=true` |
| `unsupported_tld` | TLD not in the table | `W2A_REFRESH_TABLE=true`, or report it |
| 429 for legitimate clients | Limiter sees the proxy IP | Set `W2A_TRUSTED_PROXIES` |
| `permission denied` on start | Data dir not writable by the service user | `chown whois2api /var/lib/whois2api` |
| Slow first requests | Expected: cold cache | Subsequent requests are <1 ms |
