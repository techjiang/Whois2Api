package api

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// limiter is a sharded token-bucket rate limiter.
//
// Why not a library: the whole requirement is "a few hundred keys, refill by
// time, lock-free reads". A sharded map with per-bucket mutexes keeps the hot
// path short and bounded, and avoids pulling a dependency for 60 lines.
type limiter struct {
	rate   float64 // tokens per second
	burst  float64 // bucket depth
	shards []*shard
}

type shard struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens   float64
	lastSeen time.Time
}

const limiterShards = 16

func newLimiter(perMinute, burst int) *limiter {
	if perMinute <= 0 {
		return nil
	}
	if burst <= 0 {
		burst = perMinute
	}
	l := &limiter{
		rate:   float64(perMinute) / 60.0,
		burst:  float64(burst),
		shards: make([]*shard, limiterShards),
	}
	for i := range l.shards {
		l.shards[i] = &shard{buckets: make(map[string]*bucket, 64)}
	}
	return l
}

// allow consumes one token for key, reporting whether it was available and how
// long the caller should wait if not.
func (l *limiter) allow(key string, now time.Time) (bool, time.Duration) {
	if l == nil {
		return true, 0
	}
	sh := l.shards[shardIndex(key)]
	sh.mu.Lock()
	defer sh.mu.Unlock()
	b, ok := sh.buckets[key]
	if !ok {
		b = &bucket{tokens: l.burst, lastSeen: now}
		sh.buckets[key] = b
		if len(sh.buckets) > 8192 {
			// Bound memory: drop stale buckets wholesale rather than grow.
			for k, v := range sh.buckets {
				if now.Sub(v.lastSeen) > 10*time.Minute {
					delete(sh.buckets, k)
				}
			}
		}
	}
	elapsed := now.Sub(b.lastSeen).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * l.rate
		if b.tokens > l.burst {
			b.tokens = l.burst
		}
		b.lastSeen = now
	}
	allowed := b.tokens >= 1
	var wait time.Duration
	if allowed {
		b.tokens--
	} else {
		need := 1 - b.tokens
		wait = time.Duration(need / l.rate * float64(time.Second))
	}
	return allowed, wait
}

func shardIndex(key string) int {
	// FNV-1a over the key: cheap and well distributed for IPs.
	var h uint32 = 2166136261
	for i := 0; i < len(key); i++ {
		h ^= uint32(key[i])
		h *= 16777619
	}
	return int(h % limiterShards)
}

// clientIP determines the caller's address, honouring X-Forwarded-For only
// from configured trusted proxies. Trusting the header unconditionally would
// let anyone bypass rate limits by forging it.
func clientIP(r *http.Request, trusted func(net.IP) bool) string {
	remote := r.RemoteAddr
	if host, _, err := net.SplitHostPort(remote); err == nil {
		remote = host
	}
	ip := net.ParseIP(remote)
	if ip == nil {
		return remote
	}
	if trusted != nil && trusted(ip) {
		if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
			// Left-most entry is the original client.
			for _, part := range splitComma(fwd) {
				if candidate := net.ParseIP(part); candidate != nil {
					return candidate.String()
				}
			}
		}
		if real := r.Header.Get("X-Real-IP"); real != "" {
			if candidate := net.ParseIP(real); candidate != nil {
				return candidate.String()
			}
		}
	}
	return ip.String()
}

func splitComma(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			part := trimSpace(s[start:i])
			if part != "" {
				out = append(out, part)
			}
			start = i + 1
		}
	}
	return out
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}
