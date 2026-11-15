// Package cache provides the embedded, zero-configuration lookup cache.
//
// Design constraints that shaped this:
//   - No external services. A single-file bbolt database inside the data
//     directory means "install" is copying one binary and "backup" is copying
//     one file.
//   - Correct under concurrency. Duplicate upstream queries for the same domain
//     are collapsed with singleflight so a cache stampede cannot get the
//     installation rate-limited by registries.
//   - Stale-while-revalidate. An expired entry is served immediately while one
//     background refresh runs, so users never wait on a slow registry.
package cache

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/sync/singleflight"

	"github.com/asoe/whois2api/internal/model"
)

// ErrMiss means no entry exists for the key.
var ErrMiss = errors.New("cache: miss")

var (
	bucketResults = []byte("results")
	bucketMeta    = []byte("meta")
)

// Entry is one cached lookup result.
type Entry struct {
	Domain    *model.Domain `json:"domain"`
	StoredAt  time.Time     `json:"stored_at"`
	ExpiresAt time.Time     `json:"expires_at"`
	// Negative marks "available/not found" answers, which expire faster.
	Negative bool `json:"negative,omitempty"`
	// Channel records which protocol produced the answer.
	Channel model.Source `json:"channel,omitempty"`
}

// Age reports how long ago the entry was stored.
func (e *Entry) Age(now time.Time) time.Duration { return now.Sub(e.StoredAt) }

// Fresh reports whether the entry may be served without revalidation.
func (e *Entry) Fresh(now time.Time) bool { return now.Before(e.ExpiresAt) }

// Cache is a bbolt-backed result store.
type Cache struct {
	db      *bolt.DB
	group   singleflight.Group
	ttl     time.Duration
	negTTL  time.Duration
	stale   time.Duration
	mu      sync.RWMutex
	closed  bool
	metrics Metrics
}

// Metrics counts cache activity for the status endpoint.
type Metrics struct {
	Hits      uint64 `json:"hits"`
	Misses    uint64 `json:"misses"`
	StaleHits uint64 `json:"stale_hits"`
	Writes    uint64 `json:"writes"`
	Errors    uint64 `json:"errors"`
	Entries   uint64 `json:"entries"`
}

// Options configures a cache instance.
type Options struct {
	// Dir is created if missing; the database lives at Dir/whois2api.db.
	Dir string
	// TTL is the lifetime of a positive (registered) answer.
	TTL time.Duration
	// NegativeTTL is the lifetime of an availability answer.
	NegativeTTL time.Duration
	// StaleWindow is how long past expiry an entry may still be served while
	// a refresh runs in the background.
	StaleWindow time.Duration
}

// DefaultFilename is the database file name inside the data directory.
const DefaultFilename = "whois2api.db"

// Open creates or opens the database, applying sane file permissions.
func Open(opts Options) (*Cache, error) {
	if opts.Dir == "" {
		return nil, errors.New("cache: data directory must not be empty")
	}
	if err := os.MkdirAll(opts.Dir, 0o750); err != nil {
		return nil, fmt.Errorf("cache: create data directory: %w", err)
	}
	path := filepath.Join(opts.Dir, DefaultFilename)
	db, err := bolt.Open(path, 0o600, &bolt.Options{
		Timeout: 5 * time.Second,
		// FreelistType map keeps writes fast on long-lived processes.
		FreelistType: bolt.FreelistMapType,
		NoGrowSync:   false,
	})
	if err != nil {
		return nil, fmt.Errorf("cache: open %s: %w", path, err)
	}
	c := &Cache{
		db:     db,
		ttl:    opts.TTL,
		negTTL: opts.NegativeTTL,
		stale:  opts.StaleWindow,
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(bucketResults); err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists(bucketMeta); err != nil {
			return err
		}
		return nil
	}); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("cache: initialize buckets: %w", err)
	}
	return c, nil
}

// StaleWindow reports how long expired entries may still be served.
func (c *Cache) StaleWindow() time.Duration { return c.stale }

// Envelope carries a fresh lookup result plus its metadata out of singleflight
// without exposing the cache's disk format to callers.
type Envelope struct {
	Domain *model.Domain
	Meta   model.Meta
}

// Path returns the database file path.
func (c *Cache) Path() string { return c.db.Path() }

// Peek reads an entry without touching the hit/miss counters. It exists for
// the singleflight re-check: that read is a de-duplication guard, not a cache
// hit for the caller, and counting it would double every miss.
func (c *Cache) Peek(key string) (*Entry, error) { return c.get(key, false) }

// Get returns the stored entry for key, or ErrMiss, counting the read.
func (c *Cache) Get(key string) (*Entry, error) { return c.get(key, true) }

func (c *Cache) get(key string, count bool) (*Entry, error) {
	c.mu.RLock()
	closed := c.closed
	c.mu.RUnlock()
	if closed {
		return nil, ErrMiss
	}
	var raw []byte
	err := c.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketResults).Get([]byte(key))
		if v == nil {
			return ErrMiss
		}
		// bbolt memory is only valid inside the transaction.
		raw = append(raw, v...)
		return nil
	})
	if err != nil {
		if count && errors.Is(err, ErrMiss) {
			c.bumpMiss()
		}
		return nil, err
	}
	var entry Entry
	if err := json.Unmarshal(raw, &entry); err != nil {
		// A corrupt entry is treated as a miss, never a hard failure.
		_ = c.Delete(key)
		if count {
			c.bumpMiss()
		}
		return nil, ErrMiss
	}
	// Hit means "the store had the key", not "the answer is fresh": freshness
	// is the caller's decision, and it still avoids an upstream query either
	// way. StaleHits is counted separately by the service layer.
	if count {
		c.bumpHit()
	}
	return &entry, nil
}

// Put stores an entry, choosing the TTL from its negativity.
func (c *Cache) Put(key string, domain *model.Domain, channel model.Source) error {
	now := time.Now().UTC()
	negative := domain.Verdict == model.VerdictAvailable
	ttl := c.ttl
	if negative {
		ttl = c.negTTL
	}
	entry := Entry{
		Domain:    domain,
		StoredAt:  now,
		ExpiresAt: now.Add(ttl),
		Negative:  negative,
		Channel:   channel,
	}
	blob, err := json.Marshal(&entry)
	if err != nil {
		c.bumpError()
		return fmt.Errorf("cache: encode entry: %w", err)
	}
	c.mu.RLock()
	closed := c.closed
	c.mu.RUnlock()
	if closed {
		return ErrMiss
	}
	if err := c.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketResults).Put([]byte(key), blob)
	}); err != nil {
		c.bumpError()
		return fmt.Errorf("cache: store entry: %w", err)
	}
	c.mu.Lock()
	c.metrics.Writes++
	c.mu.Unlock()
	return nil
}

// Delete removes a key.
func (c *Cache) Delete(key string) error {
	c.mu.RLock()
	closed := c.closed
	c.mu.RUnlock()
	if closed {
		return nil
	}
	return c.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketResults).Delete([]byte(key))
	})
}

// Count returns the number of stored entries.
func (c *Cache) Count() int {
	var n int
	c.mu.RLock()
	closed := c.closed
	c.mu.RUnlock()
	if closed {
		return 0
	}
	_ = c.db.View(func(tx *bolt.Tx) error {
		n = tx.Bucket(bucketResults).Stats().KeyN
		return nil
	})
	return n
}

// Purge drops every cached entry (used by the admin endpoint and tests).
func (c *Cache) Purge() error {
	c.mu.RLock()
	closed := c.closed
	c.mu.RUnlock()
	if closed {
		return nil
	}
	return c.db.Update(func(tx *bolt.Tx) error {
		if err := tx.DeleteBucket(bucketResults); err != nil && !errors.Is(err, bolt.ErrBucketNotFound) {
			return err
		}
		_, err := tx.CreateBucket(bucketResults)
		return err
	})
}

// Close flushes and closes the database.
func (c *Cache) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()
	return c.db.Close()
}

// Stats returns a snapshot of counters plus the live entry count.
func (c *Cache) Stats() Metrics {
	c.mu.RLock()
	m := c.metrics
	c.mu.RUnlock()
	m.Entries = uint64(c.Count())
	return m
}

func (c *Cache) bumpHit()   { c.mu.Lock(); c.metrics.Hits++; c.mu.Unlock() }
func (c *Cache) bumpMiss()  { c.mu.Lock(); c.metrics.Misses++; c.mu.Unlock() }
func (c *Cache) bumpStale() { c.mu.Lock(); c.metrics.StaleHits++; c.mu.Unlock() }

// CountStale records that an expired entry was served while a refresh ran.
func (c *Cache) CountStale() { c.bumpStale() }
func (c *Cache) bumpError()  { c.mu.Lock(); c.metrics.Errors++; c.mu.Unlock() }

// rawPut writes bytes without encoding, for tests that need to inject corrupt
// data and verify the store degrades to a miss instead of failing.
func (c *Cache) rawPut(key string, value []byte) error {
	return c.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketResults).Put([]byte(key), value)
	})
}
