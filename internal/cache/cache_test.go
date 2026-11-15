package cache

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/techjiang/Whois2Api/internal/model"
)

func openTestCache(t *testing.T, opts Options) *Cache {
	t.Helper()
	if opts.Dir == "" {
		opts.Dir = t.TempDir()
	}
	if opts.TTL == 0 {
		opts.TTL = time.Minute
	}
	if opts.NegativeTTL == 0 {
		opts.NegativeTTL = 30 * time.Second
	}
	c, err := Open(opts)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func sampleDomain(status model.Verdict) *model.Domain {
	return &model.Domain{Name: "example.com", TLD: "com", Verdict: status, Source: model.SourceRDAP}
}

func TestPutGetRoundTrip(t *testing.T) {
	c := openTestCache(t, Options{})
	dom := sampleDomain(model.VerdictRegistered)
	if err := c.Put("k", dom, model.SourceRDAP); err != nil {
		t.Fatalf("put: %v", err)
	}
	entry, err := c.Get("k")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if entry.Domain.Name != "example.com" || entry.Domain.Verdict != model.VerdictRegistered {
		t.Fatalf("round trip mismatch: %+v", entry.Domain)
	}
	if !entry.Fresh(time.Now()) {
		t.Fatal("entry should be fresh right after insert")
	}
}

func TestGetMissingReturnsErrMiss(t *testing.T) {
	c := openTestCache(t, Options{})
	if _, err := c.Get("absent"); !errors.Is(err, ErrMiss) {
		t.Fatalf("error = %v, want ErrMiss", err)
	}
}

func TestNegativeEntriesExpireFaster(t *testing.T) {
	c := openTestCache(t, Options{TTL: time.Hour, NegativeTTL: time.Minute})
	if err := c.Put("pos", sampleDomain(model.VerdictRegistered), model.SourceRDAP); err != nil {
		t.Fatal(err)
	}
	if err := c.Put("neg", sampleDomain(model.VerdictAvailable), model.SourceRDAP); err != nil {
		t.Fatal(err)
	}
	pos, _ := c.Get("pos")
	neg, _ := c.Get("neg")
	if !neg.ExpiresAt.Before(pos.ExpiresAt) {
		t.Fatalf("negative TTL (%v) should be shorter than positive (%v)", neg.ExpiresAt, pos.ExpiresAt)
	}
	if !neg.Negative {
		t.Fatal("negative entry not flagged")
	}
}

func TestPersistenceAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	c1, err := Open(Options{Dir: dir, TTL: time.Minute, NegativeTTL: time.Minute})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := c1.Put("persisted", sampleDomain(model.VerdictRegistered), model.SourceWhoIs); err != nil {
		t.Fatal(err)
	}
	if err := c1.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// This is the "move the install to a new machine" property: copy the data
	// directory and the cache is intact.
	c2, err := Open(Options{Dir: dir, TTL: time.Minute, NegativeTTL: time.Minute})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer c2.Close()
	entry, err := c2.Get("persisted")
	if err != nil {
		t.Fatalf("get after reopen: %v", err)
	}
	if entry.Domain.Name != "example.com" {
		t.Fatalf("value lost across reopen: %+v", entry.Domain)
	}
}

func TestConcurrentAccessIsSafe(t *testing.T) {
	c := openTestCache(t, Options{})
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			key := "k" + string(rune('a'+n%10))
			_ = c.Put(key, sampleDomain(model.VerdictRegistered), model.SourceRDAP)
			_, _ = c.Get(key)
			_, _ = c.Get("never")
			_ = c.Count()
			_ = c.Stats()
		}(i)
	}
	wg.Wait()
	if c.Count() == 0 {
		t.Fatal("expected entries after concurrent writes")
	}
}

func TestCorruptEntryIsTreatedAsMiss(t *testing.T) {
	c := openTestCache(t, Options{})
	// Write a non-JSON blob directly, simulating a torn write or bit rot.
	if err := c.rawPut("broken", []byte("{not json")); err != nil {
		t.Fatalf("raw put: %v", err)
	}
	if _, err := c.Get("broken"); !errors.Is(err, ErrMiss) {
		t.Fatalf("error = %v, want ErrMiss for corrupt entry", err)
	}
}

func TestPurgeEmptiesStore(t *testing.T) {
	c := openTestCache(t, Options{})
	for i := 0; i < 5; i++ {
		_ = c.Put("k"+string(rune('a'+i)), sampleDomain(model.VerdictRegistered), model.SourceRDAP)
	}
	if c.Count() != 5 {
		t.Fatalf("count = %d, want 5", c.Count())
	}
	if err := c.Purge(); err != nil {
		t.Fatalf("purge: %v", err)
	}
	if c.Count() != 0 {
		t.Fatalf("count after purge = %d, want 0", c.Count())
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	c, err := Open(Options{Dir: dir, TTL: time.Minute, NegativeTTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("second close should be a no-op: %v", err)
	}
	// Operations after close must not panic.
	if _, err := c.Get("x"); !errors.Is(err, ErrMiss) {
		t.Fatalf("get after close = %v, want ErrMiss", err)
	}
	if err := c.Put("x", sampleDomain(model.VerdictRegistered), model.SourceRDAP); err == nil {
		t.Fatal("put after close should fail")
	}
}

func TestDataDirPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "data")
	c, err := Open(Options{Dir: dir, TTL: time.Minute, NegativeTTL: time.Minute})
	if err != nil {
		t.Fatalf("open nested dir: %v", err)
	}
	defer c.Close()
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm&0o007 != 0 {
		t.Fatalf("data directory is world-accessible: %o", perm)
	}
	fileInfo, err := os.Stat(c.Path())
	if err != nil {
		t.Fatalf("stat db: %v", err)
	}
	if perm := fileInfo.Mode().Perm(); perm&0o077 != 0 {
		t.Fatalf("database file permissions too open: %o", perm)
	}
}

func TestMetricsCountHitsAndMisses(t *testing.T) {
	c := openTestCache(t, Options{})
	if err := c.Put("k", sampleDomain(model.VerdictRegistered), model.SourceRDAP); err != nil {
		t.Fatalf("put: %v", err)
	}
	if _, err := c.Get("k"); err != nil {
		t.Fatalf("get: %v", err)
	}
	if _, err := c.Get("absent"); !errors.Is(err, ErrMiss) {
		t.Fatalf("error = %v, want ErrMiss", err)
	}
	m := c.Stats()
	if m.Hits != 1 {
		t.Errorf("hits = %d, want 1", m.Hits)
	}
	if m.Misses != 1 {
		t.Errorf("misses = %d, want 1", m.Misses)
	}
	if m.Writes != 1 {
		t.Errorf("writes = %d, want 1", m.Writes)
	}
}

func TestCorruptEntryCountsAsMiss(t *testing.T) {
	c := openTestCache(t, Options{})
	if err := c.rawPut("k", []byte("{not json")); err != nil {
		t.Fatalf("rawPut: %v", err)
	}
	if _, err := c.Get("k"); !errors.Is(err, ErrMiss) {
		t.Fatalf("error = %v, want ErrMiss", err)
	}
	if m := c.Stats(); m.Misses != 1 || m.Hits != 0 {
		t.Errorf("metrics = hits %d / misses %d, want 0/1", m.Hits, m.Misses)
	}
	// A corrupt entry must be evicted, not served forever.
	if _, err := c.Get("k"); !errors.Is(err, ErrMiss) {
		t.Fatalf("after corruption, error = %v, want ErrMiss", err)
	}
}
