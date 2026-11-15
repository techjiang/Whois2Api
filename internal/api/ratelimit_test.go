package api

import (
	"sync"
	"testing"
	"time"
)

func TestLimiterSeparatesKeysAcrossShards(t *testing.T) {
	l := newLimiter(60, 1) // one token per key
	now := time.Now()

	if ok, _ := l.allow("10.0.0.1", now); !ok {
		t.Fatal("first request should pass")
	}
	if ok, _ := l.allow("10.0.0.1", now); ok {
		t.Fatal("second immediate request from the same client should be limited")
	}
	// A different key on a different shard must be unaffected.
	if ok, _ := l.allow("10.0.0.2", now); !ok {
		t.Fatal("a different client must not be affected by another's bucket")
	}
}

func TestLimiterRefillsOverTime(t *testing.T) {
	l := newLimiter(60, 1) // one token per second
	now := time.Now()
	if ok, _ := l.allow("k", now); !ok {
		t.Fatal("first request should pass")
	}
	if ok, wait := l.allow("k", now); ok || wait <= 0 {
		t.Fatalf("second request ok=%v wait=%v, want limited with a positive wait", ok, wait)
	}
	later := now.Add(1100 * time.Millisecond)
	if ok, _ := l.allow("k", later); !ok {
		t.Fatal("bucket should have refilled after 1.1s")
	}
}

// The limiter is shared by every in-flight request, so mis-sharded state would
// show up as a data race under -race.
func TestLimiterConcurrentAccess(t *testing.T) {
	l := newLimiter(6000, 100)
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := "ip-" + string(rune('a'+i%16))
			for j := 0; j < 50; j++ {
				l.allow(key, time.Now())
			}
		}(i)
	}
	wg.Wait()
}

func TestLimiterDisabledAllowsEverything(t *testing.T) {
	l := newLimiter(0, 0)
	if l != nil {
		t.Fatal("rate limit 0 must disable the limiter")
	}
	var nilLimiter *limiter
	if ok, _ := nilLimiter.allow("k", time.Now()); !ok {
		t.Fatal("nil limiter must allow every request")
	}
}
