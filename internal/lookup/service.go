package lookup

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/asoe/whois2api/internal/cache"
	"github.com/asoe/whois2api/internal/model"
	"github.com/asoe/whois2api/internal/tld"
)

// Service combines the engine with the embedded cache and owns the caching
// policy. It is the single entry point the HTTP layer uses.
type Service struct {
	engine *Engine
	cache  *cache.Cache
	// group collapses concurrent lookups of the same key so a burst of
	// requests produces exactly one upstream query. This is what keeps a
	// self-hosted install from being rate-limited by registries.
	group singleflightGroup
	// refreshing tracks in-flight background refreshes by key.
	refreshing sync.Map
	// lookupHook overrides engine.Lookup in tests.
	lookupHook func(ctx context.Context, t *Target) (*model.Domain, []model.ChannelTiming, []string, error)
}

// resolve runs the real engine unless a test hook is installed.
func (s *Service) resolve(ctx context.Context, t *Target) (*model.Domain, []model.ChannelTiming, []string, error) {
	if s.lookupHook != nil {
		return s.lookupHook(ctx, t)
	}
	return s.engine.Lookup(ctx, t)
}

// NewService wires an engine to a cache.
func NewService(engine *Engine, c *cache.Cache) *Service {
	return &Service{engine: engine, cache: c}
}

// Engine exposes the underlying engine.
func (s *Service) Engine() *Engine { return s.engine }

// ServiceResult is a domain plus lookup metadata.
type ServiceResult struct {
	Domain *model.Domain `json:"domain"`
	Meta   model.Meta    `json:"meta"`
}

// ErrNoAnswer means no channel produced an answer about the domain.
var ErrNoAnswer = errors.New("no authoritative answer available")

// Lookup resolves a domain, serving from cache when possible.
//
//   - Fresh cache entry: returned immediately, zero upstream traffic.
//   - Expired but inside the stale window: returned immediately with Stale=true
//     while exactly one background refresh runs. Users never wait on a slow
//     registry.
//   - Otherwise: live lookup, collapsing concurrent duplicates.
func (s *Service) Lookup(ctx context.Context, input string) (*ServiceResult, error) {
	target, err := s.engine.Prepare(input)
	if err != nil {
		return nil, err
	}
	key := cacheKey(target)
	now := time.Now().UTC()

	if entry, ok := s.cachedEntry(key); ok {
		if entry.Fresh(now) {
			return &ServiceResult{
				Domain: present(entry.Domain, target),
				Meta: model.Meta{
					Cached:          true,
					CacheAgeSeconds: ageSeconds(entry.StoredAt),
					TableSource:     s.engine.table.Source(),
				},
			}, nil
		}
		if s.withinStale(entry, now) {
			s.triggerRefresh(key, target)
			return &ServiceResult{
				Domain: present(entry.Domain, target),
				Meta: model.Meta{
					Cached:          true,
					Stale:           true,
					CacheAgeSeconds: ageSeconds(entry.StoredAt),
					TableSource:     s.engine.table.Source(),
					Warnings:        []string{"Served from cache while a background refresh runs."},
				},
			}, nil
		}
	}

	// Collapse duplicate concurrent lookups. The returned value is shared by
	// every caller waiting on this key, so it is never mutated in place: each
	// caller gets present()'s deep copy.
	value, err, _ := s.group.Do(key, func() (any, error) {
		if entry, ok := s.cachedEntry(key); ok && entry.Fresh(time.Now().UTC()) {
			return &cache.Envelope{Domain: entry.Domain}, nil
		}
		start := time.Now()
		domain, timings, warnings, lookupErr := s.resolve(ctx, target)
		if lookupErr != nil {
			return nil, lookupErr
		}
		meta := model.Meta{
			TotalMillis: time.Since(start).Milliseconds(),
			Channels:    timings,
			TableSource: s.engine.table.Source(),
			Warnings:    warnings,
		}
		// Only cache real answers. Caching "unknown" would pin a transient
		// upstream failure for the whole TTL.
		if domain.Verdict != model.VerdictUnknown {
			_ = s.cache.Put(key, storageView(domain), domain.Source)
		}
		return &cache.Envelope{Domain: domain, Meta: meta}, nil
	})
	if err != nil {
		return nil, err
	}

	switch v := value.(type) {
	case *cache.Envelope:
		return &ServiceResult{Domain: present(v.Domain, target), Meta: v.Meta}, nil
	case *model.Domain:
		return &ServiceResult{Domain: present(v, target), Meta: model.Meta{TableSource: s.engine.table.Source()}}, nil
	default:
		return nil, errors.New("lookup: unexpected result type")
	}
}

// cachedEntry reads the cache, treating any error as a miss.
func (s *Service) cachedEntry(key string) (*cache.Entry, bool) {
	entry, err := s.cache.Get(key)
	if err != nil {
		return nil, false
	}
	return entry, true
}

func (s *Service) withinStale(entry *cache.Entry, now time.Time) bool {
	stale := s.cache.StaleWindow()
	if stale <= 0 {
		return false
	}
	return now.Before(entry.ExpiresAt.Add(stale))
}

// triggerRefresh starts at most one background refresh per key.
func (s *Service) triggerRefresh(key string, target *Target) {
	if _, busy := s.refreshing.LoadOrStore(key, struct{}{}); busy {
		return
	}
	go func() {
		defer s.refreshing.Delete(key)
		// Detached context: the user's request was already answered.
		ctx, cancel := context.WithTimeout(context.Background(), s.engine.opts.TotalTimeout)
		defer cancel()
		domain, _, _, err := s.resolve(ctx, target)
		if err != nil || domain.Verdict == model.VerdictUnknown {
			return
		}
		_ = s.cache.Put(key, storageView(domain), domain.Source)
	}()
}

// cacheKey namespaces entries by registrable domain. The route table and
// protocol behaviour belong to the deployment, not the key.
func cacheKey(t *Target) string { return "v1:" + t.Query }

// Stats exposes route-table and cache counters for the status endpoint.
func (s *Service) Stats() (tld.Stats, cache.Metrics) {
	return s.engine.table.Stats(), s.cache.Stats()
}

// Table returns the active route table.
func (s *Service) Table() *tld.Table { return s.engine.table }

// SetTestHook installs a deterministic resolver for tests. It is exported only
// so the API tests can exercise the HTTP layer without touching the network.
func SetTestHook(s *Service, hook func(ctx context.Context, t *Target) (*model.Domain, []model.ChannelTiming, []string, error)) {
	s.lookupHook = hook
}
