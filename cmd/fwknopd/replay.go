package main

import (
	"sync"
	"time"
)

// replayCache tracks SPA packet digests in memory to prevent replay attacks.
// Entries automatically expire after the configured TTL.
type replayCache struct {
	mu      sync.Mutex
	entries map[string]time.Time // digest → expiration time
	ttl     time.Duration
}

// newReplayCache creates an in-memory replay cache with the given TTL.
// A background goroutine periodically purges expired entries.
func newReplayCache(ttl time.Duration) *replayCache {
	rc := &replayCache{
		entries: make(map[string]time.Time),
		ttl:     ttl,
	}

	// Purge expired entries every ttl/2 (minimum 10s).
	purgeInterval := ttl / 2
	if purgeInterval < 10*time.Second {
		purgeInterval = 10 * time.Second
	}
	go rc.purgeLoop(purgeInterval)

	return rc
}

// isDuplicate checks if a digest has been seen and is not yet expired.
func (rc *replayCache) isDuplicate(digest string) bool {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	exp, found := rc.entries[digest]
	if !found {
		return false
	}
	if time.Now().After(exp) {
		// Expired — remove and allow.
		delete(rc.entries, digest)
		return false
	}
	return true
}

// add records a digest with an expiration of now + TTL.
func (rc *replayCache) add(digest string) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.entries[digest] = time.Now().Add(rc.ttl)
}

// purgeLoop periodically removes expired entries.
func (rc *replayCache) purgeLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		rc.mu.Lock()
		now := time.Now()
		for digest, exp := range rc.entries {
			if now.After(exp) {
				delete(rc.entries, digest)
			}
		}
		rc.mu.Unlock()
	}
}
