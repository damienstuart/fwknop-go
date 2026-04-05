package main

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestReplayCacheBasic(t *testing.T) {
	rc := newReplayCache(1 * time.Minute)

	if rc.isDuplicate("digest1") {
		t.Error("new digest should not be a duplicate")
	}

	rc.add("digest1")

	if !rc.isDuplicate("digest1") {
		t.Error("added digest should be a duplicate")
	}

	if rc.isDuplicate("digest2") {
		t.Error("different digest should not be a duplicate")
	}
}

func TestReplayCacheExpiration(t *testing.T) {
	rc := newReplayCache(100 * time.Millisecond)

	rc.add("expires_soon")

	if !rc.isDuplicate("expires_soon") {
		t.Error("should be duplicate immediately after add")
	}

	// Wait for TTL to expire.
	time.Sleep(150 * time.Millisecond)

	if rc.isDuplicate("expires_soon") {
		t.Error("should no longer be duplicate after TTL expires")
	}
}

func TestReplayCacheMultipleEntries(t *testing.T) {
	rc := newReplayCache(1 * time.Minute)

	for i := 0; i < 100; i++ {
		digest := fmt.Sprintf("digest_%d", i)
		rc.add(digest)
	}

	for i := 0; i < 100; i++ {
		digest := fmt.Sprintf("digest_%d", i)
		if !rc.isDuplicate(digest) {
			t.Errorf("digest_%d should be a duplicate", i)
		}
	}

	if rc.isDuplicate("never_added") {
		t.Error("unadded digest should not be a duplicate")
	}
}

func TestReplayCacheConcurrency(t *testing.T) {
	rc := newReplayCache(1 * time.Minute)
	var wg sync.WaitGroup

	// Concurrent writers.
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			rc.add(fmt.Sprintf("concurrent_%d", n))
		}(i)
	}

	// Concurrent readers.
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			rc.isDuplicate(fmt.Sprintf("concurrent_%d", n))
		}(i)
	}

	wg.Wait()

	// Verify all entries were added.
	for i := 0; i < 50; i++ {
		if !rc.isDuplicate(fmt.Sprintf("concurrent_%d", i)) {
			t.Errorf("concurrent_%d should be a duplicate after concurrent add", i)
		}
	}
}

func TestReplayCacheReaddAfterExpiry(t *testing.T) {
	rc := newReplayCache(100 * time.Millisecond)

	rc.add("reusable")
	time.Sleep(150 * time.Millisecond)

	// Should be expired now.
	if rc.isDuplicate("reusable") {
		t.Error("should be expired")
	}

	// Re-add should work.
	rc.add("reusable")
	if !rc.isDuplicate("reusable") {
		t.Error("should be duplicate after re-add")
	}
}
