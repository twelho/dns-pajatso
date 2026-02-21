package main

import (
	"log/slog"
	"sync"
	"time"
)

const recordTTL = 10 * time.Minute

// Store holds at most one TXT record value with an expiry timestamp.
// It is safe for concurrent use.
type Store struct {
	mu     sync.RWMutex
	value  string
	expiry time.Time
	set    bool
}

// Get returns the current TXT value if one is set and has not expired.
func (s *Store) Get() (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.set {
		slog.Warn("get requested, but no TXT value set")
		return "", false
	}

	if time.Now().After(s.expiry) {
		slog.Warn("get requested, but TXT value expired")
		return "", false
	}

	return s.value, true
}

// Set stores a TXT value with a 10-minute expiry.
func (s *Store) Set(value string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.value = value
	s.expiry = time.Now().Add(recordTTL)
	s.set = true
}

// Delete removes the stored TXT value. It is a no-op if no value is set.
func (s *Store) Delete() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.value = ""
	s.set = false
}
