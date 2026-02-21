package main

import (
	"sync"
)

// Store holds at most one TXT record value.
// It is safe for concurrent use.
type Store struct {
	mu    sync.RWMutex
	value string
	set   bool
}

// Get returns the current TXT value if one is set.
func (s *Store) Get() (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.set {
		return "", false
	}
	return s.value, true
}

// Set stores a TXT value.
func (s *Store) Set(value string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.value = value
	s.set = true
}

// Delete removes the stored TXT value. It is a no-op if no value is set.
func (s *Store) Delete() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.value = ""
	s.set = false
}
