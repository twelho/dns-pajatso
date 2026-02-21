package main

import (
	"testing"
)

func TestStoreEmpty(t *testing.T) {
	var s Store
	val, ok := s.Get()
	if ok {
		t.Fatalf("expected empty store, got %q", val)
	}
}

func TestStoreSetGet(t *testing.T) {
	var s Store
	s.Set("test-token")

	val, ok := s.Get()
	if !ok || val != "test-token" {
		t.Fatalf("expected (test-token, true), got (%q, %v)", val, ok)
	}
}

func TestStoreOverwrite(t *testing.T) {
	var s Store
	s.Set("first")
	s.Set("second")

	val, ok := s.Get()
	if !ok || val != "second" {
		t.Fatalf("expected (second, true), got (%q, %v)", val, ok)
	}
}

func TestStoreDelete(t *testing.T) {
	var s Store
	s.Set("to-delete")
	s.Delete()

	val, ok := s.Get()
	if ok {
		t.Fatalf("expected deleted, got %q", val)
	}
}

func TestStoreDeleteNoop(t *testing.T) {
	var s Store
	s.Delete() // should not panic
}

