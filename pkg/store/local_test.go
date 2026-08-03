package store

import (
	"path/filepath"
	"testing"
	"time"
)

func TestLocalStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s := NewLocalStore(filepath.Join(dir, "ghosts.json"))

	rec := GhostRecord{
		Username:        "ghost-prod-db-read-a7f3c2",
		PolicyName:      "ProdDatabaseReadAccess",
		CreatedAt:       time.Now().UTC(),
		AccessKeyID:     "AKIA...",
		SecretAccessKey: "super-secret",
	}
	if err := s.AddGhost(rec); err != nil {
		t.Fatalf("AddGhost: %v", err)
	}

	got, err := s.FindGhost("ghost-prod-db-read-a7f3c2")
	if err != nil {
		t.Fatalf("FindGhost: %v", err)
	}
	if got.PolicyName != rec.PolicyName || got.AccessKeyID != rec.AccessKeyID {
		t.Fatalf("record mismatch: %+v", got)
	}

	if _, err := s.FindGhost("nope"); err == nil {
		t.Fatal("expected error for unknown ghost")
	}

	list, err := s.ListGhosts()
	if err != nil {
		t.Fatalf("ListGhosts: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 record, got %d", len(list))
	}
}

func TestLocalStoreMissingFile(t *testing.T) {
	s := NewLocalStore(filepath.Join(t.TempDir(), "nope.json"))
	list, err := s.ListGhosts()
	if err != nil {
		t.Fatalf("ListGhosts on missing file: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("expected empty list, got %d", len(list))
	}
}
