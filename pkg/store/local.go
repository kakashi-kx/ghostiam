// Package store provides a local JSON-file-backed persistence layer for ghost
// users. It replaces AWS IAM for local and demo modes where you don't want to
// create real decoy users in the cloud.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// GhostRecord is a single persisted ghost user record.
type GhostRecord struct {
	// Username is the IAM username of the ghost user.
	Username string `json:"username"`
	// PolicyName is the decoy policy attached to the ghost user.
	PolicyName string `json:"policyName"`
	// CreatedAt is the RFC3339 timestamp when the ghost user was deployed.
	CreatedAt time.Time `json:"createdAt"`
	// AccessKeyID is optional; only set when access keys were generated.
	AccessKeyID string `json:"accessKeyId,omitempty"`
	// SecretAccessKey is optional; only set when access keys were generated.
	SecretAccessKey string `json:"secretAccessKey,omitempty"`
}

// LocalStore persists GhostRecords as a flat JSON array on disk.
type LocalStore struct {
	filePath string
	mu       sync.Mutex
}

// NewLocalStore returns a store backed by the given JSON file path.
func NewLocalStore(filePath string) *LocalStore {
	return &LocalStore{filePath: filePath}
}

// AddGhost appends a record to the JSON array in the store file, creating the
// file and its parent directories when they don't exist.
func (s *LocalStore) AddGhost(record GhostRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	records, err := s.readAllLocked()
	if err != nil {
		return err
	}
	if record.CreatedAt.IsZero() {
		record.CreatedAt = time.Now().UTC()
	}

	records = append(records, record)
	return s.writeAllLocked(records)
}

// ListGhosts returns every record currently stored.
func (s *LocalStore) ListGhosts() ([]GhostRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.readAllLocked()
}

// FindGhost returns the record for the given username, or an error if no such
// record exists.
func (s *LocalStore) FindGhost(username string) (*GhostRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	records, err := s.readAllLocked()
	if err != nil {
		return nil, err
	}
	for i := range records {
		if records[i].Username == username {
			rec := records[i]
			return &rec, nil
		}
	}
	return nil, fmt.Errorf("store: ghost user %q not found", username)
}

// DeleteGhost removes the record for the given username from the store file.
// A missing file or unknown username is not an error.
func (s *LocalStore) DeleteGhost(username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	records, err := s.readAllLocked()
	if err != nil {
		return err
	}

	kept := records[:0]
	for _, rec := range records {
		if rec.Username != username {
			kept = append(kept, rec)
		}
	}
	if len(kept) == len(records) {
		return nil // nothing to remove
	}
	return s.writeAllLocked(kept)
}

// readAllLocked reads the JSON array from disk. A missing file yields an empty
// slice; a corrupt file returns an error.
func (s *LocalStore) readAllLocked() ([]GhostRecord, error) {
	data, err := os.ReadFile(s.filePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []GhostRecord{}, nil
		}
		return nil, fmt.Errorf("store: read %s: %w", s.filePath, err)
	}

	records := []GhostRecord{}
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, fmt.Errorf("store: parse %s: %w", s.filePath, err)
	}
	return records, nil
}

// writeAllLocked atomically writes the JSON array to disk.
func (s *LocalStore) writeAllLocked(records []GhostRecord) error {
	if dir := filepath.Dir(s.filePath); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("store: mkdir %s: %w", dir, err)
		}
	}

	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return fmt.Errorf("store: marshal records: %w", err)
	}
	data = append(data, '\n')

	tmp := s.filePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("store: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, s.filePath); err != nil {
		return fmt.Errorf("store: rename %s: %w", s.filePath, err)
	}
	return nil
}
