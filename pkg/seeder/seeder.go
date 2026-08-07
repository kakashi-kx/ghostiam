// Package seeder automatically "leaks" ghost access keys to realistic bait
// locations: a public GitHub repo, a public S3 bucket, or a Pastebin-style
// paste. Any attacker who finds the keys and tries to use them triggers the
// GhostIam detection pipeline.
package seeder

import (
	"context"
	"fmt"
	"time"
)

// Platform identifies a bait location type.
type Platform string

const (
	// PlatformGitHub leaks keys into a public GitHub repository.
	PlatformGitHub Platform = "github"
	// PlatformS3 leaks keys into a public S3 bucket.
	PlatformS3 Platform = "s3"
	// PlatformPastebin leaks keys into a Pastebin-style paste.
	PlatformPastebin Platform = "pastebin"
)

// SeedRequest carries the ghost identity whose credentials will be planted as
// bait.
type SeedRequest struct {
	// GhostUsername is the decoy identity the keys belong to.
	GhostUsername string
	// AccessKeyID is the ghost user's access key ID.
	AccessKeyID string
	// SecretAccessKey is the ghost user's secret access key.
	SecretAccessKey string
}

// SeedPayload describes a completed seed operation: what was planted, where,
// and when.
type SeedPayload struct {
	// GhostUsername is the decoy identity whose keys were seeded.
	GhostUsername string
	// AccessKeyID is the planted access key ID.
	AccessKeyID string
	// SecretAccessKey is the planted secret access key.
	SecretAccessKey string
	// BaitFileName is the name of the file containing the keys, e.g. config.json.
	BaitFileName string
	// BaitContent is the full bait file content.
	BaitContent string
	// Location is the URL or path where the bait was seeded.
	Location string
	// SeededAt is when the seed completed.
	SeededAt time.Time
}

// Seeder plants ghost credentials into a bait location.
type Seeder interface {
	// Name returns the platform this seeder targets.
	Name() Platform
	// Seed plants the ghost keys and returns the resulting payload.
	Seed(ctx context.Context, req SeedRequest) (SeedPayload, error)
}

// BuildConfigBait renders the canonical config.json bait file embedding the
// ghost credentials. The comment adds platform-specific realism.
func BuildConfigBait(req SeedRequest, comment string) string {
	return fmt.Sprintf(`{
  "aws_access_key_id": %q,
  "aws_secret_access_key": %q,
  "region": "us-east-1",
  "comment": %q
}
`, req.AccessKeyID, req.SecretAccessKey, comment)
}
