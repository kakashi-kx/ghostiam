// Package mesh deploys correlated ghost identities across AWS IAM, GitHub, and
// Okta so that one "employee" exists on every platform. When any of those
// identities fires, the alert flags the correlated accounts on the other
// platforms too.
package mesh

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/kakashi-kx/ghostiam/pkg/deploy"
	"github.com/kakashi-kx/ghostiam/pkg/store"
	"github.com/kakashi-kx/ghostiam/pkg/templates"
)

// MeshIdentity is one correlated ghost identity: the same persona exists on
// AWS, GitHub, and/or Okta.
type MeshIdentity struct {
	Username      string    `json:"username"`
	AWSSuccess    bool      `json:"awsSuccess"`
	GitHubSuccess bool      `json:"githubSuccess"`
	OktaSuccess   bool      `json:"oktaSuccess"`
	AWSArn        string    `json:"awsArn,omitempty"`
	GitHubHandle  string    `json:"githubHandle,omitempty"`
	GitHubURL     string    `json:"githubUrl,omitempty"`
	OktaID        string    `json:"oktaId,omitempty"`
	OktaEmail     string    `json:"oktaEmail,omitempty"`
	CreatedAt     time.Time `json:"createdAt"`
}

// MeshConfig controls a mesh deploy operation.
type MeshConfig struct {
	// Count is the number of ghost identities to create per platform.
	Count int
	// Prefix is the username prefix, e.g. "demo".
	Prefix string
	// Platforms is the list of platforms to target: aws, github, okta.
	Platforms []string
	// Local forces simulation instead of real API calls. When false, real
	// calls are attempted only if the relevant credentials exist.
	Local bool
	// GitHubToken is used to back GitHub profiles with a real repo.
	GitHubToken string
	// Region is the AWS region for the AWS leg.
	Region string
}

// MeshOrchestrator persists mesh identities and coordinates creation across
// platforms.
type MeshOrchestrator struct {
	identitiesFile string
	oktaFile       string
	mu             sync.Mutex
}

// NewOrchestrator returns an orchestrator persisting to the given files.
func NewOrchestrator(identitiesFile, oktaFile string) *MeshOrchestrator {
	return &MeshOrchestrator{identitiesFile: identitiesFile, oktaFile: oktaFile}
}

// Deploy creates count correlated ghost identities across the requested
// platforms. It never fails because one platform lacks credentials — that
// platform is simply marked unsuccessful while the others complete.
func (o *MeshOrchestrator) Deploy(ctx context.Context, cfg MeshConfig) ([]MeshIdentity, error) {
	if cfg.Count <= 0 {
		cfg.Count = 2
	}
	if cfg.Prefix == "" {
		cfg.Prefix = "demo"
	}
	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}
	if cfg.GitHubToken == "" {
		cfg.GitHubToken = os.Getenv("GITHUB_TOKEN")
	}

	platforms := normalizePlatforms(cfg.Platforms)
	ghostStore := store.NewLocalStore("ghosts.json")
	oktaCreator := NewOktaGhostCreator(o.oktaFile)

	// Real AWS creation is only attempted when the caller explicitly opted out
	// of local mode AND live credentials are resolvable. Otherwise the AWS leg
	// is correlated to a local ghost record with generated keys.
	awsReal := !cfg.Local && awsCredsAvailable(ctx, cfg.Region)

	var identities []MeshIdentity
	now := time.Now().UTC()
	for i := 0; i < cfg.Count; i++ {
		username := fmt.Sprintf("ghost-%s-%s-%s", cfg.Prefix, roleFor(i), randomHex(6))
		id := MeshIdentity{Username: username, CreatedAt: now}

		for _, p := range platforms {
			switch p {
			case "aws":
				if awsReal {
					arn, err := createRealGhost(ctx, cfg.Region, username, i)
					id.AWSSuccess = err == nil
					id.AWSArn = arn
				} else {
					id.AWSSuccess = addLocalGhost(ghostStore, username, i) == nil
				}
			case "github":
				gh, err := NewGitHubGhostCreator(cfg.GitHubToken).Create(ctx, username, i)
				id.GitHubSuccess = err == nil
				id.GitHubHandle = gh.Handle
				id.GitHubURL = gh.URL
			case "okta":
				u, err := oktaCreator.Create(username, i)
				id.OktaSuccess = err == nil
				id.OktaID = u.OktaID
				id.OktaEmail = u.Email
			}
		}
		identities = append(identities, id)
	}

	o.mu.Lock()
	defer o.mu.Unlock()

	existing, err := o.readAllLocked()
	if err != nil {
		return nil, err
	}
	existing = append(existing, identities...)
	if err := o.writeAllLocked(existing); err != nil {
		return nil, err
	}
	return identities, nil
}

// List returns every mesh identity ever deployed.
func (o *MeshOrchestrator) List() ([]MeshIdentity, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.readAllLocked()
}

// Find returns a single mesh identity by username.
func (o *MeshOrchestrator) Find(username string) (*MeshIdentity, error) {
	o.mu.Lock()
	defer o.mu.Unlock()

	records, err := o.readAllLocked()
	if err != nil {
		return nil, err
	}
	for i := range records {
		if records[i].Username == username {
			id := records[i]
			return &id, nil
		}
	}
	return nil, fmt.Errorf("mesh: identity %q not found", username)
}

// addLocalGhost correlates the AWS leg to a local ghost record with generated
// access keys, so simulate works against mesh identities without AWS.
func addLocalGhost(s *store.LocalStore, username string, idx int) error {
	policies := templates.GetDecoyPolicies()
	policy := policies[idx%len(policies)]

	akid, secret, err := deploy.GenerateKeys()
	if err != nil {
		return err
	}
	return s.AddGhost(store.GhostRecord{
		Username:        username,
		PolicyName:      policy.Name,
		CreatedAt:       time.Now().UTC(),
		AccessKeyID:     akid,
		SecretAccessKey: secret,
	})
}

// createRealGhost creates a real IAM ghost user with the exact mesh username.
func createRealGhost(ctx context.Context, region, username string, idx int) (string, error) {
	awsCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return "", err
	}
	client := iam.NewFromConfig(awsCfg)

	policies := templates.GetDecoyPolicies()
	policy := policies[idx%len(policies)]
	ghost, err := deploy.CreateGhostUser(ctx, client, username, policy, true)
	if err != nil {
		return "", err
	}
	return ghost.Arn, nil
}

// awsCredsAvailable reports whether real AWS credentials resolve to an
// identity, used to decide between real and simulated mesh AWS legs.
func awsCredsAvailable(ctx context.Context, region string) bool {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	awsCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return false
	}
	_, err = sts.NewFromConfig(awsCfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	return err == nil
}

// normalizePlatforms expands "all" and deduplicates the platform list.
func normalizePlatforms(platforms []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range platforms {
		for _, q := range expandPlatform(p) {
			q = normalizePlatform(q)
			if q == "" || seen[q] {
				continue
			}
			seen[q] = true
			out = append(out, q)
		}
	}
	return out
}

// expandPlatform expands the "all" shortcut into every concrete platform.
func expandPlatform(p string) []string {
	if p == "all" {
		return []string{"aws", "github", "okta"}
	}
	return []string{p}
}

func normalizePlatform(p string) string {
	switch p {
	case "aws", "github", "okta":
		return p
	case "all", "":
		return "all"
	}
	return ""
}

// roleFor cycles through realistic role labels for mesh usernames.
func roleFor(i int) string {
	roles := []string{"admin", "db-read", "s3-backup", "infra-view", "xacct"}
	return roles[i%len(roles)]
}

// profilePool is a roster of fictional personas, one per platform correlate.
var profilePool = []struct {
	Name   string
	Handle string
	Email  string
}{
	{"Alex Johnson", "alex-ghost-dev", "alex.johnson@fake.com"},
	{"Jordan Smith", "jordan-ghost-db", "jordan.smith@fake.com"},
	{"Priya Patel", "priya-ghost-sre", "priya.patel@fake.com"},
	{"Marcus Chen", "marcus-ghost-infra", "marcus.chen@fake.com"},
	{"Sofia Reyes", "sofia-ghost-sec", "sofia.reyes@fake.com"},
}

// groupPool is a roster of realistic Okta group memberships.
var groupPool = [][]string{
	{"prod-admin", "db-operators", "all-employees"},
	{"db-operators", "all-employees"},
	{"data-science", "all-employees"},
	{"sre-oncall", "all-employees"},
	{"security", "all-employees"},
}

// readAllLocked loads mesh identities from disk; a missing file yields empty.
func (o *MeshOrchestrator) readAllLocked() ([]MeshIdentity, error) {
	data, err := os.ReadFile(o.identitiesFile)
	if err != nil {
		if os.IsNotExist(err) {
			return []MeshIdentity{}, nil
		}
		return nil, fmt.Errorf("mesh: read %s: %w", o.identitiesFile, err)
	}
	records := []MeshIdentity{}
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, fmt.Errorf("mesh: parse %s: %w", o.identitiesFile, err)
	}
	return records, nil
}

// writeAllLocked atomically persists mesh identities.
func (o *MeshOrchestrator) writeAllLocked(records []MeshIdentity) error {
	if dir := filepath.Dir(o.identitiesFile); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	tmp := o.identitiesFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, o.identitiesFile)
}

// randomHex returns a hexadecimal string of n characters backed by crypto/rand.
func randomHex(n int) string {
	b := make([]byte, (n+1)/2)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("mesh: failed to read random bytes: %v", err))
	}
	return hex.EncodeToString(b)[:n]
}
