package seeder

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const githubAPI = "https://api.github.com"

// GitHubSeeder plants ghost credentials into a private repository that is then
// flipped to public, simulating an accidental leak. It requires a personal
// access token with the "repo" scope via GITHUB_TOKEN.
type GitHubSeeder struct {
	// Token is the GitHub personal access token used to authenticate.
	Token string
	// Client is the HTTP client used for API calls.
	Client *http.Client
}

// NewGitHubSeeder returns a GitHubSeeder authenticating with the given token.
func NewGitHubSeeder(token string) *GitHubSeeder {
	return &GitHubSeeder{Token: token, Client: http.DefaultClient}
}

// Name implements Seeder.
func (s *GitHubSeeder) Name() Platform { return PlatformGitHub }

// Seed creates a private repo, commits the bait config with ghost keys, flips
// the repo public, and reports where the keys now live.
func (s *GitHubSeeder) Seed(ctx context.Context, req SeedRequest) (SeedPayload, error) {
	if s.Token == "" {
		return SeedPayload{}, fmt.Errorf("github: GITHUB_TOKEN not set — set it to create the bait repository")
	}

	owner, err := s.authenticatedUser(ctx)
	if err != nil {
		return SeedPayload{}, err
	}

	repoName := fmt.Sprintf("accidental-backup-%s", randomHex(6))
	if err := s.createRepo(ctx, repoName); err != nil {
		return SeedPayload{}, err
	}

	baitContent := BuildConfigBait(req, "prod backup config — DO NOT DELETE")
	if err := s.commitFile(ctx, owner, repoName, "config.json", baitContent); err != nil {
		return SeedPayload{}, err
	}

	if err := s.makePublic(ctx, owner, repoName); err != nil {
		return SeedPayload{}, err
	}

	return SeedPayload{
		GhostUsername:   req.GhostUsername,
		AccessKeyID:     req.AccessKeyID,
		SecretAccessKey: req.SecretAccessKey,
		BaitFileName:    "config.json",
		BaitContent:     baitContent,
		Location:        fmt.Sprintf("https://github.com/%s/%s", owner, repoName),
		SeededAt:        time.Now().UTC(),
	}, nil
}

// authenticatedUser resolves the current token's owner via GET /user.
func (s *GitHubSeeder) authenticatedUser(ctx context.Context) (string, error) {
	var out struct {
		Login string `json:"login"`
	}
	if err := s.doJSON(ctx, http.MethodGet, githubAPI+"/user", nil, &out); err != nil {
		return "", fmt.Errorf("github: resolve authenticated user: %w", err)
	}
	if out.Login == "" {
		return "", fmt.Errorf("github: empty login for token")
	}
	return out.Login, nil
}

// createRepo creates a private repo that will later be flipped public.
func (s *GitHubSeeder) createRepo(ctx context.Context, name string) error {
	body, _ := json.Marshal(map[string]any{
		"name":        name,
		"private":     true,
		"description": "Backup of production application config",
	})
	var out struct {
		HTMLURL string `json:"html_url"`
	}
	if err := s.doJSON(ctx, http.MethodPost, githubAPI+"/user/repos", body, &out); err != nil {
		return fmt.Errorf("github: create repo %s: %w", name, err)
	}
	return nil
}

// commitFile commits a single file to the default branch of the repo.
func (s *GitHubSeeder) commitFile(ctx context.Context, owner, repo, path, content string) error {
	body, _ := json.Marshal(map[string]any{
		"message": "add production backup config",
		"content": base64.StdEncoding.EncodeToString([]byte(content)),
	})
	var out struct {
		Content struct {
			HTMLURL string `json:"html_url"`
		} `json:"content"`
	}
	if err := s.doJSON(ctx, http.MethodPut,
		fmt.Sprintf("%s/repos/%s/%s/contents/%s", githubAPI, owner, repo, path),
		body, &out); err != nil {
		return fmt.Errorf("github: commit %s: %w", path, err)
	}
	return nil
}

// makePublic flips the repo visibility to public, completing the "leak".
func (s *GitHubSeeder) makePublic(ctx context.Context, owner, repo string) error {
	body, _ := json.Marshal(map[string]any{"private": false})
	if err := s.doJSON(ctx, http.MethodPatch,
		fmt.Sprintf("%s/repos/%s/%s", githubAPI, owner, repo), body, nil); err != nil {
		return fmt.Errorf("github: make repo public: %w", err)
	}
	return nil
}

// doJSON performs an authenticated GitHub API call, decoding any JSON response.
func (s *GitHubSeeder) doJSON(ctx context.Context, method, url string, body []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.Token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("github: %s %s returned %d: %s", method, url, resp.StatusCode, truncate(string(data), 300))
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return err
		}
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// randomHex returns a hexadecimal string of n characters backed by crypto/rand.
func randomHex(n int) string {
	b := make([]byte, (n+1)/2)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("seeder: failed to read random bytes: %v", err))
	}
	return hex.EncodeToString(b)[:n]
}
