package mesh

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

const githubAPI = "https://api.github.com"

// GitHubGhost describes a created GitHub persona.
type GitHubGhost struct {
	// Handle is the GitHub username of the persona.
	Handle string
	// URL is the profile or repository URL backing the persona.
	URL string
	// Name is the display name of the persona.
	Name string
}

// GitHubGhostCreator creates GitHub personas that look like former employees or
// contractors. With a token it backs each profile with a real repo; without
// one it produces a simulated profile URL.
type GitHubGhostCreator struct {
	Token string
}

// NewGitHubGhostCreator returns a creator authenticating with the given token.
func NewGitHubGhostCreator(token string) *GitHubGhostCreator {
	return &GitHubGhostCreator{Token: token}
}

// Create produces a GitHub persona correlated to a mesh identity.
func (g *GitHubGhostCreator) Create(ctx context.Context, username string, idx int) (GitHubGhost, error) {
	prof := profilePool[idx%len(profilePool)]
	ghost := GitHubGhost{Handle: prof.Handle, Name: prof.Name}

	if g.Token == "" {
		// Simulated profile: still looks real in the mesh status table.
		ghost.URL = "https://github.com/simulated/" + prof.Handle
		return ghost, nil
	}

	repoName := fmt.Sprintf("infra-contractor-%s", randomHex(6))
	if err := g.createRepo(ctx, repoName, prof.Name); err != nil {
		// Fall back to a simulated profile rather than failing the mesh.
		ghost.URL = "https://github.com/simulated/" + prof.Handle
		return ghost, nil
	}

	owner := prof.Handle
	ghost.URL = fmt.Sprintf("https://github.com/%s/%s", owner, repoName)
	return ghost, nil
}

// createRepo creates a private contractor repo. GitHub does not allow PATs to
// create user accounts, so the repo serves as the persona's footprint.
func (g *GitHubGhostCreator) createRepo(ctx context.Context, name, displayName string) error {
	body, _ := json.Marshal(map[string]any{
		"name":        name,
		"private":     true,
		"description": fmt.Sprintf("Contract infrastructure work — %s", displayName),
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, githubAPI+"/user/repos", bytes.NewReader(body))
	if err != nil {
		return err
	}
	return g.do(req)
}

// do performs an authenticated GitHub API request.
func (g *GitHubGhostCreator) do(req *http.Request) error {
	req.Header.Set("Authorization", "Bearer "+g.Token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("github: %s %s returned %d: %s", req.Method, req.URL, resp.StatusCode, truncate(string(data), 300))
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
