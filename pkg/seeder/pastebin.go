package seeder

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// PastebinSeeder writes a Pastebin-style paste locally. The pastebin-sim.html
// file mimics the look of a real Pastebin leak page, so a demo can show what
// an attacker would find without hitting the Pastebin API.
type PastebinSeeder struct {
	// OutputDir is where pastebin-sim.html will be written.
	OutputDir string
}

// NewPastebinSeeder returns a PastebinSeeder writing into outputDir (default ".").
func NewPastebinSeeder(outputDir string) *PastebinSeeder {
	if outputDir == "" {
		outputDir = "."
	}
	return &PastebinSeeder{OutputDir: outputDir}
}

// Name implements Seeder.
func (s *PastebinSeeder) Name() Platform { return PlatformPastebin }

// Seed renders a Pastebin-style page containing the ghost credentials and
// writes it to pastebin-sim.html.
func (s *PastebinSeeder) Seed(ctx context.Context, req SeedRequest) (SeedPayload, error) {
	content := BuildConfigBait(req, "accidentally pasted aws config — do not use")
	page := renderPastebinPage(req, content)

	path := filepath.Join(s.OutputDir, "pastebin-sim.html")
	if err := os.MkdirAll(s.OutputDir, 0o755); err != nil {
		return SeedPayload{}, fmt.Errorf("pastebin: mkdir %s: %w", s.OutputDir, err)
	}
	if err := os.WriteFile(path, []byte(page), 0o644); err != nil {
		return SeedPayload{}, fmt.Errorf("pastebin: write %s: %w", path, err)
	}

	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}

	return SeedPayload{
		GhostUsername:   req.GhostUsername,
		AccessKeyID:     req.AccessKeyID,
		SecretAccessKey: req.SecretAccessKey,
		BaitFileName:    "config.json",
		BaitContent:     content,
		Location:        "file://" + abs,
		SeededAt:        time.Now().UTC(),
	}, nil
}

// renderPastebinPage builds a minimal static HTML page styled like Pastebin.
func renderPastebinPage(req SeedRequest, content string) string {
	body := `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>aws_config_backup — Pastebin</title>
  <style>
    body { font-family: monospace; background: #111; color: #ddd; margin: 2rem; }
    header { border-bottom: 1px solid #333; padding-bottom: 1rem; margin-bottom: 1.5rem; }
    a { color: #4a9eff; text-decoration: none; }
    h1 { color: #fff; font-size: 1.2rem; }
    pre { background: #000; border: 1px solid #333; padding: 1rem; overflow-x: auto; white-space: pre-wrap; }
    .meta { color: #888; font-size: 0.85rem; margin: 0.5rem 0 1.5rem; }
  </style>
</head>
<body>
  <header>
    <h1>Pastebin <span style="color:#888">/ Simulator</span></h1>
  </header>
  <main>
    <h1>aws_config_backup</h1>
    <div class="meta">
      Posted anonymously &middot; "forgot to rotate these keys" &middot;
      views: 1,247 &middot; download raw
    </div>
    <pre>`
	return body + content + "</pre>\n  </main>\n</body>\n</html>\n"
}
