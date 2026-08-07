package dashboard

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLoadTemplates(t *testing.T) {
	if _, err := loadTemplates(); err != nil {
		t.Fatalf("loadTemplates: %v", err)
	}
}

// TestPagesRender boots a dashboard with sample data and renders every page to
// catch template errors (bad funcs, missing fields) at test time.
func TestPagesRender(t *testing.T) {
	srv, err := NewDashboardServer(":memory:", "", 0)
	if err != nil {
		t.Fatalf("NewDashboardServer: %v", err)
	}

	// Seed sample data.
	ghost := Ghost{Username: "ghost-test-db-read-a1b2c3", PolicyName: "ProdDatabaseReadAccess", Platform: "local", AccessKeyID: "AKIAEXAMPLE", Status: "active"}
	if err := srv.db.UpsertGhost(ghost); err != nil {
		t.Fatalf("seed ghost: %v", err)
	}
	if _, err := srv.db.InsertAlert(Alert{
		GhostUsername: ghost.Username, Platform: "local", SourceIP: "198.51.100.7",
		Action: "s3:ListBuckets", Severity: "critical", RiskScore: 9,
	}); err != nil {
		t.Fatalf("seed alert: %v", err)
	}
	if _, err := srv.db.InsertJourney(Journey{
		GhostUsername:  ghost.Username,
		StepsJSON:      `[{"index":1,"service":"sts","action":"GetCallerIdentity","source_ip":"198.51.100.7","severity":"critical","technique":"T1087.004 — Account Discovery","timestamp":"2026-01-01T00:00:00Z"}]`,
		MermaidDiagram: "flowchart LR\n A[sts:GetCallerIdentity] --> B[alert]",
		MitreTactics:   `["T1087.004 — Account Discovery"]`,
		RiskScore:      8,
		SourceHash:     "abc123",
	}); err != nil {
		t.Fatalf("seed journey: %v", err)
	}
	if _, err := srv.db.InsertSeed(Seed{
		GhostUsername: ghost.Username, Platform: "github",
		LocationURL: "https://github.com/org/repo", BaitFilename: "keys.txt", Status: "active",
	}); err != nil {
		t.Fatalf("seed seed: %v", err)
	}
	if err := srv.db.UpsertMeshIdentity(MeshIdentity{
		MeshGroup: "ghost-demo-1", Username: "ghost-demo-1",
		Platform: "aws", ExternalID: "arn:aws:iam::123:user/ghost-demo-1", Status: "active",
	}); err != nil {
		t.Fatalf("seed mesh: %v", err)
	}

	pages := []string{"/", "/ghosts", "/alerts", "/journeys", "/journeys/1", "/mesh", "/seeds"}
	for _, p := range pages {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		rec := httptest.NewRecorder()
		srv.router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", p, rec.Code)
			continue
		}
		body := rec.Body.String()
		if strings.Contains(body, "render failed") {
			t.Errorf("GET %s rendered with error", p)
		}
		if !strings.Contains(body, "<html") {
			t.Errorf("GET %s did not return a full page", p)
		}
	}

	// Partial fragments must render standalone.
	for _, frag := range []struct {
		path, want string
	}{
		{"/partials/stats", "stats-row"},
		{"/partials/alerts", "alert-list"},
	} {
		req := httptest.NewRequest(http.MethodGet, frag.path, nil)
		rec := httptest.NewRecorder()
		srv.router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", frag.path, rec.Code)
			continue
		}
		if !strings.Contains(rec.Body.String(), frag.want) {
			t.Errorf("GET %s did not render %q fragment", frag.path, frag.want)
		}
	}
}

// TestTemplateFuncs covers the helper functions used across templates.
func TestTemplateFuncs(t *testing.T) {
	if got := sevBadgeClass("critical"); !strings.Contains(got, "rose") {
		t.Errorf("sevBadgeClass(critical) = %q", got)
	}
	if got := templateFuncs["statusBadgeClass"].(func(string) string)("triggered"); !strings.Contains(got, "rose") {
		t.Errorf("statusBadgeClass(triggered) = %q", got)
	}
	if got := riskLabel(9); got != "CRITICAL" {
		t.Errorf("riskLabel(9) = %q", got)
	}
	if got := riskPct(10); got != 100 {
		t.Errorf("riskPct(10) = %d", got)
	}
	if got := templateFuncs["platformColor"].(func(string) string)("github"); !strings.Contains(got, "purple") {
		t.Errorf("platformColor(github) = %q", got)
	}

	// titleUpper helper must exist (used by severityBadge).
	f := templateFuncs["titleUpper"].(func(string) string)
	if got := f("critical"); got != "CRITICAL" {
		t.Errorf("titleUpper(critical) = %q", got)
	}
}
