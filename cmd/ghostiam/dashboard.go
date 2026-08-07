package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/kakashi-kx/ghostiam/pkg/dashboard"
	"github.com/kakashi-kx/ghostiam/pkg/journey"
	"github.com/spf13/cobra"
)

// dashboardCmd serves the GhostIam web dashboard.
var dashboardCmd = &cobra.Command{
	Use:   "dashboard",
	Short: "Serve the GhostIam web dashboard",
	Long: `Serve the GhostIam operations dashboard: ghosts, live alerts,
attack journeys, the cross-platform mesh, token seeds, and JSON/PDF reports.

  ghostiam dashboard --port 8080 --api-key demo-key

Point GHOSTIAM_DASHBOARD_URL at this server in other shells and the CLI will
push alerts, seeds, and journeys to it in real time.`,
	RunE: runDashboard,
}

func init() {
	dashboardCmd.Flags().IntP("port", "p", 8080, "HTTP port to listen on")
	dashboardCmd.Flags().String("api-key", "", "Shared API key for dashboard + API routes (env GHOSTIAM_API_KEY)")
	dashboardCmd.Flags().String("db", "ghosts.db", "Path to the SQLite database file")
	rootCmd.AddCommand(dashboardCmd)
}

func runDashboard(cmd *cobra.Command, _ []string) error {
	port, _ := cmd.Flags().GetInt("port")
	apiKey, _ := cmd.Flags().GetString("api-key")
	dbPath, _ := cmd.Flags().GetString("db")

	if apiKey == "" {
		apiKey = os.Getenv("GHOSTIAM_API_KEY")
	}

	srv, err := dashboard.NewDashboardServer(dbPath, apiKey, port)
	if err != nil {
		return fmt.Errorf("dashboard: %w", err)
	}
	defer srv.Stop()

	base := "http://localhost"
	if port != 80 {
		base = fmt.Sprintf("%s:%d", base, port)
	}

	fmt.Printf("👻 GhostIam dashboard listening on %s\n", base)
	fmt.Printf("   Database: %s\n", dbPath)
	if apiKey == "" {
		fmt.Println("   Auth:     disabled (no API key set)")
	} else {
		fmt.Println("   Auth:     X-API-Key: " + apiKey)
	}
	fmt.Println()
	fmt.Println("   To push CLI events here from other shells:")
	fmt.Printf("     export GHOSTIAM_DASHBOARD_URL=%s\n", base)
	if apiKey != "" {
		fmt.Printf("     export GHOSTIAM_DASHBOARD_KEY=%s\n", apiKey)
	}

	return srv.Start()
}

// pushAlertToDashboard posts an alert to the dashboard's internal API, if
// configured. Best-effort: a missing or unreachable dashboard is not an error.
func pushAlertToDashboard(username, policyName string) {
	dashboardURL := os.Getenv("GHOSTIAM_DASHBOARD_URL")
	if dashboardURL == "" {
		return
	}
	dashboardKey := os.Getenv("GHOSTIAM_DASHBOARD_KEY")

	payload := map[string]any{
		"ghost_username": username,
		"platform":       "local",
		"action":         "simulated",
		"source_ip":      "127.0.0.1",
		"severity":       "critical",
		"risk_score":     8,
		"raw_event":      fmt.Sprintf(`{"username":%q,"policy":%q,"source":"local"}`, username, policyName),
	}

	body, _ := json.Marshal(payload)
	req, err := http.NewRequest(http.MethodPost, dashboardURL+"/api/v1/alerts", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if dashboardKey != "" {
		req.Header.Set("X-API-Key", dashboardKey)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return // silently fail — dashboard is optional
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		fmt.Printf("   ⚠️  dashboard alert rejected: %s\n", resp.Status)
	}
}

// postDashboardEvent pushes an event to the dashboard API, if configured. It is
// best-effort: a missing or unreachable dashboard is not an error.
func postDashboardEvent(ev dashboard.EventIngest) {
	base := os.Getenv("GHOSTIAM_DASHBOARD_URL")
	if base == "" {
		return
	}

	body, err := json.Marshal(ev)
	if err != nil {
		return
	}

	url := base + "/api/v1/events"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")

	key := os.Getenv("GHOSTIAM_DASHBOARD_KEY")
	if key == "" {
		key = os.Getenv("GHOSTIAM_API_KEY")
	}
	if key != "" {
		req.Header.Set("X-API-Key", key)
	}

	client := &http.Client{Timeout: 4 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("   ⚠️  dashboard event not pushed: %v\n", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		fmt.Printf("   ⚠️  dashboard event rejected: %s\n", resp.Status)
	}
}

// alertFromJourney builds the dashboard alert payload for a simulated journey.
func alertFromJourney(username string, g *journey.AttackGraph) dashboard.Alert {
	sev := "critical"
	srcIP := ""
	for _, n := range g.Nodes {
		if n.Severity == "low" || n.Severity == "medium" {
			sev = "medium"
		}
		if srcIP == "" && n.SourceIP != "" {
			srcIP = n.SourceIP
		}
	}
	return dashboard.Alert{
		GhostUsername: username,
		Platform:      "local",
		SourceIP:      srcIP,
		Action:        "journey:reconstructed",
		Region:        "local",
		Severity:      sev,
		RiskScore:     journey.RiskScore(g),
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
	}
}

// journeyIngestFromGraph converts an attack graph to the dashboard API payload.
func journeyIngestFromGraph(g *journey.AttackGraph) dashboard.JourneyIngest {
	steps := []dashboard.JourneyStepView{}
	tactics := []string{}
	seen := map[string]bool{}
	for i, n := range g.Nodes {
		tech := n.MitreTechnique()
		if !seen[tech] && tech != "—" {
			seen[tech] = true
			tactics = append(tactics, tech)
		}
		steps = append(steps, dashboard.JourneyStepView{
			Index:     i + 1,
			Service:   n.Service,
			Action:    n.Action,
			SourceIP:  n.SourceIP,
			Severity:  n.Severity,
			Technique: tech,
			Timestamp: n.Timestamp.Format(time.RFC3339),
		})
	}

	stepsJSON, _ := json.Marshal(steps)
	sum := sha256.Sum256(stepsJSON)

	return dashboard.JourneyIngest{
		GhostUsername:   g.GhostUsername,
		Steps:           steps,
		Mermaid:         journey.ToMermaid(g),
		MitreTactics:    tactics,
		RiskScore:       journey.RiskScore(g),
		DurationSeconds: g.Duration.Seconds(),
		SourceHash:      hex.EncodeToString(sum[:8]),
	}
}
