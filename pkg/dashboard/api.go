package dashboard

import (
	"encoding/json"
	"math/rand"
	"net/http"
	"time"
)

// EventIngest is the JSON body accepted by POST /api/v1/events. The CLI posts
// alerts, journeys, and seeds here so the dashboard updates in real time.
type EventIngest struct {
	Type    string          `json:"type"`
	Alert   *Alert          `json:"alert,omitempty"`
	Journey *JourneyIngest  `json:"journey,omitempty"`
	Seed    *Seed           `json:"seed,omitempty"`
}

// JourneyIngest is a journey payload from the CLI.
type JourneyIngest struct {
	GhostUsername   string            `json:"ghost_username"`
	Steps           []JourneyStepView `json:"steps"`
	Mermaid         string            `json:"mermaid"`
	MitreTactics    []string          `json:"mitre_tactics"`
	RiskScore       int               `json:"risk_score"`
	DurationSeconds float64           `json:"duration_seconds"`
	SourceHash      string            `json:"source_hash"`
}

func (s *DashboardServer) handleAPIStats(w http.ResponseWriter, r *http.Request) {
	_, _ = s.syncFromDisk()
	stats, err := s.buildStats()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at":      time.Now().UTC().Format(time.RFC3339),
		"ghosts":            stats.Ghosts,
		"ghosts_active":     stats.GhostsActive,
		"ghosts_triggered":  stats.GhostsTriggered,
		"alerts_total":      stats.AlertsTotal,
		"alerts_today":      stats.AlertsToday,
		"journeys":          stats.Journeys,
		"mesh_groups":       stats.MeshGroups,
		"seeds":             stats.Seeds,
		"risk_distribution": stats.RiskDistribution,
		"top_actions":       stats.TopActions,
		"top_source_ips":    stats.TopIPs,
		"alerts_by_hour":    stats.AlertsByHour,
	})
}

func (s *DashboardServer) handleAPIGhosts(w http.ResponseWriter, r *http.Request) {
	_, _ = s.syncFromDisk()
	ghosts, err := s.db.ListGhosts()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ghosts": ghosts})
}

func (s *DashboardServer) handleAPIAlerts(w http.ResponseWriter, r *http.Request) {
	alerts, err := s.db.ListAlerts(100)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"alerts": alerts})
}

func (s *DashboardServer) handleAPIJourneys(w http.ResponseWriter, r *http.Request) {
	_, _ = s.syncFromDisk()
	journeys, err := s.db.ListJourneys()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"journeys": journeys})
}

// handleCreateAlert accepts a single alert pushed by the CLI, persists it,
// marks the ghost triggered, and broadcasts it over SSE.
func (s *DashboardServer) handleCreateAlert(w http.ResponseWriter, r *http.Request) {
	var a Alert
	if err := json.NewDecoder(r.Body).Decode(&a); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid payload"})
		return
	}
	if a.Severity == "" {
		a.Severity = "critical"
	}
	if a.CreatedAt == "" {
		a.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	id, err := s.db.InsertAlert(a)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	a.ID = id
	_ = s.db.MarkGhostTriggered(a.GhostUsername)
	s.broadcastAlert(a)
	writeJSON(w, http.StatusCreated, map[string]any{"status": "ok", "alert_id": id})
}

// demo actions, severities, source IPs, and user agents used by the Simulate
// buttons so demo alerts are varied and realistic.
var (
	simActions = []string{
		"iam:PassRole", "iam:CreateAccessKey", "iam:AttachUserPolicy",
		"s3:ListBuckets", "s3:GetObject", "ec2:DescribeInstances",
		"sts:AssumeRole", "kms:Decrypt", "secretsmanager:GetSecretValue",
		"lambda:InvokeFunction", "ssm:GetParameter", "iam:AddUserToGroup",
	}
	simSeverities = []string{"info", "low", "medium", "high", "critical"}
	simSourceIPs  = []string{
		"185.220.101.23", "91.219.236.132", "103.75.190.42",
		"45.155.205.233", "185.65.135.202", "162.247.72.199", "192.42.116.16",
	}
	simUserAgents = []string{
		"aws-cli/2.15.0 Python/3.11", "boto3/1.34.0 Botocore/1.34.0",
		"curl/8.4.0", "aws-sdk-go-v2/1.24.0", "python-requests/2.31.0",
	}
)

func randomChoice(items []string) string {
	return items[rand.Intn(len(items))]
}

// handleAPISimulateAlert creates a demo alert for a random active ghost (or the
// username in the form body) and broadcasts it — used by the HTMX Simulate
// button so the live feed can be demonstrated without the CLI.
func (s *DashboardServer) handleAPISimulateAlert(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	action := r.FormValue("action")

	if username == "" {
		ghosts, err := s.db.ListGhosts()
		if err == nil {
			var active []string
			for _, g := range ghosts {
				if g.Status == "active" {
					active = append(active, g.Username)
				}
			}
			if len(active) > 0 {
				username = active[rand.Intn(len(active))]
			}
		}
	}
	if username == "" {
		username = "ghost-demo-db-read-a7f3c2"
	}
	if action == "" {
		action = randomChoice(simActions)
	}

	a := Alert{
		GhostUsername: username,
		Platform:      "local",
		SourceIP:      randomChoice(simSourceIPs),
		UserAgent:     randomChoice(simUserAgents),
		Action:        action,
		Region:        "us-east-1",
		Severity:      randomChoice(simSeverities),
		RiskScore:     1 + rand.Intn(10),
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
	}

	id, err := s.db.InsertAlert(a)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	a.ID = id
	_ = s.db.MarkGhostTriggered(username)
	s.broadcastAlert(a)
	writeJSON(w, http.StatusCreated, map[string]any{
		"status":        "ok",
		"alert_id":      id,
		"ghost_username": username,
		"alert":         a,
	})
}

// handleAPIEvents ingests alerts, journeys, and seeds pushed by the CLI,
// persists them, marks ghosts triggered, and broadcasts over SSE.
func (s *DashboardServer) handleAPIEvents(w http.ResponseWriter, r *http.Request) {
	var ev EventIngest
	if err := json.NewDecoder(r.Body).Decode(&ev); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
		return
	}

	resp := map[string]any{"ok": true}

	if ev.Journey != nil {
		stepsJSON, _ := json.Marshal(ev.Journey.Steps)
		tacticsJSON, _ := json.Marshal(ev.Journey.MitreTactics)
		hash := ev.Journey.SourceHash
		if hash == "" {
			hash = hashSource(string(stepsJSON))
		}
		id, err := s.db.InsertJourney(Journey{
			GhostUsername:   ev.Journey.GhostUsername,
			StepsJSON:       string(stepsJSON),
			MermaidDiagram:  ev.Journey.Mermaid,
			MitreTactics:    string(tacticsJSON),
			RiskScore:       ev.Journey.RiskScore,
			DurationSeconds: ev.Journey.DurationSeconds,
			SourceHash:      hash,
		})
		if err == nil {
			resp["journey_id"] = id
			if ev.Alert != nil {
				ev.Alert.JourneyID = id
			}
			s.Publish(SSEMessage{Type: "journey", Payload: map[string]any{
				"id":             id,
				"ghost_username": ev.Journey.GhostUsername,
				"risk_score":     ev.Journey.RiskScore,
			}})
		}
	}

	if ev.Alert != nil {
		if ev.Alert.Severity == "" {
			ev.Alert.Severity = "critical"
		}
		if ev.Alert.CreatedAt == "" {
			ev.Alert.CreatedAt = time.Now().UTC().Format(time.RFC3339)
		}
		id, err := s.db.InsertAlert(*ev.Alert)
		if err == nil {
			ev.Alert.ID = id
			resp["alert_id"] = id
			_ = s.db.MarkGhostTriggered(ev.Alert.GhostUsername)
			s.Publish(SSEMessage{Type: "alert", Payload: *ev.Alert})
		}
	}

	if ev.Seed != nil {
		if ev.Seed.CreatedAt == "" {
			ev.Seed.CreatedAt = time.Now().UTC().Format(time.RFC3339)
		}
		id, err := s.db.InsertSeed(*ev.Seed)
		if err == nil {
			resp["seed_id"] = id
			s.Publish(SSEMessage{Type: "seed", Payload: *ev.Seed})
		}
	}

	writeJSON(w, http.StatusOK, resp)
}
