package dashboard

import (
	"net/http"
	"time"
)

// handleAlerts renders the alert feed page.
func (s *DashboardServer) handleAlerts(w http.ResponseWriter, r *http.Request) {
	_, _ = s.syncFromDisk()
	alerts, err := s.db.ListAlerts(50)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	stats, _ := s.buildStats()

	s.render(w, s.templates.alerts, PageData{
		PageTitle: "Alert Feed",
		ActiveNav: "alerts",
		Alerts:    alerts,
		Stats:     stats,
	})
}

// handleAlertsPartial returns just the alert list fragment for HTMX refresh.
func (s *DashboardServer) handleAlertsPartial(w http.ResponseWriter, r *http.Request) {
	alerts, err := s.db.ListAlerts(20)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.templates.alerts.ExecuteTemplate(w, "alertList", alerts); err != nil {
		http.Error(w, "render failed", http.StatusInternalServerError)
	}
}

// handleAlertSimulate creates a demo alert and broadcasts it over SSE so the
// live feed and toasts can be demonstrated without the CLI.
func (s *DashboardServer) handleAlertSimulate(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	if username == "" {
		username = "ghost-demo-db-read-a7f3c2"
	}
	action := r.FormValue("action")
	if action == "" {
		action = "s3:ListBuckets"
	}

	alert := Alert{
		GhostUsername: username,
		Platform:      "local",
		SourceIP:      "185.220.101.23",
		UserAgent:     "aws-cli/2.15.0 Python/3.11",
		Action:        action,
		Region:        "us-east-1",
		Severity:      "critical",
		RiskScore:     9,
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
	}

	id, err := s.db.InsertAlert(alert)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	alert.ID = id
	_ = s.db.MarkGhostTriggered(username)

	s.Publish(SSEMessage{Type: "alert", Payload: alert})

	http.Redirect(w, r, "/alerts", http.StatusSeeOther)
}
