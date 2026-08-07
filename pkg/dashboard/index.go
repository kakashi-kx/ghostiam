package dashboard

import (
	"encoding/json"
	"net/http"
)

// handleIndex renders the dashboard home page.
func (s *DashboardServer) handleIndex(w http.ResponseWriter, r *http.Request) {
	note, _ := s.syncFromDisk()
	stats, err := s.buildStats()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	alerts, err := s.db.ListAlerts(6)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.render(w, s.templates.index, PageData{
		PageTitle: "Dashboard",
		ActiveNav: "dashboard",
		Stats:     stats,
		Charts:    buildCharts(stats),
		Alerts:    alerts,
		SyncNote:  note,
	})
}

// handleStatsPartial returns just the stats cards fragment, refreshed by HTMX.
func (s *DashboardServer) handleStatsPartial(w http.ResponseWriter, r *http.Request) {
	_, _ = s.syncFromDisk()
	stats, err := s.buildStats()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.templates.index.ExecuteTemplate(w, "statsRow", stats); err != nil {
		http.Error(w, "render failed", http.StatusInternalServerError)
	}
}

// buildCharts encodes Chart.js datasets from the current stats.
func buildCharts(stats *StatsView) *ChartData {
	// Risk distribution donut.
	risk := struct {
		Labels []string `json:"labels"`
		Values []int    `json:"values"`
	}{}
	for _, sev := range []string{"critical", "high", "medium", "low"} {
		if n, ok := stats.RiskDistribution[sev]; ok {
			risk.Labels = append(risk.Labels, sev)
			risk.Values = append(risk.Values, n)
		}
	}
	riskJSON, _ := json.Marshal(risk)

	// Alerts by hour line.
	hours := struct {
		Labels []string `json:"labels"`
		Values []int    `json:"values"`
	}{}
	for _, hc := range stats.AlertsByHour {
		hours.Labels = append(hours.Labels, hc.Hour+"h")
		hours.Values = append(hours.Values, hc.Count)
	}
	byHourJSON, _ := json.Marshal(hours)

	// Top actions bar.
	actions := struct {
		Labels []string `json:"labels"`
		Values []int    `json:"values"`
	}{}
	for _, ac := range stats.TopActions {
		actions.Labels = append(actions.Labels, ac.Action)
		actions.Values = append(actions.Values, ac.Count)
	}
	actionsJSON, _ := json.Marshal(actions)

	return &ChartData{
		RiskJSON:    string(riskJSON),
		ByHourJSON:  string(byHourJSON),
		ActionsJSON: string(actionsJSON),
	}
}
