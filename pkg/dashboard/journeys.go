package dashboard

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
)

// handleJourneys renders the journey list page.
func (s *DashboardServer) handleJourneys(w http.ResponseWriter, r *http.Request) {
	note, _ := s.syncFromDisk()
	journeys, err := s.db.ListJourneys()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	stats, _ := s.buildStats()

	s.render(w, s.templates.journeys, PageData{
		PageTitle: "Attack Journeys",
		ActiveNav: "journeys",
		Journeys:  journeys,
		Stats:     stats,
		SyncNote:  note,
	})
}

// handleJourneyDetail renders a single journey with its steps and Mermaid.
func (s *DashboardServer) handleJourneyDetail(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(mux.Vars(r)["id"], 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	j, err := s.db.GetJourney(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	var steps []JourneyStepView
	_ = json.Unmarshal([]byte(j.StepsJSON), &steps)
	var tactics []string
	_ = json.Unmarshal([]byte(j.MitreTactics), &tactics)

	s.render(w, s.templates.journey, PageData{
		PageTitle:    "Attack Journey",
		ActiveNav:    "journeys",
		Journey:      j,
		JourneySteps: steps,
		MitreTactics: tactics,
	})
}

// handleJourneyMermaid serves the raw Mermaid source for a journey.
func (s *DashboardServer) handleJourneyMermaid(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(mux.Vars(r)["id"], 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	j, err := s.db.GetJourney(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(j.MermaidDiagram))
}
