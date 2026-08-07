package dashboard

import (
	"net/http"
)

// handleSeeds renders the seed management page.
func (s *DashboardServer) handleSeeds(w http.ResponseWriter, r *http.Request) {
	note, _ := s.syncFromDisk()
	seeds, err := s.db.ListSeeds()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	ghosts, _ := s.db.ListGhosts()
	stats, _ := s.buildStats()

	s.render(w, s.templates.seeds, PageData{
		PageTitle: "Token Seeds",
		ActiveNav: "seeds",
		Seeds:     seeds,
		Ghosts:    ghosts,
		Stats:     stats,
		SyncNote:  note,
	})
}

// handleSeedCreate records a seed planted for a ghost (typically posted by the
// CLI's seed command through /api/v1/events).
func (s *DashboardServer) handleSeedCreate(w http.ResponseWriter, r *http.Request) {
	seed := Seed{
		GhostUsername: r.FormValue("ghost_user"),
		Platform:      r.FormValue("platform"),
		LocationURL:   r.FormValue("location_url"),
		BaitFilename:  r.FormValue("bait_filename"),
		Status:        "active",
	}
	if seed.GhostUsername == "" || seed.Platform == "" {
		http.Error(w, "ghost_user and platform are required", http.StatusBadRequest)
		return
	}

	if _, err := s.db.InsertSeed(seed); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/seeds", http.StatusSeeOther)
}
