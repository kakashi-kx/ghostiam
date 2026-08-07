package dashboard

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/kakashi-kx/ghostiam/pkg/mesh"
	"github.com/kakashi-kx/ghostiam/pkg/store"
)

// JourneyStepView is a display-ready attack step.
type JourneyStepView struct {
	Index     int    `json:"index"`
	Service   string `json:"service"`
	Action    string `json:"action"`
	SourceIP  string `json:"source_ip"`
	Severity  string `json:"severity"`
	Technique string `json:"technique"`
	Timestamp string `json:"timestamp"`
}

// MeshGroupView groups the platform legs of one correlated persona.
type MeshGroupView struct {
	Name string        `json:"name"`
	Legs []MeshLegView `json:"legs"`
}

// MeshLegView is one platform leg of a mesh persona.
type MeshLegView struct {
	Platform   string `json:"platform"`
	Username   string `json:"username"`
	ExternalID string `json:"external_id"`
	Status     string `json:"status"`
}

// buildStats gathers every number needed on the home page.
func (s *DashboardServer) buildStats() (*StatsView, error) {
	active, triggered, archived, err := s.db.GhostCounts()
	if err != nil {
		return nil, err
	}
	alertsTotal, alertsToday, err := s.db.AlertCounts()
	if err != nil {
		return nil, err
	}
	journeys, err := s.db.ListJourneys()
	if err != nil {
		return nil, err
	}
	meshGroups, err := s.db.MeshGroupCount()
	if err != nil {
		return nil, err
	}
	seeds, err := s.db.ListSeeds()
	if err != nil {
		return nil, err
	}
	riskDist, err := s.db.RiskDistribution()
	if err != nil {
		return nil, err
	}
	topActions, err := s.db.TopActions(6)
	if err != nil {
		return nil, err
	}
	topIPs, err := s.db.TopIPs(6)
	if err != nil {
		return nil, err
	}
	byHour, err := s.db.AlertsByHour()
	if err != nil {
		return nil, err
	}

	return &StatsView{
		Ghosts:           active + triggered + archived,
		GhostsActive:     active,
		GhostsTriggered:  triggered,
		AlertsTotal:      alertsTotal,
		AlertsToday:      alertsToday,
		Journeys:         len(journeys),
		MeshGroups:       meshGroups,
		Seeds:            len(seeds),
		RiskDistribution: riskDist,
		TopActions:       topActions,
		TopIPs:           topIPs,
		AlertsByHour:     byHour,
	}, nil
}

// syncFromDisk imports ghost, mesh, and journey data written by the CLI so the
// dashboard reflects CLI activity without any manual steps.
func (s *DashboardServer) syncFromDisk() (string, error) {
	notes := []string{}

	// Ghosts from ghosts.json
	if n, err := syncGhosts(s); err != nil {
		notes = append(notes, "ghosts: "+err.Error())
	} else if n > 0 {
		notes = append(notes, fmt.Sprintf("ghosts: %d", n))
	}

	// Mesh identities from mesh-identities.json + okta-ghosts.json
	if n, err := syncMesh(s); err != nil {
		notes = append(notes, "mesh: "+err.Error())
	} else if n > 0 {
		notes = append(notes, fmt.Sprintf("mesh: %d", n))
	}

	return joinNotes(notes), nil
}

func joinNotes(notes []string) string {
	out := ""
	for i, n := range notes {
		if i > 0 {
			out += " · "
		}
		out += n
	}
	return out
}

func syncGhosts(s *DashboardServer) (int, error) {
	if _, err := os.Stat("ghosts.json"); err != nil {
		// ghosts.json is gone (e.g. `ghostiam clean --local`): drop every
		// local ghost so the dashboard reflects the CLI state.
		if _, derr := s.db.Exec(`DELETE FROM ghosts WHERE platform = 'local'`); derr != nil {
			return 0, derr
		}
		return 0, nil
	}
	records, err := store.NewLocalStore("ghosts.json").ListGhosts()
	if err != nil {
		return 0, err
	}

	// Import every record that still exists on disk.
	seen := map[string]bool{}
	n := 0
	for _, r := range records {
		if err := s.db.UpsertGhost(Ghost{
			Username:    r.Username,
			PolicyName:  r.PolicyName,
			Platform:    "local",
			AccessKeyID: r.AccessKeyID,
			Status:      "active",
			CreatedAt:   r.CreatedAt.Format(time.RFC3339),
		}); err != nil {
			return n, err
		}
		seen[r.Username] = true
		n++
	}

	// Remove local ghosts that were deleted from ghosts.json so the dashboard
	// and CLI never drift apart.
	rows, err := s.db.Query(`SELECT username FROM ghosts WHERE platform = 'local'`)
	if err != nil {
		return n, err
	}
	defer rows.Close()
	var stale []string
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err != nil {
			return n, err
		}
		if !seen[u] {
			stale = append(stale, u)
		}
	}
	for _, u := range stale {
		if err := s.db.DeleteGhost(u); err != nil {
			return n, err
		}
	}
	return n, rows.Err()
}

func syncMesh(s *DashboardServer) (int, error) {
	n := 0

	if _, err := os.Stat("mesh-identities.json"); err == nil {
		data, err := os.ReadFile("mesh-identities.json")
		if err == nil {
			var ids []mesh.MeshIdentity
			if err := json.Unmarshal(data, &ids); err == nil {
				for _, id := range ids {
					group := id.Username
					legs := []struct {
						platform, external string
					}{
						{"aws", id.AWSArn},
						{"github", id.GitHubHandle},
						{"okta", id.OktaEmail},
					}
					for _, leg := range legs {
						if leg.external == "" {
							continue
						}
						if err := s.db.UpsertMeshIdentity(MeshIdentity{
							MeshGroup:  group,
							Username:   id.Username,
							Platform:   leg.platform,
							ExternalID: leg.external,
							Status:     "active",
							CreatedAt:  id.CreatedAt.Format(time.RFC3339),
						}); err == nil {
							n++
						}
					}
				}
			}
		}
	}

	if _, err := os.Stat("okta-ghosts.json"); err == nil {
		data, err := os.ReadFile("okta-ghosts.json")
		if err == nil {
			var users []mesh.OktaUser
			if err := json.Unmarshal(data, &users); err == nil {
				for _, u := range users {
					if err := s.db.UpsertMeshIdentity(MeshIdentity{
						MeshGroup:  u.Username,
						Username:   u.Username,
						Platform:   "okta",
						ExternalID: u.OktaID,
						Status:     "active",
						CreatedAt:  u.CreatedAt.Format(time.RFC3339),
					}); err == nil {
						n++
					}
				}
			}
		}
	}

	return n, nil
}

// hashSource returns a short sha256 of an arbitrary string for dedup.
func hashSource(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:8])
}
