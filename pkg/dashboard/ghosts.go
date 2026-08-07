package dashboard

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/kakashi-kx/ghostiam/pkg/deploy"
	"github.com/kakashi-kx/ghostiam/pkg/store"
	"github.com/kakashi-kx/ghostiam/pkg/templates"
)

// handleGhosts renders the ghost management page.
func (s *DashboardServer) handleGhosts(w http.ResponseWriter, r *http.Request) {
	_, _ = s.syncFromDisk()
	ghosts, err := s.db.ListGhosts()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	stats, _ := s.buildStats()

	s.render(w, s.templates.ghosts, PageData{
		PageTitle: "Ghost Users",
		ActiveNav: "ghosts",
		Ghosts:    ghosts,
		Stats:     stats,
	})
}

// handleGhostDeploy deploys count local ghost users with generated keys and
// records them in the dashboard database and ghosts.json.
func (s *DashboardServer) handleGhostDeploy(w http.ResponseWriter, r *http.Request) {
	count := atoiDefault(r.FormValue("count"), 5)
	if count > 50 {
		count = 50
	}
	prefix := r.FormValue("prefix")
	if prefix == "" {
		prefix = "dashboard"
	}

	syncStore := store.NewLocalStore("ghosts.json")
	policies := templates.GetDecoyPolicies()
	created := 0

	for i := 0; i < count; i++ {
		policy := policies[i%len(policies)]
		username := ghostName(prefix, policy.Name)
		akid, secret, err := deploy.GenerateKeys()
		if err != nil {
			continue
		}
		rec := store.GhostRecord{
			Username:        username,
			PolicyName:      policy.Name,
			AccessKeyID:     akid,
			SecretAccessKey: secret,
		}
		if err := syncStore.AddGhost(rec); err != nil {
			continue
		}
		if err := s.db.UpsertGhost(Ghost{
			Username:    username,
			PolicyName:  policy.Name,
			Platform:    "local",
			AccessKeyID: akid,
			Status:      "active",
		}); err != nil {
			continue
		}
		created++
	}

	ghosts, _ := s.db.ListGhosts()
	stats, _ := s.buildStats()
	s.render(w, s.templates.ghosts, PageData{
		PageTitle: "Ghost Users",
		ActiveNav: "ghosts",
		Ghosts:    ghosts,
		Stats:     stats,
	})
}

// handleGhostArchive marks a ghost as archived.
func (s *DashboardServer) handleGhostArchive(w http.ResponseWriter, r *http.Request) {
	username := mux.Vars(r)["username"]
	if err := s.db.ArchiveGhost(username); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/ghosts", http.StatusSeeOther)
}

// ghostName builds a unique ghost username with the standard shape.
func ghostName(prefix, policyName string) string {
	return "ghost-" + prefix + "-" + shortRole(policyName) + "-" + randHex(6)
}

// shortRole maps a policy name to a short role label (matches CLI naming).
func shortRole(policyName string) string {
	switch policyName {
	case "ProdDatabaseReadAccess":
		return "db-read"
	case "CloudInfrastructureViewer":
		return "infra-view"
	case "S3BackupOperator":
		return "s3-backup"
	case "IAMSecurityAuditor":
		return "iam-audit"
	case "CrossAccountAccessRole":
		return "xacct"
	default:
		return "ghost"
	}
}

// randHex returns a lowercase hex string of n characters.
func randHex(n int) string {
	b := make([]byte, (n+1)/2)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("dashboard: failed to read random bytes: %v", err))
	}
	return hex.EncodeToString(b)[:n]
}

func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return def
		}
		n = n*10 + int(c-'0')
	}
	if n == 0 {
		return def
	}
	return n
}
