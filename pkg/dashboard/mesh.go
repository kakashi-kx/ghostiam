package dashboard

import (
	"net/http"
)

// handleMesh renders the cross-platform mesh view.
func (s *DashboardServer) handleMesh(w http.ResponseWriter, r *http.Request) {
	note, _ := s.syncFromDisk()
	identities, err := s.db.ListMeshIdentities()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	stats, _ := s.buildStats()

	s.render(w, s.templates.mesh, PageData{
		PageTitle: "Ghost Mesh",
		ActiveNav: "mesh",
		MeshGroups: groupMeshIdentities(identities),
		Stats:      stats,
		SyncNote:   note,
	})
}

// handleMeshSync re-imports mesh data from disk and re-renders the page.
func (s *DashboardServer) handleMeshSync(w http.ResponseWriter, r *http.Request) {
	note, _ := s.syncFromDisk()
	identities, _ := s.db.ListMeshIdentities()
	stats, _ := s.buildStats()

	s.render(w, s.templates.mesh, PageData{
		PageTitle:  "Ghost Mesh",
		ActiveNav:  "mesh",
		MeshGroups: groupMeshIdentities(identities),
		Stats:      stats,
		SyncNote:   note,
	})
}

// groupMeshIdentities groups flat identity rows by mesh_group.
func groupMeshIdentities(ids []MeshIdentity) []MeshGroupView {
	order := []string{}
	byGroup := map[string][]MeshLegView{}
	for _, id := range ids {
		if _, ok := byGroup[id.MeshGroup]; !ok {
			order = append(order, id.MeshGroup)
		}
		byGroup[id.MeshGroup] = append(byGroup[id.MeshGroup], MeshLegView{
			Platform:   id.Platform,
			Username:   id.Username,
			ExternalID: id.ExternalID,
			Status:     id.Status,
		})
	}

	groups := []MeshGroupView{}
	for _, name := range order {
		groups = append(groups, MeshGroupView{Name: name, Legs: byGroup[name]})
	}
	return groups
}
