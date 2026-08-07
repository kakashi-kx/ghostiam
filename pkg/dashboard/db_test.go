package dashboard

import "testing"

func TestGhostDeleteAndStatusPreservation(t *testing.T) {
	db, err := OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}

	// Insert a ghost, mark it triggered, then re-upsert as "active".
	g := Ghost{Username: "ghost-del-a1b2c3", PolicyName: "ProdDatabaseReadAccess", Platform: "local", Status: "active"}
	if err := db.UpsertGhost(g); err != nil {
		t.Fatalf("UpsertGhost: %v", err)
	}
	if err := db.MarkGhostTriggered(g.Username); err != nil {
		t.Fatalf("MarkGhostTriggered: %v", err)
	}

	// A re-import from ghosts.json must NOT reset a triggered ghost.
	g.Status = "active"
	if err := db.UpsertGhost(g); err != nil {
		t.Fatalf("re-UpsertGhost: %v", err)
	}
	ghosts, err := db.ListGhosts()
	if err != nil {
		t.Fatalf("ListGhosts: %v", err)
	}
	if len(ghosts) != 1 || ghosts[0].Status != "triggered" {
		t.Fatalf("expected triggered status preserved, got %+v", ghosts)
	}

	// Deleting removes it.
	if err := db.DeleteGhost(g.Username); err != nil {
		t.Fatalf("DeleteGhost: %v", err)
	}
	ghosts, err = db.ListGhosts()
	if err != nil {
		t.Fatalf("ListGhosts after delete: %v", err)
	}
	if len(ghosts) != 0 {
		t.Fatalf("expected no ghosts after delete, got %d", len(ghosts))
	}
}

func TestAlertsByHourPadded(t *testing.T) {
	db, err := OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	hours, err := db.AlertsByHour()
	if err != nil {
		t.Fatalf("AlertsByHour: %v", err)
	}
	if len(hours) != 24 {
		t.Fatalf("expected 24 padded hours, got %d", len(hours))
	}
	if hours[0].Hour != "00" || hours[23].Hour != "23" {
		t.Fatalf("expected 00..23, got %s..%s", hours[0].Hour, hours[23].Hour)
	}
}
