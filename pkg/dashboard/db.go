// Package dashboard is the GhostIam web dashboard: a real-time operations
// console built on net/http, HTMX, and SQLite. It surfaces ghost users,
// alerts, attack journeys, cross-platform mesh, and token seeds in one place.
package dashboard

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// DB wraps the SQLite connection with typed query helpers.
type DB struct {
	*sql.DB
}

// Ghost is a dashboard view of a deployed decoy identity.
type Ghost struct {
	ID          int64     `json:"id"`
	Username    string    `json:"username"`
	PolicyName  string    `json:"policy_name"`
	Platform    string    `json:"platform"`
	MeshGroup   string    `json:"mesh_group"`
	AccessKeyID string    `json:"access_key_id"`
	Status      string    `json:"status"`
	CreatedAt   string    `json:"created_at"`
	TriggeredAt *string   `json:"triggered_at"`
}

// Alert is a single detection event.
type Alert struct {
	ID            int64  `json:"id"`
	GhostUsername string `json:"ghost_username"`
	Platform      string `json:"platform"`
	SourceIP      string `json:"source_ip"`
	UserAgent     string `json:"user_agent"`
	Action        string `json:"action"`
	Region        string `json:"region"`
	Severity      string `json:"severity"`
	RawEvent      string `json:"raw_event"`
	JourneyID     int64  `json:"journey_id"`
	RiskScore     int    `json:"risk_score"`
	CreatedAt     string `json:"created_at"`
}

// Journey is a stored attack journey.
type Journey struct {
	ID              int64   `json:"id"`
	GhostUsername   string  `json:"ghost_username"`
	StepsJSON       string  `json:"steps_json"`
	MermaidDiagram  string  `json:"mermaid_diagram"`
	MitreTactics    string  `json:"mitre_tactics"`
	RiskScore       int     `json:"risk_score"`
	DurationSeconds float64 `json:"duration_seconds"`
	Status          string  `json:"status"`
	SourceHash      string  `json:"source_hash"`
	CreatedAt       string  `json:"created_at"`
}

// Seed is a planted bait location.
type Seed struct {
	ID          int64  `json:"id"`
	GhostUsername string `json:"ghost_username"`
	Platform    string `json:"platform"`
	LocationURL string `json:"location_url"`
	BaitFilename string `json:"bait_filename"`
	Status      string `json:"status"`
	CreatedAt   string `json:"created_at"`
}

// MeshIdentity is one platform leg of a correlated ghost persona.
type MeshIdentity struct {
	ID        int64  `json:"id"`
	MeshGroup string `json:"mesh_group"`
	Username  string `json:"username"`
	Platform  string `json:"platform"`
	ExternalID string `json:"external_id"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
}

// ActionCount is an (action, count) pair used in reports.
type ActionCount struct {
	Action string `json:"action"`
	Count  int    `json:"count"`
}

// IPCount is an (ip, count) pair used in reports.
type IPCount struct {
	IP    string `json:"ip"`
	Count int    `json:"count"`
}

// HourCount is alerts-per-hour for the traffic chart.
type HourCount struct {
	Hour  string `json:"hour"`
	Count int    `json:"count"`
}

// OpenDB opens (or creates) the SQLite database and runs migrations.
func OpenDB(path string) (*DB, error) {
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("dashboard: open %s: %w", path, err)
	}
	raw.SetMaxOpenConns(1) // sqlite single-writer safety

	db := &DB{raw}
	if err := db.migrate(); err != nil {
		return nil, err
	}
	return db, nil
}

func (d *DB) migrate() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS ghosts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			policy_name TEXT NOT NULL,
			platform TEXT DEFAULT 'aws',
			mesh_group TEXT,
			access_key_id TEXT,
			access_key_secret TEXT,
			status TEXT DEFAULT 'active',
			created_at TEXT,
			triggered_at TEXT
		);`,
		`CREATE TABLE IF NOT EXISTS alerts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ghost_username TEXT NOT NULL,
			platform TEXT,
			source_ip TEXT,
			user_agent TEXT,
			action TEXT,
			region TEXT,
			severity TEXT DEFAULT 'critical',
			raw_event TEXT,
			journey_id INTEGER DEFAULT 0,
			risk_score INTEGER DEFAULT 0,
			created_at TEXT
		);`,
		`CREATE TABLE IF NOT EXISTS journeys (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ghost_username TEXT NOT NULL,
			steps_json TEXT NOT NULL,
			mermaid_diagram TEXT,
			mitre_tactics TEXT,
			risk_score INTEGER DEFAULT 0,
			duration_seconds REAL DEFAULT 0,
			status TEXT DEFAULT 'active',
			source_hash TEXT UNIQUE,
			created_at TEXT
		);`,
		`CREATE TABLE IF NOT EXISTS seeds (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ghost_username TEXT NOT NULL,
			platform TEXT NOT NULL,
			location_url TEXT,
			bait_filename TEXT,
			status TEXT DEFAULT 'active',
			created_at TEXT
		);`,
		`CREATE TABLE IF NOT EXISTS mesh_identities (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			mesh_group TEXT NOT NULL,
			username TEXT NOT NULL,
			platform TEXT NOT NULL,
			external_id TEXT,
			status TEXT DEFAULT 'active',
			created_at TEXT
		);`,
	}
	for _, s := range stmts {
		if _, err := d.Exec(s); err != nil {
			return fmt.Errorf("dashboard: migrate: %w", err)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// ghosts
// ---------------------------------------------------------------------------

// ListGhosts returns all ghost users, newest first.
func (d *DB) ListGhosts() ([]Ghost, error) {
	rows, err := d.Query(`SELECT id, username, policy_name, platform,
		COALESCE(mesh_group,''), COALESCE(access_key_id,''), status,
		COALESCE(created_at,''), COALESCE(triggered_at,'')
		FROM ghosts ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Ghost
	for rows.Next() {
		var g Ghost
		var triggeredAt string
		if err := rows.Scan(&g.ID, &g.Username, &g.PolicyName, &g.Platform,
			&g.MeshGroup, &g.AccessKeyID, &g.Status, &g.CreatedAt, &triggeredAt); err != nil {
			return nil, err
		}
		if triggeredAt != "" {
			g.TriggeredAt = &triggeredAt
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// UpsertGhost inserts or updates a ghost by username. Existing status is
// preserved: a ghost that has been triggered or archived stays that way even
// when re-imported from ghosts.json.
func (d *DB) UpsertGhost(g Ghost) error {
	if g.Status == "" {
		g.Status = "active"
	}
	if g.CreatedAt == "" {
		g.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	_, err := d.Exec(`INSERT INTO ghosts (username, policy_name, platform, mesh_group,
		access_key_id, access_key_secret, status, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(username) DO UPDATE SET
			policy_name = excluded.policy_name,
			platform = excluded.platform,
			mesh_group = COALESCE(excluded.mesh_group, ghosts.mesh_group),
			access_key_id = COALESCE(excluded.access_key_id, ghosts.access_key_id),
			status = CASE
				WHEN ghosts.status IN ('triggered', 'archived') THEN ghosts.status
				ELSE excluded.status
			END`,
		g.Username, g.PolicyName, g.Platform, g.MeshGroup,
		g.AccessKeyID, g.AccessKeyID, g.Status, g.CreatedAt)
	return err
}

// DeleteGhost removes a ghost entirely from the database.
func (d *DB) DeleteGhost(username string) error {
	_, err := d.Exec(`DELETE FROM ghosts WHERE username = ?`, username)
	return err
}

// ArchiveGhost marks a ghost as archived.
func (d *DB) ArchiveGhost(username string) error {
	_, err := d.Exec(`UPDATE ghosts SET status = 'archived' WHERE username = ?`, username)
	return err
}

// MarkGhostTriggered sets a ghost to triggered and records when.
func (d *DB) MarkGhostTriggered(username string) error {
	_, err := d.Exec(`UPDATE ghosts SET status = 'triggered', triggered_at = ? WHERE username = ?`,
		time.Now().UTC().Format(time.RFC3339), username)
	return err
}

// GhostCounts returns (active, triggered, archived).
func (d *DB) GhostCounts() (active, triggered, archived int, err error) {
	rows, err := d.Query(`SELECT status, COUNT(*) FROM ghosts GROUP BY status`)
	if err != nil {
		return 0, 0, 0, err
	}
	defer rows.Close()
	for rows.Next() {
		var status string
		var n int
		if err := rows.Scan(&status, &n); err != nil {
			return 0, 0, 0, err
		}
		switch status {
		case "active":
			active = n
		case "triggered":
			triggered = n
		case "archived":
			archived = n
		}
	}
	return active, triggered, archived, rows.Err()
}

// ---------------------------------------------------------------------------
// alerts
// ---------------------------------------------------------------------------

// ListAlerts returns up to limit alerts, newest first.
func (d *DB) ListAlerts(limit int) ([]Alert, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := d.Query(`SELECT id, ghost_username, COALESCE(platform,''),
		COALESCE(source_ip,''), COALESCE(user_agent,''), COALESCE(action,''),
		COALESCE(region,''), COALESCE(severity,'critical'), COALESCE(raw_event,''),
		COALESCE(journey_id,0), COALESCE(risk_score,0), COALESCE(created_at,'')
		FROM alerts ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Alert
	for rows.Next() {
		var a Alert
		if err := rows.Scan(&a.ID, &a.GhostUsername, &a.Platform, &a.SourceIP,
			&a.UserAgent, &a.Action, &a.Region, &a.Severity, &a.RawEvent,
			&a.JourneyID, &a.RiskScore, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// InsertAlert stores an alert and returns its id.
func (d *DB) InsertAlert(a Alert) (int64, error) {
	if a.CreatedAt == "" {
		a.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if a.Severity == "" {
		a.Severity = "critical"
	}
	res, err := d.Exec(`INSERT INTO alerts (ghost_username, platform, source_ip,
		user_agent, action, region, severity, raw_event, journey_id, risk_score, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.GhostUsername, a.Platform, a.SourceIP, a.UserAgent, a.Action,
		a.Region, a.Severity, a.RawEvent, a.JourneyID, a.RiskScore, a.CreatedAt)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// AlertCounts returns (total, today).
func (d *DB) AlertCounts() (total, today int, err error) {
	if err = d.QueryRow(`SELECT COUNT(*) FROM alerts`).Scan(&total); err != nil {
		return 0, 0, err
	}
	if err = d.QueryRow(`SELECT COUNT(*) FROM alerts WHERE date(created_at) = date('now')`).Scan(&today); err != nil {
		return 0, 0, err
	}
	return total, today, nil
}

// TopActions returns the most frequent alert actions.
func (d *DB) TopActions(limit int) ([]ActionCount, error) {
	if limit <= 0 {
		limit = 8
	}
	rows, err := d.Query(`SELECT action, COUNT(*) AS n FROM alerts
		WHERE action != '' GROUP BY action ORDER BY n DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ActionCount
	for rows.Next() {
		var ac ActionCount
		if err := rows.Scan(&ac.Action, &ac.Count); err != nil {
			return nil, err
		}
		out = append(out, ac)
	}
	return out, rows.Err()
}

// TopIPs returns the most frequent source IPs.
func (d *DB) TopIPs(limit int) ([]IPCount, error) {
	if limit <= 0 {
		limit = 8
	}
	rows, err := d.Query(`SELECT source_ip, COUNT(*) AS n FROM alerts
		WHERE source_ip != '' GROUP BY source_ip ORDER BY n DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []IPCount
	for rows.Next() {
		var ic IPCount
		if err := rows.Scan(&ic.IP, &ic.Count); err != nil {
			return nil, err
		}
		out = append(out, ic)
	}
	return out, rows.Err()
}

// RiskDistribution returns alert counts per severity level.
func (d *DB) RiskDistribution() (map[string]int, error) {
	rows, err := d.Query(`SELECT severity, COUNT(*) FROM alerts GROUP BY severity`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[string]int{}
	for rows.Next() {
		var sev string
		var n int
		if err := rows.Scan(&sev, &n); err != nil {
			return nil, err
		}
		out[sev] = n
	}
	return out, rows.Err()
}

// AlertsByHour returns alert counts per UTC hour over the last 24h, padded so
// every hour 00..23 appears (charts need a continuous window). Timestamps are
// parsed in Go so the bucketing is independent of the stored text format.
func (d *DB) AlertsByHour() ([]HourCount, error) {
	now := time.Now().UTC()
	cutoff := now.Add(-24 * time.Hour)

	rows, err := d.Query(`SELECT created_at FROM alerts WHERE created_at IS NOT NULL AND created_at != ''`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	counts := map[int]int{}
	for rows.Next() {
		var ts string
		if err := rows.Scan(&ts); err != nil {
			return nil, err
		}
		t, ok := parseAlertTime(ts)
		if !ok {
			continue
		}
		t = t.UTC()
		if t.Before(cutoff) || t.After(now) {
			continue
		}
		counts[t.Hour()]++
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := make([]HourCount, 0, 24)
	for h := 0; h < 24; h++ {
		out = append(out, HourCount{Hour: fmt.Sprintf("%02d", h), Count: counts[h]})
	}
	return out, nil
}

// parseAlertTime parses a stored timestamp in any layout the CLI or dashboard
// may have written, so hour bucketing never silently drops rows.
func parseAlertTime(s string) (time.Time, bool) {
	for _, layout := range []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999 -0700 MST",
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05 -0700 MST",
		"2006-01-02 15:04:05",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// ---------------------------------------------------------------------------
// journeys
// ---------------------------------------------------------------------------

// ListJourneys returns all journeys, newest first.
func (d *DB) ListJourneys() ([]Journey, error) {
	rows, err := d.Query(`SELECT id, ghost_username, steps_json,
		COALESCE(mermaid_diagram,''), COALESCE(mitre_tactics,''),
		COALESCE(risk_score,0), COALESCE(duration_seconds,0),
		COALESCE(status,'active'), COALESCE(source_hash,''), COALESCE(created_at,'')
		FROM journeys ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Journey
	for rows.Next() {
		var j Journey
		if err := rows.Scan(&j.ID, &j.GhostUsername, &j.StepsJSON,
			&j.MermaidDiagram, &j.MitreTactics, &j.RiskScore,
			&j.DurationSeconds, &j.Status, &j.SourceHash, &j.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// GetJourney returns a single journey by id.
func (d *DB) GetJourney(id int64) (*Journey, error) {
	row := d.QueryRow(`SELECT id, ghost_username, steps_json,
		COALESCE(mermaid_diagram,''), COALESCE(mitre_tactics,''),
		COALESCE(risk_score,0), COALESCE(duration_seconds,0),
		COALESCE(status,'active'), COALESCE(source_hash,''), COALESCE(created_at,'')
		FROM journeys WHERE id = ?`, id)

	var j Journey
	if err := row.Scan(&j.ID, &j.GhostUsername, &j.StepsJSON,
		&j.MermaidDiagram, &j.MitreTactics, &j.RiskScore,
		&j.DurationSeconds, &j.Status, &j.SourceHash, &j.CreatedAt); err != nil {
		return nil, err
	}
	return &j, nil
}

// InsertJourney stores a journey and returns its id. Duplicate source_hash
// values are ignored (returns 0, nil).
func (d *DB) InsertJourney(j Journey) (int64, error) {
	if j.Status == "" {
		j.Status = "active"
	}
	if j.CreatedAt == "" {
		j.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	res, err := d.Exec(`INSERT INTO journeys (ghost_username, steps_json,
		mermaid_diagram, mitre_tactics, risk_score, duration_seconds, status, source_hash, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(source_hash) DO NOTHING`,
		j.GhostUsername, j.StepsJSON, j.MermaidDiagram, j.MitreTactics,
		j.RiskScore, j.DurationSeconds, j.Status, j.SourceHash, j.CreatedAt)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// ---------------------------------------------------------------------------
// seeds
// ---------------------------------------------------------------------------

// ListSeeds returns all seeds, newest first.
func (d *DB) ListSeeds() ([]Seed, error) {
	rows, err := d.Query(`SELECT id, ghost_username, platform,
		COALESCE(location_url,''), COALESCE(bait_filename,''),
		COALESCE(status,'active'), COALESCE(created_at,'')
		FROM seeds ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Seed
	for rows.Next() {
		var s Seed
		if err := rows.Scan(&s.ID, &s.GhostUsername, &s.Platform,
			&s.LocationURL, &s.BaitFilename, &s.Status, &s.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// InsertSeed stores a seed and returns its id.
func (d *DB) InsertSeed(s Seed) (int64, error) {
	if s.Status == "" {
		s.Status = "active"
	}
	if s.CreatedAt == "" {
		s.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	res, err := d.Exec(`INSERT INTO seeds (ghost_username, platform,
		location_url, bait_filename, status, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		s.GhostUsername, s.Platform, s.LocationURL, s.BaitFilename, s.Status, s.CreatedAt)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// ---------------------------------------------------------------------------
// mesh
// ---------------------------------------------------------------------------

// ListMeshIdentities returns all mesh identities, grouped by mesh_group.
func (d *DB) ListMeshIdentities() ([]MeshIdentity, error) {
	rows, err := d.Query(`SELECT id, mesh_group, username, platform,
		COALESCE(external_id,''), COALESCE(status,'active'), COALESCE(created_at,'')
		FROM mesh_identities ORDER BY mesh_group, platform`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []MeshIdentity
	for rows.Next() {
		var m MeshIdentity
		if err := rows.Scan(&m.ID, &m.MeshGroup, &m.Username, &m.Platform,
			&m.ExternalID, &m.Status, &m.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// UpsertMeshIdentity inserts a mesh identity unless a leg for the same group
// and platform already exists.
func (d *DB) UpsertMeshIdentity(m MeshIdentity) error {
	if m.Status == "" {
		m.Status = "active"
	}
	if m.CreatedAt == "" {
		m.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	var n int
	if err := d.QueryRow(`SELECT COUNT(*) FROM mesh_identities
		WHERE mesh_group = ? AND platform = ?`, m.MeshGroup, m.Platform).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	_, err := d.Exec(`INSERT INTO mesh_identities (mesh_group, username, platform,
		external_id, status, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		m.MeshGroup, m.Username, m.Platform, m.ExternalID, m.Status, m.CreatedAt)
	return err
}

// MeshGroupCount returns the number of distinct mesh groups.
func (d *DB) MeshGroupCount() (int, error) {
	var n int
	err := d.QueryRow(`SELECT COUNT(DISTINCT mesh_group) FROM mesh_identities`).Scan(&n)
	return n, err
}
