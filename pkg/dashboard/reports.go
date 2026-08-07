package dashboard

import (
	"bytes"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// DashboardReport is the machine-readable report export.
type DashboardReport struct {
	GeneratedAt     string           `json:"generated_at"`
	TotalGhosts     int              `json:"total_ghosts"`
	TriggeredGhosts int              `json:"triggered_ghosts"`
	TotalAlerts     int              `json:"total_alerts"`
	AlertsToday     int              `json:"alerts_today"`
	TotalJourneys   int              `json:"total_journeys"`
	MeshGroups      int              `json:"mesh_groups"`
	ActiveSeeds     int              `json:"active_seeds"`
	TopActions      []ActionCount    `json:"top_actions"`
	TopSourceIPs    []IPCount        `json:"top_source_ips"`
	RiskDistribution map[string]int  `json:"risk_distribution"`
}

// handleReportExport serves a dashboard report as JSON or a minimal PDF.
func (s *DashboardServer) handleReportExport(w http.ResponseWriter, r *http.Request) {
	_, _ = s.syncFromDisk()
	report, err := s.buildReport()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	switch r.URL.Query().Get("format") {
	case "pdf":
		data := buildReportPDF("GhostIam Dashboard Report", reportLines(report))
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition", `attachment; filename="ghostiam-report.pdf"`)
		w.Write(data)
	default:
		writeJSON(w, http.StatusOK, report)
	}
}

// buildReport assembles the current report snapshot.
func (s *DashboardServer) buildReport() (*DashboardReport, error) {
	active, triggered, _, err := s.db.GhostCounts()
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
	topActions, err := s.db.TopActions(8)
	if err != nil {
		return nil, err
	}
	topIPs, err := s.db.TopIPs(8)
	if err != nil {
		return nil, err
	}
	riskDist, err := s.db.RiskDistribution()
	if err != nil {
		return nil, err
	}

	return &DashboardReport{
		GeneratedAt:      time.Now().UTC().Format(time.RFC3339),
		TotalGhosts:      active + triggered,
		TriggeredGhosts:  triggered,
		TotalAlerts:      alertsTotal,
		AlertsToday:      alertsToday,
		TotalJourneys:    len(journeys),
		MeshGroups:       meshGroups,
		ActiveSeeds:      len(seeds),
		TopActions:       topActions,
		TopSourceIPs:     topIPs,
		RiskDistribution: riskDist,
	}, nil
}

// reportLines flattens the report into printable text lines.
func reportLines(r *DashboardReport) []string {
	lines := []string{
		fmt.Sprintf("Generated: %s", r.GeneratedAt),
		"",
		fmt.Sprintf("Ghost users (total):   %d", r.TotalGhosts),
		fmt.Sprintf("Ghost users (triggered): %d", r.TriggeredGhosts),
		fmt.Sprintf("Alerts (total):        %d", r.TotalAlerts),
		fmt.Sprintf("Alerts (today):        %d", r.AlertsToday),
		fmt.Sprintf("Attack journeys:       %d", r.TotalJourneys),
		fmt.Sprintf("Mesh groups:           %d", r.MeshGroups),
		fmt.Sprintf("Active seeds:          %d", r.ActiveSeeds),
		"",
		"Risk distribution:",
	}
	for sev, n := range r.RiskDistribution {
		lines = append(lines, fmt.Sprintf("  %-10s %d", sev, n))
	}
	lines = append(lines, "", "Top actions:")
	for _, ac := range r.TopActions {
		lines = append(lines, fmt.Sprintf("  %-30s %d", ac.Action, ac.Count))
	}
	lines = append(lines, "", "Top source IPs:")
	for _, ip := range r.TopSourceIPs {
		lines = append(lines, fmt.Sprintf("  %-20s %d", ip.IP, ip.Count))
	}
	return lines
}

// buildReportPDF renders a minimal, valid single-page PDF of the report.
func buildReportPDF(title string, lines []string) []byte {
	var sb strings.Builder
	y := 760.0
	sb.WriteString("BT /F1 18 Tf 72 " + pdfNum(y) + " Td (" + pdfEscape(title) + ") Tj ET\n")
	y -= 30
	for _, line := range lines {
		sb.WriteString("BT /F1 11 Tf 72 " + pdfNum(y) + " Td (" + pdfEscape(line) + ") Tj ET\n")
		y -= 16
		if y < 60 {
			break
		}
	}
	content := sb.String()

	objects := [][]byte{
		[]byte("<< /Type /Catalog /Pages 2 0 R >>"),
		[]byte("<< /Type /Pages /Kids [3 0 R] /Count 1 >>"),
		[]byte("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>"),
		[]byte("<< /Length " + strconv.Itoa(len(content)) + " >>\nstream\n" + content + "\nendstream"),
		[]byte("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"),
	}

	var buf bytes.Buffer
	buf.WriteString("%PDF-1.4\n")
	offsets := []int{}
	for i, obj := range objects {
		offsets = append(offsets, buf.Len())
		fmt.Fprintf(&buf, "%d 0 obj\n", i+1)
		buf.Write(obj)
		buf.WriteString("\nendobj\n")
	}
	xrefStart := buf.Len()
	fmt.Fprintf(&buf, "xref\n0 %d\n", len(objects)+1)
	buf.WriteString("0000000000 65535 f \n")
	for _, off := range offsets {
		fmt.Fprintf(&buf, "%010d 00000 n \n", off)
	}
	fmt.Fprintf(&buf, "trailer\n<< /Size %d /Root 1 0 R >>\n", len(objects)+1)
	fmt.Fprintf(&buf, "startxref\n%d\n%%%%EOF\n", xrefStart)
	return buf.Bytes()
}

func pdfNum(y float64) string {
	return strconv.FormatFloat(y, 'f', 1, 64)
}

func pdfEscape(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "(", "\\(")
	s = strings.ReplaceAll(s, ")", "\\)")
	return s
}
