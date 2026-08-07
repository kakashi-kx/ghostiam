package journey

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// RiskScore scores an attack graph from 1 to 10 based on the severity of the
// actions it contains.
func RiskScore(g *AttackGraph) int {
	score := 5
	for _, n := range g.Nodes {
		switch n.Severity {
		case "exfiltration":
			score += 3
		case "data-access":
			score += 2
		case "lateral-movement":
			score += 2
		case "privilege-escalation":
			score += 1
		}
	}
	if score > 10 {
		score = 10
	}
	if score < 1 {
		score = 1
	}
	return score
}

// RiskLabel maps a risk score to a severity label.
func RiskLabel(score int) string {
	switch {
	case score >= 9:
		return "Critical"
	case score >= 7:
		return "High"
	case score >= 4:
		return "Medium"
	default:
		return "Low"
	}
}

// RiskBar renders a 5-segment filled risk bar.
func RiskBar(score int) string {
	filled := score / 2
	if filled > 5 {
		filled = 5
	}
	return strings.Repeat("▓", filled) + strings.Repeat("░", 5-filled)
}

// Save persists an attack graph to a JSON file.
func Save(g *AttackGraph, path string) error {
	data, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		return fmt.Errorf("journey: marshal: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("journey: write %s: %w", path, err)
	}
	return nil
}

// Load reads an attack graph from a JSON file.
func Load(path string) (*AttackGraph, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("journey: read %s: %w", path, err)
	}
	g := &AttackGraph{}
	if err := json.Unmarshal(data, g); err != nil {
		return nil, fmt.Errorf("journey: parse %s: %w", path, err)
	}
	return g, nil
}
