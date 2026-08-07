package journey

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestSimulateBuildsFiveStepGraph(t *testing.T) {
	g, err := Simulate("ghost-prod-db-read-a7f3c2")
	if err != nil {
		t.Fatalf("Simulate: %v", err)
	}
	if len(g.Nodes) != 5 {
		t.Fatalf("expected 5 nodes, got %d", len(g.Nodes))
	}
	if len(g.Edges) != 4 {
		t.Fatalf("expected 4 edges, got %d", len(g.Edges))
	}
	if g.GhostUsername != "ghost-prod-db-read-a7f3c2" {
		t.Fatalf("username mismatch: %s", g.GhostUsername)
	}
	if g.Nodes[0].FQN() != "sts:GetCallerIdentity" {
		t.Fatalf("first step mismatch: %s", g.Nodes[0].FQN())
	}
	if g.Nodes[3].Severity != "data-access" {
		t.Fatalf("expected data-access step, got %s", g.Nodes[3].Severity)
	}
}

func TestToMermaidLinksNodes(t *testing.T) {
	g, _ := Simulate("ghost-prod")
	m := ToMermaid(g)
	if !strings.HasPrefix(m, "graph TD\n") {
		t.Fatalf("expected graph TD prefix, got %q", m)
	}
	if !strings.Contains(m, "N0 --> N1") {
		t.Fatalf("expected edge N0 --> N1, got %q", m)
	}
	if !strings.Contains(m, "style N3 fill:#ff9999") {
		t.Fatalf("expected styled data-access node, got %q", m)
	}
}

func TestRiskScoreAndLabel(t *testing.T) {
	g, _ := Simulate("ghost-prod")
	score := RiskScore(g)
	if score < 7 || score > 10 {
		t.Fatalf("expected critical-ish score, got %d", score)
	}
	if RiskLabel(score) == "Low" {
		t.Fatalf("expected non-low label for %d", score)
	}
	if utf8.RuneCountInString(RiskBar(score)) != 5 {
		t.Fatalf("risk bar must be 5 segments, got %q", RiskBar(score))
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	g, _ := Simulate("ghost-prod")
	g.StartTime = time.Now().UTC()
	g.EndTime = g.StartTime.Add(28 * time.Second)
	g.Duration = 28 * time.Second

	path := t.TempDir() + "/journey.json"
	if err := Save(g, path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got.Nodes) != len(g.Nodes) || got.GhostUsername != g.GhostUsername {
		t.Fatalf("round trip mismatch: %+v", got)
	}
	if got.Duration != 28*time.Second {
		t.Fatalf("duration mismatch: %s", got.Duration)
	}
}

func TestMitreTechnique(t *testing.T) {
	if got := (AttackNode{Service: "s3", Action: "GetObject"}).MitreTechnique(); got == "—" {
		t.Fatal("expected a MITRE mapping for s3:GetObject")
	}
	if got := (AttackNode{Service: "kms", Action: "ListKeys"}).MitreTechnique(); got != "—" {
		t.Fatalf("expected fallback, got %q", got)
	}
}
