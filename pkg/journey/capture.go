package journey

import (
	"context"
	"fmt"
	"time"
)

// Capture returns the attacker journey for a ghost user. It first attempts a
// live CloudTrail lookup; when AWS credentials are unavailable or no events
// are found, it falls back to a realistic local simulation so the demo always
// works.
func Capture(ctx context.Context, ghostUsername string) (*AttackGraph, error) {
	if graph, err := captureCloudTrail(ctx, ghostUsername); err == nil && len(graph.Nodes) > 0 {
		return graph, nil
	}
	return Simulate(ghostUsername)
}

// Simulate generates a realistic 5-step attacker journey against a ghost
// user: identity discovery, permission enumeration, data discovery, a data
// access attempt, and compute discovery for lateral movement.
func Simulate(ghostUsername string) (*AttackGraph, error) {
	start := time.Now().UTC()
	steps := []struct {
		service, action, severity, ip string
	}{
		{"sts", "GetCallerIdentity", "recon", "203.0.113.42"},
		{"iam", "ListRoles", "privilege-escalation", "203.0.113.42"},
		{"s3", "ListBuckets", "discovery", "203.0.113.42"},
		{"s3", "GetObject", "data-access", "198.51.100.7"},
		{"ec2", "DescribeInstances", "lateral-movement", "198.51.100.7"},
	}

	graph := &AttackGraph{
		GhostUsername: ghostUsername,
		StartTime:     start,
	}

	for i, s := range steps {
		node := AttackNode{
			ID:        fmt.Sprintf("N%d", i),
			Service:   s.service,
			Action:    s.action,
			SourceIP:  s.ip,
			Timestamp: start.Add(time.Duration(i) * 7 * time.Second),
			Severity:  s.severity,
		}
		graph.Nodes = append(graph.Nodes, node)
		if i > 0 {
			graph.Edges = append(graph.Edges, AttackEdge{From: graph.Nodes[i-1].ID, To: node.ID})
		}
	}

	graph.EndTime = start.Add(time.Duration(len(steps)-1) * 7 * time.Second)
	graph.Duration = graph.EndTime.Sub(graph.StartTime)
	return graph, nil
}
