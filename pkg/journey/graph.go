// Package journey captures, graphs, and replays attacker journeys. When a
// ghost user fires, its API calls are turned into a directed attack graph that
// is visualized as a Mermaid diagram and posted to Slack with MITRE ATT&CK
// technique mappings.
package journey

import "time"

// AttackNode is a single attacker API call captured during a journey.
type AttackNode struct {
	// ID is the event identifier (eventID for CloudTrail events).
	ID string `json:"id"`
	// Service is the AWS service, e.g. s3, iam, ec2, sts.
	Service string `json:"service"`
	// Action is the API action, e.g. ListBuckets, GetCallerIdentity.
	Action string `json:"action"`
	// SourceIP is the attacker's source IP.
	SourceIP string `json:"sourceIp"`
	// Timestamp is when the call happened.
	Timestamp time.Time `json:"timestamp"`
	// Severity is one of recon, privilege-escalation, discovery, data-access,
	// lateral-movement, or exfiltration.
	Severity string `json:"severity"`
}

// AttackEdge is a directed edge between two attack nodes.
type AttackEdge struct {
	// From is the source node ID.
	From string `json:"from"`
	// To is the destination node ID.
	To string `json:"to"`
}

// AttackGraph is the directed graph of an attacker's actions against a ghost
// user.
type AttackGraph struct {
	// GhostUsername is the decoy identity the attacker used.
	GhostUsername string `json:"ghostUsername"`
	// Nodes are the API calls in the journey.
	Nodes []AttackNode `json:"nodes"`
	// Edges connect the calls in sequence.
	Edges []AttackEdge `json:"edges"`
	// StartTime is the first call timestamp.
	StartTime time.Time `json:"startTime"`
	// EndTime is the last call timestamp.
	EndTime time.Time `json:"endTime"`
	// Duration is the journey length.
	Duration time.Duration `json:"duration"`
}

// mitreMapping maps "service:action" to the MITRE ATT&CK technique it maps to.
var mitreMapping = map[string]string{
	"sts:GetCallerIdentity": "T1087.004 — Account Discovery",
	"iam:ListUsers":         "T1087.004 — Account Discovery",
	"iam:ListRoles":         "T1069.002 — Permission Groups Discovery",
	"s3:ListBuckets":        "T1526 — Cloud Service Discovery",
	"s3:GetObject":          "T1530 — Data from Cloud Storage",
	"ec2:DescribeInstances": "T1580 — Cloud Infrastructure Discovery",
	"iam:CreateAccessKey":   "T1098.001 — Additional Cloud Credentials",
}

// MitreTechnique returns the MITRE ATT&CK technique for the node's action.
func (n AttackNode) MitreTechnique() string {
	if t, ok := mitreMapping[n.Service+":"+n.Action]; ok {
		return t
	}
	return "—"
}

// FQN returns the fully-qualified action name, e.g. "s3:ListBuckets".
func (n AttackNode) FQN() string {
	return n.Service + ":" + n.Action
}
