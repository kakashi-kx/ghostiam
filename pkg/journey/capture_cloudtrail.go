package journey

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
)

// cloudTrailEventJSON is the subset of the raw CloudTrail record we need.
type cloudTrailEventJSON struct {
	EventSource      string `json:"eventSource"`
	SourceIPAddress  string `json:"sourceIPAddress"`
	AwsService       string `json:"awsService"`
	EventName        string `json:"eventName"`
	UserAgent        string `json:"userAgent"`
}

// captureCloudTrail looks up CloudTrail events for the ghost user over the
// last 60 seconds and builds an attack graph from them. It returns an error
// when AWS credentials are unavailable or no events were recorded, letting
// Capture fall back to the local simulator.
func captureCloudTrail(ctx context.Context, ghostUsername string) (*AttackGraph, error) {
	awsCfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}
	client := cloudtrail.NewFromConfig(awsCfg)

	end := time.Now().UTC()
	start := end.Add(-60 * time.Second)

	out, err := client.LookupEvents(ctx, &cloudtrail.LookupEventsInput{
		StartTime: aws.Time(start),
		EndTime:   aws.Time(end),
		LookupAttributes: []types.LookupAttribute{
			{
				AttributeKey:   types.LookupAttributeKeyUsername,
				AttributeValue: aws.String(ghostUsername),
			},
		},
	})
	if err != nil {
		return nil, err
	}

	graph := &AttackGraph{GhostUsername: ghostUsername}
	for _, ev := range out.Events {
		raw := parseCloudTrailEvent(aws.ToString(ev.CloudTrailEvent))
		service := raw.AwsService
		if service == "" {
			service = eventService(raw.EventSource)
		}
		action := raw.EventName
		if action == "" {
			action = aws.ToString(ev.EventName)
		}
		if service == "" || action == "" {
			continue
		}

		node := AttackNode{
			ID:       aws.ToString(ev.EventId),
			Service:  service,
			Action:   action,
			SourceIP: raw.SourceIPAddress,
			Severity: severityFor(service, action),
		}
		if ev.EventTime != nil {
			node.Timestamp = *ev.EventTime
			if graph.StartTime.IsZero() || node.Timestamp.Before(graph.StartTime) {
				graph.StartTime = node.Timestamp
			}
			if node.Timestamp.After(graph.EndTime) {
				graph.EndTime = node.Timestamp
			}
		}
		graph.Nodes = append(graph.Nodes, node)
	}

	if len(graph.Nodes) == 0 {
		return nil, fmt.Errorf("cloudtrail: no events recorded for %s in the last 60s", ghostUsername)
	}
	for i := 1; i < len(graph.Nodes); i++ {
		graph.Edges = append(graph.Edges, AttackEdge{From: graph.Nodes[i-1].ID, To: graph.Nodes[i].ID})
	}
	if !graph.StartTime.IsZero() && !graph.EndTime.IsZero() {
		graph.Duration = graph.EndTime.Sub(graph.StartTime)
	}
	return graph, nil
}

// parseCloudTrailEvent decodes the raw CloudTrail record embedded in a lookup
// event. Unknown JSON is tolerated and returns a zero value.
func parseCloudTrailEvent(raw string) cloudTrailEventJSON {
	var out cloudTrailEventJSON
	if raw == "" {
		return out
	}
	_ = json.Unmarshal([]byte(raw), &out)
	return out
}

// eventService maps a CloudTrail eventSource like "s3.amazonaws.com" to the
// short service name used in journey labels.
func eventService(eventSource string) string {
	parts := strings.Split(eventSource, ".")
	if len(parts) >= 2 {
		return parts[0]
	}
	return eventSource
}

// severityFor maps a CloudTrail service/action to a journey severity label.
func severityFor(service, action string) string {
	switch service + ":" + action {
	case "s3:GetObject", "s3:GetObjectAcl", "s3:GetBucketAcl":
		return "data-access"
	case "iam:CreateAccessKey", "iam:AttachUserPolicy", "iam:AttachRolePolicy", "iam:CreateRole":
		return "privilege-escalation"
	case "ec2:RunInstances":
		return "lateral-movement"
	default:
		return "recon"
	}
}
