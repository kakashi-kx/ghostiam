// Command lambda is the detection engine. It runs as an AWS Lambda function
// triggered by EventBridge on CloudTrail activity from a ghost IAM user, and
// posts a rich Slack alert via Block Kit.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/slack-go/slack"
)

// cloudtrailEvent captures the fields of a CloudTrail event that GhostIam
// cares about. The EventBridge rule delivers the raw CloudTrail event as
// JSON in event.Detail.
type cloudtrailEvent struct {
	EventVersion string `json:"eventVersion"`
	UserIdentity struct {
		Type        string `json:"type"`
		PrincipalID string `json:"principalId"`
		Arn         string `json:"arn"`
		AccountID   string `json:"accountId"`
		UserName    string `json:"userName"`
	} `json:"userIdentity"`
	EventTime   string `json:"eventTime"`
	EventSource string `json:"eventSource"`
	EventName   string `json:"eventName"`
	AwsRegion   string `json:"awsRegion"`
	SourceIP    string `json:"sourceIPAddress"`
	UserAgent   string `json:"userAgent"`
	RequestID   string `json:"requestID"`
	EventID     string `json:"eventID"`
}

func main() {
	lambda.Start(handleRequest)
}

// handleRequest parses a CloudTrail event, filters for ghost user activity,
// and posts an alert to Slack.
func handleRequest(ctx context.Context, event events.CloudWatchEvent) error {
	ct := cloudtrailEvent{}
	if err := json.Unmarshal(event.Detail, &ct); err != nil {
		log.Printf("detect: failed to parse CloudTrail event: %v", err)
		return nil
	}

	username := usernameFromArn(ct.UserIdentity.Arn)
	if username == "" || !strings.HasPrefix(username, "ghost-") || ct.UserIdentity.Type == "AWSAccount" {
		log.Printf("detect: ignoring non-ghost activity (user=%q, type=%q)", username, ct.UserIdentity.Type)
		return nil
	}

	webhookURL := os.Getenv("SLACK_WEBHOOK_URL")
	if webhookURL == "" {
		log.Printf("detect: SLACK_WEBHOOK_URL is not set, skipping alert for %s", username)
		return nil
	}

	msg := buildSlackMessage(ct, username)
	if err := slack.PostWebhook(webhookURL, &msg); err != nil {
		log.Printf("detect: failed to post Slack alert for %s: %v", username, err)
		return nil
	}

	log.Printf("detect: alert sent for ghost user %s (%s.%s)", username, ct.EventSource, ct.EventName)
	return nil
}

// buildSlackMessage assembles the Block Kit message describing ghost activity.
func buildSlackMessage(ct cloudtrailEvent, username string) slack.WebhookMessage {
	ts := formatTimestamp(ct.EventTime)
	apiCall := fmt.Sprintf("%s.%s", ct.EventSource, ct.EventName)

	body := fmt.Sprintf(
		"*Ghost User:* `%s`\n*API Call:* `%s`\n*Source IP:* `%s`\n*User Agent:* `%s`\n*Region:* `%s`\n*Time:* `%s`\n*Request ID:* `%s`",
		username,
		apiCall,
		ct.SourceIP,
		ct.UserAgent,
		ct.AwsRegion,
		ts,
		ct.RequestID,
	)

	return slack.WebhookMessage{
		Blocks: &slack.Blocks{
			BlockSet: []slack.Block{
				slack.NewHeaderBlock(slack.NewTextBlockObject(
					slack.MarkdownType,
					":ghost: GHOST USER ACTIVATED",
					false,
					false,
				)),
				slack.NewSectionBlock(
					slack.NewTextBlockObject(slack.MarkdownType, body, false, false),
					nil,
					nil,
				),
				slack.NewDividerBlock(),
				slack.NewContextBlock(
					"",
					slack.NewTextBlockObject(
						slack.MarkdownType,
						"GhostIam — deploy decoys, detect recon. github.com/kakashi-kx/ghostiam",
						false,
						false,
					),
				),
			},
		},
	}
}

// usernameFromArn extracts the IAM username from a user ARN such as
// arn:aws:iam::123456789012:user/ghost-prod-db-read-a7f3.
func usernameFromArn(arn string) string {
	parts := strings.Split(arn, "/")
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1]
}

// formatTimestamp normalizes an event timestamp to a readable UTC string,
// falling back to the raw value when parsing fails.
func formatTimestamp(ts string) string {
	if ts == "" {
		return ts
	}
	if parsed, err := time.Parse(time.RFC3339, ts); err == nil {
		return parsed.UTC().Format("2006-01-02 15:04:05 UTC")
	}
	return ts
}
