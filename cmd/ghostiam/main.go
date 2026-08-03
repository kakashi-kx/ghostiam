// Command ghostiam is the GhostIam CLI. It deploys decoy IAM users into an AWS
// account (or a local JSON store) and simulates attacker activity to trigger
// the detection pipeline.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/kakashi-kx/ghostiam/pkg/deploy"
	"github.com/kakashi-kx/ghostiam/pkg/store"
	"github.com/kakashi-kx/ghostiam/pkg/templates"
	"github.com/slack-go/slack"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:           "ghostiam",
	Short:         "GhostIam — Deploy decoy IAM users. Catch attacker recon instantly.",
	SilenceUsage:  true,
	SilenceErrors: true,
}

var deployCmd = &cobra.Command{
	Use:   "deploy",
	Short: "Deploy ghost IAM users into your AWS account",
	Long: `Deploy ghost IAM users into your AWS account.

Creates N decoy IAM users named ghost-{prefix}-{role}-{random}. Each user is
tagged with GhostIam=true and carries a decoy policy that looks valuable to an
attacker during reconnaissance but grants only read-only permissions. Any API
call made by these users triggers a Slack alert via the detection pipeline.

With --local, users are written to a local ghosts.json file instead of AWS
IAM, which is useful for demos and development.`,
	RunE: runDeploy,
}

var simulateCmd = &cobra.Command{
	Use:   "simulate",
	Short: "Simulate attacker activity using ghost credentials to trigger detection",
	Long: `Simulate attacker activity to trigger the detection pipeline.

In AWS mode this command uses YOUR current AWS credentials to make a harmless
API call (sts:GetCallerIdentity). The EventBridge rule detects calls made by
ghost users, so for a full end-to-end demo you would run this with the ghost
user's access keys configured.

With --local, ghost users are looked up in ghosts.json and a mock CloudTrail
alert is sent directly to Slack — no AWS required.`,
	RunE: runSimulate,
}

func init() {
	deployCmd.Flags().IntP("count", "c", 10, "Number of ghost users to create")
	deployCmd.Flags().StringP("prefix", "p", "prod", "Name prefix for ghost users (e.g. ghost-prod-...)")
	deployCmd.Flags().StringP("region", "r", "us-east-1", "AWS region")
	deployCmd.Flags().Bool("with-keys", false, "Generate access keys for each ghost user")
	deployCmd.Flags().BoolP("local", "l", false, "Use local JSON store instead of AWS IAM")

	simulateCmd.Flags().StringP("username", "u", "", "Ghost username to simulate activity with")
	simulateCmd.Flags().StringP("region", "r", "us-east-1", "AWS region")
	simulateCmd.Flags().BoolP("local", "l", false, "Look up the ghost user in the local JSON store")
	_ = simulateCmd.MarkFlagRequired("username")

	rootCmd.AddCommand(deployCmd, simulateCmd)
}

func runDeploy(cmd *cobra.Command, _ []string) error {
	count, _ := cmd.Flags().GetInt("count")
	prefix, _ := cmd.Flags().GetString("prefix")
	region, _ := cmd.Flags().GetString("region")
	withKeys, _ := cmd.Flags().GetBool("with-keys")
	local, _ := cmd.Flags().GetBool("local")

	if local {
		return deployLocally(count, prefix)
	}

	cfg := deploy.DeployConfig{
		Count:    count,
		Prefix:   prefix,
		Region:   region,
		WithKeys: withKeys,
	}

	users, err := deploy.DeployGhostUsers(context.Background(), cfg)
	if err != nil {
		log.Printf("deploy completed with errors: %v", err)
	}

	fmt.Printf("GhostIam deploy summary:\n")
	fmt.Printf("  Total created: %d\n", len(users))
	fmt.Printf("  Access keys generated: %s\n", yesNo(withKeys))
	fmt.Println()
	for _, u := range users {
		fmt.Printf("  - %s  [%s]\n", u.Username, u.PolicyAttached)
	}

	if withKeys {
		fmt.Println()
		fmt.Println("  WARNING: access keys were generated for each ghost user.")
		fmt.Println("  Store them securely, or seed them in fake repos/leaks as bait.")
		fmt.Println("  Any use of these keys WILL trigger a Slack alert.")
	}
	return err
}

// deployLocally writes ghost users to the local JSON store instead of AWS IAM.
func deployLocally(count int, prefix string) error {
	policies := templates.GetDecoyPolicies()
	if len(policies) == 0 {
		return fmt.Errorf("no decoy policies registered")
	}
	if prefix == "" {
		prefix = "prod"
	}

	s := store.NewLocalStore("ghosts.json")

	for i := 0; i < count; i++ {
		policy := policies[i%len(policies)]
		username := fmt.Sprintf("ghost-%s-%s-%s", prefix, shortName(policy.Name), randomHex(6))

		record := store.GhostRecord{
			Username:   username,
			PolicyName: policy.Name,
			CreatedAt:  time.Now().UTC(),
		}
		if err := s.AddGhost(record); err != nil {
			return fmt.Errorf("add ghost %s: %w", username, err)
		}
		fmt.Printf("[%d] Created: %s (policy: %s)\n", i+1, username, policy.Name)
	}

	fmt.Printf("Deployed %d ghost users locally in ghosts.json\n", count)
	return nil
}

func runSimulate(cmd *cobra.Command, _ []string) error {
	username, _ := cmd.Flags().GetString("username")
	region, _ := cmd.Flags().GetString("region")
	local, _ := cmd.Flags().GetBool("local")

	if strings.HasPrefix(username, "ghost-") {
		s := store.NewLocalStore("ghosts.json")
		if record, err := s.FindGhost(username); err == nil {
			if err := sendLocalAlert(username, record.PolicyName); err != nil {
				return fmt.Errorf("send local alert: %w", err)
			}
			fmt.Printf("Alert sent to Slack for %s\n", username)
			return nil
		}
		if local {
			fmt.Println("Ghost user not found in local store")
			os.Exit(1)
		}
	}

	awsCfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion(region))
	if err != nil {
		return fmt.Errorf("load aws config: %w", err)
	}
	client := sts.NewFromConfig(awsCfg)

	out, err := client.GetCallerIdentity(context.Background(), &sts.GetCallerIdentityInput{})
	if err != nil {
		return fmt.Errorf("sts:GetCallerIdentity: %w", err)
	}

	fmt.Printf("Simulated activity as %s: sts:GetCallerIdentity — check Slack for alert\n", username)
	fmt.Printf("  Account ID: %s\n", aws.ToString(out.Account))
	fmt.Printf("  ARN:        %s\n", aws.ToString(out.Arn))
	fmt.Printf("  User ID:    %s\n", aws.ToString(out.UserId))
	return nil
}

// sendLocalAlert posts a mock CloudTrail-style alert to Slack, mirroring the
// Lambda's Block Kit format.
func sendLocalAlert(username string, policyName string) error {
	webhookURL := os.Getenv("SLACK_WEBHOOK_URL")
	if webhookURL == "" {
		return fmt.Errorf("SLACK_WEBHOOK_URL is not set")
	}

	body := fmt.Sprintf(
		"*Ghost User:* `%s`\n*Policy:* `%s`\n*Source:* `local simulation`\n*Timestamp:* `%s`",
		username,
		policyName,
		time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
	)

	msg := slack.WebhookMessage{
		Blocks: &slack.Blocks{
			BlockSet: []slack.Block{
				slack.NewHeaderBlock(slack.NewTextBlockObject(
					slack.MarkdownType,
					":ghost: GHOST USER ACTIVATED (LOCAL MODE)",
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

	if err := slack.PostWebhook(webhookURL, &msg); err != nil {
		return err
	}
	return nil
}

// shortName maps a policy template name to its short role label.
func shortName(name string) string {
	switch name {
	case "ProdDatabaseReadAccess":
		return "db-read"
	case "CloudInfrastructureViewer":
		return "infra-view"
	case "S3BackupOperator":
		return "s3-backup"
	case "IAMSecurityAuditor":
		return "iam-audit"
	case "CrossAccountAccessRole":
		return "xacct"
	default:
		return "ghost"
	}
}

// randomHex returns a hexadecimal string of n characters backed by crypto/rand.
func randomHex(n int) string {
	b := make([]byte, (n+1)/2)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("ghostiam: failed to read random bytes: %v", err))
	}
	return hex.EncodeToString(b)[:n]
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
