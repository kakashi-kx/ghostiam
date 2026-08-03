// Command ghostiam is the GhostIam CLI. It deploys decoy IAM users locally in
// a JSON store or in AWS, and simulates attacker activity to trigger the
// detection pipeline. The --local flag selects the mode: no guessing, no
// fallback.
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/kakashi-kx/ghostiam/pkg/deploy"
	"github.com/kakashi-kx/ghostiam/pkg/store"
	"github.com/kakashi-kx/ghostiam/pkg/templates"
	"github.com/slack-go/slack"
	"github.com/spf13/cobra"
)

const localStoreFile = "ghosts.json"

var rootCmd = &cobra.Command{
	Use:   "ghostiam",
	Short: "GhostIam — Deploy decoy IAM users locally or in AWS. Catch attacker recon instantly.",
	Long: `GhostIam deploys decoy IAM users that look like privileged identities.

Two modes, chosen with --local. No guessing, no fallback:

  LOCAL MODE  (--local)
    Ghost users are stored in ghosts.json and alerts are posted directly to
    Slack. Zero AWS dependencies. Great for demos and development.

  AWS MODE    (no flag)
    Ghost users are real IAM identities in your AWS account, tagged with
    GhostIam=true. Any API call they make is captured by CloudTrail, filtered
    by EventBridge, and alerted on by the ghostiam-detector Lambda.

Run "ghostiam <command> --help" for details on each command.`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

var deployCmd = &cobra.Command{
	Use:   "deploy",
	Short: "Deploy ghost IAM users locally or into your AWS account",
	Long: `Deploy ghost IAM users named ghost-{prefix}-{role}-{random}.

With --local, users are written to ghosts.json and no AWS API is touched.
Without --local, users are created in AWS IAM, tagged GhostIam=true, and carry
a decoy policy that looks valuable but grants only read-only permissions.`,
	RunE: runDeploy,
}

var simulateCmd = &cobra.Command{
	Use:   "simulate",
	Short: "Simulate attacker activity to trigger detection",
	Long: `Simulate attacker activity to trigger the detection pipeline.

With --local, the ghost user is looked up in ghosts.json and a mock
CloudTrail-style alert is posted directly to Slack. No AWS required.

Without --local, this command uses YOUR current AWS credentials to make a
harmless sts:GetCallerIdentity call against AWS, documenting what an attacker
using ghost credentials would trigger.`,
	RunE: runSimulate,
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show deployed ghost users",
	Long: `Show deployed ghost users.

With --local, reads ghosts.json. Without --local, lists IAM users tagged
GhostIam=true in your AWS account.`,
	RunE: runStatus,
}

var cleanCmd = &cobra.Command{
	Use:   "clean",
	Short: "Remove deployed ghost users",
	Long: `Remove deployed ghost users.

  ghostiam clean --local   deletes ghosts.json
  ghostiam clean --all     deletes every ghost IAM user from AWS (asks first)`,
	RunE: runClean,
}

func init() {
	deployCmd.Flags().IntP("count", "c", 10, "Number of ghost users to create")
	deployCmd.Flags().StringP("prefix", "p", "prod", "Name prefix for ghost users (e.g. ghost-prod-...)")
	deployCmd.Flags().StringP("region", "r", "us-east-1", "AWS region (AWS mode only)")
	deployCmd.Flags().Bool("with-keys", false, "Generate access keys for each ghost user (AWS mode only)")
	deployCmd.Flags().BoolP("local", "l", false, "Use local JSON store instead of AWS IAM")

	simulateCmd.Flags().StringP("username", "u", "", "Ghost username to simulate activity with")
	simulateCmd.Flags().StringP("region", "r", "us-east-1", "AWS region (AWS mode only)")
	simulateCmd.Flags().BoolP("local", "l", false, "Look up the ghost user in the local JSON store")
	_ = simulateCmd.MarkFlagRequired("username")

	statusCmd.Flags().BoolP("local", "l", false, "Show ghosts from the local JSON store")

	cleanCmd.Flags().Bool("local", false, "Delete ghosts.json")
	cleanCmd.Flags().Bool("all", false, "Delete all ghost IAM users from AWS (asks first)")

	rootCmd.AddCommand(deployCmd, simulateCmd, statusCmd, cleanCmd)
}

// ---------------------------------------------------------------------------
// deploy
// ---------------------------------------------------------------------------

func runDeploy(cmd *cobra.Command, _ []string) error {
	count, _ := cmd.Flags().GetInt("count")
	prefix, _ := cmd.Flags().GetString("prefix")
	region, _ := cmd.Flags().GetString("region")
	withKeys, _ := cmd.Flags().GetBool("with-keys")
	local, _ := cmd.Flags().GetBool("local")

	if local {
		return deployLocal(count, prefix)
	}
	return deployAWS(count, prefix, region, withKeys)
}

// deployLocal writes ghost users to the local JSON store. Never touches AWS.
func deployLocal(count int, prefix string) error {
	policies := templates.GetDecoyPolicies()
	if len(policies) == 0 {
		return fmt.Errorf("no decoy policies registered")
	}
	if prefix == "" {
		prefix = "prod"
	}

	s := store.NewLocalStore(localStoreFile)
	now := time.Now().UTC()

	for i := 0; i < count; i++ {
		policy := policies[i%len(policies)]
		username := fmt.Sprintf("ghost-%s-%s-%s", prefix, shortName(policy.Name), randomHex(6))

		record := store.GhostRecord{
			Username:   username,
			PolicyName: policy.Name,
			CreatedAt:  now,
		}
		if err := s.AddGhost(record); err != nil {
			return fmt.Errorf("add ghost %s: %w", username, err)
		}
		fmt.Printf("[%d] Created: %s (policy: %s)\n", i+1, username, policy.Name)
	}

	abs, err := filepath.Abs(localStoreFile)
	if err != nil {
		abs = localStoreFile
	}
	fmt.Printf("\nDeployed %d ghost users locally.\n", count)
	fmt.Printf("  Store: %s\n", abs)
	return nil
}

// deployAWS creates real ghost IAM users in AWS. Never touches the local store.
func deployAWS(count int, prefix, region string, withKeys bool) error {
	if prefix == "" {
		prefix = "prod"
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

	account := ""
	if awsCfg, cfgErr := config.LoadDefaultConfig(context.Background(), config.WithRegion(region)); cfgErr == nil {
		if ident, identErr := sts.NewFromConfig(awsCfg).GetCallerIdentity(context.Background(), &sts.GetCallerIdentityInput{}); identErr == nil {
			account = aws.ToString(ident.Account)
		}
	}

	fmt.Printf("GhostIam deploy summary:\n")
	if account != "" {
		fmt.Printf("  AWS account: %s\n", account)
	}
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

// ---------------------------------------------------------------------------
// simulate
// ---------------------------------------------------------------------------

func runSimulate(cmd *cobra.Command, _ []string) error {
	username, _ := cmd.Flags().GetString("username")
	region, _ := cmd.Flags().GetString("region")
	local, _ := cmd.Flags().GetBool("local")

	if local {
		return simulateLocal(username)
	}
	return simulateAWS(username, region)
}

// simulateLocal looks up a ghost in ghosts.json and posts a mock alert. Never
// touches AWS.
func simulateLocal(username string) error {
	s := store.NewLocalStore(localStoreFile)

	record, err := s.FindGhost(username)
	if err != nil {
		return fmt.Errorf("ghost user %q not found in local store", username)
	}

	fmt.Printf("Found ghost user in local store:\n")
	fmt.Printf("  Username:  %s\n", record.Username)
	fmt.Printf("  Policy:    %s\n", record.PolicyName)
	fmt.Printf("  CreatedAt: %s\n", record.CreatedAt.Format(time.RFC3339))
	fmt.Println()

	sendLocalAlert(record.Username, record.PolicyName)
	return nil
}

// simulateAWS makes a harmless sts:GetCallerIdentity call against AWS. Alerts
// are handled by the EventBridge + Lambda pipeline. Never touches the local
// store.
func simulateAWS(username, region string) error {
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
// Lambda's Block Kit format. It never returns an error for a missing webhook:
// it prints a warning and continues, so local demos work without Slack.
func sendLocalAlert(username string, policyName string) {
	webhookURL := os.Getenv("SLACK_WEBHOOK_URL")
	if webhookURL == "" {
		fmt.Println("⚠️  SLACK_WEBHOOK_URL not set. Alert not sent.")
		fmt.Println("   Set it: export SLACK_WEBHOOK_URL=\"https://hooks.slack.com/services/...\"")
		return
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
		fmt.Printf("⚠️  Failed to send Slack alert: %v\n", err)
		return
	}
	fmt.Println("✅ Alert sent to Slack — check your #general channel")
}

// ---------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------

func runStatus(cmd *cobra.Command, _ []string) error {
	local, _ := cmd.Flags().GetBool("local")
	if local {
		return statusLocal()
	}
	return statusAWS()
}

// statusLocal prints the ghosts stored in ghosts.json.
func statusLocal() error {
	s := store.NewLocalStore(localStoreFile)

	records, err := s.ListGhosts()
	if err != nil {
		return err
	}

	abs, err := filepath.Abs(localStoreFile)
	if err != nil {
		abs = localStoreFile
	}

	fmt.Println("👻 GhostIam Status (local)")
	fmt.Println()
	fmt.Printf("  Ghost users deployed: %d\n", len(records))
	fmt.Printf("  Store: %s\n", abs)
	fmt.Println()
	fmt.Println("  USERS:")
	for _, r := range records {
		fmt.Printf("  %-32s %-28s %s\n", r.Username, r.PolicyName, r.CreatedAt.Format(time.RFC3339))
	}
	return nil
}

// statusAWS lists IAM users in AWS carrying the GhostIam=true tag.
func statusAWS() error {
	ctx := context.Background()
	client := iam.NewFromConfig(mustAWSConfig(ctx, "us-east-1"))

	ghosts := []types.User{}
	paginator := iam.NewListUsersPaginator(client, &iam.ListUsersInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("iam:ListUsers: %w", err)
		}
		for _, user := range page.Users {
			if isGhostUser(ctx, client, aws.ToString(user.UserName)) {
				ghosts = append(ghosts, user)
			}
		}
	}

	fmt.Println("👻 GhostIam Status (AWS)")
	fmt.Println()
	fmt.Printf("  Ghost users deployed: %d\n", len(ghosts))
	fmt.Println()
	fmt.Println("  USERS:")
	for _, u := range ghosts {
		fmt.Printf("  %-32s %s\n", aws.ToString(u.UserName), aws.ToString(u.Arn))
	}
	return nil
}

// ---------------------------------------------------------------------------
// clean
// ---------------------------------------------------------------------------

func runClean(cmd *cobra.Command, _ []string) error {
	local, _ := cmd.Flags().GetBool("local")
	all, _ := cmd.Flags().GetBool("all")

	switch {
	case local:
		return cleanLocal()
	case all:
		return cleanAWS()
	default:
		return fmt.Errorf("specify --local (delete ghosts.json) or --all (delete AWS ghost users)")
	}
}

// cleanLocal deletes ghosts.json.
func cleanLocal() error {
	if _, err := os.Stat(localStoreFile); os.IsNotExist(err) {
		fmt.Printf("No local store found (%s). Nothing to clean.\n", localStoreFile)
		return nil
	}
	if err := os.Remove(localStoreFile); err != nil {
		return fmt.Errorf("remove %s: %w", localStoreFile, err)
	}
	fmt.Printf("Deleted %s.\n", localStoreFile)
	return nil
}

// cleanAWS deletes every IAM user tagged GhostIam=true after confirmation.
func cleanAWS() error {
	ctx := context.Background()
	client := iam.NewFromConfig(mustAWSConfig(ctx, "us-east-1"))

	ghosts, err := listGhostUsers(ctx, client)
	if err != nil {
		return err
	}

	fmt.Println("👻 GhostIam clean (AWS)")
	fmt.Println()
	if len(ghosts) == 0 {
		fmt.Println("  No ghost users found. Nothing to clean.")
		return nil
	}
	fmt.Printf("  Found %d ghost user(s):\n", len(ghosts))
	for _, u := range ghosts {
		fmt.Printf("    - %s\n", aws.ToString(u.UserName))
	}
	fmt.Println()

	if !confirm("  Delete these users and all their access keys/policies? [y/N] ") {
		fmt.Println("  Aborted.")
		return nil
	}

	for _, u := range ghosts {
		username := aws.ToString(u.UserName)
		if err := deleteGhostUser(ctx, client, username); err != nil {
			log.Printf("clean: failed to delete %s: %v", username, err)
			continue
		}
		fmt.Printf("  Deleted %s\n", username)
	}
	return nil
}

// confirm reads a y/N answer from stdin.
func confirm(prompt string) bool {
	fmt.Print(prompt)
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		return false
	}
	answer := strings.ToLower(strings.TrimSpace(scanner.Text()))
	return answer == "y" || answer == "yes"
}

// ---------------------------------------------------------------------------
// AWS helpers
// ---------------------------------------------------------------------------

// mustAWSConfig loads the default AWS config, exiting with a clear message on
// failure.
func mustAWSConfig(ctx context.Context, region string) aws.Config {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		fmt.Printf("Failed to load AWS config: %v\n", err)
		fmt.Println("Check your AWS credentials (env vars, ~/.aws/credentials, or IAM role).")
		os.Exit(1)
	}
	return cfg
}

// isGhostUser reports whether the named IAM user carries the GhostIam=true tag.
func isGhostUser(ctx context.Context, client *iam.Client, username string) bool {
	tags, err := client.ListUserTags(ctx, &iam.ListUserTagsInput{UserName: aws.String(username)})
	if err != nil {
		return false
	}
	for _, t := range tags.Tags {
		if aws.ToString(t.Key) == "GhostIam" && aws.ToString(t.Value) == "true" {
			return true
		}
	}
	return false
}

// listGhostUsers returns every IAM user tagged GhostIam=true.
func listGhostUsers(ctx context.Context, client *iam.Client) ([]types.User, error) {
	ghosts := []types.User{}
	paginator := iam.NewListUsersPaginator(client, &iam.ListUsersInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("iam:ListUsers: %w", err)
		}
		for _, user := range page.Users {
			if isGhostUser(ctx, client, aws.ToString(user.UserName)) {
				ghosts = append(ghosts, user)
			}
		}
	}
	return ghosts, nil
}

// deleteGhostUser removes a user and its inline policies and access keys.
func deleteGhostUser(ctx context.Context, client *iam.Client, username string) error {
	// Delete inline policies.
	pols, err := client.ListUserPolicies(ctx, &iam.ListUserPoliciesInput{UserName: aws.String(username)})
	if err != nil {
		return fmt.Errorf("list policies for %s: %w", username, err)
	}
	for _, p := range pols.PolicyNames {
		if _, err := client.DeleteUserPolicy(ctx, &iam.DeleteUserPolicyInput{
			UserName:   aws.String(username),
			PolicyName: aws.String(p),
		}); err != nil {
			return fmt.Errorf("delete policy %s for %s: %w", p, username, err)
		}
	}

	// Delete access keys.
	keys, err := client.ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: aws.String(username)})
	if err != nil {
		return fmt.Errorf("list access keys for %s: %w", username, err)
	}
	for _, k := range keys.AccessKeyMetadata {
		if _, err := client.DeleteAccessKey(ctx, &iam.DeleteAccessKeyInput{
			UserName:    aws.String(username),
			AccessKeyId: k.AccessKeyId,
		}); err != nil {
			return fmt.Errorf("delete access key for %s: %w", username, err)
		}
	}

	// Delete the user.
	if _, err := client.DeleteUser(ctx, &iam.DeleteUserInput{UserName: aws.String(username)}); err != nil {
		return fmt.Errorf("delete user %s: %w", username, err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// misc helpers
// ---------------------------------------------------------------------------

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
