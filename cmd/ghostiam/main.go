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
	"github.com/kakashi-kx/ghostiam/pkg/dashboard"
	"github.com/kakashi-kx/ghostiam/pkg/deploy"
	"github.com/kakashi-kx/ghostiam/pkg/journey"
	"github.com/kakashi-kx/ghostiam/pkg/mesh"
	"github.com/kakashi-kx/ghostiam/pkg/seeder"
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

Commands:
  deploy    Deploy ghost users locally or in AWS
  simulate  Simulate attacker activity to trigger detection
  status    Show deployed ghost users
  clean     Remove deployed ghost users
  seed      Leak ghost access keys to realistic bait locations
  mesh      Correlated ghost identities across AWS + GitHub + Okta
  journey   Generate and visualize an attacker journey
  replay    Play back a saved attacker journey
  dashboard Serve the GhostIam web dashboard

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

var seedCmd = &cobra.Command{
	Use:   "seed [github|s3|pastebin|all]",
	Short: "Leak ghost access keys to realistic bait locations",
	Long: `Automatically "leak" ghost access keys to realistic bait locations so an
attacker who stumbles on them triggers detection:

  seed github     create a private repo, commit the keys, flip it public
  seed s3         public S3 bucket with config.json + backup.sql
  seed pastebin   local Pastebin-style leak (pastebin-sim.html)
  seed all        try every platform

Platforms that need credentials skip gracefully when the credential is missing.`,
	RunE: runSeedCmd,
}

var seedGithubCmd = &cobra.Command{
	Use:   "github",
	Short: "Seed ghost keys into a public GitHub repo",
	RunE:  runSeedGithub,
}

var seedS3Cmd = &cobra.Command{
	Use:   "s3",
	Short: "Seed ghost keys into a public S3 bucket",
	RunE:  runSeedS3,
}

var seedPastebinCmd = &cobra.Command{
	Use:   "pastebin",
	Short: "Seed ghost keys into a local Pastebin-style leak",
	RunE:  runSeedPastebin,
}

var seedAllCmd = &cobra.Command{
	Use:   "all",
	Short: "Seed ghost keys to every platform",
	RunE:  runSeedAll,
}

var meshCmd = &cobra.Command{
	Use:   "mesh",
	Short: "Deploy correlated ghost identities across AWS, GitHub, and Okta",
	Long: `Deploy matching ghost identities across AWS IAM + GitHub + Okta so one
persona exists on every platform.

When a ghost fires on one platform, the alert flags the correlated identities
on the other platforms — a "mesh" of decoys a real attacker can never fully
disentangle from real users.`,
}

var meshDeployCmd = &cobra.Command{
	Use:   "deploy",
	Short: "Deploy matching ghost identities across platforms",
	Long: `Create count correlated ghost identities across the requested platforms.

Platforms without live credentials are simulated locally so the demo always
works: AWS legs become local ghost records, GitHub profiles get simulated
URLs, and Okta profiles are written to okta-ghosts.json.`,
	RunE: runMeshDeploy,
}

var meshStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show correlated ghost identities across platforms",
	RunE:  runMeshStatus,
}

var journeyCmd = &cobra.Command{
	Use:   "journey",
	Short: "Generate and visualize an attacker journey for a ghost user",
	Long: `Capture or simulate the attacker's full journey against a ghost user,
render it as a Mermaid attack graph, post the enhanced alert to Slack, and save
it for later replay.`,
	RunE: runJourney,
}

var replayCmd = &cobra.Command{
	Use:   "replay",
	Short: "Replay a saved attack journey from a JSON file",
	Long: `Load a saved attack journey, print its Mermaid diagram to the terminal,
and re-post it to Slack.`,
	RunE: runReplay,
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
	simulateCmd.Flags().Bool("journey", false, "Capture and visualize the attacker journey (local mode)")
	_ = simulateCmd.MarkFlagRequired("username")

	statusCmd.Flags().BoolP("local", "l", false, "Show ghosts from the local JSON store")

	cleanCmd.Flags().Bool("local", false, "Delete ghosts.json")
	cleanCmd.Flags().Bool("all", false, "Delete all ghost IAM users from AWS (asks first)")

	addGhostUserFlag(seedCmd)
	seedCmd.Flags().String("platform", "all", "Platform to seed: github, s3, pastebin, or all")
	addGhostUserFlag(seedGithubCmd)
	addGhostUserFlag(seedS3Cmd)
	addGhostUserFlag(seedPastebinCmd)
	addGhostUserFlag(seedAllCmd)
	seedCmd.AddCommand(seedGithubCmd, seedS3Cmd, seedPastebinCmd, seedAllCmd)

	meshDeployCmd.Flags().IntP("count", "c", 2, "Number of ghost identities per platform")
	meshDeployCmd.Flags().StringP("prefix", "p", "demo", "Naming prefix")
	meshDeployCmd.Flags().String("platforms", "all", "Comma-separated platforms: aws,github,okta,all")
	meshDeployCmd.Flags().BoolP("local", "l", false, "Force local simulation (no real API calls)")
	meshCmd.AddCommand(meshDeployCmd, meshStatusCmd)

	journeyCmd.Flags().StringP("username", "u", "", "Ghost username to visualize the attacker journey for")
	journeyCmd.Flags().String("save", "", "Path to save the journey JSON (default attack-journey-<date>.json)")
	_ = journeyCmd.MarkFlagRequired("username")

	replayCmd.Flags().StringP("file", "f", "", "Path to a saved attack journey JSON file")
	_ = replayCmd.MarkFlagRequired("file")

	rootCmd.AddCommand(deployCmd, simulateCmd, statusCmd, cleanCmd, seedCmd, meshCmd, journeyCmd, replayCmd)
}

// addGhostUserFlag registers the --ghost-user flag used by the seed subcommands.
func addGhostUserFlag(cmd *cobra.Command) {
	cmd.Flags().StringP("ghost-user", "u", "", "Ghost username whose access keys to seed")
	_ = cmd.MarkFlagRequired("ghost-user")
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
		return deployLocal(count, prefix, withKeys)
	}
	return deployAWS(count, prefix, region, withKeys)
}

// deployLocal writes ghost users to the local JSON store. Never touches AWS.
func deployLocal(count int, prefix string, withKeys bool) error {
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

		keyNote := ""
		if withKeys {
			akid, secret, err := deploy.GenerateKeys()
			if err != nil {
				return fmt.Errorf("generate keys for %s: %w", username, err)
			}
			record.AccessKeyID = akid
			record.SecretAccessKey = secret
			keyNote = " (keys generated)"
		}

		if err := s.AddGhost(record); err != nil {
			return fmt.Errorf("add ghost %s: %w", username, err)
		}
		fmt.Printf("[%d] Created: %s (policy: %s)%s\n", i+1, username, policy.Name, keyNote)
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
	withJourney, _ := cmd.Flags().GetBool("journey")

	if local {
		// PURE LOCAL PATH
		s := store.NewLocalStore(localStoreFile)
		ghost, err := s.FindGhost(username)
		if err != nil {
			return fmt.Errorf("ghost user '%s' not found in ghosts.json\n  Deploy first: ghostiam deploy --local --count 5", username)
		}

		fmt.Printf("\n👻 Ghost user activated: %s\n", ghost.Username)
		fmt.Printf("   Policy: %s\n", ghost.PolicyName)
		fmt.Printf("   Created: %s\n", ghost.CreatedAt)

		webhookURL := os.Getenv("SLACK_WEBHOOK_URL")

		if withJourney {
			err := runJourneyForGhost(ghost.Username, "", webhookURL)
			if err == nil {
				return nil
			}
			return err
		}

		if webhookURL != "" {
			if err := sendLocalAlert(ghost.Username, ghost.PolicyName, webhookURL); err != nil {
				fmt.Printf("   ❌ Slack alert failed: %v\n", err)
			} else {
				fmt.Printf("   ✅ Alert sent to Slack — check your channel\n")
			}
		}

		pushAlertToDashboard(ghost.Username, ghost.PolicyName, "")
		return nil
	}

	// PURE AWS PATH
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

func sendLocalAlert(username, policyName, webhookURL string) error {
	headerText := slack.NewTextBlockObject("plain_text", "👻 GHOST USER ACTIVATED (LOCAL MODE)", false, false)
	headerBlock := slack.NewHeaderBlock(headerText)

	bodyText := fmt.Sprintf(
		"*Ghost User:* `%s`\n*Policy:* %s\n*Source:* local simulation\n*Time:* %s",
		username, policyName, time.Now().UTC().Format(time.RFC3339),
	)
	bodyBlock := slack.NewSectionBlock(
		slack.NewTextBlockObject("mrkdwn", bodyText, false, false),
		nil, nil,
	)

	dividerBlock := slack.NewDividerBlock()

	footerText := slack.NewTextBlockObject("mrkdwn", "GhostIam — deploy decoys, detect recon. github.com/kakashi-kx/ghostiam", false, false)
	footerBlock := slack.NewContextBlock("", footerText)

	msg := &slack.WebhookMessage{
		Blocks: &slack.Blocks{
			BlockSet: []slack.Block{headerBlock, bodyBlock, dividerBlock, footerBlock},
		},
	}

	return slack.PostWebhook(webhookURL, msg)
}

// ---------------------------------------------------------------------------
// seed
// ---------------------------------------------------------------------------

func runSeedCmd(cmd *cobra.Command, _ []string) error {
	platform, _ := cmd.Flags().GetString("platform")
	ghostUser, _ := cmd.Flags().GetString("ghost-user")
	return runSeed(platform, ghostUser)
}

func runSeedGithub(cmd *cobra.Command, _ []string) error {
	ghostUser, _ := cmd.Flags().GetString("ghost-user")
	return runSeed("github", ghostUser)
}

func runSeedS3(cmd *cobra.Command, _ []string) error {
	ghostUser, _ := cmd.Flags().GetString("ghost-user")
	return runSeed("s3", ghostUser)
}

func runSeedPastebin(cmd *cobra.Command, _ []string) error {
	ghostUser, _ := cmd.Flags().GetString("ghost-user")
	return runSeed("pastebin", ghostUser)
}

func runSeedAll(cmd *cobra.Command, _ []string) error {
	ghostUser, _ := cmd.Flags().GetString("ghost-user")
	return runSeed("all", ghostUser)
}

// runSeed loads the ghost user's keys and plants them as bait on the requested
// platforms. Every platform is tried independently; a missing credential on one
// platform does not stop the others.
func runSeed(platform, ghostUser string) error {
	s := store.NewLocalStore(localStoreFile)
	ghost, err := s.FindGhost(ghostUser)
	if err != nil {
		return fmt.Errorf("ghost user '%s' not found in ghosts.json\n  Deploy first: ghostiam deploy --local --count 1 --with-keys --prefix seed-test", ghostUser)
	}
	if ghost.AccessKeyID == "" || ghost.SecretAccessKey == "" {
		return fmt.Errorf("ghost user '%s' has no access keys\n  Redeploy with keys: ghostiam deploy --local --count 1 --with-keys", ghostUser)
	}

	req := seeder.SeedRequest{
		GhostUsername:   ghost.Username,
		AccessKeyID:     ghost.AccessKeyID,
		SecretAccessKey: ghost.SecretAccessKey,
	}

	fmt.Printf("\n👻 Seeding ghost keys for %s\n", ghost.Username)
	fmt.Println()

	ok := 0
	failures := 0
	seeders := seedersForPlatform(platform)
	for _, p := range seeders {
		if err := seedToPlatform(p, req); err != nil {
			failures++
			continue
		}
		ok++
	}

	fmt.Println()
	if failures > 0 {
		fmt.Printf("⚠️  %d platform(s) failed, %d succeeded. Check the errors above.\n", failures, ok)
	}
	fmt.Printf("✅ Seeded %d bait location(s). Any attacker who uses these keys triggers an alert.\n", ok)
	return nil
}

// seedersForPlatform resolves a platform string to the seeders to run.
func seedersForPlatform(platform string) []seeder.Seeder {
	switch platform {
	case "github":
		return []seeder.Seeder{seeder.NewGitHubSeeder(os.Getenv("GITHUB_TOKEN"))}
	case "s3":
		return []seeder.Seeder{seeder.NewS3Seeder("us-east-1")}
	case "pastebin":
		return []seeder.Seeder{seeder.NewPastebinSeeder(".")}
	default:
		return []seeder.Seeder{
			seeder.NewGitHubSeeder(os.Getenv("GITHUB_TOKEN")),
			seeder.NewS3Seeder("us-east-1"),
			seeder.NewPastebinSeeder("."),
		}
	}
}

func seedToPlatform(p seeder.Seeder, req seeder.SeedRequest) error {
	fmt.Printf("[seed] %s ...\n", p.Name())
	payload, err := p.Seed(context.Background(), req)
	if err != nil {
		fmt.Printf("  ❌ %s seed failed: %v\n", p.Name(), err)
		return err
	}
	fmt.Printf("  ✅ %s -> %s\n", payload.BaitFileName, payload.Location)

	postDashboardEvent(dashboard.EventIngest{Type: "seed", Seed: &dashboard.Seed{
		GhostUsername: req.GhostUsername,
		Platform:      string(p.Name()),
		LocationURL:   payload.Location,
		BaitFilename:  payload.BaitFileName,
		Status:        "active",
	}})
	return nil
}

// ---------------------------------------------------------------------------
// mesh
// ---------------------------------------------------------------------------

func runMeshDeploy(cmd *cobra.Command, _ []string) error {
	count, _ := cmd.Flags().GetInt("count")
	prefix, _ := cmd.Flags().GetString("prefix")
	platforms, _ := cmd.Flags().GetString("platforms")
	local, _ := cmd.Flags().GetBool("local")

	orch := mesh.NewOrchestrator("mesh-identities.json", "okta-ghosts.json")
	identities, err := orch.Deploy(context.Background(), mesh.MeshConfig{
		Count:       count,
		Prefix:      prefix,
		Platforms:   strings.Split(platforms, ","),
		Local:       local,
		GitHubToken: os.Getenv("GITHUB_TOKEN"),
		Region:      "us-east-1",
	})
	if err != nil {
		return err
	}

	fmt.Printf("\n👻 Deployed %d correlated ghost identities.\n", len(identities))
	fmt.Println()
	for _, id := range identities {
		fmt.Printf("  - %s\n", id.Username)
		if id.AWSSuccess {
			fmt.Printf("      AWS:    ✅ active%s\n", awsArnNote(id.AWSArn))
		} else {
			fmt.Printf("      AWS:    ❌\n")
		}
		if id.GitHubSuccess {
			fmt.Printf("      GitHub: ✅ %s\n", id.GitHubHandle)
		} else {
			fmt.Printf("      GitHub: ❌\n")
		}
		if id.OktaSuccess {
			fmt.Printf("      Okta:   ✅ %s\n", id.OktaEmail)
		} else {
			fmt.Printf("      Okta:   ❌\n")
		}
	}
	fmt.Println()
	fmt.Println("Run 'ghostiam mesh status' to see the correlated table.")
	return nil
}

func runMeshStatus(cmd *cobra.Command, _ []string) error {
	orch := mesh.NewOrchestrator("mesh-identities.json", "okta-ghosts.json")
	identities, err := orch.List()
	if err != nil {
		return err
	}
	if len(identities) == 0 {
		fmt.Println("No mesh identities found. Deploy first: ghostiam mesh deploy")
		return nil
	}

	fmt.Println("👻 Ghost Mesh Status")
	fmt.Println()
	fmt.Printf("%-30s %-12s %-20s %s\n", "USERNAME", "AWS", "GITHUB", "OKTA")
	fmt.Println(strings.Repeat("-", 74))
	for _, id := range identities {
		aws := "❌"
		if id.AWSSuccess {
			aws = "✅ active"
		}
		gh := "❌"
		if id.GitHubSuccess {
			gh = "✅ " + id.GitHubHandle
		}
		okta := "❌"
		if id.OktaSuccess {
			okta = "✅ " + id.OktaEmail
		}
		fmt.Printf("%-30s %-12s %-20s %s\n", id.Username, aws, gh, okta)
	}
	fmt.Println()
	fmt.Println("A ghost firing on any platform flags all its correlated identities.")
	return nil
}

func awsArnNote(arn string) string {
	if arn == "" {
		return " (local)"
	}
	return ""
}

// ---------------------------------------------------------------------------
// journey + replay
// ---------------------------------------------------------------------------

func runJourney(cmd *cobra.Command, _ []string) error {
	username, _ := cmd.Flags().GetString("username")
	savePath, _ := cmd.Flags().GetString("save")

	s := store.NewLocalStore(localStoreFile)
	ghost, err := s.FindGhost(username)
	if err != nil {
		return fmt.Errorf("ghost user '%s' not found in ghosts.json\n  Deploy first: ghostiam deploy --local --count 5", username)
	}

	webhookURL := os.Getenv("SLACK_WEBHOOK_URL")
	return runJourneyForGhost(ghost.Username, savePath, webhookURL)
}

func runReplay(cmd *cobra.Command, _ []string) error {
	file, _ := cmd.Flags().GetString("file")

	graph, err := journey.Load(file)
	if err != nil {
		return err
	}

	printJourney(graph)

	pushJourneyToDashboard(graph.GhostUsername, graph)

	webhookURL := os.Getenv("SLACK_WEBHOOK_URL")
	if webhookURL == "" {
		fmt.Println("   ⚠️  SLACK_WEBHOOK_URL not set. Journey alert not sent.")
		return nil
	}
	if err := sendJourneyAlert(webhookURL, graph.GhostUsername, graph); err != nil {
		fmt.Printf("   ❌ Slack journey alert failed: %v\n", err)
		return nil
	}
	fmt.Println("   ✅ Journey alert sent to Slack — check your channel")
	return nil
}

// runJourneyForGhost captures the attacker journey for a ghost, prints it,
// saves it, and posts the enhanced alert to Slack.
func runJourneyForGhost(username, savePath, webhookURL string) error {
	graph, err := journey.Capture(context.Background(), username)
	if err != nil {
		return fmt.Errorf("journey capture: %w", err)
	}

	printJourney(graph)

	if savePath == "" {
		savePath = fmt.Sprintf("attack-journey-%s.json", time.Now().UTC().Format("2006-01-02"))
	}
	if err := journey.Save(graph, savePath); err != nil {
		return err
	}
	fmt.Printf("   💾 Journey saved: %s\n", savePath)

	pushJourneyToDashboard(username, graph)

	if webhookURL == "" {
		fmt.Println("   ⚠️  SLACK_WEBHOOK_URL not set. Journey alert not sent.")
		return nil
	}
	if err := sendJourneyAlert(webhookURL, username, graph); err != nil {
		fmt.Printf("   ❌ Slack journey alert failed: %v\n", err)
		return nil
	}
	fmt.Println("   ✅ Journey alert sent to Slack — check your channel")
	return nil
}

// printJourney renders the attack graph, risk score, and timeline to stdout.
func printJourney(g *journey.AttackGraph) {
	score := journey.RiskScore(g)
	fmt.Printf("\n🔴 ATTACKER JOURNEY — %s\n", g.GhostUsername)
	fmt.Printf("   Risk: %s %d/10 (%s)\n", journey.RiskBar(score), score, journey.RiskLabel(score))
	fmt.Printf("   Steps: %d   Duration: %s\n", len(g.Nodes), g.Duration.Round(time.Second))
	fmt.Println()
	fmt.Println(journey.ToMermaid(g))
	fmt.Println()
	fmt.Println("Timeline:")
	for i, n := range g.Nodes {
		fmt.Printf("  %d. `%s` (%s) from %s\n", i+1, n.FQN(), n.Severity, n.SourceIP)
		fmt.Printf("     MITRE: %s\n", n.MitreTechnique())
	}
	fmt.Println()
}

// sendJourneyAlert posts the enhanced attacker-journey Block Kit message to
// Slack, including the Mermaid render, timeline, MITRE mappings, and risk bar.
func sendJourneyAlert(webhookURL, ghostUsername string, g *journey.AttackGraph) error {
	headerText := slack.NewTextBlockObject("plain_text", "🔴 ATTACKER JOURNEY DETECTED", false, false)
	headerBlock := slack.NewHeaderBlock(headerText)

	score := journey.RiskScore(g)
	diagramURL := journey.MermaidImageURL(journey.ToMermaid(g))

	summaryText := fmt.Sprintf(
		"*Ghost User:* `%s`\n*Steps:* %d\n*Duration:* %s\n*Source:* local simulation\n*Diagram:* <%s|view journey>",
		ghostUsername, len(g.Nodes), g.Duration.Round(time.Second), diagramURL,
	)
	summaryBlock := slack.NewSectionBlock(slack.NewTextBlockObject("mrkdwn", summaryText, false, false), nil, nil)

	var timeline strings.Builder
	for i, n := range g.Nodes {
		timeline.WriteString(fmt.Sprintf(
			"*%d.* `%s` — %s\n   MITRE: %s\n",
			i+1, n.FQN(), strings.ToUpper(n.Severity), n.MitreTechnique(),
		))
	}
	timelineBlock := slack.NewSectionBlock(
		slack.NewTextBlockObject("mrkdwn", "*Timeline:*\n"+timeline.String(), false, false),
		nil, nil,
	)

	riskText := fmt.Sprintf("*Risk Score:* %s %d/10 (%s)", journey.RiskBar(score), score, journey.RiskLabel(score))
	riskBlock := slack.NewSectionBlock(slack.NewTextBlockObject("mrkdwn", riskText, false, false), nil, nil)

	footerText := slack.NewTextBlockObject("mrkdwn", "GhostIam — deploy decoys, detect recon. github.com/kakashi-kx/ghostiam", false, false)
	footerBlock := slack.NewContextBlock("", footerText)

	msg := &slack.WebhookMessage{
		Blocks: &slack.Blocks{
			BlockSet: []slack.Block{headerBlock, summaryBlock, timelineBlock, riskBlock, footerBlock},
		},
	}

	return slack.PostWebhook(webhookURL, msg)
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
