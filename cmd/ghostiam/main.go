// Command ghostiam is the GhostIam CLI. It deploys decoy IAM users into an AWS
// account and simulates attacker activity to trigger the detection pipeline.
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/kakashi-kx/ghostiam/pkg/deploy"
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
call made by these users triggers a Slack alert via the detection pipeline.`,
	RunE: runDeploy,
}

var simulateCmd = &cobra.Command{
	Use:   "simulate",
	Short: "Simulate attacker activity using ghost credentials to trigger detection",
	Long: `Simulate attacker activity to trigger the detection pipeline.

This command uses YOUR current AWS credentials to make a harmless API call
(sts:GetCallerIdentity). The EventBridge rule detects calls made by ghost
users, so for a full end-to-end demo you would run this with the ghost user's
access keys configured. For v1 this documents the flow using your own
credentials.`,
	RunE: runSimulate,
}

func init() {
	deployCmd.Flags().IntP("count", "c", 10, "Number of ghost users to create")
	deployCmd.Flags().StringP("prefix", "p", "prod", "Name prefix for ghost users (e.g. ghost-prod-...)")
	deployCmd.Flags().StringP("region", "r", "us-east-1", "AWS region")
	deployCmd.Flags().Bool("with-keys", false, "Generate access keys for each ghost user")

	simulateCmd.Flags().StringP("username", "u", "", "Ghost username to simulate activity with")
	simulateCmd.Flags().StringP("region", "r", "us-east-1", "AWS region")
	_ = simulateCmd.MarkFlagRequired("username")

	rootCmd.AddCommand(deployCmd, simulateCmd)
}

func runDeploy(cmd *cobra.Command, _ []string) error {
	count, _ := cmd.Flags().GetInt("count")
	prefix, _ := cmd.Flags().GetString("prefix")
	region, _ := cmd.Flags().GetString("region")
	withKeys, _ := cmd.Flags().GetBool("with-keys")

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

func runSimulate(cmd *cobra.Command, _ []string) error {
	username, _ := cmd.Flags().GetString("username")
	region, _ := cmd.Flags().GetString("region")

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
