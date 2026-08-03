// Package deploy is the core engine. It creates ghost IAM users in AWS with
// harmlessly-tempting decoy policies attached, ready to trip attacker
// reconnaissance and fire detection alerts.
package deploy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	mrand "math/rand"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/kakashi-kx/ghostiam/pkg/templates"
)

// DeployConfig controls how ghost users are created.
type DeployConfig struct {
	// Count is the number of ghost users to create.
	Count int
	// Prefix is the environment-style prefix used in usernames (e.g. "prod").
	Prefix string
	// Region is the AWS region to configure the IAM client for.
	Region string
	// WithKeys enables creation of an access key for each ghost user.
	WithKeys bool
}

// GhostUser represents a single deployed decoy identity.
type GhostUser struct {
	// Username is the IAM username of the ghost user.
	Username string
	// Arn is the Amazon Resource Name of the ghost user.
	Arn string
	// AccessKeyID is only populated when WithKeys is enabled.
	AccessKeyID string
	// SecretAccessKey is only populated when WithKeys is enabled.
	SecretAccessKey string
	// PolicyAttached is the name of the decoy policy attached to the user.
	PolicyAttached string
}

// shorthand maps a policy template name to a short, realistic role label.
var shorthand = map[string]string{
	"ProdDatabaseReadAccess":    "db-read",
	"CloudInfrastructureViewer": "infra-view",
	"S3BackupOperator":          "s3-backup",
	"IAMSecurityAuditor":        "iam-audit",
	"CrossAccountAccessRole":    "xacct",
}

// ghostUserTags returns the tags marking a user as a decoy, tagged with the
// attached policy name for the detection layer.
func ghostUserTags(policyName string) []types.Tag {
	return []types.Tag{
		{Key: aws.String("GhostIam"), Value: aws.String("true")},
		{Key: aws.String("ghostiam:policy"), Value: aws.String(policyName)},
	}
}

// DeployGhostUsers creates count ghost IAM users in AWS, attaching a random
// decoy policy to each and tagging it for detection. It returns the created
// users plus the first error encountered (nil if all succeeded).
func DeployGhostUsers(ctx context.Context, cfg DeployConfig) ([]GhostUser, error) {
	if cfg.Prefix == "" {
		cfg.Prefix = "prod"
	}
	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}

	awsCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(cfg.Region))
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}
	client := iam.NewFromConfig(awsCfg)

	policies := templates.GetDecoyPolicies()
	if len(policies) == 0 {
		return nil, fmt.Errorf("no decoy policies registered")
	}

	var (
		users []GhostUser
		first error
	)

	for i := 0; i < cfg.Count; i++ {
		policy := randomPolicy(policies)
		username := fmt.Sprintf("ghost-%s-%s-%s", cfg.Prefix, policyShortName(policy.Name), randomHex(6))

		user, err := createGhostUser(ctx, client, username, policy, cfg.WithKeys)
		if err != nil {
			log.Printf("deploy: skipping %s: %v", username, err)
			if first == nil {
				first = err
			}
			continue
		}
		users = append(users, user)
		log.Printf("created ghost user: %s", username)
	}

	return users, first
}

// createGhostUser creates a single ghost user, attaches its decoy policy, and
// optionally provisions an access key.
func createGhostUser(ctx context.Context, client *iam.Client, username string, policy templates.PolicyTemplate, withKeys bool) (GhostUser, error) {
	createOut, err := client.CreateUser(ctx, &iam.CreateUserInput{
		UserName: aws.String(username),
		Tags:     ghostUserTags(policy.Name),
	})
	if err != nil {
		return GhostUser{}, fmt.Errorf("create user %s: %w", username, err)
	}

	_, err = client.PutUserPolicy(ctx, &iam.PutUserPolicyInput{
		UserName:       aws.String(username),
		PolicyName:     aws.String(policy.Name),
		PolicyDocument: aws.String(policy.Document),
	})
	if err != nil {
		return GhostUser{}, fmt.Errorf("attach policy %s to %s: %w", policy.Name, username, err)
	}

	ghost := GhostUser{
		Username:       username,
		Arn:            aws.ToString(createOut.User.Arn),
		PolicyAttached: policy.Name,
	}

	if withKeys {
		keyOut, err := client.CreateAccessKey(ctx, &iam.CreateAccessKeyInput{
			UserName: aws.String(username),
		})
		if err != nil {
			return GhostUser{}, fmt.Errorf("create access key for %s: %w", username, err)
		}
		ghost.AccessKeyID = aws.ToString(keyOut.AccessKey.AccessKeyId)
		ghost.SecretAccessKey = aws.ToString(keyOut.AccessKey.SecretAccessKey)
	}

	return ghost, nil
}

// randomHex returns a hexadecimal string of n characters backed by crypto/rand.
func randomHex(n int) string {
	b := make([]byte, (n+1)/2)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("deploy: failed to read random bytes: %v", err))
	}
	return hex.EncodeToString(b)[:n]
}

// policyShortName maps a policy template name to its short role label.
func policyShortName(name string) string {
	if short, ok := shorthand[name]; ok {
		return short
	}
	return "ghost"
}

// randomPolicy returns a random decoy policy using math/rand.
func randomPolicy(policies []templates.PolicyTemplate) templates.PolicyTemplate {
	return policies[mrand.Intn(len(policies))]
}
