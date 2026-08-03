// Package templates defines the decoy IAM policy documents attached to ghost
// users. Each document looks valuable to an attacker during reconnaissance
// but only grants read-only / list permissions — never create, delete, update,
// or data-read capabilities.
package templates

import (
	"encoding/json"
	"fmt"
)

// PolicyTemplate describes a single decoy IAM policy attached to a ghost user.
type PolicyTemplate struct {
	// Name is the display name of the policy, e.g. "ProdDatabaseReadAccess".
	Name string
	// Description explains what an attacker would believe this policy grants.
	Description string
	// Document is a JSON-encoded, valid AWS IAM policy document.
	Document string
}

// policyDocument is the structural form used to marshal a valid IAM policy.
type policyDocument struct {
	Version   string            `json:"Version"`
	Statement []policyStatement `json:"Statement"`
}

// policyStatement is a minimal IAM statement: a single Effect over explicit
// Actions/Resources with no conditions.
type policyStatement struct {
	Effect   string   `json:"Effect"`
	Action   []string `json:"Action"`
	Resource string   `json:"Resource"`
}

// GetDecoyPolicies returns the 5 built-in decoy policy templates. Each policy
// lists/discribes resources only and can never mutate them.
func GetDecoyPolicies() []PolicyTemplate {
	return []PolicyTemplate{
		{
			Name:        "ProdDatabaseReadAccess",
			Description: "Looks like read access to production database backups and snapshots. Actually only describes RDS instances, snapshots, and DynamoDB tables — no data can be read or modified.",
			Document: mustMarshal(policyDocument{
				Version: "2012-10-17",
				Statement: []policyStatement{
					{
						Effect:   "Allow",
						Action:   []string{"rds:DescribeDBInstances", "rds:DescribeDBSnapshots", "rds:ListTagsForResource", "dynamodb:ListTables", "dynamodb:DescribeTable"},
						Resource: "*",
					},
				},
			}),
		},
		{
			Name:        "CloudInfrastructureViewer",
			Description: "Looks like full infrastructure visibility. Actually only enumerates EC2, VPC, and Lambda resources — no changes can be made.",
			Document: mustMarshal(policyDocument{
				Version: "2012-10-17",
				Statement: []policyStatement{
					{
						Effect:   "Allow",
						Action:   []string{"ec2:DescribeInstances", "ec2:DescribeSecurityGroups", "ec2:DescribeVpcs", "ec2:DescribeSubnets", "lambda:ListFunctions", "lambda:ListTags"},
						Resource: "*",
					},
				},
			}),
		},
		{
			Name:        "S3BackupOperator",
			Description: "Looks like access to backup buckets. Actually only lists buckets and reads bucket metadata — it cannot list objects or read any data.",
			Document: mustMarshal(policyDocument{
				Version: "2012-10-17",
				Statement: []policyStatement{
					{
						Effect:   "Allow",
						Action:   []string{"s3:ListAllMyBuckets", "s3:GetBucketLocation", "s3:GetBucketTagging"},
						Resource: "*",
					},
				},
			}),
		},
		{
			Name:        "IAMSecurityAuditor",
			Description: "Looks like IAM admin audit access. Actually only enumerates users, roles, and policies — it cannot create users or attach policies.",
			Document: mustMarshal(policyDocument{
				Version: "2012-10-17",
				Statement: []policyStatement{
					{
						Effect:   "Allow",
						Action:   []string{"iam:ListUsers", "iam:ListRoles", "iam:ListPolicies", "iam:GetAccountSummary", "iam:ListAccessKeys"},
						Resource: "*",
					},
				},
			}),
		},
		{
			Name:        "CrossAccountAccessRole",
			Description: "Looks like a cross-account trust bridge. Actually only returns caller identity and reads organization structure — no roles can be assumed.",
			Document: mustMarshal(policyDocument{
				Version: "2012-10-17",
				Statement: []policyStatement{
					{
						Effect:   "Allow",
						Action:   []string{"sts:GetCallerIdentity", "organizations:DescribeOrganization", "organizations:ListAccounts"},
						Resource: "*",
					},
				},
			}),
		},
	}
}

// mustMarshal JSON-encodes an IAM policy document struct with indentation.
// It panics on error; all documents in this package are hardcoded so a failure
// here indicates a programming error caught at startup rather than at runtime.
func mustMarshal(v any) string {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		panic(fmt.Sprintf("templates: failed to marshal policy document: %v", err))
	}
	return string(data)
}
