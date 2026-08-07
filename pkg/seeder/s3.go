package seeder

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// S3Seeder plants ghost credentials in a public S3 bucket that looks like a
// production backup store: a config.json with the keys plus a dummy backup.sql
// for realism. Requires AWS credentials.
type S3Seeder struct {
	// Region is the AWS region to create the bucket in.
	Region string
}

// NewS3Seeder returns an S3Seeder targeting the given region.
func NewS3Seeder(region string) *S3Seeder {
	if region == "" {
		region = "us-east-1"
	}
	return &S3Seeder{Region: region}
}

// Name implements Seeder.
func (s *S3Seeder) Name() Platform { return PlatformS3 }

// Seed creates a public bucket, uploads the bait files, and applies a public
// read policy so the "leak" is actually discoverable.
func (s *S3Seeder) Seed(ctx context.Context, req SeedRequest) (SeedPayload, error) {
	awsCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(s.Region))
	if err != nil {
		return SeedPayload{}, fmt.Errorf("s3: load aws config: %w", err)
	}
	client := s3.NewFromConfig(awsCfg)

	bucket := fmt.Sprintf("company-prod-backups-%s", randomHex(6))
	if err := s.createBucket(ctx, client, bucket); err != nil {
		return SeedPayload{}, err
	}
	if err := s.openPublicAccess(ctx, client, bucket); err != nil {
		return SeedPayload{}, err
	}

	configContent := BuildConfigBait(req, "automated prod backup — do not delete")
	if err := s.putObject(ctx, client, bucket, "config.json", configContent); err != nil {
		return SeedPayload{}, err
	}
	if err := s.putObject(ctx, client, bucket, "backup.sql", dummySQL()); err != nil {
		return SeedPayload{}, err
	}
	if err := s.putPublicPolicy(ctx, client, bucket); err != nil {
		return SeedPayload{}, err
	}

	return SeedPayload{
		GhostUsername:   req.GhostUsername,
		AccessKeyID:     req.AccessKeyID,
		SecretAccessKey: req.SecretAccessKey,
		BaitFileName:    "config.json",
		BaitContent:     configContent,
		Location:        "https://" + bucket + ".s3." + s.Region + ".amazonaws.com/config.json",
		SeededAt:        time.Now().UTC(),
	}, nil
}

func (s *S3Seeder) createBucket(ctx context.Context, client *s3.Client, bucket string) error {
	if _, err := client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)}); err != nil {
		return fmt.Errorf("s3: create bucket %s: %w", bucket, err)
	}
	return nil
}

// openPublicAccess disables the account/block-level public access settings so
// the bucket policy below can take effect.
func (s *S3Seeder) openPublicAccess(ctx context.Context, client *s3.Client, bucket string) error {
	_, err := client.PutPublicAccessBlock(ctx, &s3.PutPublicAccessBlockInput{
		Bucket: aws.String(bucket),
		PublicAccessBlockConfiguration: &types.PublicAccessBlockConfiguration{
			BlockPublicAcls:       aws.Bool(false),
			BlockPublicPolicy:     aws.Bool(false),
			IgnorePublicAcls:      aws.Bool(false),
			RestrictPublicBuckets: aws.Bool(false),
		},
	})
	if err != nil {
		return fmt.Errorf("s3: disable public access block on %s: %w", bucket, err)
	}
	return nil
}

func (s *S3Seeder) putObject(ctx context.Context, client *s3.Client, bucket, key, content string) error {
	if _, err := client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader([]byte(content)),
	}); err != nil {
		return fmt.Errorf("s3: upload %s/%s: %w", bucket, key, err)
	}
	return nil
}

// putPublicPolicy grants anonymous GetObject and ListBucket on the bucket.
func (s *S3Seeder) putPublicPolicy(ctx context.Context, client *s3.Client, bucket string) error {
	arn := "arn:aws:s3:::" + bucket
	doc, err := json.MarshalIndent(map[string]any{
		"Version": "2012-10-17",
		"Statement": []map[string]any{
			{
				"Effect":    "Allow",
				"Principal": "*",
				"Action":    []string{"s3:GetObject", "s3:ListBucket"},
				"Resource":  []string{arn, arn + "/*"},
			},
		},
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("s3: build bucket policy: %w", err)
	}

	if _, err := client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
		Bucket: aws.String(bucket),
		Policy: aws.String(string(doc)),
	}); err != nil {
		return fmt.Errorf("s3: apply public policy to %s: %w", bucket, err)
	}
	return nil
}

// dummySQL returns a small fake database backup used to make the bait bucket
// look like a real prod backup store.
func dummySQL() string {
	return strings.TrimSpace(`
-- mysqldump 8.0.34 -- Database: prod_customer_orders
-- Host: db-primary.internal   User: backup_agent
CREATE TABLE customers (
  id BIGINT NOT NULL AUTO_INCREMENT,
  email VARCHAR(255) NOT NULL,
  created_at DATETIME NOT NULL,
  PRIMARY KEY (id)
);
INSERT INTO customers (id, email, created_at) VALUES
  (1001, 'accounting@example.com', '2026-07-01 09:00:00'),
  (1002, 'support@example.com',    '2026-07-02 10:30:00');
`) + "\n"
}
