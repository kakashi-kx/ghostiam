# GhostIam 👻

**Ghost users. Real alerts.**

Deploy decoy IAM identities across your AWS account and catch attacker reconnaissance instantly.

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8.svg)](https://go.dev)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/kakashi-kx/ghostiam/pulls)

## Overview

GhostIam fills your AWS account with decoy IAM users that look like privileged identities. When an attacker enumerates your IAM during reconnaissance and tries to use one, CloudTrail fires an alert to Slack within seconds. Zero false positives. Every alert is an attacker.

## Architecture

```
                      ┌────────────────────────────────────────────────────┐
                      │                    AWS Account                     │
                      │                                                    │
  ┌──────────┐        │   ┌──────────────────────────────────────────┐    │
  │  CLI     │  cre─  │   │  IAM Ghost Users                          │    │
  │ ghostiam │  ates  │   │  ghost-prod-db-read-a7f3                  │    │
  │ deploy   ├───────▶│   │  ghost-prod-infra-view-c2b8   (idle...)   │    │
  └──────────┘        │   │  tag: GhostIam=true                       │    │
                      │   └──────────────────────────────────────────┘    │
                      │                    ▲                              │
                      │            attacker tries to use one              │
                      │                    │                              │
                      │   ┌────────────────┴─────────────────────────┐   │
                      │   │  CloudTrail captures the API call        │   │
                      │   └──────────────────────────────────────────┘   │
                      │                    │                              │
                      │   ┌────────────────┴─────────────────────────┐   │
                      │   │  EventBridge rule filters ghost activity │   │
                      │   └──────────────────────────────────────────┘   │
                      │                    │                              │
                      │   ┌────────────────┴─────────────────────────┐   │
                      │   │  Lambda (ghostiam-detector)              │   │
                      │   │  parses event, builds Block Kit message  │   │
                      │   └──────────────────────────────────────────┘   │
                      └────────────────────┬─────────────────────────────┘
                                           │
                                           ▼
                               ┌───────────────────────┐
                               │  Slack alert (seconds)│
                               │  :ghost: GHOST USER   │
                               └───────────────────────┘
```

## Quickstart (5-minute setup)

```bash
# 1. Clone
git clone https://github.com/kakashi-kx/ghostiam
cd ghostiam

# 2. Build
make build

# 3. Deploy detection infrastructure
export SLACK_WEBHOOK_URL="https://hooks.slack.com/..."
make deploy-lambda

# 4. Deploy ghost users
./build/ghostiam deploy --count 20 --prefix prod

# 5. Simulate an attack
./build/ghostiam simulate --username ghost-prod-db-read-a7f3c2

# 6. Check your Slack — alert within seconds
```

## Commands

### `ghostiam deploy`

Deploy ghost IAM users into your AWS account.

| Flag | Shorthand | Default | Description |
|------|-----------|---------|-------------|
| `--count` | `-c` | `10` | Number of ghost users to create |
| `--prefix` | `-p` | `prod` | Name prefix for ghost users (e.g. `ghost-prod-...`) |
| `--region` | `-r` | `us-east-1` | AWS region |
| `--with-keys` | | `false` | Generate access keys for each ghost user |

```bash
# Deploy 20 ghost users with the "prod" prefix
./build/ghostiam deploy --count 20 --prefix prod

# Deploy 5 users and generate access keys to seed as bait
./build/ghostiam deploy --count 5 --with-keys
```

### `ghostiam simulate`

Simulate attacker activity using ghost credentials to trigger detection.

| Flag | Shorthand | Default | Description |
|------|-----------|---------|-------------|
| `--username` | `-u` | *(required)* | Ghost username to simulate activity with |
| `--region` | `-r` | `us-east-1` | AWS region |

```bash
./build/ghostiam simulate --username ghost-prod-db-read-a7f3c2
```

## Decoy Policies

Each ghost user carries one of five decoy policies. They look valuable, but grant only read-only permissions.

| Name | What Attackers Think It Grants | What It Actually Grants |
|------|-------------------------------|-------------------------|
| `ProdDatabaseReadAccess` | Read access to production DB backups and snapshots | Only `Describe` on RDS/DynamoDB — no data access |
| `CloudInfrastructureViewer` | Full infrastructure visibility | Only `List`/`Describe` on EC2, VPC, Lambda |
| `S3BackupOperator` | Access to backup buckets | Only bucket listing/metadata — no object access |
| `IAMSecurityAuditor` | IAM admin audit access | Only `List`/`Get` on IAM — cannot create users or keys |
| `CrossAccountAccessRole` | Cross-account trust bridge | Only `sts:GetCallerIdentity` + org structure reads |

The deception gap is the point: an attacker who finds these keys believes they've struck gold, and every attempt to use them is your detection event.

## Detection Infrastructure

The `terraform/` directory deploys:

- **Lambda** (`ghostiam-detector`, Go on `provided.al2023`, 128MB, 10s) — parses the CloudTrail event and posts a Slack alert
- **EventBridge rule** (`ghostiam-capture-ghost-activity`) — filters CloudTrail events for `userName` starting with `ghost-`
- **IAM role** (`ghostiam-detector-role`) — allows the Lambda to write CloudWatch logs
- **Lambda permission** — lets EventBridge invoke the detector

> CloudTrail must be enabled in your account. It is on by default in all AWS accounts — management-event history is captured automatically.

## Alert Format

The Lambda posts a Block Kit message to Slack. Here's what an alert looks like:

```
┌──────────────────────────────────────────────────┐
│ :ghost: GHOST USER ACTIVATED                     │
│                                                  │
│ *Ghost User:* `ghost-prod-db-read-a7f3c2`        │
│ *API Call:* `iam.amazonaws.com.ListUsers`        │
│ *Source IP:* `203.0.113.42`                      │
│ *User Agent:* `aws-cli/2.15.0 Python/3.11`       │
│ *Region:* `us-east-1`                            │
│ *Time:* `2026-08-03 18:30:00 UTC`                │
│ *Request ID:* `a1b2c3d4-...`                     │
│ ──────────────────────────────────────────────── │
│ GhostIam — deploy decoys, detect recon.          │
│ github.com/kakashi-kx/ghostiam                   │
└──────────────────────────────────────────────────┘
```

## Requirements

- Go 1.21+
- AWS account with CloudTrail enabled
- Terraform 1.5+
- Slack workspace (for a webhook URL)

## Roadmap

- [x] AWS IAM ghost users
- [ ] Okta ghost identities
- [ ] GitHub ghost users
- [ ] Multi-cloud support
- [ ] Behavioral analysis of attacker actions
- [ ] Security Hub integration
- [ ] Web dashboard

## Contributing

Contributions are welcome! Fork the repo, create a feature branch, and open a pull request. A detailed contribution guide is coming soon — see [CONTRIBUTING.md](CONTRIBUTING.md).

New decoy policy templates are the easiest first contribution: add a template to `pkg/templates/policies.go`, give it a short name in `pkg/deploy/deploy.go`, and open a PR.

## License

MIT License — Copyright (c) 2026 Kakashi. See [LICENSE](LICENSE) for details.

## Author

Built by [@kakashi-kx](https://github.com/kakashi-kx)
