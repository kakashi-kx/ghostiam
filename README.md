# GhostIam 👻

**Ghost users. Real alerts.**

Deploy decoy IAM identities across your AWS account and catch attacker reconnaissance instantly.

[![Go Version](https://img.shields.io/badge/Go-1.25+-00ADD8.svg)](https://go.dev)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/kakashi-kx/ghostiam/pulls)
[![v3 Features](https://img.shields.io/badge/status-v3%20complete-brightgreen.svg)](https://github.com/kakashi-kx/ghostiam)

## Overview

GhostIam fills your AWS account with decoy IAM users that look like privileged identities. When an attacker enumerates your IAM during reconnaissance and tries to use one, CloudTrail fires an alert to Slack within seconds. Zero false positives. Every alert is an attacker.

## GhostIam v2 — Advanced Features

GhostIam v2 is the most advanced open-source honeytoken framework:

| Feature | What it does |
|---------|--------------|
| **Token Seeder** | Automatically "leaks" ghost keys to realistic bait — public GitHub repos, public S3 buckets, Pastebin |
| **Ghost Mesh** | Deploys the same persona across AWS IAM + GitHub + Okta so a fire on one platform flags all correlated identities |
| **Journey Replay** | Turns a fired ghost into a Mermaid attack graph with MITRE ATT&CK mappings, risk scoring, and Slack visualization |

## GhostIam v3 — Web Dashboard

GhostIam v3 ships a real-time operations console (Go + HTMX + SQLite + Chart.js):

| Page | What it shows |
|------|---------------|
| **Dashboard** | Live stat cards, alert traffic by hour, severity donut, top actions, and a live alert feed |
| **Ghosts** | Deploy/archive decoys from the browser and inspect their keys and policies |
| **Alerts** | Full alert feed with severity badges, source IPs, and a one-click alert simulator |
| **Journeys** | Attack kill-chains as step timelines with MITRE tactics and Mermaid flow diagrams |
| **Mesh** | Correlated personas as platform-leg cards (AWS / GitHub / Okta) |
| **Seeds** | Record and track bait locations, keys, and files |

Everything is live via Server-Sent Events: CLI alerts bubble up as toasts on any page.

```bash
ghostiam dashboard --port 8080 --api-key demo-key
# open http://localhost:8080 (pass ?api_key=demo-key or the X-API-Key header)
```

The CLI pushes alerts, seeds, and journeys to a running dashboard automatically:

```bash
export GHOSTIAM_DASHBOARD_URL=http://localhost:8080
export GHOSTIAM_DASHBOARD_KEY=demo-key
ghostiam simulate --local --username ghost-...        # pushes an alert
ghostiam seed pastebin --ghost-user ghost-...         # pushes a seed
ghostiam journey --username ghost-...                 # pushes a journey
```

Reports are one click away: `/reports/export?format=json` or `format=pdf`. A REST API is exposed at `/api/v1/stats|ghosts|alerts|journeys`.

### Seeder demo

![Seeder demo](https://via.placeholder.com/800x60/0d1117/ffffff?text=Seeder+demo+GIF+coming+soon)

### Mesh architecture

```
        ┌────────────────────────────  GHOST MESH  ────────────────────────────┐
        │                                                                    │
        │        ghost-prod-admin-a7f3 (one persona, three platforms)        │
        │                                                                    │
        │   ┌─────────────┐     ┌──────────────┐     ┌──────────────────┐    │
        │   │   AWS IAM   │     │    GitHub    │     │      Okta        │    │
        │   │ ghost user  │     │  contractor  │     │   fake profile   │    │
        │   │ (decoy pol) │     │    profile   │     │ (okta-ghosts)    │    │
        │   └─────┬───────┘     └──────┬───────┘     └────────┬─────────┘    │
        │         │                    │                      │              │
        │         └──────────────┬─────┴──────────────────────┘              │
        │                        │ correlated by username                    │
        │                   ┌────┴─────┐                                      │
        │                   │  Alert   │  "This ghost exists on 3 platforms"  │
        │                   └──────────┘                                      │
        └────────────────────────────────────────────────────────────────────┘
```

### Journey replay example output

```
$ ghostiam simulate --local --username ghost-prod-db-read-a7f3c2 --journey

🔴 ATTACKER JOURNEY — ghost-prod-db-read-a7f3c2
   Risk: ▓▓▓▓▓ 10/10 (Critical)
   Steps: 5   Duration: 28s

graph TD
    N0[sts:GetCallerIdentity<br/>RECON]
    N1[iam:ListRoles<br/>PRIVILEGE-ESCALATION]
    N2[s3:ListBuckets<br/>DISCOVERY]
    N3[s3:GetObject<br/>DATA-ACCESS]
    N4[ec2:DescribeInstances<br/>LATERAL-MOVEMENT]
    N0 --> N1
    N1 --> N2
    N2 --> N3
    N3 --> N4

Timeline:
  1. `sts:GetCallerIdentity` (recon) from 203.0.113.42
     MITRE: T1087.004 — Account Discovery
  2. `iam:ListRoles` (privilege-escalation) from 203.0.113.42
     MITRE: T1069.002 — Permission Groups Discovery
  3. `s3:ListBuckets` (discovery) from 203.0.113.42
     MITRE: T1526 — Cloud Service Discovery
  4. `s3:GetObject` (data-access) from 198.51.100.7
     MITRE: T1530 — Data from Cloud Storage
  5. `ec2:DescribeInstances` (lateral-movement) from 198.51.100.7
     MITRE: T1580 — Cloud Infrastructure Discovery
```

The same graph is posted to Slack as an enhanced Block Kit alert with the Mermaid render (via mermaid.ink), timeline, MITRE techniques, and a risk score bar.

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

### Local demo (no AWS required)

```bash
./build/ghostiam deploy --local --count 5 --with-keys
./build/ghostiam status --local
./build/ghostiam simulate --local --username ghost-prod-db-read-a7f3c2 --journey
```

## Commands

### `ghostiam deploy`

Deploy ghost IAM users into your AWS account (or into `ghosts.json` with `--local`).

| Flag | Shorthand | Default | Description |
|------|-----------|---------|-------------|
| `--count` | `-c` | `10` | Number of ghost users to create |
| `--prefix` | `-p` | `prod` | Name prefix for ghost users (e.g. `ghost-prod-...`) |
| `--region` | `-r` | `us-east-1` | AWS region |
| `--with-keys` | | `false` | Generate access keys for each ghost user |
| `--local` | `-l` | `false` | Use local JSON store instead of AWS IAM |

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
| `--local` | `-l` | `false` | Look up the ghost in `ghosts.json` |
| `--journey` | | `false` | Capture and visualize the attacker journey |

### `ghostiam seed`

Automatically "leak" ghost access keys to realistic bait locations.

```bash
ghostiam seed github     # private repo -> committed keys -> flipped public
ghostiam seed s3         # public S3 bucket with config.json + backup.sql
ghostiam seed pastebin   # local Pastebin-style leak (pastebin-sim.html)
ghostiam seed all        # try every platform

ghostiam seed github --ghost-user ghost-prod-db-read-a7f3c2
```

Credentials used per platform: `GITHUB_TOKEN` for GitHub, standard AWS credentials for S3. Missing credentials fail gracefully while other platforms continue.

### `ghostiam mesh`

Deploy the same ghost persona across AWS + GitHub + Okta.

```bash
ghostiam mesh deploy --count 2 --prefix demo --platforms all
ghostiam mesh status
```

Platforms without live credentials are simulated locally so the demo always works.

### `ghostiam journey` and `ghostiam replay`

Generate, visualize, and replay attacker journeys.

```bash
ghostiam journey --username ghost-prod-db-read-a7f3c2
ghostiam replay --file attack-journey-2026-08-07.json
```

### `ghostiam dashboard`

Serve the GhostIam operations console.

| Flag | Shorthand | Default | Description |
|------|-----------|---------|-------------|
| `--port` | `-p` | `8080` | HTTP port to listen on |
| `--api-key` | | *(env `GHOSTIAM_API_KEY`)* | Shared API key; omit for open access |
| `--db` | | `ghosts.db` | Path to the SQLite database |

```bash
ghostiam dashboard --port 8080 --api-key demo-key
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

With `--journey`, the enhanced alert adds the Mermaid attack graph, MITRE ATT&CK mappings, a risk score bar, and a "view journey" link.

## Requirements

- Go 1.25+
- AWS account with CloudTrail enabled (AWS mode only)
- Terraform 1.5+ (detection infra only)
- Slack workspace (for a webhook URL)
- `GITHUB_TOKEN` (only for GitHub seeding / mesh)

## Roadmap

- [x] AWS IAM ghost users
- [x] Local JSON store mode (`--local`)
- [x] Ghost token seeder (GitHub, S3, Pastebin)
- [x] Cross-platform ghost mesh (AWS + GitHub + Okta)
- [x] Attacker journey replay + MITRE ATT&CK mapping
- [x] Web dashboard (live alerts, journeys, mesh, seeds, reports)
- [ ] Multi-cloud support (Azure, GCP)
- [ ] Okta real-org provisioning
- [ ] Security Hub integration

## Contributing

Contributions are welcome! Fork the repo, create a feature branch, and open a pull request. A detailed contribution guide is coming soon — see [CONTRIBUTING.md](CONTRIBUTING.md).

New decoy policy templates are the easiest first contribution: add a template to `pkg/templates/policies.go`, give it a short name in `pkg/deploy/deploy.go`, and open a PR.

## License

MIT License — Copyright (c) 2026 Kakashi. See [LICENSE](LICENSE) for details.

## Author

Built by [@kakashi-kx](https://github.com/kakashi-kx)
