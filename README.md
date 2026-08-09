# 👻 GhostIam

**Ghost users. Real alerts. Zero false positives.**

GhostIam deploys decoy IAM identities across your AWS account that look like privileged credentials. Nobody legitimate ever touches them — so the instant an attacker enumerates or uses one during reconnaissance, CloudTrail fires a Slack alert within seconds, backed by a full MITRE ATT&CK-mapped kill chain.

[![Go Version](https://img.shields.io/badge/Go-1.25+-00ADD8.svg)](https://go.dev)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/kakashi-kx/ghostiam?color=brightgreen)](https://github.com/kakashi-kx/ghostiam/releases)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)
[![Security Policy](https://img.shields.io/badge/security-policy-blue.svg)](SECURITY.md)

<p align="center">
  <img src="docs/screenshots/Screenshot 2026-08-07 202944.png" alt="GhostIam operations dashboard" width="90%">
</p>

---

## Why GhostIam

Most detection rules chase behavior — anomalous logins, unusual API volume, impossible travel — and all of that produces noise. GhostIam flips the model: it plants identities that **have no legitimate reason to ever be touched**. There's no baseline to tune, no threshold to calibrate. If a ghost user's key is used, or a ghost username shows up in an `iam:List*` call, that's not "suspicious" — it's an attacker.

- **Zero false positives.** A ghost identity has no owner, no CI job, no scheduled task referencing it. Any touch is signal.
- **Deception that survives scrutiny.** Ghost users carry realistic decoy IAM policies — an attacker who finds the keys believes they've struck gold, right up until every action they take is logged and alerted on.
- **Detection in seconds, not a SIEM query away.** CloudTrail → EventBridge → Lambda → Slack, with no polling.

## What's inside

| Layer | What it does |
|---|---|
| **Ghost Deploy** | Creates decoy IAM users (AWS or `--local` JSON store) tagged and named to look like real privileged accounts |
| **Detection Pipeline** | Terraform-deployed Lambda + EventBridge rule that catches any CloudTrail event from a ghost identity and posts to Slack in seconds |
| **Token Seeder** | Auto-"leaks" ghost keys to realistic bait — public GitHub repos, public S3 buckets, Pastebin-style dumps |
| **Ghost Mesh** | Deploys one persona across AWS IAM + GitHub + Okta, so a fire on any platform correlates and flags the whole identity |
| **Journey Replay** | Turns a fired ghost into a MITRE ATT&CK-mapped kill chain — Mermaid graph, risk score, full timeline |
| **Web Dashboard** | Real-time ops console (Go + HTMX + SQLite + Chart.js) with live SSE-streamed alerts, journey visualization, and a REST API |

<table>
<tr>
<td width="50%">
<img src="docs/screenshots/Screenshot 2026-08-07 203121.png" alt="Attacker journey kill chain with MITRE mappings">
<p align="center"><sub>Attacker journey — kill chain reconstructed with MITRE ATT&CK mapping</sub></p>
</td>
<td width="50%">
<img src="docs/screenshots/Screenshot 2026-08-07 203732.png" alt="Mermaid attack graph">
<p align="center"><sub>Same journey, rendered as a Mermaid flow diagram</sub></p>
</td>
</tr>
</table>

## Quickstart (5 minutes, no AWS required)

```bash
# 1. Clone and build
git clone https://github.com/kakashi-kx/ghostiam
cd ghostiam
make build

# 2. Deploy ghost users locally (no AWS account needed to try it)
./build/ghostiam deploy --local --count 5 --with-keys

# 3. Simulate an attacker touching one
./build/ghostiam simulate --local --username ghost-prod-db-read-a7f3c2 --journey

# 4. Watch it live
./build/ghostiam dashboard --port 8080 --api-key demo-key
# open http://localhost:8080
```

### Going live in a real AWS account

```bash
export SLACK_WEBHOOK_URL="https://hooks.slack.com/..."
make deploy-lambda                                   # Terraform: Lambda + EventBridge + IAM role
./build/ghostiam deploy --count 20 --prefix prod      # real decoy IAM users
./build/ghostiam simulate --username ghost-prod-db-read-a7f3c2   # trigger + verify Slack alert
```

> CloudTrail must be enabled — it's on by default in every AWS account, so this typically works with zero extra setup.


## Architecture

### Detection Flow — AWS Mode

```mermaid
flowchart TD
    CLI["🔧 CLI<br/>ghostiam deploy"] -->|creates| IAM["👻 IAM Ghost Users<br/>ghost-prod-db-read-a7f3<br/>ghost-admin-backup-c2b8<br/>Tag: GhostIam=true"]
    IAM -->|idle, waiting| IDLE["⏳ Ghosts sit dormant<br/>Zero cost, zero noise"]
    ATK["🕵️ Attacker finds<br/>and uses ghost creds"] -->|triggers| CT["AWS CloudTrail<br/>Captures API call"]
    CT --> EB["Amazon EventBridge<br/>Filters: GhostIam=true"]
    EB --> LAMBDA["⚡ AWS Lambda<br/>Go runtime, 128MB<br/>Parses + enriches event"]
    LAMBDA --> SLACK["🟢 Slack Alert<br/>👻 GHOST USER ACTIVATED<br/>< 2 seconds"]
    LAMBDA --> DASH["📊 Dashboard<br/>SSE real-time feed<br/>+ journey graph"]
    DASH --> SSE["🔄 Live updates<br/>no page refresh"]
    
    style CLI fill:#22c55e,stroke:#166534,color:#fff
    style IAM fill:#3b82f6,stroke:#1e40af,color:#fff
    style ATK fill:#ef4444,stroke:#991b1b,color:#fff
    style LAMBDA fill:#f59e0b,stroke:#92400e,color:#fff
    style SLACK fill:#8b5cf6,stroke:#5b21b6,color:#fff
    style DASH fill:#06b6d4,stroke:#155e75,color:#fff
```

### Attack Journey — Kill Chain Visualization

```mermaid
flowchart LR
    subgraph RECON["🔍 RECONNAISSANCE"]
        S1["sts:GetCallerIdentity<br/>Who am I?"]
    end
    
    subgraph DISCOVERY["📋 DISCOVERY"]
        S2["iam:ListRoles<br/>What can I access?"]
        S3["s3:ListBuckets<br/>Where's the data?"]
    end
    
    subgraph ACCESS["📥 DATA ACCESS"]
        S4["s3:GetObject<br/>Exfiltrate data"]
    end
    
    subgraph PERSIST["🔑 PERSISTENCE"]
        S5["iam:CreateAccessKey<br/>Plant backdoor"]
    end
    
    S1 -->|"T1087.004"| S2
    S2 -->|"T1069.002"| S3
    S3 -->|"T1526"| S4
    S4 -->|"T1530"| S5
    
    S5 -.->|"🚨 GHOST TRIGGERED<br/>Risk: 10/10 CRITICAL"| ALERT["🟢 Slack + 📊 Dashboard"]
    
    style RECON fill:#f9f9ff,stroke:#6366f1,color:#1e1b4b
    style DISCOVERY fill:#fef3c7,stroke:#d97706,color:#78350f
    style ACCESS fill:#fee2e2,stroke:#dc2626,color:#7f1d1d
    style PERSIST fill:#fce7f3,stroke:#db2777,color:#831843
    style ALERT fill:#ef4444,stroke:#991b1b,color:#fff
```

### Cross-Platform Ghost Mesh

```mermaid
flowchart TD
    PERSONA["👤 ghost-prod-admin-a7f3<br/>One persona, three platforms"]
    
    PERSONA --> AWS["🔶 AWS IAM<br/>ghost user + decoy policy"]
    PERSONA --> GH["🐙 GitHub<br/>contractor profile<br/>alex-ghost-dev"]
    PERSONA --> OKTA["🔐 Okta<br/>fake employee<br/>alex.johnson@fake.com"]
    
    AWS --> CORR{"💥 Any platform<br/>gets triggered"}
    GH --> CORR
    OKTA --> CORR
    
    CORR --> ALERT["🚨 CORRELATED ALERT<br/><br/>'ghost-prod-admin-a7f3<br/>fired on AWS.<br/>Also exists on GitHub + Okta.<br/>Check all 3 platforms.'"]
    
    ALERT --> SLACK2["🟢 Slack"]
    ALERT --> DASH2["📊 Dashboard"]
    
    style PERSONA fill:#8b5cf6,stroke:#5b21b6,color:#fff
    style AWS fill:#f97316,stroke:#9a3412,color:#fff
    style GH fill:#333,stroke:#666,color:#fff
    style OKTA fill:#06b6d4,stroke:#155e75,color:#fff
    style CORR fill:#f59e0b,stroke:#92400e,color:#fff
    style ALERT fill:#ef4444,stroke:#991b1b,color:#fff
```

### Local Mode — Zero AWS Dependencies

```mermaid
flowchart TD
    DEPLOY["🔧 ghostiam deploy --local"] -->|"writes"| JSON["📄 ghosts.json<br/>local JSON store"]
    SIM["🔧 ghostiam simulate --local<br/>--username ghost-xxx --journey"] -->|"reads"| JSON
    SIM -->|"HTTP POST"| DASHBOARD["📊 Dashboard<br/>localhost:8080"]
    SIM -->|"webhook"| SLACK3["🟢 Slack Alert"]
    
    DASHBOARD -->|"SSE stream"| BROWSER["🌐 Browser<br/>real-time updates"]
    DASHBOARD -->|"SQLite"| DB["🗄️ ghosts.db<br/>persistent storage"]
    
    DASHBOARD -->|"renders"| CHARTS["📈 Charts<br/>• Alert Severity (donut)<br/>• Top Actions (bar)<br/>• Traffic 24h (line)"]
    
    DASHBOARD -->|"renders"| JOURNEY["🗺️ Journey Viewer<br/>• Mermaid graph<br/>• MITRE ATT&CK mapping<br/>• Kill-chain timeline"]
    
    style DEPLOY fill:#22c55e,stroke:#166534,color:#fff
    style JSON fill:#a855f7,stroke:#6b21a8,color:#fff
    style DASHBOARD fill:#06b6d4,stroke:#155e75,color:#fff
    style SLACK3 fill:#8b5cf6,stroke:#5b21b6,color:#fff
    style BROWSER fill:#3b82f6,stroke:#1e40af,color:#fff
    style CHARTS fill:#f59e0b,stroke:#92400e,color:#fff
    style JOURNEY fill:#ec4899,stroke:#be185d,color:#fff
```

### Token Seeder — Bait Distribution

```mermaid
flowchart LR
    KEYS["🔑 Ghost Access Keys<br/>generated with --with-keys"] --> SEEDER["🎣 Token Seeder<br/>ghostiam seed all"]
    
    SEEDER --> GITHUB["🐙 GitHub<br/>fake 'accidentally public' repo<br/>config.json with creds"]
    SEEDER --> S3["🪣 AWS S3<br/>public bucket<br/>company-prod-backups-xxx"]
    SEEDER --> PASTE["📋 Pastebin<br/>simulated leak<br/>pastebin-sim.html"]
    
    GITHUB --> SCAN["🕵️ Attacker scans<br/>GitHub for leaked keys"]
    S3 --> SCAN2["🕵️ Attacker scans<br/>public S3 buckets"]
    PASTE --> SCAN3["🕵️ Attacker finds<br/>pastebin dumps"]
    
    SCAN & SCAN2 & SCAN3 --> USE["💥 Attacker uses<br/>the ghost keys"]
    USE --> TRAP["🚨 GHOST TRIGGERED<br/>Alert fires in < 2s"]
    
    style KEYS fill:#f59e0b,stroke:#92400e,color:#fff
    style SEEDER fill:#22c55e,stroke:#166534,color:#fff
    style TRAP fill:#ef4444,stroke:#991b1b,color:#fff
```

### Full Platform Overview

```mermaid
flowchart TB
    subgraph INPUT["🎮 Control Plane"]
        CLI2["🔧 CLI<br/>deploy · simulate · seed<br/>mesh · status · clean<br/>journey · replay · dashboard"]
        DASH3["📊 Web Dashboard<br/>HTMX + SSE + Chart.js<br/>SQLite backend"]
    end
    
    subgraph GHOSTS["👻 Ghost Layer"]
        AWS_G["AWS IAM<br/>decoy users + policies"]
        GIT_G["GitHub<br/>machine users + repos"]
        OKTA_G["Okta<br/>fake employee profiles"]
        LOCAL_G["Local JSON<br/>ghosts.json"]
    end
    
    subgraph DETECT["🎯 Detection Layer"]
        CTRAIL["AWS CloudTrail"]
        EVENTBR["Amazon EventBridge"]
        LAMBDA2["AWS Lambda<br/>Go runtime"]
        LOCAL_D["Local Alert Engine<br/>direct Slack + SSE"]
    end
    
    subgraph OUTPUT["📢 Outputs"]
        SLACK4["🟢 Slack<br/>Block Kit alerts"]
        DASH4["📊 Dashboard<br/>live SSE feed"]
        PDF["📄 PDF Reports"]
        JSON_R["📋 JSON Export"]
        MERMAID["🗺️ Mermaid<br/>attack graphs"]
        MITRE["🎯 MITRE ATT&CK<br/>technique mapping"]
    end
    
    CLI2 --> GHOSTS
    DASH3 --> GHOSTS
    GHOSTS --> DETECT
    DETECT --> OUTPUT
    
    style INPUT fill:#1e293b,stroke:#475569,color:#e2e8f0
    style GHOSTS fill:#312e81,stroke:#4338ca,color:#e0e7ff
    style DETECT fill:#701a75,stroke:#a21caf,color:#fae8ff
    style OUTPUT fill:#14532d,stroke:#16a34a,color:#dcfce7
```


---


## Web Dashboard

Serve the operations console with `ghostiam dashboard --port 8080 --api-key <key>`. Every page is authenticated with a shared API key (cookie, `?api_key=`, or `X-API-Key` header) and updates live over Server-Sent Events — no polling, no refresh.

<img src="docs/screenshots/Screenshot 2026-08-07 203035.png" alt="Live alert feed with severity badges">

| Page | What it shows |
|---|---|
| **Dashboard** | Live stat cards, alert traffic by hour, severity donut, top actions, live alert feed |
| **Ghosts** | Deploy/archive decoys from the browser, inspect keys and attached policies |
| **Alerts** | Full alert feed with severity badges, source IPs, and a one-click alert simulator |
| **Journeys** | Attack kill-chains as step timelines with MITRE tactics and Mermaid flow diagrams |
| **Mesh** | Correlated personas shown as platform-leg cards (AWS / GitHub / Okta) |
| **Seeds** | Bait locations, keys, and files — recorded automatically or by hand |

```bash
export GHOSTIAM_DASHBOARD_URL=http://localhost:8080
export GHOSTIAM_DASHBOARD_KEY=demo-key
ghostiam simulate --local --username ghost-...   # pushes an alert to the dashboard
ghostiam seed pastebin --ghost-user ghost-...    # pushes a seed
ghostiam journey --username ghost-...            # pushes a journey
```

Reports export via `/reports/export?format=json|pdf`. A REST API is exposed at `/api/v1/stats|ghosts|alerts|journeys`.

## Commands

### `ghostiam deploy`

Deploy ghost IAM users into your AWS account (or `ghosts.json` with `--local`).

| Flag | Shorthand | Default | Description |
|---|---|---|---|
| `--count` | `-c` | `10` | Number of ghost users to create |
| `--prefix` | `-p` | `prod` | Name prefix (e.g. `ghost-prod-...`) |
| `--region` | `-r` | `us-east-1` | AWS region |
| `--with-keys` | | `false` | Generate access keys for each ghost user |
| `--local` | `-l` | `false` | Use local JSON store instead of AWS IAM |

### `ghostiam simulate`

Simulate attacker activity against a ghost to trigger detection.

| Flag | Shorthand | Default | Description |
|---|---|---|---|
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
```

Credentials used per platform: `GITHUB_TOKEN` for GitHub, standard AWS credentials for S3. A missing credential for one platform fails gracefully; the rest continue.

### `ghostiam mesh`

```bash
ghostiam mesh deploy --count 2 --prefix demo --platforms all
ghostiam mesh status
```

Platforms without live credentials simulate locally, so the demo always works.

### `ghostiam journey` / `ghostiam replay`

```bash
ghostiam journey --username ghost-prod-db-read-a7f3c2
ghostiam replay --file attack-journey-2026-08-07.json
```

### `ghostiam dashboard`

| Flag | Shorthand | Default | Description |
|---|---|---|---|
| `--port` | `-p` | `8080` | HTTP port to listen on |
| `--api-key` | | *(env `GHOSTIAM_API_KEY`)* | Shared API key; omit for open access |
| `--db` | | `ghosts.db` | Path to the SQLite database |

## Decoy Policies

Each ghost user carries one of five decoy policies. They *look* valuable; they grant only read-only permissions.

| Name | What attackers think it grants | What it actually grants |
|---|---|---|
| `ProdDatabaseReadAccess` | Read access to prod DB backups/snapshots | Only `Describe` on RDS/DynamoDB — no data access |
| `CloudInfrastructureViewer` | Full infrastructure visibility | Only `List`/`Describe` on EC2, VPC, Lambda |
| `S3BackupOperator` | Access to backup buckets | Only bucket listing/metadata — no object access |
| `IAMSecurityAuditor` | IAM admin audit access | Only `List`/`Get` on IAM — cannot create users or keys |
| `CrossAccountAccessRole` | Cross-account trust bridge | Only `sts:GetCallerIdentity` + org structure reads |

The deception gap is the point: an attacker who finds these keys believes they've struck gold, and every attempt to use them is your detection event.

## Detection Infrastructure

`terraform/` deploys:

- **Lambda** (`ghostiam-detector`, Go on `provided.al2023`, 128MB, 10s timeout) — parses the CloudTrail event, posts a Slack Block Kit alert
- **EventBridge rule** (`ghostiam-capture-ghost-activity`) — filters CloudTrail events where `userName` starts with `ghost-`
- **IAM role** (`ghostiam-detector-role`) — CloudWatch Logs write access only
- **Lambda permission** — lets EventBridge invoke the detector

## Security

GhostIam handles realistic-looking AWS credentials and a dashboard exposing live detection data — treat it like the security tool it is. Please see [SECURITY.md](SECURITY.md) for the vulnerability disclosure process and hardening notes (API key auth model, SSE stream auth, local store file permissions).

**Do not** run the dashboard with `--api-key` omitted on anything but `localhost` — that disables auth entirely.

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

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for dev setup, code style, and the PR process. New decoy policy templates are the easiest first contribution: add a template to `pkg/templates/policies.go`, name it in `pkg/deploy/deploy.go`, open a PR.

## License

MIT License — Copyright (c) 2026 Kakashi. See [LICENSE](LICENSE).

## Author

Built by [@kakashi-kx](https://github.com/kakashi-kx)
