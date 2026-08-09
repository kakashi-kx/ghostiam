# Security Policy

GhostIam is a security tool that generates realistic-looking AWS credentials, seeds them as bait across public platforms, and runs a web dashboard exposing live detection data. Treat vulnerabilities in it seriously — a bug here doesn't just affect the tool, it can undermine the detection it's supposed to provide.

## Supported versions

| Version | Supported |
|---|---|
| `main` / latest tagged release | ✅ |
| Older tagged releases | ❌ (please upgrade) |

This project is pre-1.0 and moving fast; only the latest release receives security fixes. There is no long-term support branch at this time.

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report privately using one of:

1. **GitHub Private Vulnerability Reporting** (preferred) — go to the [Security tab](https://github.com/kakashi-kx/ghostiam/security/advisories/new) on this repo and open a new draft security advisory. This keeps the report private until a fix ships and gives you credit via a proper GitHub Security Advisory (GHSA) once disclosed.
2. **Email** — `kakashi4kx@gmail.com`, with `GHOSTIAM SECURITY` in the subject line.

Please include:
- A clear description of the vulnerability and its impact
- Steps to reproduce (a minimal PoC is ideal — CLI commands, dashboard requests, etc.)
- Affected version/commit
- Whether it requires local mode, real AWS credentials, or dashboard network access to exploit

### What to expect

- **Acknowledgment** within a few days of your report.
- I'll work with you on a fix and coordinate a disclosure timeline — generally aiming for a fix within 2–4 weeks depending on severity, sooner for critical issues.
- Credit given in the release notes and GHSA (unless you'd prefer to stay anonymous — just say so).

### Out of scope

- Vulnerabilities in third-party dependencies (`go.mod`) — please report those upstream; I'll pull in the fix once available, but feel free to also flag it here if it's exploitable through GhostIam specifically.
- Findings that require the operator to have already misconfigured the tool against its documented guidance (e.g., running the dashboard with `--api-key` omitted on a non-localhost interface — this is documented as disabling auth, not a vulnerability in itself, though see below).
- Social engineering, physical access, or attacks requiring compromise of the operator's AWS account itself (rather than GhostIam's own code).

## Security model & hardening notes

A few things worth knowing if you're deploying this or auditing it:

- **Dashboard auth is a single shared API key**, checked via cookie → `?api_key=` query param → `X-API-Key` header, using a constant-time comparison (`crypto/subtle`). Every route is gated behind it except when `--api-key` is omitted entirely, which intentionally disables auth (documented for local-only/demo use — don't do this on a network-reachable interface).
- **The SSE stream (`/alerts/stream`) requires the same auth as every other route.** This was previously a bypass (fixed in `be4a14e`) — if you're running an older build, upgrade.
- **Ghost access keys are realistic but scoped read-only.** Every decoy policy in `pkg/templates/policies.go` grants only `List`/`Describe`/`Get`-class permissions — never `Create`, `Put`, `Delete`, or wildcard actions. If you add a new policy, this constraint is non-negotiable (see [CONTRIBUTING.md](CONTRIBUTING.md)).
- **Local credential storage.** `ghosts.json` and `ghosts.db` (SQLite) can contain realistic-looking secret access keys and are written with `0600` permissions. Don't commit them — they're already in `.gitignore`, but double-check before pushing from a fork.
- **Seeding is intentional exposure.** `ghostiam seed` deliberately publishes bait credentials to GitHub, S3, and Pastebin-style targets. This is the tool working as designed, not a vulnerability — but it does mean `GITHUB_TOKEN` and AWS credentials used for seeding should be scoped to only what's needed for that operation.
- **No shell-out.** GhostIam does not call `os/exec` anywhere in the codebase. If a future PR introduces one, treat it as a high-priority review item.

## Disclosure credit

Security researchers who responsibly disclose a valid issue will be credited in the fix's release notes and the GHSA, unless anonymity is requested.
