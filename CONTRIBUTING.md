# Contributing to GhostIam

Thanks for considering a contribution — GhostIam is a young project and every improvement, big or small, helps.

Before opening a large PR, please open an issue first to discuss the approach. This avoids wasted effort on a design that doesn't fit the project.

**Security-sensitive changes** (auth, credential handling, the seeder, mesh, or dashboard middleware) should follow the process in [SECURITY.md](SECURITY.md), not a public PR, if they involve a vulnerability rather than a hardening improvement.

## Ways to contribute

- **New decoy policy templates** — the easiest first PR. See [Adding a decoy policy](#adding-a-decoy-policy) below.
- **Bug fixes** — check open issues, or file one if you've found something.
- **New seeder platforms** (beyond GitHub / S3 / Pastebin) — implement the `seeder.Platform` interface in `pkg/seeder/`.
- **New mesh platforms** (beyond AWS / GitHub / Okta) — see `pkg/mesh/`.
- **Multi-cloud support** (Azure, GCP) — see the Roadmap in README.md; this is a larger effort, open an issue first.
- **Documentation** — README clarity, command examples, architecture diagrams.
- **Tests** — the `seeder`, `mesh`, and `deploy` packages currently have no test coverage; PRs adding tests there are especially welcome.

## Development setup

```bash
git clone https://github.com/kakashi-kx/ghostiam
cd ghostiam
go mod download
make build
```

Run the full test suite:

```bash
go test ./...
```

Run the linter and vet before opening a PR:

```bash
go vet ./...
gofmt -l .          # should print nothing; if it does, run `gofmt -w .`
```

### Local dev loop (no AWS account needed)

```bash
./build/ghostiam deploy --local --count 5 --with-keys
./build/ghostiam simulate --local --username <ghost-username> --journey
./build/ghostiam dashboard --port 8080 --api-key dev-key
```

## Code style

- Standard Go formatting (`gofmt`) — no exceptions.
- Exported types and functions get doc comments (see existing packages for the tone/format used).
- Prefer small, focused functions; the codebase currently favors composability over deep inheritance-style abstractions — keep it that way.
- No new third-party dependencies without a good reason — check `go.mod` first; a dependency should earn its place.
- Errors are wrapped with context (`fmt.Errorf("...: %w", err)`), not swallowed or logged-and-ignored.
- SQL goes through parameterized queries only — no string-built SQL, ever.
- No `os/exec` calls unless genuinely unavoidable — this is a security tool; auditors will look here first.

## Adding a decoy policy

1. Add the policy JSON/template to `pkg/templates/policies.go`.
2. Register a short name for it in `pkg/deploy/deploy.go`.
3. Add a row to the Decoy Policies table in `README.md` describing what an attacker would *think* it grants vs. what it actually grants — the gap between those two is the entire point of a decoy policy, so be deliberate about it.
4. Add a test confirming the policy only grants read-level permissions (no `Create`, `Put`, `Delete`, or `*` actions).

## Commit messages

Use a short, imperative summary line, optionally with a `type:` prefix matching the existing history (`fix:`, `feat:`, `docs:`, `test:`, `chore:`). Example:

```
fix: protect SSE stream with auth, constant-time api key comparison
```

## Pull request checklist

- [ ] `go build ./...` and `go vet ./...` pass
- [ ] `go test ./...` passes, and you added tests for new behavior
- [ ] `gofmt -l .` is clean
- [ ] README/command reference updated if you changed CLI flags or added a command
- [ ] No secrets, real AWS credentials, or `.db`/`ghosts.json` artifacts committed
- [ ] PR description explains *why*, not just *what* — especially for anything touching auth, the seeder, or credential generation

## Reporting bugs

Open a GitHub issue with:
- What you ran (command + flags)
- What you expected vs. what happened
- Go version (`go version`) and OS
- Whether you're in `--local` mode or against real AWS

If it's a security vulnerability rather than a bug, please see [SECURITY.md](SECURITY.md) instead of filing a public issue.

## Code of conduct

Be respectful, assume good faith, and keep discussion focused on the technical merits. Disagreements about approach are normal and welcome — personal attacks are not.
