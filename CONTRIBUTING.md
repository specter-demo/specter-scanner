# Contributing to Specter Scanner

Thank you for your interest in contributing to Specter Scanner. This document explains how to contribute effectively.

## Before you start

- Check [open issues](https://github.com/spectersystems/specter-scanner/issues) to see if your idea or bug is already being tracked
- For significant changes, open an issue first to discuss the approach before writing code
- All contributions are subject to the [Apache 2.0 License](LICENSE)

## Development setup

```bash
git clone https://github.com/spectersystems/specter-scanner
cd specter-scanner
go mod download
go build ./...
go test ./...
```

Requires Go 1.22 or later.

## Running tests

```bash
# Unit tests
make test

# Integration test against demo agents (requires AWS credentials)
make test-demo
```

All pull requests must pass `make test` with zero failures.

## Adding a new plugin

Plugins discover agents from a specific platform or data source. To add a new plugin:

1. Create `internal/plugin/yourplugin/yourplugin.go`
2. Implement the `ScanPlugin` interface from `internal/plugin/interface.go`
3. Register the plugin in `cmd/scanner/main.go`
4. Add unit tests — minimum coverage for happy path, empty result, and error cases
5. Add the plugin to the README discovery section
6. Submit a pull request

### Plugin implementation checklist

Before submitting a plugin PR, verify:

- [ ] Uses canonical resource identifiers as `externalId` (full ARNs for AWS, full URLs for others)
- [ ] Calls the platform's identity API for real account/org IDs — never uses config strings as resource identifiers
- [ ] Reads owner declarations from tags or manifest files before firing NHI findings
- [ ] Returns enrichment data for existing agents rather than creating duplicate records for matched resources
- [ ] Handles empty results gracefully (no agents found is valid, not an error)
- [ ] Rate-limits external API calls using the configured `--rate-limit` value
- [ ] Does not store credentials — reads from environment variables only
- [ ] Unit tests cover: agent found with owner tag, agent found without owner tag, no agents found, API error

## Adding a new finding rule

Finding rules detect specific security or governance gaps. To add a new rule:

1. Add the rule ID and description to `internal/types/findings.go`
2. Implement the detection logic in the appropriate plugin
3. Add unit tests covering: condition present (finding fires), condition absent (finding does not fire), owner tag present (NHI findings suppressed)
4. Add the rule to the findings table in `README.md`
5. Document the remediation path in the finding description

## Known gaps

- **`internal/types/findings.go` does not exist.** The "Adding a new finding rule" section above references it as the canonical rule-ID registry, but rule IDs are currently just string literals scattered across each plugin file (e.g. `internal/plugin/aws/aws.go`, `internal/plugin/aws/cicd.go`). This is pre-existing documentation drift, not a recent regression — either adding the real registry file or fixing this doc is a good follow-up for anyone touching finding rules.
- **The GitHub plugin (`internal/plugin/github/github.go`) has zero unit test coverage.** Every other plugin's tests (see `internal/plugin/aws/aws_test.go`, `cicd_test.go`, `org_sso_test.go`) follow the bar described in "Adding a new plugin" above; the GitHub plugin does not yet meet it. This is a good first contribution — no design questions involved, just apply the same happy-path/empty-result/error-case pattern already established in the AWS plugin's tests.

### Edge/signal-resolution gaps (found together, 2026-07-21, tracked as a set)

Three related gaps surfaced investigating why a correctly-provisioned cross-account `sts:AssumeRole` relationship produced zero delegation edges (fixed in the commit adding `sts:assumerole` to `extractIAMPermissionRefs`'s allowlist). Tracked together since a fix to one is likely to touch the same code a fix to another would.

- **`NormalizedEvent.RFC8693Present` is defined but never set anywhere in the codebase — confirmed by exhaustive repo-wide search, not just in the paths touched by the `sts:AssumeRole` fix.** `chain.Reconstruct`'s RFC 8693 CloudTrail-confirmation check (`internal/chain/chain.go`) reads this field to upgrade a hop's compliance status from a real observed AssumeRole event, but nothing has ever populated it. **Scope, confirmed:** `chain.go` and the `RFC8693Compliant` field both date to the initial scanner release (2026-05-20). Since no code produced an `EdgeTypeSTSAssume` edge at all until the `sts:AssumeRole` allowlist fix, `RFC8693Compliant` was constantly `false` for every chain with at least one hop, in every report this scanner has ever generated, for its entire history to date — not a rare edge case, a constant. As of the allowlist fix it can now be `true`, but only from the edge's static type (an IAM policy grant existing), never from an actual observed CloudTrail AssumeRole call — `normalizeCloudTrailEvent` doesn't parse any RFC 8693 token-exchange signal from CloudTrail events at all today. A real fix means adding that parsing, not just flipping a flag.
- **`staticref.resolveTarget` only matches by `ExternalID`/`PublicURL`, never by `IAMRoleARN`.** An `sts:AssumeRole` ref's target is always an IAM role ARN, but `resolveTarget`'s lookup indexes only cover agents' function/service ARNs and public URLs. A real, scoped `sts:AssumeRole` grant on an already-known agent's own execution role can never resolve into an edge — confirmed live, `DataPipeline-Orchestrator` has a real grant on `ReportGen-Nightly`'s actual role ARN that doesn't resolve. It only resolves today when the target happens to be a synthesized bare-IAM-role agent whose `ExternalID` was deliberately set to its own role ARN (e.g. `scanCrossAccountTrustPolicies`'s cross-account fallback). Same family as the `sts:AssumeRole` allowlist fix — a real fix, not a design question: add a `byIAMRoleARN` index alongside `byExternalID`/`byPublicURL` in `resolveTarget`.
- **`deduplicateFindings` (`cmd/scanner/main.go`) keys only on `(AgentStableID, RuleID)`, silently dropping genuinely distinct findings — a data-integrity issue, not just a missed enhancement.** Multiple `AGENT_UNRESOLVED_DEPENDENCY` findings for the same agent pointing at different unresolved targets collapse to one in the standalone report path. Confirmed live: `DataPipeline-Orchestrator` has both a real dependency on a known agent's role and a stale grant referencing a role that no longer exists (`reportgen-nightly-role`, confirmed via IAM `GetRole` → `NoSuchEntity`) — only one of the two findings survives dedup, meaning a real, distinct finding is currently invisible in the standalone report. Fix: include a target/evidence-derived component in the dedup key, not just rule+agent.

## Pull request process

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/your-feature`
3. Write your code and tests
4. Run `make test` — all tests must pass
5. Run `go vet ./...` and `golint ./...` — no warnings
6. Commit with a clear message: `feat: add GCP Cloud Run plugin`
7. Open a pull request against `main`

Pull requests are reviewed within 5 business days. We may request changes before merging.

## Reporting bugs

Open an issue with:
- Specter Scanner version (`specter-scanner --version`)
- Operating system and Go version
- Steps to reproduce
- Expected behavior
- Actual behavior and error output

For security vulnerabilities, do not open a public issue — see [SECURITY.md](SECURITY.md).

## Code style

- Follow standard Go formatting: `gofmt -w .`
- Keep functions focused — if a function does more than one thing, split it
- Export only what external packages need
- Add comments on exported functions and types
- Avoid global state
