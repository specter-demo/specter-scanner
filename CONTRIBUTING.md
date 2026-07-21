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

### RFC 8693 detection does not exist (updated 2026-07-21)

Three related edge/signal-resolution gaps were found together on 2026-07-21 investigating why a correctly-provisioned cross-account `sts:AssumeRole` relationship produced zero delegation edges. Two are now fixed:

- ~~`staticref.resolveTarget` only matches by `ExternalID`/`PublicURL`, never by `IAMRoleARN`~~ — **fixed**: `resolveTarget` now also matches by `IAMRoleARN` (exact match only, no fuzzy prefix matching). Live-validated against `DataPipeline-Orchestrator`'s real grant on `ReportGen-Nightly`'s role.
- ~~`deduplicateFindings` keyed only on `(AgentStableID, RuleID)`, silently dropping genuinely distinct findings~~ — **fixed**: `AGENT_UNRESOLVED_DEPENDENCY` findings now also key on the referenced target from `EvidenceJSON`. Deliberately narrow — every other rule's dedup behavior, including the intentional `MISSING_INTENT_DECLARATION` collapse (independently emitted by both the AWS Bedrock check and staticref's generic check for the same agent), is unchanged. Live-validated both directions.

The third remains open:

- **`NormalizedEvent.RFC8693Present` is defined but never set anywhere in the codebase — confirmed by exhaustive repo-wide search.** `chain.Reconstruct`'s RFC 8693 CloudTrail-confirmation check (`internal/chain/chain.go`) reads this field to upgrade a hop's compliance status from a real observed AssumeRole event, but nothing has ever populated it. **Scope, confirmed:** `chain.go` and the `RFC8693Compliant` field both date to the initial scanner release (2026-05-20). Since no code produced an `EdgeTypeSTSAssume` edge at all until the `sts:AssumeRole` allowlist fix, `RFC8693Compliant` was constantly `false` for every chain with at least one hop, in every report this scanner has ever generated, for its entire history to date. As of that fix it can be `true`, but only from the edge's static type (an IAM policy grant existing), never from an actual observed CloudTrail AssumeRole call.
  **What the field was actually meant to detect, investigated 2026-07-21:** the spec docx's `NormalizedEvent` struct definition says only `RFC8693Present bool // true if token exchange metadata is in the event`, with a companion `OnBehalfOf` field that's equally never set. No design doc, comment, or spec section anywhere connects this to a concrete AWS (or GitHub) implementation. This is case (c), genuinely never specified beyond the field name — not a lost design that needs recovering. Worth being explicit about a second, independent problem even if detection were built: AWS STS `AssumeRole` doesn't implement OAuth 2.0 Token Exchange (RFC 8693) at all — it's a different, proprietary AWS mechanism. `sts:SourceIdentity` propagation is a real, close *analog* (preserving actor identity across a delegation chain), but using it would mean relabeling the badge (e.g. "Identity chain preserved (sts:SourceIdentity)"), not just implementing detection and keeping the "RFC 8693" name — that name would still be a mislabel of a different mechanism.
  The customer-facing label itself was fixed on 2026-07-21 (specter-platform, not this repo) — every "RFC 8693: NON-COMPLIANT" / "RFC 8693 VIOLATION" badge across the report, PDF, and dashboard now reads "NOT EVALUATED" rather than presenting `RFC8693Compliant` as a real evaluation result. Detection itself is still unbuilt; the `sts:SourceIdentity` analog above is a proposed design, not a decided one — needs a decision before implementation.

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
