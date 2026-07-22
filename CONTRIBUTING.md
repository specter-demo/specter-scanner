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
- ~~The GitHub plugin (`internal/plugin/github/github.go`) has zero unit test coverage.~~ **Closed 2026-07-22** — `internal/plugin/github/github_test.go` added, covering framework detection (manifest patterns, config-file override, the Tier 2 confidence-boost stacking logic), Actions workflow analysis (`GITHUB_STATIC_AWS_CREDS`/`GITHUB_UNSCOPED_WORKFLOW` fire and no-fire cases), committed-secret detection (proven to call the shared `internal/plugin/shared` detector directly, not a parallel copy), static reference extraction (ARN/URL patterns — confirmed these are a separately-defined, textually-parallel copy of `internal/plugin/aws/aws.go`'s regexes, not shared code), intent/markdown extraction, and every other pure helper in the file. Same no-network-mocking convention as the AWS plugin's tests: functions that need a live `*gogithub.Client` (`Scan`, `scanRepo`, `fetchFileContent`, etc.) aren't tested directly, matching how `aws_test.go` treats functions needing a live AWS client.

  Two items from the original ask turned out not to exist in the codebase at the time, confirmed by a full-repo grep before writing any test: OIDC-to-agent correlation (`types.EdgeTypeOIDCDeploy` was defined with no producer) and `sk_config.yaml` (Semantic Kernel) config-file detection (no reference anywhere).

  - ~~OIDC-to-agent correlation~~ **Closed 2026-07-22** — `internal/plugin/aws/oidc.go` (`parseGitHubOIDCTrustSubjects`) parses a Lambda/ECS role's trust policy for a GitHub Actions OIDC federation statement (`sts:AssumeRoleWithWebIdentity` + a `Federated` principal on `token.actions.githubusercontent.com` + a `...:sub` condition), storing every matched subject claim on `CanonicalAgentRecord.OIDCTrustSubjects`. `internal/plugin/github/oidc.go` (`correlateOIDCDeployEdges`) then matches those subjects' org/repo (parsed via the cloud-agnostic `shared.ParseGitHubOIDCSubject`) against the repos that scan's GitHub Phase 2 actually found, emitting an `EdgeTypeOIDCDeploy` edge — specter-scanner-spec.docx §5.2 step 6. Live-validated against real infrastructure (not synthetic): `specter-demo-leadscore-prod-role`'s real trust policy (`repo:specter-demo/leadscorer:*`) correctly produced an edge to the real `LeadScorer-Prod` Lambda agent in a genuine single-invocation AWS+GitHub scan — a case the existing name-based correlation alone would have missed (`leadscorer` normalizes to neither an exact nor a prefix match against `LeadScorer-Prod`).

    This is the minimal real implementation the spec's §5.2 step 6 actually describes, not the full `NormalizedCredential`/`OIDC_FEDERATED` cross-cloud identity-normalization layer from specter-architecture.docx — that type exists in `internal/types/types.go` but has zero usages anywhere (dead code), and is a separate, larger, still-unbuilt design element (a credential-type classification for `ActivityStreamAdapter`-sourced runtime events, feeding the risk scorer) that this change deliberately does not build speculatively. `ActivityStreamAdapter` itself does already exist and is implemented by the AWS plugin (`FetchEvents` for CloudTrail) — but it's about audit-log event streaming, not IAM trust-policy correlation, and this feature has no dependency on it.

    Still open, and distinct from the above: (1) the workflow-level "OIDC usage sets a `GOVERNED` signal" mechanism from spec §5.2 step 1 (`wf.HasOIDC()`) — a different check than trust-policy correlation, still unbuilt; (2) `sk_config.yaml` detection.

- ~~`sensitiveActions` (`internal/plugin/aws/aws.go`, feeds `IAM_WILDCARD_RESOURCE`) never included `iam:PassRole` or `ecs:RunTask`, so a role granting either on `Resource: "*"` produced no finding at all — found 2026-07-22 while confirming the scope of the ECS `IAMRoleARN` fix above.~~ **Closed 2026-07-22.** Confirmed via git history this was never a deliberate exclusion at the generic-check level — `sensitiveActions` has been unchanged since introduction. It *was* a known, explicitly-reasoned gap at the CodeBuild-specific level: `scanCodeBuild`'s `hasWildcardPassRole` already checks `iam:PassRole` wildcard grants for CodeBuild service roles, with its own comment explaining why it built a separate check instead of adding the action to `sensitiveActions` (broad `PassRole` is common enough on ordinary, non-CI roles that folding it into the generic bucket would bury a genuinely distinct, well-known privilege-escalation vector). That reasoning argued for a *named* rule, not for leaving the general case undetected — extended here to every Lambda/ECS agent, as two new rules rather than one, so `ecs:RunTask`'s lower severity doesn't dilute `iam:PassRole`'s: **`IAM_PASSROLE_WILDCARD`** (HIGH) and **`ECS_RUNTASK_WILDCARD`** (MEDIUM), both added via `appendPassRoleAndRunTaskWildcardFindings`, called once against a role's fully-combined `IAMPermissions` (inline + managed) so a grant repeated across multiple policies produces one finding, not one per policy — unlike the sibling `appendSecretsManagerWildcardFinding`, which has no such dedup and wasn't touched here (out of scope).

  Live-validated against both demo AWS accounts, not assumed from the fix alone: re-scanned every agent with a real IAM role (10 in customer-demo, 2 in partner-demo, 12 total). Exactly two produced the new findings — `ShadowAnalytics-7f2a` (AWS_ECS) and `DataPipeline-Orchestrator` (AWS_LAMBDA) — because they share the same role (`specter-demo-datapipeline-orchestrator-role`), which genuinely does grant both actions on `Resource: "*"`. Notably, `DataPipeline-Orchestrator` is a Lambda agent that has always gone through `enrichIAMRole` — this finding was invisible on it long before tonight's ECS `IAMRoleARN` fix, confirming the `sensitiveActions` gap was independent of and broader than the ECS-specific issue that surfaced it. The other 10 agents (`ReportGen-Nightly`, `shadow-indexer`, `VaultReader-Agent`, `ComplianceAgent-Unguarded-StatusCheck`, `PipelineForge-DeployValidator`, `CrossAccountSync-Agent`, `LeadScorer-Prod`, `CustomerInsight-Orchestrator`, `internal-tools-mcp`, `PipelineForge-Prod` in customer-demo; `meridian-credit-signals-agent` and the cross-account sync target role in partner-demo) were confirmed via the same scan to genuinely not have either wildcard grant — not assumed clean, checked.

### Multi-account (Organizations) discovery — found live-validating on 2026-07-21

- **A member account whose `SpecterReadOnly` role was never deployed reports `AccountScanResult{Status: "SUCCESS"}` with zero agents, indistinguishable from "this account genuinely has nothing" — not `FAILED`.** Confirmed live: scanning the platform/management account itself (no `SpecterReadOnly` role there, by design — it doesn't need to assume a role into itself) through `ScanOrganization`, every sub-scan (`Lambda`, `ECS`, `Bedrock`, `CloudTrail`, `EventBridge`, `IAM`) failed with `AccessDenied: ... not authorized to perform: sts:AssumeRole`, yet the account-level result still showed `SUCCESS`. Root cause: `Plugin.Scan()`'s pre-existing `isCredentialError`/`allCredentialErrors` escalation (`internal/plugin/aws/aws.go`) only promotes a scan to a hard `AuthError` for a narrow set of credential-*format* errors (`InvalidClientTokenId`, `ExpiredToken`, etc.) — `AccessDeniedException` from a failed `sts:AssumeRole` isn't in that list, so `Scan()` returns `(result, nil)` with an empty, error-free result instead. `scanAccountsWithPartialFailure` (`internal/plugin/aws/organization.go`) inherits this blind spot faithfully, since it just checks whether `Scan()` returned an error. Not fixed here — doing so means either widening `isCredentialError` to treat permission-denial-on-assume as a hard failure (risk: could reclassify other legitimately-partial single-account scans too) or having `ScanOrganization` distinguish "assumed the role, then individual API calls were denied" from "never even assumed the role" — a real design decision, not a one-line fix.
- **`SpecterReadOnlyPolicy` (the per-member-account role's own permissions, `infra/phase3/modules/specter_readonly` and its phase5 copy in specter-platform) is missing several actions the scanner now calls**, confirmed live via real `AccessDeniedException`s during the same validation run: `codecommit:ListRepositories` at minimum (the CI/CD-surface actions added earlier tonight — CodeBuild/CodePipeline/CodeDeploy/ECR — weren't individually exercised in this run either, since neither demo account has that infra, but are equally absent from the policy). This is separate from `specter-scanner-task-role`'s own policy (which this session did extend, for `organizations:ListAccounts`/`sts:AssumeRole` into the new account) — this gap is in what each *member* account's role grants once assumed.
- **Bedrock agents' `ExternalID`/`StableID` aren't account-safe across a multi-account scan** (documented in code — `internal/plugin/aws/aws.go`, `scanBedrock`): they're built from `p.cfg.OrgID` rather than the real account number, for backward compatibility with already-persisted records. `AccountID` itself is now correctly populated per-account, but two Bedrock agents with the same underlying `agentID` in two different member accounts would still collide onto one `StableID`. Low real-world probability (Bedrock agent IDs are random), not fixed here because correcting it would change every already-persisted Bedrock agent's `StableID` — a breaking change to platform DB continuity that needs its own explicit decision.

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
