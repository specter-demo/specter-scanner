# Specter Scanner

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Go Version](https://img.shields.io/badge/Go-1.22+-blue.svg)](https://golang.org)

**Specter Scanner** is an open-source CLI tool that discovers, classifies, and audits AI agents running in your infrastructure. It scans AWS (Lambda, ECS, Bedrock), GitHub repositories, and probes A2A and MCP protocol endpoints to produce a complete inventory of every AI agent in your environment — governed, discovered, shadow, and unregistered — along with security findings and a risk assessment for each.

Specter Scanner is the open-core foundation of the [Specter Platform](https://spectersystems.ai), an AI agent identity governance platform. The scanner runs in your own infrastructure. Your agent inventory never leaves your environment unless you explicitly connect it to the platform.

---

## What it discovers

**AWS agents:**
- Lambda functions using AI/agent frameworks (LangGraph, CrewAI, OpenAI SDK, Anthropic SDK)
- ECS services running agent workloads
- Bedrock managed agents
- IAM roles, creators, and permission scope for each agent

**GitHub agents:**
- Repositories containing agent source code
- Committed secrets and hardcoded credentials
- GitHub Actions workflows with broad permissions
- Declared intent from `.specter/manifest.yaml`, `AGENT.md`, `CLAUDE.md`, or `README.md`

**Protocol compliance:**
- A2A (Agent-to-Agent) card validity, authentication, and signing
- MCP (Model Context Protocol) server OAuth, PKCE, and scope configuration
- Cross-organization agent calls

**Behavioral analysis (requires CloudTrail):**
- Ephemeral agent spawning patterns
- IAM delegation chains and RFC 8693 token exchange compliance
- Unattended agent chains (EU AI Act Article 14 relevance)

---

## Findings

The scanner produces findings in these categories:

| Category | Rule IDs |
|---|---|
| NHI (Non-Human Identity) | `NHI_ORPHANED_CREATOR`, `NHI_STALE_ROLE` |
| IAM | `IAM_NO_OWNER_TAG`, `IAM_WILDCARD_RESOURCE` |
| A2A Protocol | `A2A_AUTH_NONE`, `A2A_CARD_SIGNED`, `A2A_CROSS_ORG`, `A2A_WILDCARD_CAPABILITY`, `A2A_CARD_UNREACHABLE` |
| MCP Protocol | `MCP_OAUTH_DISABLED`, `MCP_NO_PKCE`, `MCP_NO_RESOURCE_INDICATOR`, `MCP_WILDCARD_SCOPE` |
| GitHub | `GITHUB_COMMITTED_SECRET`, `GITHUB_STATIC_AWS_CREDS`, `GITHUB_UNSCOPED_WORKFLOW` |
| Behavioral | `BEHAVIORAL_EPHEMERAL_SPAWN` |
| Intent | `MISSING_INTENT_DECLARATION`, `INTENT_MISMATCH`, `INTENT_OWNER_ABSENT` |
| Static Reference | `AGENT_UNRESOLVED_DEPENDENCY` |

Severity levels: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`

---

## Installation

### Download a pre-built binary

```bash
# macOS (Apple Silicon)
curl -Lo specter-scanner https://github.com/spectersystems/specter-scanner/releases/latest/download/specter-scanner-darwin-arm64
chmod +x specter-scanner
sudo mv specter-scanner /usr/local/bin/

# macOS (Intel)
curl -Lo specter-scanner https://github.com/spectersystems/specter-scanner/releases/latest/download/specter-scanner-darwin-amd64
chmod +x specter-scanner
sudo mv specter-scanner /usr/local/bin/

# Linux (amd64)
curl -Lo specter-scanner https://github.com/spectersystems/specter-scanner/releases/latest/download/specter-scanner-linux-amd64
chmod +x specter-scanner
sudo mv specter-scanner /usr/local/bin/
```

### Build from source

```bash
git clone https://github.com/spectersystems/specter-scanner
cd specter-scanner
go build -o specter-scanner ./cmd/scanner
```

Requires Go 1.22 or later.

---

## Quick start — standalone mode

Standalone mode runs the scanner without connecting to the Specter Platform. Results are written as an HTML or JSON report. No data leaves your environment.

```bash
# Scan your AWS account and generate an HTML report
AWS_PROFILE=your-profile specter-scanner --no-platform

# Generate JSON output instead
AWS_PROFILE=your-profile specter-scanner --no-platform --output json

# Save report to a specific file
AWS_PROFILE=your-profile specter-scanner --no-platform --output html > specter-report.html
```

The scanner uses your existing AWS credentials. It requires read-only permissions — see [Required AWS permissions](#required-aws-permissions) below.

---

## Configuration

The scanner is configured via environment variables or CLI flags.

### AWS plugin

| Environment variable | CLI flag | Description | Required |
|---|---|---|---|
| `AWS_PROFILE` | — | AWS credentials profile | Yes (or IAM role) |
| `AWS_REGION` | `--region` | AWS region to scan | No (default: us-east-1) |
| — | `--since` | How far back to look in CloudTrail (default: 6h) | No |

### GitHub plugin

The GitHub plugin supports two authentication methods:

**GitHub App (recommended for CI/CD):**

| Environment variable | Description |
|---|---|
| `GITHUB_APP_ID` | GitHub App ID |
| `GITHUB_APP_PRIVATE_KEY` | GitHub App private key (PEM format) |
| `GITHUB_APP_INSTALLATION_ID` | Installation ID for your org |

**Personal Access Token (for local use):**

| Environment variable | Description |
|---|---|
| `GITHUB_TOKEN` | Personal access token with `repo` and `read:org` scopes |

### Platform mode (optional)

| Environment variable | CLI flag | Description |
|---|---|---|
| `SPECTER_API_URL` | `--platform-url` | Platform API base URL |
| `SPECTER_API_KEY` | `--api-key` | API key from the Specter Platform |
| `SPECTER_ORG_ID` | — | Organisation ID from the Specter Platform |

### All CLI flags

```
--no-platform         Standalone mode: write report locally, no ingest
--output string       Output format in standalone mode: json|html (default: html)
--plugin string       Run only this plugin: aws|github|mcp|a2a (default: all)
--since duration      How far back to look in audit logs (default: 6h)
--rate-limit int      Protocol probe requests per second (default: 10)
--log-level string    debug|info|warn|error (default: info)
--version             Print version and exit
```

---

## Required AWS permissions

The scanner requires read-only access to your AWS account. Create an IAM role with these permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "lambda:ListFunctions",
        "lambda:GetFunction",
        "lambda:GetFunctionConfiguration",
        "lambda:ListTags",
        "lambda:GetPolicy",
        "ecs:ListClusters",
        "ecs:ListServices",
        "ecs:DescribeServices",
        "ecs:ListTaskDefinitions",
        "ecs:DescribeTaskDefinition",
        "ecs:ListTagsForResource",
        "bedrock:ListAgents",
        "bedrock:GetAgent",
        "bedrock:ListTagsForResource",
        "iam:GetRole",
        "iam:GetRolePolicy",
        "iam:ListAttachedRolePolicies",
        "iam:ListRolePolicies",
        "iam:ListUsers",
        "cloudtrail:LookupEvents",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

For cross-account scanning (recommended for production), create the role in the target account with a trust policy allowing your scanner's IAM role to assume it. See [Cross-account scanning](#cross-account-scanning) below.

---

## Cross-account scanning

For production use, run the scanner in a separate account and give it read-only access to your target accounts via IAM role assumption. This is the architecture used by the Specter Platform.

**Step 1 — Create the SpecterReadOnly role in your target account:**

Use the CloudFormation template from the Specter Platform, or create the role manually with the permissions above and this trust policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::YOUR_SCANNER_ACCOUNT:role/specter-scanner-role"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "your-unique-external-id"
        }
      }
    }
  ]
}
```

**Step 2 — Configure the scanner:**

```bash
export SPECTER_ROLE_ARN="arn:aws:iam::TARGET_ACCOUNT:role/SpecterReadOnly"
export SPECTER_EXTERNAL_ID="your-unique-external-id"
specter-scanner --no-platform
```

---

## Declaring agent intent

The scanner reads agent intent declarations to detect mismatches between what an agent claims to do and what it actually does. Add a `.specter/manifest.yaml` to your agent repository for the highest-confidence intent declaration:

```yaml
# .specter/manifest.yaml
specter:
  version: 1
  agent:
    name: DataPipeline-Orchestrator
    intent: "Processes payment transaction batches and routes anomalies to downstream analysis agents"
    owner: data-engineering@your-company.com
    framework: langgraph
    classification: orchestrator   # worker | orchestrator | gateway
    risk_acknowledgements:
      spawns_child_agents: true
      handles_pii: true
      cross_account_calls: false
      unattended: false
    review_cycle_days: 30
```

If no manifest exists, the scanner falls back to reading `AGENT.md`, `CLAUDE.md`, then `README.md` in that order.

Without any intent declaration, the scanner fires a `MISSING_INTENT_DECLARATION` finding (MEDIUM severity). An agent with no declared intent cannot be audited against its stated purpose.

### Tagging agents in AWS

For agents running on AWS (Lambda, ECS, Bedrock), add a `specter:owner` tag to the resource. This tag declares accountability and suppresses `NHI_ORPHANED_CREATOR` findings — an agent with a declared owner is governed regardless of the IAM creator's employment status:

```bash
# Lambda
aws lambda tag-resource \
  --resource arn:aws:lambda:us-east-1:123456789:function:MyAgent \
  --tags '{"specter:owner":"team@your-company.com"}'

# ECS service
aws ecs tag-resource \
  --resource-arn arn:aws:ecs:us-east-1:123456789:service/cluster/MyAgent \
  --tags key=specter:owner,value=team@your-company.com
```

---

## Connecting to the Specter Platform

The Specter Platform provides a governance dashboard, historical scan tracking, risk trending, EU AI Act compliance reports, and AI-powered risk explanations.

```bash
export SPECTER_API_URL="https://app.spectersystems.ai"
export SPECTER_API_KEY="specter_live_..."
export SPECTER_ORG_ID="org_..."
specter-scanner
```

Create your API key at `https://app.spectersystems.ai/settings` under API Keys.

---

## CI/CD integration

Add the scanner to your CI/CD pipeline to catch agent governance issues before deployment:

```yaml
# GitHub Actions example
- name: Run Specter Scanner
  env:
    AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
    AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  run: |
    specter-scanner --no-platform --output json > specter-report.json
    # Fail the build if CRITICAL findings are present
    python3 -c "
    import json, sys
    r = json.load(open('specter-report.json'))
    critical = [f for f in r['findings'] if f['severity'] == 'CRITICAL']
    if critical:
        print(f'FAILED: {len(critical)} CRITICAL findings')
        for f in critical:
            print(f'  {f[\"agentName\"]}: {f[\"ruleId\"]}')
        sys.exit(1)
    print(f'PASSED: {len(r[\"findings\"])} findings, none CRITICAL')
    "
```

---

## Building plugins

The scanner uses a plugin interface that makes it straightforward to add new discovery sources. All plugins are compiled into the binary — there is no dynamic loading.

```go
// Every plugin implements ScanPlugin
type ScanPlugin interface {
    Name() string
    Scan(ctx context.Context, cfg PluginConfig) (PluginResult, error)
}
```

To add a new plugin:

1. Create `internal/plugin/yourplugin/yourplugin.go`
2. Implement the `ScanPlugin` interface
3. Register the plugin in `cmd/scanner/main.go`
4. Add tests in `yourplugin_test.go`
5. Submit a pull request

Read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting.

---

## License

Apache License 2.0 — see [LICENSE](LICENSE) for the full text.

Copyright 2026 Specter Systems Inc.
