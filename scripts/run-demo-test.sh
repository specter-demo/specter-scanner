#!/usr/bin/env bash
# run-demo-test.sh — runs the specter-scanner demo quality gate.
#
# Fetches GitHub App credentials from Secrets Manager (platform AWS profile)
# when available so the GitHub enrichment plugin exercises the full code path.
# If the platform profile is not accessible, GitHub scanning is skipped and
# the verify script adjusts accordingly (INTENT_MISMATCH check is skipped).
#
# Usage: make test-demo  (calls this script)

set -euo pipefail

GO="${GO:-go}"

# ── GitHub App credentials ────────────────────────────────────────────────────
# Pull from environment if already set (CI mode), otherwise fetch from Secrets
# Manager using the 'platform' AWS profile (developer mode).
if [ -z "${GITHUB_APP_ID:-}" ] && aws sts get-caller-identity --profile platform >/dev/null 2>&1; then
    echo "Fetching GitHub App credentials from Secrets Manager..." >&2
    export GITHUB_APP_ID=$(aws secretsmanager get-secret-value \
        --secret-id specter/github-app-id \
        --profile platform \
        --query 'SecretString' --output text 2>/dev/null || true)
    export GITHUB_APP_INSTALLATION_ID=$(aws secretsmanager get-secret-value \
        --secret-id specter/github-app-installation-id \
        --profile platform \
        --query 'SecretString' --output text 2>/dev/null || true)
    # Private key may contain newlines — write to a temp file, read back,
    # then clean up so it is never left on disk after the test completes.
    _KEY_FILE=$(mktemp)
    trap "rm -f $_KEY_FILE" EXIT
    aws secretsmanager get-secret-value \
        --secret-id specter/github-app-private-key \
        --profile platform \
        --query 'SecretString' --output text 2>/dev/null > "$_KEY_FILE" || true
    export GITHUB_APP_PRIVATE_KEY=$(cat "$_KEY_FILE")
    if [ -n "$GITHUB_APP_ID" ]; then
        echo "GitHub App credentials loaded (app_id=$GITHUB_APP_ID)." >&2
    fi
fi

# ── Run scanner ───────────────────────────────────────────────────────────────
# Extend PATH to pick up Homebrew Go on macOS developer machines.
export PATH="/opt/homebrew/bin:/usr/local/go/bin:$PATH"
GO="${GO:-go}"

AWS_PROFILE=customer-demo $GO run ./cmd/scanner \
    --no-platform \
    --output json \
    --api-key "${SPECTER_DEMO_API_KEY:-demo}" \
    --org-slug specter-demo \
    | python3 scripts/verify_demo_findings.py
