#!/usr/bin/env python3
"""
verify_demo_findings.py — validates specter-scanner demo output.

Reads JSON from stdin (scanner --no-platform --output json).
Checks:
  1. Agent count == 9 (8 Vantage Financial + 1 Meridian partner)
  2. No agents with platform == "GITHUB"
  3. Expected findings present (threshold-based)
  4. MISSING_INTENT_DECLARATION on at least 2 agents
  5. INTENT_MISMATCH on shadow-indexer (if GitHub credentials were available)
  6. At least 1 STATIC_REF or IAM_PERMISSION edge

Exits 0 on PASS, 1 on FAIL.
"""

import json
import sys


EXPECTED_FINDINGS = [
    # (agentNamePattern, ruleID, severity)
    ("shadow-indexer", "NHI_ORPHANED_CREATOR", "CRITICAL"),
    ("shadow-indexer", "IAM_WILDCARD_RESOURCE", "HIGH"),
    ("shadow-indexer", "A2A_AUTH_NONE", "CRITICAL"),
    ("shadow-indexer", "A2A_CARD_SIGNED", "HIGH"),
    ("shadow-indexer", "GITHUB_COMMITTED_SECRET", "CRITICAL"),
    ("internal-tools-mcp", "MCP_OAUTH_DISABLED", "HIGH"),
    ("internal-tools-mcp", "MCP_NO_PKCE", "HIGH"),
    ("internal-tools-mcp", "MCP_NO_RESOURCE_INDICATOR", "HIGH"),
    ("internal-tools-mcp", "MCP_WILDCARD_SCOPE", "MEDIUM"),
    (None, "A2A_CROSS_ORG", "CRITICAL"),               # meridian / any partner agent
    (None, "A2A_AUTH_NONE", "CRITICAL"),               # second occurrence
    (None, "A2A_WILDCARD_CAPABILITY", "HIGH"),
    (None, "BEHAVIORAL_EPHEMERAL_SPAWN", "HIGH"),      # optional — from CloudTrail
    # Phase 11.5 — intent / alignment findings
    (None, "MISSING_INTENT_DECLARATION", "MEDIUM"),    # at least one agent with no intent
    ("shadow-indexer", "INTENT_MISMATCH", "HIGH"),     # stated intent vs observed behaviour
]

PASS_THRESHOLD = 11   # out of 15.
# Findings NOT guaranteed without GitHub write access to demo repos:
#   GITHUB_COMMITTED_SECRET   — requires a committed secret fixture in shadow-indexer
#   INTENT_MISMATCH           — requires README.md in shadow-indexer (write access needed)
#   BEHAVIORAL_EPHEMERAL_SPAWN — requires CloudTrail events
# With those 3 excluded, 12 findings are reachable; threshold 11 gives one buffer.

# Mandatory independent checks (not in EXPECTED_FINDINGS threshold)
EXPECTED_AGENT_COUNT = 9
MIN_MISSING_INTENT_AGENTS = 2   # MISSING_INTENT_DECLARATION on at least 2 distinct agents
MIN_STATIC_EDGES = 1


def matches(finding, agent_pattern, rule_id, severity):
    if finding.get("ruleId") != rule_id:
        return False
    if finding.get("severity") != severity:
        return False
    if agent_pattern is not None:
        agent_name = finding.get("agentName", "").lower()
        if agent_pattern.lower() not in agent_name:
            return False
    return True


def main():
    try:
        data = json.load(sys.stdin)
    except json.JSONDecodeError as e:
        print(f"ERROR: Failed to parse JSON from stdin: {e}", file=sys.stderr)
        sys.exit(1)

    findings = data.get("findings", [])
    agents   = data.get("agents", [])
    edges    = data.get("edges", [])

    failures = []

    # ── 1. Agent count ─────────────────────────────────────────────────────
    print(f"Agents discovered: {len(agents)}")
    for ag in sorted(agents, key=lambda a: a.get("name", "")):
        intent_flag = "intent✓" if ag.get("intentStatement") else "intent✗"
        print(f"  {ag.get('platform','?'):15s}  {ag.get('name','?'):40s}  "
              f"vis={ag.get('visibilityClass','?'):<12s}  {intent_flag}")

    if len(agents) != EXPECTED_AGENT_COUNT:
        failures.append(
            f"FAIL: expected exactly {EXPECTED_AGENT_COUNT} agents, got {len(agents)}"
        )
    else:
        print(f"[PASS] Agent count == {EXPECTED_AGENT_COUNT}")

    # ── 2. No GITHUB-platform agents ───────────────────────────────────────
    github_agents = [a for a in agents if a.get("platform") == "GITHUB"]
    if github_agents:
        failures.append(
            f"FAIL: {len(github_agents)} GITHUB-platform agent(s) found — should be zero: "
            + ", ".join(a.get("name", "?") for a in github_agents)
        )
    else:
        print("[PASS] No GITHUB-platform agents")

    # ── 3. Expected findings (threshold) ───────────────────────────────────
    print(f"\nTotal findings in payload: {len(findings)}")
    print("\nExpected findings check:")
    print("-" * 60)

    results = []
    for agent_pattern, rule_id, severity in EXPECTED_FINDINGS:
        matched = any(matches(f, agent_pattern, rule_id, severity) for f in findings)
        label = "[PASS]" if matched else "[FAIL]"
        pattern_desc = agent_pattern if agent_pattern else "(any agent)"
        results.append((matched, f"{label} {pattern_desc} / {rule_id} / {severity}"))

    for _, line in results:
        print(line)
    print("-" * 60)

    passed = sum(1 for m, _ in results if m)
    total  = len(EXPECTED_FINDINGS)
    print(f"\nExpected findings: {passed}/{total} present (threshold: {PASS_THRESHOLD}/{total})")

    if passed < PASS_THRESHOLD:
        failures.append(
            f"FAIL: Only {passed}/{total} expected findings found (threshold {PASS_THRESHOLD})."
        )
        print("\nAll findings in payload:")
        for f in sorted(findings, key=lambda x: (x.get("severity",""), x.get("ruleId",""))):
            print(f"  {f.get('severity','?'):8s}  {f.get('ruleId','?'):35s}  {f.get('agentName','?')}")
    else:
        print(f"[PASS] findings threshold met")

    # ── 4. MISSING_INTENT_DECLARATION on >= MIN_MISSING_INTENT_AGENTS agents ─
    missing_intent_agents = set(
        f.get("agentName", "")
        for f in findings
        if f.get("ruleId") == "MISSING_INTENT_DECLARATION"
    )
    print(f"\nMISSING_INTENT_DECLARATION count: {len(missing_intent_agents)} distinct agents "
          f"(need >= {MIN_MISSING_INTENT_AGENTS})")
    if len(missing_intent_agents) < MIN_MISSING_INTENT_AGENTS:
        failures.append(
            f"FAIL: MISSING_INTENT_DECLARATION found on only {len(missing_intent_agents)} agent(s), "
            f"need at least {MIN_MISSING_INTENT_AGENTS}. "
            f"Agents: {missing_intent_agents}"
        )
    else:
        print(f"[PASS] MISSING_INTENT_DECLARATION present on {len(missing_intent_agents)} agents")

    # ── 5. INTENT_MISMATCH on shadow-indexer ───────────────────────────────
    # Only enforce if any agent has intent data (i.e., GitHub credentials were
    # used — without creds the GitHub plugin skips and no intent is extracted).
    has_any_intent = any(ag.get("intentStatement") for ag in agents)
    intent_mismatch_shadow = any(
        f.get("ruleId") == "INTENT_MISMATCH" and "shadow-indexer" in f.get("agentName", "").lower()
        for f in findings
    )
    if has_any_intent:
        if intent_mismatch_shadow:
            print("[PASS] INTENT_MISMATCH present on shadow-indexer")
        else:
            failures.append(
                "FAIL: GitHub credentials present (intent data found) but "
                "INTENT_MISMATCH not fired for shadow-indexer. "
                "Check alignment scoring — shadow-indexer should score < 0.60."
            )
    else:
        print("[SKIP] INTENT_MISMATCH check skipped — no GitHub credentials "
              "(no intent data in payload)")

    # ── 6. Static-reference edges ──────────────────────────────────────────
    static_edge_types = {"STATIC_REF", "IAM_PERMISSION"}
    static_edges = [e for e in edges if e.get("edgeType") in static_edge_types]
    print(f"\nStatic-reference edges (STATIC_REF / IAM_PERMISSION): {len(static_edges)}")
    for e in static_edges:
        print(f"  {e.get('edgeType','?'):16s}  conf={e.get('confidence',0):.2f}  {e.get('evidence','')}")

    lead_meridian = any(
        e.get("edgeType") == "IAM_PERMISSION" and
        "execute-api" in e.get("evidence", "").lower()
        for e in static_edges
    )
    print(f"  LeadScorer → Meridian IAM_PERMISSION: "
          f"{'FOUND' if lead_meridian else 'NOT FOUND (ok if not run against live AWS)'}")

    if len(static_edges) < MIN_STATIC_EDGES:
        failures.append(
            f"FAIL: Only {len(static_edges)}/{MIN_STATIC_EDGES} static-reference edges found."
        )
    else:
        print(f"[PASS] static edges: {len(static_edges)} >= {MIN_STATIC_EDGES}")

    # ── Final verdict ──────────────────────────────────────────────────────
    print("\n" + "=" * 60)
    if not failures:
        print(f"PASS: {passed}/{total} findings, {len(agents)} agents, "
              f"{len(static_edges)} static edges — all checks passed.")
        sys.exit(0)
    else:
        for f in failures:
            print(f)
        sys.exit(1)


if __name__ == "__main__":
    main()
