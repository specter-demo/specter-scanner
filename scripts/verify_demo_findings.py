#!/usr/bin/env python3
"""
verify_demo_findings.py — validates specter-scanner demo output.

Reads JSON from stdin (scanner --no-platform --output json).
Checks for 13 expected findings. Exits 0 if >=12 found, exits 1 if <12.
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
    (None, "A2A_CROSS_ORG", "CRITICAL"),               # meridian or zdgavnxdu9
    (None, "A2A_AUTH_NONE", "CRITICAL"),               # meridian or zdgavnxdu9 (second occurrence)
    (None, "A2A_WILDCARD_CAPABILITY", "HIGH"),         # meridian or zdgavnxdu9
    (None, "BEHAVIORAL_EPHEMERAL_SPAWN", "HIGH"),      # optional, from CloudTrail
    # Phase 11.5 — static reference analysis
    ("ShadowAnalytics", "MISSING_INTENT_DECLARATION", "MEDIUM"),  # ephemeral/shadow agent with no intent file
    ("shadow-indexer", "INTENT_MISMATCH", "HIGH"),     # stated intent does not match observed behaviour
]

PASS_THRESHOLD = 14

# Phase 11.5: minimum expected static-reference edges (STATIC_REF or IAM_PERMISSION)
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
    print(f"Total findings in payload: {len(findings)}")
    print()

    found_indices = set()
    results = []

    for i, (agent_pattern, rule_id, severity) in enumerate(EXPECTED_FINDINGS):
        matched = False
        for finding in findings:
            if matches(finding, agent_pattern, rule_id, severity):
                matched = True
                found_indices.add(i)
                break
        label = f"[{'PASS' if matched else 'FAIL'}]"
        pattern_desc = agent_pattern if agent_pattern else "(any agent)"
        results.append((matched, f"{label} {pattern_desc} / {rule_id} / {severity}"))

    print("Expected findings check:")
    print("-" * 60)
    for _, line in results:
        print(line)
    print("-" * 60)

    passed = sum(1 for m, _ in results if m)
    total = len(EXPECTED_FINDINGS)
    print(f"\nResult: {passed}/{total} expected findings present (threshold: {PASS_THRESHOLD}/{total})")

    # Show all findings for debugging
    if passed < PASS_THRESHOLD:
        print("\nAll findings in payload:")
        for f in sorted(findings, key=lambda x: (x.get("severity", ""), x.get("ruleId", ""))):
            print(f"  {f.get('severity','?'):8s}  {f.get('ruleId','?'):35s}  {f.get('agentName','?')}")
        print()

    agents = data.get("agents", [])
    print(f"Agents discovered: {len(agents)}")
    for ag in agents:
        print(f"  {ag.get('platform','?'):15s}  {ag.get('name','?'):40s}  "
              f"framework={ag.get('framework','') or '-':<15s}  "
              f"visibility={ag.get('visibilityClass','?')}")

    # Phase 11.5: static-reference edge check
    edges = data.get("edges", [])
    static_edge_types = {"STATIC_REF", "IAM_PERMISSION"}
    static_edges = [e for e in edges if e.get("edgeType") in static_edge_types]
    print(f"\nStatic-reference edges (STATIC_REF / IAM_PERMISSION): {len(static_edges)}")
    for e in static_edges:
        print(f"  {e.get('edgeType','?'):16s}  conf={e.get('confidence',0):.2f}  {e.get('evidence','')}")
    # Specifically look for LeadScorer-Prod → Meridian Data API Gateway IAM_PERMISSION edge
    lead_meridian = any(
        e.get("edgeType") == "IAM_PERMISSION" and
        "execute-api" in e.get("evidence", "").lower()
        for e in static_edges
    )
    print(f"  LeadScorer-Prod → Meridian IAM_PERMISSION edge: {'FOUND' if lead_meridian else 'NOT FOUND (acceptable if demo not run against live AWS)'}")

    edges_ok = len(static_edges) >= MIN_STATIC_EDGES

    if passed >= PASS_THRESHOLD and edges_ok:
        print(f"\nPASS: {passed}/{total} findings confirmed (threshold {PASS_THRESHOLD}), {len(static_edges)} static edges.")
        sys.exit(0)
    else:
        missing = [desc for matched, desc in results if not matched]
        if passed < PASS_THRESHOLD:
            print(f"\nFAIL: Only {passed}/{total} findings found. Missing:")
            for m in missing:
                print(f"  {m}")
        if not edges_ok:
            print(f"\nFAIL: Only {len(static_edges)}/{MIN_STATIC_EDGES} static-reference edges found.")
        sys.exit(1)


if __name__ == "__main__":
    main()
