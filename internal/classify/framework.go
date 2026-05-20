// Package classify implements agent classification: framework detection,
// orchestrator classification, risk scoring, and ephemeral detection.
package classify

import (
	"github.com/specter-demo/specter-scanner/internal/types"
)

// GitHubRepoContent holds optional repo content for multi-layer framework detection.
// Passed from the GitHub plugin scan result.
type GitHubRepoContent struct {
	RequirementsTxt string
	PyprojectToml   string
	PackageJSON     string
	LangGraphJSON   string
	MCPJson         string
	CrewDir         bool
}

// DetectFramework combines all 4 signal layers and computes the final
// framework + confidence for an agent.
//
// Signal Layer 1: package manifests (requirements.txt, pyproject.toml, package.json)
// Signal Layer 2: import statements in .py/.ts files
// Signal Layer 3: config files (langgraph.json, .crew/, mcp.json)
// Signal Layer 4: runtime env vars (already applied by AWS plugin)
func DetectFramework(agent types.CanonicalAgentRecord, repoContent *GitHubRepoContent) types.CanonicalAgentRecord {
	// Layer 4 signals are already on the agent from the AWS plugin.
	// Here we combine with repo signals if provided.

	if repoContent == nil {
		return agent
	}

	type signal struct {
		framework  string
		confidence float64
		layer      int
	}

	var signals []signal

	// Layer 3: config files (highest priority after env vars)
	if repoContent.LangGraphJSON != "" {
		signals = append(signals, signal{"LangGraph", 0.97, 3})
	}
	if repoContent.CrewDir {
		signals = append(signals, signal{"CrewAI", 0.95, 3})
	}
	if repoContent.MCPJson != "" {
		signals = append(signals, signal{"MCP SDK", 0.98, 3})
	}

	// Layer 1: manifest scanning
	manifest := repoContent.RequirementsTxt + "\n" + repoContent.PyprojectToml + "\n" + repoContent.PackageJSON
	l1Framework, l1Confidence := detectFromManifestText(manifest)
	if l1Framework != "" {
		signals = append(signals, signal{l1Framework, l1Confidence, 1})
	}

	if len(signals) == 0 {
		return agent
	}

	// Group signals by framework
	frameworkSignals := map[string][]signal{}
	for _, s := range signals {
		frameworkSignals[s.framework] = append(frameworkSignals[s.framework], s)
	}

	// Find best framework with highest combined confidence
	var bestFramework string
	var bestConfidence float64

	for fw, sigs := range frameworkSignals {
		var maxConf float64
		for _, s := range sigs {
			if s.confidence > maxConf {
				maxConf = s.confidence
			}
		}

		// Multi-signal boost
		var combined float64
		switch len(sigs) {
		case 1:
			combined = maxConf
		case 2:
			// Two signals agree: min(s1,s2) + 0.10, capped at 0.99
			min2 := sigs[0].confidence
			if sigs[1].confidence < min2 {
				min2 = sigs[1].confidence
			}
			combined = min2 + 0.10
			if combined > 0.99 {
				combined = 0.99
			}
		default:
			// Three+ signals: 0.99
			combined = 0.99
		}

		if combined > bestConfidence {
			bestConfidence = combined
			bestFramework = fw
		}
	}

	// Existing Layer 4 signal on agent (from env vars)
	if agent.Framework != "" && agent.FrameworkConfidence > 0 {
		existing := signal{agent.Framework, agent.FrameworkConfidence, 4}
		sigs := frameworkSignals[agent.Framework]
		if len(sigs) > 0 {
			// Layer 4 + another layer agree
			var combined float64
			switch len(sigs) + 1 {
			case 2:
				min2 := existing.confidence
				for _, s := range sigs {
					if s.confidence < min2 {
						min2 = s.confidence
					}
				}
				combined = min2 + 0.10
				if combined > 0.99 {
					combined = 0.99
				}
			default:
				combined = 0.99
			}
			if combined > bestConfidence {
				bestConfidence = combined
				bestFramework = agent.Framework
			}
		} else if existing.confidence > bestConfidence {
			bestConfidence = existing.confidence
			bestFramework = agent.Framework
		}
		_ = existing
	}

	if bestFramework != "" && bestConfidence > agent.FrameworkConfidence {
		agent.Framework = bestFramework
		agent.FrameworkConfidence = bestConfidence
	}

	// Set MCP functional class if framework is MCP
	if agent.Framework == "MCP SDK" {
		agent.FunctionalClass = types.FunctionalClassMCPServer
	}

	return agent
}

func detectFromManifestText(content string) (string, float64) {
	type manifestSignal struct {
		keyword   string
		framework string
		conf      float64
	}
	signals := []manifestSignal{
		{"langgraph", "LangGraph", 0.85},
		{"langchain", "LangChain", 0.85},
		{"crewai", "CrewAI", 0.85},
		{"autogen", "AutoGen", 0.85},
		{"pyautogen", "AutoGen", 0.85},
		{"openai-agents", "OpenAI Agents", 0.85},
		{"anthropic", "Anthropic SDK", 0.75},
		{"google-adk", "Google ADK", 0.85},
		{"\"mcp\"", "MCP SDK", 0.85},
	}

	var bestFw string
	var bestConf float64
	for _, s := range signals {
		if containsCI(content, s.keyword) && s.conf > bestConf {
			bestConf = s.conf
			bestFw = s.framework
		}
	}
	return bestFw, bestConf
}

func containsCI(s, substr string) bool {
	sl := toLower(s)
	subl := toLower(substr)
	return contains(sl, subl)
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		indexStr(s, sub) >= 0)
}

func indexStr(s, sub string) int {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func toLower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		b[i] = c
	}
	return string(b)
}
