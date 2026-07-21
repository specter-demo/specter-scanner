// Copyright 2026 Specter Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package shared holds detection logic used by more than one scanner plugin.
// It has no dependency on any specific platform SDK (GitHub, AWS, etc.) — it
// only operates on file paths and raw text content, so any plugin that can
// fetch file content from its own source-control surface can reuse it.
package shared

import "regexp"

// SecretMatch is one hardcoded-credential match found in scanned content.
type SecretMatch struct {
	Path    string // file path the match was found in
	Pattern string // truncated regex source, for evidence display
	Match   string // truncated matched text, for evidence display
}

// SecretPatterns are the known hardcoded-credential regexes. Originally
// GitHub-plugin-specific; extracted so any source-control plugin (GitHub,
// CodeCommit, etc.) can reuse the exact same detection instead of
// maintaining a second copy that could drift out of sync.
var SecretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`sk-svcacct-[A-Za-z0-9_-]{20,}`),
	regexp.MustCompile(`sk-ant-api0[3-9]-[A-Za-z0-9_-]{20,}`),
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
}

// TruncateForEvidence truncates s to n characters, appending "..." if cut.
// Used consistently so evidence blobs never leak a full secret value.
func TruncateForEvidence(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// ScanContentForSecrets checks content (the full text of one file) against
// SecretPatterns and returns one SecretMatch per pattern that matches.
// path is recorded for evidence display only — it does not affect matching.
func ScanContentForSecrets(path, content string) []SecretMatch {
	if content == "" {
		return nil
	}
	var matches []SecretMatch
	for _, pat := range SecretPatterns {
		if m := pat.FindString(content); m != "" {
			matches = append(matches, SecretMatch{
				Path:    path,
				Pattern: TruncateForEvidence(pat.String(), 20),
				Match:   TruncateForEvidence(m, 20),
			})
		}
	}
	return matches
}
