// Copyright 2026 Specter Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package shared

import "testing"

func TestScanContentForSecrets_HappyPath(t *testing.T) {
	content := "AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP\n"
	matches := ScanContentForSecrets("example/config.env", content)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match for a hardcoded AKIA-style access key, got %d", len(matches))
	}
	if matches[0].Path != "example/config.env" {
		t.Errorf("expected match Path to be the file path passed in, got %q", matches[0].Path)
	}
}

func TestScanContentForSecrets_MultiplePatternsMatch(t *testing.T) {
	content := "key1=AKIAABCDEFGHIJKLMNOP\nkey2=sk-svcacct-abcdefghijklmnopqrstuvwxyz\n"
	matches := ScanContentForSecrets("example/config.env", content)
	if len(matches) != 2 {
		t.Fatalf("expected 2 matches, one per distinct pattern present, got %d", len(matches))
	}
}

func TestScanContentForSecrets_NoMatch(t *testing.T) {
	content := "this file has no secrets in it, just ordinary configuration\nport=8080\n"
	matches := ScanContentForSecrets("example/config.env", content)
	if matches != nil {
		t.Errorf("expected no matches for content with no secret-shaped strings, got %+v", matches)
	}
}

func TestScanContentForSecrets_EmptyContent(t *testing.T) {
	matches := ScanContentForSecrets("example/config.env", "")
	if matches != nil {
		t.Errorf("expected nil for empty content, got %+v", matches)
	}
}

func TestTruncateForEvidence_ShorterThanLimit(t *testing.T) {
	got := TruncateForEvidence("short", 20)
	if got != "short" {
		t.Errorf("expected string shorter than the limit to be returned unchanged, got %q", got)
	}
}

func TestTruncateForEvidence_LongerThanLimit(t *testing.T) {
	got := TruncateForEvidence("this string is definitely longer than the limit", 10)
	want := "this strin..."
	if got != want {
		t.Errorf("expected truncation to %d chars plus ellipsis, got %q, want %q", 10, got, want)
	}
}
