# Customers should always build via `make build` (or use the official release
# binary) so the report footer shows a real version string. A plain `go build`
# with no -ldflags still falls back to "dev" (acceptable for local development
# only) — see the Version var default in cmd/scanner/main.go.
VERSION ?= 0.1.0
GOFLAGS := -ldflags="-s -w -X main.Version=$(VERSION)"

.PHONY: build build-all test test-demo sign release

build:
	go build $(GOFLAGS) -o dist/specter-scanner ./cmd/scanner

build-all:
	GOOS=linux  GOARCH=amd64  go build $(GOFLAGS) -o dist/specter-scanner-linux-amd64 ./cmd/scanner
	GOOS=linux  GOARCH=arm64  go build $(GOFLAGS) -o dist/specter-scanner-linux-arm64 ./cmd/scanner
	GOOS=darwin GOARCH=amd64  go build $(GOFLAGS) -o dist/specter-scanner-darwin-amd64 ./cmd/scanner
	GOOS=darwin GOARCH=arm64  go build $(GOFLAGS) -o dist/specter-scanner-darwin-arm64 ./cmd/scanner
	GOOS=windows GOARCH=amd64 go build $(GOFLAGS) -o dist/specter-scanner-windows-amd64.exe ./cmd/scanner

test:
	go test ./... -v -timeout 60s

test-demo:
	@echo "Running Specter Scanner in standalone mode..."
	AWS_PROFILE=customer-demo ./dist/specter-scanner \
		--no-platform \
		--output html \
		--output-file /tmp/specter-demo-report.html \
		--log-level info; \
	EXIT=$$?; \
	echo ""; \
	test -f /tmp/specter-demo-report.html && echo "✓ HTML report generated" || (echo "✗ Report not generated" && exit 1); \
	SIZE=$$(wc -c < /tmp/specter-demo-report.html); \
	test $$SIZE -gt 10240 && echo "✓ Report size $$SIZE bytes (>10KB)" || echo "⚠  Report size $$SIZE bytes (unexpectedly small)"; \
	grep -q "shadow-indexer" /tmp/specter-demo-report.html && echo "✓ shadow-indexer in report" || echo "⚠  shadow-indexer not found"; \
	grep -q "CRITICAL" /tmp/specter-demo-report.html && echo "✓ CRITICAL findings in report" || echo "⚠  No CRITICAL findings"; \
	grep -q "spectersystems.ai" /tmp/specter-demo-report.html && echo "✓ Footer with spectersystems.ai present" || echo "⚠  Footer not found"; \
	test $$EXIT -eq 1 && echo "✓ Exit code 1 (CRITICAL quality gate triggered)" || echo "⚠  Expected exit 1 (CRITICAL findings), got $$EXIT"

sign:
	cosign sign-blob --output-signature dist/specter-scanner-linux-amd64.sig dist/specter-scanner-linux-amd64

release: build-all test sign
