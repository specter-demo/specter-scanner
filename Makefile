VERSION ?= dev
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
	AWS_PROFILE=customer-demo go run ./cmd/scanner \
	  --no-platform \
	  --output json \
	  --api-key $${SPECTER_DEMO_API_KEY:-demo} \
	  --org-slug specter-demo \
	  | python3 scripts/verify_demo_findings.py

sign:
	cosign sign-blob --output-signature dist/specter-scanner-linux-amd64.sig dist/specter-scanner-linux-amd64

release: build-all test sign
