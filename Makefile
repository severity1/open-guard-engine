.PHONY: build build-all test test-coverage test-integration test-integration-all lint clean install bench

# Build variables
BINARY_NAME := open-guard
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS := -ldflags "-X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME)"

# Directories
BIN_DIR := bin
CMD_DIR := cmd/open-guard

# Default target
all: build

# Build for current platform
build:
	@mkdir -p $(BIN_DIR)
	go build $(LDFLAGS) -o $(BIN_DIR)/$(BINARY_NAME) ./$(CMD_DIR)

# Build for all platforms
build-all:
	@mkdir -p $(BIN_DIR)
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BIN_DIR)/$(BINARY_NAME)-linux-amd64 ./$(CMD_DIR)
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BIN_DIR)/$(BINARY_NAME)-linux-arm64 ./$(CMD_DIR)
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BIN_DIR)/$(BINARY_NAME)-darwin-amd64 ./$(CMD_DIR)
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BIN_DIR)/$(BINARY_NAME)-darwin-arm64 ./$(CMD_DIR)
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BIN_DIR)/$(BINARY_NAME)-windows-amd64.exe ./$(CMD_DIR)

# Run all tests
test:
	go test -v ./...

# Run tests with coverage
test-coverage:
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

# Run benchmarks
bench:
	go test -bench=. -benchmem ./...

# Run integration tests (pattern-only, no external deps)
test-integration:
	@echo "Running pattern-only integration tests..."
	go test -v ./tests/integration/... -run 'TestPatternMode|TestStrictMode|TestPermissiveMode|TestConfirmMode|TestDetectedBy_Pattern'

# Run all integration tests (requires Ollama + Claude)
test-integration-all:
	@echo "Running all integration tests..."
	@echo "Note: LLM tests require Ollama running (ollama serve)"
	@echo "Note: Agent tests require Claude CLI installed"
	go test -v -timeout 5m ./tests/integration/...

# Run linter
lint:
	golangci-lint run ./...

# Clean build artifacts
clean:
	rm -rf $(BIN_DIR)
	rm -f coverage.out coverage.html

# Install to GOPATH/bin
install:
	go install $(LDFLAGS) ./$(CMD_DIR)

# Download dependencies
deps:
	go mod download
	go mod tidy
