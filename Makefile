.PHONY: build build-all test test-coverage test-integration test-integration-all lint clean install bench demo demo-clean

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

# Run unit tests (excludes integration)
test:
	go test -v $(shell go list ./... | grep -v /tests/integration)

# Run unit tests with coverage (excludes integration)
test-coverage:
	go test -v -coverprofile=coverage.out $(shell go list ./... | grep -v /tests/integration)
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

# Run benchmarks (excludes integration)
bench:
	go test -bench=. -benchmem $(shell go list ./... | grep -v /tests/integration)

# Run integration tests (pattern-only, no external deps)
test-integration:
	@echo "Running pattern-only integration tests..."
	go test -v ./tests/integration/... -run '/pattern-only'

# Run all integration tests (requires Ollama + Claude)
test-integration-all:
	@echo "Running all integration tests..."
	@echo "Note: LLM tests require Ollama running (ollama serve)"
	@echo "Note: Agent tests require Claude CLI installed"
	go test -v -timeout 30m ./tests/integration/...

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

# Kill orphaned VHS processes (go-rod headless Chrome) and remove intermediate files
demo-clean:
	@rm -f demo/part1.webm demo/part2.webm demo/part3.webm demo/full.webm demo/concat.txt
	@-pkill -f 'leakless.*chrome' 2>/dev/null || true
	@-pkill -f 'chrome.*--headless.*--no-first-run' 2>/dev/null || true

# Generate demo GIF (three tapes -> webm -> concat -> GIF)
# Uses a shell trap to clean up intermediate files and orphaned VHS processes on failure
demo: build
	@trap 'rm -f demo/part1.webm demo/part2.webm demo/part3.webm demo/full.webm demo/concat.txt; pkill -f "[l]eakless.*chrome" 2>/dev/null; true' EXIT; \
	echo "Recording part 1 (title + patterns)..." && \
	vhs demo/part1.tape && \
	echo "Recording part 2 (agent detection)..." && \
	vhs demo/part2.tape && \
	echo "Recording part 3 (LLM safety)..." && \
	vhs demo/part3.tape && \
	echo "Concatenating recordings..." && \
	printf "file 'part1.webm'\nfile 'part2.webm'\nfile 'part3.webm'\n" > demo/concat.txt && \
	cd demo && ffmpeg -y -f concat -safe 0 -i concat.txt -c copy full.webm && cd .. && \
	echo "Converting to GIF..." && \
	ffmpeg -y -i demo/full.webm -vf "fps=15,split[s0][s1];[s0]palettegen=max_colors=128[p];[s1][p]paletteuse=dither=bayer" demo.gif && \
	echo "Generated demo.gif ($$(du -h demo.gif | cut -f1))"

# Download dependencies
deps:
	go mod download
	go mod tidy
