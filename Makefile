# Makefile for Zeus NWC Server

.PHONY: help test test-unit test-integration test-coverage build run clean lint

# Default target
help:
	@echo "Available targets:"
	@echo "  test           - Run all tests"
	@echo "  test-unit      - Run unit tests only"
	@echo "  test-integration - Run integration tests only"
	@echo "  test-coverage  - Run tests with coverage report"
	@echo "  build          - Build the server binary"
	@echo "  run            - Run the server"
	@echo "  clean          - Clean build artifacts"
	@echo "  lint           - Run linter"

# Test targets
test: test-unit test-integration

test-unit:
	@echo "Running unit tests..."
	go test -v -race -timeout=30s ./internal/services/... ./internal/handler/... ./cmd/server/...

test-integration:
	@echo "Running integration tests..."
	go test -v -timeout=60s ./test/...

test-coverage:
	@echo "Running tests with coverage..."
	go test -v -race -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Build targets
build:
	@echo "Building server..."
	go build -o bin/server ./cmd/server

build-linux:
	@echo "Building server for Linux..."
	GOOS=linux GOARCH=amd64 go build -o bin/server-linux ./cmd/server

# Run targets
run: build
	@echo "Starting server..."
	./bin/server

run-dev:
	@echo "Starting server in development mode..."
	go run ./cmd/server

# Utility targets
clean:
	@echo "Cleaning build artifacts..."
	rm -rf bin/
	rm -f coverage.out coverage.html

lint:
	@echo "Running linter..."
	golangci-lint run

# Docker targets
docker-build:
	@echo "Building Docker image..."
	docker build -t zeus-nwc-server .

docker-run:
	@echo "Running Docker container..."
	docker run -p 8080:8080 zeus-nwc-server

# Development targets
dev-deps:
	@echo "Installing development dependencies..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install github.com/stretchr/testify@latest

# Test database setup
test-redis:
	@echo "Starting Redis for testing..."
	docker run --name test-redis -p 6379:6379 -d redis:alpine

test-redis-stop:
	@echo "Stopping test Redis..."
	docker stop test-redis || true
	docker rm test-redis || true

# CI/CD targets
ci-test: test-redis
	@echo "Running CI tests..."
	make test-coverage
	make test-redis-stop

# Help for specific targets
test-help:
	@echo "Test targets:"
	@echo "  test-unit      - Run unit tests (no external dependencies)"
	@echo "  test-integration - Run integration tests (requires Redis)"
	@echo "  test-coverage  - Generate coverage report"
	@echo ""
	@echo "Prerequisites for integration tests:"
	@echo "  - Redis running on localhost:6379"
	@echo "  - Or run 'make test-redis' to start test Redis container"
