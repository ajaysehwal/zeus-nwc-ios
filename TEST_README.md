# Zeus NWC Server - Test Suite

This document describes the comprehensive test suite for the Zeus NWC Server.

## Test Structure

The test suite is organized into several categories:

### 1. Unit Tests
- **Location**: `*_test.go` files alongside source code
- **Purpose**: Test individual functions and methods in isolation
- **Dependencies**: Minimal external dependencies

### 2. Integration Tests
- **Location**: `test/integration_test.go`
- **Purpose**: Test complete workflows and service interactions
- **Dependencies**: Redis server required

### 3. Test Utilities
- **Location**: `internal/testutils/test_utils.go`
- **Purpose**: Common test setup, mocks, and utilities

## Test Categories

### Service Tests

#### HandoffService Tests (`internal/services/handoff_service_test.go`)
- ✅ Valid handoff request processing
- ✅ Invalid request validation
- ✅ Missing field handling
- ✅ Multiple connection support
- ✅ Redis storage verification

#### NostrService Tests (`internal/services/nostr_service_test.go`)
- ✅ Connection management
- ✅ Event subscription logic
- ✅ Notification queuing
- ✅ Redis operations
- ✅ Validation logic

#### NotificationService Tests (`internal/services/notification_service_test.go`)
- ✅ Device registration
- ✅ Notification creation
- ✅ APNS integration (disabled mode)
- ✅ Bulk notification handling

### Handler Tests

#### HandoffHandler Tests (`internal/handler/handoff_test.go`)
- ✅ HTTP request handling
- ✅ JSON validation
- ✅ Error responses
- ✅ Multiple connection support
- ✅ CORS handling

### Integration Tests

#### Full Server Tests (`test/integration_test.go`)
- ✅ Complete handoff workflow
- ✅ Health check endpoint
- ✅ Error handling
- ✅ Multiple concurrent requests
- ✅ CORS functionality

#### Main Server Tests (`cmd/server/main_test.go`)
- ✅ Notification processor
- ✅ Service initialization
- ✅ Configuration loading
- ✅ Concurrent processing

## Running Tests

### Prerequisites

1. **Go 1.21+** installed
2. **Redis server** running on `localhost:6379` (for integration tests)
3. **Test dependencies** installed:
   ```bash
   make dev-deps
   ```

### Test Commands

```bash
# Run all tests
make test

# Run only unit tests (no external dependencies)
make test-unit

# Run only integration tests (requires Redis)
make test-integration

# Run tests with coverage report
make test-coverage

# Start Redis for testing
make test-redis

# Stop test Redis
make test-redis-stop
```

### Manual Test Execution

```bash
# Unit tests only
go test -v ./internal/services/... ./internal/handler/... ./cmd/server/...

# Integration tests
go test -v ./test/...

# With coverage
go test -v -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html
```

## Test Configuration

### Environment Variables
Tests use the configuration in `test.env`:
- Redis DB 1 (separate from production)
- Debug logging
- Disabled APNS notifications
- Test-specific timeouts

### Test Data
- Mock data is generated in `testutils/test_utils.go`
- Each test uses isolated data
- Redis is flushed between test runs

## Test Coverage

The test suite covers:

### Core Functionality
- ✅ Handoff request processing
- ✅ Multiple connection support
- ✅ Nostr event handling
- ✅ Notification queuing
- ✅ Redis operations

### Error Handling
- ✅ Invalid JSON requests
- ✅ Missing required fields
- ✅ Invalid connection data
- ✅ Redis connection failures
- ✅ Service initialization errors

### Edge Cases
- ✅ Empty connection arrays
- ✅ Invalid relay URLs
- ✅ Missing device tokens
- ✅ Concurrent requests
- ✅ Large payloads

### Integration Scenarios
- ✅ Complete handoff workflow
- ✅ Multiple service pubkeys
- ✅ Notification processing
- ✅ CORS handling
- ✅ Health checks

## Test Data Examples

### Valid Handoff Request
```json
{
  "service_pubkey": "npub1test_service_pubkey",
  "device_token": "test_device_token_123",
  "connections": [
    {
      "relay": "wss://relay.test.com",
      "pubkey": "npub1test_pubkey_1"
    },
    {
      "relay": "wss://relay2.test.com",
      "pubkey": "npub1test_pubkey_2"
    }
  ]
}
```

### Mock Notification Data
```json
{
  "service_pubkey": "npub1test_service_pubkey",
  "device_token": "test_device_token_123",
  "title": "Test Notification",
  "body": "This is a test notification",
  "event_id": "test_event_id_123",
  "event_kind": 23194,
  "pubkey": "npub1test_pubkey_1",
  "timestamp": 1234567890
}
```

## Continuous Integration

The test suite is designed to run in CI/CD pipelines:

```bash
# CI test command
make ci-test
```

This will:
1. Start Redis container
2. Run all tests with coverage
3. Generate coverage report
4. Clean up Redis container

## Troubleshooting

### Common Issues

1. **Redis Connection Failed**
   ```bash
   # Start Redis
   make test-redis
   # Or install Redis locally
   brew install redis  # macOS
   sudo apt-get install redis-server  # Ubuntu
   ```

2. **Test Timeouts**
   - Increase timeout in test configuration
   - Check Redis performance
   - Verify network connectivity

3. **Port Conflicts**
   - Change test port in `test.env`
   - Kill existing processes on port 8080

### Debug Mode

Run tests with verbose output:
```bash
go test -v -race ./...
```

## Adding New Tests

### Unit Test Template
```go
func TestServiceName_MethodName(t *testing.T) {
    // Setup
    serviceManager, cleanup := testutils.SetupTestServices(t)
    defer cleanup()
    
    // Test
    result, err := service.Method()
    
    // Assert
    assert.NoError(t, err)
    assert.NotNil(t, result)
}
```

### Integration Test Template
```go
func TestIntegration_FeatureName(t *testing.T) {
    testutils.SkipIfRedisNotAvailable(t)
    
    testServer, cleanup := setupIntegrationTestServer(t)
    defer cleanup()
    
    // Test HTTP endpoint
    resp, err := http.Post(testServer.URL+"/endpoint", "application/json", body)
    require.NoError(t, err)
    assert.Equal(t, http.StatusOK, resp.StatusCode)
}
```

## Performance Testing

For performance testing, use:
```bash
# Run with race detection
go test -race ./...

# Run with memory profiling
go test -memprofile=mem.prof ./...
go tool pprof mem.prof
```

## Security Testing

The test suite includes security-related tests:
- Input validation
- CORS handling
- Error message sanitization
- Rate limiting (if implemented)

## Future Enhancements

Planned test improvements:
- [ ] Load testing
- [ ] Chaos engineering tests
- [ ] End-to-end tests with real Nostr relays
- [ ] Performance benchmarks
- [ ] Security penetration tests
