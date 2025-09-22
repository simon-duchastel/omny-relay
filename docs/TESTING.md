# Testing Guide

This document provides comprehensive testing guidelines for the NFC Transit Card Relay System, covering test strategy, execution, and contribution guidelines.

## Testing Philosophy

Our testing strategy focuses on:

- **Security-First**: All security-critical components have comprehensive test coverage
- **Real-World Scenarios**: Tests simulate actual NFC protocol interactions
- **Performance Validation**: System performance under various loads
- **Android Compatibility**: Protocol compliance with NFCGate standard
- **Continuous Integration**: Automated testing on every commit

## Test Structure

### Directory Organization

```
tests/
├── conftest.py              # Shared fixtures and configuration
├── fixtures/                # Test data and mock objects
│   └── nfc_packets.py      # Real NFC packet samples
├── unit/                   # Unit tests for individual components
│   ├── test_nfc_relay_server.py
│   ├── test_crypto.py
│   ├── test_config.py
│   └── test_packet_analyzer.py
├── integration/            # Integration tests
├── security/              # Security validation tests
│   └── test_security_validation.py
├── android/               # Android client simulation tests
│   └── test_websocket_client.py
└── e2e/                   # End-to-end tests
```

### Test Categories

Tests are organized into the following categories using pytest markers:

- `@pytest.mark.unit` - Unit tests for individual functions/classes
- `@pytest.mark.integration` - Tests for component interaction
- `@pytest.mark.security` - Security and vulnerability tests
- `@pytest.mark.android` - Android client simulation tests
- `@pytest.mark.performance` - Performance and load tests
- `@pytest.mark.slow` - Tests taking more than 5 seconds

## Running Tests

### Quick Start

```bash
# Install test dependencies
pip install -r requirements-test.txt

# Run all tests
pytest

# Run specific test categories
pytest -m unit           # Unit tests only
pytest -m security       # Security tests only
pytest -m android        # Android simulation tests

# Run with coverage
pytest --cov=src --cov=server --cov-report=html
```

### Detailed Test Execution

#### Unit Tests
```bash
# Run all unit tests
pytest tests/unit/ -v

# Run specific component tests
pytest tests/unit/test_nfc_relay_server.py -v
pytest tests/unit/test_crypto.py -v
pytest tests/unit/test_packet_analyzer.py -v

# Run with coverage and detailed output
pytest tests/unit/ --cov=src --cov=server --cov-report=term-missing -v
```

#### Integration Tests
```bash
# Full integration test suite
pytest tests/integration/ -v

# Test server-client integration
pytest tests/integration/test_protocol_handling.py -v

# Test analysis pipeline integration
pytest tests/integration/test_session_lifecycle.py -v
```

#### Security Tests
```bash
# Run security validation tests
pytest tests/security/ -v

# Specific security areas
pytest tests/security/test_security_validation.py::TestInputValidation -v
pytest tests/security/test_security_validation.py::TestTLSSecurity -v
pytest tests/security/test_security_validation.py::TestVulnerabilityDetection -v
```

#### Android Simulation Tests
```bash
# Run Android client simulation
pytest tests/android/ -v

# Test protocol compliance
pytest tests/android/test_websocket_client.py::TestProtocolCompliance -v

# Test NFC data relay
pytest tests/android/test_websocket_client.py::TestNFCDataRelay -v
```

#### Performance Tests
```bash
# Run performance benchmarks
pytest tests/ -m performance --benchmark-only

# Performance with memory profiling
pytest tests/ -m performance --benchmark-only --benchmark-sort=mean
```

### Test Configuration

Tests are configured via `pytest.ini`:

```ini
[tool:pytest]
testpaths = tests
addopts = --strict-markers --verbose --cov=src --cov=server
markers =
    unit: Unit tests for individual components
    integration: Integration tests for component interaction
    security: Security and vulnerability tests
    android: Android client simulation tests
    performance: Performance and load tests
```

## Test Data and Fixtures

### NFC Packet Samples

The `tests/fixtures/nfc_packets.py` module provides real-world NFC packet samples:

```python
from tests.fixtures.nfc_packets import NFCPacketSamples, REQA, OYSTER_BALANCE

# Use predefined packets
test_data = REQA  # ISO 14443 REQA command

# Generate custom transit data
oyster_data = NFCPacketSamples.create_balance_data('oyster', 15.50)

# Get protocol sequences
mifare_sequence = NFCPacketSamples.get_protocol_sequence('mifare_read')
```

### Shared Fixtures

Common test fixtures are defined in `conftest.py`:

```python
def test_my_function(temp_dir, test_config, sample_nfc_data):
    # temp_dir: Temporary directory for test files
    # test_config: Test configuration with safe defaults
    # sample_nfc_data: Dictionary of NFC packet samples
    pass
```

### Security Test Vectors

Security tests use predefined attack vectors:

```python
def test_injection_protection(security_test_vectors):
    for injection_data in security_test_vectors['injection_attempts']:
        # Test system handles injection safely
        pass
```

## Writing Tests

### Unit Test Example

```python
class TestNFCRelayServer:
    """Test NFC relay server functionality."""
    
    def test_session_creation(self, test_config):
        """Test session creation."""
        server = NFCRelayServer(use_tls=False)
        session_id = server.generate_session_id()
        
        assert len(session_id) == 6
        assert session_id.isdigit()
    
    @pytest.mark.asyncio
    async def test_handle_message(self, test_config, sample_protocol_messages):
        """Test message handling."""
        server = NFCRelayServer(use_tls=False)
        mock_websocket = AsyncMock()
        
        await server.handle_message(mock_websocket, 
                                   sample_protocol_messages['data'].SerializeToString())
        
        # Verify expected behavior
        assert mock_websocket.send.called
```

### Security Test Example

```python
class TestInputValidation:
    """Test input validation and sanitization."""
    
    @pytest.mark.asyncio
    async def test_injection_protection(self, test_config):
        """Test protection against injection attacks."""
        server = NFCRelayServer(use_tls=False)
        
        injection_vectors = [
            b'<script>alert("xss")</script>',
            b'../../etc/passwd',
            b'\x00' * 1000,
        ]
        
        for injection_data in injection_vectors:
            # System should handle safely without exposing internals
            with patch.object(server, 'send_error', new_callable=AsyncMock) as mock_error:
                await server.handle_nfc_data(injection_data)
                # Verify appropriate error handling
```

### Android Simulation Test Example

```python
class TestAndroidClient:
    """Test Android client simulation."""
    
    @pytest.mark.asyncio
    async def test_session_creation(self):
        """Test Android client session creation."""
        client = MockAndroidNFCGateClient()
        client.websocket = AsyncMock()
        
        # Mock server response
        response = create_session_response("123456")
        client.websocket.recv.return_value = response.SerializeToString()
        
        session_id = await client.create_session("READER")
        
        assert session_id == "123456"
        assert client.client_type == "READER"
```

## Test Coverage

### Coverage Requirements

- **Minimum Overall Coverage**: 80%
- **Security-Critical Components**: 95%
- **Core Server Logic**: 90%
- **Analysis Engine**: 85%

### Coverage Reports

```bash
# Generate HTML coverage report
pytest --cov=src --cov=server --cov-report=html

# View coverage report
open htmlcov/index.html

# Generate XML for CI
pytest --cov=src --cov=server --cov-report=xml
```

### Coverage Exclusions

Lines excluded from coverage analysis:

```python
# pragma: no cover
def debug_function():  # pragma: no cover
    pass

# Type checking imports
if TYPE_CHECKING:  # pragma: no cover
    from typing import Optional
```

## Continuous Integration

### GitHub Actions Workflow

Tests run automatically on:
- Push to main/develop branches
- Pull requests
- Daily scheduled runs

Workflow includes:
- Multi-Python version testing (3.8-3.12)
- Security scanning (Bandit, Safety)
- Code quality checks (Black, flake8, mypy)
- Performance benchmarks
- Docker container testing

### Pre-commit Hooks

Install pre-commit hooks for automatic code quality:

```bash
pip install pre-commit
pre-commit install
```

Hooks run automatically on commit:
- Code formatting (Black, isort)
- Linting (flake8, pylint)
- Security scanning (Bandit)
- Secret detection

## Test Environment Setup

### Local Development

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-test.txt

# Generate protocol buffers
python -m grpc_tools.protoc --python_out=. --grpc_python_out=. --proto_path=. src/protocol/messages.proto

# Run tests
pytest
```

### Docker Testing

```bash
# Build test image
docker build -t nfc-relay-test .

# Run tests in container
docker run --rm nfc-relay-test pytest

# Run specific test categories
docker run --rm nfc-relay-test pytest -m security
```

### Tox Multi-Environment Testing

```bash
# Install tox
pip install tox

# Run tests across multiple Python versions
tox

# Run specific environments
tox -e py311           # Python 3.11 only
tox -e security        # Security tests
tox -e coverage        # Coverage analysis
tox -e lint           # Code quality checks
```

## Performance Testing

### Benchmark Tests

Performance tests use pytest-benchmark:

```python
def test_packet_analysis_performance(benchmark, sample_nfc_data):
    """Benchmark packet analysis performance."""
    analyzer = TransitCardAnalyzer()
    
    result = benchmark(analyzer.analyze_packet, sample_nfc_data['reqa'], "reader_to_card")
    
    # Should complete in reasonable time
    assert result['protocol'] == 'ISO14443'
```

### Load Testing

```python
@pytest.mark.performance
@pytest.mark.asyncio
async def test_concurrent_sessions(test_server):
    """Test server under concurrent load."""
    clients = []
    
    # Create many concurrent clients
    for i in range(100):
        client = MockAndroidNFCGateClient()
        await client.connect(f"ws://localhost:{test_server.port}")
        clients.append(client)
    
    # All should connect successfully
    assert all(client.connected for client in clients)
```

## Debugging Tests

### Running Tests with Debug Output

```bash
# Verbose output with logging
pytest -v -s --log-cli-level=DEBUG

# Stop on first failure
pytest -x

# Drop into debugger on failure
pytest --pdb

# Run specific test with debug
pytest tests/unit/test_nfc_relay_server.py::TestSession::test_add_client -v -s
```

### Test Debugging Tips

1. **Use print statements**: `print(f"Debug value: {variable}")`
2. **Add temporary assertions**: `assert False, f"Debug: {value}"`
3. **Use pytest fixtures**: Access `tmp_path`, `caplog` for debugging
4. **Mock inspection**: Check `mock.call_args_list` to see what was called

## Test Data Management

### Anonymized Real Data

Test data is based on real NFC captures but anonymized:

- Card IDs are randomized
- Personal data is removed
- Balance amounts are fictional
- Timestamps are adjusted

### Creating New Test Data

When adding new test cases:

1. Capture real NFC data (authorized research only)
2. Anonymize sensitive information
3. Add to `tests/fixtures/nfc_packets.py`
4. Document the source and protocol
5. Add corresponding test cases

## Contributing Tests

### Test Contribution Guidelines

1. **Write tests first** (TDD approach)
2. **Test both success and failure paths**
3. **Use descriptive test names** that explain intent
4. **Include docstrings** for complex test logic
5. **Mock external dependencies** (network, filesystem)
6. **Use appropriate test markers**
7. **Maintain test independence** (no shared state)

### Test Review Checklist

Before submitting tests:

- [ ] Tests pass locally
- [ ] Coverage doesn't decrease
- [ ] Security tests included for security-sensitive changes
- [ ] Performance impact considered
- [ ] Documentation updated if needed
- [ ] Test data is anonymized
- [ ] No hard-coded secrets or credentials

### Adding New Test Categories

To add a new test category:

1. Add marker to `pytest.ini`
2. Create appropriate test directory
3. Update CI workflow
4. Document in this guide

## Troubleshooting

### Common Test Issues

**Protocol Buffer Import Errors**
```bash
# Regenerate protocol buffers
python -m grpc_tools.protoc --python_out=. --grpc_python_out=. --proto_path=. src/protocol/messages.proto
```

**Async Test Failures**
```python
# Ensure proper async test decoration
@pytest.mark.asyncio
async def test_async_function():
    pass
```

**Coverage Issues**
```bash
# Check what's not covered
pytest --cov=src --cov-report=term-missing | grep "TOTAL"
```

**Flaky Tests**
- Add appropriate timeouts
- Mock time-dependent operations
- Use deterministic test data
- Avoid testing implementation details

### Getting Help

- Check existing tests for examples
- Review test fixtures in `conftest.py`
- Consult pytest documentation
- Ask in project discussions

## Security Testing Notes

### Responsible Testing

- **Never test on production systems**
- **Use only authorized test cards**
- **Anonymize all test data**
- **Follow responsible disclosure** for vulnerabilities
- **Respect privacy** and legal requirements

### Test Data Sensitivity

All test data should be:
- Anonymized and fictional
- Not containing real card numbers
- Not exposing real cryptographic keys
- Suitable for public repositories

---

This testing guide ensures comprehensive validation of the NFC Transit Card Relay System while maintaining security and privacy standards.