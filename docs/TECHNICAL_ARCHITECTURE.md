# Technical Architecture

This document provides a detailed technical overview of the NFC Transit Card Relay System architecture, implementation details, and design decisions.

## System Overview

The system implements a distributed architecture for secure NFC research with the following key design principles:

- **Security-First**: All communications encrypted, data stored securely
- **Modular Design**: Pluggable protocol analyzers and visualization engines
- **Research-Focused**: Comprehensive data collection and analysis capabilities
- **Scalable**: Support for multiple concurrent sessions and devices

## Architecture Layers

### 1. Device Layer (Android)

**Components:**
- NFCGate Android application (existing)
- NFC hardware interface
- Host Card Emulation (HCE) support

**Responsibilities:**
- NFC field interaction with transit cards
- Protocol-level data capture
- Secure transmission to relay server
- Card emulation for relay attacks

**Communication Protocol:**
```
Android Device ←→ Relay Server
    ↓
WebSocket + TLS 1.3
    ↓
Protocol Buffer Messages
```

### 2. Communication Layer

**Protocol Stack:**
```
Application Layer    | Custom Protocol (Protocol Buffers)
Presentation Layer   | TLS 1.3 Encryption
Session Layer        | WebSocket Connection Management  
Transport Layer      | TCP
Network Layer        | IP
```

**Message Types:**
- `SESSION`: Session management (create, join, leave)
- `DATA`: NFC packet relay with timestamps
- `STATUS`: Connection status and error reporting

**Security Features:**
- Certificate-based authentication
- Perfect Forward Secrecy (PFS)
- Message integrity verification
- Replay attack protection

### 3. Server Layer

**Core Components:**

#### NFCRelayServer
```python
class NFCRelayServer:
    - WebSocket connection management
    - Session lifecycle management
    - Real-time packet forwarding
    - Security policy enforcement
```

#### Session Management
```python
class Session:
    - Unique 6-digit session IDs
    - Client type tracking (READER/CARD)
    - Packet logging and analysis
    - Automatic cleanup
```

#### Security Manager
```python
class TLSManager:
    - Certificate generation and management
    - SSL context configuration
    - Cipher suite selection
    - Key rotation support
```

### 4. Analysis Layer

**Protocol Analysis Pipeline:**

```
Raw NFC Data → Protocol Detection → Data Parsing → Transit Analysis → Storage
```

#### Protocol Detection
```python
class TransitProtocolDetector:
    - ISO 14443 Type A/B detection
    - MIFARE Classic/Plus identification
    - FeliCa protocol recognition
    - Custom protocol extensibility
```

#### Data Parsing
```python
class TransitDataParser:
    - Card ID extraction
    - Balance information parsing
    - Transaction data recovery
    - Security assessment
```

#### Analytics Engine
```python
class TransitAnalyticsPipeline:
    - Real-time pattern recognition
    - Historical trend analysis
    - Security vulnerability detection
    - Anomaly identification
```

### 5. Storage Layer

**Data Storage Architecture:**

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Raw Packets   │    │   Parsed Data   │    │   Analysis      │
│   (Encrypted)   │    │   (JSON)        │    │   Results       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
        │                       │                       │
        ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  File System    │    │  Secure Storage │    │   Export        │
│  (PCAP/JSON)    │    │  (AES-256)      │    │   Formats       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

**Security Features:**
- AES-256 encryption for sensitive data
- Secure key derivation and storage
- Automatic data retention policies
- Secure deletion with overwriting

### 6. Visualization Layer

**Visualization Architecture:**

```
Data Sources → Processing → Rendering → Output
     │             │           │          │
Session Data → Aggregation → matplotlib → Static Images
Analytics   → Filtering   → plotly     → Interactive HTML
Reports     → Formatting  → Custom     → PDF Reports
```

**Visualization Types:**
- **Session Overviews**: Packet distribution, protocol analysis
- **Timeline Analysis**: Protocol sequences, timing patterns
- **Security Dashboards**: Vulnerability assessments, risk scores
- **Transit Analytics**: Balance flows, transaction patterns

## Protocol Implementation

### NFC Protocol Support

#### ISO 14443 Type A/B
```python
class ISO14443Protocol:
    commands = {
        0x26: "REQA",     # Request Type A
        0x52: "WUPA",     # Wake-Up Type A
        0x93: "SELECT",   # Select Cascade Level 1
        0x30: "READ",     # Read block
        0xA0: "WRITE",    # Write block
    }
```

#### MIFARE Classic
```python
class MifareProtocol:
    - Authentication commands (0x60, 0x61)
    - Block-based data structure
    - Sector and key management
    - Access bit interpretation
```

#### Transit-Specific Extensions
```python
class TransitCardAnalyzer:
    transit_patterns = {
        'oyster': {
            'balance_offset': 8,
            'currency_factor': 100,  # Pence
        },
        'clipper': {
            'balance_offset': 12,
            'currency_factor': 100,  # Cents
        }
    }
```

### Message Protocol

**Protocol Buffer Schema:**
```protobuf
message Wrapper {
    required WrapperType type = 1;
    optional SessionMessage session = 2;
    optional DataMessage data = 3;
    optional StatusMessage status = 4;
}

message DataMessage {
    required int32 error_code = 1;
    required bytes nfc_data = 2;
    optional int64 timestamp = 3;
    optional string direction = 4;
}
```

## Security Architecture

### Threat Model

**Assets to Protect:**
- NFC communication data
- Transit card information
- User privacy data
- System availability

**Threat Actors:**
- Network attackers (eavesdropping)
- Malicious clients
- Data exfiltration attempts
- Denial of service attacks

**Attack Vectors:**
- Man-in-the-middle attacks
- Replay attacks
- Protocol downgrade attacks
- Data injection attempts

### Security Controls

#### Transport Security
```python
# TLS Configuration
context.minimum_version = ssl.TLSVersion.TLSv1_2
context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM')
context.check_hostname = True
context.verify_mode = ssl.CERT_REQUIRED
```

#### Data Protection
```python
# Encryption at Rest
class SecureStorage:
    - AES-256-GCM encryption
    - PBKDF2 key derivation
    - Authenticated encryption
    - Secure key storage
```

#### Access Control
```python
# Session Management
class SessionManager:
    - Time-based session expiration
    - Rate limiting per client
    - Connection count limits
    - IP-based filtering
```

### Privacy Protection

**Data Minimization:**
- Only collect necessary NFC data
- Automatic data expiration
- User consent mechanisms
- Anonymization options

**Data Anonymization:**
```python
class DataAnonymizer:
    - Card ID hashing/truncation
    - Location data removal
    - Timestamp fuzzing
    - Sensitive field redaction
```

## Performance Considerations

### Scalability Design

**Concurrent Sessions:**
- Asynchronous I/O with asyncio
- WebSocket connection pooling
- Memory-efficient packet handling
- Graceful degradation under load

**Memory Management:**
```python
# Streaming Processing
async def process_packet_stream():
    async for packet in packet_stream:
        # Process immediately, don't buffer
        await analyze_packet(packet)
        # Release memory immediately
        del packet
```

**Storage Optimization:**
- Compressed packet storage
- Incremental analysis processing
- Background cleanup tasks
- Storage quota management

### Network Optimization

**Bandwidth Efficiency:**
- Protocol buffer serialization
- Optional data compression
- Selective data transmission
- Connection multiplexing

**Latency Optimization:**
- Keep-alive connections
- Connection pre-establishment
- Local caching strategies
- Asynchronous processing

## Extensibility Framework

### Plugin Architecture

**Protocol Plugins:**
```python
class ProtocolPlugin(ABC):
    @abstractmethod
    def identify(self, data: bytes) -> bool:
        pass
    
    @abstractmethod
    def parse(self, data: bytes) -> Dict:
        pass
```

**Analysis Plugins:**
```python
class AnalysisPlugin(ABC):
    @abstractmethod
    async def analyze_session(self, session_data: List[Dict]) -> Dict:
        pass
```

**Visualization Plugins:**
```python
class VisualizationPlugin(ABC):
    @abstractmethod
    def create_visualization(self, data: Dict) -> str:
        pass
```

### Configuration System

**Hierarchical Configuration:**
```yaml
# config.yaml
security:
  tls:
    version: "1.3"
    ciphers: "ECDHE+AESGCM"
  
analysis:
  protocols:
    - iso14443
    - mifare
    - felica
  
plugins:
  protocol_detectors:
    - custom_transit_protocol
```

## Deployment Architectures

### Single-Node Deployment
```
┌─────────────────────────────────────┐
│              Server Host            │
│  ┌─────────────┐ ┌─────────────┐   │
│  │    Relay    │ │   Analysis  │   │
│  │   Server    │ │   Engine    │   │
│  └─────────────┘ └─────────────┘   │
│  ┌─────────────┐ ┌─────────────┐   │
│  │   Storage   │ │Visualization│   │
│  │   System    │ │   Engine    │   │
│  └─────────────┘ └─────────────┘   │
└─────────────────────────────────────┘
```

### Distributed Deployment
```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│    Relay    │    │   Analysis  │    │   Storage   │
│   Servers   │◄──►│   Cluster   │◄──►│   Cluster   │
│  (Multiple) │    │ (Multiple)  │    │ (Multiple)  │
└─────────────┘    └─────────────┘    └─────────────┘
       ▲                   ▲                   ▲
       │                   │                   │
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│ Load        │    │ Message     │    │ Distributed │
│ Balancer    │    │ Queue       │    │ Storage     │
└─────────────┘    └─────────────┘    └─────────────┘
```

### Container Deployment
```dockerfile
# Multi-stage build
FROM python:3.11-slim as builder
RUN pip install --user -r requirements.txt

FROM python:3.11-slim
COPY --from=builder /root/.local /root/.local
COPY . /app
WORKDIR /app
CMD ["python", "-m", "server.nfc_relay_server"]
```

## Monitoring and Observability

### Logging Architecture
```python
# Structured logging
logger.info("session_created", extra={
    "session_id": session_id,
    "client_type": client_type,
    "timestamp": time.time(),
    "security_level": "high"
})
```

### Metrics Collection
```python
# Performance metrics
class MetricsCollector:
    - Session count and duration
    - Packet processing rates
    - Error rates and types
    - Resource utilization
```

### Health Monitoring
```python
# Health check endpoint
@app.route('/health')
def health_check():
    return {
        "status": "healthy",
        "version": __version__,
        "sessions_active": session_count,
        "uptime": uptime_seconds
    }
```

## Testing Strategy

### Unit Testing
```python
# Protocol testing
class TestISO14443Protocol:
    def test_reqa_detection(self):
        data = bytes.fromhex("2600")
        assert iso14443.identify(data) == True
```

### Integration Testing
```python
# End-to-end testing
class TestRelaySystem:
    async def test_session_lifecycle(self):
        # Test complete session from creation to cleanup
        pass
```

### Security Testing
```python
# Security test suite
class TestSecurity:
    def test_tls_configuration(self):
        # Verify TLS settings
        pass
    
    def test_encryption_at_rest(self):
        # Verify data encryption
        pass
```

### Performance Testing
```python
# Load testing
class TestPerformance:
    async def test_concurrent_sessions(self):
        # Test multiple simultaneous sessions
        pass
```

## Compliance and Standards

### Security Standards
- **NIST Cybersecurity Framework**: Implementation guidelines
- **OWASP Top 10**: Web application security
- **ISO 27001**: Information security management
- **Common Criteria**: Security evaluation criteria

### Privacy Regulations
- **GDPR**: European data protection
- **CCPA**: California privacy rights
- **PIPEDA**: Canadian privacy law
- **Local regulations**: Transit authority requirements

### Technical Standards
- **ISO 14443**: NFC protocol specifications
- **EMV**: Payment card standards
- **NIST SP 800-63**: Digital identity guidelines
- **RFC 8446**: TLS 1.3 specification

---

This technical architecture provides the foundation for secure, scalable, and extensible NFC research capabilities while maintaining strong security and privacy protections.