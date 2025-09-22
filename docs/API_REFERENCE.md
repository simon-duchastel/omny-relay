# API Reference

This document provides comprehensive API documentation for the NFC Transit Card Relay System, including WebSocket protocols, REST endpoints, and Python APIs.

## WebSocket Protocol API

The primary communication between Android devices and the relay server uses WebSocket connections with Protocol Buffer messages.

### Connection

**Endpoint**: `wss://server:8080/`

**Headers**:
```
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Version: 13
Sec-WebSocket-Protocol: nfc-relay-v1
```

**Authentication**: TLS client certificates (production) or none (development)

### Message Format

All messages use Protocol Buffer serialization with the following wrapper:

```protobuf
message Wrapper {
    required WrapperType type = 1;
    optional SessionMessage session = 2;
    optional DataMessage data = 3;
    optional StatusMessage status = 4;
}

enum WrapperType {
    SESSION = 1;
    DATA = 2;
    STATUS = 3;
}
```

### Session Management

#### Create Session

**Request**:
```protobuf
Wrapper {
    type: SESSION
    session: {
        opcode: SESSION_CREATE
        client_type: READER  // or CARD
    }
}
```

**Response**:
```protobuf
Wrapper {
    type: SESSION
    session: {
        opcode: SESSION_CREATE
        session_id: "123456"
    }
}
```

#### Join Session

**Request**:
```protobuf
Wrapper {
    type: SESSION
    session: {
        opcode: SESSION_JOIN
        session_id: "123456"
        client_type: CARD  // or READER
    }
}
```

**Response**:
```protobuf
Wrapper {
    type: STATUS
    status: {
        status: CONNECTED
        message: "Session joined successfully"
        timestamp: 1640995200000
    }
}
```

#### Leave Session

**Request**:
```protobuf
Wrapper {
    type: SESSION
    session: {
        opcode: SESSION_LEAVE
        session_id: "123456"
    }
}
```

### Data Relay

#### Send NFC Data

**Request**:
```protobuf
Wrapper {
    type: DATA
    data: {
        error_code: 0
        nfc_data: <binary_nfc_packet>
        timestamp: 1640995200123
        direction: "reader_to_card"
    }
}
```

**Relay to Peer**:
```protobuf
Wrapper {
    type: DATA
    data: {
        error_code: 0
        nfc_data: <binary_nfc_packet>
        timestamp: 1640995200123
        direction: "card_to_reader"
    }
}
```

### Status Messages

#### Connection Status

```protobuf
Wrapper {
    type: STATUS
    status: {
        status: CONNECTED|DISCONNECTED|ERROR|NFC_ENABLED|NFC_DISABLED|CARD_DETECTED|CARD_REMOVED
        message: "Optional status message"
        timestamp: 1640995200000
    }
}
```

### Error Handling

#### Error Response

```protobuf
Wrapper {
    type: STATUS
    status: {
        status: ERROR
        message: "Error description"
        timestamp: 1640995200000
    }
}
```

**Common Error Codes**:
- `SESSION_NOT_FOUND`: Session ID doesn't exist
- `SESSION_FULL`: Session already has maximum clients
- `INVALID_CLIENT_TYPE`: Wrong client type for session
- `RELAY_FAILED`: Failed to relay data to peer
- `INVALID_MESSAGE`: Malformed protocol buffer message

## REST API

The server provides REST endpoints for monitoring, configuration, and data export.

### Health Check

**GET** `/health`

**Response**:
```json
{
    "status": "healthy",
    "version": "1.0.0",
    "uptime": 3600,
    "active_sessions": 5,
    "total_connections": 12,
    "memory_usage": {
        "rss": 1234567,
        "heap_used": 987654
    }
}
```

### Metrics

**GET** `/metrics`

**Response** (Prometheus format):
```
# HELP nfc_relay_sessions_total Total number of sessions created
# TYPE nfc_relay_sessions_total counter
nfc_relay_sessions_total 42

# HELP nfc_relay_active_sessions Current number of active sessions
# TYPE nfc_relay_active_sessions gauge
nfc_relay_active_sessions 3

# HELP nfc_relay_packets_processed_total Total number of packets processed
# TYPE nfc_relay_packets_processed_total counter
nfc_relay_packets_processed_total{direction="reader_to_card"} 1234
nfc_relay_packets_processed_total{direction="card_to_reader"} 1156

# HELP nfc_relay_packet_processing_duration_seconds Time spent processing packets
# TYPE nfc_relay_packet_processing_duration_seconds histogram
nfc_relay_packet_processing_duration_seconds_bucket{le="0.01"} 800
nfc_relay_packet_processing_duration_seconds_bucket{le="0.05"} 900
nfc_relay_packet_processing_duration_seconds_bucket{le="0.1"} 950
nfc_relay_packet_processing_duration_seconds_bucket{le="+Inf"} 1000
```

### Session Management

#### List Sessions

**GET** `/api/v1/sessions`

**Response**:
```json
{
    "sessions": [
        {
            "session_id": "123456",
            "created_at": "2023-12-31T12:00:00Z",
            "clients": ["READER", "CARD"],
            "packet_count": 42,
            "status": "active"
        }
    ],
    "total": 1
}
```

#### Get Session Details

**GET** `/api/v1/sessions/{session_id}`

**Response**:
```json
{
    "session_id": "123456",
    "created_at": "2023-12-31T12:00:00Z",
    "duration": 120.5,
    "clients": {
        "READER": {
            "connected_at": "2023-12-31T12:00:00Z",
            "packets_sent": 21,
            "packets_received": 20
        },
        "CARD": {
            "connected_at": "2023-12-31T12:00:30Z",
            "packets_sent": 20,
            "packets_received": 21
        }
    },
    "packet_count": 42,
    "data_volume": 8192,
    "status": "active"
}
```

#### Close Session

**DELETE** `/api/v1/sessions/{session_id}`

**Response**:
```json
{
    "message": "Session closed successfully",
    "session_id": "123456"
}
```

### Data Export

#### Export Session Data

**GET** `/api/v1/sessions/{session_id}/export?format=pcap`

**Query Parameters**:
- `format`: `pcap`, `json`, `csv`
- `include_analysis`: `true`, `false` (default: false)

**Response** (Content-Type varies by format):
- PCAP: `application/vnd.tcpdump.pcap`
- JSON: `application/json`  
- CSV: `text/csv`

#### Export Analysis Results

**GET** `/api/v1/sessions/{session_id}/analysis`

**Response**:
```json
{
    "session_id": "123456",
    "analysis_timestamp": "2023-12-31T12:05:00Z",
    "protocols_detected": ["ISO14443", "MIFARE"],
    "cards_detected": [
        {
            "card_id": "04A1B2C3",
            "card_type": "MIFARE/oyster",
            "current_balance": 15.50,
            "transactions": [
                {
                    "timestamp": "2023-12-31T12:01:00Z",
                    "type": "tap_in",
                    "amount": -2.90,
                    "location": "King's Cross",
                    "confidence": 0.95
                }
            ]
        }
    ],
    "security_analysis": {
        "vulnerabilities": [
            "Unencrypted balance data detected",
            "No authentication required for card access"
        ],
        "risk_score": 7.5
    }
}
```

### Configuration

#### Get Configuration

**GET** `/api/v1/config`

**Response**:
```json
{
    "server": {
        "host": "0.0.0.0",
        "port": 8080,
        "tls_enabled": true
    },
    "security": {
        "session_timeout": 3600,
        "max_session_size": 10485760,
        "require_client_cert": false
    },
    "analysis": {
        "enable_realtime_analysis": true,
        "export_pcap": true,
        "output_dir": "analysis_output"
    }
}
```

#### Update Configuration

**PUT** `/api/v1/config`

**Request**:
```json
{
    "security": {
        "session_timeout": 7200
    },
    "analysis": {
        "enable_realtime_analysis": false
    }
}
```

**Response**:
```json
{
    "message": "Configuration updated successfully",
    "restart_required": true
}
```

## Python API

### Core Classes

#### NFCRelayServer

```python
from server.nfc_relay_server import NFCRelayServer

class NFCRelayServer:
    def __init__(self, host: str = "0.0.0.0", port: int = 8080, use_tls: bool = True):
        """Initialize NFC relay server.
        
        Args:
            host: Server bind address
            port: Server port
            use_tls: Enable TLS encryption
        """
    
    async def start_server(self) -> None:
        """Start the relay server."""
    
    def generate_session_id(self) -> str:
        """Generate unique 6-digit session ID."""
    
    async def handle_message(self, websocket, message: bytes) -> None:
        """Process incoming WebSocket message."""
```

#### Session

```python
class Session:
    def __init__(self, session_id: str):
        """Initialize session.
        
        Args:
            session_id: Unique session identifier
        """
    
    def add_client(self, client_type: str, websocket) -> None:
        """Add client to session.
        
        Args:
            client_type: "READER" or "CARD"
            websocket: WebSocket connection
        """
    
    def log_data(self, data: bytes, direction: str) -> None:
        """Log NFC data packet.
        
        Args:
            data: NFC packet data
            direction: Data flow direction
        """
    
    def is_complete(self) -> bool:
        """Check if session has both reader and card."""
```

### Analysis API

#### PacketAnalyzer

```python
from src.analysis.packet_analyzer import PacketAnalyzer

class PacketAnalyzer:
    def __init__(self, output_dir: str = "analysis_output"):
        """Initialize packet analyzer.
        
        Args:
            output_dir: Directory for analysis output
        """
    
    async def analyze_nfc_packet(self, data: bytes, client_type: str, session_id: str) -> Dict:
        """Analyze single NFC packet.
        
        Args:
            data: NFC packet data
            client_type: Source client type
            session_id: Session identifier
            
        Returns:
            Analysis results dictionary
        """
    
    async def export_session_pcap(self, session) -> None:
        """Export session as PCAP file.
        
        Args:
            session: Session object to export
        """
```

#### TransitAnalyticsPipeline

```python
from src.analysis.transit_processor import TransitAnalyticsPipeline

class TransitAnalyticsPipeline:
    def __init__(self, output_dir: str = "analytics_output"):
        """Initialize analytics pipeline.
        
        Args:
            output_dir: Directory for output files
        """
    
    async def process_session(self, session_id: str, session_data: List[Dict]) -> Dict:
        """Process complete session data.
        
        Args:
            session_id: Session identifier
            session_data: List of packet data
            
        Returns:
            Comprehensive analysis results
        """
    
    async def generate_report(self, session_ids: List[str]) -> str:
        """Generate analysis report.
        
        Args:
            session_ids: List of session IDs to include
            
        Returns:
            Path to generated report file
        """
```

### Protocol Analysis API

#### TransitProtocolDetector

```python
from src.analysis.transit_processor import TransitProtocolDetector

class TransitProtocolDetector:
    def detect_protocol(self, data: bytes) -> Tuple[str, float]:
        """Detect NFC protocol in data.
        
        Args:
            data: NFC packet data
            
        Returns:
            Tuple of (protocol_name, confidence_score)
        """
    
    def detect_transit_system(self, data: bytes, card_id: str) -> Tuple[str, float]:
        """Detect specific transit system.
        
        Args:
            data: NFC packet data
            card_id: Extracted card identifier
            
        Returns:
            Tuple of (system_name, confidence_score)
        """
```

#### TransitDataParser

```python
from src.analysis.transit_processor import TransitDataParser

class TransitDataParser:
    def parse_card_data(self, data: bytes, session_data: List[Dict]) -> CardInfo:
        """Parse transit card information.
        
        Args:
            data: NFC packet data
            session_data: Complete session packet list
            
        Returns:
            Parsed card information
        """
    
    def extract_transactions(self, session_data: List[Dict], card_id: str, 
                           transit_system: str) -> List[TransitTransaction]:
        """Extract transaction data from session.
        
        Args:
            session_data: Complete session packet list
            card_id: Card identifier
            transit_system: Detected transit system
            
        Returns:
            List of extracted transactions
        """
```

### Visualization API

#### NFCDataVisualizer

```python
from src.analysis.visualizer import NFCDataVisualizer

class NFCDataVisualizer:
    def __init__(self, output_dir: str = "visualizations"):
        """Initialize data visualizer.
        
        Args:
            output_dir: Directory for visualization output
        """
    
    def create_session_overview(self, session_data: Dict) -> str:
        """Create session overview visualization.
        
        Args:
            session_data: Session analysis data
            
        Returns:
            Path to generated visualization file
        """
    
    def create_protocol_timeline(self, session_data: Dict) -> str:
        """Create protocol timeline visualization.
        
        Args:
            session_data: Session analysis data
            
        Returns:
            Path to generated timeline file
        """
    
    def create_security_dashboard(self, sessions_data: List[Dict]) -> str:
        """Create security analysis dashboard.
        
        Args:
            sessions_data: List of session analysis data
            
        Returns:
            Path to generated dashboard file
        """
```

### Security API

#### TLSManager

```python
from src.utils.crypto import TLSManager

class TLSManager:
    def __init__(self, cert_dir: str = "certs"):
        """Initialize TLS certificate manager.
        
        Args:
            cert_dir: Directory for certificate storage
        """
    
    def generate_self_signed_cert(self, hostname: str = "localhost") -> Tuple[Any, Any]:
        """Generate self-signed certificate.
        
        Args:
            hostname: Certificate hostname
            
        Returns:
            Tuple of (certificate, private_key)
        """
    
    def get_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context for server.
        
        Returns:
            Configured SSL context
        """
```

#### SecureStorage

```python
from src.utils.crypto import SecureStorage

class SecureStorage:
    def __init__(self, storage_dir: str = "secure_data"):
        """Initialize secure storage system.
        
        Args:
            storage_dir: Directory for encrypted storage
        """
    
    def store_session_data(self, session_id: str, data: Dict) -> str:
        """Store session data securely.
        
        Args:
            session_id: Session identifier
            data: Session data to encrypt and store
            
        Returns:
            Path to stored file
        """
    
    def load_session_data(self, session_id: str) -> Dict:
        """Load and decrypt session data.
        
        Args:
            session_id: Session identifier
            
        Returns:
            Decrypted session data
        """
    
    def list_sessions(self) -> List[str]:
        """List all stored sessions.
        
        Returns:
            List of session IDs
        """
```

### Configuration API

#### ConfigManager

```python
from server.config import ConfigManager

class ConfigManager:
    def __init__(self, config_file: str = "config.yaml"):
        """Initialize configuration manager.
        
        Args:
            config_file: Path to configuration file
        """
    
    def load_config(self) -> None:
        """Load configuration from file."""
    
    def save_config(self) -> None:
        """Save current configuration to file."""
    
    def validate_config(self) -> None:
        """Validate configuration settings."""
    
    def apply_security_hardening(self) -> None:
        """Apply security hardening settings."""
    
    def enable_research_mode(self) -> None:
        """Enable research-specific settings."""
```

## WebSocket Client Example

### Python Client

```python
import asyncio
import websockets
import ssl
from src.protocol.messages_pb2 import Wrapper, SessionMessage, DataMessage

async def nfc_client():
    # Create SSL context for secure connection
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE  # Development only
    
    uri = "wss://localhost:8080/"
    
    async with websockets.connect(uri, ssl=ssl_context) as websocket:
        # Create session
        wrapper = Wrapper()
        wrapper.type = Wrapper.SESSION
        wrapper.session.opcode = SessionMessage.SESSION_CREATE
        wrapper.session.client_type = SessionMessage.READER
        
        await websocket.send(wrapper.SerializeToString())
        
        # Wait for session response
        response = await websocket.recv()
        response_wrapper = Wrapper()
        response_wrapper.ParseFromString(response)
        
        session_id = response_wrapper.session.session_id
        print(f"Session created: {session_id}")
        
        # Send NFC data
        data_wrapper = Wrapper()
        data_wrapper.type = Wrapper.DATA
        data_wrapper.data.error_code = 0
        data_wrapper.data.nfc_data = b'\x26\x00'  # REQA command
        data_wrapper.data.timestamp = int(time.time() * 1000)
        data_wrapper.data.direction = "reader_to_card"
        
        await websocket.send(data_wrapper.SerializeToString())
        
        # Listen for responses
        async for message in websocket:
            response_wrapper = Wrapper()
            response_wrapper.ParseFromString(message)
            
            if response_wrapper.type == Wrapper.DATA:
                print(f"Received NFC data: {response_wrapper.data.nfc_data.hex()}")
            elif response_wrapper.type == Wrapper.STATUS:
                print(f"Status: {response_wrapper.status.message}")

# Run client
asyncio.run(nfc_client())
```

### JavaScript Client

```javascript
class NFCRelayClient {
    constructor(url) {
        this.url = url;
        this.socket = null;
        this.sessionId = null;
    }
    
    async connect() {
        this.socket = new WebSocket(this.url);
        this.socket.binaryType = 'arraybuffer';
        
        this.socket.onopen = () => {
            console.log('Connected to NFC relay server');
            this.createSession();
        };
        
        this.socket.onmessage = (event) => {
            this.handleMessage(event.data);
        };
        
        this.socket.onerror = (error) => {
            console.error('WebSocket error:', error);
        };
    }
    
    createSession() {
        // Create session message using protocol buffers
        const wrapper = new proto.nfcgate.Wrapper();
        wrapper.setType(proto.nfcgate.WrapperType.SESSION);
        
        const sessionMsg = new proto.nfcgate.SessionMessage();
        sessionMsg.setOpcode(proto.nfcgate.SessionMessage.SessionOpcode.SESSION_CREATE);
        sessionMsg.setClientType(proto.nfcgate.SessionMessage.ClientType.READER);
        
        wrapper.setSession(sessionMsg);
        
        this.socket.send(wrapper.serializeBinary());
    }
    
    sendNFCData(data) {
        const wrapper = new proto.nfcgate.Wrapper();
        wrapper.setType(proto.nfcgate.WrapperType.DATA);
        
        const dataMsg = new proto.nfcgate.DataMessage();
        dataMsg.setErrorCode(0);
        dataMsg.setNfcData(data);
        dataMsg.setTimestamp(Date.now());
        dataMsg.setDirection('reader_to_card');
        
        wrapper.setData(dataMsg);
        
        this.socket.send(wrapper.serializeBinary());
    }
    
    handleMessage(data) {
        const wrapper = proto.nfcgate.Wrapper.deserializeBinary(data);
        
        switch (wrapper.getType()) {
            case proto.nfcgate.WrapperType.SESSION:
                this.sessionId = wrapper.getSession().getSessionId();
                console.log('Session ID:', this.sessionId);
                break;
                
            case proto.nfcgate.WrapperType.DATA:
                const nfcData = wrapper.getData().getNfcData();
                console.log('Received NFC data:', Array.from(nfcData).map(b => b.toString(16).padStart(2, '0')).join(''));
                break;
                
            case proto.nfcgate.WrapperType.STATUS:
                console.log('Status:', wrapper.getStatus().getMessage());
                break;
        }
    }
}

// Usage
const client = new NFCRelayClient('wss://localhost:8080/');
client.connect();
```

## Error Codes

### WebSocket Error Codes

| Code | Name | Description |
|------|------|-------------|
| 1000 | Normal Closure | Session completed normally |
| 1001 | Going Away | Server shutting down |
| 1002 | Protocol Error | Invalid message format |
| 1003 | Unsupported Data | Message type not supported |
| 1007 | Invalid Data | Malformed protocol buffer |
| 1008 | Policy Violation | Security policy violation |
| 1011 | Internal Error | Server internal error |

### Application Error Codes

| Code | Name | Description |
|------|------|-------------|
| 4000 | Session Not Found | Session ID doesn't exist |
| 4001 | Session Full | Maximum clients reached |
| 4002 | Invalid Client Type | Wrong client type for session |
| 4003 | Authentication Failed | Client authentication failed |
| 4004 | Rate Limited | Too many requests |
| 4005 | Message Too Large | Message exceeds size limit |
| 4006 | Session Timeout | Session expired |
| 4007 | Relay Failed | Failed to relay to peer |

## Rate Limiting

### Default Limits

- **Connection Rate**: 10 connections per minute per IP
- **Message Rate**: 1000 messages per minute per session
- **Data Rate**: 10 MB per minute per session
- **Session Creation**: 5 sessions per minute per IP

### Rate Limit Headers (REST API)

```http
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1640995260
X-RateLimit-Retry-After: 60
```

### Rate Limit Exceeded Response

```json
{
    "error": "Rate limit exceeded",
    "code": 429,
    "retry_after": 60,
    "limit": 1000,
    "remaining": 0
}
```

This API reference provides comprehensive documentation for integrating with and extending the NFC Transit Card Relay System.