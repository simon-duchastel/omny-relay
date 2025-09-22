# Getting Started with NFC Transit Card Research

This quick start guide will get you up and running with the NFC Transit Card Relay System for security research.

## Overview

You've successfully set up a comprehensive NFC research platform that includes:

- **🔗 NFCGate-compatible relay server** with TLS encryption
- **📱 Android app integration** for NFC capture and relay
- **🔍 Advanced protocol analysis** for transit card systems
- **📊 Data visualization** and reporting tools
- **🔒 Enterprise-grade security** with encrypted storage

## Quick Start (5 minutes)

### 1. Verify Installation

```bash
# Check if environment is ready
source venv/bin/activate
python -c "from server.nfc_relay_server import NFCRelayServer; print('✅ Server ready')"
python -c "from src.analysis.packet_analyzer import PacketAnalyzer; print('✅ Analysis ready')"
```

### 2. Start the Server

```bash
# Start in development mode
python -m server.nfc_relay_server --debug

# Or start in background
python -m server.nfc_relay_server &
```

Server will start on `https://localhost:8080` with auto-generated certificates.

### 3. Configure Android Device

1. **Download NFCGate APK** from the official repository
2. **Install** on your Android device with NFC
3. **Configure connection**:
   - Server: Your computer's IP address
   - Port: 8080
   - Enable TLS: Yes
   - Session ID: (will be provided by server)

### 4. Test with Transit Card

1. **Select Capture mode** in NFCGate
2. **Tap your transit card** on the Android device
3. **Check server logs** for captured data
4. **View analysis results** in the web interface

## Research Workflow

### Basic Card Analysis

```bash
# 1. Capture NFC data using Android app
# 2. Analyze captured session
python -m src.analysis.transit_processor --session-id 123456

# 3. Generate visualizations
python -m src.analysis.visualizer --session-file analysis_output/session_123456.json --report

# 4. Export for further analysis
python -m src.analysis.packet_analyzer --export-pcap --session-id 123456
```

### Relay Attack Testing

```bash
# Setup requires 2 Android devices
# Device A: Reader mode (scans real card)
# Device B: Card mode (emulates to reader)

# Monitor relay in real-time
tail -f logs/nfc_relay.log | grep "RELAY"
```

### Protocol Research

```bash
# Analyze specific protocols
python -c "
from src.analysis.transit_processor import TransitProtocolDetector
detector = TransitProtocolDetector()
# Load your captured data and analyze
"

# Add support for new transit systems
# Edit src/analysis/transit_processor.py
# Add patterns to transit_patterns dictionary
```

## Supported Transit Systems

Currently includes analyzers for:

| System | Location | Status | Features |
|--------|----------|---------|----------|
| **Oyster** | London | ✅ Full | Balance, transactions, zones |
| **Clipper** | SF Bay | ✅ Full | Balance, transfers, locations |
| **OMNY** | NYC | ✅ Full | Tap patterns, fare detection |
| **Opal** | Sydney | ✅ Partial | Basic balance extraction |
| **CharlieCard** | Boston | 🔄 Basic | Limited protocol support |

## Key Features Implemented

### 🔒 Security & Privacy
- **TLS 1.3 encryption** for all communications
- **AES-256 storage encryption** for sensitive data
- **Certificate-based authentication** (production)
- **Secure session management** with timeouts
- **Privacy controls** with data anonymization

### 📡 Network Architecture
- **WebSocket-based protocol** for real-time relay
- **Protocol buffer serialization** for efficiency
- **Session-based multiplexing** for multiple devices
- **Automatic reconnection** and error handling
- **Rate limiting** and DoS protection

### 🧠 Analysis Engine
- **Real-time protocol detection** (ISO14443, MIFARE, FeliCa)
- **Transit system identification** with confidence scoring
- **Transaction parsing** from NFC data streams
- **Balance extraction** across different formats
- **Security vulnerability assessment**

### 📊 Visualization Suite
- **Session overview dashboards** with packet timelines
- **Protocol distribution analysis** 
- **Balance flow visualization** 
- **Security risk assessment** charts
- **Interactive HTML reports** with embedded graphics

### 🔧 Developer Tools
- **Extensible protocol framework** for new transit systems
- **Plugin architecture** for custom analysis
- **REST API** for external tool integration
- **Comprehensive logging** and metrics
- **Docker deployment** support

## File Structure

```
omny-relay/
├── server/                 # Relay server implementation
│   ├── nfc_relay_server.py # Main server with WebSocket handling
│   └── config.py          # Configuration management
├── src/
│   ├── protocol/          # Protocol buffer definitions
│   ├── analysis/          # Data analysis and processing
│   │   ├── packet_analyzer.py    # NFC packet analysis
│   │   ├── transit_processor.py  # Transit-specific parsing
│   │   └── visualizer.py         # Charts and reports
│   └── utils/             # Utilities and security
│       └── crypto.py      # TLS and encryption
├── android/               # Android app setup guides
├── docs/                  # Comprehensive documentation
├── certs/                 # TLS certificates (auto-generated)
├── analysis_output/       # Analysis results and reports
├── secure_data/           # Encrypted session storage
└── logs/                  # Application logs
```

## Development Setup

### Adding New Transit System Support

1. **Study the protocol** using captured packets
2. **Add patterns** to `TransitProtocolDetector`
3. **Implement parser** in `TransitDataParser`
4. **Test with real cards** and validate results
5. **Add visualizations** for new data types

Example:
```python
# In src/analysis/transit_processor.py
self.transit_patterns['new_system'] = {
    'card_id_pattern': re.compile(r'\x08[\x00-\xFF]{3}'),
    'balance_offset': 16,
    'balance_format': '>I',  # Big endian
    'currency_factor': 100,
}
```

### Extending Analysis

```python
# Custom analysis plugin
class CustomAnalyzer:
    def analyze_session(self, session_data):
        # Your custom analysis logic
        return analysis_results
        
# Register with main pipeline
from src.analysis.transit_processor import TransitAnalyticsPipeline
pipeline = TransitAnalyticsPipeline()
pipeline.register_analyzer(CustomAnalyzer())
```

## Common Use Cases

### Security Assessment
- Test for **unencrypted balance data**
- Identify **authentication weaknesses**
- Detect **replay attack vulnerabilities**
- Analyze **cryptographic implementations**

### Protocol Research
- **Reverse engineer** unknown transit protocols
- **Document command structures** and responses
- **Map data layouts** for different card types
- **Compare implementations** across systems

### Compliance Testing
- Verify **EMV contactless** compliance
- Test **ISO 14443** standard adherence
- Validate **security measures** implementation
- Check **privacy protection** mechanisms

## Troubleshooting

### Server Issues
```bash
# Check server status
curl -k https://localhost:8080/health

# View logs
tail -f logs/nfc_relay.log

# Test configuration
python server/config.py --validate
```

### Android Connection
```bash
# Test network connectivity
nmap -p 8080 <your-server-ip>

# Check certificate issues
openssl s_client -connect localhost:8080
```

### Analysis Problems
```bash
# List available sessions
python -m src.analysis.transit_processor --list-sessions

# Check analysis output
ls -la analysis_output/

# Verify data integrity
python -c "from src.utils.crypto import SecureStorage; print(SecureStorage().list_sessions())"
```

## Next Steps

1. **📖 Read the documentation** in `docs/` for detailed guides
2. **🧪 Try the examples** with your own transit cards
3. **🔬 Contribute** new protocol support for your local transit system
4. **🎯 Report findings** responsibly to transit authorities
5. **🤝 Share insights** with the security research community

## Legal Compliance

- ✅ **Only test your own cards** or with explicit permission
- ✅ **Follow responsible disclosure** for vulnerabilities
- ✅ **Respect privacy** and anonymize data
- ✅ **Comply with local laws** on NFC research
- ❌ **Never use for fraud** or unauthorized access

---

**🎉 You're ready to start your NFC transit card security research!**

For detailed documentation, see:
- `docs/TECHNICAL_ARCHITECTURE.md` - System design details
- `docs/API_REFERENCE.md` - Programming interfaces  
- `docs/DEPLOYMENT_GUIDE.md` - Production deployment
- `android/SETUP_GUIDE.md` - Android device configuration

Happy researching! 🔬