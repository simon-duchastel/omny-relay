# NFC Transit Card Relay System

A comprehensive research platform for analyzing NFC transit card communications, built on NFCGate architecture with advanced data processing and security features.

## 🎯 Project Overview

This system enables security researchers to:
- **Capture NFC traffic** from transit cards using Android devices
- **Relay communications** between NFC readers and cards over network
- **Analyze protocols** used by various transit card systems  
- **Extract transaction data** and card information
- **Visualize patterns** in transit card usage
- **Assess security** of contactless payment systems

## ⚠️ Legal Notice

**This tool is for authorized security research only.** 

- Only use on cards you own or have explicit permission to test
- Comply with all local laws regarding NFC/RFID research
- Do not use for payment card fraud or unauthorized access
- Respect transit authority terms of service
- Use responsibly and ethically

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Android App   │◄──►│  Relay Server   │◄──►│ Analysis Engine │
│   (NFCGate)     │    │  (Python)       │    │   (Python)      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
        │                       │                       │
        │                       │                       │
   ┌────▼────┐             ┌────▼────┐             ┌────▼────┐
   │ NFC Card│             │   TLS   │             │ Storage │
   │ Reader  │             │Security │             │Encryption│
   └─────────┘             └─────────┘             └─────────┘
```

### Core Components

1. **NFCGate Android App**: Captures NFC communications from transit cards
2. **Python Relay Server**: Handles secure communication between devices  
3. **Protocol Analyzer**: Identifies and parses transit card protocols
4. **Data Processor**: Extracts transactions, balances, and card metadata
5. **Visualization Engine**: Creates charts and reports from captured data
6. **Security Layer**: TLS encryption and secure data storage

## 🚀 Quick Start

### Prerequisites

- **Hardware**: 
  - 1-2 Android devices with NFC (Android 5.0+)
  - At least one device with Host Card Emulation (HCE)
  - Computer for running relay server
  
- **Software**:
  - Python 3.8+
  - Android Debug Bridge (ADB) for app installation
  - NFCGate APK (from official repository)

### Installation

1. **Clone and Setup**
   ```bash
   git clone <repository-url>
   cd omny-relay
   python3 setup_environment.py
   ```

2. **Install Dependencies**
   ```bash
   source venv/bin/activate
   pip install -r requirements.txt
   ```

3. **Run Initial Setup**
   ```bash
   python3 setup_environment.py
   ```

4. **Start the Server**
   ```bash
   python -m server.nfc_relay_server
   ```

5. **Configure Android App**
   - Follow `android/SETUP_GUIDE.md`
   - Install NFCGate APK on device(s)
   - Configure server connection

## 📱 Android Setup

See detailed instructions in [`android/SETUP_GUIDE.md`](android/SETUP_GUIDE.md).

**Quick Summary:**
1. Install NFCGate APK
2. Configure server hostname/IP and port 8080
3. Enable TLS encryption
4. Generate session ID from server
5. Select capture or relay mode

## 🔧 Configuration

### Server Configuration

Edit `config.yaml` to customize:

```yaml
security:
  enable_tls: true
  cert_file: "certs/server.crt"
  session_timeout: 3600

server:
  host: "0.0.0.0"
  port: 8080
  max_connections: 100

analysis:
  enable_realtime_analysis: true
  export_pcap: true
  output_dir: "analysis_output"

research:
  research_mode: true
  anonymize_data: true
```

### Security Hardening

For production use:
```bash
python server/config.py --harden
```

### Development Mode

For research environments:
```bash
python server/config.py --research
```

## 📊 Usage Examples

### Basic Card Analysis

1. **Start Server**
   ```bash
   python -m server.nfc_relay_server
   ```

2. **Connect Android Device**
   - Configure NFCGate with server details
   - Select "Capture" mode
   - Tap your transit card on the device

3. **View Results**
   ```bash
   # List captured sessions
   python -m src.analysis.transit_processor --list-sessions
   
   # Analyze specific session
   python -m src.analysis.transit_processor --session-id 123456
   
   # Generate visualizations
   python -m src.analysis.visualizer --sessions-dir analysis_output --report
   ```

### Relay Attack Testing

1. **Setup Two Android Devices**
   - Device A: Reader mode
   - Device B: Card emulation mode

2. **Configure Both Devices**
   - Same session ID
   - Different client types (Reader/Card)

3. **Test Relay**
   - Place transit card near Device A
   - Use Device B near card reader
   - Monitor relay in server logs

### Protocol Analysis

```bash
# Analyze captured protocols
python -m src.analysis.packet_analyzer --session-file session_123456.json

# Generate protocol timeline
python -m src.analysis.visualizer --session-file session_123456.json --interactive

# Export to Wireshark
# PCAP files automatically generated in analysis_output/
```

## 🔍 Supported Transit Systems

The system includes protocol analyzers for:

- **ISO 14443 Type A/B** (Most common)
- **MIFARE Classic/Plus** (Oyster, Clipper, etc.)
- **FeliCa** (Japanese transit cards)
- **Custom protocols** (extensible framework)

### Transit Card Compatibility

| System | Location | Protocol | Status |
|--------|----------|----------|---------|
| Oyster | London | MIFARE | ✅ Supported |
| Clipper | SF Bay Area | MIFARE | ✅ Supported |
| OMNY | New York | ISO14443 | ✅ Supported |
| Opal | Sydney | MIFARE | ✅ Supported |
| CharlieCard | Boston | MIFARE | ✅ Supported |
| Suica | Tokyo | FeliCa | 🔄 Partial |

## 📈 Analysis Features

### Real-time Analysis
- Protocol identification
- Transaction detection  
- Balance extraction
- Security assessment

### Visualizations
- Session timelines
- Protocol distribution
- Balance flow analysis
- Security dashboards

### Export Formats
- PCAP for Wireshark
- JSON for custom analysis
- CSV for spreadsheet tools
- HTML reports with charts

## 🔒 Security Features

### Data Protection
- **TLS 1.3 encryption** for all communications
- **AES encryption** for data storage
- **Secure key management** with rotation
- **Access controls** and audit logging

### Privacy Controls
- **Data anonymization** options
- **Automatic cleanup** after retention period
- **Secure deletion** with overwriting
- **No cloud storage** by default

### Security Analysis
- **Vulnerability detection** in card protocols
- **Replay attack** identification
- **Encryption assessment** 
- **Authentication analysis**

## 🐳 Docker Deployment

```bash
# Build image
docker-compose build

# Run services
docker-compose up -d

# View logs
docker-compose logs -f nfc-relay
```

## 🧪 Development

### Running Tests

```bash
# Install test dependencies
pip install pytest pytest-asyncio

# Run all tests
pytest tests/

# Run with coverage
pytest --cov=src tests/
```

### Adding Protocol Support

1. Create new protocol class in `src/analysis/protocols/`
2. Inherit from `TransitCardProtocol` base class
3. Implement `identify()` and `parse()` methods
4. Register in `TransitProtocolDetector`

Example:
```python
class NewTransitProtocol(TransitCardProtocol):
    def identify(self, data: bytes) -> bool:
        return data.startswith(b'\\x42')  # Your protocol signature
        
    def parse(self, data: bytes) -> Dict:
        # Extract protocol-specific fields
        return {'protocol': 'NewTransit', 'data': parsed_data}
```

### Adding Visualizations

1. Add methods to `NFCDataVisualizer` class
2. Use matplotlib/seaborn for static charts
3. Use plotly for interactive visualizations
4. Update HTML report generator

## 📋 API Reference

### Server API

The relay server exposes WebSocket endpoints:

```python
# Connect to server
ws://localhost:8080/

# Message format (Protocol Buffers)
{
  "type": "SESSION|DATA|STATUS",
  "session": { "opcode": "CREATE", "client_type": "READER" },
  "data": { "nfc_data": bytes, "timestamp": 1234567890 }
}
```

### Analysis API

```python
from src.analysis.transit_processor import TransitAnalyticsPipeline

# Initialize processor
pipeline = TransitAnalyticsPipeline()

# Process session
analysis = await pipeline.process_session(session_id, packet_data)

# Generate report
report = await pipeline.generate_report(session_ids)
```

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/new-protocol`)
3. Commit changes (`git commit -am 'Add NewProtocol support'`)
4. Push branch (`git push origin feature/new-protocol`)
5. Create Pull Request

### Code Standards
- Follow PEP 8 for Python code
- Add type hints for all functions
- Include docstrings for public APIs
- Write tests for new features
- Update documentation

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

### Third-Party Components
- NFCGate: Apache 2.0 License
- Protocol Buffers: BSD License
- Scapy: GPL v2 License

## 🙏 Acknowledgments

- **NFCGate Team** at TU Darmstadt for the original Android app
- **Transit research community** for protocol documentation
- **Security researchers** who responsibly disclosed vulnerabilities

## 📞 Support

- **Issues**: Report bugs via GitHub Issues
- **Discussions**: Use GitHub Discussions for questions
- **Security**: Email security@[domain] for vulnerabilities
- **Documentation**: See `docs/` directory for detailed guides

## 🗺️ Roadmap

### v1.1 (Next Release)
- [ ] Support for more transit systems
- [ ] Machine learning for protocol detection
- [ ] Real-time alerting system
- [ ] REST API for external tools

### v2.0 (Future)
- [ ] Web-based dashboard
- [ ] Distributed analysis cluster
- [ ] Advanced crypto analysis
- [ ] Mobile app for iOS

---

**⚠️ Remember: This tool is for authorized security research only. Use responsibly and ethically.**