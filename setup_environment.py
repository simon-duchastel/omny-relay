#!/usr/bin/env python3
"""
Environment setup script for the NFC transit card relay system.
Sets up certificates, directories, and initial configuration.
"""

import os
import sys
import logging
from pathlib import Path
from src.utils.crypto import TLSManager, SecureStorage
from server.config import ConfigManager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def setup_directories(config: ConfigManager):
    """Create necessary directories with proper permissions."""
    directories = [
        Path("certs"),
        Path("logs"),
        Path(config.analysis.analysis_output_dir),
        Path(config.analysis.secure_storage_dir),
        Path("android"),
        Path("docs")
    ]
    
    for directory in directories:
        try:
            if directory.name in ["secure_data", "certs"]:
                directory.mkdir(exist_ok=True, mode=0o700)  # Restricted access
            else:
                directory.mkdir(exist_ok=True, mode=0o755)
            logger.info(f"✓ Created directory: {directory}")
        except OSError as e:
            logger.error(f"✗ Failed to create {directory}: {e}")
            return False
    
    return True


def setup_certificates(tls_manager: TLSManager, hostname: str = "localhost"):
    """Generate TLS certificates for secure communication."""
    try:
        logger.info("Setting up TLS certificates...")
        
        # Check if certificates already exist
        if tls_manager.cert_file.exists() and tls_manager.key_file.exists():
            logger.info("✓ Certificates already exist")
            return True
            
        # Generate new certificates
        cert, private_key = tls_manager.generate_self_signed_cert(hostname)
        tls_manager.save_certificate(cert, private_key)
        
        logger.info("✓ TLS certificates generated successfully")
        return True
        
    except Exception as e:
        logger.error(f"✗ Certificate generation failed: {e}")
        return False


def setup_secure_storage(storage_dir: str):
    """Initialize secure storage system."""
    try:
        logger.info("Setting up secure storage...")
        
        secure_storage = SecureStorage(storage_dir)
        
        # Test storage functionality
        test_data = {"test": "encryption_working", "timestamp": "2023-01-01"}
        storage_path = secure_storage.store_session_data("test_session", test_data)
        
        # Verify we can read it back
        loaded_data = secure_storage.load_session_data("test_session")
        assert loaded_data["test"] == "encryption_working"
        
        # Clean up test data
        secure_storage.delete_session("test_session")
        
        logger.info("✓ Secure storage initialized and tested")
        return True
        
    except Exception as e:
        logger.error(f"✗ Secure storage setup failed: {e}")
        return False


def create_config_files(config: ConfigManager):
    """Create initial configuration files."""
    try:
        logger.info("Creating configuration files...")
        
        # Save main configuration
        config.save_config()
        
        # Create logging configuration
        logging_config = {
            'version': 1,
            'disable_existing_loggers': False,
            'formatters': {
                'standard': {
                    'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                },
                'detailed': {
                    'format': '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s'
                }
            },
            'handlers': {
                'console': {
                    'class': 'logging.StreamHandler',
                    'formatter': 'standard',
                    'level': config.server.log_level
                },
                'file': {
                    'class': 'logging.handlers.RotatingFileHandler',
                    'filename': 'logs/nfc_relay.log',
                    'maxBytes': 10485760,  # 10MB
                    'backupCount': 5,
                    'formatter': 'detailed',
                    'level': 'DEBUG' if config.research.enable_detailed_logging else 'INFO'
                }
            },
            'loggers': {
                '': {  # Root logger
                    'handlers': ['console', 'file'],
                    'level': 'DEBUG' if config.research.enable_detailed_logging else 'INFO',
                    'propagate': False
                }
            }
        }
        
        import yaml
        with open('logging_config.yaml', 'w') as f:
            yaml.dump(logging_config, f, default_flow_style=False)
            
        logger.info("✓ Configuration files created")
        return True
        
    except Exception as e:
        logger.error(f"✗ Configuration file creation failed: {e}")
        return False


def create_android_guide():
    """Create guide for Android app setup."""
    android_guide = """# Android Setup Guide

## Requirements
- Android device with NFC support (Android 5.0+)
- One device must support Host Card Emulation (HCE)
- For advanced features: rooted device with Xposed framework

## NFCGate Installation
1. Download NFCGate APK from the official repository
2. Enable installation from unknown sources
3. Install the APK on your Android device(s)

## Configuration
1. Open NFCGate app
2. Go to Settings
3. Configure server connection:
   - Server hostname: [Your server IP/hostname]
   - Server port: 8080
   - Enable TLS: Yes (recommended)
   - Session ID: [6-digit session ID from server]

## Usage Modes

### Capture Mode
- Used for capturing NFC traffic from cards
- Place your transit card near the device
- Captured data will be sent to the server for analysis

### Relay Mode
- Requires two devices: Reader and Card
- Reader device: Scans the NFC card
- Card device: Emulates the card using HCE
- Server relays data between the devices

## Security Notes
- Always use TLS encryption for data transmission
- Only use for authorized research purposes
- Ensure compliance with local regulations
- Do not use on payment cards without authorization

## Troubleshooting
- Check NFC is enabled on device
- Verify network connectivity to server
- Ensure server certificate is trusted
- Check app permissions (NFC, Network)
"""
    
    with open('android/SETUP_GUIDE.md', 'w') as f:
        f.write(android_guide)
    
    logger.info("✓ Android setup guide created")


def create_docker_files():
    """Create Docker configuration files."""
    dockerfile = """FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \\
    build-essential \\
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p /app/certs /app/logs /app/output /app/secure
RUN chmod 700 /app/secure /app/certs

# Expose port
EXPOSE 8080

# Run the server
CMD ["python", "-m", "server.nfc_relay_server", "--host", "0.0.0.0", "--port", "8080"]
"""

    docker_compose = """version: '3.8'

services:
  nfc-relay:
    build: .
    ports:
      - "8080:8080"
    volumes:
      - ./certs:/app/certs
      - ./logs:/app/logs
      - ./output:/app/output
      - ./secure:/app/secure
    environment:
      - NFC_HOST=0.0.0.0
      - NFC_PORT=8080
      - NFC_RESEARCH_MODE=true
    restart: unless-stopped

  # Optional: Add a web dashboard
  # dashboard:
  #   build: ./dashboard
  #   ports:
  #     - "3000:3000"
  #   depends_on:
  #     - nfc-relay
"""

    with open('Dockerfile', 'w') as f:
        f.write(dockerfile)
        
    with open('docker-compose.yml', 'w') as f:
        f.write(docker_compose)
        
    logger.info("✓ Docker configuration files created")


def run_tests():
    """Run basic system tests."""
    logger.info("Running system tests...")
    
    tests_passed = 0
    tests_total = 0
    
    # Test 1: Import all modules
    tests_total += 1
    try:
        from server.nfc_relay_server import NFCRelayServer
        from src.analysis.packet_analyzer import PacketAnalyzer
        from src.analysis.transit_processor import TransitAnalyticsPipeline
        from src.utils.crypto import TLSManager, SecureStorage
        tests_passed += 1
        logger.info("✓ Module imports successful")
    except ImportError as e:
        logger.error(f"✗ Module import failed: {e}")
    
    # Test 2: Protocol buffer compilation
    tests_total += 1
    try:
        from src.protocol.messages_pb2 import Wrapper, SessionMessage
        wrapper = Wrapper()
        tests_passed += 1
        logger.info("✓ Protocol buffers working")
    except ImportError as e:
        logger.error(f"✗ Protocol buffer import failed: {e}")
    
    # Test 3: Configuration validation
    tests_total += 1
    try:
        config = ConfigManager()
        config.validate_config()
        tests_passed += 1
        logger.info("✓ Configuration validation passed")
    except Exception as e:
        logger.error(f"✗ Configuration validation failed: {e}")
    
    # Test 4: Certificate generation
    tests_total += 1
    try:
        tls_manager = TLSManager("test_certs")
        cert, key = tls_manager.generate_self_signed_cert()
        tests_passed += 1
        logger.info("✓ Certificate generation working")
        
        # Clean up test certificates
        import shutil
        if Path("test_certs").exists():
            shutil.rmtree("test_certs")
    except Exception as e:
        logger.error(f"✗ Certificate generation failed: {e}")
    
    logger.info(f"Tests completed: {tests_passed}/{tests_total} passed")
    return tests_passed == tests_total


def main():
    """Main setup routine."""
    print("🔧 Setting up NFC Transit Card Relay System")
    print("=" * 50)
    
    # Create configuration
    config = ConfigManager()
    config.enable_research_mode()  # Enable research features
    
    # Setup steps
    setup_steps = [
        ("Creating directories", lambda: setup_directories(config)),
        ("Setting up TLS certificates", lambda: setup_certificates(TLSManager())),
        ("Initializing secure storage", lambda: setup_secure_storage(config.analysis.secure_storage_dir)),
        ("Creating configuration files", lambda: create_config_files(config)),
        ("Creating Android guide", create_android_guide),
        ("Creating Docker files", create_docker_files),
        ("Running system tests", run_tests)
    ]
    
    success_count = 0
    for step_name, step_func in setup_steps:
        print(f"\n🔄 {step_name}...")
        try:
            if step_func():
                success_count += 1
            else:
                logger.error(f"Step failed: {step_name}")
        except Exception as e:
            logger.error(f"Step failed with exception: {step_name} - {e}")
    
    print(f"\n📊 Setup completed: {success_count}/{len(setup_steps)} steps successful")
    
    if success_count == len(setup_steps):
        print("\n✅ Setup completed successfully!")
        print("\nNext steps:")
        print("1. Review config.yaml and adjust settings as needed")
        print("2. Install NFCGate app on Android device(s)")
        print("3. Follow android/SETUP_GUIDE.md for device configuration")
        print("4. Start the server: python -m server.nfc_relay_server")
        print("5. Check logs/ directory for operational logs")
    else:
        print("\n⚠️  Setup completed with errors. Check logs above.")
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())