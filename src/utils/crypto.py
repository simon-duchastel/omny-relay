#!/usr/bin/env python3
"""
Cryptographic utilities for secure NFC relay communications.
Handles TLS configuration and certificate management.
"""

import ssl
import os
import logging
import ipaddress
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime

logger = logging.getLogger(__name__)


class TLSManager:
    """Manages TLS certificates and SSL context for secure communications."""
    
    def __init__(self, cert_dir: str = "certs"):
        self.cert_dir = Path(cert_dir)
        self.cert_dir.mkdir(exist_ok=True)
        
        self.cert_file = self.cert_dir / "server.crt"
        self.key_file = self.cert_dir / "server.key"
        self.ca_file = self.cert_dir / "ca.crt"
        
    def generate_self_signed_cert(self, hostname: str = "localhost") -> tuple:
        """Generate self-signed certificate for development/testing."""
        logger.info("Generating self-signed certificate...")
        
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
        # Create certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Research"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Lab"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NFC Transit Research"),
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(hostname),
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        ).sign(private_key, hashes.SHA256())
        
        return cert, private_key
        
    def save_certificate(self, cert, private_key):
        """Save certificate and private key to files."""
        # Write certificate
        with open(self.cert_file, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
            
        # Write private key
        with open(self.key_file, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
            
        logger.info(f"Certificate saved to {self.cert_file}")
        logger.info(f"Private key saved to {self.key_file}")
        
    def get_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context for secure connections."""
        # Generate certificate if it doesn't exist
        if not (self.cert_file.exists() and self.key_file.exists()):
            cert, private_key = self.generate_self_signed_cert()
            self.save_certificate(cert, private_key)
            
        # Create SSL context
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(self.cert_file, self.key_file)
        
        # Security settings
        context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        
        logger.info("SSL context configured with TLS 1.2+ and secure ciphers")
        return context
        
    def get_client_ssl_context(self, verify_cert: bool = False) -> ssl.SSLContext:
        """Create SSL context for client connections."""
        if verify_cert:
            context = ssl.create_default_context()
            if self.ca_file.exists():
                context.load_verify_locations(self.ca_file)
        else:
            # For development with self-signed certificates
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
        return context


class DataEncryption:
    """Handles encryption/decryption of sensitive NFC data."""
    
    def __init__(self, key: bytes = None):
        from cryptography.fernet import Fernet
        
        if key is None:
            key = Fernet.generate_key()
        self.cipher = Fernet(key)
        self.key = key
        
    def encrypt_data(self, data: bytes) -> bytes:
        """Encrypt NFC data for secure storage/transmission."""
        return self.cipher.encrypt(data)
        
    def decrypt_data(self, encrypted_data: bytes) -> bytes:
        """Decrypt NFC data."""
        return self.cipher.decrypt(encrypted_data)
        
    def get_key(self) -> bytes:
        """Get encryption key for sharing/storage."""
        return self.key


class SecureStorage:
    """Secure storage for sensitive research data."""
    
    def __init__(self, storage_dir: str = "secure_data"):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(exist_ok=True, mode=0o700)  # Restricted permissions
        
        self.encryption = DataEncryption()
        self._save_key()
        
    def _save_key(self):
        """Save encryption key securely."""
        key_file = self.storage_dir / ".key"
        with open(key_file, "wb") as f:
            f.write(self.encryption.get_key())
        os.chmod(key_file, 0o600)  # Owner read/write only
        
    def _load_key(self):
        """Load encryption key."""
        key_file = self.storage_dir / ".key"
        if key_file.exists():
            with open(key_file, "rb") as f:
                key = f.read()
            self.encryption = DataEncryption(key)
            
    def store_session_data(self, session_id: str, data: dict) -> str:
        """Store session data securely."""
        import json
        
        filename = f"session_{session_id}.enc"
        filepath = self.storage_dir / filename
        
        # Serialize and encrypt data
        json_data = json.dumps(data, default=str).encode()
        encrypted_data = self.encryption.encrypt_data(json_data)
        
        with open(filepath, "wb") as f:
            f.write(encrypted_data)
            
        os.chmod(filepath, 0o600)
        logger.info(f"Session data stored securely: {filepath}")
        return str(filepath)
        
    def load_session_data(self, session_id: str) -> dict:
        """Load and decrypt session data."""
        import json
        
        filename = f"session_{session_id}.enc"
        filepath = self.storage_dir / filename
        
        if not filepath.exists():
            raise FileNotFoundError(f"Session data not found: {session_id}")
            
        with open(filepath, "rb") as f:
            encrypted_data = f.read()
            
        # Decrypt and deserialize
        json_data = self.encryption.decrypt_data(encrypted_data)
        data = json.loads(json_data.decode())
        
        return data
        
    def list_sessions(self) -> list:
        """List all stored sessions."""
        sessions = []
        for file in self.storage_dir.glob("session_*.enc"):
            session_id = file.stem.replace("session_", "")
            sessions.append(session_id)
        return sessions
        
    def delete_session(self, session_id: str):
        """Securely delete session data."""
        filename = f"session_{session_id}.enc"
        filepath = self.storage_dir / filename
        
        if filepath.exists():
            # Secure deletion (overwrite with random data)
            import secrets
            file_size = filepath.stat().st_size
            
            with open(filepath, "r+b") as f:
                for _ in range(3):  # Multiple overwrites
                    f.seek(0)
                    f.write(secrets.token_bytes(file_size))
                    f.flush()
                    os.fsync(f.fileno())
                    
            filepath.unlink()
            logger.info(f"Session data securely deleted: {session_id}")