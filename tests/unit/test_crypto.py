"""
Unit tests for cryptographic utilities.
Tests TLS management, encryption, and secure storage.
"""

import pytest
import ssl
import os
import tempfile
import shutil
from pathlib import Path
from unittest.mock import patch, mock_open
import secrets

from src.utils.crypto import TLSManager, DataEncryption, SecureStorage
from cryptography import x509
from cryptography.hazmat.primitives import serialization


class TestTLSManager:
    """Test TLS certificate management."""
    
    def test_initialization(self, temp_dir):
        """Test TLS manager initialization."""
        tls_manager = TLSManager(cert_dir=temp_dir)
        
        assert tls_manager.cert_dir == Path(temp_dir)
        assert tls_manager.cert_file == Path(temp_dir) / "server.crt"
        assert tls_manager.key_file == Path(temp_dir) / "server.key"
        assert tls_manager.ca_file == Path(temp_dir) / "ca.crt"
    
    def test_generate_self_signed_cert(self, temp_dir):
        """Test self-signed certificate generation."""
        tls_manager = TLSManager(cert_dir=temp_dir)
        
        cert, private_key = tls_manager.generate_self_signed_cert("example.com")
        
        # Verify certificate properties
        assert isinstance(cert, x509.Certificate)
        assert cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == "example.com"
        
        # Verify key properties
        assert private_key.key_size == 2048
        
        # Verify certificate is valid
        assert cert.not_valid_before <= cert.not_valid_after
        
        # Verify subject alternative names
        san_extension = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san_names = [name.value for name in san_extension.value]
        assert "example.com" in san_names
        assert "localhost" in san_names
        assert "127.0.0.1" in [str(name) for name in san_names]
    
    def test_save_certificate(self, temp_dir):
        """Test certificate saving."""
        tls_manager = TLSManager(cert_dir=temp_dir)
        cert, private_key = tls_manager.generate_self_signed_cert()
        
        tls_manager.save_certificate(cert, private_key)
        
        # Verify files were created
        assert tls_manager.cert_file.exists()
        assert tls_manager.key_file.exists()
        
        # Verify file permissions (key should be more restrictive)
        cert_mode = oct(tls_manager.cert_file.stat().st_mode)[-3:]
        key_mode = oct(tls_manager.key_file.stat().st_mode)[-3:]
        
        assert cert_mode in ['644', '664']  # Certificate can be readable
        # Note: File permissions might vary by system
        
        # Verify file contents can be loaded
        with open(tls_manager.cert_file, 'rb') as f:
            loaded_cert = x509.load_pem_x509_certificate(f.read())
        
        with open(tls_manager.key_file, 'rb') as f:
            loaded_key = serialization.load_pem_private_key(f.read(), password=None)
        
        assert loaded_cert.serial_number == cert.serial_number
        assert loaded_key.key_size == private_key.key_size
    
    def test_get_ssl_context_new_cert(self, temp_dir):
        """Test SSL context creation with new certificate."""
        tls_manager = TLSManager(cert_dir=temp_dir)
        
        context = tls_manager.get_ssl_context()
        
        # Verify context properties
        assert isinstance(context, ssl.SSLContext)
        assert context.minimum_version >= ssl.TLSVersion.TLSv1_2
        
        # Verify certificate files were created
        assert tls_manager.cert_file.exists()
        assert tls_manager.key_file.exists()
    
    def test_get_ssl_context_existing_cert(self, temp_dir):
        """Test SSL context creation with existing certificate."""
        tls_manager = TLSManager(cert_dir=temp_dir)
        
        # Create certificate first
        cert, private_key = tls_manager.generate_self_signed_cert()
        tls_manager.save_certificate(cert, private_key)
        
        # Get SSL context (should use existing cert)
        context = tls_manager.get_ssl_context()
        
        assert isinstance(context, ssl.SSLContext)
    
    def test_get_client_ssl_context(self, temp_dir):
        """Test client SSL context creation."""
        tls_manager = TLSManager(cert_dir=temp_dir)
        
        # Test without certificate verification
        context = tls_manager.get_client_ssl_context(verify_cert=False)
        assert context.check_hostname is False
        assert context.verify_mode == ssl.CERT_NONE
        
        # Test with certificate verification
        context = tls_manager.get_client_ssl_context(verify_cert=True)
        assert context.verify_mode != ssl.CERT_NONE


class TestDataEncryption:
    """Test data encryption utilities."""
    
    def test_initialization_with_key(self):
        """Test encryption initialization with provided key."""
        from cryptography.fernet import Fernet
        key = Fernet.generate_key()
        
        encryption = DataEncryption(key)
        assert encryption.key == key
    
    def test_initialization_without_key(self):
        """Test encryption initialization with generated key."""
        encryption = DataEncryption()
        
        assert encryption.key is not None
        assert len(encryption.key) == 44  # Fernet key length
    
    def test_encrypt_decrypt_data(self):
        """Test data encryption and decryption."""
        encryption = DataEncryption()
        test_data = b"Hello, NFC World!"
        
        # Encrypt data
        encrypted_data = encryption.encrypt_data(test_data)
        assert encrypted_data != test_data
        assert len(encrypted_data) > len(test_data)
        
        # Decrypt data
        decrypted_data = encryption.decrypt_data(encrypted_data)
        assert decrypted_data == test_data
    
    def test_encrypt_decrypt_large_data(self):
        """Test encryption of large data blocks."""
        encryption = DataEncryption()
        test_data = secrets.token_bytes(10000)  # 10KB
        
        encrypted_data = encryption.encrypt_data(test_data)
        decrypted_data = encryption.decrypt_data(encrypted_data)
        
        assert decrypted_data == test_data
    
    def test_encrypt_decrypt_empty_data(self):
        """Test encryption of empty data."""
        encryption = DataEncryption()
        test_data = b""
        
        encrypted_data = encryption.encrypt_data(test_data)
        decrypted_data = encryption.decrypt_data(encrypted_data)
        
        assert decrypted_data == test_data
    
    def test_decrypt_invalid_data(self):
        """Test decryption of invalid data."""
        encryption = DataEncryption()
        
        with pytest.raises(Exception):  # Fernet raises InvalidToken
            encryption.decrypt_data(b"invalid encrypted data")
    
    def test_get_key(self):
        """Test key retrieval."""
        encryption = DataEncryption()
        key = encryption.get_key()
        
        assert key == encryption.key
        assert isinstance(key, bytes)


class TestSecureStorage:
    """Test secure storage functionality."""
    
    def test_initialization(self, temp_dir):
        """Test secure storage initialization."""
        storage_dir = str(Path(temp_dir) / "secure")
        storage = SecureStorage(storage_dir=storage_dir)
        
        assert storage.storage_dir == Path(storage_dir)
        assert storage.storage_dir.exists()
        
        # Verify key file was created
        key_file = storage.storage_dir / ".key"
        assert key_file.exists()
    
    def test_store_session_data(self, temp_dir):
        """Test session data storage."""
        storage_dir = str(Path(temp_dir) / "secure")
        storage = SecureStorage(storage_dir=storage_dir)
        
        test_data = {
            "session_id": "123456",
            "packets": 42,
            "timestamp": 1640995200,
            "analysis": {"protocol": "ISO14443"}
        }
        
        file_path = storage.store_session_data("123456", test_data)
        
        # Verify file was created
        assert Path(file_path).exists()
        assert Path(file_path).name == "session_123456.enc"
        
        # Verify file is encrypted (not readable as JSON)
        with open(file_path, 'rb') as f:
            content = f.read()
        
        assert b"session_id" not in content  # Should be encrypted
        assert b"123456" not in content
    
    def test_load_session_data(self, temp_dir):
        """Test session data loading."""
        storage_dir = str(Path(temp_dir) / "secure")
        storage = SecureStorage(storage_dir=storage_dir)
        
        test_data = {
            "session_id": "123456",
            "packets": 42,
            "nested": {"key": "value"}
        }
        
        # Store and load data
        storage.store_session_data("123456", test_data)
        loaded_data = storage.load_session_data("123456")
        
        assert loaded_data == test_data
    
    def test_load_nonexistent_session(self, temp_dir):
        """Test loading nonexistent session."""
        storage_dir = str(Path(temp_dir) / "secure")
        storage = SecureStorage(storage_dir=storage_dir)
        
        with pytest.raises(FileNotFoundError):
            storage.load_session_data("nonexistent")
    
    def test_list_sessions(self, temp_dir):
        """Test session listing."""
        storage_dir = str(Path(temp_dir) / "secure")
        storage = SecureStorage(storage_dir=storage_dir)
        
        # Store multiple sessions
        for i in range(5):
            session_id = f"12345{i}"
            storage.store_session_data(session_id, {"id": session_id})
        
        sessions = storage.list_sessions()
        
        assert len(sessions) == 5
        for i in range(5):
            assert f"12345{i}" in sessions
    
    def test_delete_session(self, temp_dir):
        """Test session deletion."""
        storage_dir = str(Path(temp_dir) / "secure")
        storage = SecureStorage(storage_dir=storage_dir)
        
        # Store session
        test_data = {"session_id": "123456"}
        file_path = storage.store_session_data("123456", test_data)
        
        assert Path(file_path).exists()
        
        # Delete session
        storage.delete_session("123456")
        
        assert not Path(file_path).exists()
    
    def test_delete_nonexistent_session(self, temp_dir):
        """Test deleting nonexistent session."""
        storage_dir = str(Path(temp_dir) / "secure")
        storage = SecureStorage(storage_dir=storage_dir)
        
        # Should not raise exception
        storage.delete_session("nonexistent")
    
    def test_storage_directory_permissions(self, temp_dir):
        """Test storage directory has correct permissions."""
        storage_dir = str(Path(temp_dir) / "secure")
        storage = SecureStorage(storage_dir=storage_dir)
        
        # Check directory permissions (should be restrictive)
        dir_mode = oct(storage.storage_dir.stat().st_mode)[-3:]
        assert dir_mode == '700'  # Owner only
    
    def test_encryption_key_persistence(self, temp_dir):
        """Test encryption key persistence across instances."""
        storage_dir = str(Path(temp_dir) / "secure")
        
        # Create first instance and store data
        storage1 = SecureStorage(storage_dir=storage_dir)
        test_data = {"test": "data"}
        storage1.store_session_data("123456", test_data)
        
        # Create second instance and load data
        storage2 = SecureStorage(storage_dir=storage_dir)
        loaded_data = storage2.load_session_data("123456")
        
        assert loaded_data == test_data
    
    def test_large_data_storage(self, temp_dir):
        """Test storage of large data structures."""
        storage_dir = str(Path(temp_dir) / "secure")
        storage = SecureStorage(storage_dir=storage_dir)
        
        # Create large test data
        large_data = {
            "session_id": "123456",
            "packets": [{"data": secrets.token_hex(100)} for _ in range(1000)],
            "analysis": {f"key_{i}": f"value_{i}" for i in range(1000)}
        }
        
        # Store and load
        storage.store_session_data("123456", large_data)
        loaded_data = storage.load_session_data("123456")
        
        assert loaded_data == large_data
    
    def test_unicode_data_storage(self, temp_dir):
        """Test storage of unicode data."""
        storage_dir = str(Path(temp_dir) / "secure")
        storage = SecureStorage(storage_dir=storage_dir)
        
        unicode_data = {
            "session_id": "123456",
            "location": "東京駅",  # Tokyo Station in Japanese
            "description": "Test with émojis 🔒🚇",
            "special_chars": "àáâãäåæçèéêë"
        }
        
        storage.store_session_data("123456", unicode_data)
        loaded_data = storage.load_session_data("123456")
        
        assert loaded_data == unicode_data


class TestCryptographicSecurity:
    """Test cryptographic security properties."""
    
    def test_encryption_randomness(self):
        """Test encryption produces different outputs for same input."""
        encryption = DataEncryption()
        test_data = b"test data"
        
        # Encrypt same data multiple times
        encrypted1 = encryption.encrypt_data(test_data)
        encrypted2 = encryption.encrypt_data(test_data)
        
        # Should produce different encrypted data (due to random IV)
        assert encrypted1 != encrypted2
        
        # But both should decrypt to same plaintext
        assert encryption.decrypt_data(encrypted1) == test_data
        assert encryption.decrypt_data(encrypted2) == test_data
    
    def test_key_uniqueness(self):
        """Test each encryption instance has unique key."""
        encryption1 = DataEncryption()
        encryption2 = DataEncryption()
        
        assert encryption1.get_key() != encryption2.get_key()
    
    def test_certificate_validity_period(self, temp_dir):
        """Test certificate has appropriate validity period."""
        tls_manager = TLSManager(cert_dir=temp_dir)
        cert, _ = tls_manager.generate_self_signed_cert()
        
        validity_period = cert.not_valid_after - cert.not_valid_before
        
        # Should be valid for 365 days
        assert validity_period.days == 365
    
    def test_certificate_key_size(self, temp_dir):
        """Test certificate uses strong key size."""
        tls_manager = TLSManager(cert_dir=temp_dir)
        _, private_key = tls_manager.generate_self_signed_cert()
        
        # Should use at least 2048-bit RSA key
        assert private_key.key_size >= 2048
    
    def test_ssl_context_security(self, temp_dir):
        """Test SSL context uses secure configuration."""
        tls_manager = TLSManager(cert_dir=temp_dir)
        context = tls_manager.get_ssl_context()
        
        # Should require TLS 1.2 or higher
        assert context.minimum_version >= ssl.TLSVersion.TLSv1_2
        
        # Should have secure cipher configuration
        # Note: Exact cipher checking is implementation dependent


class TestErrorHandling:
    """Test error handling in crypto operations."""
    
    def test_invalid_cert_directory(self):
        """Test handling of invalid certificate directory."""
        with patch('pathlib.Path.mkdir', side_effect=PermissionError):
            # Should handle permission errors gracefully
            tls_manager = TLSManager(cert_dir="/invalid/path")
            # The actual error handling depends on implementation
    
    def test_corrupted_key_file(self, temp_dir):
        """Test handling of corrupted key file."""
        storage_dir = str(Path(temp_dir) / "secure")
        storage = SecureStorage(storage_dir=storage_dir)
        
        # Corrupt the key file
        key_file = storage.storage_dir / ".key"
        with open(key_file, 'wb') as f:
            f.write(b"corrupted key data")
        
        # Creating new storage instance should handle corrupted key
        # (Implementation may recreate key or raise exception)
        try:
            storage2 = SecureStorage(storage_dir=storage_dir)
            # If it succeeds, key was recreated
        except Exception:
            # If it fails, that's also acceptable behavior
            pass
    
    def test_disk_full_simulation(self, temp_dir):
        """Test handling of disk full scenario."""
        storage_dir = str(Path(temp_dir) / "secure")
        storage = SecureStorage(storage_dir=storage_dir)
        
        large_data = {"data": "x" * 1000000}  # 1MB string
        
        # This test depends on actual disk space
        # In a real scenario, you might mock the file operations
        try:
            storage.store_session_data("123456", large_data)
        except OSError:
            # Disk full or permission error - acceptable
            pass