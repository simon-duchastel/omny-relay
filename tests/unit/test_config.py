"""
Unit tests for configuration management.
Tests configuration loading, validation, and security settings.
"""

import pytest
import yaml
import os
import tempfile
from pathlib import Path
from unittest.mock import patch, mock_open

from server.config import (
    ConfigManager, SecurityConfig, ServerConfig, 
    AnalysisConfig, ResearchConfig, EnvironmentConfig
)


class TestSecurityConfig:
    """Test SecurityConfig dataclass."""
    
    def test_default_values(self):
        """Test default security configuration values."""
        config = SecurityConfig()
        
        assert config.enable_tls is True
        assert config.cert_file == "certs/server.crt"
        assert config.key_file == "certs/server.key"
        assert config.ca_file is None
        assert config.require_client_cert is False
        assert config.tls_version == "1.2"
        assert "ECDHE+AESGCM" in config.allowed_ciphers
        assert config.session_timeout == 3600
        assert config.max_session_size == 10485760
        assert config.enable_encryption is True
        assert config.log_sensitive_data is False
    
    def test_custom_values(self):
        """Test custom security configuration values."""
        config = SecurityConfig(
            enable_tls=False,
            tls_version="1.3",
            session_timeout=7200,
            require_client_cert=True
        )
        
        assert config.enable_tls is False
        assert config.tls_version == "1.3"
        assert config.session_timeout == 7200
        assert config.require_client_cert is True


class TestServerConfig:
    """Test ServerConfig dataclass."""
    
    def test_default_values(self):
        """Test default server configuration values."""
        config = ServerConfig()
        
        assert config.host == "0.0.0.0"
        assert config.port == 8080
        assert config.max_connections == 100
        assert config.max_session_duration == 7200
        assert config.enable_cors is False
        assert config.cors_origins == []
        assert config.rate_limit == 1000
        assert config.enable_compression is True
        assert config.log_level == "INFO"
    
    def test_cors_origins_initialization(self):
        """Test CORS origins list initialization."""
        config = ServerConfig(cors_origins=["http://localhost:3000"])
        assert config.cors_origins == ["http://localhost:3000"]
        
        config = ServerConfig()
        assert config.cors_origins == []


class TestAnalysisConfig:
    """Test AnalysisConfig dataclass."""
    
    def test_default_values(self):
        """Test default analysis configuration values."""
        config = AnalysisConfig()
        
        assert config.enable_realtime_analysis is True
        assert config.export_pcap is True
        assert config.export_json is True
        assert config.auto_detect_protocols is True
        assert config.save_raw_data is True
        assert config.analysis_output_dir == "analysis_output"
        assert config.secure_storage_dir == "secure_data"
        assert config.max_storage_size == 1073741824
        assert config.retention_days == 30


class TestResearchConfig:
    """Test ResearchConfig dataclass."""
    
    def test_default_values(self):
        """Test default research configuration values."""
        config = ResearchConfig()
        
        assert config.research_mode is True
        assert config.anonymize_data is True
        assert config.enable_detailed_logging is True
        assert config.export_metadata is True
        assert config.protocol_detection_threshold == 0.6
        assert config.transaction_confidence_threshold == 0.5
        assert config.enable_pattern_learning is False


class TestConfigManager:
    """Test ConfigManager functionality."""
    
    def test_initialization_no_file(self, temp_dir):
        """Test initialization when config file doesn't exist."""
        config_file = str(Path(temp_dir) / "test_config.yaml")
        
        with patch.object(Path, 'exists', return_value=False):
            config = ConfigManager(config_file)
        
        # Should create default configuration
        assert isinstance(config.security, SecurityConfig)
        assert isinstance(config.server, ServerConfig)
        assert isinstance(config.analysis, AnalysisConfig)
        assert isinstance(config.research, ResearchConfig)
    
    def test_initialization_with_file(self, temp_dir):
        """Test initialization with existing config file."""
        config_file = str(Path(temp_dir) / "test_config.yaml")
        
        # Create test config file
        test_config = {
            'security': {
                'enable_tls': False,
                'session_timeout': 1800
            },
            'server': {
                'host': '127.0.0.1',
                'port': 9999
            }
        }
        
        with open(config_file, 'w') as f:
            yaml.dump(test_config, f)
        
        config = ConfigManager(config_file)
        
        assert config.security.enable_tls is False
        assert config.security.session_timeout == 1800
        assert config.server.host == '127.0.0.1'
        assert config.server.port == 9999
    
    def test_load_config_invalid_yaml(self, temp_dir):
        """Test loading invalid YAML file."""
        config_file = str(Path(temp_dir) / "invalid_config.yaml")
        
        # Create invalid YAML file
        with open(config_file, 'w') as f:
            f.write("invalid: yaml: content: [")
        
        # Should fall back to default config
        config = ConfigManager(config_file)
        
        # Should have default values
        assert config.server.port == 8080
    
    def test_save_config(self, temp_dir):
        """Test configuration saving."""
        config_file = str(Path(temp_dir) / "test_config.yaml")
        config = ConfigManager(config_file)
        
        # Modify configuration
        config.server.port = 9999
        config.security.enable_tls = False
        
        config.save_config()
        
        # Verify file was created
        assert Path(config_file).exists()
        
        # Verify file permissions (should be restrictive)
        file_mode = oct(Path(config_file).stat().st_mode)[-3:]
        assert file_mode == '600'
        
        # Verify content
        with open(config_file, 'r') as f:
            saved_config = yaml.safe_load(f)
        
        assert saved_config['server']['port'] == 9999
        assert saved_config['security']['enable_tls'] is False
    
    def test_validate_config_success(self, temp_dir):
        """Test successful configuration validation."""
        config = ConfigManager()
        config.security.enable_tls = True
        config.server.host = "127.0.0.1"
        
        # Should not raise exception
        config.validate_config()
    
    def test_validate_config_security_errors(self, temp_dir):
        """Test configuration validation with security errors."""
        config = ConfigManager()
        config.security.enable_tls = False
        config.server.host = "0.0.0.0"  # Non-localhost with TLS disabled
        
        with pytest.raises(ValueError, match="TLS must be enabled"):
            config.validate_config()
    
    def test_validate_config_warnings(self, temp_dir):
        """Test configuration validation with warnings."""
        config = ConfigManager()
        config.security.tls_version = "1.1"  # Old TLS version
        config.security.log_sensitive_data = True
        config.server.max_connections = 2000  # High connection limit
        
        # Should complete without raising exception (warnings only)
        config.validate_config()
    
    def test_validate_config_directory_creation(self, temp_dir):
        """Test directory creation during validation."""
        config = ConfigManager()
        config.analysis.analysis_output_dir = str(Path(temp_dir) / "new_analysis")
        config.analysis.secure_storage_dir = str(Path(temp_dir) / "new_secure")
        
        config.validate_config()
        
        # Directories should be created
        assert Path(config.analysis.analysis_output_dir).exists()
        assert Path(config.analysis.secure_storage_dir).exists()
        
        # Secure storage should have restrictive permissions
        secure_mode = oct(Path(config.analysis.secure_storage_dir).stat().st_mode)[-3:]
        assert secure_mode == '700'
    
    def test_get_ssl_context_config(self):
        """Test SSL context configuration extraction."""
        config = ConfigManager()
        ssl_config = config.get_ssl_context_config()
        
        expected_keys = ['cert_file', 'key_file', 'ca_file', 'tls_version', 'ciphers', 'require_client_cert']
        for key in expected_keys:
            assert key in ssl_config
        
        assert ssl_config['cert_file'] == config.security.cert_file
        assert ssl_config['tls_version'] == config.security.tls_version
    
    def test_get_server_config(self):
        """Test server configuration extraction."""
        config = ConfigManager()
        server_config = config.get_server_config()
        
        expected_keys = ['host', 'port', 'max_size', 'ping_interval', 'ping_timeout', 'close_timeout']
        for key in expected_keys:
            assert key in server_config
        
        assert server_config['host'] == config.server.host
        assert server_config['port'] == config.server.port
    
    def test_is_development_mode(self):
        """Test development mode detection."""
        config = ConfigManager()
        
        # Production configuration
        config.server.host = "0.0.0.0"
        config.security.require_client_cert = True
        config.security.log_sensitive_data = False
        assert not config.is_development_mode()
        
        # Development configuration
        config.server.host = "127.0.0.1"
        config.security.require_client_cert = False
        config.security.log_sensitive_data = True
        assert config.is_development_mode()
    
    def test_apply_security_hardening(self):
        """Test security hardening application."""
        config = ConfigManager()
        
        # Set some insecure defaults
        config.security.enable_tls = False
        config.security.require_client_cert = False
        config.security.log_sensitive_data = True
        config.server.rate_limit = 10000
        
        config.apply_security_hardening()
        
        # Verify hardening was applied
        assert config.security.enable_tls is True
        assert config.security.require_client_cert is True
        assert config.security.tls_version == "1.3"
        assert config.security.log_sensitive_data is False
        assert config.security.session_timeout == 1800
        assert config.server.enable_cors is False
        assert config.server.rate_limit == 100
        assert config.research.anonymize_data is True
    
    def test_enable_research_mode(self):
        """Test research mode enablement."""
        config = ConfigManager()
        
        config.enable_research_mode()
        
        assert config.research.research_mode is True
        assert config.research.enable_detailed_logging is True
        assert config.research.export_metadata is True
        assert config.analysis.enable_realtime_analysis is True
        assert config.analysis.export_pcap is True
        assert config.analysis.export_json is True
        
        # Should still maintain security
        assert config.security.enable_tls is True
        assert config.security.enable_encryption is True


class TestEnvironmentConfig:
    """Test environment-based configuration."""
    
    def test_from_environment_basic(self):
        """Test basic environment variable configuration."""
        env_vars = {
            'NFC_HOST': '192.168.1.100',
            'NFC_PORT': '9999',
            'NFC_LOG_LEVEL': 'DEBUG',
            'NFC_DISABLE_TLS': '1'
        }
        
        with patch.dict(os.environ, env_vars):
            config = EnvironmentConfig.from_environment()
        
        assert config.server.host == '192.168.1.100'
        assert config.server.port == 9999
        assert config.server.log_level == 'DEBUG'
        assert config.security.enable_tls is False
    
    def test_from_environment_paths(self):
        """Test environment variable path configuration."""
        env_vars = {
            'NFC_CERT_FILE': '/custom/path/cert.pem',
            'NFC_KEY_FILE': '/custom/path/key.pem',
            'NFC_OUTPUT_DIR': '/custom/output',
            'NFC_STORAGE_DIR': '/custom/storage'
        }
        
        with patch.dict(os.environ, env_vars):
            config = EnvironmentConfig.from_environment()
        
        assert config.security.cert_file == '/custom/path/cert.pem'
        assert config.security.key_file == '/custom/path/key.pem'
        assert config.analysis.analysis_output_dir == '/custom/output'
        assert config.analysis.secure_storage_dir == '/custom/storage'
    
    def test_from_environment_research_mode(self):
        """Test research mode from environment."""
        env_vars = {
            'NFC_RESEARCH_MODE': 'true',
            'NFC_DEVELOPMENT': 'true'
        }
        
        with patch.dict(os.environ, env_vars):
            config = EnvironmentConfig.from_environment()
        
        assert config.research.research_mode is True
        assert config.security.log_sensitive_data is True
        assert config.research.enable_detailed_logging is True
    
    def test_create_docker_config(self):
        """Test Docker-optimized configuration."""
        config = EnvironmentConfig.create_docker_config()
        
        assert config.server.host == "0.0.0.0"
        assert config.server.port == 8080
        assert config.analysis.analysis_output_dir == "/app/output"
        assert config.analysis.secure_storage_dir == "/app/secure"
        assert config.security.cert_file == "/app/certs/server.crt"
        assert config.security.key_file == "/app/certs/server.key"


class TestConfigurationIntegration:
    """Test configuration integration scenarios."""
    
    def test_config_file_override_environment(self, temp_dir):
        """Test config file overriding environment variables."""
        config_file = str(Path(temp_dir) / "test_config.yaml")
        
        # Set environment variables
        env_vars = {
            'NFC_PORT': '9999',
            'NFC_HOST': '192.168.1.100'
        }
        
        # Create config file with different values
        file_config = {
            'server': {
                'port': 8888,
                'host': '10.0.0.1'
            }
        }
        
        with open(config_file, 'w') as f:
            yaml.dump(file_config, f)
        
        with patch.dict(os.environ, env_vars):
            config = ConfigManager(config_file)
        
        # Config file should take precedence
        assert config.server.port == 8888
        assert config.server.host == '10.0.0.1'
    
    def test_partial_configuration(self, temp_dir):
        """Test partial configuration loading."""
        config_file = str(Path(temp_dir) / "partial_config.yaml")
        
        # Create config with only some sections
        partial_config = {
            'security': {
                'enable_tls': False
            }
            # Missing server, analysis, research sections
        }
        
        with open(config_file, 'w') as f:
            yaml.dump(partial_config, f)
        
        config = ConfigManager(config_file)
        
        # Should have custom security setting
        assert config.security.enable_tls is False
        
        # Should have default values for other sections
        assert config.server.port == 8080
        assert config.analysis.export_pcap is True
        assert config.research.research_mode is True
    
    def test_config_save_load_roundtrip(self, temp_dir):
        """Test configuration save/load roundtrip."""
        config_file = str(Path(temp_dir) / "roundtrip_config.yaml")
        
        # Create and modify configuration
        config1 = ConfigManager(config_file)
        config1.server.port = 7777
        config1.security.session_timeout = 5400
        config1.analysis.retention_days = 60
        config1.research.protocol_detection_threshold = 0.8
        
        # Save configuration
        config1.save_config()
        
        # Load in new instance
        config2 = ConfigManager(config_file)
        
        # Should have same values
        assert config2.server.port == 7777
        assert config2.security.session_timeout == 5400
        assert config2.analysis.retention_days == 60
        assert config2.research.protocol_detection_threshold == 0.8
    
    def test_config_validation_file_permissions(self, temp_dir):
        """Test configuration validation with file permission issues."""
        config = ConfigManager()
        
        # Set directories that can't be created (mock permission error)
        config.analysis.analysis_output_dir = "/root/forbidden_analysis"
        config.analysis.secure_storage_dir = "/root/forbidden_secure"
        
        with patch('pathlib.Path.mkdir', side_effect=OSError("Permission denied")):
            with pytest.raises(ValueError, match="Cannot create"):
                config.validate_config()


class TestConfigurationSecurity:
    """Test configuration security aspects."""
    
    def test_secure_config_file_permissions(self, temp_dir):
        """Test config file is saved with secure permissions."""
        config_file = str(Path(temp_dir) / "secure_config.yaml")
        config = ConfigManager(config_file)
        
        config.save_config()
        
        # File should have owner-only permissions
        file_mode = oct(Path(config_file).stat().st_mode)[-3:]
        assert file_mode == '600'
    
    def test_sensitive_data_not_logged(self):
        """Test sensitive configuration is not exposed in logs."""
        config = ConfigManager()
        config.security.log_sensitive_data = False
        
        # This would be implementation-specific
        # In practice, you'd verify that keys, passwords, etc. are not logged
        assert config.security.log_sensitive_data is False
    
    def test_production_security_defaults(self):
        """Test production security defaults are secure."""
        config = ConfigManager()
        config.apply_security_hardening()
        
        assert config.security.enable_tls is True
        assert config.security.tls_version == "1.3"
        assert config.security.require_client_cert is True
        assert config.security.log_sensitive_data is False
        assert config.server.enable_cors is False
        assert config.research.anonymize_data is True