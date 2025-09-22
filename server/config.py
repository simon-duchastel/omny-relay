#!/usr/bin/env python3
"""
Configuration management for the NFC relay server.
Handles security settings, TLS configuration, and operational parameters.
"""

import os
import yaml
import logging
from pathlib import Path
from typing import Dict, Optional, Any
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)


@dataclass
class SecurityConfig:
    """Security configuration settings."""
    enable_tls: bool = True
    cert_file: str = "certs/server.crt"
    key_file: str = "certs/server.key"
    ca_file: Optional[str] = None
    require_client_cert: bool = False
    tls_version: str = "1.2"
    allowed_ciphers: str = "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS"
    session_timeout: int = 3600  # seconds
    max_session_size: int = 10485760  # 10MB
    enable_encryption: bool = True
    log_sensitive_data: bool = False


@dataclass
class ServerConfig:
    """Server operational configuration."""
    host: str = "0.0.0.0"
    port: int = 8080
    max_connections: int = 100
    max_session_duration: int = 7200  # 2 hours
    enable_cors: bool = False
    cors_origins: list = None
    rate_limit: int = 1000  # requests per minute
    enable_compression: bool = True
    log_level: str = "INFO"
    
    def __post_init__(self):
        if self.cors_origins is None:
            self.cors_origins = []


@dataclass
class AnalysisConfig:
    """Analysis and processing configuration."""
    enable_realtime_analysis: bool = True
    export_pcap: bool = True
    export_json: bool = True
    auto_detect_protocols: bool = True
    save_raw_data: bool = True
    analysis_output_dir: str = "analysis_output"
    secure_storage_dir: str = "secure_data"
    max_storage_size: int = 1073741824  # 1GB
    retention_days: int = 30


@dataclass
class ResearchConfig:
    """Research-specific configuration."""
    research_mode: bool = True
    anonymize_data: bool = True
    enable_detailed_logging: bool = True
    export_metadata: bool = True
    protocol_detection_threshold: float = 0.6
    transaction_confidence_threshold: float = 0.5
    enable_pattern_learning: bool = False  # Experimental


class ConfigManager:
    """Manages application configuration with security validation."""
    
    def __init__(self, config_file: str = "config.yaml"):
        self.config_file = Path(config_file)
        self.security = SecurityConfig()
        self.server = ServerConfig()
        self.analysis = AnalysisConfig()
        self.research = ResearchConfig()
        
        # Load configuration if file exists
        if self.config_file.exists():
            self.load_config()
        else:
            self.create_default_config()
            
    def load_config(self):
        """Load configuration from YAML file."""
        try:
            with open(self.config_file, 'r') as f:
                config_data = yaml.safe_load(f)
                
            if 'security' in config_data:
                self.security = SecurityConfig(**config_data['security'])
            if 'server' in config_data:
                self.server = ServerConfig(**config_data['server'])
            if 'analysis' in config_data:
                self.analysis = AnalysisConfig(**config_data['analysis'])
            if 'research' in config_data:
                self.research = ResearchConfig(**config_data['research'])
                
            logger.info(f"Configuration loaded from {self.config_file}")
            self.validate_config()
            
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            self.create_default_config()
            
    def save_config(self):
        """Save current configuration to YAML file."""
        config_data = {
            'security': asdict(self.security),
            'server': asdict(self.server),
            'analysis': asdict(self.analysis),
            'research': asdict(self.research)
        }
        
        try:
            with open(self.config_file, 'w') as f:
                yaml.dump(config_data, f, default_flow_style=False, indent=2)
            
            # Set restrictive permissions on config file
            os.chmod(self.config_file, 0o600)
            logger.info(f"Configuration saved to {self.config_file}")
            
        except Exception as e:
            logger.error(f"Failed to save configuration: {e}")
            
    def create_default_config(self):
        """Create default configuration file."""
        logger.info("Creating default configuration")
        self.save_config()
        
    def validate_config(self):
        """Validate configuration settings for security and consistency."""
        errors = []
        warnings = []
        
        # Security validation
        if not self.security.enable_tls and self.server.host != "127.0.0.1":
            errors.append("TLS must be enabled for non-localhost connections")
            
        if self.security.tls_version not in ["1.2", "1.3"]:
            warnings.append("TLS version should be 1.2 or 1.3 for security")
            
        if self.security.log_sensitive_data:
            warnings.append("Sensitive data logging is enabled - ensure compliance")
            
        # Server validation
        if self.server.port < 1024 and os.geteuid() != 0:
            warnings.append("Privileged port requires root access")
            
        if self.server.max_connections > 1000:
            warnings.append("High connection limit may impact performance")
            
        # Analysis validation
        if not Path(self.analysis.analysis_output_dir).exists():
            try:
                Path(self.analysis.analysis_output_dir).mkdir(parents=True, exist_ok=True)
            except OSError as e:
                errors.append(f"Cannot create analysis output directory: {e}")
                
        if not Path(self.analysis.secure_storage_dir).exists():
            try:
                Path(self.analysis.secure_storage_dir).mkdir(parents=True, exist_ok=True, mode=0o700)
            except OSError as e:
                errors.append(f"Cannot create secure storage directory: {e}")
                
        # Research validation
        if self.research.research_mode and not self.security.enable_encryption:
            warnings.append("Research mode without encryption may expose sensitive data")
            
        # Report validation results
        if errors:
            logger.error("Configuration validation errors:")
            for error in errors:
                logger.error(f"  - {error}")
            raise ValueError("Configuration validation failed")
            
        if warnings:
            logger.warning("Configuration validation warnings:")
            for warning in warnings:
                logger.warning(f"  - {warning}")
                
    def get_ssl_context_config(self) -> Dict[str, Any]:
        """Get SSL context configuration for the server."""
        return {
            'cert_file': self.security.cert_file,
            'key_file': self.security.key_file,
            'ca_file': self.security.ca_file,
            'tls_version': self.security.tls_version,
            'ciphers': self.security.allowed_ciphers,
            'require_client_cert': self.security.require_client_cert
        }
        
    def get_server_config(self) -> Dict[str, Any]:
        """Get server configuration for websocket server."""
        return {
            'host': self.server.host,
            'port': self.server.port,
            'max_size': self.security.max_session_size,
            'ping_interval': 20,
            'ping_timeout': 10,
            'close_timeout': 10
        }
        
    def is_development_mode(self) -> bool:
        """Check if running in development mode."""
        return (
            self.server.host in ["127.0.0.1", "localhost"] and
            not self.security.require_client_cert and
            self.security.log_sensitive_data
        )
        
    def apply_security_hardening(self):
        """Apply security hardening settings for production."""
        self.security.enable_tls = True
        self.security.require_client_cert = True
        self.security.tls_version = "1.3"
        self.security.log_sensitive_data = False
        self.security.session_timeout = 1800  # 30 minutes
        
        self.server.enable_cors = False
        self.server.cors_origins = []
        self.server.rate_limit = 100  # More restrictive
        
        self.research.anonymize_data = True
        self.research.enable_detailed_logging = False
        
        logger.info("Security hardening applied")
        
    def enable_research_mode(self):
        """Configure for research environment."""
        self.research.research_mode = True
        self.research.enable_detailed_logging = True
        self.research.export_metadata = True
        self.analysis.enable_realtime_analysis = True
        self.analysis.export_pcap = True
        self.analysis.export_json = True
        
        # Still maintain security
        self.security.enable_tls = True
        self.security.enable_encryption = True
        
        logger.info("Research mode enabled")


class EnvironmentConfig:
    """Environment-specific configuration management."""
    
    @staticmethod
    def from_environment() -> ConfigManager:
        """Create configuration from environment variables."""
        config = ConfigManager()
        
        # Security settings from environment
        if os.getenv('NFC_DISABLE_TLS'):
            config.security.enable_tls = False
            
        if os.getenv('NFC_CERT_FILE'):
            config.security.cert_file = os.getenv('NFC_CERT_FILE')
            
        if os.getenv('NFC_KEY_FILE'):
            config.security.key_file = os.getenv('NFC_KEY_FILE')
            
        # Server settings from environment
        if os.getenv('NFC_HOST'):
            config.server.host = os.getenv('NFC_HOST')
            
        if os.getenv('NFC_PORT'):
            config.server.port = int(os.getenv('NFC_PORT'))
            
        if os.getenv('NFC_LOG_LEVEL'):
            config.server.log_level = os.getenv('NFC_LOG_LEVEL')
            
        # Analysis settings from environment
        if os.getenv('NFC_OUTPUT_DIR'):
            config.analysis.analysis_output_dir = os.getenv('NFC_OUTPUT_DIR')
            
        if os.getenv('NFC_STORAGE_DIR'):
            config.analysis.secure_storage_dir = os.getenv('NFC_STORAGE_DIR')
            
        # Research mode from environment
        if os.getenv('NFC_RESEARCH_MODE'):
            config.research.research_mode = os.getenv('NFC_RESEARCH_MODE').lower() == 'true'
            
        if os.getenv('NFC_DEVELOPMENT'):
            if os.getenv('NFC_DEVELOPMENT').lower() == 'true':
                config.security.log_sensitive_data = True
                config.research.enable_detailed_logging = True
                
        return config
        
    @staticmethod
    def create_docker_config() -> ConfigManager:
        """Create configuration optimized for Docker deployment."""
        config = ConfigManager()
        
        # Docker-friendly settings
        config.server.host = "0.0.0.0"
        config.server.port = 8080
        config.analysis.analysis_output_dir = "/app/output"
        config.analysis.secure_storage_dir = "/app/secure"
        config.security.cert_file = "/app/certs/server.crt"
        config.security.key_file = "/app/certs/server.key"
        
        return config


# CLI tool for configuration management
def main():
    """Configuration management CLI."""
    import argparse
    
    parser = argparse.ArgumentParser(description="NFC Relay Server Configuration")
    parser.add_argument("--config", default="config.yaml", help="Configuration file")
    parser.add_argument("--validate", action="store_true", help="Validate configuration")
    parser.add_argument("--harden", action="store_true", help="Apply security hardening")
    parser.add_argument("--research", action="store_true", help="Enable research mode")
    parser.add_argument("--show", action="store_true", help="Show current configuration")
    parser.add_argument("--create-default", action="store_true", help="Create default config")
    
    args = parser.parse_args()
    
    config = ConfigManager(args.config)
    
    if args.validate:
        try:
            config.validate_config()
            print("✓ Configuration is valid")
        except ValueError as e:
            print(f"✗ Configuration validation failed: {e}")
            
    elif args.harden:
        config.apply_security_hardening()
        config.save_config()
        print("✓ Security hardening applied and saved")
        
    elif args.research:
        config.enable_research_mode()
        config.save_config()
        print("✓ Research mode enabled and saved")
        
    elif args.show:
        print("Current configuration:")
        print(f"  Security TLS: {config.security.enable_tls}")
        print(f"  Server: {config.server.host}:{config.server.port}")
        print(f"  Research mode: {config.research.research_mode}")
        print(f"  Analysis dir: {config.analysis.analysis_output_dir}")
        
    elif args.create_default:
        config.create_default_config()
        print(f"✓ Default configuration created: {args.config}")
        
    else:
        print("No action specified. Use --help for options.")


if __name__ == "__main__":
    main()