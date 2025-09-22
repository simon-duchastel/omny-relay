"""
pytest configuration and shared fixtures for NFC relay system tests.
"""

import pytest
import asyncio
import tempfile
import shutil
from pathlib import Path
from unittest.mock import Mock, AsyncMock
import ssl
import websockets
from src.protocol.messages_pb2 import Wrapper, SessionMessage, DataMessage, StatusMessage
from src.utils.crypto import TLSManager, SecureStorage
from server.config import ConfigManager
from server.nfc_relay_server import NFCRelayServer, Session


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def temp_dir():
    """Create temporary directory for tests."""
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    shutil.rmtree(temp_dir)


@pytest.fixture
def test_config(temp_dir):
    """Create test configuration."""
    config = ConfigManager()
    config.security.enable_tls = False  # Disable TLS for testing
    config.analysis.analysis_output_dir = str(Path(temp_dir) / "analysis")
    config.analysis.secure_storage_dir = str(Path(temp_dir) / "secure")
    config.server.host = "127.0.0.1"
    config.server.port = 0  # Use random port
    return config


@pytest.fixture
def tls_manager(temp_dir):
    """Create TLS manager for testing."""
    return TLSManager(cert_dir=str(Path(temp_dir) / "certs"))


@pytest.fixture
def secure_storage(temp_dir):
    """Create secure storage for testing."""
    return SecureStorage(storage_dir=str(Path(temp_dir) / "secure"))


@pytest.fixture
def mock_websocket():
    """Create mock WebSocket connection."""
    websocket = AsyncMock()
    websocket.remote_address = ("127.0.0.1", 12345)
    return websocket


@pytest.fixture
def sample_session():
    """Create sample session for testing."""
    session = Session("123456")
    return session


@pytest.fixture
def sample_nfc_data():
    """Sample NFC packet data for testing."""
    return {
        'reqa': b'\x26\x00',
        'wupa': b'\x52\x00',
        'select_cl1': b'\x93\x20',
        'read_block': b'\x30\x04',
        'auth_a': b'\x60\x00\xFF\xFF\xFF\xFF\xFF\xFF',
        'mifare_read': b'\x30\x08',
        'balance_data': b'\x00\x01\x23\x45\x67\x89\xAB\xCD',
        'oyster_data': b'\x04\x12\x34\x56\x00\x00\x15\x50',  # £15.50 balance
        'clipper_data': b'\x04\x98\x76\x54\x00\x00\x0F\xA0',  # $15.00 balance
    }


@pytest.fixture
def sample_protocol_messages():
    """Sample protocol buffer messages for testing."""
    # Session create message
    session_create = Wrapper()
    session_create.type = Wrapper.SESSION
    session_create.session.opcode = SessionMessage.SESSION_CREATE
    session_create.session.client_type = SessionMessage.READER
    
    # Data message
    data_msg = Wrapper()
    data_msg.type = Wrapper.DATA
    data_msg.data.error_code = 0
    data_msg.data.nfc_data = b'\x26\x00'
    data_msg.data.timestamp = 1640995200000
    data_msg.data.direction = "reader_to_card"
    
    # Status message
    status_msg = Wrapper()
    status_msg.type = Wrapper.STATUS
    status_msg.status.status = StatusMessage.CONNECTED
    status_msg.status.message = "Test status"
    status_msg.status.timestamp = 1640995200000
    
    return {
        'session_create': session_create,
        'data': data_msg,
        'status': status_msg
    }


@pytest.fixture
def sample_session_data():
    """Sample session data for analysis testing."""
    return [
        {
            'timestamp': 1640995200.0,
            'data': b'\x26\x00',
            'direction': 'reader_to_card',
            'analysis': {
                'protocol': 'ISO14443',
                'command': 'REQA',
                'length': 2
            }
        },
        {
            'timestamp': 1640995200.1,
            'data': b'\x52\x00',
            'direction': 'card_to_reader',
            'analysis': {
                'protocol': 'ISO14443',
                'command': 'WUPA',
                'length': 2
            }
        },
        {
            'timestamp': 1640995200.2,
            'data': b'\x04\x12\x34\x56\x00\x00\x15\x50',
            'direction': 'card_to_reader',
            'analysis': {
                'protocol': 'MIFARE',
                'transit_info': {
                    'possible_balance_le': 15.50,
                    'possible_card_id': '04123456'
                }
            }
        }
    ]


@pytest.fixture
def sample_transit_cards():
    """Sample transit card data for testing."""
    return {
        'oyster': {
            'card_id': '04123456',
            'balance': 15.50,
            'system': 'oyster',
            'raw_data': b'\x04\x12\x34\x56\x00\x00\x15\x50\x78\x9A\xBC\xDE\xF0\x12\x34\x56'
        },
        'clipper': {
            'card_id': '04987654',
            'balance': 25.75,
            'system': 'clipper',
            'raw_data': b'\x04\x98\x76\x54\x00\x00\x25\x75\x11\x22\x33\x44\x55\x66\x77\x88'
        },
        'omny': {
            'card_id': '04567890',
            'balance': 8.25,
            'system': 'omny',
            'raw_data': b'\x04\x56\x78\x90\x00\x00\x08\x25\xAA\xBB\xCC\xDD\xEE\xFF\x00\x11'
        }
    }


@pytest.fixture
async def test_server(test_config):
    """Create test NFC relay server."""
    server = NFCRelayServer(
        host=test_config.server.host,
        port=test_config.server.port,
        use_tls=test_config.security.enable_tls
    )
    
    # Start server in background
    server_task = asyncio.create_task(server.start_server())
    
    # Wait a bit for server to start
    await asyncio.sleep(0.1)
    
    yield server
    
    # Cleanup
    server_task.cancel()
    try:
        await server_task
    except asyncio.CancelledError:
        pass


@pytest.fixture
def mock_android_client():
    """Mock Android NFCGate client for testing."""
    class MockAndroidClient:
        def __init__(self):
            self.session_id = None
            self.connected = False
            self.messages_sent = []
            self.messages_received = []
            
        async def connect(self, uri):
            self.connected = True
            
        async def send_session_create(self, client_type="READER"):
            msg = Wrapper()
            msg.type = Wrapper.SESSION
            msg.session.opcode = SessionMessage.SESSION_CREATE
            msg.session.client_type = getattr(SessionMessage, client_type)
            self.messages_sent.append(msg)
            return "123456"  # Mock session ID
            
        async def send_nfc_data(self, data, direction="reader_to_card"):
            msg = Wrapper()
            msg.type = Wrapper.DATA
            msg.data.error_code = 0
            msg.data.nfc_data = data
            msg.data.direction = direction
            self.messages_sent.append(msg)
            
        async def disconnect(self):
            self.connected = False
    
    return MockAndroidClient()


@pytest.fixture
def security_test_vectors():
    """Security test vectors for vulnerability testing."""
    return {
        'injection_attempts': [
            b'\x00' * 1000,  # Null byte injection
            b'\xFF' * 1000,  # Overflow attempt
            b'<script>alert("xss")</script>',  # XSS attempt
            b'../../etc/passwd',  # Path traversal
            b'\x41' * 10000,  # Buffer overflow
        ],
        'protocol_fuzzing': [
            b'',  # Empty packet
            b'\x26',  # Incomplete REQA
            b'\x26\x00\x00',  # Oversized REQA
            b'\xFF\xFF\xFF\xFF',  # Invalid command
            b'\x00\x00\x00\x00',  # Null command
        ],
        'timing_attacks': [
            ('fast', 0.001),
            ('normal', 0.1),
            ('slow', 1.0),
            ('timeout', 10.0),
        ]
    }


# Utility functions for tests
def create_test_packet(command, data=b''):
    """Create test NFC packet."""
    return command + data


def serialize_wrapper(wrapper):
    """Serialize protocol buffer wrapper."""
    return wrapper.SerializeToString()


def deserialize_wrapper(data):
    """Deserialize protocol buffer wrapper."""
    wrapper = Wrapper()
    wrapper.ParseFromString(data)
    return wrapper