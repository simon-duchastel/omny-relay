"""
Mock Android WebSocket client tests.
Tests protocol compliance and communication with relay server.
"""

import pytest
import asyncio
import json
import ssl
import time
from unittest.mock import Mock, AsyncMock, patch
import websockets

from src.protocol.messages_pb2 import (
    Wrapper, SessionMessage, DataMessage, StatusMessage, WrapperType
)
from tests.fixtures.nfc_packets import REQA, OYSTER_BALANCE, AUTH_A


class MockAndroidNFCGateClient:
    """Mock implementation of Android NFCGate client for testing."""
    
    def __init__(self):
        self.websocket = None
        self.session_id = None
        self.client_type = None
        self.connected = False
        self.messages_sent = []
        self.messages_received = []
        self.nfc_data_queue = []
        
    async def connect(self, uri, ssl_context=None):
        """Connect to relay server."""
        try:
            self.websocket = await websockets.connect(uri, ssl=ssl_context)
            self.connected = True
            return True
        except Exception as e:
            self.connected = False
            return False
    
    async def disconnect(self):
        """Disconnect from server."""
        if self.websocket:
            await self.websocket.close()
        self.connected = False
    
    async def create_session(self, client_type="READER"):
        """Create new relay session."""
        wrapper = Wrapper()
        wrapper.type = WrapperType.SESSION
        wrapper.session.opcode = SessionMessage.SESSION_CREATE
        wrapper.session.client_type = getattr(SessionMessage, client_type)
        
        await self._send_message(wrapper)
        
        # Wait for response
        response = await self._receive_message()
        if response and response.type == WrapperType.SESSION:
            self.session_id = response.session.session_id
            self.client_type = client_type
            return self.session_id
        
        return None
    
    async def join_session(self, session_id, client_type="CARD"):
        """Join existing session."""
        wrapper = Wrapper()
        wrapper.type = WrapperType.SESSION
        wrapper.session.opcode = SessionMessage.SESSION_JOIN
        wrapper.session.session_id = session_id
        wrapper.session.client_type = getattr(SessionMessage, client_type)
        
        await self._send_message(wrapper)
        
        self.session_id = session_id
        self.client_type = client_type
        
        # Wait for confirmation
        response = await self._receive_message()
        return response and response.type == WrapperType.STATUS
    
    async def send_nfc_data(self, data, direction=None):
        """Send NFC data through relay."""
        if not direction:
            direction = "reader_to_card" if self.client_type == "READER" else "card_to_reader"
        
        wrapper = Wrapper()
        wrapper.type = WrapperType.DATA
        wrapper.data.error_code = 0
        wrapper.data.nfc_data = data
        wrapper.data.timestamp = int(time.time() * 1000)
        wrapper.data.direction = direction
        
        await self._send_message(wrapper)
    
    async def receive_nfc_data(self, timeout=5.0):
        """Receive NFC data from relay."""
        try:
            response = await asyncio.wait_for(self._receive_message(), timeout=timeout)
            if response and response.type == WrapperType.DATA:
                return response.data.nfc_data
        except asyncio.TimeoutError:
            pass
        return None
    
    async def send_status(self, status_type, message=""):
        """Send status message."""
        wrapper = Wrapper()
        wrapper.type = WrapperType.STATUS
        wrapper.status.status = status_type
        wrapper.status.message = message
        wrapper.status.timestamp = int(time.time() * 1000)
        
        await self._send_message(wrapper)
    
    async def _send_message(self, wrapper):
        """Send protocol buffer message."""
        if not self.websocket:
            raise ConnectionError("Not connected")
        
        data = wrapper.SerializeToString()
        await self.websocket.send(data)
        self.messages_sent.append(wrapper)
    
    async def _receive_message(self):
        """Receive protocol buffer message."""
        if not self.websocket:
            return None
        
        try:
            data = await self.websocket.recv()
            wrapper = Wrapper()
            wrapper.ParseFromString(data)
            self.messages_received.append(wrapper)
            return wrapper
        except Exception:
            return None
    
    def simulate_nfc_card_detection(self):
        """Simulate NFC card being detected."""
        self.nfc_data_queue.extend([
            REQA,
            b'\x44\x00',  # ATQA response
        ])
    
    def simulate_oyster_card_read(self):
        """Simulate reading Oyster card data."""
        self.nfc_data_queue.extend([
            REQA,
            b'\x44\x00',  # ATQA
            b'\x93\x20',  # SELECT
            b'\x88\x04\x12\x34\x9A',  # UID
            AUTH_A,
            b'\xA0',  # AUTH success
            b'\x30\x04',  # READ block 4
            OYSTER_BALANCE,  # Balance data
        ])
    
    async def simulate_nfc_sequence(self, sequence_name):
        """Simulate predefined NFC sequence."""
        sequences = {
            'card_detection': self.simulate_nfc_card_detection,
            'oyster_read': self.simulate_oyster_card_read,
        }
        
        if sequence_name in sequences:
            sequences[sequence_name]()
            
            # Send queued data
            for data in self.nfc_data_queue:
                await self.send_nfc_data(data)
                await asyncio.sleep(0.1)  # Realistic timing
            
            self.nfc_data_queue.clear()


class TestAndroidClientBasicFunctionality:
    """Test basic Android client functionality."""
    
    @pytest.mark.asyncio
    async def test_client_initialization(self):
        """Test client initialization."""
        client = MockAndroidNFCGateClient()
        
        assert client.websocket is None
        assert client.session_id is None
        assert client.connected is False
        assert client.messages_sent == []
        assert client.messages_received == []
    
    @pytest.mark.asyncio
    async def test_connection_success(self):
        """Test successful connection to server."""
        client = MockAndroidNFCGateClient()
        
        # Mock successful WebSocket connection
        mock_websocket = AsyncMock()
        
        with patch('websockets.connect', return_value=mock_websocket):
            result = await client.connect("ws://localhost:8080")
        
        assert result is True
        assert client.connected is True
        assert client.websocket == mock_websocket
    
    @pytest.mark.asyncio
    async def test_connection_failure(self):
        """Test connection failure handling."""
        client = MockAndroidNFCGateClient()
        
        # Mock connection failure
        with patch('websockets.connect', side_effect=ConnectionRefusedError):
            result = await client.connect("ws://localhost:8080")
        
        assert result is False
        assert client.connected is False
        assert client.websocket is None
    
    @pytest.mark.asyncio
    async def test_disconnect(self):
        """Test disconnection."""
        client = MockAndroidNFCGateClient()
        
        # Setup connected state
        mock_websocket = AsyncMock()
        client.websocket = mock_websocket
        client.connected = True
        
        await client.disconnect()
        
        assert client.connected is False
        mock_websocket.close.assert_called_once()


class TestSessionManagement:
    """Test session management functionality."""
    
    @pytest.mark.asyncio
    async def test_create_session_reader(self):
        """Test creating session as reader."""
        client = MockAndroidNFCGateClient()
        
        # Mock WebSocket and responses
        mock_websocket = AsyncMock()
        client.websocket = mock_websocket
        
        # Mock session creation response
        response_wrapper = Wrapper()
        response_wrapper.type = WrapperType.SESSION
        response_wrapper.session.session_id = "123456"
        
        mock_websocket.recv.return_value = response_wrapper.SerializeToString()
        
        session_id = await client.create_session("READER")
        
        assert session_id == "123456"
        assert client.session_id == "123456"
        assert client.client_type == "READER"
        
        # Verify message was sent
        mock_websocket.send.assert_called_once()
        sent_data = mock_websocket.send.call_args[0][0]
        
        sent_wrapper = Wrapper()
        sent_wrapper.ParseFromString(sent_data)
        assert sent_wrapper.type == WrapperType.SESSION
        assert sent_wrapper.session.opcode == SessionMessage.SESSION_CREATE
        assert sent_wrapper.session.client_type == SessionMessage.READER
    
    @pytest.mark.asyncio
    async def test_create_session_card(self):
        """Test creating session as card emulator."""
        client = MockAndroidNFCGateClient()
        
        mock_websocket = AsyncMock()
        client.websocket = mock_websocket
        
        response_wrapper = Wrapper()
        response_wrapper.type = WrapperType.SESSION
        response_wrapper.session.session_id = "234567"
        
        mock_websocket.recv.return_value = response_wrapper.SerializeToString()
        
        session_id = await client.create_session("CARD")
        
        assert session_id == "234567"
        assert client.client_type == "CARD"
    
    @pytest.mark.asyncio
    async def test_join_existing_session(self):
        """Test joining existing session."""
        client = MockAndroidNFCGateClient()
        
        mock_websocket = AsyncMock()
        client.websocket = mock_websocket
        
        # Mock successful join response
        response_wrapper = Wrapper()
        response_wrapper.type = WrapperType.STATUS
        response_wrapper.status.status = StatusMessage.CONNECTED
        
        mock_websocket.recv.return_value = response_wrapper.SerializeToString()
        
        result = await client.join_session("123456", "CARD")
        
        assert result is True
        assert client.session_id == "123456"
        assert client.client_type == "CARD"
        
        # Verify join message was sent
        mock_websocket.send.assert_called_once()
        sent_data = mock_websocket.send.call_args[0][0]
        
        sent_wrapper = Wrapper()
        sent_wrapper.ParseFromString(sent_data)
        assert sent_wrapper.type == WrapperType.SESSION
        assert sent_wrapper.session.opcode == SessionMessage.SESSION_JOIN
        assert sent_wrapper.session.session_id == "123456"
    
    @pytest.mark.asyncio
    async def test_session_creation_failure(self):
        """Test session creation failure."""
        client = MockAndroidNFCGateClient()
        
        mock_websocket = AsyncMock()
        client.websocket = mock_websocket
        
        # Mock error response
        response_wrapper = Wrapper()
        response_wrapper.type = WrapperType.STATUS
        response_wrapper.status.status = StatusMessage.ERROR
        
        mock_websocket.recv.return_value = response_wrapper.SerializeToString()
        
        session_id = await client.create_session("READER")
        
        assert session_id is None
        assert client.session_id is None


class TestNFCDataRelay:
    """Test NFC data relay functionality."""
    
    @pytest.mark.asyncio
    async def test_send_nfc_data_reader(self):
        """Test sending NFC data as reader."""
        client = MockAndroidNFCGateClient()
        client.websocket = AsyncMock()
        client.client_type = "READER"
        
        await client.send_nfc_data(REQA)
        
        # Verify data was sent
        client.websocket.send.assert_called_once()
        sent_data = client.websocket.send.call_args[0][0]
        
        sent_wrapper = Wrapper()
        sent_wrapper.ParseFromString(sent_data)
        
        assert sent_wrapper.type == WrapperType.DATA
        assert sent_wrapper.data.nfc_data == REQA
        assert sent_wrapper.data.direction == "reader_to_card"
        assert sent_wrapper.data.error_code == 0
    
    @pytest.mark.asyncio
    async def test_send_nfc_data_card(self):
        """Test sending NFC data as card emulator."""
        client = MockAndroidNFCGateClient()
        client.websocket = AsyncMock()
        client.client_type = "CARD"
        
        await client.send_nfc_data(OYSTER_BALANCE)
        
        sent_data = client.websocket.send.call_args[0][0]
        sent_wrapper = Wrapper()
        sent_wrapper.ParseFromString(sent_data)
        
        assert sent_wrapper.data.nfc_data == OYSTER_BALANCE
        assert sent_wrapper.data.direction == "card_to_reader"
    
    @pytest.mark.asyncio
    async def test_receive_nfc_data(self):
        """Test receiving NFC data from relay."""
        client = MockAndroidNFCGateClient()
        client.websocket = AsyncMock()
        
        # Mock received data
        response_wrapper = Wrapper()
        response_wrapper.type = WrapperType.DATA
        response_wrapper.data.nfc_data = AUTH_A
        
        client.websocket.recv.return_value = response_wrapper.SerializeToString()
        
        received_data = await client.receive_nfc_data()
        
        assert received_data == AUTH_A
    
    @pytest.mark.asyncio
    async def test_receive_nfc_data_timeout(self):
        """Test receive timeout handling."""
        client = MockAndroidNFCGateClient()
        client.websocket = AsyncMock()
        
        # Mock timeout (no response)
        async def slow_recv():
            await asyncio.sleep(10)  # Longer than timeout
            return b''
        
        client.websocket.recv.side_effect = slow_recv
        
        received_data = await client.receive_nfc_data(timeout=0.1)
        
        assert received_data is None
    
    @pytest.mark.asyncio
    async def test_bidirectional_relay(self):
        """Test bidirectional NFC data relay."""
        reader_client = MockAndroidNFCGateClient()
        card_client = MockAndroidNFCGateClient()
        
        # Setup mock WebSockets
        reader_client.websocket = AsyncMock()
        card_client.websocket = AsyncMock()
        
        reader_client.client_type = "READER"
        card_client.client_type = "CARD"
        
        # Simulate reader sending REQA
        await reader_client.send_nfc_data(REQA)
        
        # Mock card receiving REQA
        response_wrapper = Wrapper()
        response_wrapper.type = WrapperType.DATA
        response_wrapper.data.nfc_data = REQA
        
        card_client.websocket.recv.return_value = response_wrapper.SerializeToString()
        received_reqa = await card_client.receive_nfc_data()
        
        assert received_reqa == REQA
        
        # Simulate card responding with ATQA
        atqa_response = b'\x44\x00'
        await card_client.send_nfc_data(atqa_response)
        
        # Mock reader receiving response
        response_wrapper.data.nfc_data = atqa_response
        reader_client.websocket.recv.return_value = response_wrapper.SerializeToString()
        received_atqa = await reader_client.receive_nfc_data()
        
        assert received_atqa == atqa_response


class TestNFCSequenceSimulation:
    """Test NFC sequence simulation for realistic testing."""
    
    @pytest.mark.asyncio
    async def test_card_detection_sequence(self):
        """Test card detection sequence simulation."""
        client = MockAndroidNFCGateClient()
        client.websocket = AsyncMock()
        client.client_type = "READER"
        
        await client.simulate_nfc_sequence('card_detection')
        
        # Should have sent REQA and received ATQA
        assert len(client.messages_sent) >= 2
        
        # First message should be REQA
        first_msg = client.messages_sent[0]
        assert first_msg.type == WrapperType.DATA
        assert first_msg.data.nfc_data == REQA
    
    @pytest.mark.asyncio
    async def test_oyster_read_sequence(self):
        """Test Oyster card read sequence simulation."""
        client = MockAndroidNFCGateClient()
        client.websocket = AsyncMock()
        client.client_type = "READER"
        
        await client.simulate_nfc_sequence('oyster_read')
        
        # Should have sent complete read sequence
        assert len(client.messages_sent) >= 4
        
        # Should include authentication
        auth_sent = any(msg.data.nfc_data == AUTH_A for msg in client.messages_sent 
                       if msg.type == WrapperType.DATA)
        assert auth_sent
        
        # Should include balance data
        balance_sent = any(msg.data.nfc_data == OYSTER_BALANCE for msg in client.messages_sent 
                          if msg.type == WrapperType.DATA)
        assert balance_sent
    
    def test_nfc_data_queue_management(self):
        """Test NFC data queue management."""
        client = MockAndroidNFCGateClient()
        
        # Simulate card detection
        client.simulate_nfc_card_detection()
        
        assert len(client.nfc_data_queue) > 0
        assert REQA in client.nfc_data_queue
        
        # Queue should be cleared after simulation
        # (Would be cleared after simulate_nfc_sequence)


class TestProtocolCompliance:
    """Test protocol compliance with NFCGate standard."""
    
    @pytest.mark.asyncio
    async def test_message_format_compliance(self):
        """Test message format complies with protocol."""
        client = MockAndroidNFCGateClient()
        client.websocket = AsyncMock()
        
        # Send various message types
        await client.send_nfc_data(REQA)
        await client.send_status(StatusMessage.NFC_ENABLED, "NFC enabled")
        
        # All messages should be valid protocol buffers
        for msg in client.messages_sent:
            # Should be serializable/deserializable
            data = msg.SerializeToString()
            
            reconstructed = Wrapper()
            reconstructed.ParseFromString(data)
            
            assert reconstructed.type == msg.type
    
    def test_timestamp_format(self):
        """Test timestamp format compliance."""
        client = MockAndroidNFCGateClient()
        client.websocket = AsyncMock()
        
        # Create data message
        wrapper = Wrapper()
        wrapper.type = WrapperType.DATA
        wrapper.data.nfc_data = REQA
        wrapper.data.timestamp = int(time.time() * 1000)  # Milliseconds
        
        # Timestamp should be reasonable
        assert wrapper.data.timestamp > 1640000000000  # After 2021
        assert wrapper.data.timestamp < 2000000000000  # Before 2033
    
    def test_error_code_compliance(self):
        """Test error code format compliance."""
        client = MockAndroidNFCGateClient()
        
        wrapper = Wrapper()
        wrapper.type = WrapperType.DATA
        wrapper.data.error_code = 0  # Success
        wrapper.data.nfc_data = REQA
        
        # Error code should be valid
        assert wrapper.data.error_code >= 0
        assert isinstance(wrapper.data.error_code, int)


class TestErrorHandling:
    """Test error handling in Android client."""
    
    @pytest.mark.asyncio
    async def test_connection_lost_handling(self):
        """Test handling of lost connection."""
        client = MockAndroidNFCGateClient()
        client.websocket = AsyncMock()
        client.connected = True
        
        # Simulate connection lost
        client.websocket.send.side_effect = websockets.exceptions.ConnectionClosed(None, None)
        
        try:
            await client.send_nfc_data(REQA)
        except ConnectionError:
            # Should handle connection errors appropriately
            pass
    
    @pytest.mark.asyncio
    async def test_invalid_session_handling(self):
        """Test handling of invalid session responses."""
        client = MockAndroidNFCGateClient()
        client.websocket = AsyncMock()
        
        # Mock error response for session creation
        error_wrapper = Wrapper()
        error_wrapper.type = WrapperType.STATUS
        error_wrapper.status.status = StatusMessage.ERROR
        error_wrapper.status.message = "Session creation failed"
        
        client.websocket.recv.return_value = error_wrapper.SerializeToString()
        
        session_id = await client.create_session("READER")
        
        assert session_id is None
        assert client.session_id is None
    
    @pytest.mark.asyncio
    async def test_malformed_response_handling(self):
        """Test handling of malformed server responses."""
        client = MockAndroidNFCGateClient()
        client.websocket = AsyncMock()
        
        # Mock malformed response
        client.websocket.recv.return_value = b"invalid protobuf data"
        
        response = await client._receive_message()
        
        assert response is None  # Should handle gracefully
    
    @pytest.mark.asyncio
    async def test_large_data_handling(self):
        """Test handling of large NFC data packets."""
        client = MockAndroidNFCGateClient()
        client.websocket = AsyncMock()
        client.client_type = "READER"
        
        # Send large data packet
        large_data = b'A' * 10000
        
        await client.send_nfc_data(large_data)
        
        # Should handle large data without issues
        client.websocket.send.assert_called_once()
        
        sent_data = client.websocket.send.call_args[0][0]
        sent_wrapper = Wrapper()
        sent_wrapper.ParseFromString(sent_data)
        
        assert sent_wrapper.data.nfc_data == large_data


class TestPerformance:
    """Test performance characteristics of Android client."""
    
    @pytest.mark.asyncio
    async def test_high_frequency_data_relay(self):
        """Test high-frequency data relay performance."""
        client = MockAndroidNFCGateClient()
        client.websocket = AsyncMock()
        client.client_type = "READER"
        
        start_time = time.time()
        
        # Send many packets rapidly
        for i in range(100):
            await client.send_nfc_data(REQA)
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Should handle high frequency without significant delays
        assert duration < 1.0, f"High frequency relay too slow: {duration:.3f}s"
        assert len(client.messages_sent) == 100
    
    @pytest.mark.asyncio
    async def test_concurrent_sessions(self):
        """Test multiple concurrent client sessions."""
        clients = []
        
        # Create multiple clients
        for i in range(10):
            client = MockAndroidNFCGateClient()
            client.websocket = AsyncMock()
            clients.append(client)
        
        # Each client sends data
        tasks = []
        for i, client in enumerate(clients):
            client.client_type = "READER"
            task = client.send_nfc_data(REQA)
            tasks.append(task)
        
        # Should handle concurrent operations
        await asyncio.gather(*tasks)
        
        # All clients should have sent their data
        for client in clients:
            assert len(client.messages_sent) == 1