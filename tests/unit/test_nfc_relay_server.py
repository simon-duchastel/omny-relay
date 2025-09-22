"""
Unit tests for NFCRelayServer core functionality.
Tests WebSocket handling, session management, and message processing.
"""

import pytest
import asyncio
import json
from unittest.mock import Mock, AsyncMock, patch, MagicMock
import websockets
from websockets.exceptions import ConnectionClosed

from server.nfc_relay_server import NFCRelayServer, Session
from src.protocol.messages_pb2 import Wrapper, SessionMessage, DataMessage, StatusMessage, WrapperType
from tests.fixtures.nfc_packets import REQA, AUTH_A, OYSTER_BALANCE


class TestSession:
    """Test Session class functionality."""
    
    def test_session_creation(self):
        """Test session initialization."""
        session = Session("123456")
        
        assert session.session_id == "123456"
        assert session.clients == {}
        assert session.packet_count == 0
        assert session.data_log == []
        assert isinstance(session.created_at, float)
    
    def test_add_client(self, mock_websocket):
        """Test adding clients to session."""
        session = Session("123456")
        
        session.add_client("READER", mock_websocket)
        assert "READER" in session.clients
        assert session.clients["READER"] == mock_websocket
    
    def test_remove_client(self, mock_websocket):
        """Test removing clients from session."""
        session = Session("123456")
        session.add_client("READER", mock_websocket)
        
        session.remove_client("READER")
        assert "READER" not in session.clients
    
    def test_log_data(self):
        """Test NFC data logging."""
        session = Session("123456")
        
        session.log_data(REQA, "reader_to_card")
        
        assert session.packet_count == 1
        assert len(session.data_log) == 1
        
        log_entry = session.data_log[0]
        assert log_entry['data'] == REQA
        assert log_entry['direction'] == "reader_to_card"
        assert log_entry['packet_id'] == 1
        assert log_entry['size'] == len(REQA)
        assert isinstance(log_entry['timestamp'], float)
    
    def test_is_complete(self, mock_websocket):
        """Test session completion check."""
        session = Session("123456")
        
        assert not session.is_complete()
        
        session.add_client("READER", mock_websocket)
        assert not session.is_complete()
        
        session.add_client("CARD", mock_websocket)
        assert session.is_complete()
    
    def test_get_peer(self, mock_websocket):
        """Test peer client retrieval."""
        session = Session("123456")
        reader_ws = AsyncMock()
        card_ws = AsyncMock()
        
        session.add_client("READER", reader_ws)
        session.add_client("CARD", card_ws)
        
        assert session.get_peer("READER") == card_ws
        assert session.get_peer("CARD") == reader_ws
        assert session.get_peer("UNKNOWN") is None


class TestNFCRelayServer:
    """Test NFCRelayServer functionality."""
    
    def test_server_initialization(self, test_config):
        """Test server initialization."""
        server = NFCRelayServer(
            host=test_config.server.host,
            port=test_config.server.port,
            use_tls=test_config.security.enable_tls
        )
        
        assert server.host == test_config.server.host
        assert server.port == test_config.server.port
        assert server.use_tls == test_config.security.enable_tls
        assert server.sessions == {}
        assert server.client_sessions == {}
    
    def test_generate_session_id(self, test_config):
        """Test session ID generation."""
        server = NFCRelayServer(use_tls=False)
        
        session_id = server.generate_session_id()
        
        assert len(session_id) == 6
        assert session_id.isdigit()
        assert 100000 <= int(session_id) <= 999999
    
    @pytest.mark.asyncio
    async def test_handle_session_create(self, test_config, mock_websocket, sample_protocol_messages):
        """Test session creation handling."""
        server = NFCRelayServer(use_tls=False)
        session_msg = sample_protocol_messages['session_create'].session
        
        with patch.object(server, 'generate_session_id', return_value="123456"):
            await server.handle_session_message(mock_websocket, session_msg)
        
        assert "123456" in server.sessions
        assert mock_websocket in server.client_sessions
        assert server.client_sessions[mock_websocket] == "123456"
        
        session = server.sessions["123456"]
        assert "READER" in session.clients
        assert session.clients["READER"] == mock_websocket
        
        # Verify response was sent
        mock_websocket.send.assert_called_once()
        sent_data = mock_websocket.send.call_args[0][0]
        
        response = Wrapper()
        response.ParseFromString(sent_data)
        assert response.type == WrapperType.SESSION
        assert response.session.session_id == "123456"
    
    @pytest.mark.asyncio
    async def test_handle_session_join(self, test_config, sample_protocol_messages):
        """Test joining existing session."""
        server = NFCRelayServer(use_tls=False)
        
        # Create session first
        session = Session("123456")
        server.sessions["123456"] = session
        
        # Create join message
        join_msg = SessionMessage()
        join_msg.opcode = SessionMessage.SESSION_JOIN
        join_msg.session_id = "123456"
        join_msg.client_type = SessionMessage.CARD
        
        mock_websocket = AsyncMock()
        
        await server.handle_session_message(mock_websocket, join_msg)
        
        assert mock_websocket in server.client_sessions
        assert "CARD" in session.clients
        assert session.clients["CARD"] == mock_websocket
    
    @pytest.mark.asyncio
    async def test_handle_data_message(self, test_config, sample_protocol_messages):
        """Test NFC data message handling."""
        server = NFCRelayServer(use_tls=False)
        
        # Setup session with two clients
        session = Session("123456")
        reader_ws = AsyncMock()
        card_ws = AsyncMock()
        
        session.add_client("READER", reader_ws)
        session.add_client("CARD", card_ws)
        server.sessions["123456"] = session
        server.client_sessions[reader_ws] = "123456"
        
        data_msg = sample_protocol_messages['data'].data
        
        with patch.object(server.packet_analyzer, 'analyze_nfc_packet', new_callable=AsyncMock) as mock_analyze:
            mock_analyze.return_value = {'protocol': 'ISO14443', 'command': 'REQA'}
            await server.handle_data_message(reader_ws, data_msg)
        
        # Verify data was logged
        assert session.packet_count == 1
        assert len(session.data_log) == 1
        
        # Verify data was forwarded to peer
        card_ws.send.assert_called_once()
        
        # Verify analysis was called
        mock_analyze.assert_called_once_with(
            data_msg.nfc_data, "READER", "123456"
        )
    
    @pytest.mark.asyncio
    async def test_handle_data_message_no_peer(self, test_config, sample_protocol_messages):
        """Test data message with no peer available."""
        server = NFCRelayServer(use_tls=False)
        
        # Setup session with only one client
        session = Session("123456")
        reader_ws = AsyncMock()
        
        session.add_client("READER", reader_ws)
        server.sessions["123456"] = session
        server.client_sessions[reader_ws] = "123456"
        
        data_msg = sample_protocol_messages['data'].data
        
        with patch.object(server, 'send_error', new_callable=AsyncMock) as mock_error:
            await server.handle_data_message(reader_ws, data_msg)
        
        # Verify error was sent
        mock_error.assert_called_once_with(reader_ws, "No peer available for relay")
    
    @pytest.mark.asyncio
    async def test_handle_status_message(self, test_config, sample_protocol_messages):
        """Test status message handling."""
        server = NFCRelayServer(use_tls=False)
        
        # Setup session
        session = Session("123456")
        reader_ws = AsyncMock()
        session.add_client("READER", reader_ws)
        server.sessions["123456"] = session
        server.client_sessions[reader_ws] = "123456"
        
        status_msg = sample_protocol_messages['status'].status
        
        # Should not raise exception
        await server.handle_status_message(reader_ws, status_msg)
    
    @pytest.mark.asyncio
    async def test_notify_session_ready(self, test_config):
        """Test session ready notification."""
        server = NFCRelayServer(use_tls=False)
        
        session = Session("123456")
        reader_ws = AsyncMock()
        card_ws = AsyncMock()
        
        session.add_client("READER", reader_ws)
        session.add_client("CARD", card_ws)
        
        await server.notify_session_ready(session)
        
        # Both clients should receive notification
        reader_ws.send.assert_called_once()
        card_ws.send.assert_called_once()
        
        # Verify message content
        sent_data = reader_ws.send.call_args[0][0]
        wrapper = Wrapper()
        wrapper.ParseFromString(sent_data)
        
        assert wrapper.type == WrapperType.STATUS
        assert wrapper.status.status == StatusMessage.CONNECTED
        assert "ready" in wrapper.status.message.lower()
    
    @pytest.mark.asyncio
    async def test_send_error(self, test_config):
        """Test error message sending."""
        server = NFCRelayServer(use_tls=False)
        mock_websocket = AsyncMock()
        
        await server.send_error(mock_websocket, "Test error message")
        
        mock_websocket.send.assert_called_once()
        sent_data = mock_websocket.send.call_args[0][0]
        
        wrapper = Wrapper()
        wrapper.ParseFromString(sent_data)
        
        assert wrapper.type == WrapperType.STATUS
        assert wrapper.status.status == StatusMessage.ERROR
        assert wrapper.status.message == "Test error message"
    
    @pytest.mark.asyncio
    async def test_cleanup_client(self, test_config):
        """Test client cleanup."""
        server = NFCRelayServer(use_tls=False)
        
        # Setup session
        session = Session("123456")
        reader_ws = AsyncMock()
        card_ws = AsyncMock()
        
        session.add_client("READER", reader_ws)
        session.add_client("CARD", card_ws)
        server.sessions["123456"] = session
        server.client_sessions[reader_ws] = "123456"
        
        with patch.object(server, 'export_session_data', new_callable=AsyncMock) as mock_export:
            await server.cleanup_client(reader_ws)
        
        # Client should be removed from session
        assert "READER" not in session.clients
        assert reader_ws not in server.client_sessions
        
        # Session should still exist (other client present)
        assert "123456" in server.sessions
        
        # Export should not be called yet
        mock_export.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_cleanup_last_client(self, test_config):
        """Test cleanup of last client in session."""
        server = NFCRelayServer(use_tls=False)
        
        # Setup session with one client
        session = Session("123456")
        reader_ws = AsyncMock()
        
        session.add_client("READER", reader_ws)
        session.packet_count = 5  # Simulate some activity
        server.sessions["123456"] = session
        server.client_sessions[reader_ws] = "123456"
        
        with patch.object(server, 'export_session_data', new_callable=AsyncMock) as mock_export:
            await server.cleanup_client(reader_ws)
        
        # Session should be removed
        assert "123456" not in server.sessions
        assert reader_ws not in server.client_sessions
        
        # Export should be called
        mock_export.assert_called_once_with(session)
    
    @pytest.mark.asyncio
    async def test_handle_message_invalid_format(self, test_config):
        """Test handling of invalid message format."""
        server = NFCRelayServer(use_tls=False)
        mock_websocket = AsyncMock()
        
        invalid_message = b"invalid protobuf data"
        
        with patch.object(server, 'send_error', new_callable=AsyncMock) as mock_error:
            await server.handle_message(mock_websocket, invalid_message)
        
        mock_error.assert_called_once_with(mock_websocket, "Invalid message format")
    
    @pytest.mark.asyncio
    async def test_handle_message_unknown_type(self, test_config):
        """Test handling of unknown message type."""
        server = NFCRelayServer(use_tls=False)
        mock_websocket = AsyncMock()
        
        # Create wrapper with invalid type
        wrapper = Wrapper()
        wrapper.type = 99  # Invalid type
        
        with patch.object(server, 'handle_session_message', new_callable=AsyncMock), \
             patch.object(server, 'handle_data_message', new_callable=AsyncMock), \
             patch.object(server, 'handle_status_message', new_callable=AsyncMock):
            
            await server.handle_message(mock_websocket, wrapper.SerializeToString())
        
        # No handlers should be called for unknown type
        server.handle_session_message.assert_not_called()
        server.handle_data_message.assert_not_called()
        server.handle_status_message.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_register_client_connection_closed(self, test_config):
        """Test handling of client connection closure."""
        server = NFCRelayServer(use_tls=False)
        mock_websocket = AsyncMock()
        
        # Simulate connection closed
        mock_websocket.__aiter__.side_effect = ConnectionClosed(None, None)
        
        with patch.object(server, 'cleanup_client', new_callable=AsyncMock) as mock_cleanup:
            await server.register_client(mock_websocket, "/")
        
        mock_cleanup.assert_called_once_with(mock_websocket)
    
    def test_multiple_sessions(self, test_config):
        """Test handling multiple concurrent sessions."""
        server = NFCRelayServer(use_tls=False)
        
        # Create multiple sessions
        for i in range(5):
            session_id = f"12345{i}"
            session = Session(session_id)
            server.sessions[session_id] = session
        
        assert len(server.sessions) == 5
        
        # Verify each session is independent
        for i in range(5):
            session_id = f"12345{i}"
            assert session_id in server.sessions
            assert server.sessions[session_id].session_id == session_id
    
    @pytest.mark.asyncio
    async def test_concurrent_message_handling(self, test_config, sample_protocol_messages):
        """Test concurrent message handling."""
        server = NFCRelayServer(use_tls=False)
        
        # Create multiple mock websockets
        websockets = [AsyncMock() for _ in range(10)]
        
        # Handle multiple session creation messages concurrently
        tasks = []
        for i, ws in enumerate(websockets):
            session_msg = sample_protocol_messages['session_create'].session
            task = server.handle_session_message(ws, session_msg)
            tasks.append(task)
        
        # Wait for all tasks to complete
        await asyncio.gather(*tasks)
        
        # Verify all sessions were created
        assert len(server.sessions) == 10
        assert len(server.client_sessions) == 10


class TestServerConfiguration:
    """Test server configuration handling."""
    
    def test_tls_configuration(self, test_config):
        """Test TLS configuration."""
        # Test TLS enabled
        server = NFCRelayServer(use_tls=True)
        assert server.use_tls is True
        assert hasattr(server, 'tls_manager')
        
        # Test TLS disabled
        server = NFCRelayServer(use_tls=False)
        assert server.use_tls is False
    
    def test_custom_host_port(self):
        """Test custom host and port configuration."""
        server = NFCRelayServer(host="192.168.1.100", port=9999, use_tls=False)
        
        assert server.host == "192.168.1.100"
        assert server.port == 9999


class TestErrorHandling:
    """Test error handling scenarios."""
    
    @pytest.mark.asyncio
    async def test_websocket_send_failure(self, test_config):
        """Test handling of WebSocket send failures."""
        server = NFCRelayServer(use_tls=False)
        mock_websocket = AsyncMock()
        
        # Simulate send failure
        mock_websocket.send.side_effect = ConnectionClosed(None, None)
        
        # Should not raise exception
        await server.send_error(mock_websocket, "Test error")
    
    @pytest.mark.asyncio
    async def test_session_not_found(self, test_config, sample_protocol_messages):
        """Test handling of invalid session ID."""
        server = NFCRelayServer(use_tls=False)
        mock_websocket = AsyncMock()
        
        # Try to join non-existent session
        join_msg = SessionMessage()
        join_msg.opcode = SessionMessage.SESSION_JOIN
        join_msg.session_id = "999999"
        join_msg.client_type = SessionMessage.READER
        
        with patch.object(server, 'send_error', new_callable=AsyncMock) as mock_error:
            await server.handle_session_message(mock_websocket, join_msg)
        
        mock_error.assert_called_once()
        error_message = mock_error.call_args[0][1]
        assert "not found" in error_message.lower()
    
    @pytest.mark.asyncio
    async def test_data_message_no_session(self, test_config, sample_protocol_messages):
        """Test data message from client with no session."""
        server = NFCRelayServer(use_tls=False)
        mock_websocket = AsyncMock()
        
        data_msg = sample_protocol_messages['data'].data
        
        with patch.object(server, 'send_error', new_callable=AsyncMock) as mock_error:
            await server.handle_data_message(mock_websocket, data_msg)
        
        mock_error.assert_called_once_with(mock_websocket, "No active session")