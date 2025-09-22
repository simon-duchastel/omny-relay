#!/usr/bin/env python3
"""
NFCGate-compatible relay server for transit card research.
Implements the protocol buffer-based communication system.
"""

import asyncio
import logging
import ssl
import sys
import time
import secrets
from typing import Dict, Optional, Set
import websockets
from websockets.server import WebSocketServerProtocol

from src.protocol.messages_pb2 import (
    Wrapper, SessionMessage, DataMessage, StatusMessage,
    WrapperType
)
from src.utils.crypto import TLSManager
from src.analysis.packet_analyzer import PacketAnalyzer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class Session:
    """Represents an active NFC relay session."""
    
    def __init__(self, session_id: str):
        self.session_id = session_id
        self.clients: Dict[str, WebSocketServerProtocol] = {}
        self.created_at = time.time()
        self.packet_count = 0
        self.data_log = []
        
    def add_client(self, client_type: str, websocket: WebSocketServerProtocol):
        """Add a client to the session."""
        self.clients[client_type] = websocket
        logger.info(f"Client {client_type} joined session {self.session_id}")
        
    def remove_client(self, client_type: str):
        """Remove a client from the session."""
        if client_type in self.clients:
            del self.clients[client_type]
            logger.info(f"Client {client_type} left session {self.session_id}")
            
    def log_data(self, data: bytes, direction: str):
        """Log NFC data for analysis."""
        self.packet_count += 1
        self.data_log.append({
            'timestamp': time.time(),
            'packet_id': self.packet_count,
            'direction': direction,
            'data': data,
            'size': len(data)
        })
        
    def is_complete(self) -> bool:
        """Check if session has both reader and card clients."""
        return 'READER' in self.clients and 'CARD' in self.clients
        
    def get_peer(self, client_type: str) -> Optional[WebSocketServerProtocol]:
        """Get the peer client for relaying data."""
        if client_type == 'READER':
            return self.clients.get('CARD')
        elif client_type == 'CARD':
            return self.clients.get('READER')
        return None


class NFCRelayServer:
    """Main NFC relay server implementing NFCGate protocol."""
    
    def __init__(self, host: str = "0.0.0.0", port: int = 8080, use_tls: bool = True):
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.sessions: Dict[str, Session] = {}
        self.client_sessions: Dict[WebSocketServerProtocol, str] = {}
        self.packet_analyzer = PacketAnalyzer()
        
        if use_tls:
            self.tls_manager = TLSManager()
            
    def generate_session_id(self) -> str:
        """Generate a 6-digit session ID."""
        return f"{secrets.randbelow(900000) + 100000:06d}"
        
    async def register_client(self, websocket: WebSocketServerProtocol, path: str):
        """Handle new client connections."""
        try:
            logger.info(f"New client connected from {websocket.remote_address}")
            
            async for message in websocket:
                try:
                    await self.handle_message(websocket, message)
                except Exception as e:
                    logger.error(f"Error handling message: {e}")
                    await self.send_error(websocket, f"Message handling error: {e}")
                    
        except websockets.exceptions.ConnectionClosed:
            logger.info(f"Client {websocket.remote_address} disconnected")
        except Exception as e:
            logger.error(f"Client connection error: {e}")
        finally:
            await self.cleanup_client(websocket)
            
    async def handle_message(self, websocket: WebSocketServerProtocol, message: bytes):
        """Process incoming protocol buffer messages."""
        try:
            wrapper = Wrapper()
            wrapper.ParseFromString(message)
            
            if wrapper.type == WrapperType.SESSION:
                await self.handle_session_message(websocket, wrapper.session)
            elif wrapper.type == WrapperType.DATA:
                await self.handle_data_message(websocket, wrapper.data)
            elif wrapper.type == WrapperType.STATUS:
                await self.handle_status_message(websocket, wrapper.status)
            else:
                logger.warning(f"Unknown message type: {wrapper.type}")
                
        except Exception as e:
            logger.error(f"Failed to parse message: {e}")
            await self.send_error(websocket, "Invalid message format")
            
    async def handle_session_message(self, websocket: WebSocketServerProtocol, session_msg: SessionMessage):
        """Handle session management messages."""
        if session_msg.opcode == SessionMessage.SESSION_CREATE:
            session_id = self.generate_session_id()
            session = Session(session_id)
            self.sessions[session_id] = session
            self.client_sessions[websocket] = session_id
            
            client_type = "READER" if session_msg.client_type == SessionMessage.READER else "CARD"
            session.add_client(client_type, websocket)
            
            # Send session ID back to client
            response = Wrapper()
            response.type = WrapperType.SESSION
            response.session.opcode = SessionMessage.SESSION_CREATE
            response.session.session_id = session_id
            
            await websocket.send(response.SerializeToString())
            logger.info(f"Created session {session_id} for {client_type}")
            
        elif session_msg.opcode == SessionMessage.SESSION_JOIN:
            session_id = session_msg.session_id
            if session_id in self.sessions:
                session = self.sessions[session_id]
                self.client_sessions[websocket] = session_id
                
                client_type = "READER" if session_msg.client_type == SessionMessage.READER else "CARD"
                session.add_client(client_type, websocket)
                
                # Notify both clients that session is ready
                if session.is_complete():
                    await self.notify_session_ready(session)
                    
                logger.info(f"Client joined session {session_id} as {client_type}")
            else:
                await self.send_error(websocket, f"Session {session_id} not found")
                
    async def handle_data_message(self, websocket: WebSocketServerProtocol, data_msg: DataMessage):
        """Handle NFC data relay between clients."""
        session_id = self.client_sessions.get(websocket)
        if not session_id or session_id not in self.sessions:
            await self.send_error(websocket, "No active session")
            return
            
        session = self.sessions[session_id]
        
        # Determine client type and peer
        client_type = None
        for ctype, client in session.clients.items():
            if client == websocket:
                client_type = ctype
                break
                
        if not client_type:
            await self.send_error(websocket, "Client not found in session")
            return
            
        peer = session.get_peer(client_type)
        if not peer:
            await self.send_error(websocket, "No peer available for relay")
            return
            
        # Log data for analysis
        direction = f"{client_type.lower()}_to_peer"
        session.log_data(data_msg.nfc_data, direction)
        
        # Analyze packet in real-time
        analysis = await self.packet_analyzer.analyze_nfc_packet(
            data_msg.nfc_data, client_type, session_id
        )
        
        # Forward data to peer
        try:
            await peer.send(data_msg.SerializeToString())
            logger.debug(f"Relayed {len(data_msg.nfc_data)} bytes from {client_type} to peer")
        except Exception as e:
            logger.error(f"Failed to relay data: {e}")
            await self.send_error(websocket, "Relay failed")
            
    async def handle_status_message(self, websocket: WebSocketServerProtocol, status_msg: StatusMessage):
        """Handle status updates from clients."""
        session_id = self.client_sessions.get(websocket)
        logger.info(f"Status update from session {session_id}: {status_msg.status} - {status_msg.message}")
        
    async def notify_session_ready(self, session: Session):
        """Notify all clients in session that it's ready."""
        status_msg = StatusMessage()
        status_msg.status = StatusMessage.CONNECTED
        status_msg.message = "Session ready for NFC relay"
        status_msg.timestamp = int(time.time() * 1000)
        
        wrapper = Wrapper()
        wrapper.type = WrapperType.STATUS
        wrapper.status.CopyFrom(status_msg)
        
        message = wrapper.SerializeToString()
        
        for client in session.clients.values():
            try:
                await client.send(message)
            except Exception as e:
                logger.error(f"Failed to notify client: {e}")
                
    async def send_error(self, websocket: WebSocketServerProtocol, error_msg: str):
        """Send error message to client."""
        status_msg = StatusMessage()
        status_msg.status = StatusMessage.ERROR
        status_msg.message = error_msg
        status_msg.timestamp = int(time.time() * 1000)
        
        wrapper = Wrapper()
        wrapper.type = WrapperType.STATUS
        wrapper.status.CopyFrom(status_msg)
        
        try:
            await websocket.send(wrapper.SerializeToString())
        except Exception as e:
            logger.error(f"Failed to send error: {e}")
            
    async def cleanup_client(self, websocket: WebSocketServerProtocol):
        """Clean up client connection and associated session."""
        session_id = self.client_sessions.get(websocket)
        if session_id and session_id in self.sessions:
            session = self.sessions[session_id]
            
            # Find and remove client from session
            client_type = None
            for ctype, client in session.clients.items():
                if client == websocket:
                    client_type = ctype
                    break
                    
            if client_type:
                session.remove_client(client_type)
                
            # Remove session if empty
            if not session.clients:
                logger.info(f"Session {session_id} completed. Packets: {session.packet_count}")
                await self.export_session_data(session)
                del self.sessions[session_id]
                
        if websocket in self.client_sessions:
            del self.client_sessions[websocket]
            
    async def export_session_data(self, session: Session):
        """Export session data for analysis."""
        try:
            await self.packet_analyzer.export_session_pcap(session)
            logger.info(f"Exported session {session.session_id} data")
        except Exception as e:
            logger.error(f"Failed to export session data: {e}")
            
    async def start_server(self):
        """Start the relay server."""
        logger.info(f"Starting NFC relay server on {self.host}:{self.port}")
        
        ssl_context = None
        if self.use_tls:
            ssl_context = self.tls_manager.get_ssl_context()
            logger.info("TLS enabled")
            
        async with websockets.serve(
            self.register_client,
            self.host,
            self.port,
            ssl=ssl_context
        ):
            logger.info("NFC relay server started successfully")
            await asyncio.Future()  # Run forever


async def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description="NFC Relay Server for Transit Card Research")
    parser.add_argument("--host", default="0.0.0.0", help="Server host address")
    parser.add_argument("--port", type=int, default=8080, help="Server port")
    parser.add_argument("--no-tls", action="store_true", help="Disable TLS encryption")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    
    args = parser.parse_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        
    server = NFCRelayServer(
        host=args.host,
        port=args.port,
        use_tls=not args.no_tls
    )
    
    try:
        await server.start_server()
    except KeyboardInterrupt:
        logger.info("Server shutdown requested")
    except Exception as e:
        logger.error(f"Server error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())