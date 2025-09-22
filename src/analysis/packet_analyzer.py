#!/usr/bin/env python3
"""
NFC packet analysis and transit card data extraction.
Specialized analyzer for transit card protocols and data patterns.
"""

import asyncio
import logging
import struct
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import json

try:
    from scapy.all import wrpcap, Packet, Raw
    from scapy.layers.l2 import Ether
except ImportError:
    wrpcap = None
    logger.warning("Scapy not available - PCAP export disabled")

logger = logging.getLogger(__name__)


class TransitCardProtocol:
    """Base class for transit card protocol analysis."""
    
    def __init__(self, name: str):
        self.name = name
        self.patterns = {}
        
    def identify(self, data: bytes) -> bool:
        """Check if data matches this protocol."""
        raise NotImplementedError
        
    def parse(self, data: bytes) -> Dict:
        """Parse protocol-specific data."""
        raise NotImplementedError


class ISO14443Protocol(TransitCardProtocol):
    """ISO 14443 Type A/B protocol analyzer."""
    
    def __init__(self):
        super().__init__("ISO14443")
        
        # Common ISO 14443 commands
        self.commands = {
            0x26: "REQA",     # Request Type A
            0x52: "WUPA",     # Wake-Up Type A
            0x93: "SELECT",   # Select Cascade Level 1
            0x95: "SELECT",   # Select Cascade Level 2
            0x97: "SELECT",   # Select Cascade Level 3
            0x50: "HALT",     # Halt
            0x30: "READ",     # Read block
            0xA0: "WRITE",    # Write block
            0x60: "AUTH_A",   # Authenticate with Key A
            0x61: "AUTH_B",   # Authenticate with Key B
        }
        
    def identify(self, data: bytes) -> bool:
        """Check if data is ISO 14443."""
        if len(data) == 0:
            return False
            
        # Check for common ISO 14443 patterns
        first_byte = data[0]
        return (
            first_byte in self.commands or
            data.startswith(b'\x26') or  # REQA
            data.startswith(b'\x52') or  # WUPA
            data.startswith(b'\x93') or  # SELECT CL1
            len(data) == 2 and data == b'\x26\x00'  # Short REQA
        )
        
    def parse(self, data: bytes) -> Dict:
        """Parse ISO 14443 data."""
        result = {
            'protocol': 'ISO14443',
            'raw_data': data.hex(),
            'length': len(data),
            'timestamp': time.time()
        }
        
        if len(data) == 0:
            return result
            
        cmd = data[0]
        result['command'] = self.commands.get(cmd, f"UNKNOWN_{cmd:02X}")
        result['command_code'] = f"0x{cmd:02X}"
        
        # Parse specific commands
        if cmd == 0x93 and len(data) >= 2:  # SELECT
            result['cascade_level'] = 1
            if len(data) >= 5:
                result['uid_part'] = data[2:6].hex()
                
        elif cmd == 0x30 and len(data) >= 2:  # READ
            result['block_number'] = data[1]
            
        elif cmd == 0xA0 and len(data) >= 2:  # WRITE
            result['block_number'] = data[1]
            if len(data) > 2:
                result['write_data'] = data[2:].hex()
                
        return result


class MifareProtocol(TransitCardProtocol):
    """MIFARE Classic/Plus protocol analyzer."""
    
    def __init__(self):
        super().__init__("MIFARE")
        
        self.sector_size = 16  # bytes per block
        self.blocks_per_sector = 4
        
    def identify(self, data: bytes) -> bool:
        """Check if data is MIFARE."""
        if len(data) < 2:
            return False
            
        # MIFARE authentication patterns
        if data[0] in [0x60, 0x61]:  # AUTH_A or AUTH_B
            return True
            
        # MIFARE read/write patterns
        if data[0] == 0x30 and len(data) == 2:  # Read block
            return True
            
        return False
        
    def parse(self, data: bytes) -> Dict:
        """Parse MIFARE data."""
        result = {
            'protocol': 'MIFARE',
            'raw_data': data.hex(),
            'length': len(data),
            'timestamp': time.time()
        }
        
        if len(data) >= 2:
            cmd = data[0]
            block = data[1]
            
            if cmd in [0x60, 0x61]:
                result['command'] = 'AUTH_A' if cmd == 0x60 else 'AUTH_B'
                result['block'] = block
                result['sector'] = block // self.blocks_per_sector
                
            elif cmd == 0x30:
                result['command'] = 'READ'
                result['block'] = block
                result['sector'] = block // self.blocks_per_sector
                
        return result


class TransitCardAnalyzer:
    """Specialized analyzer for transit card data patterns."""
    
    def __init__(self):
        self.protocols = [
            ISO14443Protocol(),
            MifareProtocol()
        ]
        
        # Transit card specific patterns
        self.transit_patterns = {
            'balance_patterns': [
                b'\x00\x00\x00\x00',  # Zero balance
                b'\xFF\xFF\xFF\xFF',  # Max balance
            ],
            'date_patterns': [],
            'transaction_patterns': []
        }
        
    def analyze_packet(self, data: bytes, direction: str) -> Dict:
        """Analyze a single NFC packet."""
        analysis = {
            'timestamp': time.time(),
            'direction': direction,
            'length': len(data),
            'raw_data': data.hex(),
            'protocol': 'UNKNOWN',
            'parsed_data': {},
            'transit_info': {}
        }
        
        # Try to identify protocol
        for protocol in self.protocols:
            if protocol.identify(data):
                analysis['protocol'] = protocol.name
                analysis['parsed_data'] = protocol.parse(data)
                break
                
        # Look for transit-specific patterns
        transit_info = self._analyze_transit_patterns(data)
        if transit_info:
            analysis['transit_info'] = transit_info
            
        return analysis
        
    def _analyze_transit_patterns(self, data: bytes) -> Dict:
        """Look for transit card specific patterns."""
        info = {}
        
        # Look for balance information (common at specific positions)
        if len(data) >= 4:
            # Try little-endian 32-bit integer
            try:
                balance_le = struct.unpack('<I', data[:4])[0]
                if 0 < balance_le < 100000:  # Reasonable balance range (cents)
                    info['possible_balance_le'] = balance_le / 100  # Convert to dollars
            except:
                pass
                
            # Try big-endian 32-bit integer
            try:
                balance_be = struct.unpack('>I', data[:4])[0]
                if 0 < balance_be < 100000:
                    info['possible_balance_be'] = balance_be / 100
            except:
                pass
                
        # Look for date/time patterns
        if len(data) >= 4:
            # Unix timestamp (common in transit cards)
            try:
                timestamp = struct.unpack('<I', data[:4])[0]
                if 946684800 < timestamp < 2147483647:  # 2000-2038 range
                    from datetime import datetime
                    dt = datetime.fromtimestamp(timestamp)
                    info['possible_timestamp'] = dt.isoformat()
            except:
                pass
                
        # Look for card ID patterns
        if len(data) >= 8:
            # Check for repeated patterns that might be card IDs
            card_id_candidate = data[:8]
            if not all(b == 0 for b in card_id_candidate):
                info['possible_card_id'] = card_id_candidate.hex()
                
        return info


class SessionAnalyzer:
    """Analyzes complete NFC sessions for transit card insights."""
    
    def __init__(self):
        self.card_analyzer = TransitCardAnalyzer()
        self.sessions = {}
        
    def analyze_session(self, session_data: List[Dict]) -> Dict:
        """Analyze a complete session's packet data."""
        analysis = {
            'session_start': session_data[0]['timestamp'] if session_data else 0,
            'session_end': session_data[-1]['timestamp'] if session_data else 0,
            'total_packets': len(session_data),
            'protocols_detected': set(),
            'transit_insights': {},
            'packet_analysis': []
        }
        
        balances = []
        timestamps = []
        card_ids = set()
        
        for packet_data in session_data:
            data = bytes.fromhex(packet_data['data']) if isinstance(packet_data['data'], str) else packet_data['data']
            direction = packet_data.get('direction', 'unknown')
            
            packet_analysis = self.card_analyzer.analyze_packet(data, direction)
            analysis['packet_analysis'].append(packet_analysis)
            
            # Collect insights
            if packet_analysis['protocol'] != 'UNKNOWN':
                analysis['protocols_detected'].add(packet_analysis['protocol'])
                
            transit_info = packet_analysis.get('transit_info', {})
            
            # Collect balance information
            if 'possible_balance_le' in transit_info:
                balances.append(transit_info['possible_balance_le'])
            if 'possible_balance_be' in transit_info:
                balances.append(transit_info['possible_balance_be'])
                
            # Collect timestamps
            if 'possible_timestamp' in transit_info:
                timestamps.append(transit_info['possible_timestamp'])
                
            # Collect card IDs
            if 'possible_card_id' in transit_info:
                card_ids.add(transit_info['possible_card_id'])
                
        # Analyze collected data
        if balances:
            analysis['transit_insights']['possible_balances'] = list(set(balances))
            analysis['transit_insights']['balance_changes'] = self._analyze_balance_changes(balances)
            
        if timestamps:
            analysis['transit_insights']['timestamps'] = timestamps
            
        if card_ids:
            analysis['transit_insights']['possible_card_ids'] = list(card_ids)
            
        analysis['protocols_detected'] = list(analysis['protocols_detected'])
        
        return analysis
        
    def _analyze_balance_changes(self, balances: List[float]) -> List[Dict]:
        """Analyze balance changes to detect transactions."""
        changes = []
        
        for i in range(1, len(balances)):
            change = balances[i] - balances[i-1]
            if abs(change) > 0.01:  # Significant change
                changes.append({
                    'from_balance': balances[i-1],
                    'to_balance': balances[i],
                    'change': change,
                    'type': 'debit' if change < 0 else 'credit'
                })
                
        return changes


class PacketAnalyzer:
    """Main packet analyzer with export capabilities."""
    
    def __init__(self, output_dir: str = "analysis_output"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        self.session_analyzer = SessionAnalyzer()
        self.active_sessions = {}
        
    async def analyze_nfc_packet(self, data: bytes, client_type: str, session_id: str) -> Dict:
        """Analyze a single NFC packet in real-time."""
        analysis = self.session_analyzer.card_analyzer.analyze_packet(data, client_type)
        
        # Store for session analysis
        if session_id not in self.active_sessions:
            self.active_sessions[session_id] = []
            
        self.active_sessions[session_id].append({
            'timestamp': analysis['timestamp'],
            'data': data,
            'direction': client_type,
            'analysis': analysis
        })
        
        # Log interesting findings
        if analysis['transit_info']:
            logger.info(f"Transit data detected in session {session_id}: {analysis['transit_info']}")
            
        return analysis
        
    async def export_session_pcap(self, session):
        """Export session data as PCAP file."""
        if not wrpcap:
            logger.warning("PCAP export not available - Scapy not installed")
            return
            
        try:
            pcap_file = self.output_dir / f"session_{session.session_id}.pcap"
            packets = []
            
            for log_entry in session.data_log:
                # Create a simple Ethernet frame with NFC data as payload
                packet = Ether() / Raw(load=log_entry['data'])
                packet.time = log_entry['timestamp']
                packets.append(packet)
                
            if packets:
                wrpcap(str(pcap_file), packets)
                logger.info(f"PCAP exported: {pcap_file}")
                
        except Exception as e:
            logger.error(f"PCAP export failed: {e}")
            
    async def export_session_analysis(self, session):
        """Export detailed session analysis as JSON."""
        if session.session_id in self.active_sessions:
            session_data = self.active_sessions[session.session_id]
            analysis = self.session_analyzer.analyze_session(session_data)
            
            # Add session metadata
            analysis['session_metadata'] = {
                'session_id': session.session_id,
                'duration': time.time() - session.created_at,
                'total_packets': session.packet_count,
                'clients': list(session.clients.keys())
            }
            
            # Export to JSON
            analysis_file = self.output_dir / f"analysis_{session.session_id}.json"
            with open(analysis_file, 'w') as f:
                json.dump(analysis, f, indent=2, default=str)
                
            logger.info(f"Session analysis exported: {analysis_file}")
            
            # Clean up active session data
            del self.active_sessions[session.session_id]
            
            return analysis_file
            
    def generate_summary_report(self, session_ids: List[str]) -> str:
        """Generate a summary report across multiple sessions."""
        report_file = self.output_dir / f"summary_report_{int(time.time())}.json"
        
        summary = {
            'report_timestamp': time.time(),
            'sessions_analyzed': len(session_ids),
            'sessions': [],
            'aggregate_insights': {
                'unique_card_ids': set(),
                'protocols_seen': set(),
                'total_packets': 0,
                'balance_ranges': []
            }
        }
        
        for session_id in session_ids:
            analysis_file = self.output_dir / f"analysis_{session_id}.json"
            if analysis_file.exists():
                with open(analysis_file, 'r') as f:
                    session_analysis = json.load(f)
                    
                summary['sessions'].append(session_analysis)
                
                # Aggregate insights
                insights = session_analysis.get('transit_insights', {})
                if 'possible_card_ids' in insights:
                    summary['aggregate_insights']['unique_card_ids'].update(insights['possible_card_ids'])
                    
                if 'protocols_detected' in session_analysis:
                    summary['aggregate_insights']['protocols_seen'].update(session_analysis['protocols_detected'])
                    
                summary['aggregate_insights']['total_packets'] += session_analysis.get('total_packets', 0)
                
                if 'possible_balances' in insights:
                    summary['aggregate_insights']['balance_ranges'].extend(insights['possible_balances'])
                    
        # Convert sets to lists for JSON serialization
        summary['aggregate_insights']['unique_card_ids'] = list(summary['aggregate_insights']['unique_card_ids'])
        summary['aggregate_insights']['protocols_seen'] = list(summary['aggregate_insights']['protocols_seen'])
        
        with open(report_file, 'w') as f:
            json.dump(summary, f, indent=2, default=str)
            
        logger.info(f"Summary report generated: {report_file}")
        return str(report_file)