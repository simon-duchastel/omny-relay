#!/usr/bin/env python3
"""
Transit card data processing pipeline.
Advanced analysis of NFC data specific to transit card systems.
"""

import asyncio
import logging
import json
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
import struct
import re

import pandas as pd
import numpy as np
from src.utils.crypto import SecureStorage

logger = logging.getLogger(__name__)


@dataclass
class TransitTransaction:
    """Represents a parsed transit transaction."""
    timestamp: datetime
    transaction_type: str  # 'tap_in', 'tap_out', 'balance_check', 'reload'
    amount: Optional[float]
    balance_before: Optional[float]
    balance_after: Optional[float]
    location: Optional[str]
    route: Optional[str]
    card_id: str
    raw_data: bytes
    confidence: float  # 0.0 to 1.0


@dataclass
class CardInfo:
    """Represents parsed card information."""
    card_id: str
    card_type: str
    issuer: Optional[str]
    expiry_date: Optional[datetime]
    current_balance: Optional[float]
    last_transaction: Optional[TransitTransaction]


class TransitProtocolDetector:
    """Detects and identifies transit card protocols."""
    
    def __init__(self):
        # Known transit card patterns and signatures
        self.protocol_signatures = {
            'mifare_classic': [
                b'\x60',  # AUTH_A
                b'\x61',  # AUTH_B
                b'\x30',  # READ
                b'\xA0',  # WRITE
            ],
            'mifare_desfire': [
                b'\x90\x60',  # Select Application
                b'\x90\xAF',  # Additional Frame
                b'\x90\xF5',  # Get Version
            ],
            'felica': [
                b'\x10',  # SENSF_REQ
                b'\x06',  # READ
                b'\x08',  # WRITE
            ],
            'iso14443a': [
                b'\x26',  # REQA
                b'\x52',  # WUPA
                b'\x93',  # SELECT
            ]
        }
        
        # Transit system specific patterns
        self.transit_patterns = {
            'oyster': {
                'card_id_pattern': re.compile(r'\x04[\x00-\xFF]{3}'),
                'balance_offset': 8,
                'balance_format': '<I',  # Little endian 32-bit
                'currency_factor': 100,  # Pence to pounds
            },
            'clipper': {
                'card_id_pattern': re.compile(r'\x04[\x00-\xFF]{7}'),
                'balance_offset': 12,
                'balance_format': '<I',
                'currency_factor': 100,  # Cents to dollars
            },
            'opal': {
                'card_id_pattern': re.compile(r'\x08[\x00-\xFF]{3}'),
                'balance_offset': 16,
                'balance_format': '>I',  # Big endian
                'currency_factor': 100,
            },
            'omny': {  # NYC OMNY
                'card_id_pattern': re.compile(r'\x04[\x00-\xFF]{6}'),
                'balance_offset': 20,
                'balance_format': '<I',
                'currency_factor': 100,
            }
        }
        
    def detect_protocol(self, data: bytes) -> Tuple[str, float]:
        """Detect the NFC protocol used in the data."""
        if not data:
            return 'unknown', 0.0
            
        best_match = 'unknown'
        best_confidence = 0.0
        
        for protocol, signatures in self.protocol_signatures.items():
            confidence = 0.0
            matches = 0
            
            for signature in signatures:
                if signature in data:
                    matches += 1
                    
            if matches > 0:
                confidence = matches / len(signatures)
                if confidence > best_confidence:
                    best_confidence = confidence
                    best_match = protocol
                    
        return best_match, best_confidence
        
    def detect_transit_system(self, data: bytes, card_id: str) -> Tuple[str, float]:
        """Detect the specific transit system."""
        best_match = 'unknown'
        best_confidence = 0.0
        
        for system, patterns in self.transit_patterns.items():
            confidence = 0.0
            
            # Check card ID pattern
            if patterns['card_id_pattern'].search(data):
                confidence += 0.5
                
            # Check for system-specific data patterns
            if len(data) > patterns['balance_offset'] + 4:
                try:
                    balance_data = data[patterns['balance_offset']:patterns['balance_offset']+4]
                    balance = struct.unpack(patterns['balance_format'], balance_data)[0]
                    
                    # Reasonable balance range check
                    if 0 <= balance <= 50000:  # $0 to $500
                        confidence += 0.3
                        
                except (struct.error, ValueError):
                    pass
                    
            if confidence > best_confidence:
                best_confidence = confidence
                best_match = system
                
        return best_match, best_confidence


class TransitDataParser:
    """Parses transit card data into structured information."""
    
    def __init__(self):
        self.detector = TransitProtocolDetector()
        
    def parse_card_data(self, data: bytes, session_data: List[Dict]) -> CardInfo:
        """Parse card information from NFC data."""
        # Extract card ID (usually in first few bytes)
        card_id = self._extract_card_id(data)
        
        # Detect protocol and transit system
        protocol, protocol_conf = self.detector.detect_protocol(data)
        transit_system, system_conf = self.detector.detect_transit_system(data, card_id)
        
        # Parse balance
        current_balance = self._extract_balance(data, transit_system)
        
        # Parse transactions from session data
        transactions = self._extract_transactions(session_data, card_id, transit_system)
        last_transaction = transactions[-1] if transactions else None
        
        return CardInfo(
            card_id=card_id,
            card_type=f"{protocol}/{transit_system}",
            issuer=transit_system if system_conf > 0.5 else None,
            expiry_date=None,  # Would need specific parsing
            current_balance=current_balance,
            last_transaction=last_transaction
        )
        
    def _extract_card_id(self, data: bytes) -> str:
        """Extract card ID from NFC data."""
        if len(data) >= 8:
            # Try common card ID positions
            for offset in [0, 2, 4]:
                if offset + 4 <= len(data):
                    card_id_bytes = data[offset:offset+4]
                    if not all(b == 0 for b in card_id_bytes):
                        return card_id_bytes.hex().upper()
                        
        return data[:min(8, len(data))].hex().upper()
        
    def _extract_balance(self, data: bytes, transit_system: str) -> Optional[float]:
        """Extract balance from card data."""
        if transit_system == 'unknown':
            return None
            
        patterns = self.detector.transit_patterns.get(transit_system)
        if not patterns:
            return None
            
        try:
            offset = patterns['balance_offset']
            if len(data) > offset + 4:
                balance_data = data[offset:offset+4]
                balance = struct.unpack(patterns['balance_format'], balance_data)[0]
                return balance / patterns['currency_factor']
        except (struct.error, ValueError, KeyError):
            pass
            
        return None
        
    def _extract_transactions(self, session_data: List[Dict], card_id: str, 
                            transit_system: str) -> List[TransitTransaction]:
        """Extract transaction data from session."""
        transactions = []
        
        # Look for patterns that indicate transactions
        for i, packet in enumerate(session_data):
            data = packet.get('data', b'')
            if isinstance(data, str):
                data = bytes.fromhex(data)
                
            # Look for write operations (potential balance updates)
            if len(data) >= 2 and data[0] == 0xA0:  # WRITE command
                transaction = self._parse_transaction(
                    data, packet.get('timestamp', time.time()), 
                    card_id, transit_system, i
                )
                if transaction:
                    transactions.append(transaction)
                    
        return transactions
        
    def _parse_transaction(self, data: bytes, timestamp: float, card_id: str,
                         transit_system: str, packet_index: int) -> Optional[TransitTransaction]:
        """Parse a single transaction from write data."""
        try:
            # This is a simplified parser - real implementation would need
            # specific knowledge of each transit system's data format
            
            # Determine transaction type based on data patterns
            if len(data) >= 16:
                # Look for balance change indicators
                amount_data = data[8:12] if len(data) >= 12 else b'\x00\x00\x00\x00'
                amount = struct.unpack('<i', amount_data)[0] / 100.0  # Signed integer
                
                transaction_type = 'unknown'
                if amount < 0:
                    transaction_type = 'tap_in' if abs(amount) < 10 else 'purchase'
                elif amount > 0:
                    transaction_type = 'reload'
                else:
                    transaction_type = 'balance_check'
                    
                return TransitTransaction(
                    timestamp=datetime.fromtimestamp(timestamp),
                    transaction_type=transaction_type,
                    amount=amount if amount != 0 else None,
                    balance_before=None,  # Would need previous state
                    balance_after=None,   # Would need to parse
                    location=None,        # Would need location database
                    route=None,          # Would need route parsing
                    card_id=card_id,
                    raw_data=data,
                    confidence=0.6       # Medium confidence without full parsing
                )
                
        except (struct.error, ValueError):
            pass
            
        return None


class TransitAnalyticsPipeline:
    """Complete analytics pipeline for transit card data."""
    
    def __init__(self, output_dir: str = "analytics_output"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        self.parser = TransitDataParser()
        self.secure_storage = SecureStorage("transit_data")
        
    async def process_session(self, session_id: str, session_data: List[Dict]) -> Dict:
        """Process a complete session and extract transit insights."""
        logger.info(f"Processing session {session_id} with {len(session_data)} packets")
        
        analysis = {
            'session_id': session_id,
            'timestamp': time.time(),
            'total_packets': len(session_data),
            'cards_detected': [],
            'transactions': [],
            'analytics': {},
            'security_notes': []
        }
        
        # Group packets by card ID
        card_groups = self._group_by_card(session_data)
        
        for card_id, packets in card_groups.items():
            # Parse card information
            if packets:
                first_packet_data = packets[0].get('data', b'')
                if isinstance(first_packet_data, str):
                    first_packet_data = bytes.fromhex(first_packet_data)
                    
                card_info = self.parser.parse_card_data(first_packet_data, packets)
                analysis['cards_detected'].append({
                    'card_id': card_id,
                    'card_type': card_info.card_type,
                    'issuer': card_info.issuer,
                    'current_balance': card_info.current_balance,
                    'packet_count': len(packets)
                })
                
                # Extract transactions
                if card_info.last_transaction:
                    analysis['transactions'].append({
                        'card_id': card_id,
                        'transaction_type': card_info.last_transaction.transaction_type,
                        'amount': card_info.last_transaction.amount,
                        'timestamp': card_info.last_transaction.timestamp.isoformat(),
                        'confidence': card_info.last_transaction.confidence
                    })
                    
        # Perform security analysis
        security_analysis = await self._security_analysis(session_data)
        analysis['security_notes'] = security_analysis
        
        # Generate analytics
        analytics = await self._generate_analytics(session_data, analysis['cards_detected'])
        analysis['analytics'] = analytics
        
        # Store securely
        storage_path = self.secure_storage.store_session_data(session_id, analysis)
        logger.info(f"Analysis stored securely: {storage_path}")
        
        return analysis
        
    def _group_by_card(self, session_data: List[Dict]) -> Dict[str, List[Dict]]:
        """Group packets by detected card ID."""
        groups = {}
        
        for packet in session_data:
            data = packet.get('data', b'')
            if isinstance(data, str):
                data = bytes.fromhex(data)
                
            # Extract card ID
            card_id = self.parser._extract_card_id(data)
            
            if card_id not in groups:
                groups[card_id] = []
            groups[card_id].append(packet)
            
        return groups
        
    async def _security_analysis(self, session_data: List[Dict]) -> List[str]:
        """Analyze session for security issues."""
        notes = []
        
        # Check for unencrypted sensitive data
        for packet in session_data:
            data = packet.get('data', b'')
            if isinstance(data, str):
                data = bytes.fromhex(data)
                
            # Look for patterns that suggest unencrypted balance data
            if len(data) >= 8:
                # Check for repeated balance patterns
                for i in range(len(data) - 4):
                    if data[i:i+4] != b'\x00\x00\x00\x00':
                        try:
                            value = struct.unpack('<I', data[i:i+4])[0]
                            if 100 <= value <= 50000:  # Reasonable balance range
                                notes.append(f"Potential unencrypted balance data at offset {i}")
                                break
                        except struct.error:
                            continue
                            
        # Check for authentication weaknesses
        auth_count = sum(1 for packet in session_data 
                        if packet.get('data', b'').startswith(b'\x60') or 
                           packet.get('data', b'').startswith(b'\x61'))
        
        if auth_count == 0:
            notes.append("No authentication commands detected - card may be vulnerable")
        elif auth_count < len(session_data) * 0.1:
            notes.append("Low authentication frequency - potential security risk")
            
        # Check for replay attack vulnerabilities
        packet_hashes = []
        for packet in session_data:
            data = packet.get('data', b'')
            if isinstance(data, str):
                data = bytes.fromhex(data)
            packet_hash = hash(data)
            if packet_hash in packet_hashes:
                notes.append("Duplicate packets detected - potential replay vulnerability")
                break
            packet_hashes.append(packet_hash)
            
        return notes
        
    async def _generate_analytics(self, session_data: List[Dict], 
                                cards_detected: List[Dict]) -> Dict:
        """Generate advanced analytics from the session."""
        analytics = {
            'session_duration': 0,
            'packet_frequency': 0,
            'data_patterns': {},
            'card_interactions': {},
            'timing_analysis': {}
        }
        
        if not session_data:
            return analytics
            
        # Calculate session duration
        timestamps = [p.get('timestamp', 0) for p in session_data]
        if timestamps:
            duration = max(timestamps) - min(timestamps)
            analytics['session_duration'] = duration
            analytics['packet_frequency'] = len(session_data) / max(duration, 1)
            
        # Analyze data patterns
        data_lengths = [len(p.get('data', b'')) for p in session_data]
        analytics['data_patterns'] = {
            'avg_packet_size': np.mean(data_lengths) if data_lengths else 0,
            'min_packet_size': min(data_lengths) if data_lengths else 0,
            'max_packet_size': max(data_lengths) if data_lengths else 0,
            'total_data_bytes': sum(data_lengths)
        }
        
        # Analyze timing patterns
        if len(timestamps) > 1:
            intervals = np.diff(sorted(timestamps))
            analytics['timing_analysis'] = {
                'avg_interval': float(np.mean(intervals)),
                'min_interval': float(np.min(intervals)),
                'max_interval': float(np.max(intervals)),
                'interval_std': float(np.std(intervals))
            }
            
        # Card interaction analysis
        for card in cards_detected:
            card_id = card['card_id']
            card_packets = [p for p in session_data 
                          if self.parser._extract_card_id(p.get('data', b'')) == card_id]
            
            analytics['card_interactions'][card_id] = {
                'total_interactions': len(card_packets),
                'avg_data_size': np.mean([len(p.get('data', b'')) for p in card_packets]),
                'interaction_frequency': len(card_packets) / max(analytics['session_duration'], 1)
            }
            
        return analytics
        
    async def generate_report(self, session_ids: List[str]) -> str:
        """Generate comprehensive report across multiple sessions."""
        report_data = {
            'report_timestamp': datetime.now().isoformat(),
            'sessions_analyzed': len(session_ids),
            'summary': {
                'total_cards': 0,
                'total_transactions': 0,
                'transit_systems': set(),
                'security_issues': []
            },
            'sessions': []
        }
        
        for session_id in session_ids:
            try:
                session_analysis = self.secure_storage.load_session_data(session_id)
                report_data['sessions'].append(session_analysis)
                
                # Update summary
                report_data['summary']['total_cards'] += len(session_analysis.get('cards_detected', []))
                report_data['summary']['total_transactions'] += len(session_analysis.get('transactions', []))
                
                for card in session_analysis.get('cards_detected', []):
                    if card.get('issuer'):
                        report_data['summary']['transit_systems'].add(card['issuer'])
                        
                report_data['summary']['security_issues'].extend(
                    session_analysis.get('security_notes', [])
                )
                
            except FileNotFoundError:
                logger.warning(f"Session {session_id} data not found")
                
        # Convert sets to lists for JSON serialization
        report_data['summary']['transit_systems'] = list(report_data['summary']['transit_systems'])
        
        # Save report
        report_file = self.output_dir / f"transit_report_{int(time.time())}.json"
        with open(report_file, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)
            
        logger.info(f"Transit analysis report generated: {report_file}")
        return str(report_file)


# CLI interface for the transit processor
async def main():
    """Main CLI interface."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Transit Card Data Processor")
    parser.add_argument("--session-id", help="Process specific session")
    parser.add_argument("--generate-report", action="store_true", help="Generate summary report")
    parser.add_argument("--list-sessions", action="store_true", help="List available sessions")
    parser.add_argument("--output-dir", default="analytics_output", help="Output directory")
    
    args = parser.parse_args()
    
    pipeline = TransitAnalyticsPipeline(args.output_dir)
    
    if args.list_sessions:
        sessions = pipeline.secure_storage.list_sessions()
        print("Available sessions:")
        for session in sessions:
            print(f"  - {session}")
            
    elif args.generate_report:
        sessions = pipeline.secure_storage.list_sessions()
        if sessions:
            report_file = await pipeline.generate_report(sessions)
            print(f"Report generated: {report_file}")
        else:
            print("No sessions available for report generation")
            
    elif args.session_id:
        try:
            session_data = pipeline.secure_storage.load_session_data(args.session_id)
            print(f"Session {args.session_id} analysis:")
            print(json.dumps(session_data, indent=2, default=str))
        except FileNotFoundError:
            print(f"Session {args.session_id} not found")
            
    else:
        print("No action specified. Use --help for options.")


if __name__ == "__main__":
    asyncio.run(main())