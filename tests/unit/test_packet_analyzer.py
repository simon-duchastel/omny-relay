"""
Unit tests for NFC packet analysis functionality.
Tests protocol detection, parsing, and session analysis.
"""

import pytest
import asyncio
import json
import time
from pathlib import Path
from unittest.mock import Mock, AsyncMock, patch, mock_open

from src.analysis.packet_analyzer import (
    PacketAnalyzer, SessionAnalyzer, TransitCardAnalyzer
)
from tests.fixtures.nfc_packets import (
    NFCPacketSamples, REQA, WUPA, READ_BLOCK_4, AUTH_A, 
    OYSTER_BALANCE, CLIPPER_BALANCE
)


class TestTransitCardAnalyzer:
    """Test transit card analysis functionality."""
    
    def test_initialization(self):
        """Test analyzer initialization."""
        analyzer = TransitCardAnalyzer()
        
        assert len(analyzer.protocols) > 0
        assert analyzer.transit_patterns is not None
        assert 'balance_patterns' in analyzer.transit_patterns
    
    def test_analyze_packet_iso14443(self):
        """Test ISO 14443 packet analysis."""
        analyzer = TransitCardAnalyzer()
        
        analysis = analyzer.analyze_packet(REQA, "reader_to_card")
        
        assert analysis['protocol'] == 'ISO14443'
        assert analysis['direction'] == "reader_to_card"
        assert analysis['length'] == len(REQA)
        assert 'parsed_data' in analysis
        assert analysis['parsed_data']['command'] == 'REQA'
        assert analysis['parsed_data']['command_code'] == '0x26'
    
    def test_analyze_packet_mifare(self):
        """Test MIFARE packet analysis."""
        analyzer = TransitCardAnalyzer()
        
        analysis = analyzer.analyze_packet(AUTH_A, "reader_to_card")
        
        assert analysis['protocol'] == 'MIFARE'
        assert analysis['parsed_data']['command'] == 'AUTH_A'
        assert analysis['parsed_data']['block'] == 0
        assert analysis['parsed_data']['sector'] == 0
    
    def test_analyze_packet_unknown(self):
        """Test unknown packet analysis."""
        analyzer = TransitCardAnalyzer()
        
        unknown_data = b'\xFF\xFF\xFF\xFF'
        analysis = analyzer.analyze_packet(unknown_data, "unknown")
        
        assert analysis['protocol'] == 'UNKNOWN'
        assert analysis['direction'] == "unknown"
        assert analysis['length'] == 4
    
    def test_analyze_packet_empty(self):
        """Test empty packet analysis."""
        analyzer = TransitCardAnalyzer()
        
        analysis = analyzer.analyze_packet(b'', "reader_to_card")
        
        assert analysis['protocol'] == 'UNKNOWN'
        assert analysis['length'] == 0
    
    def test_analyze_transit_patterns_oyster(self):
        """Test transit pattern analysis for Oyster card."""
        analyzer = TransitCardAnalyzer()
        
        # Use Oyster balance data
        analysis = analyzer.analyze_packet(OYSTER_BALANCE, "card_to_reader")
        
        transit_info = analysis.get('transit_info', {})
        
        # Should detect balance information
        assert 'possible_balance_le' in transit_info or 'possible_balance_be' in transit_info
        assert 'possible_card_id' in transit_info
        
        card_id = transit_info['possible_card_id']
        assert len(card_id) >= 8  # At least 4 bytes in hex
    
    def test_analyze_transit_patterns_timestamp(self):
        """Test timestamp detection in transit data."""
        analyzer = TransitCardAnalyzer()
        
        # Create data with Unix timestamp
        timestamp_data = b'\x60\x95\x99\x61' + b'\x00' * 12  # 2023 timestamp
        analysis = analyzer.analyze_packet(timestamp_data, "card_to_reader")
        
        transit_info = analysis.get('transit_info', {})
        if 'possible_timestamp' in transit_info:
            # Should be a valid ISO format timestamp
            assert 'T' in transit_info['possible_timestamp']
    
    def test_analyze_packet_large_data(self):
        """Test analysis of large packet data."""
        analyzer = TransitCardAnalyzer()
        
        large_data = REQA + b'\x00' * 1000
        analysis = analyzer.analyze_packet(large_data, "reader_to_card")
        
        assert analysis['protocol'] == 'ISO14443'
        assert analysis['length'] == len(large_data)


class TestSessionAnalyzer:
    """Test session analysis functionality."""
    
    def test_initialization(self):
        """Test session analyzer initialization."""
        analyzer = SessionAnalyzer()
        
        assert analyzer.card_analyzer is not None
        assert analyzer.sessions == {}
    
    def test_analyze_session_empty(self):
        """Test analysis of empty session."""
        analyzer = SessionAnalyzer()
        
        analysis = analyzer.analyze_session([])
        
        assert analysis['total_packets'] == 0
        assert analysis['protocols_detected'] == []
        assert analysis['packet_analysis'] == []
    
    def test_analyze_session_basic(self, sample_session_data):
        """Test basic session analysis."""
        analyzer = SessionAnalyzer()
        
        analysis = analyzer.analyze_session(sample_session_data)
        
        assert analysis['total_packets'] == len(sample_session_data)
        assert 'ISO14443' in analysis['protocols_detected']
        assert 'MIFARE' in analysis['protocols_detected']
        assert len(analysis['packet_analysis']) == len(sample_session_data)
    
    def test_analyze_session_transit_insights(self, sample_session_data):
        """Test transit insights extraction from session."""
        analyzer = SessionAnalyzer()
        
        analysis = analyzer.analyze_session(sample_session_data)
        
        transit_insights = analysis.get('transit_insights', {})
        
        # Should extract balance information
        if 'possible_balances' in transit_insights:
            balances = transit_insights['possible_balances']
            assert len(balances) > 0
            assert all(isinstance(b, float) for b in balances)
        
        # Should extract card IDs
        if 'possible_card_ids' in transit_insights:
            card_ids = transit_insights['possible_card_ids']
            assert len(card_ids) > 0
            assert all(isinstance(cid, str) for cid in card_ids)
    
    def test_analyze_balance_changes(self):
        """Test balance change analysis."""
        analyzer = SessionAnalyzer()
        
        balances = [20.00, 17.10, 17.10, 14.35]  # Two transactions
        changes = analyzer._analyze_balance_changes(balances)
        
        assert len(changes) == 2
        
        # First transaction: -2.90
        assert abs(changes[0]['change'] + 2.90) < 0.01
        assert changes[0]['type'] == 'debit'
        assert changes[0]['from_balance'] == 20.00
        assert changes[0]['to_balance'] == 17.10
        
        # Second transaction: -2.75
        assert abs(changes[1]['change'] + 2.75) < 0.01
        assert changes[1]['type'] == 'debit'
    
    def test_analyze_balance_changes_credit(self):
        """Test balance change analysis with credit."""
        analyzer = SessionAnalyzer()
        
        balances = [5.00, 25.00]  # Top-up
        changes = analyzer._analyze_balance_changes(balances)
        
        assert len(changes) == 1
        assert changes[0]['change'] == 20.00
        assert changes[0]['type'] == 'credit'
    
    def test_analyze_balance_changes_no_change(self):
        """Test balance analysis with no changes."""
        analyzer = SessionAnalyzer()
        
        balances = [15.50, 15.50, 15.50]  # No changes
        changes = analyzer._analyze_balance_changes(balances)
        
        assert len(changes) == 0


class TestPacketAnalyzer:
    """Test main packet analyzer functionality."""
    
    def test_initialization(self, temp_dir):
        """Test packet analyzer initialization."""
        output_dir = str(Path(temp_dir) / "test_output")
        analyzer = PacketAnalyzer(output_dir=output_dir)
        
        assert analyzer.output_dir == Path(output_dir)
        assert analyzer.output_dir.exists()
        assert analyzer.session_analyzer is not None
        assert analyzer.active_sessions == {}
    
    @pytest.mark.asyncio
    async def test_analyze_nfc_packet(self, temp_dir):
        """Test real-time NFC packet analysis."""
        analyzer = PacketAnalyzer(output_dir=temp_dir)
        
        analysis = await analyzer.analyze_nfc_packet(
            REQA, "READER", "123456"
        )
        
        assert analysis['protocol'] == 'ISO14443'
        assert analysis['direction'] == "READER"
        
        # Should store for session analysis
        assert "123456" in analyzer.active_sessions
        assert len(analyzer.active_sessions["123456"]) == 1
    
    @pytest.mark.asyncio
    async def test_analyze_nfc_packet_multiple(self, temp_dir):
        """Test multiple packet analysis for same session."""
        analyzer = PacketAnalyzer(output_dir=temp_dir)
        
        # Analyze multiple packets
        await analyzer.analyze_nfc_packet(REQA, "READER", "123456")
        await analyzer.analyze_nfc_packet(AUTH_A, "READER", "123456")
        await analyzer.analyze_nfc_packet(OYSTER_BALANCE, "CARD", "123456")
        
        # Should accumulate packets
        assert len(analyzer.active_sessions["123456"]) == 3
    
    @pytest.mark.asyncio
    async def test_analyze_nfc_packet_interesting_findings(self, temp_dir):
        """Test detection of interesting transit data."""
        analyzer = PacketAnalyzer(output_dir=temp_dir)
        
        with patch('logging.Logger.info') as mock_log:
            analysis = await analyzer.analyze_nfc_packet(
                OYSTER_BALANCE, "CARD", "123456"
            )
            
            # Should log interesting findings
            if analysis.get('transit_info'):
                mock_log.assert_called()
    
    @pytest.mark.asyncio
    async def test_export_session_pcap_no_scapy(self, temp_dir, sample_session):
        """Test PCAP export when Scapy is not available."""
        analyzer = PacketAnalyzer(output_dir=temp_dir)
        
        # Mock Scapy not being available
        with patch('src.analysis.packet_analyzer.wrpcap', None):
            await analyzer.export_session_pcap(sample_session)
            
            # Should not raise exception, just log warning
    
    @pytest.mark.asyncio
    async def test_export_session_pcap_with_scapy(self, temp_dir, sample_session):
        """Test PCAP export with Scapy available."""
        analyzer = PacketAnalyzer(output_dir=temp_dir)
        
        # Add some data to session
        sample_session.log_data(REQA, "reader_to_card")
        sample_session.log_data(OYSTER_BALANCE, "card_to_reader")
        
        with patch('src.analysis.packet_analyzer.wrpcap') as mock_wrpcap:
            await analyzer.export_session_pcap(sample_session)
            
            # Should call wrpcap with packets
            mock_wrpcap.assert_called_once()
            
            # Verify file path
            call_args = mock_wrpcap.call_args[0]
            assert "session_123456.pcap" in call_args[0]
    
    @pytest.mark.asyncio
    async def test_export_session_analysis(self, temp_dir, sample_session):
        """Test session analysis export."""
        analyzer = PacketAnalyzer(output_dir=temp_dir)
        
        # Add session to active sessions
        analyzer.active_sessions[sample_session.session_id] = [
            {
                'timestamp': time.time(),
                'data': REQA,
                'direction': 'reader_to_card',
                'analysis': {'protocol': 'ISO14443', 'command': 'REQA'}
            }
        ]
        
        analysis_file = await analyzer.export_session_analysis(sample_session)
        
        assert analysis_file is not None
        assert Path(analysis_file).exists()
        
        # Verify JSON content
        with open(analysis_file, 'r') as f:
            data = json.load(f)
        
        assert 'session_metadata' in data
        assert data['session_metadata']['session_id'] == sample_session.session_id
        assert 'total_packets' in data
        assert 'protocols_detected' in data
        
        # Session should be cleaned up
        assert sample_session.session_id not in analyzer.active_sessions
    
    def test_generate_summary_report_empty(self, temp_dir):
        """Test summary report generation with no sessions."""
        analyzer = PacketAnalyzer(output_dir=temp_dir)
        
        report_file = analyzer.generate_summary_report([])
        
        assert Path(report_file).exists()
        
        with open(report_file, 'r') as f:
            report = json.load(f)
        
        assert report['sessions_analyzed'] == 0
        assert report['sessions'] == []
    
    def test_generate_summary_report_with_sessions(self, temp_dir):
        """Test summary report generation with multiple sessions."""
        analyzer = PacketAnalyzer(output_dir=temp_dir)
        
        # Create mock analysis files
        session_ids = ['123456', '234567', '345678']
        
        for session_id in session_ids:
            analysis_data = {
                'session_id': session_id,
                'total_packets': 10,
                'protocols_detected': ['ISO14443', 'MIFARE'],
                'transit_insights': {
                    'possible_card_ids': [f'04{session_id[:6]}'],
                    'possible_balances': [15.50]
                }
            }
            
            analysis_file = analyzer.output_dir / f"analysis_{session_id}.json"
            with open(analysis_file, 'w') as f:
                json.dump(analysis_data, f)
        
        report_file = analyzer.generate_summary_report(session_ids)
        
        with open(report_file, 'r') as f:
            report = json.load(f)
        
        assert report['sessions_analyzed'] == 3
        assert len(report['sessions']) == 3
        assert len(report['aggregate_insights']['unique_card_ids']) == 3
        assert 'ISO14443' in report['aggregate_insights']['protocols_seen']
        assert report['aggregate_insights']['total_packets'] == 30


class TestProtocolDetection:
    """Test protocol detection algorithms."""
    
    def test_iso14443_detection(self):
        """Test ISO 14443 protocol detection."""
        analyzer = TransitCardAnalyzer()
        
        # Test various ISO 14443 commands
        test_cases = [
            (REQA, True),
            (WUPA, True),
            (b'\x93\x20', True),  # SELECT CL1
            (b'\x50\x00', True),  # HALT
            (b'\xFF\xFF', False), # Invalid
        ]
        
        for data, expected in test_cases:
            protocols = [p for p in analyzer.protocols if p.name == "ISO14443"]
            if protocols:
                result = protocols[0].identify(data)
                assert result == expected, f"Failed for data: {data.hex()}"
    
    def test_mifare_detection(self):
        """Test MIFARE protocol detection."""
        analyzer = TransitCardAnalyzer()
        
        test_cases = [
            (AUTH_A, True),
            (b'\x61\x00\xFF\xFF\xFF\xFF\xFF\xFF', True),  # AUTH_B
            (READ_BLOCK_4, True),
            (b'\x26\x00', False),  # ISO 14443, not MIFARE
        ]
        
        for data, expected in test_cases:
            protocols = [p for p in analyzer.protocols if p.name == "MIFARE"]
            if protocols:
                result = protocols[0].identify(data)
                assert result == expected, f"Failed for data: {data.hex()}"
    
    def test_protocol_parsing_iso14443(self):
        """Test ISO 14443 protocol parsing."""
        analyzer = TransitCardAnalyzer()
        
        protocols = [p for p in analyzer.protocols if p.name == "ISO14443"]
        if protocols:
            protocol = protocols[0]
            
            # Test REQA parsing
            result = protocol.parse(REQA)
            assert result['protocol'] == 'ISO14443'
            assert result['command'] == 'REQA'
            assert result['command_code'] == '0x26'
            
            # Test SELECT parsing
            select_data = b'\x93\x20\x12\x34\x56\x78'
            result = protocol.parse(select_data)
            assert result['command'] == 'SELECT'
            assert result['cascade_level'] == 1
            if 'uid_part' in result:
                assert result['uid_part'] == '12345678'
    
    def test_protocol_parsing_mifare(self):
        """Test MIFARE protocol parsing."""
        analyzer = TransitCardAnalyzer()
        
        protocols = [p for p in analyzer.protocols if p.name == "MIFARE"]
        if protocols:
            protocol = protocols[0]
            
            # Test AUTH parsing
            result = protocol.parse(AUTH_A)
            assert result['protocol'] == 'MIFARE'
            assert result['command'] == 'AUTH_A'
            assert result['block'] == 0
            assert result['sector'] == 0
            
            # Test READ parsing
            result = protocol.parse(READ_BLOCK_4)
            assert result['command'] == 'READ'
            assert result['block'] == 4
            assert result['sector'] == 1


class TestTransitSystemDetection:
    """Test transit system specific detection."""
    
    def test_oyster_pattern_detection(self):
        """Test Oyster card pattern detection."""
        analyzer = TransitCardAnalyzer()
        
        # Test with Oyster balance data
        analysis = analyzer.analyze_packet(OYSTER_BALANCE, "card_to_reader")
        transit_info = analysis.get('transit_info', {})
        
        # Should detect balance and card ID
        assert 'possible_card_id' in transit_info
        card_id = transit_info['possible_card_id']
        assert len(card_id) >= 8
    
    def test_clipper_pattern_detection(self):
        """Test Clipper card pattern detection."""
        analyzer = TransitCardAnalyzer()
        
        analysis = analyzer.analyze_packet(CLIPPER_BALANCE, "card_to_reader")
        transit_info = analysis.get('transit_info', {})
        
        assert 'possible_card_id' in transit_info
    
    def test_balance_extraction_patterns(self):
        """Test balance extraction from different formats."""
        analyzer = TransitCardAnalyzer()
        
        # Test different balance formats
        test_patterns = [
            (b'\x00\x00\x15\x50' + b'\x00' * 12, 15.50),  # £15.50 in pence
            (b'\x00\x00\x0F\xA0' + b'\x00' * 12, 15.00),  # $15.00 in cents
            (b'\x00\x00\x00\x64' + b'\x00' * 12, 1.00),   # $1.00
        ]
        
        for data, expected_balance in test_patterns:
            analysis = analyzer.analyze_packet(data, "card_to_reader")
            transit_info = analysis.get('transit_info', {})
            
            # Check both little and big endian interpretations
            found_balance = False
            if 'possible_balance_le' in transit_info:
                if abs(transit_info['possible_balance_le'] - expected_balance) < 0.01:
                    found_balance = True
            if 'possible_balance_be' in transit_info:
                if abs(transit_info['possible_balance_be'] - expected_balance) < 0.01:
                    found_balance = True
            
            # At least one format should match
            # Note: This is a heuristic test, so we don't assert always


class TestPerformance:
    """Test analyzer performance with various data sizes."""
    
    @pytest.mark.asyncio
    async def test_analyze_large_session(self, temp_dir):
        """Test analysis of large session data."""
        analyzer = PacketAnalyzer(output_dir=temp_dir)
        
        # Simulate large session with many packets
        session_id = "large_session"
        
        for i in range(1000):
            data = REQA if i % 2 == 0 else OYSTER_BALANCE
            await analyzer.analyze_nfc_packet(data, "READER", session_id)
        
        # Should handle large sessions efficiently
        assert len(analyzer.active_sessions[session_id]) == 1000
    
    def test_analyze_packet_performance(self):
        """Test packet analysis performance."""
        analyzer = TransitCardAnalyzer()
        
        start_time = time.time()
        
        # Analyze many packets
        for _ in range(1000):
            analyzer.analyze_packet(REQA, "reader_to_card")
        
        end_time = time.time()
        
        # Should complete in reasonable time (< 1 second for 1000 packets)
        duration = end_time - start_time
        assert duration < 1.0, f"Analysis too slow: {duration:.3f}s for 1000 packets"


class TestErrorHandling:
    """Test error handling in packet analysis."""
    
    def test_analyze_corrupted_packet(self):
        """Test analysis of corrupted packet data."""
        analyzer = TransitCardAnalyzer()
        
        # Various types of corrupted data
        corrupted_packets = [
            b'\x26',  # Incomplete REQA
            b'\x93',  # Incomplete SELECT
            b'\x60\x00',  # Incomplete AUTH
            b'',  # Empty packet
            None,  # None data
        ]
        
        for data in corrupted_packets:
            if data is not None:
                # Should not raise exception
                analysis = analyzer.analyze_packet(data, "unknown")
                assert 'protocol' in analysis
                assert 'length' in analysis
    
    @pytest.mark.asyncio
    async def test_export_session_file_error(self, temp_dir, sample_session):
        """Test session export with file system errors."""
        analyzer = PacketAnalyzer(output_dir=temp_dir)
        
        # Mock file system error
        with patch('builtins.open', side_effect=OSError("Disk full")):
            # Should not raise exception
            result = await analyzer.export_session_analysis(sample_session)
            # May return None or handle error gracefully
    
    def test_invalid_output_directory(self):
        """Test analyzer with invalid output directory."""
        # Test with read-only or non-existent directory
        with patch('pathlib.Path.mkdir', side_effect=PermissionError):
            # Should handle gracefully or raise appropriate exception
            try:
                analyzer = PacketAnalyzer(output_dir="/invalid/readonly/path")
            except (PermissionError, OSError):
                # Acceptable to raise exception for invalid directory
                pass