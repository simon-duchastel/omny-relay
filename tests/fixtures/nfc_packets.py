"""
Real-world NFC packet samples for testing (anonymized).
Contains protocol examples from various transit card systems.
"""

import struct
from typing import Dict, List


class NFCPacketSamples:
    """Collection of real NFC packet samples for testing."""
    
    # ISO 14443 Type A packets
    ISO14443_PACKETS = {
        'reqa': b'\x26',
        'reqa_response': b'\x44\x00',  # ATQA response
        'wupa': b'\x52',
        'wupa_response': b'\x44\x00',
        'select_cl1': b'\x93\x20',
        'select_cl1_response': b'\x88\x04\x12\x34\x9A',  # Partial UID
        'select_cl2': b'\x95\x20',
        'select_cl2_response': b'\x56\x78\x9A\xBC\xDE',  # Full UID
        'select_complete': b'\x95\x70\x56\x78\x9A\xBC\xDE\xF0\x12',
        'halt': b'\x50\x00\x57\xCD',
    }
    
    # MIFARE Classic packets
    MIFARE_PACKETS = {
        'auth_a_block_0': b'\x60\x00\xFF\xFF\xFF\xFF\xFF\xFF',
        'auth_b_block_0': b'\x61\x00\xFF\xFF\xFF\xFF\xFF\xFF',
        'auth_success': b'\xA0',
        'read_block_0': b'\x30\x00',
        'read_block_4': b'\x30\x04',
        'read_block_8': b'\x30\x08',
        'write_block_4': b'\xA0\x04',
        'write_data': b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F',
        'write_success': b'\x0A',
        'sector_trailer': b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x07\x80\x69\xFF\xFF\xFF\xFF\xFF\xFF',
    }
    
    # Transit-specific data blocks
    TRANSIT_DATA = {
        'oyster_balance': {
            'raw': b'\x04\x12\x34\x56\x78\x9A\xBC\xDE\x00\x00\x15\x50\x12\x34\x56\x78',
            'card_id': '04123456',
            'balance': 15.50,  # £15.50
            'system': 'oyster',
            'currency': 'GBP'
        },
        'clipper_balance': {
            'raw': b'\x04\x98\x76\x54\x32\x10\xAB\xCD\x00\x00\x25\x75\x87\x65\x43\x21',
            'card_id': '04987654',
            'balance': 25.75,  # $25.75
            'system': 'clipper',
            'currency': 'USD'
        },
        'omny_balance': {
            'raw': b'\x04\x56\x78\x90\xAB\xCD\xEF\x12\x00\x00\x08\x25\xFE\xDC\xBA\x98',
            'card_id': '04567890',
            'balance': 8.25,  # $8.25
            'system': 'omny',
            'currency': 'USD'
        },
        'opal_balance': {
            'raw': b'\x08\x11\x22\x33\x44\x55\x66\x77\x00\x00\x12\x30\x88\x99\xAA\xBB',
            'card_id': '08112233',
            'balance': 12.30,  # $12.30 AUD
            'system': 'opal',
            'currency': 'AUD'
        },
    }
    
    # Transaction records
    TRANSACTION_SAMPLES = {
        'oyster_tap_in': {
            'raw': b'\xA0\x04\x12\x34\x56\x78\x9A\xBC\xDE\xF0\x11\x22\x33\x44\x55\x66',
            'type': 'tap_in',
            'amount': -2.90,
            'balance_before': 18.40,
            'balance_after': 15.50,
            'location': 'Kings Cross',
            'timestamp': 1640995200
        },
        'clipper_transfer': {
            'raw': b'\xA0\x08\x98\x76\x54\x32\x10\xAB\xCD\xEF\x12\x34\x56\x78\x9A\xBC',
            'type': 'transfer',
            'amount': 0.00,
            'balance_before': 25.75,
            'balance_after': 25.75,
            'location': 'Montgomery BART',
            'timestamp': 1640995800
        },
        'omny_fare': {
            'raw': b'\xA0\x0C\x56\x78\x90\xAB\xCD\xEF\x12\x34\x56\x78\x9A\xBC\xDE\xF0',
            'type': 'fare_payment',
            'amount': -2.75,
            'balance_before': 11.00,
            'balance_after': 8.25,
            'location': 'Union Sq - 14 St',
            'timestamp': 1640996400
        },
    }
    
    # Security test vectors
    SECURITY_VECTORS = {
        'replay_attacks': [
            b'\x60\x00\xFF\xFF\xFF\xFF\xFF\xFF',  # Repeated auth
            b'\x30\x04',  # Repeated read
            b'\xA0\x04\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F',  # Repeated write
        ],
        'injection_attempts': [
            b'\x00' * 1000,  # Null overflow
            b'\xFF' * 1000,  # Byte overflow
            b'\x30' + b'\xFF' * 100,  # Command overflow
            b'\x60\x00' + b'\x00' * 100,  # Auth overflow
        ],
        'malformed_packets': [
            b'',  # Empty
            b'\x26\x00\x00',  # Extra bytes
            b'\x30',  # Incomplete read
            b'\x60',  # Incomplete auth
            b'\xFF\xFF\xFF\xFF',  # Invalid command
        ],
    }
    
    # Performance test data
    PERFORMANCE_DATA = {
        'small_packets': [b'\x26\x00'] * 1000,
        'medium_packets': [b'\x30\x04' + b'\x00' * 16] * 1000,
        'large_packets': [b'\xA0\x04' + b'\x55' * 256] * 100,
        'mixed_packets': [
            b'\x26\x00',
            b'\x30\x04' + b'\x00' * 16,
            b'\x60\x00\xFF\xFF\xFF\xFF\xFF\xFF',
            b'\xA0\x04' + b'\x55' * 16,
        ] * 250,
    }
    
    @classmethod
    def get_protocol_sequence(cls, protocol: str) -> List[bytes]:
        """Get typical protocol communication sequence."""
        sequences = {
            'iso14443_basic': [
                cls.ISO14443_PACKETS['reqa'],
                cls.ISO14443_PACKETS['reqa_response'],
                cls.ISO14443_PACKETS['select_cl1'],
                cls.ISO14443_PACKETS['select_cl1_response'],
                cls.ISO14443_PACKETS['halt'],
            ],
            'mifare_read': [
                cls.ISO14443_PACKETS['reqa'],
                cls.ISO14443_PACKETS['reqa_response'],
                cls.ISO14443_PACKETS['select_cl1'],
                cls.ISO14443_PACKETS['select_cl1_response'],
                cls.MIFARE_PACKETS['auth_a_block_0'],
                cls.MIFARE_PACKETS['auth_success'],
                cls.MIFARE_PACKETS['read_block_4'],
                cls.TRANSIT_DATA['oyster_balance']['raw'][:16],
                cls.ISO14443_PACKETS['halt'],
            ],
            'mifare_write': [
                cls.ISO14443_PACKETS['reqa'],
                cls.ISO14443_PACKETS['reqa_response'],
                cls.ISO14443_PACKETS['select_cl1'],
                cls.ISO14443_PACKETS['select_cl1_response'],
                cls.MIFARE_PACKETS['auth_a_block_0'],
                cls.MIFARE_PACKETS['auth_success'],
                cls.MIFARE_PACKETS['write_block_4'],
                cls.MIFARE_PACKETS['write_data'],
                cls.MIFARE_PACKETS['write_success'],
                cls.ISO14443_PACKETS['halt'],
            ],
        }
        return sequences.get(protocol, [])
    
    @classmethod
    def create_balance_data(cls, system: str, balance: float) -> bytes:
        """Create balance data for specific transit system."""
        templates = {
            'oyster': b'\x04\x12\x34\x56\x78\x9A\xBC\xDE\x00\x00{}\x12\x34\x56\x78',
            'clipper': b'\x04\x98\x76\x54\x32\x10\xAB\xCD\x00\x00{}\x87\x65\x43\x21',
            'omny': b'\x04\x56\x78\x90\xAB\xCD\xEF\x12\x00\x00{}\xFE\xDC\xBA\x98',
            'opal': b'\x08\x11\x22\x33\x44\x55\x66\x77\x00\x00{}\x88\x99\xAA\xBB',
        }
        
        if system not in templates:
            raise ValueError(f"Unknown transit system: {system}")
        
        # Convert balance to cents/pence
        balance_cents = int(balance * 100)
        balance_bytes = struct.pack('<H', balance_cents)
        
        return templates[system].format(balance_bytes)
    
    @classmethod
    def get_vulnerability_samples(cls) -> Dict[str, List[bytes]]:
        """Get samples for security vulnerability testing."""
        return {
            'buffer_overflow': [
                b'\x30' + b'\x00' * 1000,  # Read with overflow
                b'\x60' + b'\xFF' * 1000,  # Auth with overflow
                b'\xA0\x04' + b'\x55' * 1000,  # Write with overflow
            ],
            'format_string': [
                b'\x30\x04%n%n%n%n',
                b'\x60\x00%x%x%x%x',
                b'\xA0\x04%s%s%s%s' + b'\x00' * 12,
            ],
            'injection': [
                b'\x30\x04; rm -rf /',
                b'\x60\x00\x27\x27; DROP TABLE;',
                b'\xA0\x04<script>alert(1)</script>' + b'\x00' * 4,
            ],
            'timing': [
                b'\x30\x04',  # Normal timing
                b'\x30\x04' + b'\x00' * 100,  # Slow processing
                b'\x30\x04' + b'\xFF' * 100,  # CPU intensive
            ],
        }


# Export commonly used packets as module constants
REQA = NFCPacketSamples.ISO14443_PACKETS['reqa']
WUPA = NFCPacketSamples.ISO14443_PACKETS['wupa']
READ_BLOCK_4 = NFCPacketSamples.MIFARE_PACKETS['read_block_4']
AUTH_A = NFCPacketSamples.MIFARE_PACKETS['auth_a_block_0']
OYSTER_BALANCE = NFCPacketSamples.TRANSIT_DATA['oyster_balance']['raw']
CLIPPER_BALANCE = NFCPacketSamples.TRANSIT_DATA['clipper_balance']['raw']