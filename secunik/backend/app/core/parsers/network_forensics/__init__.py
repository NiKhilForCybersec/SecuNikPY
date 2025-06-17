"""
SecuNik - Network Forensics Package
Network packet analysis and traffic forensics

Location: backend/app/core/parsers/network_forensics/__init__.py
"""

from .pcap_parser import create_parser as create_pcap_parser, PCAPParser

__all__ = [
    'create_pcap_parser',
    'PCAPParser'
]