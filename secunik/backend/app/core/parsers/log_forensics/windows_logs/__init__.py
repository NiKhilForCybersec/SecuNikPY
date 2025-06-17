"""
SecuNik - Windows Logs Package
Windows event log analysis and forensics

Location: backend/app/core/parsers/log_forensics/windows_logs/__init__.py
"""

from .evtx_parser import create_parser as create_evtx_parser, EVTXParser

__all__ = [
    'create_evtx_parser',
    'EVTXParser'
]