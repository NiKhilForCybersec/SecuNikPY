"""
SecuNik - Log Forensics Package
Advanced log analysis and forensics

Location: backend/app/core/parsers/log_forensics/__init__.py
"""

from .windows_logs.evtx_parser import create_parser as create_evtx_parser

__all__ = [
    'create_evtx_parser'
]

# Version information
__version__ = "1.0.0"
__author__ = "SecuNik Team"
__description__ = "Advanced log forensics and analysis parsers"