"""
SecuNik - Email Forensics Package
Email analysis and forensics (PST, EML, MSG)

Location: backend/app/core/parsers/email_forensics/__init__.py
"""

from .pst_parser import create_parser as create_email_parser, EmailForensicsParser

__all__ = [
    'create_email_parser',
    'EmailForensicsParser'
]