# utils/__init__.py
"""
SecuNik Utility Functions
Common utilities and helper functions
"""

# utils/file_utils.py
"""
File manipulation and validation utilities
"""

import os
import hashlib
import magic
from pathlib import Path
from typing import Dict, Any, List, Optional
import mimetypes
import logging
from fastapi import UploadFile

logger = logging.getLogger(__name__)

# Supported file extensions
SUPPORTED_EXTENSIONS = {
    # Documents
    '.pdf', '.doc', '.docx', '.txt', '.rtf', '.odt',
    # Archives
    '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2',
    # Logs
    '.log', '.evtx', '.json', '.csv', '.xml', '.yaml', '.yml',
    # Network
    '.pcap', '.pcapng', '.cap',
    # Memory/Disk
    '.mem', '.dmp', '.raw', '.img', '.dd', '.e01',
    # Email
    '.pst', '.ost', '.eml', '.msg', '.mbox',
    # Executables
    '.exe', '.dll', '.sys', '.bin', '.com', '.scr',
    # Registry
    '.reg', '.hiv', '.dat',
    # Mobile
    '.ab', '.tar',
    # Images (for metadata analysis)
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff',
    # Scripts
    '.ps1', '.bat', '.cmd', '.sh', '.py', '.js'
}

# MIME type mappings
MIME_TYPE_MAP = {
    'application/pdf': 'PDF Document',
    'application/msword': 'Word Document',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'Word Document',
    'text/plain': 'Text File',
    'text/csv': 'CSV File',
    'application/json': 'JSON File',
    'application/xml': 'XML File',
    'text/xml': 'XML File',
    'application/zip': 'ZIP Archive',
    'application/x-rar-compressed': 'RAR Archive',
    'application/x-7z-compressed': '7-Zip Archive',
    'application/x-tar': 'TAR Archive',
    'application/gzip': 'GZIP Archive',
    'application/x-dosexec': 'Windows Executable',
    'application/x-executable': 'Executable',
    'application/octet-stream': 'Binary File',
    'application/vnd.tcpdump.pcap': 'Network Capture',
    'application/vnd.ms-outlook': 'Outlook Data File',
    'message/rfc822': 'Email Message',
    'application/x-raw-disk-image': 'Disk Image',
    'image/jpeg': 'JPEG Image',
    'image/png': 'PNG Image',
    'image/gif': 'GIF Image',
    'image/bmp': 'BMP Image',
    'image/tiff': 'TIFF Image'
}

def get_file_extension(filename: str) -> str:
    """Get file extension in lowercase"""
    return Path(filename).suffix.lower()

def validate_file_type(file_type: str) -> bool:
    """Validate if file type is supported"""
    # Always allow common forensic file types
    forensic_types = [
        'application/pdf',
        'text/plain',
        'application/json',
        'text/csv',
        'application/zip',
        'application/x-dosexec',
        'application/octet-stream',
        'application/vnd.tcpdump.pcap',
        'application/vnd.ms-outlook',
        'message/rfc822'
    ]
    
    return file_type in forensic_types

def validate_filename(filename: str) -> bool:
    """Validate filename for security"""
    if not filename:
        return False
    
    # Check for dangerous characters
    dangerous_chars = ['..', '/', '\\', ':', '*', '?', '"', '<', '>', '|']
    for char in dangerous_chars:
        if char in filename:
            return False
    
    # Check file extension
    extension = get_file_extension(filename)
    return extension in SUPPORTED_EXTENSIONS

async def get_file_info(file: UploadFile) -> Dict[str, Any]:
    """Get comprehensive file information"""
    try:
        # Read file content
        content = await file.read()
        await file.seek(0)  # Reset file pointer
        
        # Basic info
        file_info = {
            'filename': file.filename,
            'size': len(content),
            'content_type': file.content_type or 'application/octet-stream'
        }
        
        # Try to detect MIME type
        try:
            magic_instance = magic.Magic(mime=True)
            detected_type = magic_instance.from_buffer(content)
            file_info['type'] = detected_type
        except Exception as e:
            logger.warning(f"Failed to detect MIME type: {e}")
            # Fallback to extension-based detection
            extension = get_file_extension(file.filename)
            file_info['type'] = _get_type_from_extension(extension)
        
        # Calculate hash
        file_info['md5'] = hashlib.md5(content).hexdigest()
        file_info['sha256'] = hashlib.sha256(content).hexdigest()
        
        # Human-readable type
        file_info['type_description'] = MIME_TYPE_MAP.get(
            file_info['type'], 
            'Unknown File Type'
        )
        
        return file_info
        
    except Exception as e:
        logger.error(f"Error getting file info: {e}")
        return {
            'filename': file.filename,
            'size': 0,
            'type': 'application/octet-stream',
            'error': str(e)
        }

def _get_type_from_extension(extension: str) -> str:
    """Get MIME type from file extension"""
    extension_map = {
        '.pdf': 'application/pdf',
        '.txt': 'text/plain',
        '.json': 'application/json',
        '.csv': 'text/csv',
        '.xml': 'application/xml',
        '.zip': 'application/zip',
        '.rar': 'application/x-rar-compressed',
        '.7z': 'application/x-7z-compressed',
        '.tar': 'application/x-tar',
        '.gz': 'application/gzip',
        '.exe': 'application/x-dosexec',
        '.dll': 'application/x-dosexec',
        '.log': 'text/plain',
        '.pcap': 'application/vnd.tcpdump.pcap',
        '.pcapng': 'application/vnd.tcpdump.pcap',
        '.evtx': 'application/octet-stream',
        '.pst': 'application/vnd.ms-outlook',
        '.ost': 'application/vnd.ms-outlook',
        '.eml': 'message/rfc822',
        '.msg': 'application/vnd.ms-outlook',
        '.mem': 'application/octet-stream',
        '.dmp': 'application/octet-stream',
        '.raw': 'application/x-raw-disk-image',
        '.img': 'application/x-raw-disk-image',
        '.dd': 'application/x-raw-disk-image',
        '.jpg': 'image/jpeg',
        '.jpeg': 'image/jpeg',
        '.png': 'image/png',
        '.gif': 'image/gif',
        '.bmp': 'image/bmp',
        '.tiff': 'image/tiff'
    }
    
    return extension_map.get(extension, 'application/octet-stream')

def format_file_size(size_bytes: int) -> str:
    """Format file size in human-readable format"""
    if size_bytes == 0:
        return "0 B"
    
    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    size = float(size_bytes)
    
    while size >= 1024.0 and i < len(size_names) - 1:
        size /= 1024.0
        i += 1
    
    return f"{size:.2f} {size_names[i]}"

def sanitize_filename(filename: str) -> str:
    """Sanitize filename for safe storage"""
    if not filename:
        return "unknown_file"
    
    # Remove dangerous characters
    safe_chars = []
    for char in filename:
        if char.isalnum() or char in '-_.':
            safe_chars.append(char)
        else:
            safe_chars.append('_')
    
    safe_filename = ''.join(safe_chars)
    
    # Limit length
    if len(safe_filename) > 100:
        name, ext = os.path.splitext(safe_filename)
        safe_filename = name[:90] + ext
    
    return safe_filename

def is_archive_file(filename: str) -> bool:
    """Check if file is an archive"""
    archive_extensions = {'.zip', '.rar', '.7z', '.tar', '.gz', '.bz2'}
    return get_file_extension(filename) in archive_extensions

def is_executable_file(filename: str) -> bool:
    """Check if file is an executable"""
    executable_extensions = {'.exe', '.dll', '.sys', '.bin', '.com', '.scr'}
    return get_file_extension(filename) in executable_extensions

def is_log_file(filename: str) -> bool:
    """Check if file is a log file"""
    log_extensions = {'.log', '.evtx', '.json', '.csv', '.xml'}
    return get_file_extension(filename) in log_extensions

def is_network_capture(filename: str) -> bool:
    """Check if file is a network capture"""
    network_extensions = {'.pcap', '.pcapng', '.cap'}
    return get_file_extension(filename) in network_extensions

def is_memory_dump(filename: str) -> bool:
    """Check if file is a memory dump"""
    memory_extensions = {'.mem', '.dmp', '.raw'}
    return get_file_extension(filename) in memory_extensions

def is_disk_image(filename: str) -> bool:
    """Check if file is a disk image"""
    disk_extensions = {'.img', '.dd', '.e01', '.raw'}
    return get_file_extension(filename) in disk_extensions

def is_email_file(filename: str) -> bool:
    """Check if file is an email file"""
    email_extensions = {'.pst', '.ost', '.eml', '.msg', '.mbox'}
    return get_file_extension(filename) in email_extensions

def get_file_category(filename: str) -> str:
    """Get file category for analysis routing"""
    extension = get_file_extension(filename)
    
    if is_archive_file(filename):
        return "archive"
    elif is_executable_file(filename):
        return "executable"
    elif is_log_file(filename):
        return "log"
    elif is_network_capture(filename):
        return "network"
    elif is_memory_dump(filename):
        return "memory"
    elif is_disk_image(filename):
        return "disk"
    elif is_email_file(filename):
        return "email"
    elif extension in {'.pdf', '.doc', '.docx'}:
        return "document"
    elif extension in {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff'}:
        return "image"
    else:
        return "unknown"

# utils/validation.py
"""
Input validation utilities
"""

import re
from typing import Optional, List

def validate_case_id(case_id: str) -> bool:
    """Validate case ID format"""
    if not case_id:
        return False
    
    # Allow alphanumeric, underscores, hyphens
    pattern = r'^[a-zA-Z0-9_-]+$'
    return bool(re.match(pattern, case_id)) and len(case_id) <= 50

def validate_file_id(file_id: str) -> bool:
    """Validate file ID format (UUID-like)"""
    if not file_id:
        return False
    
    # UUID pattern
    pattern = r'^[a-fA-F0-9-]+$'
    return bool(re.match(pattern, file_id)) and len(file_id) <= 50

def sanitize_input(text: str, max_length: int = 1000) -> str:
    """Sanitize text input"""
    if not text:
        return ""
    
    # Remove potentially dangerous characters
    safe_text = re.sub(r'[<>"\']', '', text)
    
    # Limit length
    return safe_text[:max_length]

def validate_email(email: str) -> bool:
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def validate_ip_address(ip: str) -> bool:
    """Validate IP address format"""
    ipv4_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    return bool(re.match(ipv4_pattern, ip))

def validate_domain(domain: str) -> bool:
    """Validate domain name format"""
    pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))

def validate_hash(hash_value: str, hash_type: str = "sha256") -> bool:
    """Validate hash format"""
    patterns = {
        "md5": r'^[a-fA-F0-9]{32}$',
        "sha1": r'^[a-fA-F0-9]{40}$',
        "sha256": r'^[a-fA-F0-9]{64}$'
    }
    
    pattern = patterns.get(hash_type.lower())
    if not pattern:
        return False
    
    return bool(re.match(pattern, hash_value))

# utils/constants.py
"""
Application constants
"""

# API Response Messages
API_MESSAGES = {
    "FILE_UPLOADED": "File uploaded successfully",
    "FILE_NOT_FOUND": "File not found",
    "ANALYSIS_STARTED": "Analysis started",
    "ANALYSIS_COMPLETED": "Analysis completed",
    "ANALYSIS_FAILED": "Analysis failed",
    "CASE_CREATED": "Case created successfully",
    "CASE_NOT_FOUND": "Case not found",
    "INVALID_FILE_TYPE": "Invalid file type",
    "FILE_TOO_LARGE": "File too large",
    "UPLOAD_FAILED": "Upload failed"
}

# File size limits
FILE_SIZE_LIMITS = {
    "small": 10 * 1024 * 1024,    # 10MB
    "medium": 100 * 1024 * 1024,  # 100MB
    "large": 1024 * 1024 * 1024,  # 1GB
    "max": 5 * 1024 * 1024 * 1024  # 5GB
}

# Analysis timeouts (in seconds)
ANALYSIS_TIMEOUTS = {
    "quick": 30,
    "standard": 300,    # 5 minutes
    "deep": 1800,       # 30 minutes
    "comprehensive": 3600  # 1 hour
}

# Risk score thresholds
RISK_THRESHOLDS = {
    "low": 0.3,
    "medium": 0.6,
    "high": 0.8,
    "critical": 0.95
}

# Default configuration values
DEFAULT_CONFIG = {
    "max_file_size": 100 * 1024 * 1024,  # 100MB
    "upload_timeout": 300,  # 5 minutes
    "analysis_timeout": 1800,  # 30 minutes
    "max_concurrent_uploads": 5,
    "max_concurrent_analyses": 3,
    "cache_ttl": 3600,  # 1 hour
    "enable_ai_analysis": True,
    "enable_file_scanning": True,
    "log_level": "INFO"
}