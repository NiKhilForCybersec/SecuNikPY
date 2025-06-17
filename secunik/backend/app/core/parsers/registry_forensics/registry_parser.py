"""
SecuNik - Email Forensics Parser (PST/EML) - Pure Data Extractor
Extracts raw email data for AI analysis

Location: backend/app/core/parsers/email_forensics/pst_parser.py
"""

import json
import email
import logging
import re
from datetime import datetime
from typing import Dict, List, Optional, Any, Set
from pathlib import Path
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import base64
import quopri

try:
    import libpst
    PST_AVAILABLE = True
except ImportError:
    PST_AVAILABLE = False

try:
    import eml_parser
    EML_PARSER_AVAILABLE = True
except ImportError:
    EML_PARSER_AVAILABLE = False

from ...models.analysis import AnalysisResult, Severity, IOC, IOCType

logger = logging.getLogger(__name__)

class EmailForensicsParser:
    """Pure Data Extractor for Email Forensics - AI analyzes the data"""
    
    def __init__(self):
        self.name = "Email Forensics Parser"
        self.version = "2.0.0"
        self.supported_formats = [".pst", ".ost", ".eml", ".msg"]
        
        # Regular expressions for data extraction (not threat assessment)
        self.regex_patterns = {
            "email": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            "ip": re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
            "url": re.compile(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'),
            "phone": re.compile(r'(\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}'),
            "credit_card": re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b'),
            "ssn": re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
            "bitcoin": re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b')
        }
        
        # Security headers to analyze
        self.security_headers = [
            "Authentication-Results",
            "Received-SPF", 
            "DKIM-Signature",
            "ARC-Authentication-Results",
            "X-Spam-Status",
            "X-Spam-Score",
            "X-Virus-Scan-Result"
        ]

    def can_parse(self, file_path: str) -> bool:
        """Check if file can be parsed by this parser"""
        extension = Path(file_path).suffix.lower()
        if extension == ".pst" or extension == ".ost":
            return PST_AVAILABLE
        elif extension == ".eml":
            return True
        return extension in self.supported_formats

    def parse(self, file_path: str) -> AnalysisResult:
        """Extract raw email data - AI will analyze for threats"""
        try:
            extension = Path(file_path).suffix.lower()
            
            logger.info(f"Extracting email data: {file_path}")
            
            if extension in [".pst", ".ost"]:
                emails = self._parse_pst_file(file_path)
            elif extension == ".eml":
                emails = self._parse_eml_file(file_path)
            else:
                return self._create_error_result(f"Unsupported email format: {extension}")
            
            # Extract structured email data
            email_data = self._extract_email_data(emails)
            
            # Extract factual IOCs
            iocs = self._extract_factual_iocs(email_data, emails)
            
            # Create analysis result with extracted data
            result = AnalysisResult(
                file_path=file_path,
                parser_name=self.name,
                analysis_type="Email Data Extraction",
                timestamp=datetime.now(),
                summary=f"Extracted data from {len(emails)} emails for AI analysis",
                details=email_data,
                threats_detected=[],  # AI will determine threats
                iocs_found=iocs,
                severity=Severity.LOW,  # AI will determine severity
                risk_score=0.0,  # AI will calculate risk score
                recommendations=["Data extracted - pending AI analysis for threat assessment and recommendations"]
            )
            
            logger.info(f"Email data extraction completed: {len(emails)} emails processed")
            return result
            
        except Exception as e:
            logger.error(f"Error extracting email data {file_path}: {str(e)}")
            return self._create_error_result(str(e))

    def _parse_pst_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Parse PST/OST file"""
        emails = []
        
        if not PST_AVAILABLE:
            logger.warning("libpst not available, cannot parse PST files")
            return emails
        
        try:
            # This is a simplified version - actual PST parsing would require
            # more complex implementation with libpst
            logger.warning("PST parsing requires libpst library - using placeholder")
            return emails
        except Exception as e:
            logger.error(f"Error parsing PST file: {e}")
            return emails

    def _parse_eml_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Parse EML file"""
        emails = []
        
        try:
            with open(file_path, 'rb') as f:
                raw_email = f.read()
            
            # Parse with email library
            msg = email.message_from_bytes(raw_email)
            email_data = self._extract_email_message_data(msg, file_path)
            emails.append(email_data)
            
            # Also try eml_parser if available
            if EML_PARSER_AVAILABLE:
                try:
                    ep = eml_parser.EmlParser()
                    parsed = ep.decode_email_bytes(raw_email)
                    if parsed:
                        email_data["eml_parser_data"] = parsed
                except Exception as e:
                    logger.warning(f"eml_parser failed: {e}")
            
        except Exception as e:
            logger.error(f"Error parsing EML file: {e}")
        
        return emails

    def _extract_email_message_data(self, msg, file_path: str) -> Dict[str, Any]:
        """Extract comprehensive data from email message"""
        email_data = {
            "file_path": file_path,
            "message_id": msg.get("Message-ID", ""),
            "subject": msg.get("Subject", ""),
            "from": msg.get("From", ""),
            "to": msg.get("To", ""),
            "cc": msg.get("Cc", ""),
            "bcc": msg.get("Bcc", ""),
            "date": msg.get("Date", ""),
            "received": [],
            "headers": dict(msg.items()),
            "body_text": "",
            "body_html": "",
            "attachments": [],
            "urls": [],
            "security_headers": {},
            "routing_info": []
        }
        
        # Parse date
        try:
            if email_data["date"]:
                email_data["parsed_date"] = email.utils.parsedate_to_datetime(email_data["date"])
        except Exception:
            email_data["parsed_date"] = None
        
        # Extract Received headers for routing analysis
        received_headers = msg.get_all("Received", [])
        email_data["received"] = received_headers
        email_data["routing_info"] = self._parse_routing_info(received_headers)
        
        # Extract security headers
        for header in self.security_headers:
            value = msg.get(header)
            if value:
                email_data["security_headers"][header] = value
        
        # Extract body content
        if msg.is_multipart():
            for part in msg.walk():
                self._process_email_part(part, email_data)
        else:
            self._process_email_part(msg, email_data)
        
        # Extract URLs from all text content
        all_text = email_data["body_text"] + " " + email_data["body_html"]
        email_data["urls"] = self._extract_urls(all_text)
        
        # Extract additional patterns
        email_data["extracted_patterns"] = self._extract_all_patterns(all_text)
        
        return email_data

    def _process_email_part(self, part, email_data: Dict[str, Any]):
        """Process individual email part (body, attachment, etc.)"""
        content_type = part.get_content_type()
        content_disposition = part.get("Content-Disposition", "")
        
        if "attachment" in content_disposition or "inline" in content_disposition:
            # Handle attachment
            filename = part.get_filename()
            if filename:
                attachment_data = {
                    "filename": filename,
                    "content_type": content_type,
                    "size": len(part.get_payload(decode=True) or b""),
                    "content_disposition": content_disposition
                }
                
                # Extract attachment content for analysis (limited size)
                try:
                    payload = part.get_payload(decode=True)
                    if payload and len(payload) < 1024 * 1024:  # Limit to 1MB
                        attachment_data["content_preview"] = payload[:1000]  # First 1000 bytes
                        attachment_data["file_hash"] = self._calculate_hash(payload)
                except Exception as e:
                    logger.warning(f"Error extracting attachment content: {e}")
                
                email_data["attachments"].append(attachment_data)
        
        elif content_type == "text/plain":
            # Plain text body
            try:
                payload = part.get_payload(decode=True)
                if payload:
                    email_data["body_text"] += payload.decode('utf-8', errors='ignore')
            except Exception as e:
                logger.warning(f"Error decoding text part: {e}")
        
        elif content_type == "text/html":
            # HTML body
            try:
                payload = part.get_payload(decode=True)
                if payload:
                    email_data["body_html"] += payload.decode('utf-8', errors='ignore')
            except Exception as e:
                logger.warning(f"Error decoding HTML part: {e}")

    def _parse_routing_info(self, received_headers: List[str]) -> List[Dict[str, Any]]:
        """Parse email routing information from Received headers"""
        routing_info = []
        
        for header in received_headers:
            route_data = {
                "raw_header": header,
                "servers": [],
                "ips": [],
                "timestamp": None
            }
            
            # Extract IP addresses
            ips = self.regex_patterns["ip"].findall(header)
            route_data["ips"] = ips
            
            # Extract server names
            if "from" in header.lower():
                try:
                    parts = header.split("from")[1].split("by")[0]
                    route_data["servers"].append(parts.strip())
                except Exception:
                    pass
            
            # Extract timestamp
            if ";" in header:
                timestamp_part = header.split(";")[-1].strip()
                try:
                    route_data["timestamp"] = email.utils.parsedate_to_datetime(timestamp_part)
                except Exception:
                    pass
            
            routing_info.append(route_data)
        
        return routing_info

    def _extract_urls(self, text: str) -> List[Dict[str, Any]]:
        """Extract URLs from text"""
        urls = []
        
        for match in self.regex_patterns["url"].finditer(text):
            url = match.group()
            url_data = {
                "url": url,
                "domain": self._extract_domain(url)
            }
            urls.append(url_data)
        
        return urls

    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            return parsed.netloc
        except Exception:
            return ""

    def _extract_all_patterns(self, text: str) -> Dict[str, List[str]]:
        """Extract all patterns from text content"""
        patterns = {}
        
        for pattern_name, regex in self.regex_patterns.items():
            matches = regex.findall(text)
            if matches:
                patterns[pattern_name] = matches[:20]  # Limit matches
        
        return patterns

    def _calculate_hash(self, data: bytes) -> str:
        """Calculate SHA-256 hash of data"""
        import hashlib
        return hashlib.sha256(data).hexdigest()

    def _extract_email_data(self, emails: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Extract structured data from all emails"""
        email_data = {
            "total_emails": len(emails),
            "email_summary": self._build_email_summary(emails),
            "sender_analysis": self._analyze_senders(emails),
            "recipient_analysis": self._analyze_recipients(emails),
            "attachment_analysis": self._analyze_attachments(emails),
            "content_analysis": self._analyze_content(emails),
            "header_analysis": self._analyze_headers(emails),
            "timeline": self._build_email_timeline(emails),
            "communication_patterns": self._analyze_communication_patterns(emails),
            "metadata_analysis": self._analyze_metadata(emails)
        }
        
        return email_data

    def _build_email_summary(self, emails: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Build summary statistics"""
        if not emails:
            return {}
        
        summary = {
            "total_emails": len(emails),
            "date_range": self._get_date_range(emails),
            "emails_with_attachments": len([e for e in emails if e.get("attachments")]),
            "total_attachments": sum(len(e.get("attachments", [])) for e in emails),
            "emails_with_urls": len([e for e in emails if e.get("urls")]),
            "total_urls": sum(len(e.get("urls", [])) for e in emails),
            "unique_senders": len(set(e.get("from", "") for e in emails if e.get("from"))),
            "unique_subjects": len(set(e.get("subject", "") for e in emails if e.get("subject")))
        }
        
        return summary

    def _get_date_range(self, emails: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Get date range of emails"""
        dates = []
        for email_data in emails:
            parsed_date = email_data.get("parsed_date")
            if parsed_date:
                dates.append(parsed_date)
        
        if dates:
            return {
                "earliest": min(dates).isoformat(),
                "latest": max(dates).isoformat(),
                "span_days": (max(dates) - min(dates)).days
            }
        return {}

    def _analyze_senders(self, emails: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze email senders"""
        sender_stats = {
            "unique_senders": set(),
            "sender_frequency": {},
            "sender_domains": set(),
            "external_senders": []
        }
        
        for email_data in emails:
            sender = email_data.get("from", "")
            if sender:
                sender_stats["unique_senders"].add(sender)
                sender_stats["sender_frequency"][sender] = sender_stats["sender_frequency"].get(sender, 0) + 1
                
                # Extract domain
                if "@" in sender:
                    domain = sender.split("@")[-1].split(">")[0]
                    sender_stats["sender_domains"].add(domain)
                    
                    # Check if external (simple heuristic)
                    if not any(internal in domain for internal in ["company.com", "organization.org"]):
                        sender_stats["external_senders"].append(sender)
        
        return {
            "total_unique_senders": len(sender_stats["unique_senders"]),
            "top_senders": dict(sorted(sender_stats["sender_frequency"].items(), 
                                     key=lambda x: x[1], reverse=True)[:10]),
            "unique_domains": len(sender_stats["sender_domains"]),
            "sender_domains": list(sender_stats["sender_domains"]),
            "external_senders": sender_stats["external_senders"][:20]
        }

    def _analyze_recipients(self, emails: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze email recipients"""
        recipient_stats = {
            "to_recipients": [],
            "cc_recipients": [],
            "bcc_recipients": [],
            "bulk_emails": []
        }
        
        for email_data in emails:
            to_recipients = email_data.get("to", "")
            cc_recipients = email_data.get("cc", "")
            bcc_recipients = email_data.get("bcc", "")
            
            # Count recipients
            to_count = len([r for r in to_recipients.split(",") if r.strip()]) if to_recipients else 0
            cc_count = len([r for r in cc_recipients.split(",") if r.strip()]) if cc_recipients else 0
            
            total_recipients = to_count + cc_count
            
            if total_recipients > 10:  # Bulk email threshold
                recipient_stats["bulk_emails"].append({
                    "subject": email_data.get("subject", ""),
                    "from": email_data.get("from", ""),
                    "recipient_count": total_recipients
                })
            
            if bcc_recipients:
                recipient_stats["bcc_recipients"].append(email_data.get("subject", ""))
        
        return {
            "bulk_email_count": len(recipient_stats["bulk_emails"]),
            "emails_with_bcc": len(recipient_stats["bcc_recipients"]),
            "bulk_emails": recipient_stats["bulk_emails"][:10]
        }

    def _analyze_attachments(self, emails: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze email attachments"""
        attachment_stats = {
            "total_attachments": 0,
            "file_types": {},
            "attachment_sizes": [],
            "large_attachments": []
        }
        
        for email_data in emails:
            for attachment in email_data.get("attachments", []):
                attachment_stats["total_attachments"] += 1
                
                filename = attachment.get("filename", "")
                file_size = attachment.get("size", 0)
                
                # Track file types
                if "." in filename:
                    ext = filename.split(".")[-1].lower()
                    attachment_stats["file_types"][ext] = attachment_stats["file_types"].get(ext, 0) + 1
                
                attachment_stats["attachment_sizes"].append(file_size)
                
                # Track large attachments
                if file_size > 10 * 1024 * 1024:  # 10MB
                    attachment_stats["large_attachments"].append({
                        "filename": filename,
                        "size": file_size,
                        "email_subject": email_data.get("subject", "")
                    })
        
        return {
            "total_attachments": attachment_stats["total_attachments"],
            "file_type_distribution": attachment_stats["file_types"],
            "average_attachment_size": sum(attachment_stats["attachment_sizes"]) / len(attachment_stats["attachment_sizes"]) if attachment_stats["attachment_sizes"] else 0,
            "large_attachments": attachment_stats["large_attachments"]
        }

    def _analyze_content(self, emails: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze email content patterns"""
        content_stats = {
            "pattern_matches": {},
            "url_domains": set(),
            "content_languages": [],
            "message_lengths": []
        }
        
        for email_data in emails:
            all_content = email_data.get("body_text", "") + " " + email_data.get("body_html", "")
            content_stats["message_lengths"].append(len(all_content))
            
            # Extract patterns
            patterns = email_data.get("extracted_patterns", {})
            for pattern_type, matches in patterns.items():
                if pattern_type not in content_stats["pattern_matches"]:
                    content_stats["pattern_matches"][pattern_type] = 0
                content_stats["pattern_matches"][pattern_type] += len(matches)
            
            # Extract URL domains
            for url_data in email_data.get("urls", []):
                domain = url_data.get("domain", "")
                if domain:
                    content_stats["url_domains"].add(domain)
        
        return {
            "average_message_length": sum(content_stats["message_lengths"]) / len(content_stats["message_lengths"]) if content_stats["message_lengths"] else 0,
            "pattern_distribution": content_stats["pattern_matches"],
            "unique_url_domains": len(content_stats["url_domains"]),
            "url_domains": list(content_stats["url_domains"])[:50]
        }

    def _analyze_headers(self, emails: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze email headers"""
        header_stats = {
            "security_header_presence": {},
            "routing_analysis": {},
            "header_anomalies": []
        }
        
        for email_data in emails:
            security_headers = email_data.get("security_headers", {})
            
            # Track security header presence
            for header in self.security_headers:
                if header not in header_stats["security_header_presence"]:
                    header_stats["security_header_presence"][header] = 0
                if header in security_headers:
                    header_stats["security_header_presence"][header] += 1
            
            # Analyze routing
            routing_info = email_data.get("routing_info", [])
            hop_count = len(routing_info)
            
            if hop_count not in header_stats["routing_analysis"]:
                header_stats["routing_analysis"][hop_count] = 0
            header_stats["routing_analysis"][hop_count] += 1
            
            # Check for anomalies
            if hop_count > 10:
                header_stats["header_anomalies"].append({
                    "type": "Excessive routing hops",
                    "subject": email_data.get("subject", ""),
                    "hop_count": hop_count
                })
        
        return header_stats

    def _build_email_timeline(self, emails: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Build timeline of email events"""
        timeline = []
        
        for email_data in emails:
            parsed_date = email_data.get("parsed_date")
            if parsed_date:
                timeline.append({
                    "timestamp": parsed_date.isoformat(),
                    "subject": email_data.get("subject", ""),
                    "from": email_data.get("from", ""),
                    "to": email_data.get("to", ""),
                    "has_attachments": len(email_data.get("attachments", [])) > 0,
                    "attachment_count": len(email_data.get("attachments", [])),
                    "url_count": len(email_data.get("urls", []))
                })
        
        # Sort by timestamp
        timeline.sort(key=lambda x: x["timestamp"])
        
        return timeline[:100]  # Limit timeline size

    def _analyze_communication_patterns(self, emails: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze communication patterns"""
        patterns = {
            "hourly_distribution": {},
            "daily_distribution": {},
            "communication_frequency": {},
            "response_patterns": []
        }
        
        for email_data in emails:
            parsed_date = email_data.get("parsed_date")
            if parsed_date:
                hour = parsed_date.hour
                day = parsed_date.strftime("%A")
                
                patterns["hourly_distribution"][hour] = patterns["hourly_distribution"].get(hour, 0) + 1
                patterns["daily_distribution"][day] = patterns["daily_distribution"].get(day, 0) + 1
        
        return patterns

    def _analyze_metadata(self, emails: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze email metadata"""
        metadata = {
            "message_id_patterns": [],
            "client_analysis": {},
            "encoding_analysis": {},
            "format_analysis": {}
        }
        
        for email_data in emails:
            message_id = email_data.get("message_id", "")
            if message_id and "@" in message_id:
                domain = message_id.split("@")[-1].rstrip(">")
                metadata["message_id_patterns"].append(domain)
        
        return metadata

    def _extract_factual_iocs(self, email_data: Dict[str, Any], emails: List[Dict[str, Any]]) -> List[IOC]:
        """Extract factual IOCs from email data"""
        iocs = []
        
        # Extract email addresses
        sender_analysis = email_data.get("sender_analysis", {})
        external_senders = sender_analysis.get("external_senders", [])
        
        for sender in external_senders[:50]:  # Limit to prevent overflow
            if "@" in sender:
                # Extract actual email from "Display Name <email@domain.com>" format
                if "<" in sender and ">" in sender:
                    actual_email = sender.split("<")[1].split(">")[0].strip()
                else:
                    actual_email = sender.strip()
                
                iocs.append(IOC(
                    type=IOCType.EMAIL_ADDRESS,
                    value=actual_email,
                    confidence=1.0,
                    source="Email Headers",
                    description="Email address found in sender field"
                ))
        
        # Extract domains from URLs
        content_analysis = email_data.get("content_analysis", {})
        url_domains = content_analysis.get("url_domains", [])
        
        for domain in url_domains[:30]:  # Limit to prevent overflow
            if domain:
                iocs.append(IOC(
                    type=IOCType.DOMAIN,
                    value=domain,
                    confidence=1.0,
                    source="Email Content",
                    description="Domain found in email URLs"
                ))
        
        # Extract URLs from email content
        for email_msg in emails:
            for url_data in email_msg.get("urls", []):
                url = url_data.get("url", "")
                if url:
                    iocs.append(IOC(
                        type=IOCType.URL,
                        value=url,
                        confidence=1.0,
                        source="Email Content",
                        description="URL found in email content"
                    ))
        
        # Extract file hashes from attachments
        for email_msg in emails:
            for attachment in email_msg.get("attachments", []):
                file_hash = attachment.get("file_hash")
                if file_hash:
                    iocs.append(IOC(
                        type=IOCType.FILE_HASH,
                        value=file_hash,
                        confidence=1.0,
                        source="Email Attachment",
                        description=f"Hash of attachment: {attachment.get('filename', 'unknown')}"
                    ))
        
        return iocs

    def _create_error_result(self, error_message: str) -> AnalysisResult:
        """Create error result for failed analysis"""
        return AnalysisResult(
            file_path="",
            parser_name=self.name,
            analysis_type="Email Data Extraction",
            timestamp=datetime.now(),
            summary=f"Data extraction failed: {error_message}",
            details={"error": error_message},
            threats_detected=[],
            iocs_found=[],
            severity=Severity.LOW,
            risk_score=0.0,
            recommendations=["Fix extraction error and retry analysis"]
        )

def create_parser():
    """Factory function to create parser instance"""
    return EmailForensicsParser()