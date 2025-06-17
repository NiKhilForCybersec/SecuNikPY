"""
PST (Personal Storage Table) parser for SecuNik
Analyzes Outlook PST files for security threats and IOCs
"""

import json
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional, Set
from pathlib import Path
import pypff
import email
from email import policy
from email.parser import BytesParser
import re
from collections import defaultdict, Counter
import hashlib

from ....models.analysis import (
    AnalysisResult, IOC, IOCType, Severity, ThreatInfo
)
from ..base.abstract_parser import AbstractParser

logger = logging.getLogger(__name__)

class PSTParser(AbstractParser):
    """Parser for Outlook PST files"""
    
    name = "PST Email Parser"
    supported_extensions = [".pst", ".ost"]
    
    def __init__(self):
        super().__init__()
        self.suspicious_patterns = {
            "phishing_keywords": [
                "urgent", "verify your account", "suspended", "click here immediately",
                "confirm your identity", "update your information", "verify your email",
                "security alert", "unusual activity", "temporary suspension"
            ],
            "malware_indicators": [
                ".exe", ".scr", ".vbs", ".bat", ".cmd", ".com", ".pif",
                ".zip", ".rar", ".7z", "password protected", "encrypted attachment"
            ],
            "suspicious_senders": [
                "no-reply", "noreply", "do-not-reply", "notification", "alert",
                "security", "support", "admin", "administrator"
            ]
        }
        
        # Email header patterns for analysis
        self.header_patterns = {
            "spoofed_sender": re.compile(r'From:.*?<(.+?)>.*?Reply-To:.*?<(.+?)>', re.IGNORECASE | re.DOTALL),
            "suspicious_received": re.compile(r'Received:.*?(\d+\.\d+\.\d+\.\d+)', re.IGNORECASE),
            "x_mailer": re.compile(r'X-Mailer:\s*(.+?)(?:\r?\n|\r)', re.IGNORECASE),
            "authentication_results": re.compile(r'Authentication-Results:.*?spf=(\w+)', re.IGNORECASE)
        }
    
    async def parse(self, file_path: str) -> Dict[str, Any]:
        """Parse PST file and extract email data"""
        try:
            pst = pypff.file()
            pst.open(file_path)
            
            email_data = {
                "total_messages": 0,
                "folders": [],
                "messages": [],
                "attachments": [],
                "suspicious_emails": [],
                "sender_analysis": defaultdict(int),
                "recipient_analysis": defaultdict(int),
                "timeline": [],
                "attachment_analysis": defaultdict(int)
            }
            
            # Process root folder
            root = pst.get_root_folder()
            await self._process_folder(root, email_data, "")
            
            pst.close()
            
            # Post-processing
            email_data["sender_analysis"] = dict(
                sorted(email_data["sender_analysis"].items(), 
                       key=lambda x: x[1], reverse=True)[:20]
            )
            email_data["recipient_analysis"] = dict(
                sorted(email_data["recipient_analysis"].items(), 
                       key=lambda x: x[1], reverse=True)[:20]
            )
            email_data["attachment_analysis"] = dict(email_data["attachment_analysis"])
            
            # Limit stored messages to prevent memory issues
            email_data["messages"] = email_data["messages"][:100]
            email_data["timeline"] = sorted(
                email_data["timeline"], 
                key=lambda x: x["timestamp"], 
                reverse=True
            )[:100]
            
            return {
                "extraction_successful": True,
                "email_data": email_data
            }
            
        except Exception as e:
            logger.error(f"Failed to parse PST file: {str(e)}")
            return {
                "extraction_successful": False,
                "error": str(e)
            }
    
    async def _process_folder(self, folder, email_data: Dict[str, Any], path: str):
        """Recursively process PST folders"""
        try:
            folder_name = folder.name or "Root"
            current_path = f"{path}/{folder_name}" if path else folder_name
            
            folder_info = {
                "name": folder_name,
                "path": current_path,
                "message_count": folder.number_of_sub_messages
            }
            email_data["folders"].append(folder_info)
            
            # Process messages in folder
            for i in range(folder.number_of_sub_messages):
                try:
                    message = folder.get_sub_message(i)
                    await self._process_message(message, email_data, current_path)
                except Exception as e:
                    logger.warning(f"Failed to process message {i}: {str(e)}")
            
            # Process subfolders
            for i in range(folder.number_of_sub_folders):
                try:
                    subfolder = folder.get_sub_folder(i)
                    await self._process_folder(subfolder, email_data, current_path)
                except Exception as e:
                    logger.warning(f"Failed to process subfolder {i}: {str(e)}")
                    
        except Exception as e:
            logger.error(f"Error processing folder: {str(e)}")
    
    async def _process_message(self, message, email_data: Dict[str, Any], folder_path: str):
        """Process individual email message"""
        try:
            email_data["total_messages"] += 1
            
            # Extract basic message info
            subject = message.subject or "No Subject"
            sender = message.sender_name or "Unknown"
            
            # Get timestamps
            delivery_time = None
            if hasattr(message, 'delivery_time') and message.delivery_time:
                delivery_time = message.delivery_time
            elif hasattr(message, 'client_submit_time') and message.client_submit_time:
                delivery_time = message.client_submit_time
            
            timestamp = delivery_time.isoformat() if delivery_time else "Unknown"
            
            # Extract recipients
            recipients = []
            if hasattr(message, 'number_of_recipients'):
                for i in range(message.number_of_recipients):
                    try:
                        recipient = message.get_recipient(i)
                        recipients.append(recipient.email_address or recipient.name)
                    except:
                        pass
            
            # Get message body
            body = ""
            if hasattr(message, 'plain_text_body'):
                body = str(message.plain_text_body) if message.plain_text_body else ""
            elif hasattr(message, 'html_body'):
                body = str(message.html_body) if message.html_body else ""
            
            # Get headers
            headers = {}
            if hasattr(message, 'transport_headers'):
                header_text = str(message.transport_headers) if message.transport_headers else ""
                headers = self._parse_headers(header_text)
            
            message_info = {
                "subject": subject,
                "sender": sender,
                "recipients": recipients,
                "timestamp": timestamp,
                "folder": folder_path,
                "has_attachments": message.number_of_attachments > 0,
                "attachment_count": message.number_of_attachments,
                "body_preview": body[:200] if body else "",
                "headers": headers
            }
            
            # Track sender/recipient statistics
            email_data["sender_analysis"][sender] += 1
            for recipient in recipients:
                email_data["recipient_analysis"][recipient] += 1
            
            # Add to timeline
            if delivery_time:
                email_data["timeline"].append({
                    "timestamp": timestamp,
                    "subject": subject,
                    "sender": sender,
                    "event": "email_received"
                })
            
            # Process attachments
            if message.number_of_attachments > 0:
                attachments = await self._process_attachments(message, email_data)
                message_info["attachments"] = attachments
            
            # Check for suspicious content
            suspicion_score = self._analyze_suspicious_content(message_info, body)
            if suspicion_score > 0.5:
                message_info["suspicion_score"] = suspicion_score
                email_data["suspicious_emails"].append(message_info)
            
            # Store message info
            email_data["messages"].append(message_info)
            
        except Exception as e:
            logger.warning(f"Error processing message: {str(e)}")
    
    async def _process_attachments(self, message, email_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Process email attachments"""
        attachments = []
        
        for i in range(message.number_of_attachments):
            try:
                attachment = message.get_attachment(i)
                
                # Get attachment info
                filename = attachment.name or f"attachment_{i}"
                size = attachment.size if hasattr(attachment, 'size') else 0
                
                # Calculate hash if possible
                file_hash = ""
                if hasattr(attachment, 'read'):
                    try:
                        data = attachment.read()
                        file_hash = hashlib.sha256(data).hexdigest()
                    except:
                        pass
                
                # Determine file type
                file_ext = Path(filename).suffix.lower()
                
                attachment_info = {
                    "filename": filename,
                    "size": size,
                    "extension": file_ext,
                    "hash": file_hash
                }
                
                attachments.append(attachment_info)
                email_data["attachments"].append(attachment_info)
                email_data["attachment_analysis"][file_ext] += 1
                
            except Exception as e:
                logger.warning(f"Error processing attachment {i}: {str(e)}")
        
        return attachments
    
    def _parse_headers(self, header_text: str) -> Dict[str, str]:
        """Parse email headers"""
        headers = {}
        
        try:
            # Parse key headers
            for line in header_text.split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip().lower()
                    value = value.strip()
                    
                    if key in ['from', 'to', 'subject', 'date', 'message-id', 
                              'return-path', 'reply-to', 'x-mailer', 
                              'authentication-results', 'received-spf']:
                        headers[key] = value
        except:
            pass
        
        return headers
    
    def _analyze_suspicious_content(self, message_info: Dict[str, Any], body: str) -> float:
        """Analyze email for suspicious content"""
        suspicion_score = 0.0
        factors = []
        
        # Check subject and body for phishing keywords
        content = (message_info["subject"] + " " + body).lower()
        phishing_count = sum(1 for keyword in self.suspicious_patterns["phishing_keywords"] 
                           if keyword in content)
        if phishing_count > 0:
            suspicion_score += min(phishing_count * 0.15, 0.5)
            factors.append("phishing_keywords")
        
        # Check for suspicious attachments
        if message_info.get("attachments"):
            for att in message_info["attachments"]:
                ext = att.get("extension", "").lower()
                if ext in [".exe", ".scr", ".vbs", ".bat", ".cmd", ".com", ".pif"]:
                    suspicion_score += 0.3
                    factors.append("executable_attachment")
                elif ext in [".zip", ".rar", ".7z"] and "password" in content:
                    suspicion_score += 0.2
                    factors.append("encrypted_archive")
        
        # Check sender patterns
        sender = message_info["sender"].lower()
        if any(pattern in sender for pattern in self.suspicious_patterns["suspicious_senders"]):
            suspicion_score += 0.1
            factors.append("suspicious_sender")
        
        # Check for header anomalies
        headers = message_info.get("headers", {})
        if headers.get("from", "") != headers.get("return-path", ""):
            suspicion_score += 0.1
            factors.append("sender_mismatch")
        
        if headers.get("authentication-results") and "fail" in headers["authentication-results"]:
            suspicion_score += 0.2
            factors.append("spf_fail")
        
        # Check for URL patterns
        url_pattern = re.compile(r'https?://[^\s]+')
        urls = url_pattern.findall(body)
        if len(urls) > 5:
            suspicion_score += 0.1
            factors.append("many_urls")
        
        # Shortened URLs
        shortened_domains = ["bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly"]
        if any(domain in body for domain in shortened_domains):
            suspicion_score += 0.15
            factors.append("shortened_urls")
        
        message_info["suspicion_factors"] = factors
        return min(suspicion_score, 1.0)
    
    async def analyze(self, file_path: str, extracted_data: Dict[str, Any]) -> AnalysisResult:
        """Analyze PST data for threats"""
        if not extracted_data.get("extraction_successful"):
            return self._create_error_result(extracted_data.get("error", "Unknown error"))
        
        email_data = extracted_data.get("email_data", {})
        threats = []
        severity = Severity.LOW
        risk_score = 0.2
        
        # Analyze suspicious emails
        suspicious_emails = email_data.get("suspicious_emails", [])
        if suspicious_emails:
            # Group by suspicion factors
            factor_counts = defaultdict(int)
            for email in suspicious_emails:
                for factor in email.get("suspicion_factors", []):
                    factor_counts[factor] += 1
            
            # Phishing threats
            if factor_counts.get("phishing_keywords", 0) > 5:
                threats.append(ThreatInfo(
                    threat_type="Phishing Campaign",
                    description=f"Multiple emails with phishing indicators detected",
                    severity=Severity.HIGH,
                    confidence=0.85,
                    evidence={
                        "phishing_emails": len([e for e in suspicious_emails 
                                              if "phishing_keywords" in e.get("suspicion_factors", [])])
                    }
                ))
                severity = Severity.HIGH
                risk_score = max(risk_score, 0.8)
            
            # Malware threats
            if factor_counts.get("executable_attachment", 0) > 0:
                threats.append(ThreatInfo(
                    threat_type="Potential Malware",
                    description="Emails with executable attachments detected",
                    severity=Severity.HIGH,
                    confidence=0.9,
                    evidence={
                        "malware_emails": len([e for e in suspicious_emails 
                                             if "executable_attachment" in e.get("suspicion_factors", [])])
                    }
                ))
                severity = Severity.HIGH
                risk_score = max(risk_score, 0.85)
            
            # Sender spoofing
            if factor_counts.get("sender_mismatch", 0) > 3:
                threats.append(ThreatInfo(
                    threat_type="Email Spoofing",
                    description="Multiple emails with sender verification failures",
                    severity=Severity.MEDIUM,
                    confidence=0.7,
                    evidence={
                        "spoofed_emails": factor_counts["sender_mismatch"]
                    }
                ))
                if severity == Severity.LOW:
                    severity = Severity.MEDIUM
                risk_score = max(risk_score, 0.6)
        
        # Extract IOCs
        iocs = self._extract_iocs(email_data)
        
        # Generate summary
        summary = self._generate_summary(email_data, threats)
        
        # Recommendations
        recommendations = self._generate_recommendations(threats, email_data)
        
        return AnalysisResult(
            file_path=file_path,
            parser_name=self.name,
            analysis_type="Email Forensic Analysis",
            timestamp=datetime.now(),
            summary=summary,
            details={
                "total_messages": email_data.get("total_messages", 0),
                "total_folders": len(email_data.get("folders", [])),
                "suspicious_emails": len(suspicious_emails),
                "total_attachments": len(email_data.get("attachments", [])),
                "top_senders": list(email_data.get("sender_analysis", {}).items())[:5],
                "top_recipients": list(email_data.get("recipient_analysis", {}).items())[:5],
                "attachment_types": email_data.get("attachment_analysis", {})
            },
            threats_detected=threats,
            iocs_found=iocs,
            severity=severity,
            risk_score=risk_score,
            recommendations=recommendations
        )
    
    def _generate_summary(self, email_data: Dict[str, Any], threats: List[ThreatInfo]) -> str:
        """Generate analysis summary"""
        total = email_data.get("total_messages", 0)
        suspicious = len(email_data.get("suspicious_emails", []))
        attachments = len(email_data.get("attachments", []))
        
        summary = f"Analyzed {total} emails across {len(email_data.get('folders', []))} folders. "
        
        if suspicious > 0:
            summary += f"Found {suspicious} suspicious emails. "
        
        if attachments > 0:
            summary += f"Processed {attachments} attachments. "
        
        if threats:
            summary += f"Detected {len(threats)} potential threats. "
        else:
            summary += "No significant threats detected. "
        
        return summary
    
    def _generate_recommendations(self, threats: List[ThreatInfo], email_data: Dict[str, Any]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        if any(t.threat_type == "Phishing Campaign" for t in threats):
            recommendations.append("Implement advanced email filtering and anti-phishing solutions")
            recommendations.append("Conduct user awareness training on phishing identification")
            recommendations.append("Enable multi-factor authentication for all accounts")
        
        if any(t.threat_type == "Potential Malware" for t in threats):
            recommendations.append("Scan all executable attachments with updated antivirus")
            recommendations.append("Block executable file types in email gateway")
            recommendations.append("Implement sandboxing for suspicious attachments")
        
        if any(t.threat_type == "Email Spoofing" for t in threats):
            recommendations.append("Implement SPF, DKIM, and DMARC email authentication")
            recommendations.append("Configure email gateway to reject failed SPF/DKIM")
            recommendations.append("Monitor for domain spoofing attempts")
        
        suspicious = email_data.get("suspicious_emails", [])
        if any("shortened_urls" in e.get("suspicion_factors", []) for e in suspicious):
            recommendations.append("Implement URL rewriting to reveal shortened URLs")
            recommendations.append("Block or quarantine emails with suspicious URLs")
        
        if not recommendations:
            recommendations.append("Maintain regular email security monitoring")
            recommendations.append("Keep email security policies up to date")
        
        return recommendations[:5]
    
    def _extract_iocs(self, email_data: Dict[str, Any]) -> List[IOC]:
        """Extract IOCs from email data"""
        iocs = []
        seen_values = set()
        
        # Extract email addresses
        for sender, count in list(email_data.get("sender_analysis", {}).items())[:20]:
            if '@' in sender and sender not in seen_values:
                iocs.append(IOC(
                    type=IOCType.EMAIL_ADDRESS,
                    value=sender,
                    confidence=1.0,
                    source="Email Sender",
                    description=f"Email sender (appeared {count} times)"
                ))
                seen_values.add(sender)
        
        # Extract from suspicious emails
        for email in email_data.get("suspicious_emails", [])[:20]:
            # Extract URLs from body
            body = email.get("body_preview", "")
            url_pattern = re.compile(r'https?://[^\s<>"]+')
            urls = url_pattern.findall(body)
            
            for url in urls[:5]:  # Limit URLs per email
                if url not in seen_values:
                    iocs.append(IOC(
                        type=IOCType.URL,
                        value=url,
                        confidence=0.8,
                        source="Suspicious Email",
                        description="URL found in suspicious email"
                    ))
                    seen_values.add(url)
            
            # Extract attachment hashes
            for att in email.get("attachments", []):
                if att.get("hash") and att["hash"] not in seen_values:
                    iocs.append(IOC(
                        type=IOCType.HASH_SHA256,
                        value=att["hash"],
                        confidence=1.0,
                        source="Email Attachment",
                        description=f"Attachment: {att.get('filename', 'unknown')}"
                    ))
                    seen_values.add(att["hash"])
        
        # Extract IPs from headers
        for message in email_data.get("messages", [])[:50]:
            headers = message.get("headers", {})
            received = headers.get("received", "")
            
            ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
            ips = ip_pattern.findall(received)
            
            for ip in ips[:2]:  # Limit IPs per message
                if ip not in seen_values and not ip.startswith("192.168.") and not ip.startswith("10."):
                    iocs.append(IOC(
                        type=IOCType.IP_ADDRESS,
                        value=ip,
                        confidence=0.7,
                        source="Email Headers",
                        description="IP from email routing"
                    ))
                    seen_values.add(ip)
        
        return iocs[:50]  # Limit total IOCs
    
    def _create_error_result(self, error_message: str) -> AnalysisResult:
        """Create error result for failed analysis"""
        return AnalysisResult(
            file_path="",
            parser_name=self.name,
            analysis_type="Email Forensic Analysis",
            timestamp=datetime.now(),
            summary=f"Analysis failed: {error_message}",
            details={"error": error_message},
            threats_detected=[],
            iocs_found=[],
            severity=Severity.LOW,
            risk_score=0.0,
            recommendations=["Fix parsing error and retry analysis"]
        )

def create_parser():
    """Factory function to create parser instance"""
    return PSTParser()