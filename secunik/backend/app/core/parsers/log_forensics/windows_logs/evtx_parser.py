"""
SecuNik - Windows Event Log (EVTX) Parser - Pure Data Extractor
Extracts raw data from Windows Event Logs for AI analysis

Location: backend/app/core/parsers/log_forensics/windows_logs/evtx_parser.py
"""

import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path

try:
    import Evtx.Evtx as evtx
    import Evtx.Views as e_views
    EVTX_AVAILABLE = True
except ImportError:
    EVTX_AVAILABLE = False

from ....models.analysis import AnalysisResult, Severity, IOC, IOCType

logger = logging.getLogger(__name__)

class EVTXParser:
    """Pure Data Extractor for Windows Event Logs - AI analyzes the data"""
    
    def __init__(self):
        self.name = "Windows Event Log Parser"
        self.version = "2.0.0"
        self.supported_formats = [".evtx"]
        
        # Event ID descriptions for context (not threat detection)
        self.event_descriptions = {
            4624: "Successful Logon",
            4625: "Failed Logon", 
            4634: "Account Logoff",
            4648: "Logon with Explicit Credentials",
            4720: "User Account Created",
            4722: "User Account Enabled",
            4724: "Password Reset",
            4728: "User Added to Security Group",
            4732: "User Added to Local Group",
            4756: "User Added to Universal Group",
            4771: "Kerberos Pre-authentication Failed",
            4776: "Credential Validation",
            4778: "Session Reconnected",
            4779: "Session Disconnected",
            4781: "Account Name Changed",
            4946: "Windows Firewall Rule Added",
            4947: "Windows Firewall Rule Modified",
            4950: "Windows Firewall Setting Changed",
            1102: "Audit Log Cleared",
            7045: "Service Installed",
            7034: "Service Crashed",
            7035: "Service Control Manager"
        }

    def can_parse(self, file_path: str) -> bool:
        """Check if file can be parsed by this parser"""
        return Path(file_path).suffix.lower() in self.supported_formats and EVTX_AVAILABLE

    def parse(self, file_path: str) -> AnalysisResult:
        """Extract raw data from Windows Event Log file - AI will analyze for threats"""
        try:
            if not EVTX_AVAILABLE:
                return self._create_error_result("python-evtx library not available")
            
            logger.info(f"Extracting data from Windows Event Log: {file_path}")
            
            # Extract raw events data
            events_data = self._extract_events_data(file_path)
            
            # Build structured data for AI analysis
            extracted_data = self._build_extracted_data(events_data)
            
            # Extract basic IOCs (factual data only, no threat assessment)
            iocs = self._extract_factual_iocs(events_data)
            
            # Create analysis result with raw data (AI will determine threats and recommendations)
            result = AnalysisResult(
                file_path=file_path,
                parser_name=self.name,
                analysis_type="Windows Event Log Data Extraction",
                timestamp=datetime.now(),
                summary=f"Extracted {len(events_data)} events from Windows Event Log for AI analysis",
                details=extracted_data,
                threats_detected=[],  # AI will determine threats
                iocs_found=iocs,
                severity=Severity.LOW,  # AI will determine severity
                risk_score=0.0,  # AI will calculate risk score
                recommendations=["Data extracted - pending AI analysis for threat assessment and recommendations"]
            )
            
            logger.info(f"EVTX data extraction completed: {len(events_data)} events extracted")
            return result
            
        except Exception as e:
            logger.error(f"Error extracting EVTX data {file_path}: {str(e)}")
            return self._create_error_result(str(e))

    def _extract_events_data(self, file_path: str) -> List[Dict[str, Any]]:
        """Extract raw events data from EVTX file"""
        events = []
        
        try:
            with evtx.Evtx(file_path) as log:
                for record in log.records():
                    try:
                        event_data = self._parse_event_record(record)
                        if event_data:
                            events.append(event_data)
                    except Exception as e:
                        logger.warning(f"Error parsing event record: {e}")
                        continue
                        
        except Exception as e:
            logger.error(f"Error opening EVTX file: {e}")
            
        return events

    def _parse_event_record(self, record) -> Optional[Dict[str, Any]]:
        """Parse individual event record - extract data only"""
        try:
            # Get XML representation
            xml_data = record.xml()
            
            # Extract basic event information
            event_data = {
                "record_number": record.record_num(),
                "timestamp": record.timestamp(),
                "xml": xml_data
            }
            
            # Parse XML for structured data
            import xml.etree.ElementTree as ET
            root = ET.fromstring(xml_data)
            
            # Extract System information
            system = root.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}System')
            if system is not None:
                event_id_elem = system.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}EventID')
                if event_id_elem is not None:
                    event_data["event_id"] = int(event_id_elem.text)
                    # Add description for context (not threat classification)
                    event_data["event_description"] = self.event_descriptions.get(
                        event_data["event_id"], f"Event ID {event_data['event_id']}"
                    )
                
                provider_elem = system.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}Provider')
                if provider_elem is not None:
                    event_data["provider"] = provider_elem.get("Name", "Unknown")
                
                computer_elem = system.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}Computer')
                if computer_elem is not None:
                    event_data["computer"] = computer_elem.text
                
                user_elem = system.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}Security')
                if user_elem is not None:
                    event_data["user_sid"] = user_elem.get("UserID", "Unknown")
            
            # Extract EventData
            event_data_elem = root.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}EventData')
            if event_data_elem is not None:
                data_fields = {}
                for data in event_data_elem.findall('.//{http://schemas.microsoft.com/win/2004/08/events/event}Data'):
                    name = data.get("Name", f"data_{len(data_fields)}")
                    value = data.text or ""
                    data_fields[name] = value
                event_data["event_data"] = data_fields
                
                # Extract common fields for easy access
                if "TargetUserName" in data_fields:
                    event_data["user"] = data_fields["TargetUserName"]
                elif "SubjectUserName" in data_fields:
                    event_data["user"] = data_fields["SubjectUserName"]
                
                if "WorkstationName" in data_fields:
                    event_data["workstation"] = data_fields["WorkstationName"]
                
                if "IpAddress" in data_fields:
                    event_data["ip_address"] = data_fields["IpAddress"]
                
                if "ProcessName" in data_fields:
                    event_data["process"] = data_fields["ProcessName"]
            
            return event_data
            
        except Exception as e:
            logger.warning(f"Error parsing event record: {e}")
            return None

    def _build_extracted_data(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Build structured extracted data for AI analysis"""
        extracted_data = {
            "total_events": len(events),
            "time_range": self._get_time_range(events),
            "event_distribution": self._get_event_distribution(events),
            "unique_users": list(set(e.get("user", "Unknown") for e in events if e.get("user"))),
            "unique_computers": list(set(e.get("computer", "Unknown") for e in events if e.get("computer"))),
            "unique_ip_addresses": list(set(e.get("ip_address", "") for e in events if e.get("ip_address") and e.get("ip_address") not in ["-", "127.0.0.1", "::1"])),
            "processes_mentioned": list(set(e.get("process", "") for e in events if e.get("process"))),
            "timeline": self._build_timeline(events),
            "authentication_events": self._extract_auth_events(events),
            "service_events": self._extract_service_events(events),
            "system_events": self._extract_system_events(events),
            "network_events": self._extract_network_events(events)
        }
        
        return extracted_data

    def _get_time_range(self, events: List[Dict[str, Any]]) -> Dict[str, str]:
        """Get time range of events"""
        if not events:
            return {}
        
        timestamps = [e.get("timestamp") for e in events if e.get("timestamp")]
        if not timestamps:
            return {}
        
        return {
            "start": min(timestamps).isoformat(),
            "end": max(timestamps).isoformat(),
            "duration_hours": (max(timestamps) - min(timestamps)).total_seconds() / 3600,
            "total_events": len(events)
        }

    def _get_event_distribution(self, events: List[Dict[str, Any]]) -> Dict[str, int]:
        """Get distribution of event types"""
        distribution = {}
        for event in events:
            event_id = event.get("event_id", 0)
            description = event.get("event_description", f"Event {event_id}")
            distribution[description] = distribution.get(description, 0) + 1
        
        # Sort by frequency
        return dict(sorted(distribution.items(), key=lambda x: x[1], reverse=True))

    def _build_timeline(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Build chronological timeline of events"""
        timeline = []
        
        # Sort events by timestamp and take sample for performance
        sorted_events = sorted(events, key=lambda x: x.get("timestamp", datetime.min))
        
        # Take representative sample for timeline (every nth event or important events)
        sample_events = sorted_events[::max(1, len(sorted_events) // 100)]  # Max 100 timeline entries
        
        for event in sample_events:
            timeline_entry = {
                "timestamp": event.get("timestamp").isoformat() if event.get("timestamp") else "Unknown",
                "event_id": event.get("event_id"),
                "description": event.get("event_description", "Unknown Event"),
                "user": event.get("user", "Unknown"),
                "computer": event.get("computer", "Unknown"),
                "additional_data": event.get("event_data", {})
            }
            timeline.append(timeline_entry)
        
        return timeline

    def _extract_auth_events(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Extract authentication-related events"""
        auth_event_ids = [4624, 4625, 4634, 4648, 4771, 4776]
        auth_events = [e for e in events if e.get("event_id") in auth_event_ids]
        
        successful_logins = [e for e in auth_events if e.get("event_id") == 4624]
        failed_logins = [e for e in auth_events if e.get("event_id") == 4625]
        
        return {
            "total_auth_events": len(auth_events),
            "successful_logins": len(successful_logins),
            "failed_logins": len(failed_logins),
            "success_rate": (len(successful_logins) / len(auth_events) * 100) if auth_events else 0,
            "unique_failed_users": list(set(e.get("user", "Unknown") for e in failed_logins if e.get("user"))),
            "unique_success_users": list(set(e.get("user", "Unknown") for e in successful_logins if e.get("user"))),
            "sample_events": auth_events[:10]  # Sample for AI analysis
        }

    def _extract_service_events(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Extract service-related events"""
        service_event_ids = [7045, 7034, 7035, 7036]
        service_events = [e for e in events if e.get("event_id") in service_event_ids]
        
        return {
            "total_service_events": len(service_events),
            "service_installs": len([e for e in service_events if e.get("event_id") == 7045]),
            "service_crashes": len([e for e in service_events if e.get("event_id") == 7034]),
            "sample_events": service_events[:10]
        }

    def _extract_system_events(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Extract system-related events"""
        system_event_ids = [1102, 4946, 4947, 4950]
        system_events = [e for e in events if e.get("event_id") in system_event_ids]
        
        return {
            "total_system_events": len(system_events),
            "log_clears": len([e for e in system_events if e.get("event_id") == 1102]),
            "firewall_changes": len([e for e in system_events if e.get("event_id") in [4946, 4947, 4950]]),
            "sample_events": system_events[:10]
        }

    def _extract_network_events(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Extract network-related events"""
        network_events = [e for e in events if e.get("ip_address") and e.get("ip_address") not in ["-", "127.0.0.1", "::1"]]
        
        return {
            "total_network_events": len(network_events),
            "unique_ips": list(set(e.get("ip_address") for e in network_events)),
            "sample_events": network_events[:10]
        }

    def _extract_factual_iocs(self, events: List[Dict[str, Any]]) -> List[IOC]:
        """Extract factual IOCs (no threat assessment)"""
        iocs = []
        
        # Extract IP addresses (factual, not threat assessment)
        ip_addresses = set()
        for event in events:
            if event.get("ip_address") and event["ip_address"] not in ["127.0.0.1", "::1", "-"]:
                ip_addresses.add(event["ip_address"])
        
        for ip in ip_addresses:
            iocs.append(IOC(
                type=IOCType.IP_ADDRESS,
                value=ip,
                confidence=1.0,  # Factual extraction, high confidence
                source="Windows Event Logs",
                description="IP address found in authentication events"
            ))
        
        # Extract usernames (factual)
        usernames = set()
        for event in events:
            if event.get("user") and event["user"] not in ["Unknown", "-", ""]:
                usernames.add(event["user"])
        
        for user in list(usernames)[:20]:  # Limit to prevent overflow
            iocs.append(IOC(
                type=IOCType.USERNAME,
                value=user,
                confidence=1.0,
                source="Windows Event Logs",
                description="Username found in events"
            ))
        
        # Extract process names (factual)
        processes = set()
        for event in events:
            process = event.get("process", "")
            if process and process not in ["", "-"]:
                processes.add(process)
        
        for process in list(processes)[:20]:  # Limit to prevent overflow
            iocs.append(IOC(
                type=IOCType.PROCESS_NAME,
                value=process,
                confidence=1.0,
                source="Windows Event Logs",
                description="Process name found in events"
            ))
        
        return iocs

    def _create_error_result(self, error_message: str) -> AnalysisResult:
        """Create error result for failed analysis"""
        return AnalysisResult(
            file_path="",
            parser_name=self.name,
            analysis_type="Windows Event Log Data Extraction",
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
    return EVTXParser()