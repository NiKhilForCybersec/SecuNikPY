"""
Windows Registry parser for SecuNik
Analyzes registry hive files for security threats and IOCs
"""

import json
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional, Set
from pathlib import Path
import struct
from Registry import Registry
from collections import defaultdict
import re

from ....models.analysis import (
    AnalysisResult, IOC, IOCType, Severity, ThreatInfo
)
from ..base.abstract_parser import AbstractParser

logger = logging.getLogger(__name__)

class RegistryParser(AbstractParser):
    """Parser for Windows Registry files"""
    
    name = "Windows Registry Parser"
    supported_extensions = [".dat", ".hive", ".reg"]
    
    def __init__(self):
        super().__init__()
        
        # Known malicious registry locations
        self.suspicious_keys = {
            # Autostart locations
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run": "Startup",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce": "Startup",
            r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run": "Startup",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices": "Startup",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce": "Startup",
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon": "Winlogon",
            r"SYSTEM\CurrentControlSet\Services": "Services",
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs": "AppInit",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders": "Shell",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders": "Shell",
            
            # Browser hijacking
            r"SOFTWARE\Microsoft\Internet Explorer\Main": "Browser",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects": "BHO",
            
            # Security settings
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies": "Policy",
            r"SOFTWARE\Policies": "Policy",
            r"SYSTEM\CurrentControlSet\Control\SecurityProviders": "Security",
            r"SYSTEM\CurrentControlSet\Control\Lsa": "Security",
            
            # Network settings
            r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters": "Network",
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList": "Network",
            
            # File associations
            r"SOFTWARE\Classes": "FileAssoc",
            
            # Scheduled tasks
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache": "Tasks"
        }
        
        # Suspicious value patterns
        self.suspicious_patterns = {
            "executable_paths": re.compile(r'.*\.(exe|dll|bat|cmd|ps1|vbs|js)$', re.IGNORECASE),
            "network_addresses": re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
            "urls": re.compile(r'https?://[^\s<>"]+'),
            "encoded_commands": re.compile(r'powershell.*-e[nc].*', re.IGNORECASE),
            "wmi_persistence": re.compile(r'wmic|cimv2|root\\subscription', re.IGNORECASE),
            "temp_paths": re.compile(r'%temp%|\\temp\\|\\tmp\\', re.IGNORECASE)
        }
        
        # Known malware registry artifacts
        self.malware_indicators = {
            "ransomware": [
                "vssadmin", "delete shadows", "bcdedit", "wbadmin",
                "cipher", "diskpart", "recover", ".encrypted", ".locked"
            ],
            "backdoor": [
                "nc.exe", "netcat", "psexec", "meterpreter", "cobalt",
                "reverse", "bind", "shell", "payload", "beacon"
            ],
            "trojan": [
                "svchost", "csrss", "lsass", "services", "winlogon",
                "explorer", "rundll32", "regsvr32", "mshta"
            ]
        }
    
    async def parse(self, file_path: str) -> Dict[str, Any]:
        """Parse registry file and extract data"""
        try:
            reg = Registry.Registry(file_path)
            
            registry_data = {
                "hive_name": self._identify_hive_type(file_path),
                "root_key": reg.root().name(),
                "last_modified": reg.root().timestamp().isoformat() if reg.root().timestamp() else None,
                "total_keys": 0,
                "total_values": 0,
                "autostart_entries": [],
                "services": [],
                "suspicious_entries": [],
                "network_settings": [],
                "user_accounts": [],
                "installed_software": [],
                "recent_docs": [],
                "usb_devices": []
            }
            
            # Recursively process registry
            await self._process_key(reg.root(), registry_data, "")
            
            # Post-processing
            registry_data["suspicious_entries"] = registry_data["suspicious_entries"][:100]
            registry_data["autostart_entries"] = registry_data["autostart_entries"][:50]
            registry_data["services"] = registry_data["services"][:50]
            
            return {
                "extraction_successful": True,
                "registry_data": registry_data
            }
            
        except Exception as e:
            logger.error(f"Failed to parse registry file: {str(e)}")
            return {
                "extraction_successful": False,
                "error": str(e)
            }
    
    def _identify_hive_type(self, file_path: str) -> str:
        """Identify the type of registry hive"""
        filename = Path(file_path).name.lower()
        
        if "system" in filename:
            return "SYSTEM"
        elif "software" in filename:
            return "SOFTWARE"
        elif "sam" in filename:
            return "SAM"
        elif "security" in filename:
            return "SECURITY"
        elif "ntuser" in filename:
            return "NTUSER"
        elif "usrclass" in filename:
            return "USRCLASS"
        else:
            return "UNKNOWN"
    
    async def _process_key(self, key, registry_data: Dict[str, Any], path: str):
        """Recursively process registry keys"""
        try:
            current_path = f"{path}\\{key.name()}" if path else key.name()
            registry_data["total_keys"] += 1
            
            # Check if this is a suspicious key location
            for suspicious_path, category in self.suspicious_keys.items():
                if suspicious_path.lower() in current_path.lower():
                    # Process values in suspicious locations
                    for value in key.values():
                        registry_data["total_values"] += 1
                        value_data = self._extract_value_data(value)
                        
                        if value_data:
                            entry = {
                                "key_path": current_path,
                                "value_name": value.name(),
                                "value_type": value.value_type_str(),
                                "value_data": value_data,
                                "category": category,
                                "timestamp": key.timestamp().isoformat() if key.timestamp() else None
                            }
                            
                            # Categorize the entry
                            if category == "Startup":
                                registry_data["autostart_entries"].append(entry)
                            elif category == "Services":
                                await self._process_service(key, registry_data)
                            
                            # Check for suspicious patterns
                            if self._is_suspicious(value_data):
                                entry["suspicious_indicators"] = self._get_suspicious_indicators(value_data)
                                registry_data["suspicious_entries"].append(entry)
            
            # Special processing for specific paths
            if "CurrentVersion\\Run" in current_path:
                await self._process_run_key(key, registry_data, current_path)
            elif "Services\\Tcpip\\Parameters" in current_path:
                await self._process_network_settings(key, registry_data)
            elif "Microsoft\\Windows\\CurrentVersion\\Uninstall" in current_path:
                await self._process_installed_software(key, registry_data)
            elif "RecentDocs" in current_path:
                await self._process_recent_docs(key, registry_data)
            elif "USBSTOR" in current_path:
                await self._process_usb_devices(key, registry_data)
            
            # Process subkeys (limit recursion depth)
            if current_path.count("\\") < 10:  # Prevent too deep recursion
                for subkey in key.subkeys():
                    await self._process_key(subkey, registry_data, current_path)
                    
        except Exception as e:
            logger.debug(f"Error processing key {path}: {str(e)}")
    
    def _extract_value_data(self, value) -> str:
        """Extract data from registry value"""
        try:
            if value.value_type() == Registry.RegSZ or value.value_type() == Registry.RegExpandSZ:
                return str(value.value())
            elif value.value_type() == Registry.RegMultiSZ:
                return "; ".join(value.value())
            elif value.value_type() == Registry.RegDWord:
                return str(value.value())
            elif value.value_type() == Registry.RegBin:
                # Convert binary to hex string (limit size)
                data = value.value()
                if len(data) <= 256:
                    return data.hex()
                else:
                    return data[:256].hex() + "..."
            else:
                return str(value.value())
        except:
            return ""
    
    def _is_suspicious(self, value_data: str) -> bool:
        """Check if registry value contains suspicious content"""
        if not value_data:
            return False
        
        value_lower = value_data.lower()
        
        # Check against patterns
        for pattern_name, pattern in self.suspicious_patterns.items():
            if pattern.search(value_data):
                return True
        
        # Check against malware indicators
        for category, indicators in self.malware_indicators.items():
            if any(indicator in value_lower for indicator in indicators):
                return True
        
        # Check for obfuscation
        if self._is_obfuscated(value_data):
            return True
        
        return False
    
    def _is_obfuscated(self, value: str) -> bool:
        """Check if value appears to be obfuscated"""
        # Base64 pattern
        if re.match(r'^[A-Za-z0-9+/]{20,}={0,2}$', value):
            return True
        
        # Hex encoded
        if re.match(r'^[0-9A-Fa-f]{32,}$', value):
            return True
        
        # PowerShell encoded command
        if "-enc" in value.lower() or "-e " in value.lower():
            return True
        
        return False
    
    def _get_suspicious_indicators(self, value_data: str) -> List[str]:
        """Get list of suspicious indicators in value"""
        indicators = []
        value_lower = value_data.lower()
        
        # Check patterns
        if self.suspicious_patterns["executable_paths"].search(value_data):
            indicators.append("executable_path")
        if self.suspicious_patterns["network_addresses"].search(value_data):
            indicators.append("network_address")
        if self.suspicious_patterns["urls"].search(value_data):
            indicators.append("url")
        if self.suspicious_patterns["encoded_commands"].search(value_data):
            indicators.append("encoded_command")
        if self.suspicious_patterns["temp_paths"].search(value_data):
            indicators.append("temp_path")
        
        # Check malware indicators
        for category, terms in self.malware_indicators.items():
            if any(term in value_lower for term in terms):
                indicators.append(f"{category}_indicator")
        
        # Check obfuscation
        if self._is_obfuscated(value_data):
            indicators.append("obfuscated")
        
        return indicators
    
    async def _process_run_key(self, key, registry_data: Dict[str, Any], path: str):
        """Process Run/RunOnce keys"""
        for value in key.values():
            try:
                entry = {
                    "name": value.name(),
                    "command": self._extract_value_data(value),
                    "key_path": path,
                    "type": "autostart"
                }
                registry_data["autostart_entries"].append(entry)
            except:
                pass
    
    async def _process_service(self, key, registry_data: Dict[str, Any]):
        """Process service entries"""
        try:
            service_info = {
                "name": key.name(),
                "display_name": "",
                "image_path": "",
                "start_type": "",
                "service_type": ""
            }
            
            for value in key.values():
                name = value.name().lower()
                if name == "displayname":
                    service_info["display_name"] = self._extract_value_data(value)
                elif name == "imagepath":
                    service_info["image_path"] = self._extract_value_data(value)
                elif name == "start":
                    service_info["start_type"] = str(value.value())
                elif name == "type":
                    service_info["service_type"] = str(value.value())
            
            if service_info["image_path"]:
                registry_data["services"].append(service_info)
                
        except:
            pass
    
    async def _process_network_settings(self, key, registry_data: Dict[str, Any]):
        """Process network configuration"""
        try:
            for value in key.values():
                name = value.name()
                data = self._extract_value_data(value)
                
                if name in ["DhcpServer", "DhcpIPAddress", "DefaultGateway", "NameServer"]:
                    registry_data["network_settings"].append({
                        "setting": name,
                        "value": data
                    })
        except:
            pass
    
    async def _process_installed_software(self, key, registry_data: Dict[str, Any]):
        """Process installed software"""
        try:
            software_info = {
                "name": key.name(),
                "display_name": "",
                "version": "",
                "publisher": "",
                "install_date": ""
            }
            
            for value in key.values():
                name = value.name().lower()
                if name == "displayname":
                    software_info["display_name"] = self._extract_value_data(value)
                elif name == "displayversion":
                    software_info["version"] = self._extract_value_data(value)
                elif name == "publisher":
                    software_info["publisher"] = self._extract_value_data(value)
                elif name == "installdate":
                    software_info["install_date"] = self._extract_value_data(value)
            
            if software_info["display_name"]:
                registry_data["installed_software"].append(software_info)
                
        except:
            pass
    
    async def _process_recent_docs(self, key, registry_data: Dict[str, Any]):
        """Process recent documents"""
        try:
            for value in key.values():
                if value.value_type() == Registry.RegBin:
                    # Recent docs are stored as binary data
                    registry_data["recent_docs"].append({
                        "name": value.name(),
                        "data": "Binary data"
                    })
        except:
            pass
    
    async def _process_usb_devices(self, key, registry_data: Dict[str, Any]):
        """Process USB device history"""
        try:
            device_info = {
                "device_id": key.name(),
                "friendly_name": "",
                "first_connected": key.timestamp().isoformat() if key.timestamp() else None
            }
            
            for value in key.values():
                if value.name() == "FriendlyName":
                    device_info["friendly_name"] = self._extract_value_data(value)
            
            registry_data["usb_devices"].append(device_info)
            
        except:
            pass
    
    async def analyze(self, file_path: str, extracted_data: Dict[str, Any]) -> AnalysisResult:
        """Analyze registry data for threats"""
        if not extracted_data.get("extraction_successful"):
            return self._create_error_result(extracted_data.get("error", "Unknown error"))
        
        registry_data = extracted_data.get("registry_data", {})
        threats = []
        severity = Severity.LOW
        risk_score = 0.2
        
        # Analyze autostart entries
        autostart = registry_data.get("autostart_entries", [])
        suspicious_autostart = [e for e in autostart if any(
            ind in e.get("command", "").lower() 
            for cat in self.malware_indicators.values() 
            for ind in cat
        )]
        
        if suspicious_autostart:
            threats.append(ThreatInfo(
                threat_type="Persistence Mechanism",
                description=f"Suspicious autostart entries detected ({len(suspicious_autostart)} entries)",
                severity=Severity.HIGH,
                confidence=0.85,
                evidence={"entries": suspicious_autostart[:5]}
            ))
            severity = Severity.HIGH
            risk_score = max(risk_score, 0.8)
        
        # Analyze suspicious entries
        suspicious_entries = registry_data.get("suspicious_entries", [])
        
        # Group by indicators
        indicator_counts = defaultdict(int)
        for entry in suspicious_entries:
            for indicator in entry.get("suspicious_indicators", []):
                indicator_counts[indicator] += 1
        
        if indicator_counts.get("obfuscated", 0) > 3:
            threats.append(ThreatInfo(
                threat_type="Obfuscated Registry Values",
                description="Multiple obfuscated registry values detected",
                severity=Severity.HIGH,
                confidence=0.8,
                evidence={"obfuscated_count": indicator_counts["obfuscated"]}
            ))
            severity = Severity.HIGH
            risk_score = max(risk_score, 0.75)
        
        if indicator_counts.get("encoded_command", 0) > 0:
            threats.append(ThreatInfo(
                threat_type="Encoded Commands",
                description="Encoded PowerShell commands in registry",
                severity=Severity.HIGH,
                confidence=0.9,
                evidence={"encoded_commands": indicator_counts["encoded_command"]}
            ))
            severity = Severity.HIGH
            risk_score = max(risk_score, 0.85)
        
        # Check for specific malware patterns
        for category in ["ransomware", "backdoor", "trojan"]:
            indicator_key = f"{category}_indicator"
            if indicator_counts.get(indicator_key, 0) > 0:
                threats.append(ThreatInfo(
                    threat_type=f"Potential {category.title()}",
                    description=f"Registry entries matching {category} patterns",
                    severity=Severity.CRITICAL,
                    confidence=0.75,
                    evidence={f"{category}_indicators": indicator_counts[indicator_key]}
                ))
                severity = Severity.CRITICAL
                risk_score = max(risk_score, 0.9)
        
        # Analyze services
        services = registry_data.get("services", [])
        suspicious_services = [s for s in services if self._is_suspicious(s.get("image_path", ""))]
        
        if suspicious_services:
            threats.append(ThreatInfo(
                threat_type="Suspicious Services",
                description=f"Services with suspicious characteristics ({len(suspicious_services)} services)",
                severity=Severity.MEDIUM,
                confidence=0.7,
                evidence={"services": suspicious_services[:5]}
            ))
            if severity == Severity.LOW:
                severity = Severity.MEDIUM
            risk_score = max(risk_score, 0.6)
        
        # Extract IOCs
        iocs = self._extract_iocs(registry_data)
        
        # Generate summary
        summary = self._generate_summary(registry_data, threats)
        
        # Recommendations
        recommendations = self._generate_recommendations(threats, registry_data)
        
        return AnalysisResult(
            file_path=file_path,
            parser_name=self.name,
            analysis_type="Registry Forensic Analysis",
            timestamp=datetime.now(),
            summary=summary,
            details={
                "hive_type": registry_data.get("hive_name", "Unknown"),
                "total_keys": registry_data.get("total_keys", 0),
                "total_values": registry_data.get("total_values", 0),
                "autostart_entries": len(autostart),
                "suspicious_entries": len(suspicious_entries),
                "services_analyzed": len(services),
                "installed_software": len(registry_data.get("installed_software", [])),
                "usb_devices": len(registry_data.get("usb_devices", []))
            },
            threats_detected=threats,
            iocs_found=iocs,
            severity=severity,
            risk_score=risk_score,
            recommendations=recommendations
        )
    
    def _generate_summary(self, registry_data: Dict[str, Any], threats: List[ThreatInfo]) -> str:
        """Generate analysis summary"""
        hive = registry_data.get("hive_name", "Unknown")
        keys = registry_data.get("total_keys", 0)
        suspicious = len(registry_data.get("suspicious_entries", []))
        
        summary = f"Analyzed {hive} registry hive with {keys} keys. "
        
        if suspicious > 0:
            summary += f"Found {suspicious} suspicious entries. "
        
        autostart = len(registry_data.get("autostart_entries", []))
        if autostart > 0:
            summary += f"Identified {autostart} autostart entries. "
        
        if threats:
            summary += f"Detected {len(threats)} potential threats. "
        else:
            summary += "No significant threats detected. "
        
        return summary
    
    def _generate_recommendations(self, threats: List[ThreatInfo], registry_data: Dict[str, Any]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        if any(t.threat_type == "Persistence Mechanism" for t in threats):
            recommendations.append("Review and remove suspicious autostart entries")
            recommendations.append("Monitor registry Run keys for changes")
            recommendations.append("Implement application whitelisting")
        
        if any("Obfuscated" in t.threat_type for t in threats):
            recommendations.append("Investigate obfuscated registry values for malicious content")
            recommendations.append("Decode and analyze suspicious encoded commands")
        
        if any("Potential" in t.threat_type and any(m in t.threat_type.lower() for m in ["ransomware", "backdoor", "trojan"]) for t in threats):
            recommendations.append("Perform full system malware scan")
            recommendations.append("Check for active malicious processes")
            recommendations.append("Review network connections for C2 communication")
        
        if any(t.threat_type == "Suspicious Services" for t in threats):
            recommendations.append("Audit all system services for legitimacy")
            recommendations.append("Disable unnecessary or suspicious services")
        
        if not recommendations:
            recommendations.append("Continue monitoring registry for suspicious changes")
            recommendations.append("Implement registry auditing")
        
        return recommendations[:5]
    
    def _extract_iocs(self, registry_data: Dict[str, Any]) -> List[IOC]:
        """Extract IOCs from registry data"""
        iocs = []
        seen_values = set()
        
        # Extract from suspicious entries
        for entry in registry_data.get("suspicious_entries", [])[:30]:
            value_data = entry.get("value_data", "")
            
            # Extract file paths
            if "executable_path" in entry.get("suspicious_indicators", []):
                exe_pattern = re.compile(r'([A-Za-z]:\\[^"<>|?*\n\r]+\.(?:exe|dll|bat|cmd|ps1))', re.IGNORECASE)
                paths = exe_pattern.findall(value_data)
                
                for path in paths[:2]:
                    if path not in seen_values:
                        iocs.append(IOC(
                            type=IOCType.FILE_PATH,
                            value=path,
                            confidence=0.8,
                            source="Registry",
                            description=f"Executable path in {entry.get('category', 'registry')}"
                        ))
                        seen_values.add(path)
            
            # Extract IPs
            ips = self.suspicious_patterns["network_addresses"].findall(value_data)
            for ip in ips[:2]:
                if ip not in seen_values and not ip.startswith("192.168.") and not ip.startswith("10."):
                    iocs.append(IOC(
                        type=IOCType.IP_ADDRESS,
                        value=ip,
                        confidence=0.7,
                        source="Registry",
                        description="IP address in registry value"
                    ))
                    seen_values.add(ip)
            
            # Extract URLs
            urls = self.suspicious_patterns["urls"].findall(value_data)
            for url in urls[:2]:
                if url not in seen_values:
                    iocs.append(IOC(
                        type=IOCType.URL,
                        value=url,
                        confidence=0.8,
                        source="Registry",
                        description="URL in registry value"
                    ))
                    seen_values.add(url)
        
        # Extract from services
        for service in registry_data.get("services", [])[:20]:
            image_path = service.get("image_path", "")
            if image_path and image_path not in seen_values:
                # Clean up the path
                clean_path = image_path.strip('"').split()[0]  # Remove quotes and parameters
                if clean_path.lower().endswith(('.exe', '.dll')):
                    iocs.append(IOC(
                        type=IOCType.FILE_PATH,
                        value=clean_path,
                        confidence=0.9,
                        source="Windows Service",
                        description=f"Service: {service.get('name', 'Unknown')}"
                    ))
                    seen_values.add(image_path)
        
        return iocs[:50]  # Limit total IOCs
    
    def _create_error_result(self, error_message: str) -> AnalysisResult:
        """Create error result for failed analysis"""
        return AnalysisResult(
            file_path="",
            parser_name=self.name,
            analysis_type="Registry Forensic Analysis",
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
    return RegistryParser()