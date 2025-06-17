"""
Network packet capture (PCAP) parser for SecuNik
Analyzes network traffic for security threats and IOCs
"""

import json
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional, Set
from pathlib import Path
import pyshark
import asyncio
from collections import defaultdict, Counter

from ....models.analysis import (
    AnalysisResult, IOC, IOCType, Severity, ThreatInfo
)
from ..base.abstract_parser import AbstractParser

logger = logging.getLogger(__name__)

class PCAPParser(AbstractParser):
    """Parser for network packet capture files"""
    
    name = "PCAP Network Parser"
    supported_extensions = [".pcap", ".pcapng", ".cap"]
    
    def __init__(self):
        super().__init__()
        self.suspicious_ports = {
            20: "FTP Data", 21: "FTP Control", 22: "SSH", 23: "Telnet",
            25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
            443: "HTTPS", 445: "SMB", 1433: "MSSQL", 3306: "MySQL",
            3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP-Alt",
            # Known malware ports
            4444: "Metasploit Default", 5555: "Android Debug Bridge",
            6666: "IRC Bot", 7777: "Oracle Backdoor", 8888: "Proxy",
            9999: "Telnet Backdoor", 12345: "NetBus", 31337: "Back Orifice"
        }
        
        self.malicious_domains = {
            "malware", "phishing", "c2server", "botnet", "exploit",
            "ransomware", "trojan", "backdoor", "rootkit", "keylogger"
        }
    
    async def parse(self, file_path: str) -> Dict[str, Any]:
        """Parse PCAP file and extract network data"""
        try:
            cap = pyshark.FileCapture(
                file_path,
                use_json=True,
                include_raw=True
            )
            
            network_data = {
                "total_packets": 0,
                "protocols": defaultdict(int),
                "conversations": defaultdict(lambda: {"packets": 0, "bytes": 0}),
                "dns_queries": [],
                "http_requests": [],
                "suspicious_traffic": [],
                "top_talkers": defaultdict(int),
                "port_scan_detection": defaultdict(set),
                "timeline": []
            }
            
            # Process packets
            packet_count = 0
            for packet in cap:
                packet_count += 1
                network_data["total_packets"] = packet_count
                
                # Extract basic info
                timestamp = float(packet.sniff_timestamp)
                packet_info = {
                    "timestamp": datetime.fromtimestamp(timestamp).isoformat(),
                    "length": int(packet.length),
                    "number": packet_count
                }
                
                # Protocol analysis
                if hasattr(packet, 'highest_layer'):
                    protocol = packet.highest_layer
                    network_data["protocols"][protocol] += 1
                
                # IP layer analysis
                if hasattr(packet, 'ip'):
                    src_ip = packet.ip.src
                    dst_ip = packet.ip.dst
                    
                    # Track conversations
                    conv_key = f"{src_ip} <-> {dst_ip}"
                    network_data["conversations"][conv_key]["packets"] += 1
                    network_data["conversations"][conv_key]["bytes"] += int(packet.length)
                    
                    # Track top talkers
                    network_data["top_talkers"][src_ip] += int(packet.length)
                    network_data["top_talkers"][dst_ip] += int(packet.length)
                    
                    packet_info["src_ip"] = src_ip
                    packet_info["dst_ip"] = dst_ip
                
                # TCP/UDP port analysis
                if hasattr(packet, 'tcp'):
                    src_port = int(packet.tcp.srcport)
                    dst_port = int(packet.tcp.dstport)
                    packet_info["src_port"] = src_port
                    packet_info["dst_port"] = dst_port
                    packet_info["protocol"] = "TCP"
                    
                    # Port scan detection
                    if hasattr(packet.tcp, 'flags_syn') and packet.tcp.flags_syn == '1':
                        if hasattr(packet.tcp, 'flags_ack') and packet.tcp.flags_ack == '0':
                            network_data["port_scan_detection"][src_ip].add(dst_port)
                    
                    # Check suspicious ports
                    if dst_port in self.suspicious_ports:
                        network_data["suspicious_traffic"].append({
                            "type": "suspicious_port",
                            "description": f"Traffic to {self.suspicious_ports[dst_port]} port {dst_port}",
                            "src": f"{src_ip}:{src_port}",
                            "dst": f"{dst_ip}:{dst_port}",
                            "timestamp": packet_info["timestamp"]
                        })
                
                elif hasattr(packet, 'udp'):
                    src_port = int(packet.udp.srcport)
                    dst_port = int(packet.udp.dstport)
                    packet_info["src_port"] = src_port
                    packet_info["dst_port"] = dst_port
                    packet_info["protocol"] = "UDP"
                
                # DNS analysis
                if hasattr(packet, 'dns'):
                    if hasattr(packet.dns, 'qry_name'):
                        domain = packet.dns.qry_name.lower()
                        dns_query = {
                            "domain": domain,
                            "timestamp": packet_info["timestamp"],
                            "src_ip": packet_info.get("src_ip", "unknown")
                        }
                        network_data["dns_queries"].append(dns_query)
                        
                        # Check for suspicious domains
                        if any(mal in domain for mal in self.malicious_domains):
                            network_data["suspicious_traffic"].append({
                                "type": "suspicious_domain",
                                "description": f"DNS query for suspicious domain: {domain}",
                                "src": packet_info.get("src_ip", "unknown"),
                                "timestamp": packet_info["timestamp"]
                            })
                
                # HTTP analysis
                if hasattr(packet, 'http'):
                    http_req = {
                        "timestamp": packet_info["timestamp"],
                        "src_ip": packet_info.get("src_ip", "unknown"),
                        "dst_ip": packet_info.get("dst_ip", "unknown")
                    }
                    
                    if hasattr(packet.http, 'request_method'):
                        http_req["method"] = packet.http.request_method
                        http_req["uri"] = getattr(packet.http, 'request_uri', '')
                        http_req["host"] = getattr(packet.http, 'host', '')
                        network_data["http_requests"].append(http_req)
                
                # Add to timeline
                network_data["timeline"].append(packet_info)
                
                # Limit processing for large files
                if packet_count >= 10000:
                    logger.warning(f"Large PCAP file, limiting analysis to first 10000 packets")
                    break
            
            cap.close()
            
            # Post-processing
            network_data["conversations"] = dict(network_data["conversations"])
            network_data["top_talkers"] = dict(
                sorted(network_data["top_talkers"].items(), 
                       key=lambda x: x[1], reverse=True)[:10]
            )
            network_data["protocols"] = dict(network_data["protocols"])
            
            # Port scan detection
            port_scanners = []
            for ip, ports in network_data["port_scan_detection"].items():
                if len(ports) > 10:
                    port_scanners.append({
                        "ip": ip,
                        "ports_scanned": len(ports),
                        "sample_ports": list(ports)[:10]
                    })
            
            if port_scanners:
                network_data["suspicious_traffic"].append({
                    "type": "port_scan",
                    "description": "Potential port scanning detected",
                    "scanners": port_scanners
                })
            
            # Clean up
            del network_data["port_scan_detection"]
            network_data["timeline"] = network_data["timeline"][:100]  # Keep first 100 packets
            
            return {
                "extraction_successful": True,
                "network_data": network_data
            }
            
        except Exception as e:
            logger.error(f"Failed to parse PCAP file: {str(e)}")
            return {
                "extraction_successful": False,
                "error": str(e)
            }
    
    async def analyze(self, file_path: str, extracted_data: Dict[str, Any]) -> AnalysisResult:
        """Analyze PCAP data for threats"""
        if not extracted_data.get("extraction_successful"):
            return self._create_error_result(extracted_data.get("error", "Unknown error"))
        
        network_data = extracted_data.get("network_data", {})
        threats = []
        severity = Severity.LOW
        risk_score = 0.2
        
        # Analyze suspicious traffic
        suspicious = network_data.get("suspicious_traffic", [])
        if suspicious:
            threat_types = [s["type"] for s in suspicious]
            
            if "port_scan" in threat_types:
                threats.append(ThreatInfo(
                    threat_type="Network Reconnaissance",
                    description="Port scanning activity detected",
                    severity=Severity.HIGH,
                    confidence=0.9,
                    evidence={"suspicious_traffic": suspicious[:5]}
                ))
                severity = Severity.HIGH
                risk_score = max(risk_score, 0.8)
            
            if "suspicious_domain" in threat_types:
                threats.append(ThreatInfo(
                    threat_type="Malicious Communication",
                    description="Communication with suspicious domains detected",
                    severity=Severity.HIGH,
                    confidence=0.85,
                    evidence={"suspicious_domains": [s for s in suspicious if s["type"] == "suspicious_domain"][:5]}
                ))
                severity = Severity.HIGH
                risk_score = max(risk_score, 0.85)
            
            if "suspicious_port" in threat_types:
                threats.append(ThreatInfo(
                    threat_type="Suspicious Network Activity",
                    description="Traffic on suspicious ports detected",
                    severity=Severity.MEDIUM,
                    confidence=0.7,
                    evidence={"suspicious_ports": [s for s in suspicious if s["type"] == "suspicious_port"][:5]}
                ))
                if severity == Severity.LOW:
                    severity = Severity.MEDIUM
                risk_score = max(risk_score, 0.6)
        
        # Extract IOCs
        iocs = self._extract_iocs(network_data)
        
        # Generate summary
        summary = self._generate_summary(network_data, threats)
        
        # Recommendations
        recommendations = self._generate_recommendations(threats, network_data)
        
        return AnalysisResult(
            file_path=file_path,
            parser_name=self.name,
            analysis_type="Network Traffic Analysis",
            timestamp=datetime.now(),
            summary=summary,
            details={
                "total_packets": network_data.get("total_packets", 0),
                "protocols": network_data.get("protocols", {}),
                "top_conversations": list(network_data.get("conversations", {}).items())[:5],
                "top_talkers": network_data.get("top_talkers", {}),
                "dns_queries_count": len(network_data.get("dns_queries", [])),
                "http_requests_count": len(network_data.get("http_requests", [])),
                "suspicious_activities": len(suspicious)
            },
            threats_detected=threats,
            iocs_found=iocs,
            severity=severity,
            risk_score=risk_score,
            recommendations=recommendations
        )
    
    def _generate_summary(self, network_data: Dict[str, Any], threats: List[ThreatInfo]) -> str:
        """Generate analysis summary"""
        packets = network_data.get("total_packets", 0)
        protocols = network_data.get("protocols", {})
        suspicious = len(network_data.get("suspicious_traffic", []))
        
        summary = f"Analyzed {packets} network packets. "
        
        if protocols:
            top_protocol = max(protocols.items(), key=lambda x: x[1])
            summary += f"Primary protocol: {top_protocol[0]}. "
        
        if suspicious > 0:
            summary += f"Found {suspicious} suspicious activities. "
        
        if threats:
            summary += f"Detected {len(threats)} potential threats. "
        else:
            summary += "No significant threats detected. "
        
        return summary
    
    def _generate_recommendations(self, threats: List[ThreatInfo], network_data: Dict[str, Any]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        if any(t.threat_type == "Network Reconnaissance" for t in threats):
            recommendations.append("Implement network segmentation to limit port scanning impact")
            recommendations.append("Deploy intrusion detection systems (IDS) to detect scanning activities")
            recommendations.append("Configure firewall rules to block unnecessary ports")
        
        if any(t.threat_type == "Malicious Communication" for t in threats):
            recommendations.append("Block identified malicious domains at DNS/firewall level")
            recommendations.append("Implement DNS filtering and monitoring")
            recommendations.append("Investigate systems communicating with suspicious domains")
        
        suspicious_ports = [s for s in network_data.get("suspicious_traffic", []) 
                          if s["type"] == "suspicious_port"]
        if suspicious_ports:
            recommendations.append("Review and restrict access to suspicious ports")
            recommendations.append("Monitor traffic on non-standard ports")
        
        if not recommendations:
            recommendations.append("Continue monitoring network traffic for anomalies")
            recommendations.append("Maintain up-to-date network security policies")
        
        return recommendations[:5]  # Limit to 5 recommendations
    
    def _extract_iocs(self, network_data: Dict[str, Any]) -> List[IOC]:
        """Extract IOCs from network data"""
        iocs = []
        seen_values = set()
        
        # Extract IPs from conversations
        for conv in list(network_data.get("conversations", {}).keys())[:20]:
            ips = conv.split(" <-> ")
            for ip in ips:
                if ip not in seen_values and not ip.startswith("192.168.") and not ip.startswith("10."):
                    iocs.append(IOC(
                        type=IOCType.IP_ADDRESS,
                        value=ip,
                        confidence=1.0,
                        source="Network Traffic",
                        description="IP address in network communication"
                    ))
                    seen_values.add(ip)
        
        # Extract domains from DNS queries
        for dns in network_data.get("dns_queries", [])[:20]:
            domain = dns.get("domain", "").rstrip(".")
            if domain and domain not in seen_values:
                iocs.append(IOC(
                    type=IOCType.DOMAIN,
                    value=domain,
                    confidence=1.0,
                    source="DNS Query",
                    description="Domain from DNS query"
                ))
                seen_values.add(domain)
        
        # Extract URLs from HTTP requests
        for http in network_data.get("http_requests", [])[:20]:
            host = http.get("host", "")
            uri = http.get("uri", "")
            if host and uri:
                url = f"http://{host}{uri}"
                if url not in seen_values:
                    iocs.append(IOC(
                        type=IOCType.URL,
                        value=url,
                        confidence=1.0,
                        source="HTTP Request",
                        description="URL from HTTP traffic"
                    ))
                    seen_values.add(url)
        
        return iocs
    
    def _create_error_result(self, error_message: str) -> AnalysisResult:
        """Create error result for failed analysis"""
        return AnalysisResult(
            file_path="",
            parser_name=self.name,
            analysis_type="Network Traffic Analysis",
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
    return PCAPParser()