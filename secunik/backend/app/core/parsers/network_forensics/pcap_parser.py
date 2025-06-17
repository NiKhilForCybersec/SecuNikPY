"""
SecuNik - Network Packet Analyzer (PCAP) Parser - Pure Data Extractor
Extracts raw network traffic data for AI analysis

Location: backend/app/core/parsers/network_forensics/pcap_parser.py
"""

import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any, Set
from pathlib import Path
from collections import Counter, defaultdict
import ipaddress

try:
    from scapy.all import rdpcap, IP, TCP, UDP, DNS, ICMP, ARP, Ether
    from scapy.layers.http import HTTPRequest, HTTPResponse
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from ....models.analysis import AnalysisResult, Severity, IOC, IOCType

logger = logging.getLogger(__name__)

class PCAPParser:
    """Pure Data Extractor for Network Packet Analysis - AI analyzes the data"""
    
    def __init__(self):
        self.name = "Network Packet Analyzer"
        self.version = "2.0.0"
        self.supported_formats = [".pcap", ".pcapng", ".cap"]

    def can_parse(self, file_path: str) -> bool:
        """Check if file can be parsed by this parser"""
        return Path(file_path).suffix.lower() in self.supported_formats and SCAPY_AVAILABLE

    def parse(self, file_path: str) -> AnalysisResult:
        """Extract raw network traffic data - AI will analyze for threats"""
        try:
            if not SCAPY_AVAILABLE:
                return self._create_error_result("scapy library not available")
            
            logger.info(f"Extracting network traffic data: {file_path}")
            
            # Load packet capture
            packets = rdpcap(file_path)
            logger.info(f"Loaded {len(packets)} packets")
            
            # Extract raw traffic data
            traffic_data = self._extract_traffic_data(packets)
            
            # Extract factual IOCs
            iocs = self._extract_factual_iocs(traffic_data)
            
            # Create analysis result with extracted data (AI will determine threats and recommendations)
            result = AnalysisResult(
                file_path=file_path,
                parser_name=self.name,
                analysis_type="Network Traffic Data Extraction",
                timestamp=datetime.now(),
                summary=f"Extracted data from {len(packets)} network packets for AI analysis",
                details=traffic_data,
                threats_detected=[],  # AI will determine threats
                iocs_found=iocs,
                severity=Severity.LOW,  # AI will determine severity
                risk_score=0.0,  # AI will calculate risk score
                recommendations=["Data extracted - pending AI analysis for threat assessment and recommendations"]
            )
            
            logger.info(f"PCAP data extraction completed: {len(packets)} packets processed")
            return result
            
        except Exception as e:
            logger.error(f"Error extracting PCAP data {file_path}: {str(e)}")
            return self._create_error_result(str(e))

    def _extract_traffic_data(self, packets) -> Dict[str, Any]:
        """Extract comprehensive traffic data from packets"""
        traffic_data = {
            "capture_summary": self._get_capture_summary(packets),
            "protocol_distribution": self._analyze_protocols(packets),
            "ip_analysis": self._analyze_ip_traffic(packets),
            "dns_analysis": self._analyze_dns_traffic(packets),
            "http_analysis": self._analyze_http_traffic(packets),
            "port_analysis": self._analyze_port_usage(packets),
            "flow_analysis": self._analyze_network_flows(packets),
            "timeline_sample": self._build_traffic_timeline(packets),
            "geographic_data": self._extract_geographic_indicators(packets),
            "connection_patterns": self._analyze_connection_patterns(packets)
        }
        
        return traffic_data

    def _get_capture_summary(self, packets) -> Dict[str, Any]:
        """Get basic capture information"""
        if not packets:
            return {}
        
        # Calculate basic statistics
        total_bytes = sum(len(packet) for packet in packets)
        duration = self._get_capture_duration(packets)
        
        return {
            "total_packets": len(packets),
            "total_bytes": total_bytes,
            "duration_seconds": duration,
            "average_packet_size": total_bytes / len(packets) if packets else 0,
            "packets_per_second": len(packets) / duration if duration > 0 else 0,
            "bytes_per_second": total_bytes / duration if duration > 0 else 0,
            "start_time": min(float(packet.time) for packet in packets if hasattr(packet, 'time')),
            "end_time": max(float(packet.time) for packet in packets if hasattr(packet, 'time'))
        }

    def _analyze_protocols(self, packets) -> Dict[str, Any]:
        """Analyze protocol distribution"""
        protocol_counts = Counter()
        layer_counts = Counter()
        
        for packet in packets:
            # Count IP protocols
            if IP in packet:
                if packet[IP].proto == 6:
                    protocol_counts["TCP"] += 1
                elif packet[IP].proto == 17:
                    protocol_counts["UDP"] += 1
                elif packet[IP].proto == 1:
                    protocol_counts["ICMP"] += 1
                else:
                    protocol_counts[f"Protocol_{packet[IP].proto}"] += 1
            
            # Count higher layer protocols
            if DNS in packet:
                layer_counts["DNS"] += 1
            if HTTPRequest in packet or HTTPResponse in packet:
                layer_counts["HTTP"] += 1
            if ARP in packet:
                layer_counts["ARP"] += 1
        
        return {
            "ip_protocols": dict(protocol_counts),
            "application_protocols": dict(layer_counts),
            "total_protocols": len(protocol_counts) + len(layer_counts)
        }

    def _analyze_ip_traffic(self, packets) -> Dict[str, Any]:
        """Analyze IP traffic patterns"""
        ip_stats = {
            "unique_ips": set(),
            "internal_ips": set(),
            "external_ips": set(),
            "traffic_volume": Counter(),
            "ip_conversations": defaultdict(int)
        }
        
        for packet in packets:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                packet_size = len(packet)
                
                ip_stats["unique_ips"].add(src_ip)
                ip_stats["unique_ips"].add(dst_ip)
                ip_stats["traffic_volume"][src_ip] += packet_size
                ip_stats["traffic_volume"][dst_ip] += packet_size
                
                # Classify internal vs external
                try:
                    src_ip_obj = ipaddress.ip_address(src_ip)
                    dst_ip_obj = ipaddress.ip_address(dst_ip)
                    
                    if src_ip_obj.is_private:
                        ip_stats["internal_ips"].add(src_ip)
                    else:
                        ip_stats["external_ips"].add(src_ip)
                    
                    if dst_ip_obj.is_private:
                        ip_stats["internal_ips"].add(dst_ip)
                    else:
                        ip_stats["external_ips"].add(dst_ip)
                        
                except ValueError:
                    pass
                
                # Track conversations
                conversation = tuple(sorted([src_ip, dst_ip]))
                ip_stats["ip_conversations"][conversation] += 1
        
        # Convert sets to lists for JSON serialization
        return {
            "total_unique_ips": len(ip_stats["unique_ips"]),
            "internal_ips": list(ip_stats["internal_ips"]),
            "external_ips": list(ip_stats["external_ips"]),
            "top_talkers": dict(ip_stats["traffic_volume"].most_common(20)),
            "top_conversations": dict(ip_stats["ip_conversations"].most_common(20))
        }

    def _analyze_dns_traffic(self, packets) -> Dict[str, Any]:
        """Extract DNS traffic information"""
        dns_data = {
            "total_queries": 0,
            "total_responses": 0,
            "queried_domains": Counter(),
            "query_types": Counter(),
            "response_codes": Counter(),
            "dns_servers": set()
        }
        
        for packet in packets:
            if DNS in packet:
                dns = packet[DNS]
                
                if dns.qr == 0:  # DNS query
                    dns_data["total_queries"] += 1
                    if dns.qd:
                        domain = dns.qd.qname.decode('utf-8').rstrip('.')
                        dns_data["queried_domains"][domain] += 1
                        dns_data["query_types"][dns.qd.qtype] += 1
                    
                    if IP in packet:
                        dns_data["dns_servers"].add(packet[IP].dst)
                
                elif dns.qr == 1:  # DNS response
                    dns_data["total_responses"] += 1
                    dns_data["response_codes"][dns.rcode] += 1
        
        return {
            "total_queries": dns_data["total_queries"],
            "total_responses": dns_data["total_responses"],
            "unique_domains": len(dns_data["queried_domains"]),
            "top_domains": dict(dns_data["queried_domains"].most_common(20)),
            "query_types": dict(dns_data["query_types"]),
            "response_codes": dict(dns_data["response_codes"]),
            "dns_servers": list(dns_data["dns_servers"])
        }

    def _analyze_http_traffic(self, packets) -> Dict[str, Any]:
        """Extract HTTP traffic information"""
        http_data = {
            "total_requests": 0,
            "total_responses": 0,
            "hosts": Counter(),
            "user_agents": Counter(),
            "methods": Counter(),
            "status_codes": Counter(),
            "sample_requests": []
        }
        
        for packet in packets:
            if HTTPRequest in packet:
                http_data["total_requests"] += 1
                http_req = packet[HTTPRequest]
                
                if http_req.Host:
                    host = http_req.Host.decode('utf-8')
                    http_data["hosts"][host] += 1
                
                if http_req.User_Agent:
                    user_agent = http_req.User_Agent.decode('utf-8')
                    http_data["user_agents"][user_agent] += 1
                
                if http_req.Method:
                    method = http_req.Method.decode('utf-8')
                    http_data["methods"][method] += 1
                
                # Sample requests for analysis
                if len(http_data["sample_requests"]) < 10:
                    request_info = {
                        "method": http_req.Method.decode('utf-8') if http_req.Method else "Unknown",
                        "host": http_req.Host.decode('utf-8') if http_req.Host else "Unknown",
                        "path": http_req.Path.decode('utf-8') if http_req.Path else "/",
                        "user_agent": http_req.User_Agent.decode('utf-8') if http_req.User_Agent else "Unknown",
                        "src_ip": packet[IP].src if IP in packet else "Unknown"
                    }
                    http_data["sample_requests"].append(request_info)
            
            elif HTTPResponse in packet:
                http_data["total_responses"] += 1
                # Additional response analysis could be added here
        
        return {
            "total_requests": http_data["total_requests"],
            "total_responses": http_data["total_responses"],
            "unique_hosts": len(http_data["hosts"]),
            "top_hosts": dict(http_data["hosts"].most_common(10)),
            "top_user_agents": dict(http_data["user_agents"].most_common(10)),
            "methods": dict(http_data["methods"]),
            "sample_requests": http_data["sample_requests"]
        }

    def _analyze_port_usage(self, packets) -> Dict[str, Any]:
        """Analyze port usage patterns"""
        port_data = {
            "tcp_ports": Counter(),
            "udp_ports": Counter(),
            "port_pairs": Counter()
        }
        
        for packet in packets:
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                port_data["tcp_ports"][dst_port] += 1
                port_data["port_pairs"][f"{src_port}->{dst_port}"] += 1
            
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                port_data["udp_ports"][dst_port] += 1
                port_data["port_pairs"][f"{src_port}->{dst_port}"] += 1
        
        return {
            "top_tcp_ports": dict(port_data["tcp_ports"].most_common(20)),
            "top_udp_ports": dict(port_data["udp_ports"].most_common(20)),
            "top_port_pairs": dict(port_data["port_pairs"].most_common(20))
        }

    def _analyze_network_flows(self, packets) -> Dict[str, Any]:
        """Analyze network flows"""
        flows = defaultdict(lambda: {
            "packets": 0, "bytes": 0, "start_time": None, "end_time": None,
            "src_ip": None, "dst_ip": None, "src_port": None, "dst_port": None,
            "protocol": None
        })
        
        for packet in packets:
            if IP not in packet:
                continue
                
            flow_key = self._get_flow_key(packet)
            flow = flows[flow_key]
            timestamp = float(packet.time) if hasattr(packet, 'time') else 0
            
            # Update flow information
            flow["packets"] += 1
            flow["bytes"] += len(packet)
            
            if flow["start_time"] is None or timestamp < flow["start_time"]:
                flow["start_time"] = timestamp
            if flow["end_time"] is None or timestamp > flow["end_time"]:
                flow["end_time"] = timestamp
            
            # Extract connection details
            if flow["src_ip"] is None:
                flow["src_ip"] = packet[IP].src
                flow["dst_ip"] = packet[IP].dst
                flow["protocol"] = packet[IP].proto
                
                if TCP in packet:
                    flow["src_port"] = packet[TCP].sport
                    flow["dst_port"] = packet[TCP].dport
                elif UDP in packet:
                    flow["src_port"] = packet[UDP].sport
                    flow["dst_port"] = packet[UDP].dport
        
        # Convert to list and add analysis
        flow_list = []
        for flow_key, flow_data in flows.items():
            flow_data["flow_id"] = flow_key
            flow_data["duration"] = (flow_data["end_time"] or 0) - (flow_data["start_time"] or 0)
            
            if flow_data["duration"] > 0:
                flow_data["packets_per_second"] = flow_data["packets"] / flow_data["duration"]
                flow_data["bytes_per_second"] = flow_data["bytes"] / flow_data["duration"]
            else:
                flow_data["packets_per_second"] = 0
                flow_data["bytes_per_second"] = 0
            
            flow_list.append(flow_data)
        
        # Sort by bytes (largest flows first) and limit for performance
        top_flows = sorted(flow_list, key=lambda x: x["bytes"], reverse=True)[:50]
        
        return {
            "total_flows": len(flow_list),
            "top_flows_by_volume": top_flows[:20],
            "flow_statistics": {
                "avg_flow_duration": sum(f["duration"] for f in flow_list) / len(flow_list) if flow_list else 0,
                "avg_flow_bytes": sum(f["bytes"] for f in flow_list) / len(flow_list) if flow_list else 0,
                "total_flow_bytes": sum(f["bytes"] for f in flow_list)
            }
        }

    def _get_flow_key(self, packet) -> str:
        """Generate flow key for packet"""
        if IP not in packet:
            return "unknown_flow"
        
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        
        src_port = dst_port = 0
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        
        # Normalize flow (smaller IP first)
        if src_ip < dst_ip:
            return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
        else:
            return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"

    def _build_traffic_timeline(self, packets) -> List[Dict[str, Any]]:
        """Build sample timeline of network events"""
        timeline = []
        
        # Sample packets for timeline (take every nth packet)
        sample_size = min(50, len(packets))
        step = max(1, len(packets) // sample_size)
        sample_packets = packets[::step]
        
        for packet in sample_packets:
            if IP in packet:
                timeline_entry = {
                    "timestamp": float(packet.time) if hasattr(packet, 'time') else 0,
                    "src_ip": packet[IP].src,
                    "dst_ip": packet[IP].dst,
                    "protocol": packet[IP].proto,
                    "size": len(packet)
                }
                
                if TCP in packet:
                    timeline_entry["src_port"] = packet[TCP].sport
                    timeline_entry["dst_port"] = packet[TCP].dport
                    timeline_entry["protocol_name"] = "TCP"
                elif UDP in packet:
                    timeline_entry["src_port"] = packet[UDP].sport
                    timeline_entry["dst_port"] = packet[UDP].dport
                    timeline_entry["protocol_name"] = "UDP"
                elif ICMP in packet:
                    timeline_entry["protocol_name"] = "ICMP"
                
                timeline.append(timeline_entry)
        
        return sorted(timeline, key=lambda x: x["timestamp"])

    def _extract_geographic_indicators(self, packets) -> Dict[str, Any]:
        """Extract geographic indicators from traffic"""
        # This would typically include GeoIP lookups, but for now we'll extract basic patterns
        external_ips = set()
        
        for packet in packets:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                try:
                    src_ip_obj = ipaddress.ip_address(src_ip)
                    dst_ip_obj = ipaddress.ip_address(dst_ip)
                    
                    if not src_ip_obj.is_private:
                        external_ips.add(src_ip)
                    if not dst_ip_obj.is_private:
                        external_ips.add(dst_ip)
                        
                except ValueError:
                    pass
        
        return {
            "external_ips": list(external_ips),
            "external_ip_count": len(external_ips),
            "geographic_analysis": "GeoIP lookup would be performed here"
        }

    def _analyze_connection_patterns(self, packets) -> Dict[str, Any]:
        """Analyze connection patterns"""
        connection_attempts = 0
        successful_connections = 0
        connection_failures = 0
        
        for packet in packets:
            if TCP in packet:
                flags = packet[TCP].flags
                
                # SYN packet (connection attempt)
                if flags & 0x02:  # SYN flag
                    connection_attempts += 1
                
                # SYN-ACK (successful connection response)
                if flags & 0x12 == 0x12:  # SYN + ACK flags
                    successful_connections += 1
                
                # RST packet (connection failure/reset)
                if flags & 0x04:  # RST flag
                    connection_failures += 1
        
        return {
            "connection_attempts": connection_attempts,
            "successful_connections": successful_connections,
            "connection_failures": connection_failures,
            "success_rate": (successful_connections / connection_attempts * 100) if connection_attempts > 0 else 0
        }

    def _get_capture_duration(self, packets) -> float:
        """Calculate capture duration in seconds"""
        if not packets or len(packets) < 2:
            return 0
        
        timestamps = [float(packet.time) for packet in packets if hasattr(packet, 'time')]
        if not timestamps:
            return 0
        
        return max(timestamps) - min(timestamps)

    def _extract_factual_iocs(self, traffic_data: Dict[str, Any]) -> List[IOC]:
        """Extract factual IOCs from traffic data"""
        iocs = []
        
        # Extract external IP addresses
        ip_analysis = traffic_data.get("ip_analysis", {})
        external_ips = ip_analysis.get("external_ips", [])
        
        for ip in external_ips[:50]:  # Limit to prevent overflow
            iocs.append(IOC(
                type=IOCType.IP_ADDRESS,
                value=ip,
                confidence=1.0,  # Factual extraction
                source="Network Traffic",
                description="External IP address observed in network traffic"
            ))
        
        # Extract domains from DNS traffic
        dns_analysis = traffic_data.get("dns_analysis", {})
        top_domains = dns_analysis.get("top_domains", {})
        
        for domain in list(top_domains.keys())[:30]:  # Limit to prevent overflow
            if domain and '.' in domain:
                iocs.append(IOC(
                    type=IOCType.DOMAIN,
                    value=domain,
                    confidence=1.0,
                    source="DNS Traffic",
                    description="Domain queried in DNS traffic"
                ))
        
        # Extract HTTP hosts as potential URLs
        http_analysis = traffic_data.get("http_analysis", {})
        top_hosts = http_analysis.get("top_hosts", {})
        
        for host in list(top_hosts.keys())[:20]:
            if host:
                url = f"http://{host}"
                iocs.append(IOC(
                    type=IOCType.URL,
                    value=url,
                    confidence=1.0,
                    source="HTTP Traffic",
                    description="HTTP host observed in traffic"
                ))
        
        return iocs

    def _create_error_result(self, error_message: str) -> AnalysisResult:
        """Create error result for failed analysis"""
        return AnalysisResult(
            file_path="",
            parser_name=self.name,
            analysis_type="Network Traffic Data Extraction",
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
    return PCAPParser()