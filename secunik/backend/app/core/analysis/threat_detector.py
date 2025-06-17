"""
Threat Detector for SecuNik
Detects security threats from analysis data
"""

import logging
from typing import Dict, Any, List, Optional, Set
from datetime import datetime
import json

from ...models.analysis import ThreatInfo, Severity, AnalysisResult

logger = logging.getLogger(__name__)

class ThreatDetector:
    """Detects security threats from various data sources"""
    
    def __init__(self):
        # Threat detection rules
        self.detection_rules = {
            'malware_indicators': self._detect_malware_indicators,
            'ransomware_patterns': self._detect_ransomware_patterns,
            'backdoor_signatures': self._detect_backdoor_signatures,
            'data_exfiltration': self._detect_data_exfiltration,
            'persistence_mechanisms': self._detect_persistence_mechanisms,
            'credential_theft': self._detect_credential_theft,
            'lateral_movement': self._detect_lateral_movement,
            'defense_evasion': self._detect_defense_evasion,
            'reconnaissance': self._detect_reconnaissance,
            'exploitation': self._detect_exploitation
        }
        
        # Threat signatures database
        self.signatures = {
            'ransomware_extensions': [
                '.encrypted', '.locked', '.crypto', '.enc', '.crypted',
                '.locky', '.cerber', '.zepto', '.odin', '.aesir',
                '.zzzzz', '.micro', '.encrypted', '.cryptolocker'
            ],
            'ransomware_notes': [
                'your files have been encrypted', 'pay bitcoin',
                'decrypt your files', 'ransom', 'payment instructions',
                'tor browser', 'bitcoin wallet'
            ],
            'backdoor_ports': [
                4444, 5555, 6666, 7777, 8888, 9999, 
                12345, 31337, 1337, 2222, 3333
            ],
            'suspicious_processes': [
                'nc.exe', 'netcat', 'ncat', 'psexec', 'procdump',
                'mimikatz', 'lazagne', 'bloodhound', 'sharphound',
                'cobalt', 'beacon', 'meterpreter', 'empire'
            ],
            'suspicious_commands': [
                'whoami', 'net user', 'net group', 'ipconfig',
                'systeminfo', 'tasklist', 'netstat', 'wmic',
                'vssadmin delete shadows', 'bcdedit', 'cipher /w'
            ],
            'known_malware_hashes': {
                # Add known malware hashes here
                # 'hash': 'malware_family'
            },
            'apt_indicators': {
                'apt28': ['sofacy', 'sednit', 'fancy bear'],
                'apt29': ['cozy bear', 'the dukes', 'yttrium'],
                'lazarus': ['hidden cobra', 'zinc', 'nickel academy']
            }
        }
        
        # MITRE ATT&CK mapping
        self.attack_mapping = {
            'T1055': 'Process Injection',
            'T1053': 'Scheduled Task',
            'T1543': 'Service Creation',
            'T1547': 'Boot or Logon Autostart',
            'T1070': 'Indicator Removal',
            'T1036': 'Masquerading',
            'T1027': 'Obfuscated Files',
            'T1003': 'Credential Dumping',
            'T1078': 'Valid Accounts',
            'T1021': 'Remote Services',
            'T1048': 'Exfiltration Over Protocol',
            'T1567': 'Exfiltration Over Web Service'
        }
    
    async def detect_threats(self, 
                           extracted_data: Dict[str, Any],
                           analysis_result: AnalysisResult) -> List[ThreatInfo]:
        """Detect threats from extracted data and analysis results"""
        threats = []
        
        # Run all detection rules
        for rule_name, rule_func in self.detection_rules.items():
            try:
                rule_threats = await rule_func(extracted_data, analysis_result)
                threats.extend(rule_threats)
            except Exception as e:
                logger.error(f"Error in threat detection rule {rule_name}: {str(e)}")
        
        # Correlate and enhance threats
        enhanced_threats = self._enhance_threat_detection(threats, extracted_data)
        
        # Deduplicate threats
        unique_threats = self._deduplicate_threats(enhanced_threats)
        
        return unique_threats
    
    async def _detect_malware_indicators(self, 
                                       data: Dict[str, Any],
                                       result: AnalysisResult) -> List[ThreatInfo]:
        """Detect general malware indicators"""
        threats = []
        
        # Check for known malware hashes
        for ioc in result.iocs_found:
            if ioc.type.startswith('HASH_') and ioc.value in self.signatures['known_malware_hashes']:
                malware_family = self.signatures['known_malware_hashes'][ioc.value]
                threats.append(ThreatInfo(
                    threat_type="Known Malware",
                    description=f"Known malware detected: {malware_family}",
                    severity=Severity.CRITICAL,
                    confidence=1.0,
                    evidence={
                        'hash': ioc.value,
                        'malware_family': malware_family
                    },
                    mitre_attack_ids=['T1055', 'T1027']
                ))
        
        # Check for suspicious processes
        process_data = data.get('process_data', {})
        for process in process_data.get('processes', []):
            process_name = process.get('name', '').lower()
            if any(susp in process_name for susp in self.signatures['suspicious_processes']):
                threats.append(ThreatInfo(
                    threat_type="Suspicious Process",
                    description=f"Suspicious process detected: {process_name}",
                    severity=Severity.HIGH,
                    confidence=0.8,
                    evidence={
                        'process_name': process_name,
                        'command_line': process.get('command_line', '')
                    },
                    mitre_attack_ids=['T1055']
                ))
        
        # Check PE file characteristics
        if 'pe_data' in data:
            pe_threats = self._analyze_pe_characteristics(data['pe_data'])
            threats.extend(pe_threats)
        
        return threats
    
    async def _detect_ransomware_patterns(self,
                                        data: Dict[str, Any],
                                        result: AnalysisResult) -> List[ThreatInfo]:
        """Detect ransomware patterns"""
        threats = []
        indicators_found = []
        
        # Check for ransomware file extensions
        file_data = data.get('file_data', {})
        encrypted_files = []
        
        for file_info in file_data.get('files', []):
            filename = file_info.get('name', '').lower()
            if any(ext in filename for ext in self.signatures['ransomware_extensions']):
                encrypted_files.append(filename)
        
        if encrypted_files:
            indicators_found.append(f"Encrypted files: {len(encrypted_files)}")
            
        # Check for ransom notes
        text_content = self._extract_all_text(data).lower()
        ransom_note_indicators = [
            note for note in self.signatures['ransomware_notes']
            if note in text_content
        ]
        
        if ransom_note_indicators:
            indicators_found.append(f"Ransom note keywords: {len(ransom_note_indicators)}")
        
        # Check for shadow copy deletion
        command_data = self._extract_commands(data)
        shadow_deletion = any('vssadmin' in cmd and 'delete' in cmd for cmd in command_data)
        if shadow_deletion:
            indicators_found.append("Shadow copy deletion detected")
        
        # Check for encryption-related APIs
        if 'api_calls' in data:
            crypto_apis = [api for api in data['api_calls'] 
                          if any(crypto in api.lower() for crypto in ['crypt', 'aes', 'rsa'])]
            if len(crypto_apis) > 5:
                indicators_found.append(f"Excessive crypto API calls: {len(crypto_apis)}")
        
        # Generate threat if indicators found
        if len(indicators_found) >= 2:
            confidence = min(0.5 + (len(indicators_found) * 0.15), 0.95)
            threats.append(ThreatInfo(
                threat_type="Ransomware Activity",
                description="Multiple ransomware indicators detected",
                severity=Severity.CRITICAL,
                confidence=confidence,
                evidence={
                    'indicators': indicators_found,
                    'encrypted_files_sample': encrypted_files[:5],
                    'ransom_keywords': ransom_note_indicators[:5]
                },
                mitre_attack_ids=['T1486', 'T1490', 'T1027']
            ))
        
        return threats
    
    async def _detect_backdoor_signatures(self,
                                        data: Dict[str, Any],
                                        result: AnalysisResult) -> List[ThreatInfo]:
        """Detect backdoor and remote access tools"""
        threats = []
        
        # Check network connections for backdoor ports
        network_data = data.get('network_data', {})
        suspicious_ports = []
        
        for conn in network_data.get('connections', []):
            dst_port = conn.get('dst_port', 0)
            if dst_port in self.signatures['backdoor_ports']:
                suspicious_ports.append({
                    'port': dst_port,
                    'dst_ip': conn.get('dst_ip', 'unknown')
                })
        
        if suspicious_ports:
            threats.append(ThreatInfo(
                threat_type="Backdoor Communication",
                description=f"Connections to known backdoor ports detected",
                severity=Severity.HIGH,
                confidence=0.85,
                evidence={
                    'suspicious_connections': suspicious_ports[:5]
                },
                mitre_attack_ids=['T1071', 'T1573']
            ))
        
        # Check for reverse shell indicators
        shell_indicators = self._detect_reverse_shell_patterns(data)
        if shell_indicators:
            threats.append(ThreatInfo(
                threat_type="Reverse Shell",
                description="Reverse shell indicators detected",
                severity=Severity.HIGH,
                confidence=0.8,
                evidence=shell_indicators,
                mitre_attack_ids=['T1059', 'T1071']
            ))
        
        return threats
    
    async def _detect_data_exfiltration(self,
                                      data: Dict[str, Any],
                                      result: AnalysisResult) -> List[ThreatInfo]:
        """Detect data exfiltration attempts"""
        threats = []
        exfil_indicators = []
        
        network_data = data.get('network_data', {})
        
        # Check for large outbound data transfers
        large_transfers = []
        for conn in network_data.get('connections', []):
            bytes_sent = conn.get('bytes_sent', 0)
            if bytes_sent > 10 * 1024 * 1024:  # 10MB
                large_transfers.append({
                    'dst_ip': conn.get('dst_ip', 'unknown'),
                    'bytes': bytes_sent,
                    'port': conn.get('dst_port', 0)
                })
        
        if large_transfers:
            exfil_indicators.append(f"Large data transfers: {len(large_transfers)}")
        
        # Check for connections to cloud storage
        cloud_domains = ['dropbox', 'googledrive', 'onedrive', 'wetransfer', 'mega.nz']
        cloud_connections = []
        
        for domain_ioc in result.iocs_found:
            if domain_ioc.type == 'DOMAIN':
                if any(cloud in domain_ioc.value.lower() for cloud in cloud_domains):
                    cloud_connections.append(domain_ioc.value)
        
        if cloud_connections:
            exfil_indicators.append(f"Cloud storage connections: {cloud_connections}")
        
        # Check for base64 encoded data in network traffic
        if 'http_data' in network_data:
            for req in network_data['http_data']:
                if self._contains_base64_data(req.get('body', '')):
                    exfil_indicators.append("Base64 encoded data in HTTP")
        
        if exfil_indicators:
            confidence = min(0.6 + (len(exfil_indicators) * 0.1), 0.9)
            threats.append(ThreatInfo(
                threat_type="Data Exfiltration",
                description="Potential data exfiltration activity detected",
                severity=Severity.HIGH,
                confidence=confidence,
                evidence={
                    'indicators': exfil_indicators,
                    'large_transfers': large_transfers[:3]
                },
                mitre_attack_ids=['T1048', 'T1567', 'T1041']
            ))
        
        return threats
    
    async def _detect_persistence_mechanisms(self,
                                           data: Dict[str, Any],
                                           result: AnalysisResult) -> List[ThreatInfo]:
        """Detect persistence mechanisms"""
        threats = []
        persistence_found = []
        
        # Check registry run keys
        registry_data = data.get('registry_data', {})
        for entry in registry_data.get('autostart_entries', []):
            key_path = entry.get('key_path', '')
            if 'run' in key_path.lower():
                persistence_found.append({
                    'type': 'Registry Run Key',
                    'path': key_path,
                    'value': entry.get('value_data', '')[:100]
                })
        
        # Check scheduled tasks
        for task in data.get('scheduled_tasks', []):
            if task.get('enabled'):
                persistence_found.append({
                    'type': 'Scheduled Task',
                    'name': task.get('name', 'unknown'),
                    'action': task.get('action', '')[:100]
                })
        
        # Check services
        for service in registry_data.get('services', []):
            if service.get('start_type') in ['2', 'auto']:  # Auto start
                persistence_found.append({
                    'type': 'Service',
                    'name': service.get('name', 'unknown'),
                    'image_path': service.get('image_path', '')[:100]
                })
        
        if persistence_found:
            threats.append(ThreatInfo(
                threat_type="Persistence Mechanism",
                description=f"Multiple persistence mechanisms detected ({len(persistence_found)})",
                severity=Severity.HIGH,
                confidence=0.85,
                evidence={
                    'mechanisms': persistence_found[:5]
                },
                mitre_attack_ids=['T1547', 'T1053', 'T1543']
            ))
        
        return threats
    
    async def _detect_credential_theft(self,
                                     data: Dict[str, Any],
                                     result: AnalysisResult) -> List[ThreatInfo]:
        """Detect credential theft attempts"""
        threats = []
        cred_indicators = []
        
        # Check for credential dumping tools
        process_data = data.get('process_data', {})
        cred_tools = ['mimikatz', 'lazagne', 'procdump', 'gsecdump', 'pwdump']
        
        for process in process_data.get('processes', []):
            process_name = process.get('name', '').lower()
            if any(tool in process_name for tool in cred_tools):
                cred_indicators.append(f"Credential tool: {process_name}")
        
        # Check for LSASS access
        for proc in process_data.get('processes', []):
            if 'lsass' in proc.get('name', '').lower():
                accessing_procs = proc.get('accessing_processes', [])
                if accessing_procs:
                    cred_indicators.append(f"LSASS access by: {accessing_procs}")
        
        # Check for SAM/SYSTEM registry access
        reg_accesses = data.get('registry_accesses', [])
        for access in reg_accesses:
            if any(hive in access.get('path', '').upper() for hive in ['SAM', 'SECURITY']):
                cred_indicators.append(f"Sensitive registry access: {access['path']}")
        
        if cred_indicators:
            threats.append(ThreatInfo(
                threat_type="Credential Theft",
                description="Credential theft activity detected",
                severity=Severity.CRITICAL,
                confidence=0.9,
                evidence={
                    'indicators': cred_indicators
                },
                mitre_attack_ids=['T1003', 'T1555', 'T1552']
            ))
        
        return threats
    
    async def _detect_lateral_movement(self,
                                     data: Dict[str, Any],
                                     result: AnalysisResult) -> List[ThreatInfo]:
        """Detect lateral movement indicators"""
        threats = []
        lateral_indicators = []
        
        # Check for remote execution tools
        remote_tools = ['psexec', 'wmic', 'winrm', 'ssh', 'rdp']
        command_data = self._extract_commands(data)
        
        for cmd in command_data:
            cmd_lower = cmd.lower()
            if any(tool in cmd_lower for tool in remote_tools):
                lateral_indicators.append(f"Remote tool usage: {cmd[:100]}")
        
        # Check for SMB/RPC connections
        network_data = data.get('network_data', {})
        smb_connections = []
        
        for conn in network_data.get('connections', []):
            if conn.get('dst_port') in [445, 139, 135]:  # SMB/NetBIOS/RPC
                smb_connections.append({
                    'dst_ip': conn.get('dst_ip'),
                    'port': conn.get('dst_port')
                })
        
        if len(smb_connections) > 5:
            lateral_indicators.append(f"Multiple SMB connections: {len(smb_connections)}")
        
        # Check for network discovery commands
        discovery_cmds = ['net view', 'net group', 'net user', 'arp -a', 'nbtstat']
        for cmd in command_data:
            if any(disc in cmd.lower() for disc in discovery_cmds):
                lateral_indicators.append("Network discovery commands")
                break
        
        if lateral_indicators:
            threats.append(ThreatInfo(
                threat_type="Lateral Movement",
                description="Lateral movement activity detected",
                severity=Severity.HIGH,
                confidence=0.8,
                evidence={
                    'indicators': lateral_indicators,
                    'smb_connections': smb_connections[:5]
                },
                mitre_attack_ids=['T1021', 'T1570', 'T1210']
            ))
        
        return threats
    
    async def _detect_defense_evasion(self,
                                    data: Dict[str, Any],
                                    result: AnalysisResult) -> List[ThreatInfo]:
        """Detect defense evasion techniques"""
        threats = []
        evasion_indicators = []
        
        # Check for obfuscation
        if 'strings_analysis' in data:
            strings = data['strings_analysis']
            
            # Check for base64 encoded commands
            base64_count = sum(1 for s in strings.get('strings', []) 
                             if self._is_base64(s) and len(s) > 50)
            if base64_count > 10:
                evasion_indicators.append(f"Excessive base64 strings: {base64_count}")
            
            # Check for obfuscated PowerShell
            if any('-enc' in s.lower() or '-e ' in s.lower() for s in strings.get('strings', [])):
                evasion_indicators.append("Encoded PowerShell commands")
        
        # Check for anti-analysis techniques
        if 'api_calls' in data:
            anti_debug_apis = [
                'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
                'NtQueryInformationProcess', 'GetTickCount'
            ]
            anti_debug = [api for api in data['api_calls'] 
                         if any(debug in api for debug in anti_debug_apis)]
            if anti_debug:
                evasion_indicators.append(f"Anti-debugging APIs: {len(anti_debug)}")
        
        # Check for process injection indicators
        injection_apis = ['WriteProcessMemory', 'VirtualAllocEx', 'CreateRemoteThread']
        if 'api_calls' in data:
            injection_calls = [api for api in data['api_calls']
                             if any(inj in api for inj in injection_apis)]
            if len(injection_calls) >= 3:
                evasion_indicators.append("Process injection APIs detected")
        
        if evasion_indicators:
            threats.append(ThreatInfo(
                threat_type="Defense Evasion",
                description="Defense evasion techniques detected",
                severity=Severity.MEDIUM,
                confidence=0.75,
                evidence={
                    'techniques': evasion_indicators
                },
                mitre_attack_ids=['T1027', 'T1055', 'T1140', 'T1622']
            ))
        
        return threats
    
    async def _detect_reconnaissance(self,
                                   data: Dict[str, Any],
                                   result: AnalysisResult) -> List[ThreatInfo]:
        """Detect reconnaissance activities"""
        threats = []
        recon_indicators = []
        
        # Check for system discovery commands
        discovery_commands = [
            'systeminfo', 'whoami', 'ipconfig', 'netstat',
            'tasklist', 'net user', 'net group', 'wmic'
        ]
        
        command_data = self._extract_commands(data)
        discovery_found = []
        
        for cmd in command_data:
            cmd_lower = cmd.lower()
            for disc_cmd in discovery_commands:
                if disc_cmd in cmd_lower:
                    discovery_found.append(disc_cmd)
        
        if len(set(discovery_found)) >= 3:
            recon_indicators.append(f"System discovery commands: {len(set(discovery_found))}")
        
        # Check for port scanning
        network_data = data.get('network_data', {})
        port_scan_indicators = network_data.get('port_scan_detection', {})
        
        if port_scan_indicators:
            recon_indicators.append("Port scanning activity detected")
        
        # Check for DNS queries to many unique domains
        dns_queries = network_data.get('dns_queries', [])
        unique_domains = set(q.get('domain', '') for q in dns_queries)
        
        if len(unique_domains) > 50:
            recon_indicators.append(f"Excessive DNS queries: {len(unique_domains)} domains")
        
        if recon_indicators:
            threats.append(ThreatInfo(
                threat_type="Reconnaissance Activity",
                description="System reconnaissance detected",
                severity=Severity.MEDIUM,
                confidence=0.7,
                evidence={
                    'indicators': recon_indicators,
                    'discovery_commands': list(set(discovery_found))[:5]
                },
                mitre_attack_ids=['T1057', 'T1082', 'T1016', 'T1049']
            ))
        
        return threats
    
    async def _detect_exploitation(self,
                                 data: Dict[str, Any],
                                 result: AnalysisResult) -> List[ThreatInfo]:
        """Detect exploitation attempts"""
        threats = []
        
        # Check for CVE references
        cve_references = []
        for ioc in result.iocs_found:
            if ioc.type == 'CVE':
                cve_references.append(ioc.value)
        
        if cve_references:
            threats.append(ThreatInfo(
                threat_type="Vulnerability Exploitation",
                description=f"References to {len(cve_references)} CVEs found",
                severity=Severity.HIGH,
                confidence=0.8,
                evidence={
                    'cves': cve_references
                },
                mitre_attack_ids=['T1190', 'T1211', 'T1212']
            ))
        
        # Check for exploit patterns in code
        if 'code_analysis' in data:
            exploit_patterns = [
                'buffer overflow', 'heap spray', 'rop chain',
                'shellcode', 'egg hunter', 'nop sled'
            ]
            
            code_content = str(data['code_analysis']).lower()
            found_patterns = [p for p in exploit_patterns if p in code_content]
            
            if found_patterns:
                threats.append(ThreatInfo(
                    threat_type="Exploit Code",
                    description="Potential exploit code patterns detected",
                    severity=Severity.HIGH,
                    confidence=0.75,
                    evidence={
                        'patterns': found_patterns
                    },
                    mitre_attack_ids=['T1055', 'T1203']
                ))
        
        return threats
    
    def _analyze_pe_characteristics(self, pe_data: Dict[str, Any]) -> List[ThreatInfo]:
        """Analyze PE file characteristics for threats"""
        threats = []
        suspicious_indicators = []
        
        # Check entropy (high entropy may indicate packing)
        entropy = pe_data.get('entropy', 0)
        if entropy > 7.5:
            suspicious_indicators.append(f"High entropy: {entropy:.2f} (possibly packed)")
        
        # Check for suspicious section names
        suspicious_sections = []
        for section in pe_data.get('sections', []):
            name = section.get('name', '')
            if not name or name.startswith('.') and len(name) == 1:
                suspicious_sections.append(name)
        
        if suspicious_sections:
            suspicious_indicators.append(f"Suspicious sections: {suspicious_sections}")
        
        # Check imports
        imports = pe_data.get('imports', {})
        suspicious_imports = []
        
        suspicious_dlls = ['ntdll.dll', 'kernel32.dll', 'user32.dll']
        suspicious_apis = [
            'VirtualAlloc', 'VirtualProtect', 'WriteProcessMemory',
            'CreateRemoteThread', 'SetWindowsHookEx'
        ]
        
        for dll, functions in imports.items():
            if dll.lower() in suspicious_dlls:
                for func in functions:
                    if any(api in func for api in suspicious_apis):
                        suspicious_imports.append(f"{dll}!{func}")
        
        if len(suspicious_imports) > 3:
            suspicious_indicators.append(f"Suspicious imports: {len(suspicious_imports)}")
        
        # Check for unusual characteristics
        characteristics = pe_data.get('characteristics', {})
        if characteristics.get('is_dll') and characteristics.get('is_executable'):
            suspicious_indicators.append("DLL with executable characteristics")
        
        if not pe_data.get('has_debug_info'):
            suspicious_indicators.append("No debug information")
        
        if pe_data.get('has_signature') is False:
            suspicious_indicators.append("Unsigned executable")
        
        if suspicious_indicators:
            confidence = min(0.5 + (len(suspicious_indicators) * 0.1), 0.9)
            threats.append(ThreatInfo(
                threat_type="Suspicious PE File",
                description="PE file has suspicious characteristics",
                severity=Severity.MEDIUM,
                confidence=confidence,
                evidence={
                    'indicators': suspicious_indicators,
                    'suspicious_imports': suspicious_imports[:5]
                },
                mitre_attack_ids=['T1027', 'T1055']
            ))
        
        return threats
    
    def _detect_reverse_shell_patterns(self, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Detect reverse shell patterns"""
        indicators = []
        
        # Check network connections
        network_data = data.get('network_data', {})
        
        # Look for connections with shell-related processes
        shell_processes = ['cmd.exe', 'powershell.exe', 'bash', 'sh']
        for conn in network_data.get('connections', []):
            process = conn.get('process_name', '').lower()
            if any(shell in process for shell in shell_processes):
                if conn.get('direction') == 'outbound':
                    indicators.append({
                        'type': 'shell_connection',
                        'process': process,
                        'dst': f"{conn.get('dst_ip')}:{conn.get('dst_port')}"
                    })
        
        # Check for reverse shell commands
        command_data = self._extract_commands(data)
        shell_patterns = [
            'nc -e', 'ncat -e', 'bash -i', '/dev/tcp/',
            'powershell -nop -c', 'IEX(New-Object'
        ]
        
        for cmd in command_data:
            for pattern in shell_patterns:
                if pattern in cmd:
                    indicators.append({
                        'type': 'shell_command',
                        'pattern': pattern,
                        'command': cmd[:100]
                    })
        
        return {'indicators': indicators} if indicators else None
    
    def _extract_commands(self, data: Dict[str, Any]) -> List[str]:
        """Extract all commands from data"""
        commands = []
        
        # From process data
        for process in data.get('process_data', {}).get('processes', []):
            if process.get('command_line'):
                commands.append(process['command_line'])
        
        # From event logs
        for event in data.get('event_data', {}).get('events', []):
            if 'command' in event:
                commands.append(event['command'])
        
        # From strings
        if 'strings_analysis' in data:
            # Look for command patterns in strings
            for string in data['strings_analysis'].get('strings', []):
                if any(cmd in string.lower() for cmd in ['cmd', 'powershell', 'wmic']):
                    commands.append(string)
        
        return commands
    
    def _extract_all_text(self, data: Dict[str, Any]) -> str:
        """Extract all text content from data"""
        text_parts = []
        
        def extract_text(obj, depth=0):
            if depth > 5:  # Prevent infinite recursion
                return
            
            if isinstance(obj, str):
                text_parts.append(obj)
            elif isinstance(obj, list):
                for item in obj[:100]:  # Limit items
                    extract_text(item, depth + 1)
            elif isinstance(obj, dict):
                for key, value in list(obj.items())[:100]:  # Limit items
                    text_parts.append(str(key))
                    extract_text(value, depth + 1)
        
        extract_text(data)
        return ' '.join(text_parts)
    
    def _contains_base64_data(self, text: str) -> bool:
        """Check if text contains base64 encoded data"""
        # Simple heuristic for base64
        import re
        base64_pattern = re.compile(r'[A-Za-z0-9+/]{50,}={0,2}')
        matches = base64_pattern.findall(text)
        return len(matches) > 0
    
    def _is_base64(self, s: str) -> bool:
        """Check if string is base64 encoded"""
        import re
        if len(s) < 20:
            return False
        return bool(re.match(r'^[A-Za-z0-9+/]+={0,2}$', s))
    
    def _enhance_threat_detection(self, 
                                threats: List[ThreatInfo],
                                data: Dict[str, Any]) -> List[ThreatInfo]:
        """Enhance threat detection with additional context"""
        enhanced = []
        
        for threat in threats:
            # Add timestamps if available
            if 'timeline' in data:
                relevant_events = []
                for event in data['timeline']:
                    if any(keyword in str(event).lower() 
                          for keyword in threat.threat_type.lower().split()):
                        relevant_events.append(event)
                
                if relevant_events:
                    threat.evidence['timeline_events'] = relevant_events[:3]
            
            # Add MITRE ATT&CK context
            if threat.mitre_attack_ids:
                threat.evidence['attack_techniques'] = [
                    {
                        'id': attack_id,
                        'name': self.attack_mapping.get(attack_id, 'Unknown')
                    }
                    for attack_id in threat.mitre_attack_ids
                ]
            
            # Adjust confidence based on evidence strength
            evidence_count = len(threat.evidence.get('indicators', []))
            if evidence_count > 5:
                threat.confidence = min(threat.confidence * 1.1, 1.0)
            
            enhanced.append(threat)
        
        return enhanced
    
    def _deduplicate_threats(self, threats: List[ThreatInfo]) -> List[ThreatInfo]:
        """Remove duplicate threats"""
        seen = set()
        unique = []
        
        for threat in threats:
            # Create unique key
            key = f"{threat.threat_type}:{threat.severity}"
            
            if key not in seen:
                seen.add(key)
                unique.append(threat)
            else:
                # Merge evidence if duplicate
                for existing in unique:
                    if f"{existing.threat_type}:{existing.severity}" == key:
                        # Merge evidence
                        for k, v in threat.evidence.items():
                            if k not in existing.evidence:
                                existing.evidence[k] = v
                        # Use higher confidence
                        existing.confidence = max(existing.confidence, threat.confidence)
                        break
        
        return unique