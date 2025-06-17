"""
Timeline Builder for SecuNik
Builds comprehensive timelines from security events
"""

import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta
from collections import defaultdict
import json

from ...models.analysis import AnalysisResult

logger = logging.getLogger(__name__)

class TimelineBuilder:
    """Builds timelines from various security events"""
    
    def __init__(self):
        # Event type priorities (higher = more important)
        self.event_priorities = {
            'compromise': 100,
            'malware_execution': 90,
            'credential_theft': 85,
            'persistence_created': 80,
            'lateral_movement': 75,
            'data_exfiltration': 70,
            'reconnaissance': 60,
            'file_created': 50,
            'file_modified': 45,
            'process_started': 40,
            'network_connection': 35,
            'registry_modified': 30,
            'user_activity': 20,
            'system_event': 10
        }
        
        # Event categorization rules
        self.event_categories = {
            'initial_access': [
                'first_seen', 'exploit', 'phishing', 'external_connection'
            ],
            'execution': [
                'process_started', 'script_executed', 'command_executed'
            ],
            'persistence': [
                'registry_modified', 'service_created', 'scheduled_task'
            ],
            'privilege_escalation': [
                'privilege_gained', 'token_manipulation', 'bypass_uac'
            ],
            'defense_evasion': [
                'process_injection', 'file_deletion', 'log_cleared'
            ],
            'credential_access': [
                'credential_dumped', 'keylogger', 'password_found'
            ],
            'discovery': [
                'system_info', 'network_scan', 'file_search'
            ],
            'lateral_movement': [
                'remote_execution', 'smb_connection', 'rdp_connection'
            ],
            'collection': [
                'file_accessed', 'screenshot', 'audio_capture'
            ],
            'exfiltration': [
                'data_compressed', 'data_encrypted', 'data_uploaded'
            ],
            'impact': [
                'data_encrypted', 'system_shutdown', 'defacement'
            ]
        }
    
    async def extract_timeline_events(self,
                                    extracted_data: Dict[str, Any],
                                    analysis_result: AnalysisResult) -> List[Dict[str, Any]]:
        """Extract timeline events from analysis data"""
        events = []
        
        # Extract from different data sources
        events.extend(await self._extract_file_events(extracted_data))
        events.extend(await self._extract_process_events(extracted_data))
        events.extend(await self._extract_network_events(extracted_data))
        events.extend(await self._extract_registry_events(extracted_data))
        events.extend(await self._extract_log_events(extracted_data))
        
        # Add threat detection events
        events.extend(self._create_threat_events(analysis_result))
        
        # Normalize and enrich events
        normalized_events = self._normalize_events(events)
        
        # Sort by timestamp
        normalized_events.sort(key=lambda x: x['timestamp'])
        
        return normalized_events
    
    async def build_unified_timeline(self, 
                                   results: List[AnalysisResult]) -> List[Dict[str, Any]]:
        """Build unified timeline from multiple analysis results"""
        all_events = []
        
        # Collect all events
        for result in results:
            # Get events from result details
            timeline_events = result.details.get('timeline', [])
            
            # Add file reference to each event
            for event in timeline_events:
                event['source_file'] = result.file_path
                event['file_id'] = getattr(result, 'file_id', '')
                all_events.append(event)
            
            # Add analysis metadata as events
            all_events.append({
                'timestamp': result.timestamp.isoformat(),
                'event_type': 'analysis_completed',
                'description': f"Analysis completed for {result.file_path}",
                'source_file': result.file_path,
                'severity': result.severity,
                'risk_score': result.risk_score
            })
        
        # Normalize all events
        normalized = self._normalize_events(all_events)
        
        # Sort chronologically
        normalized.sort(key=lambda x: x['timestamp'])
        
        # Identify event clusters
        clusters = self._identify_event_clusters(normalized)
        
        # Build attack chain
        attack_chain = self._build_attack_chain(normalized, clusters)
        
        # Add cluster and chain information to events
        for event in normalized:
            event['cluster_id'] = self._find_event_cluster(event, clusters)
            event['attack_stage'] = self._find_attack_stage(event, attack_chain)
        
        return normalized
    
    async def _extract_file_events(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract file-related events"""
        events = []
        
        file_data = data.get('file_data', {})
        
        # File creation/modification times
        if 'created_time' in file_data:
            events.append({
                'timestamp': file_data['created_time'],
                'event_type': 'file_created',
                'description': f"File created: {file_data.get('filename', 'unknown')}",
                'details': {
                    'filename': file_data.get('filename'),
                    'size': file_data.get('size')
                }
            })
        
        if 'modified_time' in file_data:
            events.append({
                'timestamp': file_data['modified_time'],
                'event_type': 'file_modified',
                'description': f"File modified: {file_data.get('filename', 'unknown')}",
                'details': {
                    'filename': file_data.get('filename')
                }
            })
        
        # Embedded file events
        for embedded in file_data.get('embedded_files', []):
            if embedded.get('timestamp'):
                events.append({
                    'timestamp': embedded['timestamp'],
                    'event_type': 'file_embedded',
                    'description': f"File embedded: {embedded.get('filename', 'unknown')}",
                    'details': embedded
                })
        
        return events
    
    async def _extract_process_events(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract process-related events"""
        events = []
        
        process_data = data.get('process_data', {})
        
        for process in process_data.get('processes', []):
            # Process start time
            if process.get('start_time'):
                events.append({
                    'timestamp': process['start_time'],
                    'event_type': 'process_started',
                    'description': f"Process started: {process.get('name', 'unknown')}",
                    'details': {
                        'process_name': process.get('name'),
                        'pid': process.get('pid'),
                        'parent_pid': process.get('parent_pid'),
                        'command_line': process.get('command_line')
                    }
                })
            
            # Process termination
            if process.get('end_time'):
                events.append({
                    'timestamp': process['end_time'],
                    'event_type': 'process_terminated',
                    'description': f"Process terminated: {process.get('name', 'unknown')}",
                    'details': {
                        'process_name': process.get('name'),
                        'pid': process.get('pid')
                    }
                })
        
        return events
    
    async def _extract_network_events(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract network-related events"""
        events = []
        
        network_data = data.get('network_data', {})
        
        # Network connections
        for conn in network_data.get('connections', []):
            if conn.get('timestamp'):
                events.append({
                    'timestamp': conn['timestamp'],
                    'event_type': 'network_connection',
                    'description': f"Network connection: {conn.get('src_ip')} -> {conn.get('dst_ip')}:{conn.get('dst_port')}",
                    'details': {
                        'src_ip': conn.get('src_ip'),
                        'src_port': conn.get('src_port'),
                        'dst_ip': conn.get('dst_ip'),
                        'dst_port': conn.get('dst_port'),
                        'protocol': conn.get('protocol'),
                        'bytes_sent': conn.get('bytes_sent'),
                        'bytes_received': conn.get('bytes_received')
                    }
                })
        
        # DNS queries
        for query in network_data.get('dns_queries', []):
            if query.get('timestamp'):
                events.append({
                    'timestamp': query['timestamp'],
                    'event_type': 'dns_query',
                    'description': f"DNS query: {query.get('domain')}",
                    'details': {
                        'domain': query.get('domain'),
                        'query_type': query.get('query_type'),
                        'response': query.get('response')
                    }
                })
        
        # HTTP requests
        for request in network_data.get('http_requests', []):
            if request.get('timestamp'):
                events.append({
                    'timestamp': request['timestamp'],
                    'event_type': 'http_request',
                    'description': f"HTTP {request.get('method', 'GET')} {request.get('url')}",
                    'details': {
                        'method': request.get('method'),
                        'url': request.get('url'),
                        'host': request.get('host'),
                        'user_agent': request.get('user_agent'),
                        'status_code': request.get('status_code')
                    }
                })
        
        return events
    
    async def _extract_registry_events(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract registry-related events"""
        events = []
        
        registry_data = data.get('registry_data', {})
        
        # Registry modifications
        for entry in registry_data.get('modified_keys', []):
            if entry.get('timestamp'):
                events.append({
                    'timestamp': entry['timestamp'],
                    'event_type': 'registry_modified',
                    'description': f"Registry modified: {entry.get('key_path')}",
                    'details': {
                        'key_path': entry.get('key_path'),
                        'value_name': entry.get('value_name'),
                        'value_data': entry.get('value_data'),
                        'operation': entry.get('operation', 'modified')
                    }
                })
        
        # Autostart entries
        for autostart in registry_data.get('autostart_entries', []):
            if autostart.get('timestamp'):
                events.append({
                    'timestamp': autostart['timestamp'],
                    'event_type': 'persistence_created',
                    'description': f"Persistence created: {autostart.get('name')}",
                    'details': {
                        'type': 'registry_autostart',
                        'key_path': autostart.get('key_path'),
                        'value': autostart.get('command')
                    }
                })
        
        return events
    
    async def _extract_log_events(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract events from logs"""
        events = []
        
        # Windows event logs
        event_data = data.get('event_data', {})
        
        for event in event_data.get('events', []):
            event_time = event.get('timestamp')
            if event_time:
                # Map event IDs to event types
                event_id = event.get('event_id')
                event_type = self._map_event_id_to_type(event_id)
                
                events.append({
                    'timestamp': event_time,
                    'event_type': event_type,
                    'description': event.get('message', f"Event ID {event_id}"),
                    'details': {
                        'event_id': event_id,
                        'source': event.get('source'),
                        'user': event.get('user'),
                        'computer': event.get('computer'),
                        'level': event.get('level')
                    }
                })
        
        # Authentication logs
        for auth in event_data.get('authentication_events', []):
            if auth.get('timestamp'):
                events.append({
                    'timestamp': auth['timestamp'],
                    'event_type': 'authentication',
                    'description': f"Authentication: {auth.get('user')} ({auth.get('logon_type')})",
                    'details': {
                        'user': auth.get('user'),
                        'logon_type': auth.get('logon_type'),
                        'source_ip': auth.get('source_ip'),
                        'success': auth.get('success')
                    }
                })
        
        return events
    
    def _create_threat_events(self, result: AnalysisResult) -> List[Dict[str, Any]]:
        """Create events from detected threats"""
        events = []
        
        for threat in result.threats_detected:
            # Use threat detection time or analysis time
            timestamp = getattr(threat, 'timestamp', result.timestamp)
            
            events.append({
                'timestamp': timestamp.isoformat() if hasattr(timestamp, 'isoformat') else str(timestamp),
                'event_type': 'threat_detected',
                'description': f"Threat detected: {threat.threat_type}",
                'severity': threat.severity,
                'details': {
                    'threat_type': threat.threat_type,
                    'description': threat.description,
                    'confidence': threat.confidence,
                    'evidence': threat.evidence
                }
            })
        
        return events
    
    def _normalize_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Normalize event formats"""
        normalized = []
        
        for event in events:
            # Ensure required fields
            norm_event = {
                'timestamp': self._normalize_timestamp(event.get('timestamp')),
                'event_type': event.get('event_type', 'unknown'),
                'description': event.get('description', 'No description'),
                'severity': event.get('severity', 'info'),
                'source': event.get('source', 'unknown'),
                'details': event.get('details', {})
            }
            
            # Add priority
            norm_event['priority'] = self.event_priorities.get(
                norm_event['event_type'], 
                0
            )
            
            # Add category
            norm_event['category'] = self._categorize_event(norm_event)
            
            # Add source file if available
            if 'source_file' in event:
                norm_event['source_file'] = event['source_file']
            
            normalized.append(norm_event)
        
        return normalized
    
    def _normalize_timestamp(self, timestamp: Any) -> str:
        """Normalize timestamp to ISO format"""
        if isinstance(timestamp, datetime):
            return timestamp.isoformat()
        elif isinstance(timestamp, str):
            # Try to parse and normalize
            try:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                return dt.isoformat()
            except:
                return timestamp
        else:
            return str(timestamp)
    
    def _categorize_event(self, event: Dict[str, Any]) -> str:
        """Categorize event into attack framework category"""
        event_type = event['event_type'].lower()
        description = event['description'].lower()
        
        for category, keywords in self.event_categories.items():
            if any(keyword in event_type or keyword in description 
                  for keyword in keywords):
                return category
        
        return 'other'
    
    def _identify_event_clusters(self, 
                               events: List[Dict[str, Any]],
                               time_window: int = 300) -> List[Dict[str, Any]]:
        """Identify clusters of related events"""
        clusters = []
        current_cluster = None
        
        for event in events:
            event_time = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
            
            if current_cluster is None:
                # Start new cluster
                current_cluster = {
                    'id': len(clusters),
                    'start_time': event_time,
                    'end_time': event_time,
                    'events': [event],
                    'categories': set([event['category']])
                }
            else:
                # Check if event belongs to current cluster
                time_diff = (event_time - current_cluster['end_time']).total_seconds()
                
                if time_diff <= time_window:
                    # Add to current cluster
                    current_cluster['events'].append(event)
                    current_cluster['end_time'] = event_time
                    current_cluster['categories'].add(event['category'])
                else:
                    # Save current cluster and start new one
                    current_cluster['categories'] = list(current_cluster['categories'])
                    clusters.append(current_cluster)
                    
                    current_cluster = {
                        'id': len(clusters),
                        'start_time': event_time,
                        'end_time': event_time,
                        'events': [event],
                        'categories': set([event['category']])
                    }
        
        # Add final cluster
        if current_cluster:
            current_cluster['categories'] = list(current_cluster['categories'])
            clusters.append(current_cluster)
        
        # Analyze cluster patterns
        for cluster in clusters:
            cluster['pattern'] = self._analyze_cluster_pattern(cluster)
            cluster['severity'] = max(e['severity'] for e in cluster['events'] 
                                    if isinstance(e.get('severity'), str))
        
        return clusters
    
    def _analyze_cluster_pattern(self, cluster: Dict[str, Any]) -> str:
        """Analyze pattern of events in cluster"""
        categories = cluster['categories']
        event_count = len(cluster['events'])
        
        # Check for known attack patterns
        if 'initial_access' in categories and 'execution' in categories:
            return 'initial_compromise'
        elif 'discovery' in categories and 'collection' in categories:
            return 'data_gathering'
        elif 'lateral_movement' in categories:
            return 'lateral_expansion'
        elif 'exfiltration' in categories:
            return 'data_theft'
        elif 'persistence' in categories:
            return 'establishing_foothold'
        elif event_count > 10:
            return 'burst_activity'
        else:
            return 'normal_activity'
    
    def _build_attack_chain(self, 
                          events: List[Dict[str, Any]],
                          clusters: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Build attack chain from events and clusters"""
        attack_chain = []
        
        # Identify key stages based on clusters
        stages = {
            'initial_access': None,
            'execution': None,
            'persistence': None,
            'privilege_escalation': None,
            'defense_evasion': None,
            'credential_access': None,
            'discovery': None,
            'lateral_movement': None,
            'collection': None,
            'exfiltration': None,
            'impact': None
        }
        
        # Map clusters to stages
        for cluster in clusters:
            for category in cluster['categories']:
                if category in stages and stages[category] is None:
                    stages[category] = cluster
        
        # Build ordered chain
        stage_order = [
            'initial_access', 'execution', 'persistence',
            'privilege_escalation', 'defense_evasion',
            'credential_access', 'discovery', 'lateral_movement',
            'collection', 'exfiltration', 'impact'
        ]
        
        for stage_name in stage_order:
            if stages[stage_name]:
                cluster = stages[stage_name]
                attack_chain.append({
                    'stage': stage_name,
                    'cluster_id': cluster['id'],
                    'timestamp': cluster['start_time'].isoformat(),
                    'duration': (cluster['end_time'] - cluster['start_time']).total_seconds(),
                    'event_count': len(cluster['events']),
                    'key_events': self._extract_key_events(cluster['events'])[:3]
                })
        
        return attack_chain
    
    def _extract_key_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract most important events from list"""
        # Sort by priority and severity
        sorted_events = sorted(
            events,
            key=lambda x: (x.get('priority', 0), x.get('severity', 'info')),
            reverse=True
        )
        
        # Return simplified version of top events
        key_events = []
        for event in sorted_events[:5]:
            key_events.append({
                'timestamp': event['timestamp'],
                'type': event['event_type'],
                'description': event['description'],
                'severity': event.get('severity', 'info')
            })
        
        return key_events
    
    def _find_event_cluster(self, 
                          event: Dict[str, Any],
                          clusters: List[Dict[str, Any]]) -> Optional[int]:
        """Find which cluster an event belongs to"""
        event_time = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
        
        for cluster in clusters:
            if (cluster['start_time'] <= event_time <= cluster['end_time']):
                return cluster['id']
        
        return None
    
    def _find_attack_stage(self, 
                         event: Dict[str, Any],
                         attack_chain: List[Dict[str, Any]]) -> Optional[str]:
        """Find which attack stage an event belongs to"""
        cluster_id = event.get('cluster_id')
        
        if cluster_id is not None:
            for stage in attack_chain:
                if stage['cluster_id'] == cluster_id:
                    return stage['stage']
        
        return None
    
    def _map_event_id_to_type(self, event_id: int) -> str:
        """Map Windows event ID to event type"""
        event_mapping = {
            4624: 'logon',
            4625: 'logon_failed',
            4634: 'logoff',
            4648: 'explicit_logon',
            4672: 'special_logon',
            4688: 'process_created',
            4689: 'process_terminated',
            4698: 'scheduled_task_created',
            4702: 'scheduled_task_updated',
            4719: 'audit_policy_changed',
            4720: 'user_created',
            4726: 'user_deleted',
            4738: 'user_changed',
            4740: 'account_locked',
            5140: 'network_share_accessed',
            5156: 'network_connection',
            7045: 'service_installed'
        }
        
        return event_mapping.get(event_id, f'event_{event_id}')
    
    async def generate_timeline_summary(self, 
                                      timeline: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate summary of timeline"""
        if not timeline:
            return {
                'total_events': 0,
                'summary': 'No timeline events found'
            }
        
        # Calculate time range
        start_time = datetime.fromisoformat(timeline[0]['timestamp'].replace('Z', '+00:00'))
        end_time = datetime.fromisoformat(timeline[-1]['timestamp'].replace('Z', '+00:00'))
        duration = end_time - start_time
        
        # Count by category
        category_counts = defaultdict(int)
        severity_counts = defaultdict(int)
        
        for event in timeline:
            category_counts[event.get('category', 'other')] += 1
            severity_counts[event.get('severity', 'info')] += 1
        
        # Identify critical events
        critical_events = [
            e for e in timeline 
            if e.get('severity', '').upper() in ['HIGH', 'CRITICAL']
        ]
        
        return {
            'total_events': len(timeline),
            'time_range': {
                'start': start_time.isoformat(),
                'end': end_time.isoformat(),
                'duration_hours': duration.total_seconds() / 3600
            },
            'categories': dict(category_counts),
            'severities': dict(severity_counts),
            'critical_events': len(critical_events),
            'events_per_hour': len(timeline) / max(duration.total_seconds() / 3600, 1),
            'summary': self._generate_narrative_summary(timeline, category_counts)
        }
    
    def _generate_narrative_summary(self, 
                                  timeline: List[Dict[str, Any]],
                                  category_counts: Dict[str, int]) -> str:
        """Generate narrative summary of timeline"""
        total = len(timeline)
        
        if total == 0:
            return "No security events detected."
        
        # Find dominant activity
        dominant_category = max(category_counts.items(), key=lambda x: x[1])[0]
        
        summary = f"Detected {total} security events. "
        
        if dominant_category == 'initial_access':
            summary += "Timeline shows initial compromise activity. "
        elif dominant_category == 'lateral_movement':
            summary += "Significant lateral movement detected. "
        elif dominant_category == 'exfiltration':
            summary += "Data exfiltration activity observed. "
        elif dominant_category == 'persistence':
            summary += "Multiple persistence mechanisms established. "
        
        # Add severity information
        high_severity = sum(1 for e in timeline if e.get('severity', '').upper() in ['HIGH', 'CRITICAL'])
        if high_severity > 0:
            summary += f"{high_severity} high-severity events require immediate attention."
        
        return summary