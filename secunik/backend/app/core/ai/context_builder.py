"""
AI Context Builder for SecuNik
Builds structured context from evidence for AI analysis
"""

import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
from collections import defaultdict

logger = logging.getLogger(__name__)

class ContextBuilder:
    """Builds context for AI analysis from various evidence sources"""
    
    def __init__(self):
        self.max_context_size = 8000  # Token limit consideration
        self.priority_weights = {
            'threats': 1.0,
            'iocs': 0.9,
            'suspicious_activities': 0.8,
            'timeline': 0.7,
            'file_metadata': 0.6,
            'statistics': 0.5
        }
    
    def build_comprehensive_context(self, analysis_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Build comprehensive context from multiple analysis results"""
        context = {
            "summary": self._generate_summary(analysis_results),
            "evidence_count": len(analysis_results),
            "analysis_timestamp": datetime.now().isoformat(),
            "aggregated_threats": [],
            "aggregated_iocs": [],
            "timeline_events": [],
            "file_relationships": [],
            "statistics": {},
            "key_findings": []
        }
        
        # Aggregate data from all results
        for result in analysis_results:
            self._aggregate_threats(result, context)
            self._aggregate_iocs(result, context)
            self._aggregate_timeline(result, context)
            self._extract_key_findings(result, context)
        
        # Build relationships
        context["file_relationships"] = self._build_file_relationships(analysis_results)
        
        # Calculate statistics
        context["statistics"] = self._calculate_statistics(context)
        
        # Prioritize and trim context to size limit
        context = self._prioritize_context(context)
        
        return context
    
    def build_ioc_context(self, iocs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Build context specifically for IOC analysis"""
        # Group IOCs by type
        ioc_groups = defaultdict(list)
        for ioc in iocs:
            ioc_type = ioc.get('type', 'unknown')
            ioc_groups[ioc_type].append(ioc)
        
        # Extract unique values
        unique_ips = set()
        unique_domains = set()
        unique_hashes = set()
        unique_emails = set()
        
        for ioc in iocs:
            ioc_type = ioc.get('type', '').lower()
            value = ioc.get('value', '')
            
            if 'ip' in ioc_type:
                unique_ips.add(value)
            elif 'domain' in ioc_type or 'url' in ioc_type:
                unique_domains.add(value)
            elif 'hash' in ioc_type:
                unique_hashes.add(value)
            elif 'email' in ioc_type:
                unique_emails.add(value)
        
        context = {
            "total_iocs": len(iocs),
            "ioc_types": dict(ioc_groups),
            "unique_indicators": {
                "ip_addresses": list(unique_ips)[:50],
                "domains": list(unique_domains)[:50],
                "file_hashes": list(unique_hashes)[:50],
                "email_addresses": list(unique_emails)[:50]
            },
            "high_confidence_iocs": [
                ioc for ioc in iocs 
                if ioc.get('confidence', 0) >= 0.8
            ][:20],
            "ioc_sources": self._extract_ioc_sources(iocs),
            "temporal_distribution": self._analyze_temporal_distribution(iocs)
        }
        
        return context
    
    def build_threat_context(self, threats: List[Dict[str, Any]], evidence: Dict[str, Any]) -> Dict[str, Any]:
        """Build context for threat assessment"""
        # Categorize threats
        threat_categories = defaultdict(list)
        for threat in threats:
            category = threat.get('threat_type', 'unknown')
            threat_categories[category].append(threat)
        
        # Extract attack patterns
        attack_patterns = self._extract_attack_patterns(threats, evidence)
        
        context = {
            "total_threats": len(threats),
            "threat_categories": dict(threat_categories),
            "severity_distribution": self._get_severity_distribution(threats),
            "attack_patterns": attack_patterns,
            "affected_systems": self._identify_affected_systems(threats, evidence),
            "threat_timeline": self._build_threat_timeline(threats),
            "high_severity_threats": [
                t for t in threats 
                if t.get('severity', '').upper() in ['HIGH', 'CRITICAL']
            ],
            "evidence_summary": self._summarize_evidence(evidence)
        }
        
        return context
    
    def build_timeline_context(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Build context for timeline analysis"""
        # Sort events chronologically
        sorted_events = sorted(
            events,
            key=lambda x: x.get('timestamp', ''),
            reverse=False
        )
        
        # Group events by time windows
        time_windows = self._group_by_time_windows(sorted_events)
        
        # Identify patterns
        patterns = self._identify_temporal_patterns(sorted_events)
        
        context = {
            "total_events": len(events),
            "time_range": {
                "start": sorted_events[0].get('timestamp') if sorted_events else None,
                "end": sorted_events[-1].get('timestamp') if sorted_events else None
            },
            "events": sorted_events[:100],  # Limit for context size
            "time_windows": time_windows,
            "temporal_patterns": patterns,
            "event_frequency": self._calculate_event_frequency(sorted_events),
            "critical_periods": self._identify_critical_periods(sorted_events)
        }
        
        return context
    
    def _generate_summary(self, analysis_results: List[Dict[str, Any]]) -> str:
        """Generate summary of analysis results"""
        total_files = len(analysis_results)
        total_threats = sum(len(r.get('threats_detected', [])) for r in analysis_results)
        total_iocs = sum(len(r.get('iocs_found', [])) for r in analysis_results)
        
        high_risk_files = [
            r for r in analysis_results 
            if r.get('risk_score', 0) >= 0.7
        ]
        
        summary = f"Analyzed {total_files} files, found {total_threats} threats and {total_iocs} IOCs. "
        
        if high_risk_files:
            summary += f"{len(high_risk_files)} files show high risk indicators. "
        
        # Add file type summary
        file_types = defaultdict(int)
        for r in analysis_results:
            file_type = r.get('analysis_type', 'Unknown')
            file_types[file_type] += 1
        
        summary += f"File types analyzed: {', '.join(f'{k} ({v})' for k, v in file_types.items())}."
        
        return summary
    
    def _aggregate_threats(self, result: Dict[str, Any], context: Dict[str, Any]):
        """Aggregate threats from result"""
        threats = result.get('threats_detected', [])
        for threat in threats:
            # Add file reference
            threat['source_file'] = result.get('file_path', 'Unknown')
            threat['file_id'] = result.get('file_id', '')
            context['aggregated_threats'].append(threat)
    
    def _aggregate_iocs(self, result: Dict[str, Any], context: Dict[str, Any]):
        """Aggregate IOCs from result"""
        iocs = result.get('iocs_found', [])
        for ioc in iocs:
            # Add file reference
            ioc['source_file'] = result.get('file_path', 'Unknown')
            ioc['file_id'] = result.get('file_id', '')
            context['aggregated_iocs'].append(ioc)
    
    def _aggregate_timeline(self, result: Dict[str, Any], context: Dict[str, Any]):
        """Aggregate timeline events from result"""
        # Extract timeline from various sources
        details = result.get('details', {})
        
        # Add analysis timestamp as event
        context['timeline_events'].append({
            'timestamp': result.get('timestamp', datetime.now()).isoformat(),
            'event': 'file_analyzed',
            'description': f"Analyzed {result.get('file_path', 'Unknown')}",
            'source': 'analysis_engine'
        })
        
        # Extract events from details
        if 'timeline' in details:
            for event in details['timeline']:
                context['timeline_events'].append(event)
        
        # Extract events from threats
        for threat in result.get('threats_detected', []):
            if threat.get('timestamp'):
                context['timeline_events'].append({
                    'timestamp': threat['timestamp'],
                    'event': 'threat_detected',
                    'description': threat.get('description', ''),
                    'severity': threat.get('severity', 'UNKNOWN')
                })
    
    def _extract_key_findings(self, result: Dict[str, Any], context: Dict[str, Any]):
        """Extract key findings from result"""
        # High risk files
        if result.get('risk_score', 0) >= 0.7:
            context['key_findings'].append({
                'type': 'high_risk_file',
                'description': f"High risk file: {result.get('file_path', 'Unknown')}",
                'risk_score': result.get('risk_score'),
                'file_id': result.get('file_id', '')
            })
        
        # Critical threats
        for threat in result.get('threats_detected', []):
            if threat.get('severity', '').upper() == 'CRITICAL':
                context['key_findings'].append({
                    'type': 'critical_threat',
                    'description': threat.get('description', ''),
                    'threat_type': threat.get('threat_type', ''),
                    'file_id': result.get('file_id', '')
                })
    
    def _build_file_relationships(self, analysis_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Build relationships between analyzed files"""
        relationships = []
        
        # Group files by common IOCs
        ioc_map = defaultdict(list)
        for result in analysis_results:
            file_id = result.get('file_id', '')
            for ioc in result.get('iocs_found', []):
                ioc_value = ioc.get('value', '')
                if ioc_value:
                    ioc_map[ioc_value].append(file_id)
        
        # Create relationships for files sharing IOCs
        for ioc_value, file_ids in ioc_map.items():
            if len(file_ids) > 1:
                relationships.append({
                    'type': 'shared_ioc',
                    'ioc_value': ioc_value,
                    'related_files': file_ids,
                    'confidence': 0.8
                })
        
        return relationships
    
    def _calculate_statistics(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate statistics from aggregated data"""
        stats = {
            'total_threats': len(context['aggregated_threats']),
            'total_iocs': len(context['aggregated_iocs']),
            'unique_threat_types': len(set(t.get('threat_type', '') for t in context['aggregated_threats'])),
            'unique_ioc_types': len(set(i.get('type', '') for i in context['aggregated_iocs'])),
            'severity_breakdown': self._get_severity_distribution(context['aggregated_threats']),
            'ioc_type_breakdown': self._get_ioc_type_distribution(context['aggregated_iocs'])
        }
        
        return stats
    
    def _prioritize_context(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Prioritize context elements to fit within size limits"""
        # Estimate context size
        context_str = json.dumps(context)
        
        if len(context_str) <= self.max_context_size:
            return context
        
        # Trim lower priority items
        if len(context['timeline_events']) > 50:
            context['timeline_events'] = context['timeline_events'][:50]
        
        if len(context['aggregated_iocs']) > 100:
            # Keep high confidence IOCs
            context['aggregated_iocs'] = sorted(
                context['aggregated_iocs'],
                key=lambda x: x.get('confidence', 0),
                reverse=True
            )[:100]
        
        return context
    
    def _extract_attack_patterns(self, threats: List[Dict[str, Any]], evidence: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract attack patterns from threats and evidence"""
        patterns = []
        
        # Look for common attack patterns
        threat_types = [t.get('threat_type', '') for t in threats]
        
        # Persistence patterns
        if any('persistence' in t.lower() for t in threat_types):
            patterns.append({
                'pattern': 'Persistence Mechanism',
                'confidence': 0.8,
                'indicators': [t for t in threats if 'persistence' in t.get('threat_type', '').lower()]
            })
        
        # Lateral movement patterns
        if any('lateral' in t.lower() or 'movement' in t.lower() for t in threat_types):
            patterns.append({
                'pattern': 'Lateral Movement',
                'confidence': 0.7,
                'indicators': [t for t in threats if any(x in t.get('threat_type', '').lower() for x in ['lateral', 'movement'])]
            })
        
        return patterns
    
    def _identify_affected_systems(self, threats: List[Dict[str, Any]], evidence: Dict[str, Any]) -> List[str]:
        """Identify systems affected by threats"""
        affected = set()
        
        for threat in threats:
            # Extract from threat evidence
            threat_evidence = threat.get('evidence', {})
            
            # Look for system identifiers
            if 'hostname' in threat_evidence:
                affected.add(threat_evidence['hostname'])
            if 'ip_address' in threat_evidence:
                affected.add(threat_evidence['ip_address'])
            if 'system_name' in threat_evidence:
                affected.add(threat_evidence['system_name'])
        
        return list(affected)
    
    def _build_threat_timeline(self, threats: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Build timeline of threat events"""
        timeline = []
        
        for threat in threats:
            timestamp = threat.get('timestamp')
            if timestamp:
                timeline.append({
                    'timestamp': timestamp,
                    'event': threat.get('threat_type', 'Unknown threat'),
                    'severity': threat.get('severity', 'UNKNOWN'),
                    'description': threat.get('description', '')
                })
        
        # Sort by timestamp
        timeline.sort(key=lambda x: x['timestamp'])
        
        return timeline
    
    def _summarize_evidence(self, evidence: Dict[str, Any]) -> Dict[str, Any]:
        """Summarize evidence for context"""
        summary = {
            'total_files': evidence.get('file_count', 0),
            'data_sources': list(evidence.get('sources', [])),
            'time_range': evidence.get('time_range', {}),
            'key_artifacts': evidence.get('key_artifacts', [])[:10]
        }
        
        return summary
    
    def _group_by_time_windows(self, events: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Group events by time windows"""
        windows = defaultdict(list)
        
        for event in events:
            timestamp_str = event.get('timestamp', '')
            if timestamp_str:
                try:
                    dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                    # Group by hour
                    window_key = dt.strftime('%Y-%m-%d %H:00')
                    windows[window_key].append(event)
                except:
                    continue
        
        return dict(windows)
    
    def _identify_temporal_patterns(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify patterns in temporal data"""
        patterns = []
        
        if len(events) < 2:
            return patterns
        
        # Calculate time deltas
        timestamps = []
        for event in events:
            ts_str = event.get('timestamp', '')
            if ts_str:
                try:
                    dt = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
                    timestamps.append(dt)
                except:
                    continue
        
        if len(timestamps) > 1:
            # Check for burst activity
            deltas = [(timestamps[i+1] - timestamps[i]).total_seconds() 
                     for i in range(len(timestamps)-1)]
            
            avg_delta = sum(deltas) / len(deltas) if deltas else 0
            
            # Identify bursts (events closer than 25% of average)
            burst_threshold = avg_delta * 0.25
            bursts = [i for i, d in enumerate(deltas) if d < burst_threshold]
            
            if len(bursts) > len(deltas) * 0.3:
                patterns.append({
                    'pattern': 'Burst Activity',
                    'description': 'Multiple events in rapid succession',
                    'confidence': 0.8
                })
        
        return patterns
    
    def _calculate_event_frequency(self, events: List[Dict[str, Any]]) -> Dict[str, int]:
        """Calculate event frequency by type"""
        frequency = defaultdict(int)
        
        for event in events:
            event_type = event.get('event', 'unknown')
            frequency[event_type] += 1
        
        return dict(frequency)
    
    def _identify_critical_periods(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify critical time periods"""
        critical_periods = []
        
        # Group by time windows
        windows = self._group_by_time_windows(events)
        
        # Find windows with high severity events
        for window, window_events in windows.items():
            severity_scores = []
            for event in window_events:
                severity = event.get('severity', 'LOW').upper()
                if severity == 'CRITICAL':
                    severity_scores.append(1.0)
                elif severity == 'HIGH':
                    severity_scores.append(0.8)
                elif severity == 'MEDIUM':
                    severity_scores.append(0.5)
                else:
                    severity_scores.append(0.2)
            
            avg_severity = sum(severity_scores) / len(severity_scores) if severity_scores else 0
            
            if avg_severity >= 0.7:
                critical_periods.append({
                    'period': window,
                    'event_count': len(window_events),
                    'average_severity': avg_severity,
                    'events': window_events[:5]  # Sample events
                })
        
        return critical_periods
    
    def _extract_ioc_sources(self, iocs: List[Dict[str, Any]]) -> Dict[str, int]:
        """Extract and count IOC sources"""
        sources = defaultdict(int)
        
        for ioc in iocs:
            source = ioc.get('source', 'unknown')
            sources[source] += 1
        
        return dict(sources)
    
    def _analyze_temporal_distribution(self, iocs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze temporal distribution of IOCs"""
        timestamps = []
        
        for ioc in iocs:
            ts_str = ioc.get('first_seen', '')
            if ts_str:
                try:
                    dt = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
                    timestamps.append(dt)
                except:
                    continue
        
        if not timestamps:
            return {}
        
        timestamps.sort()
        
        return {
            'earliest': timestamps[0].isoformat(),
            'latest': timestamps[-1].isoformat(),
            'span_days': (timestamps[-1] - timestamps[0]).days,
            'distribution': 'clustered' if len(set(t.date() for t in timestamps)) < len(timestamps) * 0.5 else 'spread'
        }
    
    def _get_severity_distribution(self, items: List[Dict[str, Any]]) -> Dict[str, int]:
        """Get distribution of severity levels"""
        distribution = defaultdict(int)
        
        for item in items:
            severity = item.get('severity', 'UNKNOWN').upper()
            distribution[severity] += 1
        
        return dict(distribution)
    
    def _get_ioc_type_distribution(self, iocs: List[Dict[str, Any]]) -> Dict[str, int]:
        """Get distribution of IOC types"""
        distribution = defaultdict(int)
        
        for ioc in iocs:
            ioc_type = ioc.get('type', 'unknown')
            distribution[ioc_type] += 1
        
        return dict(distribution)

# Singleton instance
_context_builder = None

def get_context_builder() -> ContextBuilder:
    """Get or create context builder instance"""
    global _context_builder
    
    if _context_builder is None:
        _context_builder = ContextBuilder()
    
    return _context_builder