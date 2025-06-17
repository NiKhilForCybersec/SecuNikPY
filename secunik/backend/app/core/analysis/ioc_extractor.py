"""
Analysis Correlator for SecuNik
Correlates findings across multiple analysis results
"""

import logging
from typing import Dict, Any, List, Set, Tuple
from datetime import datetime, timedelta
from collections import defaultdict
import networkx as nx

from ...models.analysis import AnalysisResult, IOC, ThreatInfo

logger = logging.getLogger(__name__)

class Correlator:
    """Correlates findings across multiple analysis results"""
    
    def __init__(self):
        self.correlation_rules = {
            'ioc_overlap': self._correlate_by_iocs,
            'temporal_proximity': self._correlate_by_time,
            'threat_similarity': self._correlate_by_threats,
            'file_relationships': self._correlate_by_file_properties,
            'attack_patterns': self._correlate_by_attack_patterns
        }
        
        # Correlation thresholds
        self.thresholds = {
            'ioc_similarity': 0.3,  # 30% IOC overlap
            'temporal_window': 3600,  # 1 hour in seconds
            'threat_similarity': 0.5,  # 50% threat type overlap
            'confidence_minimum': 0.6  # Minimum confidence for correlation
        }
    
    async def correlate_results(self, 
                              results: List[AnalysisResult],
                              correlation_types: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Correlate multiple analysis results"""
        if len(results) < 2:
            return []
        
        # Use all correlation types if not specified
        if correlation_types is None:
            correlation_types = list(self.correlation_rules.keys())
        
        # Build correlation graph
        correlation_graph = nx.Graph()
        
        # Add nodes (analysis results)
        for i, result in enumerate(results):
            correlation_graph.add_node(i, result=result)
        
        # Run correlation rules
        correlations = []
        for corr_type in correlation_types:
            if corr_type in self.correlation_rules:
                rule_correlations = await self.correlation_rules[corr_type](results)
                correlations.extend(rule_correlations)
                
                # Add edges to graph
                for corr in rule_correlations:
                    if corr['confidence'] >= self.thresholds['confidence_minimum']:
                        correlation_graph.add_edge(
                            corr['source_index'],
                            corr['target_index'],
                            weight=corr['confidence'],
                            type=corr_type
                        )
        
        # Find correlation clusters
        clusters = self._find_correlation_clusters(correlation_graph)
        
        # Build correlation summary for each result
        result_correlations = []
        for i, result in enumerate(results):
            result_corr = {
                'file_id': getattr(result, 'file_id', ''),
                'file_path': result.file_path,
                'correlations': [],
                'cluster_id': None,
                'correlation_score': 0.0
            }
            
            # Find direct correlations
            for corr in correlations:
                if corr['source_index'] == i or corr['target_index'] == i:
                    result_corr['correlations'].append(corr)
            
            # Calculate correlation score
            if result_corr['correlations']:
                result_corr['correlation_score'] = max(
                    c['confidence'] for c in result_corr['correlations']
                )
            
            # Find cluster membership
            for cluster_id, cluster_nodes in enumerate(clusters):
                if i in cluster_nodes:
                    result_corr['cluster_id'] = cluster_id
                    break
            
            result_correlations.append(result_corr)
        
        return result_correlations
    
    async def _correlate_by_iocs(self, results: List[AnalysisResult]) -> List[Dict[str, Any]]:
        """Correlate results based on shared IOCs"""
        correlations = []
        
        # Build IOC index
        ioc_index = defaultdict(list)
        for i, result in enumerate(results):
            for ioc in result.iocs_found:
                ioc_key = f"{ioc.type}:{ioc.value}"
                ioc_index[ioc_key].append(i)
        
        # Find results sharing IOCs
        for i in range(len(results)):
            for j in range(i + 1, len(results)):
                shared_iocs = []
                
                # Count shared IOCs
                for ioc in results[i].iocs_found:
                    ioc_key = f"{ioc.type}:{ioc.value}"
                    if j in ioc_index[ioc_key]:
                        shared_iocs.append(ioc)
                
                if shared_iocs:
                    # Calculate overlap percentage
                    total_iocs = len(results[i].iocs_found) + len(results[j].iocs_found)
                    overlap_ratio = (2 * len(shared_iocs)) / total_iocs if total_iocs > 0 else 0
                    
                    if overlap_ratio >= self.thresholds['ioc_similarity']:
                        correlations.append({
                            'source_index': i,
                            'target_index': j,
                            'type': 'ioc_overlap',
                            'confidence': min(overlap_ratio * 1.5, 1.0),  # Boost confidence
                            'evidence': {
                                'shared_iocs': [
                                    {
                                        'type': ioc.type,
                                        'value': ioc.value,
                                        'confidence': ioc.confidence
                                    } for ioc in shared_iocs[:10]  # Limit to 10
                                ],
                                'overlap_ratio': overlap_ratio
                            },
                            'description': f"Files share {len(shared_iocs)} IOCs ({overlap_ratio:.1%} overlap)"
                        })
        
        return correlations
    
    async def _correlate_by_time(self, results: List[AnalysisResult]) -> List[Dict[str, Any]]:
        """Correlate results based on temporal proximity"""
        correlations = []
        
        # Extract timestamps from results
        timestamps = []
        for i, result in enumerate(results):
            # Try to extract meaningful timestamp
            ts = None
            
            # Check timeline events
            timeline = result.details.get('timeline', [])
            if timeline:
                # Get earliest event
                for event in timeline:
                    event_ts = event.get('timestamp')
                    if event_ts:
                        try:
                            dt = datetime.fromisoformat(event_ts.replace('Z', '+00:00'))
                            if ts is None or dt < ts:
                                ts = dt
                        except:
                            continue
            
            # Use analysis timestamp as fallback
            if ts is None:
                ts = result.timestamp
            
            timestamps.append((i, ts))
        
        # Find temporally close results
        for i, (idx1, ts1) in enumerate(timestamps):
            for j, (idx2, ts2) in enumerate(timestamps[i+1:], i+1):
                if ts1 and ts2:
                    time_diff = abs((ts2 - ts1).total_seconds())
                    
                    if time_diff <= self.thresholds['temporal_window']:
                        # Calculate confidence based on proximity
                        confidence = 1.0 - (time_diff / self.thresholds['temporal_window'])
                        confidence = max(confidence, 0.5)  # Minimum 50% for temporal correlation
                        
                        correlations.append({
                            'source_index': idx1,
                            'target_index': idx2,
                            'type': 'temporal_proximity',
                            'confidence': confidence,
                            'evidence': {
                                'time_difference_seconds': time_diff,
                                'timestamp1': ts1.isoformat(),
                                'timestamp2': ts2.isoformat()
                            },
                            'description': f"Events occurred within {time_diff:.0f} seconds of each other"
                        })
        
        return correlations
    
    async def _correlate_by_threats(self, results: List[AnalysisResult]) -> List[Dict[str, Any]]:
        """Correlate results based on similar threats"""
        correlations = []
        
        for i in range(len(results)):
            for j in range(i + 1, len(results)):
                # Get threat types for each result
                threats1 = set(t.threat_type for t in results[i].threats_detected)
                threats2 = set(t.threat_type for t in results[j].threats_detected)
                
                if threats1 and threats2:
                    # Calculate Jaccard similarity
                    intersection = threats1.intersection(threats2)
                    union = threats1.union(threats2)
                    similarity = len(intersection) / len(union) if union else 0
                    
                    if similarity >= self.thresholds['threat_similarity']:
                        # Find common high-severity threats
                        high_severity_common = []
                        for t1 in results[i].threats_detected:
                            for t2 in results[j].threats_detected:
                                if (t1.threat_type == t2.threat_type and 
                                    t1.severity.upper() in ['HIGH', 'CRITICAL']):
                                    high_severity_common.append(t1.threat_type)
                        
                        confidence = similarity
                        if high_severity_common:
                            confidence = min(confidence * 1.2, 1.0)  # Boost for high severity
                        
                        correlations.append({
                            'source_index': i,
                            'target_index': j,
                            'type': 'threat_similarity',
                            'confidence': confidence,
                            'evidence': {
                                'common_threats': list(intersection)[:10],
                                'similarity_score': similarity,
                                'high_severity_common': list(set(high_severity_common))
                            },
                            'description': f"Files share {len(intersection)} threat types ({similarity:.1%} similarity)"
                        })
        
        return correlations
    
    async def _correlate_by_file_properties(self, results: List[AnalysisResult]) -> List[Dict[str, Any]]:
        """Correlate results based on file properties"""
        correlations = []
        
        for i in range(len(results)):
            for j in range(i + 1, len(results)):
                similarities = []
                
                # Check file type similarity
                type1 = results[i].analysis_type
                type2 = results[j].analysis_type
                if type1 == type2:
                    similarities.append(('file_type', type1))
                
                # Check for similar file sizes (if available)
                size1 = results[i].details.get('file_size')
                size2 = results[j].details.get('file_size')
                if size1 and size2:
                    size_ratio = min(size1, size2) / max(size1, size2)
                    if size_ratio > 0.9:  # Within 10% size difference
                        similarities.append(('similar_size', f"{size_ratio:.1%}"))
                
                # Check for similar hashes in details
                hash1 = results[i].details.get('file_hash')
                hash2 = results[j].details.get('file_hash')
                if hash1 and hash2 and hash1 == hash2:
                    similarities.append(('same_hash', hash1))
                
                # Check for similar metadata
                meta1 = results[i].details.get('metadata', {})
                meta2 = results[j].details.get('metadata', {})
                
                # Author similarity
                author1 = meta1.get('author', '').lower()
                author2 = meta2.get('author', '').lower()
                if author1 and author2 and author1 == author2:
                    similarities.append(('same_author', author1))
                
                # Creation tool similarity
                tool1 = meta1.get('creator_tool', '').lower()
                tool2 = meta2.get('creator_tool', '').lower()
                if tool1 and tool2 and tool1 == tool2:
                    similarities.append(('same_tool', tool1))
                
                if similarities:
                    # Calculate confidence based on number and type of similarities
                    confidence = min(len(similarities) * 0.25, 1.0)
                    
                    # Boost for strong indicators
                    if any(s[0] == 'same_hash' for s in similarities):
                        confidence = 1.0
                    elif any(s[0] in ['same_author', 'same_tool'] for s in similarities):
                        confidence = min(confidence * 1.5, 1.0)
                    
                    correlations.append({
                        'source_index': i,
                        'target_index': j,
                        'type': 'file_relationships',
                        'confidence': confidence,
                        'evidence': {
                            'similarities': similarities
                        },
                        'description': f"Files share {len(similarities)} properties"
                    })
        
        return correlations
    
    async def _correlate_by_attack_patterns(self, results: List[AnalysisResult]) -> List[Dict[str, Any]]:
        """Correlate results based on attack patterns"""
        correlations = []
        
        # Define attack pattern indicators
        attack_patterns = {
            'data_exfiltration': [
                'exfiltration', 'data_theft', 'upload', 'c2_communication'
            ],
            'ransomware': [
                'encryption', 'ransom', 'file_encryption', 'shadow_deletion'
            ],
            'lateral_movement': [
                'lateral', 'movement', 'credential_theft', 'network_discovery'
            ],
            'persistence': [
                'persistence', 'autostart', 'registry_modification', 'scheduled_task'
            ],
            'reconnaissance': [
                'scanning', 'discovery', 'enumeration', 'reconnaissance'
            ]
        }
        
        for i in range(len(results)):
            for j in range(i + 1, len(results)):
                # Extract attack indicators from both results
                indicators1 = self._extract_attack_indicators(results[i])
                indicators2 = self._extract_attack_indicators(results[j])
                
                # Find matching patterns
                matching_patterns = []
                for pattern_name, pattern_keywords in attack_patterns.items():
                    match1 = any(keyword in indicators1 for keyword in pattern_keywords)
                    match2 = any(keyword in indicators2 for keyword in pattern_keywords)
                    
                    if match1 and match2:
                        matching_patterns.append(pattern_name)
                
                if matching_patterns:
                    # Check for attack chain progression
                    chain_progression = self._detect_attack_chain(
                        results[i], results[j], matching_patterns
                    )
                    
                    confidence = len(matching_patterns) * 0.3
                    if chain_progression:
                        confidence = min(confidence * 1.5, 1.0)
                    
                    correlations.append({
                        'source_index': i,
                        'target_index': j,
                        'type': 'attack_patterns',
                        'confidence': confidence,
                        'evidence': {
                            'matching_patterns': matching_patterns,
                            'chain_progression': chain_progression
                        },
                        'description': f"Files show {len(matching_patterns)} matching attack patterns"
                    })
        
        return correlations
    
    def _extract_attack_indicators(self, result: AnalysisResult) -> Set[str]:
        """Extract attack indicators from analysis result"""
        indicators = set()
        
        # From threats
        for threat in result.threats_detected:
            indicators.add(threat.threat_type.lower())
            if threat.description:
                indicators.update(threat.description.lower().split())
        
        # From summary
        if result.summary:
            indicators.update(result.summary.lower().split())
        
        # From details
        for key, value in result.details.items():
            if isinstance(value, str):
                indicators.add(key.lower())
                indicators.update(value.lower().split()[:10])  # Limit words
        
        return indicators
    
    def _detect_attack_chain(self, 
                           result1: AnalysisResult,
                           result2: AnalysisResult,
                           patterns: List[str]) -> Optional[str]:
        """Detect if results show attack chain progression"""
        # Common attack chains
        attack_chains = {
            ('reconnaissance', 'lateral_movement'): 'Initial Access to Lateral Movement',
            ('lateral_movement', 'data_exfiltration'): 'Lateral Movement to Exfiltration',
            ('persistence', 'data_exfiltration'): 'Persistence to Exfiltration',
            ('reconnaissance', 'persistence'): 'Initial Access to Persistence'
        }
        
        # Check timestamps to determine order
        ts1 = result1.timestamp
        ts2 = result2.timestamp
        
        # Get patterns for each result
        patterns1 = set()
        patterns2 = set()
        
        indicators1 = self._extract_attack_indicators(result1)
        indicators2 = self._extract_attack_indicators(result2)
        
        for pattern in patterns:
            if pattern in str(indicators1):
                patterns1.add(pattern)
            if pattern in str(indicators2):
                patterns2.add(pattern)
        
        # Check for chain progression
        if ts1 < ts2:
            for p1 in patterns1:
                for p2 in patterns2:
                    if (p1, p2) in attack_chains:
                        return attack_chains[(p1, p2)]
        else:
            for p2 in patterns2:
                for p1 in patterns1:
                    if (p2, p1) in attack_chains:
                        return attack_chains[(p2, p1)]
        
        return None
    
    def _find_correlation_clusters(self, graph: nx.Graph) -> List[Set[int]]:
        """Find clusters of correlated results"""
        # Use connected components to find clusters
        clusters = []
        for component in nx.connected_components(graph):
            if len(component) > 1:  # Only interested in actual clusters
                clusters.append(component)
        
        return clusters
    
    async def find_related_files(self, 
                               target_result: AnalysisResult,
                               all_results: List[AnalysisResult],
                               min_confidence: float = 0.6) -> List[Dict[str, Any]]:
        """Find files related to a specific result"""
        # Create temporary list with target and others
        temp_results = [target_result] + [r for r in all_results if r != target_result]
        
        # Run correlation
        correlations = await self.correlate_results(temp_results)
        
        # Extract correlations for target (index 0)
        related = []
        if correlations and correlations[0]['correlations']:
            for corr in correlations[0]['correlations']:
                if corr['confidence'] >= min_confidence:
                    # Get the related file index
                    related_idx = corr['target_index'] if corr['source_index'] == 0 else corr['source_index']
                    if related_idx > 0:  # Skip target itself
                        related.append({
                            'file': temp_results[related_idx],
                            'correlation': corr
                        })
        
        # Sort by confidence
        related.sort(key=lambda x: x['correlation']['confidence'], reverse=True)
        
        return related
    
    def update_thresholds(self, threshold_updates: Dict[str, float]):
        """Update correlation thresholds"""
        self.thresholds.update(threshold_updates)
        logger.info(f"Updated correlation thresholds: {threshold_updates}")