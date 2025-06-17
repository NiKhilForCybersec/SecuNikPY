"""
SecuNik - Context Builder (Evidence Context for AI)
Builds structured context from forensic evidence for AI analysis

Location: backend/app/core/ai/context_builder.py
"""

import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any, Union
from collections import Counter

from ...models.analysis import AnalysisResult, IOC, IOCType

logger = logging.getLogger(__name__)

class ContextBuilder:
    """Builds structured context from forensic evidence for AI analysis"""
    
    def __init__(self):
        self.max_context_size = 15000  # Maximum context size to prevent prompt overflow
        self.ioc_type_priorities = {
            IOCType.FILE_HASH: 10,
            IOCType.IP_ADDRESS: 9,
            IOCType.DOMAIN: 8,
            IOCType.URL: 7,
            IOCType.EMAIL_ADDRESS: 6,
            IOCType.FILE_PATH: 5,
            IOCType.REGISTRY_KEY: 4,
            IOCType.USER_AGENT: 3,
            IOCType.USERNAME: 2
        }

    def build_file_context(self, analysis_result: AnalysisResult) -> Dict[str, Any]:
        """
        Build comprehensive context for single file analysis
        
        Args:
            analysis_result: Analysis result from a parser
            
        Returns:
            Structured context dictionary for AI analysis
        """
        try:
            context = {
                "file_path": analysis_result.file_path,
                "parser_name": analysis_result.parser_name,
                "analysis_type": analysis_result.analysis_type,
                "timestamp": analysis_result.timestamp.isoformat(),
                "summary": analysis_result.summary,
                "severity": analysis_result.severity.value if analysis_result.severity else "UNKNOWN",
                "risk_score": analysis_result.risk_score,
                "file_type": self._determine_file_type(analysis_result.file_path),
                "threats": self._format_threats_for_context(analysis_result.threats_detected),
                "iocs": self._format_iocs_for_context(analysis_result.iocs_found),
                "details": self._summarize_details_for_context(analysis_result.details),
                "recommendations": analysis_result.recommendations,
                "key_findings": self._extract_key_findings(analysis_result)
            }
            
            # Truncate context if too large
            context = self._truncate_context(context)
            
            logger.debug(f"Built file context for {analysis_result.file_path}")
            return context
            
        except Exception as e:
            logger.error(f"Error building file context: {str(e)}")
            return self._create_minimal_context(analysis_result)

    def build_multi_file_context(self, analysis_results: List[AnalysisResult]) -> Dict[str, Any]:
        """
        Build context for multiple file correlation analysis
        
        Args:
            analysis_results: List of analysis results
            
        Returns:
            Structured context for correlation analysis
        """
        try:
            context = {
                "file_count": len(analysis_results),
                "analysis_timestamp": datetime.now().isoformat(),
                "files": [],
                "aggregate_summary": self._build_aggregate_summary(analysis_results),
                "all_threats": [],
                "all_iocs": [],
                "threat_correlation": self._analyze_threat_correlation(analysis_results),
                "ioc_correlation": self._analyze_ioc_correlation(analysis_results),
                "timeline": self._build_multi_file_timeline(analysis_results),
                "file_relationships": self._analyze_file_relationships(analysis_results)
            }
            
            # Add individual file summaries
            for result in analysis_results:
                file_summary = {
                    "file_path": result.file_path,
                    "analysis_type": result.analysis_type,
                    "severity": result.severity.value if result.severity else "UNKNOWN",
                    "risk_score": result.risk_score,
                    "threat_count": len(result.threats_detected),
                    "ioc_count": len(result.iocs_found),
                    "summary": result.summary[:200]  # Truncate for overview
                }
                context["files"].append(file_summary)
                
                # Aggregate threats and IOCs
                context["all_threats"].extend(self._format_threats_for_context(result.threats_detected))
                context["all_iocs"].extend(self._format_iocs_for_context(result.iocs_found))
            
            # Truncate context if too large
            context = self._truncate_context(context)
            
            logger.debug(f"Built multi-file context for {len(analysis_results)} files")
            return context
            
        except Exception as e:
            logger.error(f"Error building multi-file context: {str(e)}")
            return {"error": f"Context building failed: {str(e)}"}

    def build_conversation_context(self, user_question: str, analysis_data: Dict[str, Any], 
                                 conversation_history: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Build context for interactive chat about analysis
        
        Args:
            user_question: User's question
            analysis_data: Relevant analysis data
            conversation_history: Previous conversation messages
            
        Returns:
            Structured context for chat interaction
        """
        try:
            context = {
                "user_question": user_question,
                "analysis_data": self._summarize_analysis_for_chat(analysis_data),
                "conversation_history": self._format_conversation_history(conversation_history),
                "question_type": self._classify_question_type(user_question),
                "relevant_data": self._extract_relevant_data(user_question, analysis_data)
            }
            
            logger.debug("Built conversation context")
            return context
            
        except Exception as e:
            logger.error(f"Error building conversation context: {str(e)}")
            return {"user_question": user_question, "error": str(e)}

    def build_ioc_context(self, iocs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Build context for threat intelligence analysis from IOCs
        
        Args:
            iocs: List of IOC dictionaries
            
        Returns:
            Structured context for threat intelligence
        """
        try:
            context = {
                "total_iocs": len(iocs),
                "iocs": self._prioritize_iocs_for_analysis(iocs),
                "ioc_summary": self._summarize_ioc_distribution(iocs),
                "high_confidence_iocs": self._filter_high_confidence_iocs(iocs),
                "network_indicators": self._extract_network_indicators(iocs),
                "file_indicators": self._extract_file_indicators(iocs),
                "behavioral_indicators": self._extract_behavioral_indicators(iocs)
            }
            
            logger.debug(f"Built IOC context for {len(iocs)} indicators")
            return context
            
        except Exception as e:
            logger.error(f"Error building IOC context: {str(e)}")
            return {"error": f"IOC context building failed: {str(e)}"}

    def build_incident_context(self, analysis_results: List[AnalysisResult], 
                             incident_metadata: Dict[str, Any]) -> Dict[str, Any]:
        """
        Build context for incident report generation
        
        Args:
            analysis_results: List of analysis results
            incident_metadata: Additional incident information
            
        Returns:
            Structured context for incident reporting
        """
        try:
            context = {
                "incident_id": incident_metadata.get("incident_id", "Unknown"),
                "detection_time": incident_metadata.get("detection_time", "Unknown"),
                "affected_systems": incident_metadata.get("affected_systems", []),
                "business_impact": incident_metadata.get("business_impact", "Unknown"),
                "incident_type": incident_metadata.get("incident_type", "Security Incident"),
                "evidence_summary": self._build_evidence_summary(analysis_results),
                "timeline": self._build_incident_timeline(analysis_results, incident_metadata),
                "impact_assessment": self._assess_incident_impact(analysis_results, incident_metadata),
                "containment_actions": incident_metadata.get("containment_actions", []),
                "response_team": incident_metadata.get("response_team", [])
            }
            
            logger.debug(f"Built incident context for incident {context['incident_id']}")
            return context
            
        except Exception as e:
            logger.error(f"Error building incident context: {str(e)}")
            return {"error": f"Incident context building failed: {str(e)}"}

    def _determine_file_type(self, file_path: str) -> str:
        """Determine file type from path"""
        if not file_path:
            return "Unknown"
        
        extension = file_path.lower().split('.')[-1] if '.' in file_path else ""
        
        file_type_map = {
            "evtx": "Windows Event Log",
            "pcap": "Network Capture", 
            "pcapng": "Network Capture",
            "pst": "Email Archive",
            "eml": "Email Message",
            "exe": "Executable",
            "dll": "Dynamic Library",
            "sys": "System Driver",
            "reg": "Registry File",
            "pdf": "PDF Document",
            "doc": "Word Document",
            "docx": "Word Document",
            "zip": "Archive"
        }
        
        return file_type_map.get(extension, f"File (.{extension})" if extension else "Unknown")

    def _format_threats_for_context(self, threats: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Format threats for AI context"""
        formatted_threats = []
        
        for threat in threats[:10]:  # Limit to top 10 threats
            formatted_threat = {
                "type": threat.get("type", "Unknown"),
                "severity": threat.get("severity", "Unknown"),
                "description": threat.get("description", "No description")[:200],  # Truncate
                "confidence": threat.get("confidence", "Unknown"),
                "indicators": threat.get("indicators", [])[:5]  # Limit indicators
            }
            formatted_threats.append(formatted_threat)
        
        return formatted_threats

    def _format_iocs_for_context(self, iocs: List[IOC]) -> List[Dict[str, Any]]:
        """Format IOCs for AI context"""
        formatted_iocs = []
        
        # Sort IOCs by priority and confidence
        sorted_iocs = sorted(iocs, key=lambda x: (
            self.ioc_type_priorities.get(x.type, 0),
            x.confidence
        ), reverse=True)
        
        for ioc in sorted_iocs[:20]:  # Limit to top 20 IOCs
            formatted_ioc = {
                "type": ioc.type.value if hasattr(ioc.type, 'value') else str(ioc.type),
                "value": ioc.value,
                "confidence": ioc.confidence,
                "source": ioc.source,
                "description": ioc.description[:100] if ioc.description else ""  # Truncate
            }
            formatted_iocs.append(formatted_ioc)
        
        return formatted_iocs

    def _summarize_details_for_context(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Summarize technical details for context"""
        if not details:
            return {}
        
        summary = {}
        
        # Prioritize important details
        priority_keys = [
            "file_info", "pe_header", "registry_hive", "email_analysis",
            "network_analysis", "total_packets", "total_emails", "autostart_analysis"
        ]
        
        # Add priority keys first
        for key in priority_keys:
            if key in details:
                summary[key] = self._summarize_detail_value(details[key])
        
        # Add other keys up to limit
        remaining_keys = [k for k in details.keys() if k not in priority_keys]
        for key in remaining_keys[:10]:  # Limit additional keys
            summary[key] = self._summarize_detail_value(details[key])
        
        return summary

    def _summarize_detail_value(self, value: Any) -> Any:
        """Summarize a detail value"""
        if isinstance(value, dict):
            if len(value) > 10:
                # Return summary for large dicts
                return {
                    "_summary": f"Dictionary with {len(value)} keys",
                    "_sample_keys": list(value.keys())[:5]
                }
            return value
        elif isinstance(value, list):
            if len(value) > 10:
                # Return summary for large lists
                return {
                    "_summary": f"List with {len(value)} items",
                    "_sample_items": value[:3]
                }
            return value
        elif isinstance(value, str) and len(value) > 500:
            # Truncate long strings
            return value[:500] + "..."
        else:
            return value

    def _extract_key_findings(self, analysis_result: AnalysisResult) -> List[str]:
        """Extract key findings from analysis result"""
        findings = []
        
        # Add severity-based finding
        if analysis_result.severity:
            findings.append(f"Severity Level: {analysis_result.severity.value}")
        
        # Add risk score finding
        if analysis_result.risk_score is not None:
            risk_level = "Low" if analysis_result.risk_score < 30 else "Medium" if analysis_result.risk_score < 70 else "High"
            findings.append(f"Risk Score: {analysis_result.risk_score}/100 ({risk_level})")
        
        # Add threat findings
        if analysis_result.threats_detected:
            threat_types = [t.get("type", "Unknown") for t in analysis_result.threats_detected]
            unique_threats = list(set(threat_types))
            findings.append(f"Threats Detected: {', '.join(unique_threats[:3])}")
        
        # Add IOC findings
        if analysis_result.iocs_found:
            ioc_types = [ioc.type.value if hasattr(ioc.type, 'value') else str(ioc.type) 
                        for ioc in analysis_result.iocs_found]
            unique_ioc_types = list(set(ioc_types))
            findings.append(f"IOC Types: {', '.join(unique_ioc_types[:3])}")
        
        return findings

    def _build_aggregate_summary(self, analysis_results: List[AnalysisResult]) -> Dict[str, Any]:
        """Build aggregate summary across multiple analyses"""
        total_threats = sum(len(result.threats_detected) for result in analysis_results)
        total_iocs = sum(len(result.iocs_found) for result in analysis_results)
        
        # Aggregate risk scores
        risk_scores = [result.risk_score for result in analysis_results if result.risk_score is not None]
        avg_risk_score = sum(risk_scores) / len(risk_scores) if risk_scores else 0
        
        # Aggregate severities
        severity_counts = Counter(result.severity.value if result.severity else "UNKNOWN" 
                                for result in analysis_results)
        
        return {
            "total_files": len(analysis_results),
            "total_threats": total_threats,
            "total_iocs": total_iocs,
            "average_risk_score": round(avg_risk_score, 2),
            "severity_distribution": dict(severity_counts),
            "analysis_types": list(set(result.analysis_type for result in analysis_results))
        }

    def _analyze_threat_correlation(self, analysis_results: List[AnalysisResult]) -> Dict[str, Any]:
        """Analyze threat correlations across files"""
        all_threats = []
        for result in analysis_results:
            for threat in result.threats_detected:
                threat_copy = threat.copy()
                threat_copy["source_file"] = result.file_path
                all_threats.append(threat_copy)
        
        # Count threat types
        threat_type_counts = Counter(threat.get("type", "Unknown") for threat in all_threats)
        
        # Find files with similar threats
        file_threat_types = {}
        for result in analysis_results:
            threat_types = set(threat.get("type", "Unknown") for threat in result.threats_detected)
            file_threat_types[result.file_path] = threat_types
        
        # Find common threat patterns
        common_threats = [threat_type for threat_type, count in threat_type_counts.items() if count > 1]
        
        return {
            "threat_type_distribution": dict(threat_type_counts),
            "common_threats": common_threats,
            "files_with_threats": len([f for f in file_threat_types.values() if f]),
            "threat_overlap": self._calculate_threat_overlap(file_threat_types)
        }

    def _analyze_ioc_correlation(self, analysis_results: List[AnalysisResult]) -> Dict[str, Any]:
        """Analyze IOC correlations across files"""
        all_iocs = []
        ioc_values = Counter()
        
        for result in analysis_results:
            for ioc in result.iocs_found:
                ioc_dict = {
                    "type": ioc.type.value if hasattr(ioc.type, 'value') else str(ioc.type),
                    "value": ioc.value,
                    "confidence": ioc.confidence,
                    "source_file": result.file_path
                }
                all_iocs.append(ioc_dict)
                ioc_values[ioc.value] += 1
        
        # Find shared IOCs
        shared_iocs = [value for value, count in ioc_values.items() if count > 1]
        
        # IOC type distribution
        ioc_type_counts = Counter(ioc["type"] for ioc in all_iocs)
        
        return {
            "total_unique_iocs": len(set(ioc["value"] for ioc in all_iocs)),
            "shared_iocs": shared_iocs[:10],  # Top 10 shared IOCs
            "ioc_type_distribution": dict(ioc_type_counts),
            "files_with_iocs": len([r for r in analysis_results if r.iocs_found])
        }

    def _build_multi_file_timeline(self, analysis_results: List[AnalysisResult]) -> List[Dict[str, Any]]:
        """Build timeline across multiple files"""
        timeline_events = []
        
        for result in analysis_results:
            # Add analysis timestamp as an event
            timeline_events.append({
                "timestamp": result.timestamp,
                "event_type": "Analysis Completed",
                "description": f"Completed {result.analysis_type} for {result.file_path}",
                "file": result.file_path,
                "severity": result.severity.value if result.severity else "UNKNOWN"
            })
            
            # Extract timeline from details if available
            if result.details and "timeline" in result.details:
                file_timeline = result.details["timeline"]
                if isinstance(file_timeline, list):
                    for event in file_timeline[:5]:  # Limit events per file
                        if isinstance(event, dict) and "timestamp" in event:
                            timeline_event = {
                                "timestamp": event["timestamp"],
                                "event_type": event.get("event_type", "File Event"),
                                "description": event.get("description", "Timeline event"),
                                "file": result.file_path
                            }
                            timeline_events.append(timeline_event)
        
        # Sort by timestamp
        timeline_events.sort(key=lambda x: x["timestamp"])
        
        return timeline_events[:20]  # Return top 20 events

    def _analyze_file_relationships(self, analysis_results: List[AnalysisResult]) -> Dict[str, Any]:
        """Analyze relationships between files"""
        relationships = {
            "potential_relationships": [],
            "file_types": Counter(),
            "analysis_patterns": {}
        }
        
        # Count file types
        for result in analysis_results:
            file_type = self._determine_file_type(result.file_path)
            relationships["file_types"][file_type] += 1
        
        # Look for potential relationships based on IOCs and threats
        shared_indicators = {}
        for i, result1 in enumerate(analysis_results):
            for j, result2 in enumerate(analysis_results[i+1:], i+1):
                shared_count = self._count_shared_indicators(result1, result2)
                if shared_count > 0:
                    relationships["potential_relationships"].append({
                        "file1": result1.file_path,
                        "file2": result2.file_path,
                        "shared_indicators": shared_count,
                        "relationship_strength": "High" if shared_count > 5 else "Medium" if shared_count > 2 else "Low"
                    })
        
        return relationships

    def _count_shared_indicators(self, result1: AnalysisResult, result2: AnalysisResult) -> int:
        """Count shared indicators between two analysis results"""
        # Get IOC values from both results
        iocs1 = set(ioc.value for ioc in result1.iocs_found)
        iocs2 = set(ioc.value for ioc in result2.iocs_found)
        
        # Get threat types from both results
        threats1 = set(threat.get("type", "") for threat in result1.threats_detected)
        threats2 = set(threat.get("type", "") for threat in result2.threats_detected)
        
        # Count shared items
        shared_iocs = len(iocs1.intersection(iocs2))
        shared_threats = len(threats1.intersection(threats2))
        
        return shared_iocs + shared_threats

    def _calculate_threat_overlap(self, file_threat_types: Dict[str, set]) -> float:
        """Calculate threat overlap percentage across files"""
        if len(file_threat_types) < 2:
            return 0.0
        
        all_threat_types = set()
        for threat_types in file_threat_types.values():
            all_threat_types.update(threat_types)
        
        if not all_threat_types:
            return 0.0
        
        # Calculate average overlap
        total_overlap = 0
        comparisons = 0
        
        files = list(file_threat_types.keys())
        for i in range(len(files)):
            for j in range(i+1, len(files)):
                types1 = file_threat_types[files[i]]
                types2 = file_threat_types[files[j]]
                
                if types1 or types2:
                    overlap = len(types1.intersection(types2))
                    union = len(types1.union(types2))
                    overlap_ratio = overlap / union if union > 0 else 0
                    total_overlap += overlap_ratio
                    comparisons += 1
        
        return (total_overlap / comparisons) * 100 if comparisons > 0 else 0.0

    def _summarize_analysis_for_chat(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Summarize analysis data for chat context"""
        if not analysis_data:
            return {}
        
        summary = {}
        
        # Include key fields for chat
        chat_relevant_keys = [
            "file_path", "analysis_type", "summary", "severity", "risk_score",
            "threats", "iocs", "recommendations"
        ]
        
        for key in chat_relevant_keys:
            if key in analysis_data:
                if key in ["threats", "iocs"] and isinstance(analysis_data[key], list):
                    # Limit list sizes for chat
                    summary[key] = analysis_data[key][:5]
                else:
                    summary[key] = analysis_data[key]
        
        return summary

    def _format_conversation_history(self, conversation_history: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Format conversation history for context"""
        formatted_history = []
        
        # Include last 5 exchanges for context
        recent_history = conversation_history[-10:] if len(conversation_history) > 10 else conversation_history
        
        for msg in recent_history:
            formatted_msg = {
                "role": msg.get("role", "unknown"),
                "content": msg.get("content", "")[:200],  # Truncate for context
                "timestamp": msg.get("timestamp", "")
            }
            formatted_history.append(formatted_msg)
        
        return formatted_history

    def _classify_question_type(self, user_question: str) -> str:
        """Classify the type of user question"""
        question_lower = user_question.lower()
        
        if any(word in question_lower for word in ["what", "which", "who"]):
            return "factual"
        elif any(word in question_lower for word in ["how", "why"]):
            return "explanatory"
        elif any(word in question_lower for word in ["should", "recommend", "suggest"]):
            return "recommendation"
        elif any(word in question_lower for word in ["threat", "malware", "attack"]):
            return "security_analysis"
        elif any(word in question_lower for word in ["ioc", "indicator", "compromise"]):
            return "ioc_analysis"
        else:
            return "general"

    def _extract_relevant_data(self, user_question: str, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract data relevant to the user's question"""
        question_lower = user_question.lower()
        relevant_data = {}
        
        # Map question keywords to relevant data
        keyword_mapping = {
            "threat": ["threats", "threat_assessment", "suspicious_indicators"],
            "ioc": ["iocs", "indicators", "ioc_analysis"],
            "malware": ["threats", "pe_header", "packer_detection"],
            "network": ["network_analysis", "pcap_analysis", "flows"],
            "email": ["email_analysis", "phishing_analysis", "attachments"],
            "registry": ["registry_analysis", "autostart_analysis"],
            "file": ["file_info", "file_analysis", "hash"]
        }
        
        for keyword, data_keys in keyword_mapping.items():
            if keyword in question_lower:
                for data_key in data_keys:
                    if data_key in analysis_data:
                        relevant_data[data_key] = analysis_data[data_key]
        
        # If no specific matches, include summary data
        if not relevant_data:
            summary_keys = ["summary", "severity", "risk_score", "threats", "iocs"]
            for key in summary_keys:
                if key in analysis_data:
                    relevant_data[key] = analysis_data[key]
        
        return relevant_data

    def _prioritize_iocs_for_analysis(self, iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Prioritize IOCs for threat intelligence analysis"""
        # Sort by confidence and type priority
        def ioc_priority(ioc):
            ioc_type = ioc.get("type", "unknown")
            confidence = ioc.get("confidence", 0)
            type_priority = self.ioc_type_priorities.get(ioc_type, 0)
            return (confidence, type_priority)
        
        sorted_iocs = sorted(iocs, key=ioc_priority, reverse=True)
        return sorted_iocs[:25]  # Top 25 IOCs for analysis

    def _summarize_ioc_distribution(self, iocs: List[Dict[str, Any]]) -> Dict[str, int]:
        """Summarize IOC type distribution"""
        ioc_types = [ioc.get("type", "unknown") for ioc in iocs]
        return dict(Counter(ioc_types))

    def _filter_high_confidence_iocs(self, iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Filter IOCs with high confidence levels"""
        return [ioc for ioc in iocs if ioc.get("confidence", 0) > 0.7]

    def _extract_network_indicators(self, iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract network-related indicators"""
        network_types = ["IP_ADDRESS", "DOMAIN", "URL"]
        return [ioc for ioc in iocs if ioc.get("type") in network_types]

    def _extract_file_indicators(self, iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract file-related indicators"""
        file_types = ["FILE_HASH", "FILE_PATH"]
        return [ioc for ioc in iocs if ioc.get("type") in file_types]

    def _extract_behavioral_indicators(self, iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract behavioral indicators"""
        behavioral_types = ["REGISTRY_KEY", "USER_AGENT", "USERNAME"]
        return [ioc for ioc in iocs if ioc.get("type") in behavioral_types]

    def _build_evidence_summary(self, analysis_results: List[AnalysisResult]) -> Dict[str, Any]:
        """Build evidence summary for incident reporting"""
        evidence_types = Counter()
        total_threats = 0
        total_iocs = 0
        
        for result in analysis_results:
            evidence_types[result.analysis_type] += 1
            total_threats += len(result.threats_detected)
            total_iocs += len(result.iocs_found)
        
        return {
            "evidence_files": len(analysis_results),
            "evidence_types": dict(evidence_types),
            "total_threats": total_threats,
            "total_iocs": total_iocs,
            "analysis_timespan": self._calculate_analysis_timespan(analysis_results)
        }

    def _build_incident_timeline(self, analysis_results: List[AnalysisResult], 
                                incident_metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Build incident timeline"""
        timeline = []
        
        # Add detection event
        detection_time = incident_metadata.get("detection_time")
        if detection_time:
            timeline.append({
                "timestamp": detection_time,
                "action": "Incident Detected",
                "actor": "Security Team",
                "description": "Initial incident detection"
            })
        
        # Add analysis events
        for result in analysis_results:
            timeline.append({
                "timestamp": result.timestamp.isoformat(),
                "action": "Evidence Analysis",
                "actor": "Forensic Analyst",
                "description": f"Analyzed {result.file_path} - {result.analysis_type}"
            })
        
        # Add containment actions
        containment_actions = incident_metadata.get("containment_actions", [])
        for action in containment_actions:
            if isinstance(action, dict):
                timeline.append({
                    "timestamp": action.get("timestamp", "Unknown"),
                    "action": action.get("action", "Containment Action"),
                    "actor": action.get("actor", "Response Team"),
                    "description": action.get("description", "Containment measure taken")
                })
        
        # Sort timeline by timestamp
        timeline.sort(key=lambda x: x.get("timestamp", ""))
        
        return timeline

    def _assess_incident_impact(self, analysis_results: List[AnalysisResult], 
                              incident_metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Assess incident impact"""
        # Calculate severity distribution
        severities = [result.severity.value if result.severity else "UNKNOWN" 
                     for result in analysis_results]
        severity_counts = Counter(severities)
        
        # Calculate average risk score
        risk_scores = [result.risk_score for result in analysis_results 
                      if result.risk_score is not None]
        avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0
        
        return {
            "severity_distribution": dict(severity_counts),
            "average_risk_score": round(avg_risk, 2),
            "affected_systems": incident_metadata.get("affected_systems", []),
            "business_impact": incident_metadata.get("business_impact", "Unknown"),
            "data_classification": incident_metadata.get("data_classification", "Unknown"),
            "estimated_cost": incident_metadata.get("estimated_cost", "Unknown")
        }

    def _calculate_analysis_timespan(self, analysis_results: List[AnalysisResult]) -> Dict[str, str]:
        """Calculate timespan of analysis"""
        if not analysis_results:
            return {}
        
        timestamps = [result.timestamp for result in analysis_results]
        start_time = min(timestamps)
        end_time = max(timestamps)
        
        return {
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "duration": str(end_time - start_time)
        }

    def _truncate_context(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Truncate context if it exceeds size limits"""
        # Estimate context size (rough approximation)
        context_str = json.dumps(context, default=str)
        
        if len(context_str) > self.max_context_size:
            logger.warning(f"Context size ({len(context_str)}) exceeds limit, truncating")
            
            # Truncate lists and large text fields
            if "threats" in context and isinstance(context["threats"], list):
                context["threats"] = context["threats"][:5]
            
            if "iocs" in context and isinstance(context["iocs"], list):
                context["iocs"] = context["iocs"][:10]
            
            if "details" in context and isinstance(context["details"], dict):
                # Keep only the most important details
                important_keys = list(context["details"].keys())[:5]
                context["details"] = {k: context["details"][k] for k in important_keys}
        
        return context

    def _create_minimal_context(self, analysis_result: AnalysisResult) -> Dict[str, Any]:
        """Create minimal context when full context building fails"""
        return {
            "file_path": analysis_result.file_path,
            "analysis_type": analysis_result.analysis_type,
            "summary": analysis_result.summary,
            "error": "Full context building failed, using minimal context"
        }