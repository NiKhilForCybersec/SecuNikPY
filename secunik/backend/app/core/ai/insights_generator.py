"""
AI Insights Generator for SecuNik
Generates actionable insights from security analysis
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
import asyncio

from .openai_client import get_openai_client
from .context_builder import get_context_builder

logger = logging.getLogger(__name__)

class InsightsGenerator:
    """Generates AI-powered insights from security analysis"""
    
    def __init__(self):
        self.ai_client = get_openai_client()
        self.context_builder = get_context_builder()
        
        # Insight templates
        self.insight_types = {
            'threat_summary': self._generate_threat_summary,
            'risk_assessment': self._generate_risk_assessment,
            'ioc_analysis': self._generate_ioc_analysis,
            'recommendations': self._generate_recommendations,
            'executive_summary': self._generate_executive_summary,
            'technical_details': self._generate_technical_details,
            'timeline_analysis': self._generate_timeline_analysis,
            'correlation_insights': self._generate_correlation_insights
        }
    
    async def generate_comprehensive_insights(self, 
                                            analysis_results: List[Dict[str, Any]],
                                            insight_types: Optional[List[str]] = None) -> Dict[str, Any]:
        """Generate comprehensive insights from analysis results"""
        if not self.ai_client.is_configured:
            return {
                "error": "AI not configured",
                "insights": {},
                "generated": False
            }
        
        # Build context
        context = self.context_builder.build_comprehensive_context(analysis_results)
        
        # Determine which insights to generate
        if insight_types is None:
            insight_types = ['executive_summary', 'threat_summary', 'risk_assessment', 'recommendations']
        
        insights = {
            "generated_at": datetime.now().isoformat(),
            "analysis_count": len(analysis_results),
            "insights": {}
        }
        
        # Generate each type of insight
        for insight_type in insight_types:
            if insight_type in self.insight_types:
                try:
                    insight = await self.insight_types[insight_type](context)
                    insights["insights"][insight_type] = insight
                except Exception as e:
                    logger.error(f"Failed to generate {insight_type}: {str(e)}")
                    insights["insights"][insight_type] = {
                        "error": str(e),
                        "generated": False
                    }
        
        # Add overall assessment
        insights["overall_assessment"] = await self._generate_overall_assessment(insights["insights"])
        
        return insights
    
    async def generate_file_insights(self, analysis_result: Dict[str, Any]) -> Dict[str, Any]:
        """Generate insights for a single file analysis"""
        if not self.ai_client.is_configured:
            return {"error": "AI not configured"}
        
        prompt = f"""Analyze this security analysis result and provide insights:

File: {analysis_result.get('file_path', 'Unknown')}
Risk Score: {analysis_result.get('risk_score', 0)}
Threats Found: {len(analysis_result.get('threats_detected', []))}
IOCs Found: {len(analysis_result.get('iocs_found', []))}

Key Details:
{self._format_analysis_details(analysis_result)}

Provide:
1. Summary of findings
2. Risk assessment
3. Potential attack vectors
4. Recommended actions
5. Additional investigation points
"""
        
        result = await self.ai_client.complete(prompt)
        
        if "error" in result:
            return result
        
        return {
            "file_insights": result["content"],
            "generated_at": datetime.now().isoformat()
        }
    
    async def generate_quick_insights(self, data: Dict[str, Any], insight_type: str) -> Dict[str, Any]:
        """Generate quick insights for specific data"""
        if insight_type == "ioc_summary":
            return await self._quick_ioc_summary(data)
        elif insight_type == "threat_analysis":
            return await self._quick_threat_analysis(data)
        elif insight_type == "risk_explanation":
            return await self._quick_risk_explanation(data)
        else:
            return {"error": "Unknown insight type"}
    
    async def _generate_threat_summary(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Generate threat summary insights"""
        threats = context.get('aggregated_threats', [])
        
        if not threats:
            return {
                "summary": "No threats detected in the analyzed files.",
                "details": [],
                "severity": "LOW"
            }
        
        prompt = f"""Analyze these security threats and provide a comprehensive summary:

Total Threats: {len(threats)}
Threat Types: {context['statistics'].get('unique_threat_types', 0)}
Severity Distribution: {context['statistics'].get('severity_breakdown', {})}

Sample Threats:
{self._format_threats_sample(threats[:10])}

Provide:
1. Executive summary of the threat landscape
2. Most critical threats requiring immediate attention
3. Common attack patterns observed
4. Potential threat actors or campaigns
5. Overall threat severity assessment
"""
        
        result = await self.ai_client.complete(prompt)
        
        if "error" in result:
            return {"error": result["error"]}
        
        # Parse response
        return self._parse_threat_summary(result["content"], threats)
    
    async def _generate_risk_assessment(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Generate risk assessment insights"""
        prompt = f"""Perform a comprehensive risk assessment based on this security analysis:

Evidence Summary: {context['summary']}
Total Threats: {context['statistics']['total_threats']}
Total IOCs: {context['statistics']['total_iocs']}
Key Findings: {len(context['key_findings'])}

Threat Severity Breakdown:
{context['statistics'].get('severity_breakdown', {})}

High-Risk Indicators:
{self._format_key_findings(context['key_findings'][:10])}

Provide:
1. Overall risk level (CRITICAL/HIGH/MEDIUM/LOW)
2. Risk factors contributing to the assessment
3. Potential business impact
4. Likelihood of active compromise
5. Risk mitigation priorities
"""
        
        result = await self.ai_client.complete(prompt)
        
        if "error" in result:
            return {"error": result["error"]}
        
        return self._parse_risk_assessment(result["content"])
    
    async def _generate_ioc_analysis(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Generate IOC analysis insights"""
        iocs = context.get('aggregated_iocs', [])
        
        if not iocs:
            return {
                "summary": "No IOCs found in the analyzed files.",
                "details": [],
                "recommendations": []
            }
        
        # Build IOC context
        ioc_context = self.context_builder.build_ioc_context(iocs)
        
        prompt = f"""Analyze these Indicators of Compromise (IOCs):

Total IOCs: {ioc_context['total_iocs']}
IOC Types: {list(ioc_context['ioc_types'].keys())}

High Confidence IOCs:
{self._format_iocs_sample(ioc_context['high_confidence_iocs'][:20])}

Unique Indicators Summary:
- IP Addresses: {len(ioc_context['unique_indicators']['ip_addresses'])}
- Domains: {len(ioc_context['unique_indicators']['domains'])}
- File Hashes: {len(ioc_context['unique_indicators']['file_hashes'])}
- Email Addresses: {len(ioc_context['unique_indicators']['email_addresses'])}

Provide:
1. IOC analysis summary
2. Potential malicious infrastructure
3. Attribution indicators
4. Recommended blocking actions
5. Threat hunting queries
"""
        
        result = await self.ai_client.complete(prompt)
        
        if "error" in result:
            return {"error": result["error"]}
        
        return self._parse_ioc_analysis(result["content"], ioc_context)
    
    async def _generate_recommendations(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Generate actionable recommendations"""
        prompt = f"""Based on this security analysis, provide actionable recommendations:

Summary: {context['summary']}
Threats Found: {context['statistics']['total_threats']}
Risk Level: {self._calculate_overall_risk(context)}
Key Issues: {self._format_key_findings(context['key_findings'][:5])}

Provide prioritized recommendations in these categories:
1. IMMEDIATE ACTIONS (0-24 hours)
2. SHORT-TERM ACTIONS (1-7 days)
3. MEDIUM-TERM ACTIONS (1-4 weeks)
4. LONG-TERM IMPROVEMENTS (1-3 months)

For each recommendation include:
- Specific action to take
- Expected outcome
- Resources required
- Priority level
"""
        
        result = await self.ai_client.complete(prompt)
        
        if "error" in result:
            return {"error": result["error"]}
        
        return self._parse_recommendations(result["content"])
    
    async def _generate_executive_summary(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary"""
        prompt = f"""Create an executive summary of this security analysis:

Analysis Overview:
- Files Analyzed: {context['evidence_count']}
- Total Threats: {context['statistics']['total_threats']}
- Total IOCs: {context['statistics']['total_iocs']}
- Time Period: {context['analysis_timestamp']}

Key Statistics:
{self._format_statistics(context['statistics'])}

Critical Findings:
{self._format_key_findings(context['key_findings'][:5])}

Create a brief executive summary (3-5 paragraphs) that:
1. Summarizes the overall security posture
2. Highlights the most critical findings
3. Assesses the business risk
4. Provides top 3 recommendations
5. Suggests next steps

Write for a non-technical executive audience.
"""
        
        result = await self.ai_client.complete(prompt)
        
        if "error" in result:
            return {"error": result["error"]}
        
        return {
            "summary": result["content"],
            "generated_at": datetime.now().isoformat(),
            "key_metrics": {
                "files_analyzed": context['evidence_count'],
                "threats_found": context['statistics']['total_threats'],
                "critical_issues": len([f for f in context['key_findings'] if f['type'] == 'critical_threat'])
            }
        }
    
    async def _generate_technical_details(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Generate technical analysis details"""
        prompt = f"""Provide detailed technical analysis of this security incident:

Evidence Summary: {context['summary']}

Threat Details:
{self._format_threats_sample(context['aggregated_threats'][:10])}

IOC Details:
{self._format_iocs_sample(context['aggregated_iocs'][:10])}

File Relationships:
{context['file_relationships'][:5]}

Provide:
1. Technical attack chain analysis
2. Exploitation techniques identified
3. Persistence mechanisms
4. Data exfiltration indicators
5. Technical remediation steps
6. Detection rule recommendations
"""
        
        result = await self.ai_client.complete(prompt)
        
        if "error" in result:
            return {"error": result["error"]}
        
        return self._parse_technical_details(result["content"])
    
    async def _generate_timeline_analysis(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Generate timeline analysis insights"""
        timeline_context = self.context_builder.build_timeline_context(
            context.get('timeline_events', [])
        )
        
        prompt = f"""Analyze this security event timeline:

Time Range: {timeline_context['time_range']['start']} to {timeline_context['time_range']['end']}
Total Events: {timeline_context['total_events']}

Event Frequency:
{timeline_context['event_frequency']}

Critical Periods:
{self._format_critical_periods(timeline_context['critical_periods'][:5])}

Provide:
1. Timeline narrative of the incident
2. Initial compromise indicators
3. Lateral movement timeline
4. Data access/exfiltration timeline
5. Cleanup attempt timeline
6. Gaps in the timeline that need investigation
"""
        
        result = await self.ai_client.complete(prompt)
        
        if "error" in result:
            return {"error": result["error"]}
        
        return self._parse_timeline_analysis(result["content"], timeline_context)
    
    async def _generate_correlation_insights(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Generate insights from correlations"""
        relationships = context.get('file_relationships', [])
        
        if not relationships:
            return {
                "summary": "No significant correlations found between files.",
                "relationships": []
            }
        
        prompt = f"""Analyze these file relationships and correlations:

Total Files: {context['evidence_count']}
Relationships Found: {len(relationships)}

Sample Relationships:
{relationships[:10]}

Common IOCs across files:
{self._extract_common_iocs(context['aggregated_iocs'])}

Provide:
1. Correlation analysis summary
2. Related file clusters
3. Common attack infrastructure
4. Potential single campaign indicators
5. Investigation priorities based on correlations
"""
        
        result = await self.ai_client.complete(prompt)
        
        if "error" in result:
            return {"error": result["error"]}
        
        return self._parse_correlation_insights(result["content"], relationships)
    
    async def _generate_overall_assessment(self, insights: Dict[str, Any]) -> Dict[str, Any]:
        """Generate overall assessment from all insights"""
        prompt = f"""Based on all the security analysis insights, provide an overall assessment:

Available Insights:
{list(insights.keys())}

Create a final assessment that:
1. Determines overall security status (SECURE/AT RISK/COMPROMISED/CRITICAL)
2. Confidence level in the assessment
3. Top 3 critical findings
4. Immediate action required (YES/NO)
5. Estimated time to remediate
"""
        
        result = await self.ai_client.complete(prompt, max_tokens=500)
        
        if "error" in result:
            return {"error": result["error"]}
        
        return self._parse_overall_assessment(result["content"])
    
    # Quick insight methods
    async def _quick_ioc_summary(self, iocs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate quick IOC summary"""
        if not iocs:
            return {"summary": "No IOCs to analyze"}
        
        ioc_types = {}
        for ioc in iocs:
            ioc_type = ioc.get('type', 'unknown')
            ioc_types[ioc_type] = ioc_types.get(ioc_type, 0) + 1
        
        return {
            "total_iocs": len(iocs),
            "ioc_types": ioc_types,
            "high_confidence": len([i for i in iocs if i.get('confidence', 0) >= 0.8]),
            "summary": f"Found {len(iocs)} IOCs across {len(ioc_types)} types. " + 
                      f"{ioc_types.get('ip_address', 0)} IPs, {ioc_types.get('domain', 0)} domains, " +
                      f"{ioc_types.get('file_hash', 0)} file hashes detected."
        }
    
    async def _quick_threat_analysis(self, threats: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate quick threat analysis"""
        if not threats:
            return {"summary": "No threats to analyze"}
        
        severity_counts = {}
        threat_types = set()
        
        for threat in threats:
            severity = threat.get('severity', 'UNKNOWN')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            threat_types.add(threat.get('threat_type', 'unknown'))
        
        critical = severity_counts.get('CRITICAL', 0)
        high = severity_counts.get('HIGH', 0)
        
        return {
            "total_threats": len(threats),
            "critical_threats": critical,
            "high_threats": high,
            "threat_types": list(threat_types),
            "summary": f"Detected {len(threats)} threats: {critical} critical, {high} high severity. " +
                      f"Main threat types: {', '.join(list(threat_types)[:3])}"
        }
    
    async def _quick_risk_explanation(self, risk_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate quick risk explanation"""
        risk_score = risk_data.get('risk_score', 0)
        
        if risk_score >= 0.8:
            level = "CRITICAL"
            explanation = "Immediate action required. High likelihood of active compromise."
        elif risk_score >= 0.6:
            level = "HIGH"
            explanation = "Significant security concerns detected. Investigation recommended."
        elif risk_score >= 0.4:
            level = "MEDIUM"
            explanation = "Moderate security issues found. Review and remediate."
        else:
            level = "LOW"
            explanation = "Minor security concerns. Monitor and update defenses."
        
        factors = risk_data.get('factors', [])
        
        return {
            "risk_level": level,
            "risk_score": risk_score,
            "explanation": explanation,
            "contributing_factors": factors[:5]
        }
    
    # Formatting helper methods
    def _format_analysis_details(self, analysis: Dict[str, Any]) -> str:
        """Format analysis details for prompt"""
        details = analysis.get('details', {})
        summary = analysis.get('summary', '')
        
        formatted = f"Summary: {summary}\n\n"
        
        # Add key details
        for key, value in list(details.items())[:5]:
            formatted += f"- {key}: {value}\n"
        
        return formatted
    
    def _format_threats_sample(self, threats: List[Dict[str, Any]]) -> str:
        """Format threat sample for prompt"""
        formatted = ""
        for i, threat in enumerate(threats, 1):
            formatted += f"{i}. {threat.get('threat_type', 'Unknown')} " + \
                        f"(Severity: {threat.get('severity', 'UNKNOWN')})\n" + \
                        f"   Description: {threat.get('description', 'N/A')}\n"
        return formatted
    
    def _format_iocs_sample(self, iocs: List[Dict[str, Any]]) -> str:
        """Format IOC sample for prompt"""
        formatted = ""
        for i, ioc in enumerate(iocs, 1):
            formatted += f"{i}. Type: {ioc.get('type', 'unknown')}, " + \
                        f"Value: {ioc.get('value', 'N/A')}, " + \
                        f"Confidence: {ioc.get('confidence', 0)}\n"
        return formatted
    
    def _format_key_findings(self, findings: List[Dict[str, Any]]) -> str:
        """Format key findings for prompt"""
        formatted = ""
        for i, finding in enumerate(findings, 1):
            formatted += f"{i}. {finding.get('type', 'unknown')}: " + \
                        f"{finding.get('description', 'N/A')}\n"
        return formatted
    
    def _format_statistics(self, stats: Dict[str, Any]) -> str:
        """Format statistics for prompt"""
        formatted = ""
        for key, value in stats.items():
            formatted += f"- {key}: {value}\n"
        return formatted
    
    def _format_critical_periods(self, periods: List[Dict[str, Any]]) -> str:
        """Format critical periods for prompt"""
        formatted = ""
        for period in periods:
            formatted += f"Period: {period['period']}, " + \
                        f"Events: {period['event_count']}, " + \
                        f"Severity: {period['average_severity']:.2f}\n"
        return formatted
    
    def _calculate_overall_risk(self, context: Dict[str, Any]) -> str:
        """Calculate overall risk level from context"""
        critical_threats = len([t for t in context.get('aggregated_threats', []) 
                              if t.get('severity', '').upper() == 'CRITICAL'])
        high_threats = len([t for t in context.get('aggregated_threats', []) 
                          if t.get('severity', '').upper() == 'HIGH'])
        
        if critical_threats > 0:
            return "CRITICAL"
        elif high_threats > 3:
            return "HIGH"
        elif high_threats > 0:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _extract_common_iocs(self, iocs: List[Dict[str, Any]]) -> str:
        """Extract common IOCs across files"""
        ioc_files = {}
        for ioc in iocs:
            value = ioc.get('value', '')
            file_id = ioc.get('file_id', '')
            if value:
                if value not in ioc_files:
                    ioc_files[value] = set()
                ioc_files[value].add(file_id)
        
        # Find IOCs in multiple files
        common = {k: len(v) for k, v in ioc_files.items() if len(v) > 1}
        
        formatted = ""
        for ioc, count in list(common.items())[:5]:
            formatted += f"- {ioc}: found in {count} files\n"
        
        return formatted or "No common IOCs found"
    
    # Response parsing methods
    def _parse_threat_summary(self, response: str, threats: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Parse threat summary response"""
        return {
            "summary": response,
            "total_threats": len(threats),
            "critical_count": len([t for t in threats if t.get('severity', '').upper() == 'CRITICAL']),
            "generated_at": datetime.now().isoformat()
        }
    
    def _parse_risk_assessment(self, response: str) -> Dict[str, Any]:
        """Parse risk assessment response"""
        # Extract risk level from response
        risk_level = "MEDIUM"  # Default
        if "CRITICAL" in response.upper():
            risk_level = "CRITICAL"
        elif "HIGH" in response.upper():
            risk_level = "HIGH"
        elif "LOW" in response.upper():
            risk_level = "LOW"
        
        return {
            "assessment": response,
            "risk_level": risk_level,
            "generated_at": datetime.now().isoformat()
        }
    
    def _parse_ioc_analysis(self, response: str, ioc_context: Dict[str, Any]) -> Dict[str, Any]:
        """Parse IOC analysis response"""
        return {
            "analysis": response,
            "total_iocs": ioc_context['total_iocs'],
            "ioc_types": list(ioc_context['ioc_types'].keys()),
            "generated_at": datetime.now().isoformat()
        }
    
    def _parse_recommendations(self, response: str) -> Dict[str, Any]:
        """Parse recommendations response"""
        return {
            "recommendations": response,
            "generated_at": datetime.now().isoformat()
        }
    
    def _parse_technical_details(self, response: str) -> Dict[str, Any]:
        """Parse technical details response"""
        return {
            "technical_analysis": response,
            "generated_at": datetime.now().isoformat()
        }
    
    def _parse_timeline_analysis(self, response: str, timeline_context: Dict[str, Any]) -> Dict[str, Any]:
        """Parse timeline analysis response"""
        return {
            "timeline_analysis": response,
            "event_count": timeline_context['total_events'],
            "time_span": timeline_context['time_range'],
            "generated_at": datetime.now().isoformat()
        }
    
    def _parse_correlation_insights(self, response: str, relationships: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Parse correlation insights response"""
        return {
            "correlation_analysis": response,
            "relationships_found": len(relationships),
            "generated_at": datetime.now().isoformat()
        }
    
    def _parse_overall_assessment(self, response: str) -> Dict[str, Any]:
        """Parse overall assessment response"""
        # Extract status from response
        status = "AT RISK"  # Default
        if "SECURE" in response.upper():
            status = "SECURE"
        elif "COMPROMISED" in response.upper():
            status = "COMPROMISED"
        elif "CRITICAL" in response.upper():
            status = "CRITICAL"
        
        # Extract immediate action requirement
        immediate_action = "YES" in response.upper() and "IMMEDIATE" in response.upper()
        
        return {
            "status": status,
            "assessment": response,
            "immediate_action_required": immediate_action,
            "generated_at": datetime.now().isoformat()
        }


# Singleton instance
_insights_generator = None

def get_insights_generator() -> InsightsGenerator:
    """Get or create insights generator instance"""
    global _insights_generator
    
    if _insights_generator is None:
        _insights_generator = InsightsGenerator()
    
    return _insights_generator