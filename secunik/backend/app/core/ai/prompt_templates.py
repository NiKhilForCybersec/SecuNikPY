"""
SecuNik - Enhanced AI Prompt Templates
Comprehensive AI prompts for full cybersecurity threat analysis

Location: backend/app/core/ai/prompt_templates.py
"""

from typing import Dict, Any, List
from collections import defaultdict

class PromptTemplates:
    """Enhanced AI prompts for complete cybersecurity analysis"""
    
    def __init__(self):
        self.base_context = """
You are SecuNik AI, an expert cybersecurity analyst with deep expertise in:
- Digital forensics and incident response
- Malware analysis and reverse engineering  
- Network security and threat hunting
- Vulnerability assessment and penetration testing
- Threat intelligence and attribution
- Security operations and SOC analysis

You will perform COMPLETE cybersecurity analysis including:
- Threat detection and classification
- Risk assessment and scoring
- Severity determination
- Actionable recommendations
- Attribution analysis when possible

Provide detailed, accurate, and actionable analysis based on the extracted data.
Focus on practical security implications and concrete recommendations.
"""

    def get_comprehensive_analysis_prompt(self, context: Dict[str, Any]) -> str:
        """Generate comprehensive AI-powered analysis prompt"""
        
        prompt = f"""{self.base_context}

COMPREHENSIVE CYBERSECURITY ANALYSIS REQUEST:
You are analyzing forensic evidence that has been extracted from: {context.get('file_path', 'Unknown file')}

EVIDENCE TYPE: {context.get('analysis_type', 'Unknown')}
EXTRACTION SUMMARY: {context.get('summary', 'No summary available')}

EXTRACTED DATA FOR ANALYSIS:
{self._format_extracted_data(context.get('details', {}))}

FACTUAL INDICATORS EXTRACTED:
{self._format_factual_iocs(context.get('iocs', []))}

YOUR COMPREHENSIVE ANALYSIS MUST INCLUDE:

## 1. THREAT DETECTION & CLASSIFICATION
Analyze the extracted data and identify ALL potential security threats:
- **Malware Indicators**: Signs of malicious software, packers, obfuscation
- **Attack Techniques**: MITRE ATT&CK mapping where applicable
- **Persistence Mechanisms**: Ways adversaries maintain access
- **Lateral Movement**: Evidence of network traversal
- **Data Exfiltration**: Signs of data theft or unauthorized transfer
- **Evasion Techniques**: Anti-analysis, anti-forensics methods
- **Command & Control**: C2 communication patterns
- **Privilege Escalation**: Evidence of elevated access attempts

For EACH threat detected, provide:
- Threat name and classification
- Confidence level (High/Medium/Low)
- Evidence supporting the detection
- Potential impact if exploited

## 2. SEVERITY ASSESSMENT
Determine the overall security severity level:
- **CRITICAL**: Immediate threat to system/data integrity, active compromise likely
- **HIGH**: Significant security risk, potential for system compromise
- **MEDIUM**: Moderate risk, security controls should be reviewed
- **LOW**: Minor security concerns, monitoring recommended

Justify your severity assessment with specific evidence.

## 3. RISK ANALYSIS
Calculate risk score (0.0-1.0) based on:
- Threat severity
- Number and type of indicators
- Potential impact
- Attack sophistication

## 4. RECOMMENDATIONS
Provide actionable recommendations categorized by urgency:
- **IMMEDIATE**: Actions needed within 0-24 hours
- **SHORT-TERM**: Actions needed within 1-7 days
- **LONG-TERM**: Strategic improvements for 1-3 months

## 5. ADDITIONAL ANALYSIS
Include any of these if relevant:
- **Attribution**: Possible threat actors or campaigns
- **Attack Timeline**: Sequence of malicious activities
- **Affected Systems**: Scope of potential compromise
- **Data at Risk**: Types of sensitive data potentially exposed

Provide specific evidence references to support your analysis.
Be comprehensive but prioritize actionable insights.

CRITICAL: Base ALL analysis on the extracted data provided. Do not make assumptions about data not present in the evidence.
"""
        return prompt

    def get_threat_assessment_prompt(self, context: Dict[str, Any]) -> str:
        """Enhanced focused threat assessment prompt"""
        
        prompt = f"""{self.base_context}

FOCUSED THREAT ASSESSMENT REQUEST:
Perform detailed threat analysis of extracted forensic evidence.

EVIDENCE OVERVIEW:
- Source: {context.get('file_path', 'Unknown')}
- Type: {context.get('analysis_type', 'Unknown')}
- Extraction Summary: {context.get('summary', 'No summary available')}

EXTRACTED EVIDENCE DATA:
{self._format_extracted_data(context.get('details', {}))}

FACTUAL INDICATORS:
{self._format_factual_iocs(context.get('iocs', []))}

THREAT ASSESSMENT REQUIREMENTS:

## THREAT IDENTIFICATION
Analyze the evidence for these specific threat categories:

**Malware Analysis:**
- Executable analysis (packing, obfuscation, suspicious APIs)
- Behavioral indicators (file operations, network connections)
- Known malware family signatures

**Network Threats:**
- C2 communication patterns (beaconing, unusual protocols)
- Data exfiltration indicators (large transfers, suspicious destinations)
- Lateral movement evidence (authentication patterns, host hopping)

**System Compromise:**
- Persistence mechanisms (registry entries, scheduled tasks, services)
- Privilege escalation attempts (user/group modifications)
- System configuration changes

**Email-Based Threats:**
- Phishing indicators (spoofed domains, suspicious attachments)
- Social engineering tactics (urgency language, credential requests)
- Email infrastructure analysis (routing, authentication failures)

**Log Analysis Threats:**
- Authentication anomalies (brute force, unusual access patterns)
- System event anomalies (service crashes, log clearing)
- Timeline correlation with known attack patterns

## THREAT SCORING & PRIORITIZATION
For each identified threat:
1. **Threat Confidence**: High (90-100%), Medium (60-89%), Low (30-59%)
2. **Impact Severity**: Critical/High/Medium/Low
3. **Exploitation Likelihood**: Immediate/Likely/Possible/Unlikely
4. **Priority Score**: Combined assessment for response prioritization

## THREAT CONTEXT
Position identified threats within:
- Current threat landscape trends
- Industry-specific threat patterns
- Geographic threat intelligence
- Recent campaign similarities

Provide evidence-based threat assessment with clear prioritization for response.
"""
        return prompt

    def get_ioc_analysis_prompt(self, context: Dict[str, Any]) -> str:
        """Enhanced IOC-focused analysis prompt"""
        
        prompt = f"""{self.base_context}

IOC ANALYSIS AND THREAT INTELLIGENCE REQUEST:
Analyze the extracted Indicators of Compromise (IOCs) for threat intelligence.

EXTRACTED IOCS:
Total IOCs: {context.get('total_iocs', 0)}
IOC Types: {', '.join(context.get('ioc_types', {}).keys())}

DETAILED IOC LIST:
{self._format_detailed_iocs(context.get('high_confidence_iocs', []))}

IOC CATEGORIES:
{self._format_ioc_categories(context.get('unique_indicators', {}))}

IOC ANALYSIS REQUIREMENTS:

## THREAT INTELLIGENCE ANALYSIS
For significant IOCs, determine:
- Known malicious associations
- Historical usage in campaigns
- Infrastructure relationships
- Geographic origins (when applicable)

## ATTACK PATTERN IDENTIFICATION
Based on IOC combinations:
- Attack techniques indicated
- Tool signatures present
- Campaign similarities
- Threat actor TTPs

## INFRASTRUCTURE ANALYSIS
For network-based IOCs:
- Hosting provider patterns
- Domain registration analysis
- Certificate patterns
- Network relationships

## MALWARE ASSOCIATION
For file-based IOCs:
- Known malware family matches
- Behavioral pattern indicators
- Code similarity markers
- Distribution methods

## TIMELINE CORRELATION
Analyze temporal aspects:
- IOC appearance sequence
- Activity patterns
- Campaign timing indicators
- Attack progression markers

## THREAT HUNTING GUIDANCE
Based on IOCs found:
- Additional IOCs to search for
- Log sources to examine
- Network patterns to monitor
- System artifacts to check

## DEFENSIVE RECOMMENDATIONS
Provide specific guidance:
- Blocking recommendations (IPs, domains, hashes)
- Detection rule suggestions
- Monitoring priorities
- Incident response actions

Focus on actionable intelligence that enables proactive defense.
"""
        return prompt

    def get_timeline_analysis_prompt(self, context: Dict[str, Any]) -> str:
        """Timeline and sequence analysis prompt"""
        
        prompt = f"""{self.base_context}

TIMELINE & ATTACK SEQUENCE ANALYSIS REQUEST:
Reconstruct the attack timeline and analyze the sequence of events.

TIMELINE DATA:
{self._format_timeline_context(context.get('timeline', []))}

EVIDENCE CONTEXT:
{self._format_extracted_data(context.get('evidence_data', {}))}

TIMELINE ANALYSIS REQUIREMENTS:

## CHRONOLOGICAL RECONSTRUCTION
Build a detailed timeline showing:
- **Initial Access**: How the attack began
- **Reconnaissance**: Information gathering activities
- **Lateral Movement**: Progression through the environment
- **Persistence**: Methods used to maintain access
- **Data Access**: What information was targeted
- **Exfiltration**: How data was removed (if applicable)
- **Cleanup**: Evidence destruction attempts

## ATTACK PHASE MAPPING
Map events to attack framework phases:
- **MITRE ATT&CK Tactics**: Initial Access, Execution, Persistence, etc.
- **Cyber Kill Chain**: Reconnaissance through Actions on Objectives
- **Diamond Model**: Adversary, Infrastructure, Capability, Victim

## BEHAVIORAL ANALYSIS
Identify patterns indicating:
- **Automated vs Manual**: Tool-based vs human-driven activities
- **Skill Level**: Sophistication of techniques used
- **Operational Security**: How well the attacker covered tracks
- **Objectives**: What the attacker was trying to achieve

## CRITICAL DECISION POINTS
Identify moments when:
- Attack could have been detected/stopped
- Attacker made operational errors
- Security controls should have triggered
- Incident response should have activated

## ATTACK VELOCITY ANALYSIS
Assess:
- **Dwell Time**: How long attackers had access
- **Movement Speed**: Rate of lateral progression
- **Data Volume**: Amount of information accessed/stolen
- **Attack Complexity**: Sophistication of the operation

## INVESTIGATIVE GAPS
Identify missing information:
- Time periods without evidence
- Systems that may have been compromised
- Data that may have been accessed
- Activities that may have occurred

## DEFENSIVE RECOMMENDATIONS
Based on timeline analysis:
- Detection improvements needed
- Response time optimizations
- Security control enhancements
- Monitoring gap closures

Provide a comprehensive attack timeline with security implications.
"""
        return prompt
    
    def get_report_generation_prompt(self, context: Dict[str, Any]) -> str:
        """Report generation prompt"""
        
        prompt = f"""{self.base_context}

SECURITY INCIDENT REPORT GENERATION:
Create a professional security incident report based on the analysis results.

CASE INFORMATION:
{self._format_case_info(context.get('case_info', {}))}

ANALYSIS SUMMARY:
- Total Files Analyzed: {len(context.get('analysis_results', []))}
- Analysis Period: {context.get('timestamp', 'Unknown')}

KEY FINDINGS:
{self._format_report_findings(context.get('analysis_results', []))}

REPORT STRUCTURE REQUIREMENTS:

## EXECUTIVE SUMMARY
- Incident overview (2-3 paragraphs)
- Critical findings
- Business impact
- Recommended actions

## INCIDENT DETAILS
### Timeline of Events
- Chronological sequence of activities
- Key milestones identified

### Technical Findings
- Malware analysis results
- Network activity summary
- System compromises
- Data exposure assessment

### Threat Actor Profile
- Attribution indicators
- TTPs observed
- Sophistication assessment

## IMPACT ASSESSMENT
### Systems Affected
- List of compromised systems
- Level of compromise
- Recovery requirements

### Data Impact
- Types of data accessed
- Volume of data affected
- Sensitivity classification

### Business Impact
- Operational disruptions
- Financial implications
- Reputational considerations

## RESPONSE ACTIONS
### Immediate Response
- Containment measures taken
- Evidence preserved
- Initial remediation

### Ongoing Actions
- Investigation activities
- System hardening
- Monitoring enhancement

## RECOMMENDATIONS
### Technical Recommendations
- Security control improvements
- Architecture changes
- Tool implementations

### Process Recommendations
- Policy updates needed
- Training requirements
- Incident response improvements

## APPENDICES
### A. Detailed IOCs
### B. Technical Evidence
### C. Recovery Procedures

Generate a professional report suitable for executive leadership and technical teams.
"""
        return prompt
    
    def get_chat_system_prompt(self) -> str:
        """System prompt for chat interactions"""
        
        return f"""{self.base_context}

You are an interactive cybersecurity assistant helping users understand and respond to security incidents. You have access to detailed analysis results and can provide expert guidance.

ASSISTANT CAPABILITIES:
- Explain technical findings in accessible terms
- Answer questions about specific threats or IOCs
- Provide remediation guidance
- Help prioritize response actions
- Clarify attack techniques and impacts
- Suggest investigation next steps

COMMUNICATION STYLE:
- Be concise but thorough
- Use technical terms when appropriate but explain them
- Provide specific, actionable advice
- Ask clarifying questions when needed
- Reference specific evidence when available

Remember: You're helping both technical and non-technical users understand complex security incidents.
"""

    # Helper formatting methods
    def _format_extracted_data(self, details: Dict[str, Any]) -> str:
        """Format extracted data for prompt"""
        if not details:
            return "No extracted data available"
        
        formatted = []
        for key, value in details.items():
            if isinstance(value, dict):
                formatted.append(f"**{key.replace('_', ' ').title()}**:")
                for sub_key, sub_value in value.items():
                    formatted.append(f"  - {sub_key}: {self._truncate_value(sub_value)}")
            elif isinstance(value, list):
                formatted.append(f"**{key.replace('_', ' ').title()}**: {len(value)} items")
                if value and len(value) <= 3:
                    for item in value:
                        formatted.append(f"  - {self._truncate_value(item)}")
            else:
                formatted.append(f"**{key.replace('_', ' ').title()}**: {self._truncate_value(value)}")
        
        return "\n".join(formatted)

    def _format_factual_iocs(self, iocs: List[Dict[str, Any]]) -> str:
        """Format factual IOCs for prompt"""
        if not iocs:
            return "No IOCs extracted"
        
        formatted = []
        ioc_by_type = {}
        
        for ioc in iocs:
            ioc_type = ioc.get('type', 'Unknown')
            if ioc_type not in ioc_by_type:
                ioc_by_type[ioc_type] = []
            ioc_by_type[ioc_type].append(ioc)
        
        for ioc_type, ioc_list in ioc_by_type.items():
            formatted.append(f"\n**{ioc_type}** ({len(ioc_list)} found):")
            for ioc in ioc_list[:5]:  # Limit to 5 per type
                value = ioc.get('value', 'N/A')
                confidence = ioc.get('confidence', 0)
                source = ioc.get('source', 'Unknown')
                formatted.append(f"  - {value} (confidence: {confidence}, source: {source})")
        
        return "\n".join(formatted)

    def _format_detailed_iocs(self, iocs: List[Dict[str, Any]]) -> str:
        """Format detailed IOCs for analysis"""
        if not iocs:
            return "No high-confidence IOCs found"
        
        formatted = []
        for i, ioc in enumerate(iocs[:20], 1):  # Limit to prevent token overflow
            formatted.append(f"{i}. **{ioc.get('type', 'Unknown')}**: {ioc.get('value', 'N/A')}")
            formatted.append(f"   - Confidence: {ioc.get('confidence', 0)}")
            formatted.append(f"   - Source: {ioc.get('source', 'Unknown')}")
            if ioc.get('description'):
                formatted.append(f"   - Description: {ioc['description']}")
        
        return "\n".join(formatted)

    def _format_ioc_categories(self, categories: Dict[str, List]) -> str:
        """Format IOC categories"""
        if not categories:
            return "No IOC categories available"
        
        formatted = []
        for category, items in categories.items():
            if items:
                formatted.append(f"\n**{category.replace('_', ' ').title()}** ({len(items)} unique):")
                for item in items[:5]:  # Show first 5
                    formatted.append(f"  - {item}")
                if len(items) > 5:
                    formatted.append(f"  - ... and {len(items) - 5} more")
        
        return "\n".join(formatted)

    def _format_timeline_context(self, timeline: List[Dict[str, Any]]) -> str:
        """Format timeline events for prompt"""
        if not timeline:
            return "No timeline events available"
        
        formatted = []
        formatted.append(f"Total Events: {len(timeline)}")
        
        # Show sample of events
        for event in timeline[:20]:  # Limit to prevent token overflow
            timestamp = event.get('timestamp', 'Unknown')
            event_type = event.get('event', 'Unknown')
            description = event.get('description', 'No description')
            formatted.append(f"\n**{timestamp}** - {event_type}")
            formatted.append(f"  {description}")
        
        if len(timeline) > 20:
            formatted.append(f"\n... and {len(timeline) - 20} more events")
        
        return "\n".join(formatted)

    def _format_case_info(self, case_info: Dict[str, Any]) -> str:
        """Format case information for prompt"""
        if not case_info:
            return "No case information provided"
        
        return f"""
Case ID: {case_info.get('case_id', 'Unknown')}
Case Name: {case_info.get('name', 'Unnamed Case')}
Created: {case_info.get('created_timestamp', 'Unknown')}
Description: {case_info.get('description', 'No description')}
Status: {case_info.get('status', 'Unknown')}
"""

    def _format_report_findings(self, results: List[Dict[str, Any]]) -> str:
        """Format findings for report generation"""
        if not results:
            return "No analysis results available"
        
        high_risk = [r for r in results if r.get('risk_score', 0) >= 0.7]
        critical_threats = []
        
        for result in results:
            for threat in result.get('threats_detected', []):
                if threat.get('severity', '').upper() in ['CRITICAL', 'HIGH']:
                    critical_threats.append(threat)
        
        return f"""
High Risk Files: {len(high_risk)} of {len(results)}
Critical Threats: {len(critical_threats)}
Average Risk Score: {sum(r.get('risk_score', 0) for r in results) / len(results):.2f}

Top Threats:
{self._format_aggregated_threats(critical_threats[:5])}
"""

    def _format_aggregated_threats(self, threats: List[Dict[str, Any]]) -> str:
        """Format aggregated threats for prompt"""
        if not threats:
            return "No threats detected"
        
        formatted = []
        for i, threat in enumerate(threats[:10], 1):
            formatted.append(
                f"{i}. {threat.get('threat_type', 'Unknown')} "
                f"(Severity: {threat.get('severity', 'UNKNOWN')})\n"
                f"   Description: {threat.get('description', 'N/A')}\n"
                f"   Source: {threat.get('source_file', 'Unknown')}"
            )
        
        return "\n".join(formatted)

    def _format_key_findings(self, findings: List[Dict[str, Any]]) -> str:
        """Format key findings for prompt"""
        if not findings:
            return "No key findings identified"
        
        formatted = []
        for i, finding in enumerate(findings[:10], 1):
            formatted.append(f"{i}. {finding.get('type', 'Unknown')}: {finding.get('description', 'No description')}")
        
        return "\n".join(formatted)

    def _format_aggregated_iocs(self, iocs: List[Dict[str, Any]]) -> str:
        """Format aggregated IOCs for prompt"""
        if not iocs:
            return "No IOCs found"
        
        # Group by type
        ioc_groups = defaultdict(list)
        for ioc in iocs[:50]:  # Limit to prevent token overflow
            ioc_groups[ioc.get('type', 'unknown')].append(ioc)
        
        formatted = []
        for ioc_type, ioc_list in ioc_groups.items():
            formatted.append(f"\n{ioc_type} ({len(ioc_list)} found):")
            for ioc in ioc_list[:5]:  # Show sample
                formatted.append(f"  - {ioc.get('value', 'N/A')} (confidence: {ioc.get('confidence', 0)})")
        
        return "\n".join(formatted)

    def _format_file_relationships(self, relationships: List[Dict[str, Any]]) -> str:
        """Format file relationships for prompt"""
        if not relationships:
            return "No file relationships identified"
        
        formatted = []
        for i, rel in enumerate(relationships[:5], 1):
            formatted.append(
                f"{i}. {rel.get('type', 'Unknown')} relationship:\n"
                f"   Files: {', '.join(rel.get('related_files', []))}\n"
                f"   Evidence: {rel.get('ioc_value', 'N/A')}"
            )
        
        return "\n".join(formatted)

    def _truncate_value(self, value: Any, max_length: int = 100) -> str:
        """Truncate long values for display"""
        str_value = str(value)
        if len(str_value) > max_length:
            return str_value[:max_length] + "..."
        return str_value

    def _format_data_value(self, value: Any) -> str:
        """Format data value for display"""
        if isinstance(value, list):
            return f"[{len(value)} items]"
        elif isinstance(value, dict):
            return f"{{object with {len(value)} fields}}"
        else:
            return self._truncate_value(value)