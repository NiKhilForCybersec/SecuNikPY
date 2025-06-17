"""
SecuNik - Enhanced AI Prompt Templates
Comprehensive AI prompts for full cybersecurity threat analysis

Location: backend/app/core/ai/prompt_templates.py
"""

from typing import Dict, Any, List

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

## 3. RISK SCORING (0-100 scale)
Calculate a comprehensive risk score considering:
- Number and severity of threats (0-40 points)
- Potential business impact (0-20 points)
- Ease of exploitation (0-20 points)
- Current security posture (0-20 points)

Provide the numerical score and explain your calculation.

## 4. DETAILED TECHNICAL ANALYSIS
Provide deep technical insights:
- **File/Network/System Analysis**: Technical details of what was found
- **Behavioral Analysis**: How the threats would manifest
- **Timeline Analysis**: Sequence of events if applicable
- **Attribution Indicators**: Potential threat actor signatures
- **Related Campaigns**: Known similar attacks or malware families

## 5. IMMEDIATE ACTION ITEMS (Prioritized)
Generate specific, actionable recommendations:
- **URGENT** (Do immediately): Critical containment actions
- **HIGH PRIORITY** (Within 24 hours): Important security measures
- **MEDIUM PRIORITY** (Within week): Strengthening measures
- **ONGOING** (Continuous): Monitoring and prevention

## 6. INVESTIGATION RECOMMENDATIONS
Suggest next steps for deeper investigation:
- Additional evidence to collect
- Systems to examine
- Tools and techniques to use
- External resources to consult

## 7. LONG-TERM SECURITY IMPROVEMENTS
Recommend systemic improvements:
- Security architecture changes
- Policy updates
- Training recommendations
- Technology implementations

## 8. EXECUTIVE SUMMARY
Provide a non-technical summary for leadership:
- Key findings in business terms
- Potential business impact
- Recommended investment priorities
- Risk acceptance considerations

RESPONSE FORMAT:
Structure your response with clear headings using ## for sections.
Use bullet points for lists and **bold** for emphasis.
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
4. **Business Risk**: Financial/Operational/Reputational/Compliance

## ATTACK CHAIN RECONSTRUCTION
If multiple threats detected:
- Map the complete attack sequence
- Identify initial access vectors
- Track lateral movement progression
- Determine final objectives (data theft, persistence, disruption)

## THREAT INTELLIGENCE CORRELATION
Compare findings with known threat intelligence:
- Similar attack patterns or TTPs
- Known malware families or tools
- Threat actor attribution indicators
- Geographic or sector targeting patterns

## IMMEDIATE THREAT RESPONSE
Provide specific containment actions:
- Systems to isolate or shut down
- Network segments to block
- Accounts to disable or monitor
- Evidence preservation requirements

Prioritize response actions by urgency and impact.
"""
        return prompt

    def get_risk_scoring_prompt(self, context: Dict[str, Any]) -> str:
        """AI-powered risk scoring prompt"""
        
        prompt = f"""{self.base_context}

INTELLIGENT RISK SCORING REQUEST:
Calculate a comprehensive cybersecurity risk score (0-100) based on extracted evidence.

EVIDENCE DATA:
{self._format_extracted_data(context.get('details', {}))}

IDENTIFIED THREATS:
{self._format_threat_context(context.get('threats', []))}

RISK SCORING METHODOLOGY:

## BASE RISK FACTORS (60 points maximum)

**Threat Severity (0-25 points):**
- Critical threats: 25 points
- High threats: 15-20 points each
- Medium threats: 8-12 points each  
- Low threats: 2-5 points each

**Threat Confidence (0-15 points):**
- High confidence detections: Full points
- Medium confidence: 70% of points
- Low confidence: 40% of points

**Number of Threats (0-20 points):**
- Single threat: 5-10 points
- Multiple related threats: 10-15 points
- Multiple unrelated threats: 15-20 points

## IMPACT MULTIPLIERS (40 points maximum)

**System Criticality (0-15 points):**
- Critical infrastructure: 15 points
- Business-critical systems: 10-12 points
- Standard systems: 5-8 points
- Development/test systems: 2-5 points

**Data Sensitivity (0-15 points):**
- Personal/financial data: 15 points
- Proprietary information: 10-12 points
- Internal business data: 5-8 points
- Public information: 2-5 points

**Business Impact Potential (0-10 points):**
- Service disruption potential
- Financial loss potential
- Regulatory compliance impact
- Reputational damage risk

## RISK CALCULATION
1. Calculate base threat score (0-60)
2. Add impact assessment (0-40)  
3. Apply any aggravating factors
4. Ensure final score is 0-100

## RISK LEVEL CLASSIFICATION
- 0-25: **LOW RISK** - Monitoring recommended
- 26-50: **MEDIUM RISK** - Security review needed
- 51-75: **HIGH RISK** - Immediate action required
- 76-100: **CRITICAL RISK** - Emergency response

Provide your detailed scoring breakdown and final risk assessment.
"""
        return prompt

    def get_ioc_analysis_prompt(self, context: Dict[str, Any]) -> str:
        """Enhanced IOC analysis and threat correlation prompt"""
        
        prompt = f"""{self.base_context}

IOC ANALYSIS & THREAT CORRELATION REQUEST:
Analyze extracted indicators and correlate with threat intelligence.

EXTRACTED INDICATORS:
{self._format_detailed_iocs(context.get('iocs', []))}

SUPPORTING EVIDENCE:
{self._format_extracted_data(context.get('evidence_data', {}))}

IOC ANALYSIS REQUIREMENTS:

## IOC CLASSIFICATION & VALIDATION
For each indicator, determine:
- **IOC Type**: IP, Domain, URL, File Hash, Registry Key, etc.
- **Threat Relevance**: Direct threat, Supporting evidence, False positive likely
- **Confidence Level**: How certain are you this is malicious/suspicious?
- **Context**: How this IOC fits into the broader evidence

## THREAT INTELLIGENCE CORRELATION
Analyze IOCs for:
- **Known Malicious Indicators**: Match against known bad IOCs
- **Suspicious Patterns**: Unusual but not definitively malicious
- **Infrastructure Analysis**: Hosting patterns, registration data
- **Campaign Correlation**: Similar IOCs from known campaigns

## IOC PRIORITIZATION
Rank IOCs by:
1. **High Priority**: Definitive threat indicators requiring immediate action
2. **Medium Priority**: Suspicious indicators needing investigation
3. **Low Priority**: Contextual indicators for monitoring

## NETWORK IOC ANALYSIS
For IP addresses, domains, URLs:
- Geolocation and hosting analysis
- Domain registration patterns
- URL structure analysis
- Network infrastructure assessment

## FILE IOC ANALYSIS  
For file hashes and paths:
- Known malware family associations
- File behavior analysis
- Distribution patterns
- Variant analysis

## BEHAVIORAL IOC ANALYSIS
For registry keys, user agents, etc.:
- Attack technique mapping
- Persistence mechanism analysis
- Evasion technique identification

## IOC-BASED DETECTION RULES
Generate detection rules for security tools:
- SIEM queries
- Network monitoring rules
- Endpoint detection logic
- Threat hunting queries

## THREAT HUNTING RECOMMENDATIONS
Suggest proactive hunting for:
- Related IOCs not yet discovered
- Similar attack patterns
- Compromised systems showing these indicators
- Historical evidence of these threats

Provide actionable threat intelligence based on IOC analysis.
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

    def _format_extracted_data(self, details: Dict[str, Any]) -> str:
        """Format extracted data for AI analysis"""
        if not details:
            return "No extracted data available"
        
        formatted = []
        
        # Prioritize important data categories
        priority_keys = [
            "total_events", "total_packets", "total_emails", "autostart_entries",
            "installed_software", "pe_header", "sections", "imports", "exports",
            "authentication_events", "network_interfaces", "usb_devices",
            "file_info", "strings_analysis", "entropy_analysis"
        ]
        
        # Format priority data first
        for key in priority_keys:
            if key in details:
                formatted.append(f"**{key.replace('_', ' ').title()}**: {self._format_data_value(details[key])}")
        
        # Add other relevant data
        remaining_keys = [k for k in details.keys() if k not in priority_keys]
        for key in remaining_keys[:10]:  # Limit to prevent prompt overflow
            formatted.append(f"**{key.replace('_', ' ').title()}**: {self._format_data_value(details[key])}")
        
        return "\n".join(formatted)

    def _format_data_value(self, value: Any) -> str:
        """Format individual data values for readability"""
        if isinstance(value, dict):
            if len(value) > 5:
                sample_items = list(value.items())[:3]
                return f"Dictionary with {len(value)} items. Sample: {dict(sample_items)}"
            return str(value)
        elif isinstance(value, list):
            if len(value) > 10:
                return f"List with {len(value)} items. Sample: {value[:3]}"
            return str(value)
        elif isinstance(value, str) and len(value) > 200:
            return value[:200] + "..."
        else:
            return str(value)

    def _format_factual_iocs(self, iocs: List[Dict[str, Any]]) -> str:
        """Format factual IOCs for AI analysis"""
        if not iocs:
            return "No indicators extracted"
        
        formatted = []
        ioc_types = {}
        
        # Group IOCs by type
        for ioc in iocs:
            ioc_type = ioc.get('type', 'Unknown')
            if ioc_type not in ioc_types:
                ioc_types[ioc_type] = []
            ioc_types[ioc_type].append(ioc)
        
        # Format by type
        for ioc_type, ioc_list in ioc_types.items():
            formatted.append(f"**{ioc_type}** ({len(ioc_list)} items):")
            for ioc in ioc_list[:10]:  # Limit per type
                value = ioc.get('value', 'Unknown')
                source = ioc.get('source', 'Unknown')
                formatted.append(f"  - {value} (from {source})")
            
            if len(ioc_list) > 10:
                formatted.append(f"  ... and {len(ioc_list) - 10} more")
        
        return "\n".join(formatted)

    def _format_threat_context(self, threats: List[Dict[str, Any]]) -> str:
        """Format threat context for scoring"""
        if not threats:
            return "No threats identified yet - AI should identify threats from evidence"
        
        formatted = []
        for i, threat in enumerate(threats, 1):
            formatted.append(f"{i}. **{threat.get('type', 'Unknown Threat')}**")
            formatted.append(f"   - Severity: {threat.get('severity', 'Unknown')}")
            formatted.append(f"   - Description: {threat.get('description', 'No description')}")
            if threat.get('indicators'):
                formatted.append(f"   - Indicators: {', '.join(threat['indicators'][:3])}")
        
        return "\n".join(formatted)

    def _format_detailed_iocs(self, iocs: List[Dict[str, Any]]) -> str:
        """Format detailed IOCs for threat intelligence analysis"""
        if not iocs:
            return "No IOCs available for analysis"
        
        formatted = []
        for i, ioc in enumerate(iocs[:25], 1):  # Limit to prevent prompt overflow
            formatted.append(f"{i}. **{ioc.get('type', 'Unknown')}**: {ioc.get('value', 'Unknown')}")
            formatted.append(f"   - Confidence: {ioc.get('confidence', 'Unknown')}")
            formatted.append(f"   - Source: {ioc.get('source', 'Unknown')}")
            formatted.append(f"   - Context: {ioc.get('description', 'No description')}")
            formatted.append("")
        
        return "\n".join(formatted)

    def _format_timeline_context(self, timeline: List[Dict[str, Any]]) -> str:
        """Format timeline data for analysis"""
        if not timeline:
            return "No timeline data available"
        
        formatted = []
        for i, event in enumerate(timeline[:50], 1):  # Limit to prevent overflow
            timestamp = event.get('timestamp', 'Unknown time')
            description = event.get('description', 'No description')
            source = event.get('source', 'Unknown source')
            formatted.append(f"{i}. **{timestamp}**: {description} ({source})")
        
        if len(timeline) > 50:
            formatted.append(f"... and {len(timeline) - 50} more events")
        
        return "\n".join(formatted)

    # Keep existing methods for backward compatibility
    def get_quick_summary_prompt(self, context: Dict[str, Any]) -> str:
        """Generate quick AI-powered summary prompt"""
        
        prompt = f"""{self.base_context}

QUICK CYBERSECURITY ASSESSMENT REQUEST:
Provide rapid threat assessment and recommendations.

EVIDENCE: {context.get('file_path', 'Unknown')}
TYPE: {context.get('analysis_type', 'Unknown')}
SUMMARY: {context.get('summary', 'No summary available')}

KEY DATA EXTRACTED:
{self._format_extracted_data(context.get('details', {}))}

QUICK ANALYSIS REQUIREMENTS:

## THREAT SUMMARY (2-3 sentences)
Identify the most critical security concerns from the evidence.

## RISK LEVEL
Assign overall risk: CRITICAL / HIGH / MEDIUM / LOW
Justify with specific evidence.

## IMMEDIATE ACTIONS (Top 3)
Most urgent security actions needed:
1. [Critical action]
2. [Important action]  
3. [Recommended action]

## KEY INDICATORS
Most important IOCs or evidence found.

## INVESTIGATION PRIORITY
What should be investigated next?

Keep response focused and actionable for immediate decision-making.
"""
        return prompt

    def get_correlation_analysis_prompt(self, context: Dict[str, Any]) -> str:
        """Multi-file correlation analysis prompt"""
        
        prompt = f"""{self.base_context}

MULTI-SOURCE CORRELATION ANALYSIS REQUEST:
Analyze relationships and attack patterns across multiple evidence sources.

EVIDENCE SOURCES: {context.get('file_count', 0)} files analyzed
{self._format_correlation_sources(context.get('files', []))}

COMBINED EXTRACTED DATA:
{self._format_aggregate_data(context.get('aggregate_data', {}))}

CORRELATION ANALYSIS REQUIREMENTS:

## CROSS-SOURCE THREAT CORRELATION
Identify threats that span multiple evidence sources:
- Shared IOCs and their significance
- Related attack techniques across sources
- Timeline correlation between sources
- Common adversary TTPs

## ATTACK CHAIN RECONSTRUCTION
Build complete attack narrative:
- Initial access vector identification
- Lateral movement progression
- Persistence mechanism deployment
- Data access and exfiltration
- Cleanup and evasion activities

## THREAT ACTOR PROFILING
Analyze adversary characteristics:
- Skill level and sophistication
- Tools and techniques used
- Operational patterns and timing
- Possible attribution indicators

## IMPACT ASSESSMENT
Evaluate combined impact:
- Systems and data affected
- Business operations disrupted
- Security control failures
- Containment requirements

## COMPREHENSIVE RISK SCORING
Calculate aggregate risk considering:
- Multiple attack vectors
- Compounded vulnerabilities
- Systemic security failures
- Business impact magnitude

## STRATEGIC RECOMMENDATIONS
Provide enterprise-level guidance:
- Immediate response priorities
- Security architecture improvements
- Incident response enhancements
- Long-term risk mitigation

Focus on insights that emerge only from analyzing multiple sources together.
"""
        return prompt

    def get_interactive_chat_prompt(self, context: Dict[str, Any]) -> str:
        """Enhanced interactive chat prompt"""
        
        prompt = f"""{self.base_context}

INTERACTIVE CYBERSECURITY CONSULTATION:
Answer the user's question about the forensic analysis with expert insight.

USER QUESTION: {context.get('user_question', '')}

RELEVANT EVIDENCE:
{self._format_chat_context(context.get('analysis_data', {}))}

CONVERSATION HISTORY:
{self._format_conversation_history(context.get('conversation_history', []))}

RESPONSE REQUIREMENTS:
- Answer the specific question directly and thoroughly
- Provide cybersecurity expertise and context
- Reference specific evidence when relevant
- Suggest follow-up questions or analysis if appropriate
- Maintain conversation context and continuity
- Use clear, professional language appropriate to the question complexity

If the question requires analysis not present in the evidence, clearly explain what additional information would be needed and suggest how to obtain it.

Provide actionable cybersecurity insights that help the user understand and respond to the threats.
"""
        return prompt

    def get_threat_intelligence_prompt(self, context: Dict[str, Any]) -> str:
        """Enhanced threat intelligence generation prompt"""
        
        prompt = f"""{self.base_context}

THREAT INTELLIGENCE ANALYSIS REQUEST:
Generate comprehensive threat intelligence from the analyzed indicators.

INDICATORS FOR ANALYSIS:
{self._format_detailed_iocs(context.get('iocs', []))}

SUPPORTING EVIDENCE:
{self._format_extracted_data(context.get('evidence_context', {}))}

THREAT INTELLIGENCE REQUIREMENTS:

## INDICATOR ANALYSIS
For each significant indicator:
- Threat classification and severity
- Known associations with malware families
- Historical usage in campaigns
- Confidence assessment

## THREAT ACTOR ATTRIBUTION
Analyze for attribution indicators:
- TTP matching with known threat actors
- Infrastructure patterns and hosting
- Tool and technique preferences
- Geographic and temporal patterns

## CAMPAIGN CORRELATION
Identify potential campaign associations:
- Similar attack patterns
- Related infrastructure
- Coordinated timing
- Target selection patterns

## THREAT LANDSCAPE CONTEXT
Position threats within broader landscape:
- Current threat trends alignment
- Industry targeting patterns
- Geographic threat distribution
- Emerging attack techniques

## DEFENSIVE INTELLIGENCE
Generate actionable defense information:
- IOC-based detection rules
- Behavioral detection logic
- Threat hunting hypotheses
- Prevention recommendations

## STRATEGIC INTELLIGENCE
Provide strategic insights:
- Threat actor motivation assessment
- Future attack prediction
- Risk trajectory analysis
- Investment recommendations

Focus on intelligence that enables proactive defense and threat hunting.
"""
        return prompt

    def get_incident_report_prompt(self, context: Dict[str, Any]) -> str:
        """Enhanced incident report generation prompt"""
        
        prompt = f"""{self.base_context}

COMPREHENSIVE INCIDENT REPORT GENERATION:
Create a detailed incident response report suitable for executive and technical audiences.

INCIDENT DETAILS:
- Incident ID: {context.get('incident_id', 'Unknown')}
- Detection Time: {context.get('detection_time', 'Unknown')}
- Affected Systems: {context.get('affected_systems', 'Unknown')}

EVIDENCE ANALYSIS SUMMARY:
{self._format_incident_evidence(context.get('evidence_summary', {}))}

INCIDENT TIMELINE:
{self._format_incident_timeline(context.get('timeline', []))}

REPORT STRUCTURE REQUIREMENTS:

## EXECUTIVE SUMMARY
**For senior leadership (non-technical):**
- What happened in business terms
- Impact on operations and data
- Financial and reputational implications
- Current status and next steps

## INCIDENT OVERVIEW
**Technical summary:**
- Attack vector and method
- Systems and data affected
- Duration and scope
- Detection and response timeline

## DETAILED TECHNICAL ANALYSIS
**For technical teams:**
- Complete attack chain reconstruction
- Threat actor TTPs and tools used
- Security control failures and bypasses
- Evidence analysis and findings

## IMPACT ASSESSMENT
**Business and technical impact:**
- Data accessed, modified, or stolen
- System availability and performance
- Regulatory and compliance implications
- Customer and stakeholder effects

## RESPONSE ACTIONS TAKEN
**Chronological response activities:**
- Detection and initial response
- Containment and isolation measures
- Eradication and recovery efforts
- Communication and coordination

## ROOT CAUSE ANALYSIS
**Why the incident occurred:**
- Primary vulnerability or weakness
- Contributing factors and failures
- Systemic issues identified
- Process and technology gaps

## LESSONS LEARNED
**Improvement opportunities:**
- What worked well in response
- What could be improved
- Technology and process gaps
- Training and awareness needs

## RECOMMENDATIONS
**Prioritized improvement actions:**
- **Immediate** (0-30 days): Critical fixes
- **Short-term** (1-6 months): Important improvements
- **Long-term** (6+ months): Strategic enhancements

## APPENDICES
**Supporting documentation:**
- Technical evidence details
- IOC lists and detection rules
- Timeline of all events
- Communication records

Format as a professional incident report with clear sections, executive summary, and actionable recommendations.
"""
        return prompt

    def _format_correlation_sources(self, files: List[Dict[str, Any]]) -> str:
        """Format correlation source information"""
        if not files:
            return "No source files provided"
        
        formatted = []
        for i, file_info in enumerate(files, 1):
            formatted.append(f"{i}. **{file_info.get('file_path', 'Unknown')}**")
            formatted.append(f"   - Type: {file_info.get('analysis_type', 'Unknown')}")
            formatted.append(f"   - Threats: {file_info.get('threat_count', 0)}")
            formatted.append(f"   - IOCs: {file_info.get('ioc_count', 0)}")
        
        return "\n".join(formatted)

    def _format_aggregate_data(self, aggregate_data: Dict[str, Any]) -> str:
        """Format aggregated data across sources"""
        if not aggregate_data:
            return "No aggregate data available"
        
        formatted = []
        for key, value in aggregate_data.items():
            formatted.append(f"**{key.replace('_', ' ').title()}**: {self._format_data_value(value)}")
        
        return "\n".join(formatted)

    def _format_chat_context(self, analysis_data: Dict[str, Any]) -> str:
        """Format analysis data for chat context"""
        if not analysis_data:
            return "No analysis context available"
        
        formatted = []
        priority_keys = ['file_path', 'analysis_type', 'summary', 'severity', 'risk_score', 'threats', 'iocs']
        
        for key in priority_keys:
            if key in analysis_data:
                formatted.append(f"**{key.replace('_', ' ').title()}**: {self._format_data_value(analysis_data[key])}")
        
        return "\n".join(formatted)

    def _format_conversation_history(self, history: List[Dict[str, Any]]) -> str:
        """Format conversation history for context"""
        if not history:
            return "No previous conversation"
        
        formatted = []
        for msg in history[-6:]:  # Last 6 messages for context
            role = msg.get('role', 'unknown')
            content = msg.get('content', '')[:150]  # Truncate for context
            formatted.append(f"**{role.title()}**: {content}")
        
        return "\n".join(formatted)

    def _format_incident_evidence(self, evidence_summary: Dict[str, Any]) -> str:
        """Format incident evidence summary"""
        if not evidence_summary:
            return "No evidence summary available"
        
        formatted = []
        for key, value in evidence_summary.items():
            formatted.append(f"**{key.replace('_', ' ').title()}**: {self._format_data_value(value)}")
        
        return "\n".join(formatted)

    def _format_incident_timeline(self, timeline: List[Dict[str, Any]]) -> str:
        """Format incident timeline for reporting"""
        if not timeline:
            return "No timeline available"
        
        formatted = []
        for event in timeline:
            timestamp = event.get('timestamp', 'Unknown')
            action = event.get('action', 'Unknown action')
            actor = event.get('actor', 'Unknown actor')
            formatted.append(f"**{timestamp}** - {actor}: {action}")
        
        return "\n".join(formatted)