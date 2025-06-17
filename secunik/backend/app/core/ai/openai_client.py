"""
SecuNik - OpenAI Client (AI Foundation)
Advanced AI integration for cybersecurity analysis using OpenAI GPT-4

Location: backend/app/core/ai/openai_client.py
"""

import json
import logging
import asyncio
from datetime import datetime
from typing import Dict, List, Optional, Any, Union
import os

try:
    import openai
    from openai import AsyncOpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

from .prompt_templates import PromptTemplates
from .context_builder import ContextBuilder
from ...models.analysis import AnalysisResult, Severity

logger = logging.getLogger(__name__)

class SecuNikAI:
    """Advanced AI Client for Cybersecurity Analysis"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        self.model = "gpt-4"  # Default to GPT-4 for best analysis
        self.max_tokens = 4000
        self.temperature = 0.1  # Low temperature for factual analysis
        
        # Initialize components
        self.prompt_templates = PromptTemplates()
        self.context_builder = ContextBuilder()
        
        # Initialize OpenAI client
        if OPENAI_AVAILABLE and self.api_key:
            self.client = AsyncOpenAI(api_key=self.api_key)
            self.is_available = True
            logger.info("OpenAI client initialized successfully")
        else:
            self.client = None
            self.is_available = False
            if not OPENAI_AVAILABLE:
                logger.warning("OpenAI library not available")
            if not self.api_key:
                logger.warning("OpenAI API key not provided")
        
        # Conversation history for chat interface
        self.conversation_history = []
        
        # Analysis cache to avoid redundant API calls
        self.analysis_cache = {}

    async def analyze_file_with_intelligence(self, analysis_result: AnalysisResult, analysis_type: str = "comprehensive") -> AnalysisResult:
        """
        Enhance analysis result with AI intelligence - converts raw data extraction to comprehensive threat analysis
        
        Args:
            analysis_result: Raw data extraction result from parser
            analysis_type: Type of AI analysis to perform
        
        Returns:
            Enhanced AnalysisResult with AI-determined threats, risk scores, and recommendations
        """
        if not self.is_available:
            logger.warning("AI not available, returning original result")
            return analysis_result
        
        try:
            # Build context for AI analysis
            context = self.context_builder.build_file_context(analysis_result)
            
            # Get AI analysis based on type
            if analysis_type == "threat_assessment":
                ai_response = await self._get_threat_assessment(context)
            elif analysis_type == "quick_summary":
                ai_response = await self._get_quick_assessment(context)
            else:  # comprehensive
                ai_response = await self._get_comprehensive_analysis(context)
            
            # Parse AI response and enhance the analysis result
            enhanced_result = self._enhance_analysis_result(analysis_result, ai_response, analysis_type)
            
            logger.info(f"AI analysis completed for {analysis_result.file_path}")
            return enhanced_result
            
        except Exception as e:
            logger.error(f"Error in AI analysis enhancement: {str(e)}")
            # Return original result if AI enhancement fails
            return analysis_result

    async def _get_comprehensive_analysis(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Get comprehensive AI analysis"""
        prompt = self.prompt_templates.get_comprehensive_analysis_prompt(context)
        response = await self._make_api_call(prompt, max_tokens=6000)
        return self._parse_comprehensive_response(response)

    async def _get_threat_assessment(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Get focused threat assessment"""
        prompt = self.prompt_templates.get_threat_assessment_prompt(context)
        response = await self._make_api_call(prompt, max_tokens=4000)
        return self._parse_threat_assessment_response(response)

    async def _get_quick_assessment(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Get quick threat assessment"""
        prompt = self.prompt_templates.get_quick_summary_prompt(context)
        response = await self._make_api_call(prompt, max_tokens=2000)
        return self._parse_quick_assessment_response(response)

    def _enhance_analysis_result(self, original_result: AnalysisResult, ai_response: Dict[str, Any], analysis_type: str) -> AnalysisResult:
        """Enhance original analysis result with AI intelligence"""
        # Extract AI-determined components
        ai_threats = ai_response.get("threats", [])
        ai_severity = self._parse_ai_severity(ai_response.get("severity", "LOW"))
        ai_risk_score = ai_response.get("risk_score", 0.0)
        ai_recommendations = ai_response.get("recommendations", [])
        ai_summary = ai_response.get("summary", original_result.summary)
        
        # Create enhanced analysis result
        enhanced_result = AnalysisResult(
            file_path=original_result.file_path,
            parser_name=original_result.parser_name,
            analysis_type=f"AI-Enhanced {original_result.analysis_type}",
            timestamp=original_result.timestamp,
            summary=ai_summary,
            details={
                **original_result.details,  # Keep original extracted data
                "ai_analysis": ai_response,  # Add AI analysis
                "analysis_type": analysis_type,
                "ai_enhanced": True
            },
            threats_detected=ai_threats,  # AI-determined threats
            iocs_found=original_result.iocs_found,  # Keep original IOCs
            severity=ai_severity,  # AI-determined severity
            risk_score=ai_risk_score,  # AI-calculated risk score
            recommendations=ai_recommendations  # AI-generated recommendations
        )
        
        return enhanced_result

    def _parse_ai_severity(self, severity_str: str) -> Severity:
        """Parse AI severity string to Severity enum"""
        severity_map = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH, 
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW
        }
        
        return severity_map.get(severity_str.upper(), Severity.LOW)

    def _parse_comprehensive_response(self, response: str) -> Dict[str, Any]:
        """Parse comprehensive AI analysis response"""
        parsed = {
            "threats": self._extract_threats_from_response(response),
            "severity": self._extract_severity_from_response(response),
            "risk_score": self._extract_risk_score_from_response(response),
            "recommendations": self._extract_recommendations_from_response(response),
            "summary": self._extract_summary_from_response(response),
            "technical_analysis": self._extract_section(response, "DETAILED TECHNICAL ANALYSIS", "IMMEDIATE ACTION ITEMS"),
            "attribution": self._extract_section(response, "ATTRIBUTION", "RECOMMENDATIONS"),
            "raw_response": response
        }
        
        return parsed

    def _parse_threat_assessment_response(self, response: str) -> Dict[str, Any]:
        """Parse threat assessment response"""
        parsed = {
            "threats": self._extract_threats_from_response(response),
            "severity": self._extract_severity_from_response(response),
            "risk_score": self._extract_risk_score_from_response(response),
            "recommendations": self._extract_recommendations_from_response(response),
            "summary": self._extract_summary_from_response(response),
            "threat_details": self._extract_section(response, "THREAT IDENTIFICATION", "THREAT SCORING"),
            "raw_response": response
        }
        
        return parsed

    def _parse_quick_assessment_response(self, response: str) -> Dict[str, Any]:
        """Parse quick assessment response"""
        parsed = {
            "threats": self._extract_threats_from_response(response),
            "severity": self._extract_severity_from_response(response),
            "risk_score": self._extract_risk_score_from_response(response),
            "recommendations": self._extract_recommendations_from_response(response),
            "summary": self._extract_summary_from_response(response),
            "raw_response": response
        }
        
        return parsed

    def _extract_threats_from_response(self, response: str) -> List[Dict[str, Any]]:
        """Extract threat information from AI response"""
        threats = []
        
        # Look for threat detection section
        threat_section = self._extract_section(response, "THREAT DETECTION", "SEVERITY ASSESSMENT")
        if not threat_section:
            threat_section = self._extract_section(response, "THREAT IDENTIFICATION", "RISK LEVEL")
        
        if threat_section:
            # Parse individual threats (this is a simplified parser)
            lines = threat_section.split('\n')
            current_threat = None
            
            for line in lines:
                line = line.strip()
                if line.startswith('**') or line.startswith('- **'):
                    # New threat
                    if current_threat:
                        threats.append(current_threat)
                    
                    threat_name = line.replace('**', '').replace('- ', '').strip(':')
                    current_threat = {
                        "type": threat_name,
                        "severity": "MEDIUM",  # Default
                        "description": "",
                        "confidence": "Medium",
                        "indicators": []
                    }
                elif current_threat and line:
                    # Add to current threat description
                    if "severity" in line.lower() or "confidence" in line.lower():
                        # Parse severity/confidence
                        if "high" in line.lower():
                            current_threat["severity"] = "HIGH"
                            current_threat["confidence"] = "High"
                        elif "critical" in line.lower():
                            current_threat["severity"] = "CRITICAL"
                            current_threat["confidence"] = "High"
                        elif "low" in line.lower():
                            current_threat["severity"] = "LOW"
                            current_threat["confidence"] = "Low"
                    else:
                        current_threat["description"] += " " + line
            
            if current_threat:
                threats.append(current_threat)
        
        # If no structured threats found, create a generic one if risk indicators present
        if not threats and ("threat" in response.lower() or "malware" in response.lower() or "attack" in response.lower()):
            threats.append({
                "type": "General Security Concern",
                "severity": "MEDIUM",
                "description": "AI identified potential security concerns in the analyzed data",
                "confidence": "Medium",
                "indicators": []
            })
        
        return threats

    def _extract_severity_from_response(self, response: str) -> str:
        """Extract overall severity from AI response"""
        response_lower = response.lower()
        
        if "critical" in response_lower and ("risk" in response_lower or "severity" in response_lower):
            return "CRITICAL"
        elif "high" in response_lower and ("risk" in response_lower or "severity" in response_lower):
            return "HIGH"
        elif "medium" in response_lower and ("risk" in response_lower or "severity" in response_lower):
            return "MEDIUM"
        else:
            return "LOW"

    def _extract_risk_score_from_response(self, response: str) -> float:
        """Extract risk score from AI response"""
        import re
        
        # Look for risk score patterns
        patterns = [
            r"risk score[:\s]*(\d+(?:\.\d+)?)",
            r"score[:\s]*(\d+(?:\.\d+)?)[/\s]*100",
            r"(\d+(?:\.\d+)?)[/\s]*100",
            r"risk[:\s]*(\d+(?:\.\d+)?)"
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, response.lower())
            if matches:
                try:
                    score = float(matches[0])
                    return min(score, 100.0)  # Cap at 100
                except ValueError:
                    continue
        
        # Default scoring based on severity if no explicit score found
        severity = self._extract_severity_from_response(response)
        severity_scores = {
            "CRITICAL": 85.0,
            "HIGH": 70.0,
            "MEDIUM": 45.0,
            "LOW": 20.0
        }
        
        return severity_scores.get(severity, 20.0)

    def _extract_recommendations_from_response(self, response: str) -> List[str]:
        """Extract recommendations from AI response"""
        recommendations = []
        
        # Look for recommendations section
        rec_section = self._extract_section(response, "IMMEDIATE ACTION", "INVESTIGATION")
        if not rec_section:
            rec_section = self._extract_section(response, "RECOMMENDATIONS", "CONCLUSION")
        if not rec_section:
            rec_section = self._extract_section(response, "ACTIONS", "NEXT STEPS")
        
        if rec_section:
            lines = rec_section.split('\n')
            for line in lines:
                line = line.strip()
                if line and (line.startswith('-') or line.startswith('*') or line.startswith('1.') or line.startswith('•')):
                    # Clean up the recommendation
                    clean_rec = line.lstrip('-*1234567890.• ').strip()
                    if clean_rec and len(clean_rec) > 10:  # Filter out very short items
                        recommendations.append(clean_rec)
        
        # If no structured recommendations found, add generic ones based on threats
        if not recommendations:
            if "threat" in response.lower() or "malware" in response.lower():
                recommendations = [
                    "Monitor the analyzed system for additional suspicious activity",
                    "Review security logs for related indicators",
                    "Consider additional forensic analysis if threats are confirmed",
                    "Update security controls based on findings"
                ]
            else:
                recommendations = [
                    "Continue monitoring for suspicious activity",
                    "Review security posture periodically"
                ]
        
        return recommendations[:10]  # Limit to 10 recommendations

    def _extract_summary_from_response(self, response: str) -> str:
        """Extract summary from AI response"""
        # Look for executive summary or threat summary
        summary = self._extract_section(response, "EXECUTIVE SUMMARY", "THREAT DETECTION")
        if not summary:
            summary = self._extract_section(response, "THREAT SUMMARY", "RISK LEVEL")
        if not summary:
            summary = self._extract_section(response, "SUMMARY", "DETAILED")
        
        if summary:
            # Take first few sentences
            sentences = summary.split('.')[:3]
            return '.'.join(sentences).strip() + '.'
        
        # Fallback: create summary from threats and severity
        threats = self._extract_threats_from_response(response)
        severity = self._extract_severity_from_response(response)
        
        if threats:
            threat_types = [t["type"] for t in threats[:3]]
            return f"AI analysis identified {len(threats)} security concerns ({', '.join(threat_types)}) with {severity.lower()} overall risk level."
        else:
            return "AI analysis completed - detailed findings available in analysis results."

    # Backward compatibility method
    async def analyze_file(self, analysis_result: AnalysisResult, analysis_type: str = "comprehensive") -> Dict[str, Any]:
        """
        Legacy method for backward compatibility - returns dict format
        """
        enhanced_result = await self.analyze_file_with_intelligence(analysis_result, analysis_type)
        
        # Convert back to dict format for backward compatibility
        return {
            "analysis": enhanced_result.details.get("ai_analysis", {}),
            "threats": enhanced_result.threats_detected,
            "severity": enhanced_result.severity.value if enhanced_result.severity else "LOW",
            "risk_score": enhanced_result.risk_score,
            "recommendations": enhanced_result.recommendations,
            "summary": enhanced_result.summary,
            "metadata": {
                "model_used": self.model,
                "analysis_type": analysis_type,
                "timestamp": datetime.now().isoformat(),
                "original_file": analysis_result.file_path,
                "parser_used": analysis_result.parser_name
            }
        }

    async def analyze_multiple_files(self, analysis_results: List[AnalysisResult]) -> Dict[str, Any]:
        """
        Perform cross-file correlation analysis using AI
        
        Args:
            analysis_results: List of analysis results from multiple files
        
        Returns:
            Dict containing correlated analysis and insights
        """
        if not self.is_available:
            return self._create_unavailable_response()
        
        try:
            # Build context for multiple files
            context = self.context_builder.build_multi_file_context(analysis_results)
            
            # Get correlation analysis prompt
            prompt = self.prompt_templates.get_correlation_analysis_prompt(context)
            
            # Make API call
            response = await self._make_api_call(prompt)
            
            # Parse correlation response
            correlation_analysis = self._parse_correlation_response(response)
            
            # Add metadata
            correlation_analysis["metadata"] = {
                "model_used": self.model,
                "analysis_type": "correlation",
                "timestamp": datetime.now().isoformat(),
                "files_analyzed": len(analysis_results),
                "file_list": [result.file_path for result in analysis_results]
            }
            
            logger.info(f"AI correlation analysis completed for {len(analysis_results)} files")
            return correlation_analysis
            
        except Exception as e:
            logger.error(f"Error in AI correlation analysis: {str(e)}")
            return self._create_error_response(str(e))
        """
        Perform cross-file correlation analysis using AI
        
        Args:
            analysis_results: List of analysis results from multiple files
        
        Returns:
            Dict containing correlated analysis and insights
        """
        if not self.is_available:
            return self._create_unavailable_response()
        
        try:
            # Build context for multiple files
            context = self.context_builder.build_multi_file_context(analysis_results)
            
            # Get correlation analysis prompt
            prompt = self.prompt_templates.get_correlation_analysis_prompt(context)
            
            # Make API call
            response = await self._make_api_call(prompt)
            
            # Parse correlation response
            correlation_analysis = self._parse_correlation_response(response)
            
            # Add metadata
            correlation_analysis["metadata"] = {
                "model_used": self.model,
                "analysis_type": "correlation",
                "timestamp": datetime.now().isoformat(),
                "files_analyzed": len(analysis_results),
                "file_list": [result.file_path for result in analysis_results]
            }
            
            logger.info(f"AI correlation analysis completed for {len(analysis_results)} files")
            return correlation_analysis
            
        except Exception as e:
            logger.error(f"Error in AI correlation analysis: {str(e)}")
            return self._create_error_response(str(e))

    async def chat_about_analysis(self, user_question: str, context_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Interactive chat about analysis results
        
        Args:
            user_question: User's question about the analysis
            context_data: Relevant analysis data for context
        
        Returns:
            Dict containing AI response and conversation update
        """
        if not self.is_available:
            return self._create_unavailable_response()
        
        try:
            # Build conversation context
            conversation_context = self.context_builder.build_conversation_context(
                user_question, context_data, self.conversation_history
            )
            
            # Get chat prompt
            prompt = self.prompt_templates.get_interactive_chat_prompt(conversation_context)
            
            # Make API call
            response = await self._make_api_call(prompt)
            
            # Update conversation history
            self.conversation_history.append({
                "role": "user",
                "content": user_question,
                "timestamp": datetime.now().isoformat()
            })
            
            self.conversation_history.append({
                "role": "assistant", 
                "content": response,
                "timestamp": datetime.now().isoformat()
            })
            
            # Limit conversation history to last 20 messages
            if len(self.conversation_history) > 20:
                self.conversation_history = self.conversation_history[-20:]
            
            chat_response = {
                "response": response,
                "conversation_id": len(self.conversation_history),
                "timestamp": datetime.now().isoformat(),
                "context_used": bool(context_data)
            }
            
            logger.info("AI chat response generated")
            return chat_response
            
        except Exception as e:
            logger.error(f"Error in AI chat: {str(e)}")
            return self._create_error_response(str(e))

    async def generate_threat_intelligence(self, iocs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate threat intelligence insights from IOCs
        
        Args:
            iocs: List of Indicators of Compromise
        
        Returns:
            Dict containing threat intelligence analysis
        """
        if not self.is_available:
            return self._create_unavailable_response()
        
        try:
            # Build IOC context
            ioc_context = self.context_builder.build_ioc_context(iocs)
            
            # Get threat intelligence prompt
            prompt = self.prompt_templates.get_threat_intelligence_prompt(ioc_context)
            
            # Make API call
            response = await self._make_api_call(prompt)
            
            # Parse threat intelligence response
            threat_intel = self._parse_threat_intelligence_response(response)
            
            # Add metadata
            threat_intel["metadata"] = {
                "model_used": self.model,
                "analysis_type": "threat_intelligence",
                "timestamp": datetime.now().isoformat(),
                "iocs_analyzed": len(iocs)
            }
            
            logger.info(f"Threat intelligence analysis completed for {len(iocs)} IOCs")
            return threat_intel
            
        except Exception as e:
            logger.error(f"Error in threat intelligence generation: {str(e)}")
            return self._create_error_response(str(e))

    async def generate_incident_report(self, analysis_results: List[AnalysisResult], 
                                     incident_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate comprehensive incident response report
        
        Args:
            analysis_results: List of analysis results
            incident_context: Additional incident context and metadata
        
        Returns:
            Dict containing structured incident report
        """
        if not self.is_available:
            return self._create_unavailable_response()
        
        try:
            # Build incident context
            context = self.context_builder.build_incident_context(analysis_results, incident_context)
            
            # Get incident report prompt
            prompt = self.prompt_templates.get_incident_report_prompt(context)
            
            # Make API call with higher token limit for comprehensive reports
            response = await self._make_api_call(prompt, max_tokens=6000)
            
            # Parse incident report response
            incident_report = self._parse_incident_report_response(response)
            
            # Add metadata
            incident_report["metadata"] = {
                "model_used": self.model,
                "analysis_type": "incident_report",
                "timestamp": datetime.now().isoformat(),
                "files_analyzed": len(analysis_results),
                "incident_id": incident_context.get("incident_id", "N/A")
            }
            
            logger.info("Incident report generated successfully")
            return incident_report
            
        except Exception as e:
            logger.error(f"Error generating incident report: {str(e)}")
            return self._create_error_response(str(e))

    async def _make_api_call(self, prompt: str, max_tokens: Optional[int] = None) -> str:
        """Make API call to OpenAI"""
        try:
            messages = [
                {
                    "role": "system",
                    "content": "You are SecuNik AI, an expert cybersecurity analyst specialized in digital forensics, threat analysis, and incident response. Provide detailed, accurate, and actionable security analysis."
                },
                {
                    "role": "user", 
                    "content": prompt
                }
            ]
            
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                max_tokens=max_tokens or self.max_tokens,
                temperature=self.temperature
            )
            
            return response.choices[0].message.content
            
        except Exception as e:
            logger.error(f"OpenAI API call failed: {str(e)}")
            raise

    def _parse_analysis_response(self, response: str, analysis_type: str) -> Dict[str, Any]:
        """Parse AI analysis response into structured format"""
        try:
            # Try to parse as JSON first
            if response.strip().startswith('{'):
                return json.loads(response)
        except json.JSONDecodeError:
            pass
        
        # Fallback to structured parsing
        analysis = {
            "summary": self._extract_section(response, "SUMMARY", "THREAT ASSESSMENT"),
            "threat_assessment": self._extract_section(response, "THREAT ASSESSMENT", "RECOMMENDATIONS"),
            "recommendations": self._extract_section(response, "RECOMMENDATIONS", "TECHNICAL DETAILS"),
            "technical_details": self._extract_section(response, "TECHNICAL DETAILS", "CONCLUSION"),
            "conclusion": self._extract_section(response, "CONCLUSION", None),
            "raw_response": response
        }
        
        # Clean up empty sections
        analysis = {k: v for k, v in analysis.items() if v and v.strip()}
        
        return analysis

    def _parse_correlation_response(self, response: str) -> Dict[str, Any]:
        """Parse correlation analysis response"""
        correlation = {
            "relationships": self._extract_section(response, "RELATIONSHIPS", "ATTACK CHAIN"),
            "attack_chain": self._extract_section(response, "ATTACK CHAIN", "THREAT ACTOR"),
            "threat_actor_analysis": self._extract_section(response, "THREAT ACTOR", "RECOMMENDATIONS"),
            "recommendations": self._extract_section(response, "RECOMMENDATIONS", None),
            "raw_response": response
        }
        
        return {k: v for k, v in correlation.items() if v and v.strip()}

    def _parse_threat_intelligence_response(self, response: str) -> Dict[str, Any]:
        """Parse threat intelligence response"""
        threat_intel = {
            "threat_analysis": self._extract_section(response, "THREAT ANALYSIS", "IOC ASSESSMENT"),
            "ioc_assessment": self._extract_section(response, "IOC ASSESSMENT", "ATTRIBUTION"),
            "attribution": self._extract_section(response, "ATTRIBUTION", "MITIGATION"),
            "mitigation_strategies": self._extract_section(response, "MITIGATION", None),
            "raw_response": response
        }
        
        return {k: v for k, v in threat_intel.items() if v and v.strip()}

    def _parse_incident_report_response(self, response: str) -> Dict[str, Any]:
        """Parse incident report response"""
        incident_report = {
            "executive_summary": self._extract_section(response, "EXECUTIVE SUMMARY", "TIMELINE"),
            "timeline": self._extract_section(response, "TIMELINE", "IMPACT ASSESSMENT"),
            "impact_assessment": self._extract_section(response, "IMPACT ASSESSMENT", "ROOT CAUSE"),
            "root_cause_analysis": self._extract_section(response, "ROOT CAUSE", "CONTAINMENT"),
            "containment_actions": self._extract_section(response, "CONTAINMENT", "LESSONS LEARNED"),
            "lessons_learned": self._extract_section(response, "LESSONS LEARNED", None),
            "raw_response": response
        }
        
        return {k: v for k, v in incident_report.items() if v and v.strip()}

    def _extract_section(self, text: str, start_marker: str, end_marker: Optional[str]) -> str:
        """Extract section between markers"""
        start_idx = text.find(start_marker)
        if start_idx == -1:
            return ""
        
        start_idx += len(start_marker)
        
        if end_marker:
            end_idx = text.find(end_marker, start_idx)
            if end_idx != -1:
                return text[start_idx:end_idx].strip()
        
        return text[start_idx:].strip()

    def _generate_cache_key(self, file_path: str, analysis_type: str) -> str:
        """Generate cache key for analysis results"""
        import hashlib
        key_string = f"{file_path}:{analysis_type}:{self.model}"
        return hashlib.md5(key_string.encode()).hexdigest()

    def _create_unavailable_response(self) -> Dict[str, Any]:
        """Create response when AI is unavailable"""
        return {
            "available": False,
            "message": "AI analysis unavailable - OpenAI API key not configured",
            "recommendation": "Configure OPENAI_API_KEY environment variable to enable AI features",
            "timestamp": datetime.now().isoformat()
        }

    def _create_error_response(self, error_message: str) -> Dict[str, Any]:
        """Create error response"""
        return {
            "error": True,
            "message": f"AI analysis failed: {error_message}",
            "recommendation": "Check API configuration and try again",
            "timestamp": datetime.now().isoformat()
        }

    def clear_conversation_history(self):
        """Clear conversation history"""
        self.conversation_history = []
        logger.info("Conversation history cleared")

    def clear_analysis_cache(self):
        """Clear analysis cache"""
        self.analysis_cache = {}
        logger.info("Analysis cache cleared")

    def get_usage_stats(self) -> Dict[str, Any]:
        """Get AI usage statistics"""
        return {
            "is_available": self.is_available,
            "model": self.model,
            "cached_analyses": len(self.analysis_cache),
            "conversation_length": len(self.conversation_history),
            "api_key_configured": bool(self.api_key)
        }

    async def test_connection(self) -> Dict[str, Any]:
        """Test OpenAI API connection"""
        if not self.is_available:
            return self._create_unavailable_response()
        
        try:
            # Simple test call
            test_prompt = "Respond with 'SecuNik AI connection successful' if you can read this."
            response = await self._make_api_call(test_prompt, max_tokens=20)
            
            return {
                "connection_successful": True,
                "response": response,
                "model": self.model,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                "connection_successful": False,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }

# Factory function for creating AI client
def create_ai_client(api_key: Optional[str] = None) -> SecuNikAI:
    """Create SecuNik AI client instance"""
    return SecuNikAI(api_key=api_key)