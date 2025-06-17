"""
OpenAI API client for SecuNik
Provides AI-powered analysis using GPT-4
"""

import os
import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
import asyncio
import aiohttp
from tenacity import retry, stop_after_attempt, wait_exponential

logger = logging.getLogger(__name__)

class OpenAIClient:
    """Client for OpenAI API integration"""
    
    def __init__(self, api_key: Optional[str] = None):
        """Initialize OpenAI client"""
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        self.base_url = "https://api.openai.com/v1"
        self.model = os.getenv("OPENAI_MODEL", "gpt-4-turbo-preview")
        self.max_tokens = int(os.getenv("OPENAI_MAX_TOKENS", "2000"))
        self.temperature = float(os.getenv("OPENAI_TEMPERATURE", "0.3"))
        
        if not self.api_key:
            logger.warning("OpenAI API key not configured")
        
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
    
    @property
    def is_configured(self) -> bool:
        """Check if OpenAI is properly configured"""
        return bool(self.api_key)
    
    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
    async def complete(self, 
                      prompt: str, 
                      system_prompt: Optional[str] = None,
                      max_tokens: Optional[int] = None,
                      temperature: Optional[float] = None) -> Dict[str, Any]:
        """Get completion from OpenAI"""
        if not self.is_configured:
            return {
                "error": "OpenAI API key not configured",
                "status": "unavailable"
            }
        
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        
        payload = {
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens or self.max_tokens,
            "temperature": temperature or self.temperature,
            "top_p": 0.95,
            "frequency_penalty": 0.1,
            "presence_penalty": 0.1
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.base_url}/chat/completions",
                    headers=self.headers,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=60)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return {
                            "content": data["choices"][0]["message"]["content"],
                            "usage": data.get("usage", {}),
                            "model": data.get("model", self.model)
                        }
                    else:
                        error_data = await response.text()
                        logger.error(f"OpenAI API error: {response.status} - {error_data}")
                        return {
                            "error": f"API error: {response.status}",
                            "details": error_data
                        }
                        
        except asyncio.TimeoutError:
            logger.error("OpenAI API request timed out")
            return {"error": "Request timed out"}
        except Exception as e:
            logger.error(f"OpenAI API error: {str(e)}")
            return {"error": str(e)}
    
    async def analyze_security_evidence(self, 
                                      evidence_context: Dict[str, Any],
                                      analysis_type: str = "comprehensive") -> Dict[str, Any]:
        """Analyze security evidence with AI"""
        from .prompt_templates import PromptTemplates
        
        templates = PromptTemplates()
        
        # Select appropriate prompt based on analysis type
        if analysis_type == "ioc_analysis":
            prompt = templates.get_ioc_analysis_prompt(evidence_context)
        elif analysis_type == "threat_assessment":
            prompt = templates.get_threat_assessment_prompt(evidence_context)
        elif analysis_type == "timeline_analysis":
            prompt = templates.get_timeline_analysis_prompt(evidence_context)
        else:
            prompt = templates.get_comprehensive_analysis_prompt(evidence_context)
        
        # Get AI analysis
        result = await self.complete(prompt, system_prompt=templates.base_context)
        
        if "error" in result:
            return result
        
        # Parse and structure the response
        try:
            analysis = self._parse_analysis_response(result["content"], analysis_type)
            analysis["model"] = result.get("model", self.model)
            analysis["usage"] = result.get("usage", {})
            return analysis
        except Exception as e:
            logger.error(f"Failed to parse AI response: {str(e)}")
            return {
                "error": "Failed to parse AI response",
                "raw_response": result["content"]
            }
    
    async def generate_threat_report(self, 
                                   analysis_results: List[Dict[str, Any]],
                                   case_info: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Generate comprehensive threat report"""
        from .prompt_templates import PromptTemplates
        
        templates = PromptTemplates()
        
        context = {
            "analysis_results": analysis_results,
            "case_info": case_info or {},
            "timestamp": datetime.now().isoformat()
        }
        
        prompt = templates.get_report_generation_prompt(context)
        
        result = await self.complete(
            prompt, 
            system_prompt=templates.base_context,
            max_tokens=3000  # Longer for reports
        )
        
        if "error" in result:
            return result
        
        return {
            "report": result["content"],
            "generated_at": datetime.now().isoformat(),
            "model": result.get("model", self.model)
        }
    
    async def chat(self, 
                   message: str, 
                   conversation_history: List[Dict[str, str]] = None,
                   evidence_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Interactive chat about security analysis"""
        from .prompt_templates import PromptTemplates
        
        templates = PromptTemplates()
        
        # Build conversation context
        messages = [{"role": "system", "content": templates.get_chat_system_prompt()}]
        
        # Add evidence context if available
        if evidence_context:
            context_prompt = f"Current analysis context:\n{json.dumps(evidence_context, indent=2)}"
            messages.append({"role": "system", "content": context_prompt})
        
        # Add conversation history
        if conversation_history:
            for msg in conversation_history[-10:]:  # Last 10 messages
                messages.append(msg)
        
        # Add current message
        messages.append({"role": "user", "content": message})
        
        payload = {
            "model": self.model,
            "messages": messages,
            "max_tokens": 1000,
            "temperature": 0.7  # More creative for chat
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.base_url}/chat/completions",
                    headers=self.headers,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return {
                            "response": data["choices"][0]["message"]["content"],
                            "role": "assistant"
                        }
                    else:
                        return {
                            "error": f"API error: {response.status}",
                            "response": "I encountered an error. Please try again."
                        }
                        
        except Exception as e:
            logger.error(f"Chat error: {str(e)}")
            return {
                "error": str(e),
                "response": "I'm having trouble connecting. Please check the API configuration."
            }
    
    def _parse_analysis_response(self, response: str, analysis_type: str) -> Dict[str, Any]:
        """Parse AI response into structured format"""
        # Try to extract JSON if present
        json_start = response.find("{")
        json_end = response.rfind("}")
        
        if json_start != -1 and json_end != -1:
            try:
                json_str = response[json_start:json_end + 1]
                return json.loads(json_str)
            except:
                pass
        
        # Parse structured text response
        analysis = {
            "analysis_type": analysis_type,
            "timestamp": datetime.now().isoformat(),
            "findings": [],
            "recommendations": [],
            "risk_assessment": {},
            "raw_analysis": response
        }
        
        # Extract sections from response
        lines = response.split("\n")
        current_section = None
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # Detect section headers
            if "FINDINGS" in line.upper() or "THREATS" in line.upper():
                current_section = "findings"
            elif "RECOMMENDATIONS" in line.upper():
                current_section = "recommendations"
            elif "RISK" in line.upper() or "SEVERITY" in line.upper():
                current_section = "risk"
            elif line.startswith("- ") or line.startswith("• "):
                # Bullet points
                content = line[2:].strip()
                if current_section == "findings":
                    analysis["findings"].append(content)
                elif current_section == "recommendations":
                    analysis["recommendations"].append(content)
            elif current_section == "risk" and ":" in line:
                # Risk assessment details
                key, value = line.split(":", 1)
                analysis["risk_assessment"][key.strip()] = value.strip()
        
        return analysis
    
    async def extract_iocs_with_ai(self, text_content: str) -> List[Dict[str, Any]]:
        """Use AI to extract IOCs from unstructured text"""
        prompt = f"""Extract all Indicators of Compromise (IOCs) from the following text.
        
        Return them in this JSON format:
        {{
            "iocs": [
                {{
                    "type": "ip_address|domain|url|email|hash|file_path|registry_key",
                    "value": "the actual IOC value",
                    "context": "brief context where it was found"
                }}
            ]
        }}
        
        Text to analyze:
        {text_content[:3000]}  # Limit to prevent token overflow
        """
        
        result = await self.complete(prompt, temperature=0.1)  # Low temperature for accuracy
        
        if "error" in result:
            return []
        
        try:
            # Parse JSON response
            response = result["content"]
            json_start = response.find("{")
            json_end = response.rfind("}")
            
            if json_start != -1 and json_end != -1:
                json_str = response[json_start:json_end + 1]
                data = json.loads(json_str)
                return data.get("iocs", [])
        except:
            logger.error("Failed to parse IOC extraction response")
        
        return []
    
    async def correlate_events(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Use AI to correlate security events"""
        prompt = f"""Analyze these security events and identify correlations, patterns, and potential attack chains.
        
        Events:
        {json.dumps(events[:20], indent=2)}  # Limit events
        
        Provide:
        1. Event correlations and relationships
        2. Identified attack patterns
        3. Timeline of potential attack chain
        4. Key indicators linking events
        """
        
        result = await self.complete(prompt, temperature=0.3)
        
        if "error" in result:
            return result
        
        return {
            "correlation_analysis": result["content"],
            "events_analyzed": len(events),
            "timestamp": datetime.now().isoformat()
        }

    async def health_check(self) -> Dict[str, Any]:
        """Check OpenAI API health"""
        if not self.is_configured:
            return {
                "status": "not_configured",
                "message": "OpenAI API key not set"
            }
        
        try:
            result = await self.complete(
                "Hello", 
                system_prompt="Reply with 'OK'",
                max_tokens=10
            )
            
            if "error" not in result:
                return {
                    "status": "healthy",
                    "model": self.model,
                    "message": "OpenAI API is accessible"
                }
            else:
                return {
                    "status": "error",
                    "message": result.get("error", "Unknown error")
                }
                
        except Exception as e:
            return {
                "status": "error",
                "message": str(e)
            }

# Singleton instance
_client_instance = None

def get_openai_client(api_key: Optional[str] = None) -> OpenAIClient:
    """Get or create OpenAI client instance"""
    global _client_instance
    
    if _client_instance is None or api_key:
        _client_instance = OpenAIClient(api_key)
    
    return _client_instance