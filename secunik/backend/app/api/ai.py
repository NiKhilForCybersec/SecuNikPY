"""
SecuNik - AI API Endpoints
API endpoints for AI-powered cybersecurity analysis

Location: backend/app/api/ai.py
"""

import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from pydantic import BaseModel, Field

from ..core.ai import create_ai_client, SecuNikAI
from ..core.parsers import parser_registry
from ..models.analysis import AnalysisResult

logger = logging.getLogger(__name__)

# Initialize router
router = APIRouter(prefix="/api/ai", tags=["AI Analysis"])

# Global AI client instance
ai_client = create_ai_client()

# Request/Response Models
class ChatRequest(BaseModel):
    message: str = Field(..., description="User message for AI chat")
    context_file_id: Optional[str] = Field(None, description="File ID for context")
    session_id: Optional[str] = Field(None, description="Chat session ID")

class ChatResponse(BaseModel):
    response: str
    session_id: str
    timestamp: str
    context_used: bool

class AIAnalysisRequest(BaseModel):
    file_id: str = Field(..., description="File ID to analyze")
    analysis_type: str = Field("comprehensive", description="Type of AI analysis")

class AIAnalysisResponse(BaseModel):
    analysis: Dict[str, Any]
    metadata: Dict[str, Any]
    available: bool

class ThreatIntelRequest(BaseModel):
    iocs: List[Dict[str, Any]] = Field(..., description="IOCs for threat intelligence")

class CorrelationRequest(BaseModel):
    file_ids: List[str] = Field(..., description="File IDs for correlation analysis")

class IncidentReportRequest(BaseModel):
    file_ids: List[str] = Field(..., description="File IDs for incident")
    incident_metadata: Dict[str, Any] = Field(..., description="Incident context")

# Helper functions
def get_analysis_result(file_id: str) -> Optional[AnalysisResult]:
    """Get analysis result from storage"""
    # This would typically load from your storage system
    # For now, we'll simulate this - in real implementation, 
    # you'd load from your database or file storage
    try:
        # Placeholder - implement actual storage retrieval
        logger.info(f"Loading analysis result for file_id: {file_id}")
        return None  # Return actual AnalysisResult from storage
    except Exception as e:
        logger.error(f"Failed to load analysis result {file_id}: {e}")
        return None

def load_multiple_analysis_results(file_ids: List[str]) -> List[AnalysisResult]:
    """Load multiple analysis results"""
    results = []
    for file_id in file_ids:
        result = get_analysis_result(file_id)
        if result:
            results.append(result)
    return results

# API Endpoints

@router.get("/status")
async def get_ai_status():
    """Get AI service status"""
    try:
        status = ai_client.get_usage_stats()
        connection_test = await ai_client.test_connection() if ai_client.is_available else {"connection_successful": False}
        
        return {
            "ai_available": ai_client.is_available,
            "model": ai_client.model,
            "api_key_configured": bool(ai_client.api_key),
            "connection_status": connection_test,
            "usage_stats": status,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Error getting AI status: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get AI status: {str(e)}")

@router.post("/analyze", response_model=AIAnalysisResponse)
async def analyze_file_with_ai(request: AIAnalysisRequest):
    """Perform AI-enhanced analysis on a file (NEW: AI-First Approach)"""
    try:
        # Load analysis result (this would be the raw extraction result)
        analysis_result = get_analysis_result(request.file_id)
        if not analysis_result:
            raise HTTPException(status_code=404, detail=f"Analysis result not found for file_id: {request.file_id}")
        
        # Perform AI-enhanced analysis (NEW: AI determines everything)
        enhanced_result = await ai_client.analyze_file_with_intelligence(analysis_result, request.analysis_type)
        
        return AIAnalysisResponse(
            analysis={
                "threats": enhanced_result.threats_detected,
                "severity": enhanced_result.severity.value if enhanced_result.severity else "LOW",
                "risk_score": enhanced_result.risk_score,
                "recommendations": enhanced_result.recommendations,
                "summary": enhanced_result.summary,
                "ai_analysis": enhanced_result.details.get("ai_analysis", {}),
                "original_extraction": {k: v for k, v in enhanced_result.details.items() if k != "ai_analysis"}
            },
            metadata={
                "file_id": request.file_id,
                "analysis_type": request.analysis_type,
                "timestamp": datetime.now().isoformat(),
                "ai_enhanced": True,
                "parser_used": enhanced_result.parser_name
            },
            available=ai_client.is_available
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in AI file analysis: {e}")
        raise HTTPException(status_code=500, detail=f"AI analysis failed: {str(e)}")

@router.post("/analyze-raw")
async def analyze_file_raw_only(request: AIAnalysisRequest):
    """Perform raw data extraction only (no AI enhancement)"""
    try:
        # Load analysis result
        analysis_result = get_analysis_result(request.file_id)
        if not analysis_result:
            raise HTTPException(status_code=404, detail=f"Analysis result not found for file_id: {request.file_id}")
        
        return {
            "extraction": {
                "summary": analysis_result.summary,
                "details": analysis_result.details,
                "iocs_found": [{"type": ioc.type.value if hasattr(ioc.type, 'value') else str(ioc.type), 
                               "value": ioc.value, "confidence": ioc.confidence} 
                              for ioc in analysis_result.iocs_found],
                "parser_used": analysis_result.parser_name,
                "file_path": analysis_result.file_path
            },
            "metadata": {
                "file_id": request.file_id,
                "timestamp": datetime.now().isoformat(),
                "ai_enhanced": False
            },
            "note": "Raw extraction only - use /analyze endpoint for AI-enhanced threat analysis"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in raw analysis: {e}")
        raise HTTPException(status_code=500, detail=f"Raw analysis failed: {str(e)}")

@router.post("/chat", response_model=ChatResponse)
async def chat_with_ai(request: ChatRequest):
    """Interactive chat with AI about analysis results"""
    try:
        # Build context data
        context_data = {}
        if request.context_file_id:
            analysis_result = get_analysis_result(request.context_file_id)
            if analysis_result:
                context_data = {
                    "file_path": analysis_result.file_path,
                    "analysis_type": analysis_result.analysis_type,
                    "summary": analysis_result.summary,
                    "threats": [t for t in analysis_result.threats_detected],
                    "iocs": [{"type": ioc.type.value if hasattr(ioc.type, 'value') else str(ioc.type), 
                             "value": ioc.value, "confidence": ioc.confidence} 
                            for ioc in analysis_result.iocs_found],
                    "severity": analysis_result.severity.value if analysis_result.severity else "UNKNOWN",
                    "risk_score": analysis_result.risk_score
                }
        
        # Get AI response
        chat_response = await ai_client.chat_about_analysis(request.message, context_data)
        
        session_id = request.session_id or f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        return ChatResponse(
            response=chat_response.get("response", "AI response not available"),
            session_id=session_id,
            timestamp=chat_response.get("timestamp", datetime.now().isoformat()),
            context_used=chat_response.get("context_used", False)
        )
        
    except Exception as e:
        logger.error(f"Error in AI chat: {e}")
        raise HTTPException(status_code=500, detail=f"AI chat failed: {str(e)}")

@router.post("/threat-intelligence")
async def generate_threat_intelligence(request: ThreatIntelRequest):
    """Generate threat intelligence from IOCs"""
    try:
        threat_intel = await ai_client.generate_threat_intelligence(request.iocs)
        
        return {
            "threat_intelligence": threat_intel,
            "ioc_count": len(request.iocs),
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error generating threat intelligence: {e}")
        raise HTTPException(status_code=500, detail=f"Threat intelligence generation failed: {str(e)}")

@router.post("/correlate")
async def correlate_files(request: CorrelationRequest):
    """Perform AI-powered correlation analysis across multiple files"""
    try:
        # Load analysis results
        analysis_results = load_multiple_analysis_results(request.file_ids)
        if not analysis_results:
            raise HTTPException(status_code=404, detail="No valid analysis results found for provided file IDs")
        
        # Perform correlation analysis
        correlation_analysis = await ai_client.analyze_multiple_files(analysis_results)
        
        return {
            "correlation_analysis": correlation_analysis,
            "files_analyzed": len(analysis_results),
            "file_ids": request.file_ids,
            "timestamp": datetime.now().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in correlation analysis: {e}")
        raise HTTPException(status_code=500, detail=f"Correlation analysis failed: {str(e)}")

@router.post("/incident-report")
async def generate_incident_report(request: IncidentReportRequest):
    """Generate comprehensive incident report using AI"""
    try:
        # Load analysis results
        analysis_results = load_multiple_analysis_results(request.file_ids)
        if not analysis_results:
            raise HTTPException(status_code=404, detail="No valid analysis results found for provided file IDs")
        
        # Generate incident report
        incident_report = await ai_client.generate_incident_report(analysis_results, request.incident_metadata)
        
        return {
            "incident_report": incident_report,
            "evidence_files": len(analysis_results),
            "incident_id": request.incident_metadata.get("incident_id", "Unknown"),
            "timestamp": datetime.now().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error generating incident report: {e}")
        raise HTTPException(status_code=500, detail=f"Incident report generation failed: {str(e)}")

@router.post("/clear-cache")
async def clear_ai_cache():
    """Clear AI analysis cache and conversation history"""
    try:
        ai_client.clear_analysis_cache()
        ai_client.clear_conversation_history()
        
        return {
            "message": "AI cache and conversation history cleared",
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error clearing AI cache: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to clear AI cache: {str(e)}")

@router.get("/capabilities")
async def get_ai_capabilities():
    """Get AI analysis capabilities and features (UPDATED: AI-First Platform)"""
    try:
        return {
            "platform_architecture": "AI-First Cybersecurity Analysis",
            "available": ai_client.is_available,
            "model": ai_client.model,
            "core_capabilities": {
                "intelligent_threat_detection": {
                    "description": "AI performs all threat detection and classification",
                    "features": [
                        "Dynamic malware detection",
                        "Behavioral analysis",
                        "Attack technique identification (MITRE ATT&CK)",
                        "Zero-day threat detection",
                        "Contextual threat assessment"
                    ]
                },
                "ai_powered_risk_scoring": {
                    "description": "AI calculates comprehensive risk scores (0-100)",
                    "features": [
                        "Multi-factor risk assessment", 
                        "Business impact analysis",
                        "Threat landscape correlation",
                        "Dynamic severity determination"
                    ]
                },
                "intelligent_recommendations": {
                    "description": "AI generates actionable security recommendations",
                    "features": [
                        "Prioritized action items",
                        "Context-aware suggestions",
                        "Investigation guidance",
                        "Long-term security improvements"
                    ]
                },
                "natural_language_analysis": {
                    "description": "Interactive analysis through natural language",
                    "features": [
                        "Question-answer capability",
                        "Threat explanation",
                        "Investigation assistance",
                        "Executive summaries"
                    ]
                }
            },
            "analysis_workflow": {
                "step_1": "Raw data extraction from evidence files",
                "step_2": "AI processes extracted data for threat detection",
                "step_3": "AI determines severity and calculates risk scores", 
                "step_4": "AI generates contextual recommendations",
                "step_5": "Interactive analysis through natural language queries"
            },
            "analysis_types": [
                {
                    "type": "comprehensive",
                    "description": "Complete AI threat analysis with detailed findings",
                    "use_case": "Full investigation and incident response"
                },
                {
                    "type": "threat_assessment", 
                    "description": "Focused AI threat detection and classification",
                    "use_case": "Rapid threat identification and triage"
                },
                {
                    "type": "quick_summary",
                    "description": "Fast AI assessment for immediate decisions",
                    "use_case": "Quick security evaluation and prioritization"
                }
            ],
            "supported_evidence_types": parser_registry.get_supported_file_types(),
            "ai_features": {
                "threat_intelligence": "Generate threat intelligence from IOCs",
                "correlation_analysis": "Cross-evidence correlation and attack chain reconstruction", 
                "incident_reporting": "Automated comprehensive incident reports",
                "bulk_analysis": "Analyze multiple files with AI enhancement",
                "comparison_analysis": "Compare raw extraction vs AI-enhanced results"
            },
            "key_advantages": [
                "No hardcoded rules - AI adapts to new threats",
                "Contextual analysis based on complete evidence picture",
                "Natural language interaction with analysis results",
                "Continuous improvement through AI model updates",
                "Expert-level analysis available instantly"
            ],
            "usage_stats": ai_client.get_usage_stats(),
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error getting AI capabilities: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get AI capabilities: {str(e)}")

@router.get("/models")
async def get_available_models():
    """Get available AI models and their capabilities"""
    return {
        "current_model": ai_client.model,
        "available_models": [
            {
                "name": "gpt-4",
                "description": "Most advanced model for complex cybersecurity analysis",
                "use_cases": ["Comprehensive analysis", "Complex correlation", "Detailed reports"]
            },
            {
                "name": "gpt-3.5-turbo", 
                "description": "Fast model for quick analysis and chat",
                "use_cases": ["Quick summaries", "Interactive chat", "Basic analysis"]
            }
        ],
        "recommendation": "GPT-4 recommended for forensic analysis"
    }

# Export router
__all__ = ['router']

# Background task functions
async def background_ai_analysis(file_id: str, analysis_type: str):
    """Background AI analysis task"""
    try:
        analysis_result = get_analysis_result(file_id)
        if analysis_result:
            ai_analysis = await ai_client.analyze_file(analysis_result, analysis_type)
            # Store AI analysis result - implement your storage logic here
            logger.info(f"Background AI analysis completed for {file_id}")
    except Exception as e:
        logger.error(f"Background AI analysis failed for {file_id}: {e}")

@router.post("/analyze-async")
async def analyze_file_async(request: AIAnalysisRequest, background_tasks: BackgroundTasks):
    """Start asynchronous AI analysis"""
    try:
        # Verify file exists
        analysis_result = get_analysis_result(request.file_id)
        if not analysis_result:
            raise HTTPException(status_code=404, detail=f"Analysis result not found for file_id: {request.file_id}")
        
        # Start background analysis
        background_tasks.add_task(background_ai_analysis, request.file_id, request.analysis_type)
        
        return {
            "message": "AI analysis started",
            "file_id": request.file_id,
            "analysis_type": request.analysis_type,
            "status": "processing",
            "timestamp": datetime.now().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error starting async AI analysis: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to start AI analysis: {str(e)}")

@router.get("/platform-info")
async def get_platform_architecture_info():
    """Get information about the AI-first platform architecture"""
    return {
        "platform_name": "SecuNik AI-First Cybersecurity Platform",
        "architecture": "AI-Powered Intelligence Engine",
        "description": "Advanced cybersecurity analysis platform where AI performs ALL threat detection, risk assessment, and recommendation generation",
        
        "key_differentiators": {
            "ai_first_design": {
                "description": "AI is the primary intelligence engine, not an add-on",
                "benefits": [
                    "No hardcoded threat signatures to maintain",
                    "Adapts to new and unknown threats",
                    "Contextual analysis beyond simple pattern matching",
                    "Continuous improvement through AI model updates"
                ]
            },
            "pure_data_extraction": {
                "description": "Parsers focus solely on data extraction",
                "benefits": [
                    "Clean separation of data extraction and analysis",
                    "Easier to maintain and extend parsers",
                    "AI sees all available data for analysis",
                    "No missed threats due to parser limitations"
                ]
            },
            "intelligent_threat_detection": {
                "description": "AI performs dynamic threat detection",
                "benefits": [
                    "Detects zero-day and unknown threats",
                    "Contextual threat assessment",
                    "Cross-evidence correlation",
                    "Behavioral and pattern analysis"
                ]
            },
            "natural_language_interface": {
                "description": "Interact with analysis results using natural language",
                "benefits": [
                    "Ask questions about findings",
                    "Get explanations in plain English", 
                    "No need to learn complex query languages",
                    "Accessible to non-technical stakeholders"
                ]
            }
        },
        
        "workflow": {
            "phase_1": {
                "name": "Data Extraction",
                "description": "Specialized parsers extract raw data from evidence files",
                "output": "Structured data ready for AI analysis"
            },
            "phase_2": {
                "name": "AI Intelligence Processing", 
                "description": "AI analyzes extracted data for threats, risks, and patterns",
                "output": "Comprehensive threat assessment with severity and risk scoring"
            },
            "phase_3": {
                "name": "Recommendation Generation",
                "description": "AI generates prioritized, actionable security recommendations",
                "output": "Specific steps for containment, investigation, and improvement"
            },
            "phase_4": {
                "name": "Interactive Analysis",
                "description": "Natural language interface for deeper investigation",
                "output": "Answers to specific questions about findings and threats"
            }
        },
        
        "comparison_with_traditional_tools": {
            "traditional_approach": [
                "Hardcoded signatures and rules",
                "Limited to known threats",
                "Manual rule maintenance required",
                "Limited contextual analysis",
                "Technical expertise required for interpretation"
            ],
            "secunik_ai_approach": [
                "Dynamic AI-powered threat detection",
                "Detects unknown and zero-day threats",
                "Self-updating through AI model improvements",
                "Full contextual and behavioral analysis",
                "Natural language explanations for all stakeholders"
            ]
        },
        
        "evidence_types_supported": {
            "network_forensics": [".pcap", ".pcapng", ".cap"],
            "windows_logs": [".evtx"],
            "email_forensics": [".pst", ".ost", ".eml", ".msg"],
            "registry_analysis": [".reg", ".dat", ".hiv"],
            "malware_analysis": [".exe", ".dll", ".sys", ".scr", ".com"],
            "document_analysis": [".pdf"],
            "archive_analysis": [".zip", ".rar", ".7z"]
        },
        
        "ai_model_info": {
            "current_model": ai_client.model,
            "capabilities": [
                "Expert-level cybersecurity analysis",
                "Multi-language understanding",
                "Contextual reasoning",
                "Pattern recognition",
                "Threat intelligence correlation"
            ],
            "advantages": [
                "Trained on vast cybersecurity knowledge",
                "Understands attack techniques and TTPs",
                "Can explain findings in natural language",
                "Continuously updated knowledge base"
            ]
        },
        
        "timestamp": datetime.now().isoformat()
    }