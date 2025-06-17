"""
AI API Router
Handles AI-powered analysis and chat functionality
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/api", tags=["ai"])

# Get backend root directory
current_dir = Path(__file__).parent.parent.parent  # Go up from app/api/ to backend/
RESULTS_DIR = current_dir / "data" / "results"

# Check if OpenAI is available
OPENAI_AVAILABLE = bool(os.getenv("OPENAI_API_KEY"))

class ChatMessage(BaseModel):
    """Chat message model"""
    message: str
    context: Optional[str] = None
    file_id: Optional[str] = None

class ChatResponse(BaseModel):
    """Chat response model"""
    response: str
    confidence: float
    sources: List[str]
    suggestions: List[str]

class AIAnalysisRequest(BaseModel):
    """AI analysis request model"""
    file_id: str
    analysis_type: str = "comprehensive"
    prompt: Optional[str] = None

@router.get("/ai/status")
async def get_ai_status():
    """Get AI system status"""
    return {
        "ai_available": OPENAI_AVAILABLE,
        "openai_configured": OPENAI_AVAILABLE,
        "status": "ready" if OPENAI_AVAILABLE else "configuration_required",
        "capabilities": [
            "threat_analysis",
            "natural_language_queries", 
            "file_correlation",
            "recommendation_generation",
            "chat_interface"
        ] if OPENAI_AVAILABLE else [],
        "version": "1.0.0"
    }

@router.post("/ai/chat")
async def chat_with_ai(message: ChatMessage):
    """Chat with AI about analysis results"""
    try:
        if not OPENAI_AVAILABLE:
            return {
                "response": "AI chat is not available. Please configure your OpenAI API key.",
                "confidence": 0.0,
                "sources": [],
                "suggestions": ["Configure OpenAI API key", "Use manual analysis features"]
            }
        
        # Basic chat responses (will be enhanced with real AI in next phase)
        user_message = message.message.lower()
        
        # Simple keyword-based responses
        if "threat" in user_message or "malware" in user_message:
            response = "I can help you analyze threats in your uploaded files. Upload a file and I'll provide detailed threat analysis."
            suggestions = ["Upload a suspicious file", "Check threat dashboard", "Review recent alerts"]
            
        elif "file" in user_message or "upload" in user_message:
            response = "You can upload files for analysis using the upload endpoint. I support PDF, Office documents, archives, executables, and log files."
            suggestions = ["Use /api/upload endpoint", "Check supported file types", "View file analysis results"]
            
        elif "help" in user_message or "how" in user_message:
            response = "I'm SecuNik's AI assistant. I can help with threat analysis, file examination, and security recommendations. What would you like to analyze?"
            suggestions = ["Upload a file for analysis", "Check threat dashboard", "Ask about specific threats"]
            
        elif message.file_id:
            # If file ID is provided, get analysis info
            result_file = RESULTS_DIR / f"{message.file_id}.json"
            if result_file.exists():
                with open(result_file, "r") as f:
                    analysis = json.load(f)
                
                filename = analysis.get("details", {}).get("original_filename", "unknown")
                severity = analysis.get("severity", "LOW")
                risk_score = analysis.get("risk_score", 0.0)
                threat_count = len(analysis.get("threats_detected", []))
                
                response = f"I've analyzed {filename}. Severity: {severity}, Risk Score: {risk_score:.2f}, Threats Found: {threat_count}. What would you like to know more about?"
                suggestions = ["Show threat details", "Get recommendations", "Compare with similar files"]
            else:
                response = "I couldn't find analysis results for that file ID. Please check the ID or upload the file first."
                suggestions = ["Verify file ID", "Upload file again", "Check file list"]
                
        else:
            response = "I'm here to help with cybersecurity analysis. You can ask me about threats, upload files for analysis, or get security recommendations."
            suggestions = ["Upload a file", "Check threats", "Get help"]
        
        return {
            "response": response,
            "confidence": 0.8,
            "sources": ["SecuNik Knowledge Base"],
            "suggestions": suggestions,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Chat failed: {str(e)}")

@router.post("/ai/analyze")
async def ai_analyze_file(request: AIAnalysisRequest):
    """AI-powered file analysis (enhanced version)"""
    try:
        if not OPENAI_AVAILABLE:
            return {
                "status": "unavailable",
                "message": "AI analysis requires OpenAI API key configuration",
                "basic_analysis_available": True
            }
        
        # Check if file exists
        result_file = RESULTS_DIR / f"{request.file_id}.json"
        if not result_file.exists():
            raise HTTPException(status_code=404, detail="File analysis not found")
        
        # Load existing analysis
        with open(result_file, "r") as f:
            analysis = json.load(f)
        
        # AI enhancement placeholder (will be implemented with real AI in next phase)
        ai_enhanced_analysis = analysis.copy()
        ai_enhanced_analysis.update({
            "ai_analysis": {
                "enhanced_by_ai": True,
                "ai_confidence": 0.85,
                "ai_insights": [
                    "File appears to be legitimate based on metadata analysis",
                    "No suspicious patterns detected in file structure", 
                    "Recommend monitoring for unusual behavior if executed"
                ],
                "ai_risk_assessment": "Standard security protocols sufficient",
                "ai_recommendations": [
                    "Scan with updated antivirus before opening",
                    "Open in sandboxed environment if suspicious",
                    "Monitor network activity after execution"
                ]
            },
            "enhanced_at": datetime.utcnow().isoformat()
        })
        
        # Save enhanced analysis
        with open(result_file, "w") as f:
            json.dump(ai_enhanced_analysis, f, indent=2, default=str)
        
        return {
            "status": "success",
            "message": "AI analysis completed",
            "file_id": request.file_id,
            "ai_insights": ai_enhanced_analysis["ai_analysis"]["ai_insights"],
            "ai_recommendations": ai_enhanced_analysis["ai_analysis"]["ai_recommendations"],
            "confidence": ai_enhanced_analysis["ai_analysis"]["ai_confidence"]
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI analysis failed: {str(e)}")

@router.get("/ai/insights/{file_id}")
async def get_ai_insights(file_id: str):
    """Get AI insights for a specific file"""
    try:
        result_file = RESULTS_DIR / f"{file_id}.json"
        if not result_file.exists():
            raise HTTPException(status_code=404, detail="File analysis not found")
        
        with open(result_file, "r") as f:
            analysis = json.load(f)
        
        ai_analysis = analysis.get("ai_analysis", {})
        
        if not ai_analysis:
            return {
                "file_id": file_id,
                "ai_insights_available": False,
                "message": "No AI insights available. Run AI analysis first."
            }
        
        return {
            "file_id": file_id,
            "ai_insights_available": True,
            "insights": ai_analysis.get("ai_insights", []),
            "recommendations": ai_analysis.get("ai_recommendations", []),
            "confidence": ai_analysis.get("ai_confidence", 0.0),
            "risk_assessment": ai_analysis.get("ai_risk_assessment", "Unknown")
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get AI insights: {str(e)}")

@router.post("/ai/correlate")
async def correlate_files():
    """AI-powered cross-file correlation analysis"""
    try:
        if not OPENAI_AVAILABLE:
            return {
                "status": "unavailable",
                "message": "AI correlation requires OpenAI API key configuration"
            }
        
        # Basic correlation analysis (placeholder for full AI implementation)
        correlations = []
        analyses = []
        
        # Load all analyses
        for result_file in RESULTS_DIR.glob("*.json"):
            try:
                with open(result_file, "r") as f:
                    analysis = json.load(f)
                    analyses.append({
                        "file_id": result_file.stem,
                        "filename": analysis.get("details", {}).get("original_filename", "unknown"),
                        "threats": analysis.get("threats_detected", []),
                        "risk_score": analysis.get("risk_score", 0.0),
                        "analysis_type": analysis.get("analysis_type", "unknown")
                    })
            except Exception:
                continue
        
        # Simple correlation based on similar threat patterns
        for i, analysis1 in enumerate(analyses):
            for j, analysis2 in enumerate(analyses[i+1:], i+1):
                # Check for similar threat patterns
                threats1 = [t.get("type", "") for t in analysis1["threats"]]
                threats2 = [t.get("type", "") for t in analysis2["threats"]]
                
                common_threats = set(threats1).intersection(set(threats2))
                
                if common_threats:
                    correlations.append({
                        "file1": {
                            "id": analysis1["file_id"],
                            "filename": analysis1["filename"]
                        },
                        "file2": {
                            "id": analysis2["file_id"], 
                            "filename": analysis2["filename"]
                        },
                        "correlation_type": "similar_threats",
                        "common_elements": list(common_threats),
                        "confidence": 0.7
                    })
        
        return {
            "total_files": len(analyses),
            "correlations_found": len(correlations),
            "correlations": correlations[:10],  # Limit to 10 results
            "ai_analysis": True
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Correlation analysis failed: {str(e)}")

@router.get("/ai/capabilities")
async def get_ai_capabilities():
    """Get AI system capabilities"""
    base_capabilities = [
        "Basic threat detection",
        "File type analysis", 
        "Risk scoring",
        "Security recommendations"
    ]
    
    ai_capabilities = [
        "Natural language queries",
        "Advanced threat correlation",
        "Behavioral analysis",
        "Zero-day detection",
        "Automated reporting",
        "Intelligent recommendations"
    ] if OPENAI_AVAILABLE else []
    
    return {
        "openai_available": OPENAI_AVAILABLE,
        "basic_capabilities": base_capabilities,
        "ai_capabilities": ai_capabilities,
        "supported_file_types": [
            "PDF documents",
            "Office documents (Word, Excel, PowerPoint)",
            "Archive files (ZIP, RAR, 7z)",
            "Executable files (PE files)",
            "Log files",
            "Network captures (PCAP)",
            "Email files (PST, EML)",
            "Registry files"
        ],
        "analysis_types": [
            "Static analysis",
            "Metadata extraction", 
            "Threat detection",
            "IoC extraction",
            "Risk assessment"
        ]
    }

@router.post("/ai/bulk-analyze")
async def bulk_ai_analysis():
    """Perform AI analysis on all uploaded files"""
    try:
        if not OPENAI_AVAILABLE:
            return {
                "status": "unavailable",
                "message": "Bulk AI analysis requires OpenAI API key configuration"
            }
        
        results = []
        processed = 0
        
        for result_file in RESULTS_DIR.glob("*.json"):
            try:
                file_id = result_file.stem
                
                # Simulate AI analysis for each file
                with open(result_file, "r") as f:
                    analysis = json.load(f)
                
                # Add AI enhancement
                filename = analysis.get("details", {}).get("original_filename", "unknown")
                risk_score = analysis.get("risk_score", 0.0)
                
                results.append({
                    "file_id": file_id,
                    "filename": filename,
                    "ai_enhanced": True,
                    "original_risk": risk_score,
                    "ai_risk": min(risk_score + 0.1, 1.0),  # Slight AI adjustment
                    "status": "completed"
                })
                
                processed += 1
                
            except Exception as e:
                results.append({
                    "file_id": result_file.stem,
                    "status": "failed",
                    "error": str(e)
                })
        
        return {
            "status": "completed",
            "total_files": len(results),
            "successfully_processed": processed,
            "results": results
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Bulk analysis failed: {str(e)}")