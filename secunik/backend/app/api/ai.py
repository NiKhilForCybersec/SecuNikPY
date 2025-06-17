"""
AI-powered analysis endpoints for SecuNik
"""

import logging
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
from datetime import datetime
import json
import asyncio
from pathlib import Path

from ..models.analysis import AnalysisStatus
from ..core.ai.openai_client import get_openai_client
from ..core.ai.insights_generator import get_insights_generator
from ..core.ai.context_builder import get_context_builder

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/ai", tags=["AI"])

# Request/Response models
class AIAnalysisRequest(BaseModel):
    file_id: str
    analysis_type: Optional[str] = "comprehensive"
    enable_insights: Optional[bool] = True

class AIChatRequest(BaseModel):
    message: str
    conversation_history: Optional[List[Dict[str, str]]] = None
    context_file_id: Optional[str] = None

class AIInsightsRequest(BaseModel):
    file_ids: List[str]
    insight_types: Optional[List[str]] = None

class BulkAIAnalysisRequest(BaseModel):
    file_ids: Optional[List[str]] = None
    analysis_options: Optional[Dict[str, Any]] = None

# Storage paths
UPLOADS_DIR = Path("data/uploads")
RESULTS_DIR = Path("data/results")

@router.get("/status")
async def get_ai_status():
    """Get AI service status"""
    ai_client = get_openai_client()
    
    health = await ai_client.health_check()
    
    return {
        "status": health['status'],
        "configured": ai_client.is_configured,
        "model": ai_client.model if ai_client.is_configured else None,
        "message": health.get('message', ''),
        "capabilities": [
            "threat_analysis",
            "ioc_extraction",
            "risk_assessment",
            "timeline_analysis",
            "chat_interface",
            "report_generation"
        ]
    }

@router.post("/analyze/{file_id}")
async def ai_analyze_file(file_id: str, request: AIAnalysisRequest):
    """Perform AI-enhanced analysis on a file"""
    try:
        # Get AI client
        ai_client = get_openai_client()
        
        if not ai_client.is_configured:
            return {
                "status": "unavailable",
                "error": "AI service not configured"
            }
        
        # Load existing analysis result
        result_file = RESULTS_DIR / f"{file_id}.json"
        if not result_file.exists():
            raise HTTPException(status_code=404, detail="Analysis result not found")
        
        with open(result_file, "r") as f:
            analysis_result = json.load(f)
        
        # Build context
        context_builder = get_context_builder()
        evidence_context = context_builder.build_comprehensive_context([analysis_result])
        
        # Perform AI analysis
        ai_result = await ai_client.analyze_security_evidence(
            evidence_context,
            request.analysis_type
        )
        
        if "error" in ai_result:
            return {
                "status": "failed",
                "error": ai_result['error']
            }
        
        # Generate insights if requested
        insights = None
        if request.enable_insights:
            insights_generator = get_insights_generator()
            insights = await insights_generator.generate_file_insights(analysis_result)
        
        # Update analysis result with AI enhancement
        analysis_result['ai_analysis'] = ai_result
        analysis_result['ai_insights'] = insights
        analysis_result['ai_enhanced'] = True
        analysis_result['ai_timestamp'] = datetime.now().isoformat()
        
        # Save updated result
        with open(result_file, "w") as f:
            json.dump(analysis_result, f, indent=2, default=str)
        
        return {
            "status": "completed",
            "file_id": file_id,
            "ai_analysis": ai_result,
            "insights": insights,
            "confidence": ai_result.get('confidence', 0.8)
        }
        
    except Exception as e:
        logger.error(f"AI analysis failed for {file_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/chat")
async def ai_chat(request: AIChatRequest):
    """Chat with AI about security analysis"""
    try:
        ai_client = get_openai_client()
        
        if not ai_client.is_configured:
            return {
                "status": "unavailable",
                "error": "AI service not configured",
                "response": "AI features are not available. Please configure OpenAI API key."
            }
        
        # Load context if file specified
        evidence_context = None
        if request.context_file_id:
            result_file = RESULTS_DIR / f"{request.context_file_id}.json"
            if result_file.exists():
                with open(result_file, "r") as f:
                    analysis_result = json.load(f)
                
                context_builder = get_context_builder()
                evidence_context = {
                    "file_id": request.context_file_id,
                    "summary": analysis_result.get("summary", ""),
                    "threats": analysis_result.get("threats_detected", []),
                    "iocs": analysis_result.get("iocs_found", []),
                    "risk_score": analysis_result.get("risk_score", 0)
                }
        
        # Get AI response
        response = await ai_client.chat(
            request.message,
            request.conversation_history,
            evidence_context
        )
        
        return {
            "status": "success",
            "response": response.get("response", ""),
            "role": response.get("role", "assistant"),
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"AI chat error: {str(e)}")
        return {
            "status": "error",
            "error": str(e),
            "response": "I encountered an error processing your request."
        }

@router.post("/insights")
async def generate_insights(request: AIInsightsRequest):
    """Generate AI insights for multiple files"""
    try:
        insights_generator = get_insights_generator()
        
        # Load analysis results
        analysis_results = []
        for file_id in request.file_ids:
            result_file = RESULTS_DIR / f"{file_id}.json"
            if result_file.exists():
                with open(result_file, "r") as f:
                    analysis_results.append(json.load(f))
        
        if not analysis_results:
            return {
                "status": "failed",
                "error": "No valid analysis results found"
            }
        
        # Generate insights
        insights = await insights_generator.generate_comprehensive_insights(
            analysis_results,
            request.insight_types
        )
        
        return {
            "status": "completed",
            "file_count": len(analysis_results),
            "insights": insights,
            "generated_at": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Insights generation failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/extract-iocs")
async def extract_iocs_with_ai(text: str):
    """Extract IOCs from text using AI"""
    try:
        ai_client = get_openai_client()
        
        if not ai_client.is_configured:
            return {
                "status": "unavailable",
                "error": "AI service not configured"
            }
        
        # Extract IOCs
        iocs = await ai_client.extract_iocs_with_ai(text)
        
        return {
            "status": "completed",
            "iocs": iocs,
            "total_found": len(iocs)
        }
        
    except Exception as e:
        logger.error(f"IOC extraction failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/correlate-events")
async def correlate_events(events: List[Dict[str, Any]]):
    """Correlate security events using AI"""
    try:
        ai_client = get_openai_client()
        
        if not ai_client.is_configured:
            return {
                "status": "unavailable",
                "error": "AI service not configured"
            }
        
        # Correlate events
        correlation_result = await ai_client.correlate_events(events)
        
        return {
            "status": "completed",
            "correlation": correlation_result
        }
        
    except Exception as e:
        logger.error(f"Event correlation failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/generate-report/{case_id}")
async def generate_ai_report(case_id: str):
    """Generate comprehensive AI report for a case"""
    try:
        ai_client = get_openai_client()
        insights_generator = get_insights_generator()
        
        if not ai_client.is_configured:
            return {
                "status": "unavailable",
                "error": "AI service not configured"
            }
        
        # Load all analysis results for the case
        analysis_results = []
        case_dir = Path(f"data/cases/{case_id}")
        
        if not case_dir.exists():
            raise HTTPException(status_code=404, detail="Case not found")
        
        # Load case metadata
        case_file = case_dir / "case.json"
        case_info = {}
        if case_file.exists():
            with open(case_file, "r") as f:
                case_info = json.load(f)
        
        # Load analysis results
        for result_file in RESULTS_DIR.glob("*.json"):
            with open(result_file, "r") as f:
                result = json.load(f)
                # Check if file belongs to case
                if result.get("case_id") == case_id:
                    analysis_results.append(result)
        
        if not analysis_results:
            return {
                "status": "failed",
                "error": "No analysis results found for case"
            }
        
        # Generate comprehensive report
        report = await ai_client.generate_threat_report(
            analysis_results,
            case_info
        )
        
        if "error" in report:
            return {
                "status": "failed",
                "error": report['error']
            }
        
        # Save report
        report_file = case_dir / f"ai_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, "w") as f:
            json.dump(report, f, indent=2)
        
        return {
            "status": "completed",
            "case_id": case_id,
            "report": report['report'],
            "report_file": str(report_file),
            "generated_at": report['generated_at']
        }
        
    except Exception as e:
        logger.error(f"Report generation failed for case {case_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/bulk-analysis")
async def bulk_ai_analysis(request: BulkAIAnalysisRequest, background_tasks: BackgroundTasks):
    """Perform AI analysis on multiple files"""
    try:
        # Get AI client
        ai_client = get_openai_client()
        insights_generator = get_insights_generator()
        
        if not ai_client.is_configured:
            return {
                "status": "unavailable",
                "error": "AI service not configured"
            }
        
        # Determine which files to analyze
        file_ids = request.file_ids
        if not file_ids:
            # Analyze all available results
            file_ids = [f.stem for f in RESULTS_DIR.glob("*.json")]
        
        if not file_ids:
            return {
                "status": "failed",
                "error": "No files to analyze"
            }
        
        # Start background task
        task_id = f"bulk_ai_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        background_tasks.add_task(
            perform_bulk_ai_analysis,
            file_ids,
            request.analysis_options or {},
            task_id
        )
        
        return {
            "status": "started",
            "task_id": task_id,
            "file_count": len(file_ids),
            "message": "Bulk AI analysis started in background"
        }
        
    except Exception as e:
        logger.error(f"Bulk analysis failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

async def perform_bulk_ai_analysis(file_ids: List[str], options: Dict[str, Any], task_id: str):
    """Background task to perform bulk AI analysis"""
    try:
        ai_client = get_openai_client()
        insights_generator = get_insights_generator()
        
        results = []
        
        for file_id in file_ids:
            try:
                # Load analysis result
                result_file = RESULTS_DIR / f"{file_id}.json"
                if not result_file.exists():
                    continue
                
                with open(result_file, "r") as f:
                    analysis_result = json.load(f)
                
                # Build context
                context_builder = get_context_builder()
                evidence_context = context_builder.build_comprehensive_context([analysis_result])
                
                # Perform AI analysis
                ai_result = await ai_client.analyze_security_evidence(
                    evidence_context,
                    options.get('analysis_type', 'comprehensive')
                )
                
                if "error" not in ai_result:
                    # Update result
                    analysis_result['ai_analysis'] = ai_result
                    analysis_result['ai_enhanced'] = True
                    analysis_result['ai_timestamp'] = datetime.now().isoformat()
                    
                    # Save updated result
                    with open(result_file, "w") as f:
                        json.dump(analysis_result, f, indent=2, default=str)
                    
                    results.append({
                        "file_id": file_id,
                        "status": "completed"
                    })
                else:
                    results.append({
                        "file_id": file_id,
                        "status": "failed",
                        "error": ai_result['error']
                    })
                    
            except Exception as e:
                logger.error(f"Error processing {file_id}: {str(e)}")
                results.append({
                    "file_id": file_id,
                    "status": "failed",
                    "error": str(e)
                })
        
        # Generate comprehensive insights
        successful_results = []
        for file_id in file_ids:
            result_file = RESULTS_DIR / f"{file_id}.json"
            if result_file.exists():
                with open(result_file, "r") as f:
                    successful_results.append(json.load(f))
        
        if successful_results:
            insights = await insights_generator.generate_comprehensive_insights(
                successful_results,
                options.get('insight_types')
            )
            
            # Save insights
            insights_file = RESULTS_DIR / f"{task_id}_insights.json"
            with open(insights_file, "w") as f:
                json.dump(insights, f, indent=2)
        
        # Save task results
        task_result = {
            "task_id": task_id,
            "status": "completed",
            "completed_at": datetime.now().isoformat(),
            "total_files": len(file_ids),
            "successful": len([r for r in results if r['status'] == 'completed']),
            "failed": len([r for r in results if r['status'] == 'failed']),
            "results": results,
            "insights_file": str(insights_file) if successful_results else None
        }
        
        task_file = RESULTS_DIR / f"{task_id}.json"
        with open(task_file, "w") as f:
            json.dump(task_result, f, indent=2)
            
    except Exception as e:
        logger.error(f"Bulk AI analysis task failed: {str(e)}")

@router.get("/task/{task_id}")
async def get_task_status(task_id: str):
    """Get status of a background AI task"""
    task_file = RESULTS_DIR / f"{task_id}.json"
    
    if not task_file.exists():
        return {
            "status": "running",
            "task_id": task_id,
            "message": "Task is still processing"
        }
    
    with open(task_file, "r") as f:
        task_result = json.load(f)
    
    return task_result

@router.post("/quick-insights")
async def get_quick_insights(data: Dict[str, Any], insight_type: str):
    """Get quick AI insights for specific data"""
    try:
        insights_generator = get_insights_generator()
        
        insights = await insights_generator.generate_quick_insights(
            data,
            insight_type
        )
        
        return {
            "status": "completed",
            "insight_type": insight_type,
            "insights": insights
        }
        
    except Exception as e:
        logger.error(f"Quick insights failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))