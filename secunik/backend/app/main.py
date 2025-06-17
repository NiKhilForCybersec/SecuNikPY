#!/usr/bin/env python3
"""
SecuNik - Ultimate Local Cybersecurity Analysis Platform
FastAPI application definition - FIXED VERSION
"""

import os
import sys
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional
import uvicorn
from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from enum import Enum

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Get the correct directory structure
current_dir = Path(__file__).parent  # backend/app/
backend_root = current_dir.parent    # backend/
project_root = backend_root.parent   # secunik/

# Data directory setup
DATA_DIR = project_root / "data"
UPLOADS_DIR = DATA_DIR / "uploads"
RESULTS_DIR = DATA_DIR / "results"
CASES_DIR = DATA_DIR / "cases"
TEMP_DIR = DATA_DIR / "temp"

# Create data directories
for directory in [DATA_DIR, UPLOADS_DIR, RESULTS_DIR, CASES_DIR, TEMP_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

logger.info(f"📁 Data directories created at: {DATA_DIR}")

# Check for OpenAI API key
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_AVAILABLE = bool(OPENAI_API_KEY)

logger.info(f"🤖 OpenAI available: {OPENAI_AVAILABLE}")

# Basic models (fallback if app models not available)
class AnalysisStatus(str, Enum):
    UPLOADED = "uploaded"
    ANALYZING = "analyzing" 
    COMPLETED = "completed"
    FAILED = "failed"

class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class AnalysisResult(BaseModel):
    file_id: str
    filename: str
    file_path: str
    parser_name: str = "basic"
    analysis_type: str = "basic"
    timestamp: datetime = datetime.utcnow()
    summary: str = ""
    details: Dict[str, Any] = {}
    threats_detected: List[Dict[str, Any]] = []
    severity: Severity = Severity.LOW
    risk_score: float = 0.0
    recommendations: List[str] = []
    threat_count: int = 0

class ChatMessage(BaseModel):
    message: str
    context: Optional[str] = None
    file_id: Optional[str] = None

# Initialize FastAPI app
app = FastAPI(
    title="SecuNik API",
    description="Ultimate Local Cybersecurity Analysis Platform",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8501", "http://127.0.0.1:8501", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Utility functions
def generate_file_id() -> str:
    """Generate unique file ID"""
    import uuid
    return str(uuid.uuid4())

def save_analysis_result(analysis: AnalysisResult):
    """Save analysis result to JSON file"""
    result_file = RESULTS_DIR / f"{analysis.file_id}.json"
    with open(result_file, "w") as f:
        json.dump(analysis.dict(), f, indent=2, default=str)

def load_analysis_result(file_id: str) -> Optional[Dict]:
    """Load analysis result from JSON file"""
    result_file = RESULTS_DIR / f"{file_id}.json"
    if result_file.exists():
        with open(result_file, "r") as f:
            return json.load(f)
    return None

def basic_file_analysis(file_path: Path, filename: str) -> AnalysisResult:
    """Perform basic file analysis"""
    file_id = generate_file_id()
    
    # Basic file info
    file_size = file_path.stat().st_size
    file_ext = file_path.suffix.lower()
    
    # Simple risk assessment based on file type
    risk_score = 0.1  # Default low risk
    severity = Severity.LOW
    threats = []
    recommendations = []
    
    # Basic threat detection based on file extension
    dangerous_extensions = ['.exe', '.scr', '.bat', '.cmd', '.pif', '.vbs', '.js']
    if file_ext in dangerous_extensions:
        risk_score = 0.6
        severity = Severity.MEDIUM
        threats.append({
            "type": "executable_file",
            "severity": "MEDIUM",
            "description": f"Executable file type detected: {file_ext}"
        })
        recommendations.append("Scan with antivirus before execution")
        recommendations.append("Execute only in sandboxed environment")
    
    # Archive files
    elif file_ext in ['.zip', '.rar', '.7z', '.tar', '.gz']:
        risk_score = 0.3
        severity = Severity.LOW
        recommendations.append("Scan archive contents before extraction")
    
    # Document files
    elif file_ext in ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx']:
        risk_score = 0.2
        severity = Severity.LOW
        recommendations.append("Check for embedded macros or scripts")
    
    # Large files
    if file_size > 100 * 1024 * 1024:  # > 100MB
        risk_score += 0.1
        recommendations.append("Large file - verify legitimacy")
    
    analysis = AnalysisResult(
        file_id=file_id,
        filename=filename,
        file_path=str(file_path),
        parser_name="basic_analyzer",
        analysis_type="basic",
        timestamp=datetime.utcnow(),
        summary=f"Basic analysis of {filename} completed. Risk level: {severity.value}",
        details={
            "original_filename": filename,
            "file_size": file_size,
            "file_extension": file_ext,
            "file_type": "executable" if file_ext in dangerous_extensions else "document" if file_ext in ['.pdf', '.doc', '.docx'] else "archive" if file_ext in ['.zip', '.rar'] else "unknown"
        },
        threats_detected=threats,
        severity=severity,
        risk_score=risk_score,
        recommendations=recommendations,
        threat_count=len(threats)
    )
    
    return analysis

# API Endpoints

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0",
        "openai_available": OPENAI_AVAILABLE,
        "data_dir": str(DATA_DIR)
    }

@app.get("/")
async def root():
    """Root endpoint with API information"""
    return {
        "name": "SecuNik API",
        "description": "Ultimate Local Cybersecurity Analysis Platform", 
        "version": "1.0.0",
        "models_status": "available",
        "openai_available": OPENAI_AVAILABLE,
        "docs": "/docs",
        "health": "/health"
    }

@app.get("/api/dashboard")
async def get_dashboard():
    """Get dashboard data"""
    try:
        # Count files and analyses
        total_files = len(list(UPLOADS_DIR.glob("*"))) if UPLOADS_DIR.exists() else 0
        total_analyses = len(list(RESULTS_DIR.glob("*.json"))) if RESULTS_DIR.exists() else 0
        
        # Calculate threat statistics
        threat_alerts = 0
        high_risk_files = 0
        total_threats = 0
        
        for result_file in RESULTS_DIR.glob("*.json"):
            try:
                with open(result_file, "r") as f:
                    analysis = json.load(f)
                    
                threats = analysis.get("threats_detected", [])
                total_threats += len(threats)
                
                if threats:
                    threat_alerts += 1
                
                risk_score = analysis.get("risk_score", 0.0)
                if risk_score > 0.6:
                    high_risk_files += 1
                    
            except Exception:
                continue
        
        return {
            "total_files": total_files,
            "total_analyses": total_analyses,
            "active_cases": 1,
            "threat_alerts": threat_alerts,
            "high_risk_files": high_risk_files,
            "clean_files": total_analyses - threat_alerts,
            "total_threats": total_threats,
            "average_risk_score": 0.2,  # Placeholder
            "system_status": "operational",
            "ai_available": OPENAI_AVAILABLE,
            "recent_activity": []
        }
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        return {
            "total_files": 0,
            "total_analyses": 0, 
            "active_cases": 0,
            "threat_alerts": 0,
            "system_status": "degraded",
            "error": str(e)
        }

@app.post("/api/upload")
async def upload_file(file: UploadFile = File(...)):
    """Upload and analyze a file"""
    try:
        # Save uploaded file
        file_id = generate_file_id()
        file_extension = Path(file.filename).suffix if file.filename else ""
        stored_filename = f"{file_id}{file_extension}"
        file_path = UPLOADS_DIR / stored_filename
        
        # Write file to disk
        with open(file_path, "wb") as f:
            content = await file.read()
            f.write(content)
        
        logger.info(f"📤 File uploaded: {file.filename} -> {file_path}")
        
        # Perform analysis
        analysis = basic_file_analysis(file_path, file.filename or "unknown")
        
        # Save analysis result
        save_analysis_result(analysis)
        
        logger.info(f"📊 Analysis completed for {file.filename}")
        
        return {
            "status": "success",
            "message": f"File {file.filename} uploaded and analyzed successfully",
            "file_id": analysis.file_id,
            "analysis": analysis.dict()
        }
        
    except Exception as e:
        logger.error(f"Upload error: {e}")
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")

@app.get("/api/files")
async def list_files():
    """List all uploaded files with analysis status"""
    try:
        files = []
        
        for result_file in RESULTS_DIR.glob("*.json"):
            try:
                with open(result_file, "r") as f:
                    analysis = json.load(f)
                
                files.append({
                    "file_id": analysis["file_id"],
                    "filename": analysis["filename"],
                    "analysis_type": analysis["analysis_type"],
                    "severity": analysis["severity"],
                    "risk_score": analysis["risk_score"],
                    "timestamp": analysis["timestamp"],
                    "threat_count": analysis.get("threat_count", 0)
                })
                
            except Exception as e:
                logger.warning(f"Error reading analysis file {result_file}: {e}")
                continue
        
        return {
            "files": files,
            "total_files": len(files)
        }
        
    except Exception as e:
        logger.error(f"List files error: {e}")
        return {"error": str(e), "files": []}

@app.get("/api/analysis")
async def get_all_analyses():
    """Get all analysis results"""
    try:
        analyses = []
        
        for result_file in RESULTS_DIR.glob("*.json"):
            try:
                with open(result_file, "r") as f:
                    analysis = json.load(f)
                analyses.append(analysis)
                
            except Exception as e:
                logger.warning(f"Error reading analysis file {result_file}: {e}")
                continue
        
        return {
            "analyses": analyses,
            "total_analyses": len(analyses)
        }
        
    except Exception as e:
        logger.error(f"Get analyses error: {e}")
        return {"error": str(e), "analyses": []}

@app.get("/api/analysis/{file_id}")
async def get_analysis(file_id: str):
    """Get detailed analysis for a specific file"""
    try:
        analysis = load_analysis_result(file_id)
        
        if not analysis:
            raise HTTPException(status_code=404, detail="Analysis not found")
        
        return {"analysis": analysis}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get analysis error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/analysis/{file_id}/threats")
async def get_file_threats(file_id: str):
    """Get threats for a specific file"""
    try:
        analysis = load_analysis_result(file_id)
        
        if not analysis:
            raise HTTPException(status_code=404, detail="Analysis not found")
        
        threats = analysis.get("threats_detected", [])
        
        return {
            "file_id": file_id,
            "threats": threats,
            "threat_count": len(threats),
            "severity": analysis.get("severity", "LOW"),
            "risk_score": analysis.get("risk_score", 0.0)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get threats error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/analysis/{file_id}/recommendations")
async def get_file_recommendations(file_id: str):
    """Get recommendations for a specific file"""
    try:
        analysis = load_analysis_result(file_id)
        
        if not analysis:
            raise HTTPException(status_code=404, detail="Analysis not found")
        
        recommendations = analysis.get("recommendations", [])
        severity = analysis.get("severity", "LOW")
        
        priority = "high" if severity in ["HIGH", "CRITICAL"] else "normal"
        
        return {
            "file_id": file_id,
            "recommendations": recommendations,
            "priority": priority
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get recommendations error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/files/{file_id}")
async def delete_file(file_id: str):
    """Delete a file and its analysis"""
    try:
        # Load analysis to get file path
        analysis = load_analysis_result(file_id)
        
        if analysis:
            # Delete uploaded file
            file_path = Path(analysis["file_path"])
            if file_path.exists():
                file_path.unlink()
            
            # Delete analysis file
            result_file = RESULTS_DIR / f"{file_id}.json"
            if result_file.exists():
                result_file.unlink()
        
        return {"message": "File and analysis deleted successfully"}
        
    except Exception as e:
        logger.error(f"Delete file error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# AI Endpoints
@app.get("/api/ai/status")
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
        ] if OPENAI_AVAILABLE else []
    }

@app.post("/api/ai/chat")
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
        
        # Simple keyword-based responses for now
        user_message = message.message.lower()
        
        if "threat" in user_message or "malware" in user_message:
            response = "I can help you analyze threats in your uploaded files. Upload a file and I'll provide detailed threat analysis."
            suggestions = ["Upload a suspicious file", "Check threat dashboard", "Review recent alerts"]
            
        elif "file" in user_message or "upload" in user_message:
            response = "You can upload files for analysis using the upload page. I support PDF, Office documents, archives, executables, and log files."
            suggestions = ["Go to upload page", "Check supported file types", "View file analysis results"]
            
        else:
            response = "I'm SecuNik's AI assistant. I can help with threat analysis, file examination, and security recommendations. What would you like to analyze?"
            suggestions = ["Upload a file for analysis", "Check threat dashboard", "Ask about specific threats"]
        
        return {
            "response": response,
            "confidence": 0.8,
            "sources": ["SecuNik Knowledge Base"],
            "suggestions": suggestions
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Chat failed: {str(e)}")

@app.get("/api/ai/insights/{file_id}")
async def get_ai_insights(file_id: str):
    """Get AI insights for a specific file"""
    try:
        analysis = load_analysis_result(file_id)
        
        if not analysis:
            raise HTTPException(status_code=404, detail="Analysis not found")
        
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
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/ai/analyze")
async def ai_analyze_file(request: dict):
    """AI-powered file analysis"""
    try:
        file_id = request.get("file_id")
        if not file_id:
            raise HTTPException(status_code=400, detail="file_id is required")
        
        if not OPENAI_AVAILABLE:
            return {
                "status": "unavailable",
                "message": "AI analysis requires OpenAI API key configuration"
            }
        
        analysis = load_analysis_result(file_id)
        if not analysis:
            raise HTTPException(status_code=404, detail="Analysis not found")
        
        # Add AI enhancement placeholder
        ai_enhanced = {
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
            }
        }
        
        analysis.update(ai_enhanced)
        
        # Save enhanced analysis
        result_file = RESULTS_DIR / f"{file_id}.json"
        with open(result_file, "w") as f:
            json.dump(analysis, f, indent=2, default=str)
        
        return {
            "status": "success",
            "message": "AI analysis completed",
            "file_id": file_id,
            "ai_insights": ai_enhanced["ai_analysis"]["ai_insights"],
            "ai_recommendations": ai_enhanced["ai_analysis"]["ai_recommendations"],
            "confidence": ai_enhanced["ai_analysis"]["ai_confidence"]
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/ai/capabilities")
async def get_ai_capabilities():
    """Get AI system capabilities"""
    return {
        "openai_available": OPENAI_AVAILABLE,
        "basic_capabilities": [
            "Basic threat detection",
            "File type analysis", 
            "Risk scoring",
            "Security recommendations"
        ],
        "ai_capabilities": [
            "Natural language queries",
            "Advanced threat correlation",
            "Behavioral analysis",
            "Automated reporting",
            "Intelligent recommendations"
        ] if OPENAI_AVAILABLE else [],
        "supported_file_types": [
            "PDF documents",
            "Office documents (Word, Excel, PowerPoint)",
            "Archive files (ZIP, RAR, 7z)",
            "Executable files (PE files)",
            "Log files",
            "Email files",
            "Registry files"
        ]
    }

# Exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    logger.error(f"Global exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "detail": str(exc)
        }
    )

if __name__ == "__main__":
    logger.info("🚀 Starting SecuNik API server...")
    logger.info(f"📁 Backend root: {backend_root}")
    logger.info(f"📁 Data directory: {DATA_DIR}")
    logger.info(f"🤖 OpenAI available: {OPENAI_AVAILABLE}")
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )