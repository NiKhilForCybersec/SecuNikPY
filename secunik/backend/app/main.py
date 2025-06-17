#!/usr/bin/env python3
"""
SecuNik - Ultimate Local Cybersecurity Analysis Platform
FastAPI application definition (app/main.py)
"""

import os
import sys
import logging
from pathlib import Path
from datetime import datetime
from models.analysis import AnalysisResult  # Not app.models.analysis
from api.upload import router as upload_router

# Add current directory to path for relative imports
current_dir = Path(__file__).parent
if str(current_dir) not in sys.path:
    sys.path.insert(0, str(current_dir))

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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
    allow_origins=["http://localhost:8501", "http://127.0.0.1:8501"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Try to import analysis models with fallback
try:
    from models.analysis import (
        AnalysisStatus,
        ThreatLevel,
        Severity,
        IOCType,
        IOC,
        BasicFileInfo,
        ThreatAssessment,
        AnalysisMetrics,
        AnalysisResult,
        AnalysisSummary
    )
    logger.info("✅ Analysis models imported successfully")
    MODELS_AVAILABLE = True
except ImportError as e:
    logger.warning(f"⚠️  Analysis models not found. Using basic models. Error: {e}")
    MODELS_AVAILABLE = False
    
    # Fallback basic models
    from pydantic import BaseModel
    from typing import List, Dict, Any, Optional
    from enum import Enum
    
    class AnalysisStatus(str, Enum):
        UPLOADED = "uploaded"
        ANALYZING = "analyzing" 
        COMPLETED = "completed"
        FAILED = "failed"
    
    class ThreatLevel(str, Enum):
        LOW = "low"
        MEDIUM = "medium"
        HIGH = "high"
        CRITICAL = "critical"
    
    class Severity(str, Enum):
        LOW = "LOW"
        MEDIUM = "MEDIUM"
        HIGH = "HIGH"
        CRITICAL = "CRITICAL"
    
    class AnalysisResult(BaseModel):
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

# Import API routers with corrected paths
try:
    from api.upload import router as upload_router
    from api.analysis import router as analysis_router
    from api.dashboard import router as dashboard_router
    from api.ai import router as ai_router
    logger.info("✅ API routers imported successfully")
except ImportError as e:
    logger.error(f"❌ Could not import API routers: {e}")
    # Create basic routers as fallback
    from fastapi import APIRouter
    
    upload_router = APIRouter(prefix="/api", tags=["upload"])
    analysis_router = APIRouter(prefix="/api", tags=["analysis"])
    dashboard_router = APIRouter(prefix="/api", tags=["dashboard"])
    ai_router = APIRouter(prefix="/api", tags=["ai"])

# Basic health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "models_available": MODELS_AVAILABLE,
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0"
    }

@app.get("/")
async def root():
    """Root endpoint with API information"""
    return {
        "name": "SecuNik API",
        "description": "Ultimate Local Cybersecurity Analysis Platform", 
        "version": "1.0.0",
        "models_status": "available" if MODELS_AVAILABLE else "basic_fallback",
        "docs": "/docs",
        "health": "/health"
    }

# Basic dashboard endpoint fallback
@app.get("/api/dashboard")
async def get_dashboard():
    """Basic dashboard data"""
    try:
        # Get data directory relative to backend root
        backend_root = current_dir.parent  # Go up from app/ to backend/
        data_dir = backend_root / "data"
        uploads_dir = data_dir / "uploads"
        results_dir = data_dir / "results"
        
        # Create directories if they don't exist
        uploads_dir.mkdir(parents=True, exist_ok=True)
        results_dir.mkdir(parents=True, exist_ok=True)
        
        # Count files
        total_files = len(list(uploads_dir.glob("*"))) if uploads_dir.exists() else 0
        total_analyses = len(list(results_dir.glob("*.json"))) if results_dir.exists() else 0
        
        return {
            "total_files": total_files,
            "total_analyses": total_analyses,
            "active_cases": 1,
            "threat_alerts": 0,
            "system_status": "operational",
            "models_status": "available" if MODELS_AVAILABLE else "basic",
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
            "models_status": "unavailable",
            "recent_activity": [],
            "error": str(e)
        }

# Include API routers (these will use fallback empty routers if imports failed)
app.include_router(upload_router)
app.include_router(analysis_router)
app.include_router(dashboard_router)
app.include_router(ai_router)

# Exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    logger.error(f"Global exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "detail": str(exc),
            "models_available": MODELS_AVAILABLE
        }
    )

# For testing this file directly
if __name__ == "__main__":
    logger.info("🚀 Starting SecuNik API server directly...")
    logger.info(f"📁 App directory: {current_dir}")
    logger.info(f"📊 Models available: {MODELS_AVAILABLE}")
    
    # Ensure data directories exist
    backend_root = current_dir.parent
    (backend_root / "data" / "uploads").mkdir(parents=True, exist_ok=True)
    (backend_root / "data" / "results").mkdir(parents=True, exist_ok=True)
    (backend_root / "data" / "temp").mkdir(parents=True, exist_ok=True)
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )