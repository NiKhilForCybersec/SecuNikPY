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
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Get the correct directory structure
current_dir = Path(__file__).parent  # backend/app/
backend_root = current_dir.parent    # backend/
project_root = backend_root.parent   # secunik/

# Data directory setup
DATA_DIR = backend_root / "data"
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

# Import routers AFTER app creation
try:
    from api import upload, analysis, dashboard, ai
    app.include_router(upload.router)
    app.include_router(analysis.router)
    app.include_router(dashboard.router)
    app.include_router(ai.router)
    logger.info("✅ All routers registered successfully")
except ImportError as e:
    logger.error(f"❌ Failed to import routers: {e}")
    logger.warning("API endpoints will be limited")

# Import models with fallback
try:
    from models.analysis import (
        AnalysisStatus, Severity, AnalysisResult,
        IOC, IOCType, ThreatInfo
    )
    logger.info("✅ Models imported successfully")
except ImportError:
    logger.warning("⚠️ Could not import models, using fallback definitions")
    
    # Fallback models
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

# Utility functions
def generate_file_id() -> str:
    """Generate unique file ID"""
    import uuid
    return str(uuid.uuid4())

def save_analysis_result(analysis: AnalysisResult):
    """Save analysis result to JSON file"""
    result_file = RESULTS_DIR / f"{analysis.file_id}.json"
    with open(result_file, "w") as f:
        json.dump(analysis.dict() if hasattr(analysis, 'dict') else analysis.__dict__, 
                  f, indent=2, default=str)

def load_analysis_result(file_id: str) -> Optional[Dict]:
    """Load analysis result from JSON file"""
    result_file = RESULTS_DIR / f"{file_id}.json"
    if result_file.exists():
        with open(result_file, "r") as f:
            return json.load(f)
    return None

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