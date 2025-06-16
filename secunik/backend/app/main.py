"""
SecuNik Backend - FastAPI Application
Main application entry point for the cybersecurity analysis platform
"""

from fastapi import FastAPI, HTTPException, UploadFile, File, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse
import uvicorn
import os
import sys
from pathlib import Path
import logging
from datetime import datetime
import uuid

# Add the app directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from config import Settings
from core.storage.file_manager import FileManager
from models.analysis import AnalysisResult
from models.case import Case
from utils.file_utils import get_file_info, validate_file_type

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="SecuNik API",
    description="Ultimate Local Cybersecurity Analysis Platform",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Initialize settings and services
settings = Settings()
file_manager = FileManager(settings.data_path)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
static_path = Path(__file__).parent / "static"
if static_path.exists():
    app.mount("/static", StaticFiles(directory=str(static_path)), name="static")

@app.on_event("startup")
async def startup_event():
    """Initialize application on startup"""
    logger.info("🚀 SecuNik Backend starting up...")
    
    # Ensure data directories exist
    file_manager.ensure_directories()
    
    logger.info("✅ SecuNik Backend startup complete!")

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    logger.info("🛑 SecuNik Backend shutting down...")

# Health Check Endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0",
        "services": {
            "file_manager": "operational",
            "storage": "operational"
        }
    }

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "SecuNik API - Ultimate Cybersecurity Analysis Platform",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/health"
    }

# File Upload Endpoints
@app.post("/api/upload")
async def upload_file(file: UploadFile = File(...), case_id: str = None):
    """
    Upload a file for analysis
    """
    try:
        # Validate file
        if not file.filename:
            raise HTTPException(status_code=400, detail="No file provided")
        
        # Get file info
        file_info = await get_file_info(file)
        
        # Validate file type and size
        if not validate_file_type(file_info["type"]):
            raise HTTPException(
                status_code=400, 
                detail=f"Unsupported file type: {file_info['type']}"
            )
        
        if file_info["size"] > settings.max_file_size:
            raise HTTPException(
                status_code=400, 
                detail=f"File too large. Max size: {settings.max_file_size} bytes"
            )
        
        # Generate file ID
        file_id = str(uuid.uuid4())
        
        # Create case if not provided
        if not case_id:
            case_id = f"case_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Save file
        saved_file = await file_manager.save_uploaded_file(
            file, file_id, case_id
        )
        
        # Create analysis result placeholder
        analysis_result = AnalysisResult(
            file_id=file_id,
            case_id=case_id,
            filename=file.filename,
            file_type=file_info["type"],
            file_size=file_info["size"],
            upload_timestamp=datetime.utcnow(),
            status="uploaded",
            file_path=saved_file["path"]
        )
        
        # Save analysis result
        await file_manager.save_analysis_result(analysis_result)
        
        logger.info(f"📁 File uploaded: {file.filename} ({file_info['size']} bytes)")
        
        return {
            "message": "File uploaded successfully",
            "file_id": file_id,
            "case_id": case_id,
            "filename": file.filename,
            "file_type": file_info["type"],
            "file_size": file_info["size"],
            "status": "uploaded"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Upload error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")

@app.get("/api/files")
async def list_files(case_id: str = None):
    """
    List uploaded files
    """
    try:
        files = await file_manager.list_files(case_id)
        return {
            "files": files,
            "count": len(files),
            "case_id": case_id
        }
    except Exception as e:
        logger.error(f"❌ Error listing files: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to list files: {str(e)}")

@app.get("/api/files/{file_id}")
async def get_file_details(file_id: str):
    """
    Get detailed information about a specific file
    """
    try:
        file_details = await file_manager.get_file_details(file_id)
        if not file_details:
            raise HTTPException(status_code=404, detail="File not found")
        
        return file_details
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error getting file details: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get file details: {str(e)}")

# Analysis Endpoints
@app.post("/api/analyze/{file_id}")
async def analyze_file(file_id: str):
    """
    Start analysis of an uploaded file
    """
    try:
        # Get file details
        file_details = await file_manager.get_file_details(file_id)
        if not file_details:
            raise HTTPException(status_code=404, detail="File not found")
        
        # Update status to analyzing
        await file_manager.update_analysis_status(file_id, "analyzing")
        
        # Basic analysis (Phase 1 - just file info)
        basic_analysis = {
            "file_id": file_id,
            "filename": file_details["filename"],
            "file_type": file_details["file_type"],
            "file_size": file_details["file_size"],
            "analysis_timestamp": datetime.utcnow().isoformat(),
            "basic_info": {
                "format_detected": file_details["file_type"],
                "size_human": f"{file_details['file_size'] / 1024:.2f} KB",
                "upload_time": file_details.get("upload_timestamp", "Unknown")
            },
            "status": "completed"
        }
        
        # Update analysis result
        await file_manager.update_analysis_result(file_id, basic_analysis)
        
        logger.info(f"🔍 Basic analysis completed for: {file_details['filename']}")
        
        return {
            "message": "Analysis completed",
            "file_id": file_id,
            "status": "completed",
            "analysis": basic_analysis
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Analysis error: {str(e)}")
        await file_manager.update_analysis_status(file_id, "failed")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.get("/api/analysis/{file_id}")
async def get_analysis_results(file_id: str):
    """
    Get analysis results for a file
    """
    try:
        results = await file_manager.get_analysis_results(file_id)
        if not results:
            raise HTTPException(status_code=404, detail="Analysis results not found")
        
        return results
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error getting analysis results: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get analysis results: {str(e)}")

# Case Management Endpoints
@app.get("/api/cases")
async def list_cases():
    """
    List all cases
    """
    try:
        cases = await file_manager.list_cases()
        return {
            "cases": cases,
            "count": len(cases)
        }
    except Exception as e:
        logger.error(f"❌ Error listing cases: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to list cases: {str(e)}")

@app.post("/api/cases")
async def create_case(case_name: str, description: str = ""):
    """
    Create a new case
    """
    try:
        case_id = f"case_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        case = Case(
            case_id=case_id,
            name=case_name,
            description=description,
            created_timestamp=datetime.utcnow(),
            status="active"
        )
        
        await file_manager.create_case(case)
        
        logger.info(f"📋 New case created: {case_name} ({case_id})")
        
        return {
            "message": "Case created successfully",
            "case_id": case_id,
            "name": case_name,
            "status": "active"
        }
        
    except Exception as e:
        logger.error(f"❌ Error creating case: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to create case: {str(e)}")

# Dashboard Endpoints
@app.get("/api/dashboard")
async def get_dashboard_data():
    """
    Get dashboard summary data
    """
    try:
        dashboard_data = await file_manager.get_dashboard_stats()
        return dashboard_data
    except Exception as e:
        logger.error(f"❌ Error getting dashboard data: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get dashboard data: {str(e)}")

# Error handler
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Global exception handler"""
    logger.error(f"❌ Unhandled exception: {str(exc)}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "error": str(exc)}
    )

def main():
    """Run the application"""
    uvicorn.run(
        "main:app",
        host=settings.host,
        port=settings.backend_port,
        reload=settings.debug,
        log_level="info" if settings.debug else "warning"
    )

if __name__ == "__main__":
    main()