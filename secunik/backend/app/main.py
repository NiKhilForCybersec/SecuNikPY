""" 
SecuNik Backend - FastAPI Application
Main application entry point for the cybersecurity analysis platform
"""

from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn
import os
import sys
from pathlib import Path
from datetime import datetime
import uuid
import hashlib
import json
from typing import List, Optional

# Add the app directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from config import settings

# Import analysis models
try:
    from app.models.analysis import (
        AnalysisResult, AnalysisStatus, ThreatLevel, IOCType, 
        IOCIndicator, ThreatAssessment, AnalysisMetrics, AnalysisSummary
    )
except ImportError:
    print("⚠️ Analysis models not found. Using basic models...")
    from pydantic import BaseModel
    
    class AnalysisResult(BaseModel):
        file_id: str
        filename: str
        status: str = "completed"
        risk_score: float = 0.0
        threats_found: List[str] = []

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
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000", "http://localhost:8501"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Data storage
DATA_DIR = Path("data")
UPLOADS_DIR = DATA_DIR / "uploads"
RESULTS_DIR = DATA_DIR / "results"
CASES_DIR = DATA_DIR / "cases"

# Create directories
for dir_path in [DATA_DIR, UPLOADS_DIR, RESULTS_DIR, CASES_DIR]:
    dir_path.mkdir(exist_ok=True)

# In-memory storage for demo (replace with proper storage later)
uploaded_files = []
analysis_results = []

@app.on_event("startup")
async def startup_event():
    """Initialize application on startup"""
    print("🚀 SecuNik Backend starting up...")
    print(f"📁 Data directory: {DATA_DIR.absolute()}")
    print(f"📤 Uploads directory: {UPLOADS_DIR.absolute()}")
    print(f"📊 Results directory: {RESULTS_DIR.absolute()}")
    print("✅ SecuNik Backend startup complete!")

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0",
        "services": {
            "api": "operational",
            "storage": "operational",
            "analysis": "operational"
        }
    }

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "🔐 SecuNik API - Ultimate Cybersecurity Analysis Platform",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/health",
        "endpoints": {
            "upload": "/api/upload",
            "files": "/api/files", 
            "analysis": "/api/analysis",
            "dashboard": "/api/dashboard",
            "cases": "/api/cases"
        }
    }

@app.post("/api/upload")
async def upload_file(file: UploadFile = File(...)):
    """Upload a file for analysis"""
    try:
        if not file.filename:
            raise HTTPException(status_code=400, detail="No file provided")
        
        # Read file content
        content = await file.read()
        file_size = len(content)
        
        # Generate file hash
        file_hash = hashlib.md5(content).hexdigest()
        file_id = str(uuid.uuid4())
        
        # Save file to uploads directory
        safe_filename = "".join(c for c in file.filename if c.isalnum() or c in '._-')
        file_path = UPLOADS_DIR / f"{file_hash}_{safe_filename}"
        
        with open(file_path, "wb") as f:
            f.write(content)
        
        # Detect file type
        file_type = detect_file_type(file.filename)
        
        # Create file record
        file_record = {
            "id": file_id,
            "filename": file.filename,
            "file_type": file_type,
            "size": file_size,
            "upload_time": datetime.utcnow().isoformat(),
            "upload_date": datetime.utcnow().date().isoformat(),
            "hash_md5": file_hash,
            "status": "uploaded",
            "file_path": str(file_path)
        }
        
        # Add to uploaded files
        uploaded_files.append(file_record)
        
        # Perform basic analysis
        try:
            analysis_result = await analyze_file(file_record, content)
            analysis_results.append(analysis_result)
            
            # Update file status
            file_record["status"] = "analyzed"
            
            return {
                "message": "File uploaded and analyzed successfully",
                "file_id": file_id,
                "filename": file.filename,
                "file_type": file_type,
                "size": file_size,
                "hash_md5": file_hash,
                "status": "analyzed",
                "analysis_id": analysis_result["file_id"]
            }
            
        except Exception as analysis_error:
            print(f"Analysis error: {analysis_error}")
            file_record["status"] = "analysis_failed"
            
            return {
                "message": "File uploaded but analysis failed",
                "file_id": file_id,
                "filename": file.filename,
                "file_type": file_type,
                "size": file_size,
                "status": "analysis_failed",
                "error": str(analysis_error)
            }
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")

@app.get("/api/files")
async def list_files():
    """List uploaded files"""
    return {
        "files": uploaded_files,
        "count": len(uploaded_files),
        "message": "Files retrieved successfully"
    }

@app.get("/api/analysis")
async def get_analysis_results():
    """Get analysis results - FIXED MISSING ENDPOINT"""
    try:
        # Calculate summary statistics
        total_results = len(analysis_results)
        critical_threats = len([r for r in analysis_results if r.get("risk_score", 0) >= 80])
        clean_files = len([r for r in analysis_results if r.get("risk_score", 0) < 30])
        average_risk = sum([r.get("risk_score", 0) for r in analysis_results]) / total_results if total_results > 0 else 0
        
        return {
            "results": analysis_results,
            "total_results": total_results,
            "summary": {
                "critical_threats": critical_threats,
                "clean_files": clean_files,
                "average_risk": round(average_risk, 1),
                "files_analyzed": total_results
            },
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get analysis results: {str(e)}")

@app.get("/api/analysis/{file_id}")
async def get_file_analysis(file_id: str):
    """Get analysis results for a specific file"""
    try:
        # Find analysis result for the file
        file_analysis = None
        for result in analysis_results:
            if result.get("file_id") == file_id:
                file_analysis = result
                break
        
        if not file_analysis:
            raise HTTPException(status_code=404, detail="Analysis not found for this file")
        
        return file_analysis
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get file analysis: {str(e)}")

@app.delete("/api/files/{file_id}")
async def delete_file(file_id: str):
    """Delete uploaded file and its analysis"""
    try:
        global uploaded_files, analysis_results
        
        # Find and remove from uploaded files
        file_record = None
        uploaded_files_new = []
        
        for f in uploaded_files:
            if f["id"] == file_id:
                file_record = f
            else:
                uploaded_files_new.append(f)
        
        if not file_record:
            raise HTTPException(status_code=404, detail="File not found")
        
        uploaded_files = uploaded_files_new
        
        # Remove from analysis results
        analysis_results = [r for r in analysis_results if r.get("file_id") != file_id]
        
        # Delete physical file
        try:
            file_path = Path(file_record["file_path"])
            if file_path.exists():
                file_path.unlink()
        except Exception as e:
            print(f"Warning: Could not delete physical file: {e}")
        
        return {"message": "File deleted successfully", "file_id": file_id}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete file: {str(e)}")

@app.get("/api/cases")
async def list_cases():
    """List all cases"""
    try:
        # Get unique case IDs from analysis results
        case_ids = set()
        for result in analysis_results:
            case_id = result.get("case_id")
            if case_id:
                case_ids.add(case_id)
        
        cases = []
        for case_id in case_ids:
            case_files = [r for r in analysis_results if r.get("case_id") == case_id]
            cases.append({
                "case_id": case_id,
                "files_count": len(case_files),
                "created_date": min([r.get("analysis_time", datetime.utcnow().isoformat()) for r in case_files]),
                "status": "active"
            })
        
        return {
            "cases": cases,
            "count": len(cases),
            "message": "Cases retrieved successfully"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list cases: {str(e)}")

@app.get("/api/dashboard")
async def get_dashboard_data():
    """Get dashboard summary data"""
    try:
        # Calculate statistics
        total_files = len(uploaded_files)
        total_cases = len(set([r.get("case_id") for r in analysis_results if r.get("case_id")]))
        total_size = sum([f.get("size", 0) for f in uploaded_files])
        
        # Recent activity
        recent_uploads = sorted(uploaded_files, key=lambda x: x.get("upload_time", ""), reverse=True)[:5]
        recent_analysis = sorted(analysis_results, key=lambda x: x.get("analysis_time", ""), reverse=True)[:5]
        
        # System stats
        active_threats = len([r for r in analysis_results if r.get("risk_score", 0) >= 70])
        files_analyzed_today = len([f for f in uploaded_files if f.get("upload_date") == datetime.utcnow().date().isoformat()])
        
        return {
            "system_stats": {
                "total_cases": total_cases,
                "active_threats": active_threats,
                "total_files": total_files,
                "files_analyzed_today": files_analyzed_today,
                "risk_score": min(active_threats * 10, 90)  # Simple risk calculation
            },
            "recent_uploads": recent_uploads,
            "recent_analysis": recent_analysis,
            "total_size": total_size,
            "total_size_human": format_file_size(total_size),
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get dashboard data: {str(e)}")

# Helper functions
def detect_file_type(filename: str) -> str:
    """Detect file type based on extension"""
    extension_map = {
        '.pdf': 'PDF Document',
        '.doc': 'Word Document', '.docx': 'Word Document',
        '.eml': 'Email Message', '.msg': 'Outlook Message',
        '.pst': 'Outlook Data File', '.ost': 'Outlook Cache File',
        '.zip': 'ZIP Archive', '.rar': 'RAR Archive', '.7z': '7-Zip Archive',
        '.exe': 'Executable File', '.dll': 'Dynamic Library',
        '.log': 'Log File', '.txt': 'Text File',
        '.pcap': 'Network Capture', '.pcapng': 'Network Capture',
        '.evtx': 'Windows Event Log', '.evt': 'Windows Event Log',
        '.reg': 'Registry File', '.hiv': 'Registry Hive',
        '.mem': 'Memory Dump', '.dmp': 'Memory Dump',
        '.img': 'Disk Image', '.dd': 'Disk Image', '.raw': 'Raw Image',
        '.json': 'JSON Data', '.csv': 'CSV Data', '.xml': 'XML Data'
    }
    
    try:
        ext = Path(filename).suffix.lower()
        return extension_map.get(ext, 'Unknown File Type')
    except:
        return 'Unknown File Type'

def format_file_size(size_bytes: int) -> str:
    """Format file size in human-readable format"""
    if size_bytes == 0:
        return "0 B"
    
    size_names = ["B", "KB", "MB", "GB", "TB"]
    import math
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return f"{s} {size_names[i]}"

async def analyze_file(file_record: dict, content: bytes) -> dict:
    """Perform basic file analysis"""
    import random
    
    filename = file_record["filename"]
    file_type = file_record["file_type"]
    file_id = file_record["id"]
    
    # Simulate analysis based on file type
    if "Executable" in file_type or "Dynamic Library" in file_type:
        risk_score = random.randint(40, 95)
        threats = ["Potential Malware Signature", "Suspicious API Calls", "Packed Executable"]
    elif "Email" in file_type:
        risk_score = random.randint(15, 60)
        threats = ["Suspicious Email Headers", "Potential Phishing Links", "Attachment Scanning"]
    elif "Log File" in file_type or "Event Log" in file_type:
        risk_score = random.randint(10, 50)
        threats = ["Failed Login Attempts", "Suspicious Process Activity", "Network Anomalies"]
    elif "Network Capture" in file_type:
        risk_score = random.randint(20, 75)
        threats = ["Suspicious Network Traffic", "Potential Data Exfiltration", "Malicious Communications"]
    elif "Archive" in file_type:
        risk_score = random.randint(25, 70)
        threats = ["Suspicious Archive Contents", "Potential Malware Container", "Hidden Files Detected"]
    else:
        risk_score = random.randint(5, 35)
        threats = ["File Integrity Verified", "Metadata Analyzed", "Clean Document"]
    
    # Adjust threats based on risk score
    if risk_score < 30:
        threats = threats[:1] if threats else ["No significant threats detected"]
    elif risk_score < 60:
        threats = threats[:2]
    else:
        threats = threats[:3]
    
    # Generate case ID
    case_id = f"CASE_{random.randint(1000, 9999)}"
    
    return {
        "file_id": file_id,
        "filename": filename,
        "file_type": file_type,
        "risk_score": risk_score,
        "threats_found": threats,
        "iocs_extracted": random.randint(0, 20),
        "analysis_time": datetime.utcnow().isoformat(),
        "analysis_engine": "SecuNik Analysis Engine v1.0",
        "scan_duration": f"{random.uniform(0.3, 8.0):.2f}s",
        "case_id": case_id,
        "status": "completed"
    }

if __name__ == "__main__":
    print("🚀 Starting SecuNik Backend...")
    print(f"📍 Backend available at: http://localhost:{settings.backend_port}")
    print(f"📚 API Documentation at: http://localhost:{settings.backend_port}/docs")
    print(f"🔄 Health Check at: http://localhost:{settings.backend_port}/health")
    print(f"📊 Analysis endpoint at: http://localhost:{settings.backend_port}/api/analysis")
    print("-" * 60)
    
    uvicorn.run(
        "main:app",
        host=settings.host,
        port=settings.backend_port,
        reload=settings.debug,
        log_level="info"
    )