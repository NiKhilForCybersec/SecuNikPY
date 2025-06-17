"""
Upload API Router
Handles file uploads and processing
"""

import os
import json
import hashlib
from datetime import datetime
from pathlib import Path
from typing import List

from fastapi import APIRouter, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse

# Import models with proper path
try:
    from models.analysis import AnalysisResult, AnalysisStatus, Severity
except ImportError:
    # Fallback models
    from pydantic import BaseModel
    from enum import Enum
    
    class AnalysisStatus(str, Enum):
        UPLOADED = "uploaded"
        COMPLETED = "completed"
    
    class Severity(str, Enum):
        LOW = "LOW"
        MEDIUM = "MEDIUM" 
        HIGH = "HIGH"
        CRITICAL = "CRITICAL"
    
    class AnalysisResult(BaseModel):
        file_path: str
        parser_name: str = "basic"
        analysis_type: str = "upload"
        timestamp: datetime = datetime.utcnow()
        summary: str = ""
        details: dict = {}
        threats_detected: List[dict] = []
        severity: Severity = Severity.LOW
        risk_score: float = 0.0
        recommendations: List[str] = []

router = APIRouter(prefix="/api", tags=["upload"])

# Get backend root directory
current_dir = Path(__file__).parent.parent.parent  # Go up from app/api/ to backend/
UPLOAD_DIR = current_dir / "data" / "uploads"
RESULTS_DIR = current_dir / "data" / "results"

# Ensure directories exist
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

# ... rest of the file remains the same ...

def get_file_hash(file_content: bytes) -> str:
    """Generate SHA256 hash of file content"""
    return hashlib.sha256(file_content).hexdigest()

def analyze_file_basic(file_path: Path, original_filename: str) -> AnalysisResult:
    """Basic file analysis"""
    file_size = file_path.stat().st_size
    file_ext = file_path.suffix.lower()
    
    # Basic analysis based on file type
    analysis_type = "unknown"
    parser_name = "basic"
    summary = f"Uploaded file: {original_filename}"
    threats = []
    risk_score = 0.0
    severity = Severity.LOW
    recommendations = ["File uploaded successfully", "No advanced analysis performed"]
    
    if file_ext in ['.pdf']:
        analysis_type = "document"
        parser_name = "pdf_basic"
        summary = f"PDF document: {original_filename} ({file_size} bytes)"
        
    elif file_ext in ['.zip', '.rar', '.7z']:
        analysis_type = "archive" 
        parser_name = "archive_basic"
        summary = f"Archive file: {original_filename} ({file_size} bytes)"
        risk_score = 0.1  # Archives slightly more risky
        
    elif file_ext in ['.exe', '.dll', '.sys']:
        analysis_type = "executable"
        parser_name = "pe_basic" 
        summary = f"Executable file: {original_filename} ({file_size} bytes)"
        risk_score = 0.3  # Executables more risky
        severity = Severity.MEDIUM
        threats.append({
            "type": "executable_file",
            "description": "Executable file detected - requires careful analysis",
            "severity": "MEDIUM"
        })
        recommendations = [
            "Scan with antivirus",
            "Analyze in isolated environment", 
            "Check file reputation"
        ]
        
    elif file_ext in ['.log', '.txt']:
        analysis_type = "log"
        parser_name = "log_basic"
        summary = f"Log file: {original_filename} ({file_size} bytes)"
        
    return AnalysisResult(
        file_path=str(file_path),
        parser_name=parser_name,
        analysis_type=analysis_type,
        summary=summary,
        details={
            "original_filename": original_filename,
            "file_size": file_size,
            "file_extension": file_ext,
            "upload_timestamp": datetime.utcnow().isoformat()
        },
        threats_detected=threats,
        severity=severity,
        risk_score=risk_score,
        recommendations=recommendations
    )

@router.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    """Upload and analyze a file"""
    try:
        # Read file content
        content = await file.read()
        file_hash = get_file_hash(content)
        
        # Generate unique filename
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"{timestamp}_{file_hash[:8]}_{file.filename}"
        file_path = UPLOAD_DIR / filename
        
        # Save file
        with open(file_path, "wb") as f:
            f.write(content)
        
        # Perform basic analysis
        analysis_result = analyze_file_basic(file_path, file.filename)
        
        # Save analysis result
        result_file = RESULTS_DIR / f"{file_hash}.json"
        with open(result_file, "w") as f:
            json.dump(analysis_result.dict(), f, indent=2, default=str)
        
        return {
            "status": "success",
            "message": "File uploaded and analyzed",
            "file_id": file_hash,
            "filename": file.filename,
            "analysis": analysis_result.dict()
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")

@router.get("/files")
async def list_files():
    """List all uploaded files"""
    try:
        files = []
        for result_file in RESULTS_DIR.glob("*.json"):
            try:
                with open(result_file, "r") as f:
                    analysis = json.load(f)
                    files.append({
                        "file_id": result_file.stem,
                        "filename": analysis.get("details", {}).get("original_filename", "unknown"),
                        "upload_time": analysis.get("timestamp"),
                        "analysis_type": analysis.get("analysis_type"),
                        "risk_score": analysis.get("risk_score", 0.0),
                        "severity": analysis.get("severity", "LOW")
                    })
            except Exception:
                continue
                
        return {"files": files}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list files: {str(e)}")

@router.delete("/files/{file_id}")
async def delete_file(file_id: str):
    """Delete a file and its analysis results"""
    try:
        # Delete analysis result
        result_file = RESULTS_DIR / f"{file_id}.json"
        if result_file.exists():
            result_file.unlink()
        
        # Find and delete uploaded file
        for upload_file in UPLOAD_DIR.glob(f"*{file_id[:8]}*"):
            upload_file.unlink()
            
        return {"status": "success", "message": "File deleted"}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete file: {str(e)}")

@router.get("/files/{file_id}")
async def get_file_analysis(file_id: str):
    """Get analysis results for a specific file"""
    try:
        result_file = RESULTS_DIR / f"{file_id}.json"
        if not result_file.exists():
            raise HTTPException(status_code=404, detail="File not found")
            
        with open(result_file, "r") as f:
            analysis = json.load(f)
            
        return {"file_id": file_id, "analysis": analysis}
        
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="File not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get analysis: {str(e)}")