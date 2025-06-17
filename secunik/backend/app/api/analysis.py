"""
Analysis API Router
Handles analysis operations and results
"""

import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

# Import models with fallback
try:
    from models.analysis import AnalysisResult, AnalysisStatus, Severity
except ImportError:
    # Fallback models
    from pydantic import BaseModel
    from enum import Enum
    
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

router = APIRouter(prefix="/api", tags=["analysis"])

# Get backend root directory
current_dir = Path(__file__).parent.parent.parent  # Go up from app/api/ to backend/
RESULTS_DIR = current_dir / "data" / "results"
UPLOAD_DIR = current_dir / "data" / "uploads"

# Ensure directories exist
RESULTS_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

class AnalysisRequest(BaseModel):
    """Request model for analysis operations"""
    file_id: str
    analysis_type: Optional[str] = "standard"
    options: Dict[str, Any] = {}

class AnalysisSummary(BaseModel):
    """Summary model for analysis results"""
    file_id: str
    filename: str
    status: AnalysisStatus
    analysis_type: str
    severity: Severity
    risk_score: float
    threat_count: int
    timestamp: datetime

@router.get("/analysis")
async def get_all_analyses():
    """Get all analysis results summary"""
    try:
        analyses = []
        
        for result_file in RESULTS_DIR.glob("*.json"):
            try:
                with open(result_file, "r") as f:
                    analysis = json.load(f)
                    
                analyses.append({
                    "file_id": result_file.stem,
                    "filename": analysis.get("details", {}).get("original_filename", "unknown"),
                    "status": "completed",
                    "analysis_type": analysis.get("analysis_type", "unknown"),
                    "severity": analysis.get("severity", "LOW"),
                    "risk_score": analysis.get("risk_score", 0.0),
                    "threat_count": len(analysis.get("threats_detected", [])),
                    "timestamp": analysis.get("timestamp", datetime.utcnow().isoformat()),
                    "parser_name": analysis.get("parser_name", "unknown"),
                    "summary": analysis.get("summary", "")
                })
            except Exception as e:
                print(f"Error reading analysis file {result_file}: {e}")
                continue
        
        # Sort by timestamp, newest first
        analyses.sort(key=lambda x: x["timestamp"], reverse=True)
        
        return {
            "total_analyses": len(analyses),
            "analyses": analyses
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get analyses: {str(e)}")

@router.get("/analysis/{file_id}")
async def get_analysis(file_id: str):
    """Get detailed analysis results for a specific file"""
    try:
        result_file = RESULTS_DIR / f"{file_id}.json"
        
        if not result_file.exists():
            raise HTTPException(status_code=404, detail="Analysis not found")
        
        with open(result_file, "r") as f:
            analysis = json.load(f)
        
        return {
            "file_id": file_id,
            "analysis": analysis,
            "status": "completed"
        }
        
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Analysis not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get analysis: {str(e)}")

@router.post("/analysis/{file_id}/reanalyze")
async def reanalyze_file(file_id: str, request: AnalysisRequest):
    """Reanalyze a file with different parameters"""
    try:
        # Check if file exists
        result_file = RESULTS_DIR / f"{file_id}.json"
        if not result_file.exists():
            raise HTTPException(status_code=404, detail="File not found")
        
        # Load existing analysis
        with open(result_file, "r") as f:
            existing_analysis = json.load(f)
        
        # Update analysis with new parameters
        updated_analysis = existing_analysis.copy()
        updated_analysis.update({
            "reanalyzed_at": datetime.utcnow().isoformat(),
            "analysis_type": request.analysis_type,
            "reanalysis_options": request.options
        })
        
        # Save updated analysis
        with open(result_file, "w") as f:
            json.dump(updated_analysis, f, indent=2, default=str)
        
        return {
            "status": "success",
            "message": "File reanalyzed",
            "file_id": file_id,
            "analysis": updated_analysis
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Reanalysis failed: {str(e)}")

@router.get("/analysis/stats/summary")
async def get_analysis_stats():
    """Get analysis statistics summary"""
    try:
        total_files = 0
        by_severity = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        by_type = {}
        total_threats = 0
        avg_risk_score = 0.0
        risk_scores = []
        
        for result_file in RESULTS_DIR.glob("*.json"):
            try:
                with open(result_file, "r") as f:
                    analysis = json.load(f)
                    
                total_files += 1
                
                # Count by severity
                severity = analysis.get("severity", "LOW")
                if severity in by_severity:
                    by_severity[severity] += 1
                
                # Count by analysis type
                analysis_type = analysis.get("analysis_type", "unknown")
                by_type[analysis_type] = by_type.get(analysis_type, 0) + 1
                
                # Count threats
                threats = analysis.get("threats_detected", [])
                total_threats += len(threats)
                
                # Collect risk scores
                risk_score = analysis.get("risk_score", 0.0)
                risk_scores.append(risk_score)
                
            except Exception:
                continue
        
        # Calculate average risk score
        if risk_scores:
            avg_risk_score = sum(risk_scores) / len(risk_scores)
        
        return {
            "total_files": total_files,
            "total_threats": total_threats,
            "average_risk_score": round(avg_risk_score, 3),
            "by_severity": by_severity,
            "by_analysis_type": by_type,
            "high_risk_files": sum(1 for score in risk_scores if score > 0.7),
            "clean_files": sum(1 for score in risk_scores if score == 0.0)
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get stats: {str(e)}")

@router.get("/analysis/{file_id}/threats")
async def get_file_threats(file_id: str):
    """Get threats detected in a specific file"""
    try:
        result_file = RESULTS_DIR / f"{file_id}.json"
        
        if not result_file.exists():
            raise HTTPException(status_code=404, detail="Analysis not found")
        
        with open(result_file, "r") as f:
            analysis = json.load(f)
        
        threats = analysis.get("threats_detected", [])
        
        return {
            "file_id": file_id,
            "threat_count": len(threats),
            "threats": threats,
            "severity": analysis.get("severity", "LOW"),
            "risk_score": analysis.get("risk_score", 0.0)
        }
        
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Analysis not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get threats: {str(e)}")

@router.get("/analysis/{file_id}/recommendations")
async def get_file_recommendations(file_id: str):
    """Get recommendations for a specific file"""
    try:
        result_file = RESULTS_DIR / f"{file_id}.json"
        
        if not result_file.exists():
            raise HTTPException(status_code=404, detail="Analysis not found")
        
        with open(result_file, "r") as f:
            analysis = json.load(f)
        
        recommendations = analysis.get("recommendations", [])
        
        return {
            "file_id": file_id,
            "recommendations": recommendations,
            "priority": "high" if analysis.get("risk_score", 0.0) > 0.5 else "normal"
        }
        
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Analysis not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get recommendations: {str(e)}")