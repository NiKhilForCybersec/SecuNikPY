"""
Dashboard API Router
Provides dashboard data and metrics
"""

import json
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/api", tags=["dashboard"])

# Get backend root directory
current_dir = Path(__file__).parent.parent.parent  # Go up from app/api/ to backend/
RESULTS_DIR = current_dir / "data" / "results"
UPLOAD_DIR = current_dir / "data" / "uploads"

# Ensure directories exist
RESULTS_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

class DashboardStats(BaseModel):
    """Dashboard statistics model"""
    total_files: int
    total_analyses: int
    active_cases: int
    threat_alerts: int
    system_status: str
    recent_activity: List[Dict[str, Any]]

class ThreatTrend(BaseModel):
    """Threat trend data model"""
    date: str
    threat_count: int
    risk_score: float

@router.get("/dashboard")
async def get_dashboard_data():
    """Get main dashboard data"""
    try:
        # Count files and analyses
        total_files = len(list(UPLOAD_DIR.glob("*"))) if UPLOAD_DIR.exists() else 0
        total_analyses = len(list(RESULTS_DIR.glob("*.json"))) if RESULTS_DIR.exists() else 0
        
        # Calculate threat alerts
        threat_alerts = 0
        recent_activity = []
        
        # Process analysis results for metrics
        for result_file in RESULTS_DIR.glob("*.json"):
            try:
                with open(result_file, "r") as f:
                    analysis = json.load(f)
                
                # Count high-risk files as threat alerts
                risk_score = analysis.get("risk_score", 0.0)
                if risk_score > 0.5:
                    threat_alerts += 1
                
                # Add to recent activity
                filename = analysis.get("details", {}).get("original_filename", "unknown")
                timestamp = analysis.get("timestamp", datetime.utcnow().isoformat())
                
                recent_activity.append({
                    "type": "analysis_completed",
                    "filename": filename,
                    "timestamp": timestamp,
                    "severity": analysis.get("severity", "LOW"),
                    "risk_score": risk_score
                })
                
            except Exception as e:
                print(f"Error processing {result_file}: {e}")
                continue
        
        # Sort recent activity by timestamp (newest first) and limit to 10
        recent_activity.sort(key=lambda x: x["timestamp"], reverse=True)
        recent_activity = recent_activity[:10]
        
        # Determine system status
        system_status = "operational"
        if threat_alerts > 5:
            system_status = "alert"
        elif threat_alerts > 0:
            system_status = "warning"
        
        return {
            "total_files": total_files,
            "total_analyses": total_analyses,
            "active_cases": 1,  # Default case
            "threat_alerts": threat_alerts,
            "system_status": system_status,
            "models_status": "available",
            "recent_activity": recent_activity,
            "last_updated": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get dashboard data: {str(e)}")

@router.get("/dashboard/threats")
async def get_threat_dashboard():
    """Get threat-focused dashboard data"""
    try:
        threat_summary = {
            "total_threats": 0,
            "critical_threats": 0,
            "high_threats": 0,
            "medium_threats": 0,
            "low_threats": 0,
            "recent_threats": []
        }
        
        # Process analysis results for threat data
        for result_file in RESULTS_DIR.glob("*.json"):
            try:
                with open(result_file, "r") as f:
                    analysis = json.load(f)
                
                threats = analysis.get("threats_detected", [])
                threat_summary["total_threats"] += len(threats)
                
                # Count by severity
                severity = analysis.get("severity", "LOW")
                if severity == "CRITICAL":
                    threat_summary["critical_threats"] += 1
                elif severity == "HIGH":
                    threat_summary["high_threats"] += 1
                elif severity == "MEDIUM":
                    threat_summary["medium_threats"] += 1
                else:
                    threat_summary["low_threats"] += 1
                
                # Add recent threats
                if threats:
                    filename = analysis.get("details", {}).get("original_filename", "unknown")
                    timestamp = analysis.get("timestamp", datetime.utcnow().isoformat())
                    
                    threat_summary["recent_threats"].append({
                        "filename": filename,
                        "threat_count": len(threats),
                        "severity": severity,
                        "risk_score": analysis.get("risk_score", 0.0),
                        "timestamp": timestamp,
                        "threats": threats[:3]  # Show first 3 threats
                    })
                
            except Exception as e:
                print(f"Error processing threats in {result_file}: {e}")
                continue
        
        # Sort recent threats by risk score (highest first) and limit to 10
        threat_summary["recent_threats"].sort(key=lambda x: x["risk_score"], reverse=True)
        threat_summary["recent_threats"] = threat_summary["recent_threats"][:10]
        
        return threat_summary
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get threat dashboard: {str(e)}")

@router.get("/dashboard/trends")
async def get_trends_data():
    """Get trend data for dashboard charts"""
    try:
        # Generate trend data for the last 7 days
        trends = []
        today = datetime.utcnow().date()
        
        for i in range(7):
            date = today - timedelta(days=i)
            date_str = date.isoformat()
            
            # Count analyses for this date (simplified - in real scenario, would check actual dates)
            daily_count = 0
            daily_risk = 0.0
            risk_scores = []
            
            for result_file in RESULTS_DIR.glob("*.json"):
                try:
                    with open(result_file, "r") as f:
                        analysis = json.load(f)
                    
                    # Simplified date matching (in real scenario, parse timestamp)
                    daily_count += 1
                    risk_score = analysis.get("risk_score", 0.0)
                    risk_scores.append(risk_score)
                    
                except Exception:
                    continue
            
            # Calculate average risk for the day
            if risk_scores:
                daily_risk = sum(risk_scores) / len(risk_scores)
            
            trends.append({
                "date": date_str,
                "analyses_count": daily_count if i == 0 else max(0, daily_count - i),  # Simulate daily distribution
                "threat_count": len([s for s in risk_scores if s > 0.3]) if i == 0 else 0,
                "avg_risk_score": round(daily_risk, 3)
            })
        
        # Reverse to show chronological order
        trends.reverse()
        
        return {
            "trends": trends,
            "period": "7_days"
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get trends: {str(e)}")

@router.get("/dashboard/system")
async def get_system_status():
    """Get system status and health metrics"""
    try:
        # Calculate system metrics
        total_storage_used = 0
        if UPLOAD_DIR.exists():
            for file_path in UPLOAD_DIR.rglob("*"):
                if file_path.is_file():
                    total_storage_used += file_path.stat().st_size
        
        # Convert to MB
        storage_mb = round(total_storage_used / (1024 * 1024), 2)
        
        # Calculate processing metrics
        total_analyses = len(list(RESULTS_DIR.glob("*.json"))) if RESULTS_DIR.exists() else 0
        
        # System health checks
        health_checks = {
            "upload_directory": UPLOAD_DIR.exists() and UPLOAD_DIR.is_dir(),
            "results_directory": RESULTS_DIR.exists() and RESULTS_DIR.is_dir(),
            "storage_available": storage_mb < 1000,  # Less than 1GB used
            "analysis_engine": True  # Always true for basic version
        }
        
        overall_health = all(health_checks.values())
        
        return {
            "system_status": "healthy" if overall_health else "degraded",
            "uptime": "running",  # Simplified
            "storage_used_mb": storage_mb,
            "total_analyses": total_analyses,
            "health_checks": health_checks,
            "last_analysis": datetime.utcnow().isoformat() if total_analyses > 0 else None,
            "version": "1.0.0"
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get system status: {str(e)}")

@router.get("/dashboard/activity")
async def get_recent_activity():
    """Get detailed recent activity"""
    try:
        activities = []
        
        # Get file upload activities
        if UPLOAD_DIR.exists():
            for file_path in UPLOAD_DIR.glob("*"):
                if file_path.is_file():
                    stat = file_path.stat()
                    activities.append({
                        "type": "file_uploaded",
                        "filename": file_path.name,
                        "timestamp": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                        "size": stat.st_size,
                        "status": "completed"
                    })
        
        # Get analysis activities
        for result_file in RESULTS_DIR.glob("*.json"):
            try:
                with open(result_file, "r") as f:
                    analysis = json.load(f)
                
                filename = analysis.get("details", {}).get("original_filename", "unknown")
                timestamp = analysis.get("timestamp", datetime.utcnow().isoformat())
                
                activities.append({
                    "type": "analysis_completed",
                    "filename": filename,
                    "timestamp": timestamp,
                    "severity": analysis.get("severity", "LOW"),
                    "risk_score": analysis.get("risk_score", 0.0),
                    "threat_count": len(analysis.get("threats_detected", [])),
                    "status": "completed"
                })
                
            except Exception:
                continue
        
        # Sort by timestamp (newest first) and limit to 20
        activities.sort(key=lambda x: x["timestamp"], reverse=True)
        activities = activities[:20]
        
        return {
            "activities": activities,
            "total_count": len(activities)
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get activity: {str(e)}")