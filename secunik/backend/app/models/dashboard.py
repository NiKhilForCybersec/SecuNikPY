"""
Dashboard data models
"""

from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field

class DashboardStats(BaseModel):
    """Dashboard statistics"""
    total_cases: int = 0
    total_files: int = 0
    total_size: int = 0
    total_size_human: str = "0 MB"
    active_analyses: int = 0
    completed_analyses: int = 0
    failed_analyses: int = 0
    high_risk_files: int = 0
    recent_uploads: int = 0
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class RecentActivity(BaseModel):
    """Recent activity item"""
    activity_type: str  # upload, analysis_complete, threat_detected, etc.
    description: str
    timestamp: datetime
    file_id: Optional[str] = None
    case_id: Optional[str] = None
    severity: Optional[str] = "info"  # info, warning, error, success

class DashboardData(BaseModel):
    """Complete dashboard data"""
    stats: DashboardStats
    recent_activities: List[RecentActivity] = Field(default_factory=list)
    threat_summary: Dict[str, int] = Field(default_factory=dict)
    file_type_distribution: Dict[str, int] = Field(default_factory=dict)
    case_status_distribution: Dict[str, int] = Field(default_factory=dict)
