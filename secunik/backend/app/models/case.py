"""
Case management data models
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum

class CaseStatus(str, Enum):
    """Case status enumeration"""
    ACTIVE = "active"
    CLOSED = "closed"
    ARCHIVED = "archived"
    PENDING = "pending"

class Case(BaseModel):
    """Case data model"""
    case_id: str = Field(..., description="Unique case identifier")
    name: str = Field(..., description="Case name")
    description: Optional[str] = Field("", description="Case description")
    created_timestamp: datetime = Field(default_factory=datetime.utcnow, description="Case creation timestamp")
    updated_timestamp: Optional[datetime] = Field(None, description="Last update timestamp")
    status: CaseStatus = Field(CaseStatus.ACTIVE, description="Case status")
    created_by: Optional[str] = Field("system", description="Case creator")
    tags: List[str] = Field(default_factory=list, description="Case tags")
    priority: Optional[str] = Field("medium", description="Case priority")
    
    class Config:
        json_encoders = {
            datetime: lambda dt: dt.isoformat()
        }

class CaseMetadata(BaseModel):
    """Case metadata for listings"""
    case_id: str
    name: str
    description: str
    created_timestamp: datetime
    status: CaseStatus
    file_count: int = 0
    total_size: int = 0
    last_activity: Optional[datetime] = None