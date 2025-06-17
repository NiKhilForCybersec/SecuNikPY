"""
Analysis result data models
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any, Union
from datetime import datetime
from enum import Enum

class AnalysisStatus(str, Enum):
    """Analysis status enumeration"""
    UPLOADED = "uploaded"
    QUEUED = "queued"
    ANALYZING = "analyzing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class ThreatLevel(str, Enum):
    """Threat level enumeration"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class IOCType(str, Enum):
    """Indicator of Compromise types"""
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    EMAIL = "email"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    FILE_PATH = "file_path"
    REGISTRY_KEY = "registry_key"
    PROCESS_NAME = "process_name"
    SERVICE_NAME = "service_name"
    USER_AGENT = "user_agent"
    USERNAME = "username"

class IOCIndicator(BaseModel):
    """Individual IOC indicator"""
    type: IOCType
    value: str
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence score 0-1")
    context: Optional[str] = Field(None, description="Context where IOC was found")
    threat_level: ThreatLevel = ThreatLevel.LOW
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    source: Optional[str] = Field(None, description="Source of the IOC")

class BasicFileInfo(BaseModel):
    """Basic file information"""
    filename: str
    file_size: int
    file_type: str
    file_hash: Optional[str] = None
    upload_timestamp: datetime
    analysis_timestamp: Optional[datetime] = None

class ThreatAssessment(BaseModel):
    """Threat assessment results"""
    overall_threat_level: ThreatLevel = ThreatLevel.LOW
    risk_score: float = Field(ge=0.0, le=1.0, description="Risk score 0-1")
    threat_indicators: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0, description="Assessment confidence")

class AnalysisMetrics(BaseModel):
    """Analysis performance metrics"""
    analysis_duration: Optional[float] = Field(None, description="Analysis duration in seconds")
    parser_used: Optional[str] = Field(None, description="Primary parser used")
    ai_analysis_used: bool = False
    iocs_extracted: int = 0
    threats_detected: int = 0

class AnalysisResult(BaseModel):
    """Complete analysis result"""
    # Identification
    file_id: str = Field(..., description="Unique file identifier")
    case_id: str = Field(..., description="Associated case ID")
    
    # File information
    filename: str
    file_type: str
    file_size: int
    file_path: Optional[str] = None
    file_hash: Optional[str] = None
    
    # Timestamps
    upload_timestamp: datetime = Field(default_factory=datetime.utcnow)
    analysis_start: Optional[datetime] = None
    analysis_end: Optional[datetime] = None
    
    # Status
    status: AnalysisStatus = AnalysisStatus.UPLOADED
    error_message: Optional[str] = None
    
    # Analysis results
    basic_info: Optional[Dict[str, Any]] = Field(default_factory=dict)
    iocs: List[IOCIndicator] = Field(default_factory=list)
    threat_assessment: Optional[ThreatAssessment] = None
    
    # Detailed analysis data
    parser_results: Dict[str, Any] = Field(default_factory=dict)
    ai_insights: Optional[Dict[str, Any]] = None
    correlations: List[str] = Field(default_factory=list)
    
    # Metrics
    metrics: Optional[AnalysisMetrics] = None
    
    # Additional data
    tags: List[str] = Field(default_factory=list)
    notes: Optional[str] = None
    
    class Config:
        json_encoders = {
            datetime: lambda dt: dt.isoformat()
        }

class AnalysisSummary(BaseModel):
    """Analysis summary for dashboards"""
    file_id: str
    case_id: str
    filename: str
    status: AnalysisStatus
    threat_level: ThreatLevel
    risk_score: float
    ioc_count: int
    analysis_timestamp: Optional[datetime]