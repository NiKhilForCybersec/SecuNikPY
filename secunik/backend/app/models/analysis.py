"""
Analysis result data models
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
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

# New severity enumeration used across the AI modules
class Severity(str, Enum):
    """General severity levels"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class IOCType(str, Enum):
    """Indicator of Compromise types"""
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    EMAIL_ADDRESS = "email_address"
    URL = "url"
    FILE_HASH = "file_hash"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    FILE_PATH = "file_path"
    REGISTRY_KEY = "registry_key"
    PROCESS_NAME = "process_name"
    SERVICE_NAME = "service_name"
    USER_AGENT = "user_agent"
    USERNAME = "username"

class IOC(BaseModel):
    """Indicator of Compromise as extracted by parsers"""
    type: IOCType
    value: str
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence score 0-1")
    source: Optional[str] = Field(None, description="Source where IOC was found")
    description: Optional[str] = Field(None, description="Context or description of IOC")
    first_seen: datetime = Field(default_factory=datetime.utcnow)

# Backwards compatibility
IOCIndicator = IOC

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
    """Simplified analysis result used by parsers and AI modules"""
    file_path: str
    parser_name: str
    analysis_type: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    summary: Optional[str] = ""
    details: Dict[str, Any] = Field(default_factory=dict)
    threats_detected: List[Dict[str, Any]] = Field(default_factory=list)
    iocs_found: List[IOC] = Field(default_factory=list)
    severity: Severity = Severity.LOW
    risk_score: float = 0.0
    recommendations: List[str] = Field(default_factory=list)

    class Config:
        json_encoders = {datetime: lambda dt: dt.isoformat()}

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

