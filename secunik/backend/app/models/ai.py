"""
AI integration data models
"""

class AIQuery(BaseModel):
    """AI query model"""
    query: str = Field(..., description="Natural language query")
    context: Optional[Dict[str, Any]] = Field(default_factory=dict)
    file_ids: List[str] = Field(default_factory=list)
    case_id: Optional[str] = None
    max_tokens: int = Field(2000, description="Maximum response tokens")

class AIResponse(BaseModel):
    """AI response model"""
    response: str = Field(..., description="AI response text")
    confidence: float = Field(ge=0.0, le=1.0, description="Response confidence")
    sources: List[str] = Field(default_factory=list, description="Data sources used")
    recommendations: List[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    token_usage: Optional[Dict[str, int]] = None

class AIInsight(BaseModel):
    """AI-generated insight"""
    insight_type: str  # threat_assessment, correlation, recommendation, etc.
    title: str
    description: str
    confidence: float = Field(ge=0.0, le=1.0)
    severity: ThreatLevel = ThreatLevel.LOW
    evidence: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=datetime.utcnow)