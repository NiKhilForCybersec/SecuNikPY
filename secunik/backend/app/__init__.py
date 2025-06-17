"""
SecuNik App Package
Main application package for the SecuNik cybersecurity platform
"""

__version__ = "1.0.0"
__app_name__ = "SecuNik"
__description__ = "Ultimate Local Cybersecurity Analysis Platform"

# Try to import commonly used models
try:
    from .models.analysis import (
        AnalysisStatus,
        ThreatLevel,
        Severity,
        AnalysisResult,
        IOC
    )
    MODELS_AVAILABLE = True
    print("✅ App package: Models imported successfully")
except ImportError as e:
    print(f"⚠️  App package: Could not import models: {e}")
    MODELS_AVAILABLE = False

# Package metadata
__all__ = [
    "__version__",
    "__app_name__", 
    "__description__",
    "MODELS_AVAILABLE"
]

if MODELS_AVAILABLE:
    __all__.extend([
        "AnalysisStatus",
        "ThreatLevel", 
        "Severity",
        "AnalysisResult",
        "IOC"
    ])