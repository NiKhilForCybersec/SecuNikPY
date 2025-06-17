#!/usr/bin/env python3
"""
SecuNik App Structure Fixer
Fixes the structure for the run.py + app/main.py setup
"""

import os
from pathlib import Path

def create_app_structure():
    """Create the proper app structure"""
    
    # Get the backend directory (where this script should be run from)
    backend_dir = Path.cwd()
    print(f"🔧 Working in backend directory: {backend_dir}")
    
    # Check if we're in the right place
    if not (backend_dir / "run.py").exists():
        print("❌ run.py not found! Make sure you're in the backend directory.")
        return False
    
    # Directories that need __init__.py files
    init_dirs = [
        "app",
        "app/models", 
        "app/api",
        "app/core",
        "app/core/analysis",
        "app/core/ai",
        "app/core/parsers",
        "app/core/parsers/base",
        "app/core/parsers/log_forensics",
        "app/core/parsers/log_forensics/windows_logs",
        "app/core/parsers/network_forensics",
        "app/core/parsers/email_forensics",
        "app/core/parsers/document_forensics",
        "app/core/parsers/archive_forensics",
        "app/core/parsers/registry_forensics",
        "app/core/parsers/malware_analysis",
        "app/services",
        "app/utils"
    ]
    
    # Create directories and __init__.py files
    for dir_path in init_dirs:
        full_path = backend_dir / dir_path
        
        # Create directory if it doesn't exist
        full_path.mkdir(parents=True, exist_ok=True)
        print(f"📁 Created directory: {dir_path}")
        
        # Create __init__.py if it doesn't exist
        init_file = full_path / "__init__.py"
        if not init_file.exists():
            init_file.write_text(f'"""{dir_path.replace("/", ".")} package"""\n')
            print(f"✅ Created: {dir_path}/__init__.py")
        else:
            print(f"✓ Exists: {dir_path}/__init__.py")
    
    # Create data directories
    data_dirs = [
        "data",
        "data/uploads",
        "data/results", 
        "data/cases",
        "data/exports",
        "data/temp"
    ]
    
    for dir_path in data_dirs:
        full_path = backend_dir / dir_path
        full_path.mkdir(parents=True, exist_ok=True)
        print(f"📁 Created data directory: {dir_path}")
    
    return True

def create_models_init():
    """Create proper models/__init__.py for the app structure"""
    backend_dir = Path.cwd()
    models_init = backend_dir / "app" / "models" / "__init__.py"
    
    init_content = '''"""
Models package initialization
Exports all analysis models for easy import
"""

try:
    from .analysis import (
        AnalysisStatus,
        ThreatLevel, 
        Severity,
        IOCType,
        IOC,
        IOCIndicator,  # Backwards compatibility
        BasicFileInfo,
        ThreatAssessment,
        AnalysisMetrics,
        AnalysisResult,
        AnalysisSummary
    )
    
    __all__ = [
        "AnalysisStatus",
        "ThreatLevel",
        "Severity", 
        "IOCType",
        "IOC",
        "IOCIndicator",
        "BasicFileInfo",
        "ThreatAssessment", 
        "AnalysisMetrics",
        "AnalysisResult",
        "AnalysisSummary"
    ]
    
    print("✅ Models imported successfully in __init__.py")
    
except ImportError as e:
    print(f"⚠️  Could not import models in __init__.py: {e}")
    __all__ = []

__version__ = "1.0.0"
'''
    
    models_init.write_text(init_content)
    print(f"✅ Created models/__init__.py")

def check_structure():
    """Check if the structure is correct"""
    backend_dir = Path.cwd()
    
    critical_files = [
        "run.py",
        "app/main.py",
        "app/__init__.py",
        "app/models/__init__.py",
        "app/models/analysis.py"
    ]
    
    print("\n🔍 Checking critical files:")
    all_good = True
    for file_path in critical_files:
        full_path = backend_dir / file_path
        if full_path.exists():
            print(f"✅ {file_path}")
        else:
            print(f"❌ {file_path} - MISSING!")
            all_good = False
    
    return all_good

def test_imports():
    """Test if imports work correctly"""
    print("\n🧪 Testing imports:")
    
    backend_dir = Path.cwd()
    app_dir = backend_dir / "app"
    
    # Add app to path like run.py does
    import sys
    if str(app_dir) not in sys.path:
        sys.path.insert(0, str(app_dir))
    
    try:
        # Test importing the app
        from app.main import app
        print("✅ Successfully imported app from app.main")
        
        # Test importing models
        from models.analysis import AnalysisResult
        print("✅ Successfully imported AnalysisResult from models.analysis")
        
        return True
        
    except ImportError as e:
        print(f"❌ Import test failed: {e}")
        return False

if __name__ == "__main__":
    print("🚀 SecuNik App Structure Fixer")
    print("=" * 50)
    
    if not create_app_structure():
        print("❌ Failed to create structure")
        exit(1)
    
    create_models_init()
    
    if check_structure():
        print("\n✅ All critical files present!")
        
        if test_imports():
            print("✅ Import tests passed!")
            print("\n🎯 Structure is ready!")
            print("💡 Now run: python run.py")
        else:
            print("❌ Import tests failed")
            print("💡 Check that analysis.py is in app/models/ and is valid Python")
    else:
        print("\n⚠️  Some critical files are missing")
        print("💡 Please ensure you have:")
        print("   - app/main.py (use the fixed version)")
        print("   - app/models/analysis.py (your existing file)")