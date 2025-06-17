#!/usr/bin/env python3
"""
SecuNik Import Diagnostics
Diagnoses import issues and provides solutions
"""

import sys
import os
from pathlib import Path

def diagnose_imports():
    """Diagnose import issues"""
    print("🔍 SecuNik Import Diagnostics")
    print("=" * 50)
    
    # Check current directory
    current_dir = Path.cwd()
    print(f"📁 Current directory: {current_dir}")
    
    # Check if we're in the right place
    backend_dir = current_dir if current_dir.name == "backend" else current_dir / "backend"
    if not backend_dir.exists():
        print("❌ Backend directory not found!")
        print("💡 Make sure you're running this from the backend directory or project root")
        return False
    
    print(f"📁 Backend directory: {backend_dir}")
    
    # Check Python path
    print(f"\n🐍 Python path:")
    for i, path in enumerate(sys.path):
        print(f"  {i}: {path}")
    
    # Add backend to path if needed
    if str(backend_dir) not in sys.path:
        sys.path.insert(0, str(backend_dir))
        print(f"✅ Added {backend_dir} to Python path")
    
    # Check critical files
    critical_files = {
        "main.py": backend_dir / "main.py",
        "analysis.py": backend_dir / "app" / "models" / "analysis.py",
        "app __init__": backend_dir / "app" / "__init__.py",
        "models __init__": backend_dir / "app" / "models" / "__init__.py"
    }
    
    print(f"\n📋 Critical files check:")
    missing_files = []
    for name, file_path in critical_files.items():
        if file_path.exists():
            print(f"✅ {name}: {file_path}")
        else:
            print(f"❌ {name}: {file_path} - MISSING!")
            missing_files.append((name, file_path))
    
    # Try imports
    print(f"\n🔧 Testing imports:")
    
    # Test 1: Basic app import
    try:
        os.chdir(backend_dir)
        import app
        print("✅ app package imported successfully")
    except ImportError as e:
        print(f"❌ app package import failed: {e}")
    
    # Test 2: Models import
    try:
        from app.models import analysis
        print("✅ app.models.analysis imported successfully")
    except ImportError as e:
        print(f"❌ app.models.analysis import failed: {e}")
    
    # Test 3: Specific models
    try:
        from app.models.analysis import AnalysisResult, AnalysisStatus
        print("✅ Specific analysis models imported successfully")
    except ImportError as e:
        print(f"❌ Specific analysis models import failed: {e}")
    
    # Provide solutions
    print(f"\n💡 Solutions:")
    if missing_files:
        print("1. Create missing files:")
        for name, file_path in missing_files:
            print(f"   - {file_path}")
        print("   Run the fix_project_structure.py script")
    
    print("2. Ensure you're in the backend directory when running main.py")
    print("3. Check that analysis.py is properly formatted (no syntax errors)")
    print("4. Run: python -c 'from app.models.analysis import AnalysisResult; print(\"Success!\")' to test")
    
    return len(missing_files) == 0

def test_analysis_file():
    """Test if analysis.py file is valid"""
    backend_dir = Path.cwd() if Path.cwd().name == "backend" else Path.cwd() / "backend"
    analysis_file = backend_dir / "app" / "models" / "analysis.py"
    
    if not analysis_file.exists():
        print(f"❌ Analysis file not found: {analysis_file}")
        return False
    
    print(f"🔍 Testing analysis.py file: {analysis_file}")
    
    try:
        # Try to compile the file
        with open(analysis_file, 'r') as f:
            code = f.read()
        
        compile(code, str(analysis_file), 'exec')
        print("✅ analysis.py syntax is valid")
        
        # Try to import it directly
        import importlib.util
        spec = importlib.util.spec_from_file_location("analysis", analysis_file)
        analysis_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(analysis_module)
        
        print("✅ analysis.py imports successfully")
        print(f"📊 Available classes: {[name for name in dir(analysis_module) if not name.startswith('_')]}")
        
        return True
        
    except SyntaxError as e:
        print(f"❌ Syntax error in analysis.py: {e}")
        return False
    except Exception as e:
        print(f"❌ Error importing analysis.py: {e}")
        return False

if __name__ == "__main__":
    success = diagnose_imports()
    test_analysis_file()
    
    if success:
        print("\n✅ Diagnostics passed! Your imports should work.")
        print("🚀 Try running: python main.py")
    else:
        print("\n⚠️  Issues found. Please fix the missing files first.")
        print("🔧 Run the fix_project_structure.py script to auto-fix.")