#!/usr/bin/env python3
"""
Test SecuNik Project Structure
Verifies that everything is set up correctly for run.py + app/main.py structure
"""

import sys
from pathlib import Path

def test_project_structure():
    """Test the complete project structure"""
    print("🧪 Testing SecuNik Project Structure")
    print("=" * 50)
    
    # Check current directory
    current_dir = Path.cwd()
    print(f"📁 Current directory: {current_dir}")
    
    # Ensure we're in backend directory
    if not (current_dir / "run.py").exists():
        print("❌ Not in backend directory! Please cd to backend/")
        return False
    
    # Test 1: File structure
    print("\n📋 Test 1: Critical files")
    critical_files = [
        "run.py",
        "app/main.py", 
        "app/__init__.py",
        "app/models/__init__.py",
        "app/models/analysis.py"
    ]
    
    structure_ok = True
    for file_path in critical_files:
        full_path = current_dir / file_path
        if full_path.exists():
            print(f"✅ {file_path}")
        else:
            print(f"❌ {file_path} - MISSING")
            structure_ok = False
    
    if not structure_ok:
        print("💡 Run fix_app_structure.py to create missing files")
        return False
    
    # Test 2: Add app to path like run.py does
    print("\n🐍 Test 2: Path setup")
    app_dir = current_dir / "app"
    if str(app_dir) not in sys.path:
        sys.path.insert(0, str(app_dir))
        print(f"✅ Added {app_dir} to Python path")
    else:
        print(f"✓ {app_dir} already in Python path")
    
    # Test 3: Import analysis models directly
    print("\n📊 Test 3: Direct model imports")
    try:
        from models.analysis import AnalysisResult, AnalysisStatus, Severity
        print("✅ Direct model imports successful")
        
        # Test creating a model instance
        result = AnalysisResult(
            file_path="test.pdf",
            parser_name="test",
            analysis_type="test"
        )
        print(f"✅ Model instance creation successful: {result.parser_name}")
        
    except Exception as e:
        print(f"❌ Direct model imports failed: {e}")
        return False
    
    # Test 4: Import app.main (like run.py does)
    print("\n🚀 Test 4: App import (run.py simulation)")
    try:
        from app.main import app
        print("✅ app.main import successful")
        print(f"✅ FastAPI app object: {type(app)}")
        
    except Exception as e:
        print(f"❌ app.main import failed: {e}")
        return False
    
    # Test 5: Check FastAPI endpoints
    print("\n🌐 Test 5: FastAPI endpoints")
    try:
        routes = [route.path for route in app.routes]
        expected_routes = ["/health", "/", "/api/dashboard"]
        
        for route in expected_routes:
            if route in routes:
                print(f"✅ Route {route} found")
            else:
                print(f"⚠️  Route {route} not found")
        
    except Exception as e:
        print(f"❌ Route check failed: {e}")
        return False
    
    # Test 6: Data directories
    print("\n📁 Test 6: Data directories")
    data_dirs = ["data/uploads", "data/results", "data/temp"]
    for dir_path in data_dirs:
        full_path = current_dir / dir_path
        if full_path.exists():
            print(f"✅ {dir_path}")
        else:
            print(f"⚠️  {dir_path} - will be created at runtime")
    
    return True

def simulate_run_py():
    """Simulate what run.py does"""
    print("\n🎬 Simulating run.py execution...")
    
    current_dir = Path.cwd()
    app_dir = current_dir / "app"
    
    # Add app directory to path (like run.py does)
    if str(app_dir) not in sys.path:
        sys.path.insert(0, str(app_dir))
    
    try:
        # Import the app (like run.py does)
        from app.main import app
        print("✅ run.py simulation successful!")
        print("✅ FastAPI app ready to run")
        
        # Check app configuration
        print(f"📋 App title: {app.title}")
        print(f"📋 App version: {app.version}")
        print(f"📋 Number of routes: {len(app.routes)}")
        
        return True
        
    except Exception as e:
        print(f"❌ run.py simulation failed: {e}")
        return False

if __name__ == "__main__":
    success = test_project_structure()
    
    if success:
        success = simulate_run_py()
    
    print("\n" + "=" * 50)
    if success:
        print("🎉 ALL TESTS PASSED!")
        print("✅ Your project structure is correct")
        print("🚀 Ready to run: python run.py")
        print("🌐 Server will start on: http://localhost:8000")
        print("📚 API docs will be at: http://localhost:8000/docs")
    else:
        print("❌ TESTS FAILED!")
        print("🔧 Run fix_app_structure.py to fix issues")
        print("📝 Ensure analysis.py is in app/models/")
        print("🔄 Then run this test again")