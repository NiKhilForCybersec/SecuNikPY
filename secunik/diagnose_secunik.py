#!/usr/bin/env python3
"""
SecuNik Diagnostic Script
Run this to verify all components and endpoints are working correctly
"""

import sys
import requests
from pathlib import Path
import importlib.util
import json

def check_frontend_components():
    """Check if all frontend components have the required functions"""
    print("\n🔍 Checking Frontend Components...")
    
    frontend_dir = Path("frontend_streamlit")
    components_dir = frontend_dir / "components"
    
    required_components = {
        "dashboard": "show_dashboard",
        "file_upload": "show_upload_page",
        "analysis": "show_analysis_page",
        "cases": "show_cases_page",
        "settings": "show_settings_page",
        "ai_chat": "show_ai_chat"
    }
    
    all_good = True
    
    for component_name, required_function in required_components.items():
        component_path = components_dir / f"{component_name}.py"
        
        if not component_path.exists():
            print(f"❌ {component_name}.py not found")
            all_good = False
            continue
        
        # Try to load the module and check for the function
        try:
            spec = importlib.util.spec_from_file_location(component_name, component_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            if hasattr(module, required_function):
                print(f"✅ {component_name}.py has {required_function}()")
            else:
                print(f"❌ {component_name}.py missing {required_function}()")
                all_good = False
        except Exception as e:
            print(f"❌ {component_name}.py has import errors: {str(e)}")
            all_good = False
    
    return all_good

def check_backend_endpoints():
    """Check if all backend endpoints are accessible"""
    print("\n🔍 Checking Backend Endpoints...")
    
    base_url = "http://localhost:8000"
    
    endpoints_to_check = [
        ("/health", "GET"),
        ("/api/dashboard", "GET"),
        ("/api/dashboard/threats", "GET"),
        ("/api/dashboard/trends", "GET"),
        ("/api/dashboard/activity", "GET"),
        ("/api/dashboard/system", "GET"),
        ("/api/files", "GET"),
        ("/api/ai/status", "GET"),
    ]
    
    all_good = True
    
    # First check if backend is running
    try:
        response = requests.get(f"{base_url}/health", timeout=2)
        if response.status_code == 200:
            print("✅ Backend is running")
        else:
            print("❌ Backend returned non-200 status")
            return False
    except requests.ConnectionError:
        print("❌ Backend is not running at http://localhost:8000")
        print("   Run: cd backend && python run.py")
        return False
    except Exception as e:
        print(f"❌ Error connecting to backend: {e}")
        return False
    
    # Check each endpoint
    for endpoint, method in endpoints_to_check:
        try:
            if method == "GET":
                response = requests.get(f"{base_url}{endpoint}", timeout=2)
            
            if response.status_code == 200:
                print(f"✅ {endpoint}")
            else:
                print(f"❌ {endpoint} - Status: {response.status_code}")
                all_good = False
        except Exception as e:
            print(f"❌ {endpoint} - Error: {str(e)}")
            all_good = False
    
    return all_good

def check_backend_routers():
    """Check if backend routers are properly configured"""
    print("\n🔍 Checking Backend Router Configuration...")
    
    backend_dir = Path("backend")
    main_file = backend_dir / "app" / "main.py"
    
    if not main_file.exists():
        print("❌ backend/app/main.py not found")
        return False
    
    with open(main_file, 'r') as f:
        content = f.read()
    
    # Check for router imports
    required_imports = [
        "from app.api import upload",
        "from app.api import analysis", 
        "from app.api import dashboard",
        "from app.api import ai"
    ]
    
    # Check for router registration
    required_registrations = [
        "app.include_router(upload.router)",
        "app.include_router(analysis.router)",
        "app.include_router(dashboard.router)",
        "app.include_router(ai.router)"
    ]
    
    all_good = True
    
    for import_line in required_imports:
        if import_line in content:
            print(f"✅ Found import: {import_line}")
        else:
            print(f"❌ Missing import: {import_line}")
            all_good = False
    
    for registration in required_registrations:
        if registration in content:
            print(f"✅ Found registration: {registration}")
        else:
            print(f"❌ Missing registration: {registration}")
            all_good = False
    
    return all_good

def main():
    """Run all diagnostic checks"""
    print("🔧 SecuNik Diagnostic Tool")
    print("=" * 50)
    
    # Check frontend
    frontend_ok = check_frontend_components()
    
    # Check backend configuration
    backend_config_ok = check_backend_routers()
    
    # Check backend endpoints
    backend_endpoints_ok = check_backend_endpoints()
    
    print("\n" + "=" * 50)
    print("📊 Diagnostic Summary:")
    print(f"   Frontend Components: {'✅ OK' if frontend_ok else '❌ Issues Found'}")
    print(f"   Backend Configuration: {'✅ OK' if backend_config_ok else '❌ Issues Found'}")
    print(f"   Backend Endpoints: {'✅ OK' if backend_endpoints_ok else '❌ Issues Found'}")
    
    if frontend_ok and backend_config_ok and backend_endpoints_ok:
        print("\n🎉 All checks passed! SecuNik should be working correctly.")
    else:
        print("\n❌ Issues detected. Please fix the errors above.")
        print("\n💡 Quick fixes:")
        if not frontend_ok:
            print("   - Add missing show_* functions to component files")
        if not backend_config_ok:
            print("   - Add router imports and registrations to backend/app/main.py")
        if not backend_endpoints_ok:
            print("   - Make sure backend is running: cd backend && python run.py")

if __name__ == "__main__":
    main()