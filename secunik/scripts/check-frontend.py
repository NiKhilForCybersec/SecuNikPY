# Create this as: scripts/check-frontend.py
"""
Frontend Diagnostic Script
Tests if frontend components are working
"""

import sys
import os
from pathlib import Path
import subprocess

def check_frontend():
    print("SecuNik Frontend Diagnostic")
    print("=" * 40)
    
    base_path = Path(__file__).parent.parent
    frontend_dir = base_path / "frontend"
    
    print(f"Project path: {base_path}")
    print(f"Frontend path: {frontend_dir}")
    
    # Check directory structure
    print("\n1. Directory Structure:")
    print(f"   frontend/ exists: {frontend_dir.exists()}")
    print(f"   frontend/serve.py exists: {(frontend_dir / 'serve.py').exists()}")
    print(f"   frontend/package.json exists: {(frontend_dir / 'package.json').exists()}")
    print(f"   frontend/public/ exists: {(frontend_dir / 'public').exists()}")
    print(f"   frontend/public/index.html exists: {(frontend_dir / 'public' / 'index.html').exists()}")
    print(f"   frontend/src/ exists: {(frontend_dir / 'src').exists()}")
    
    # Check Node.js
    print("\n2. Node.js Environment:")
    try:
        result = subprocess.run(["node", "--version"], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"   ✅ Node.js: {result.stdout.strip()}")
        else:
            print(f"   ❌ Node.js: Not working")
    except FileNotFoundError:
        print(f"   ❌ Node.js: Not installed")
    
    try:
        result = subprocess.run(["npm", "--version"], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"   ✅ npm: {result.stdout.strip()}")
        else:
            print(f"   ❌ npm: Not working")
    except FileNotFoundError:
        print(f"   ❌ npm: Not installed")
    
    # Check package.json
    package_file = frontend_dir / "package.json"
    if package_file.exists():
        print(f"\n3. package.json Content:")
        try:
            content = package_file.read_text(encoding='utf-8')
            print(f"   First 200 chars: {content[:200]}...")
        except Exception as e:
            print(f"   ❌ Error reading package.json: {e}")
    
    # Check serve.py
    serve_file = frontend_dir / "serve.py"
    if serve_file.exists():
        print(f"\n4. serve.py exists - can use Python server")
    else:
        print(f"\n4. serve.py missing - need to create it")
    
    print(f"\nFrontend Options:")
    if (frontend_dir / "serve.py").exists():
        print(f"1. Python server: cd {frontend_dir} && python serve.py")
    if (frontend_dir / "package.json").exists():
        print(f"2. npm server: cd {frontend_dir} && npm run dev")
    else:
        print("1. No frontend servers available")

if __name__ == "__main__":
    check_frontend()

# ===================================================================