# Create this as: scripts/check-backend.py
"""
Backend Diagnostic Script
Tests if backend components are working
"""

import sys
import os
from pathlib import Path
import subprocess

def check_backend():
    print("SecuNik Backend Diagnostic")
    print("=" * 40)
    
    base_path = Path(__file__).parent.parent
    backend_dir = base_path / "backend"
    
    print(f"Project path: {base_path}")
    print(f"Backend path: {backend_dir}")
    
    # Check directory structure
    print("\n1. Directory Structure:")
    print(f"   backend/ exists: {backend_dir.exists()}")
    print(f"   backend/run.py exists: {(backend_dir / 'run.py').exists()}")
    print(f"   backend/venv/ exists: {(backend_dir / 'venv').exists()}")
    print(f"   backend/app/ exists: {(backend_dir / 'app').exists()}")
    
    # Check virtual environment
    print("\n2. Virtual Environment:")
    venv_dir = backend_dir / "venv"
    if venv_dir.exists():
        if os.name == 'nt':
            python_exe = venv_dir / "Scripts" / "python.exe"
            pip_exe = venv_dir / "Scripts" / "pip.exe"
        else:
            python_exe = venv_dir / "bin" / "python"
            pip_exe = venv_dir / "bin" / "pip"
        
        print(f"   Python executable: {python_exe.exists()}")
        print(f"   Pip executable: {pip_exe.exists()}")
        
        # Test packages
        if python_exe.exists():
            print("\n3. Package Check:")
            packages = ["fastapi", "uvicorn", "aiofiles", "requests"]
            for package in packages:
                try:
                    result = subprocess.run(
                        [str(python_exe), "-c", f"import {package}; print('{package} OK')"],
                        capture_output=True, text=True, timeout=10
                    )
                    if result.returncode == 0:
                        print(f"   ✅ {package}: Installed")
                    else:
                        print(f"   ❌ {package}: Missing")
                except Exception as e:
                    print(f"   ❌ {package}: Error - {e}")
    else:
        print("   ❌ Virtual environment not found")
    
    # Check run.py content
    run_file = backend_dir / "run.py"
    if run_file.exists():
        print(f"\n4. run.py Content (first 10 lines):")
        try:
            content = run_file.read_text(encoding='utf-8')
            lines = content.split('\n')[:10]
            for i, line in enumerate(lines, 1):
                print(f"   {i:2d}: {line}")
        except Exception as e:
            print(f"   ❌ Error reading run.py: {e}")
    
    print(f"\nTo test backend manually:")
    print(f"1. cd {backend_dir}")
    print(f"2. venv\\Scripts\\activate")
    print(f"3. python run.py")

if __name__ == "__main__":
    check_backend()

# ===================================================================