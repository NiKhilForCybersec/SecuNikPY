#!/usr/bin/env python3
"""
SecuNik Frontend Run Script
Starts the Streamlit application with backend connectivity check
"""

import subprocess
import sys
import time
from pathlib import Path

# Try to import requests, but don't fail if not available
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("WARNING: requests library not available - skipping backend check")


def check_backend_connection():
    """Check if backend is running"""
    if not REQUESTS_AVAILABLE:
        return False
        
    try:
        response = requests.get("http://localhost:8000/health", timeout=3)
        if response.status_code == 200:
            data = response.json()
            print(f"SUCCESS: Backend is online (v{data.get('version', 'unknown')})")
            return True
        else:
            print(f"WARNING: Backend responded with status: {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print("WARNING: Backend is not running on localhost:8000")
        return False
    except Exception as e:
        print(f"WARNING: Error checking backend: {e}")
        return False


def wait_for_backend(max_attempts=6):
    """Wait for backend to become available"""
    if not REQUESTS_AVAILABLE:
        print("INFO: Skipping backend check (requests not available)")
        return False
        
    print("INFO: Checking backend connection...")
    
    for attempt in range(max_attempts):
        if check_backend_connection():
            return True
        
        if attempt < max_attempts - 1:
            print(f"INFO: Waiting for backend... (attempt {attempt + 1}/{max_attempts})")
            time.sleep(5)
    
    return False


def main():
    """Start the Streamlit app"""
    app_file = Path(__file__).parent / "app.py"
    
    # Check if app.py exists
    if not app_file.exists():
        print("ERROR: app.py not found!")
        print("INFO: Make sure you're in the frontend_streamlit directory")
        print(f"INFO: Current directory: {Path.cwd()}")
        print(f"INFO: Looking for: {app_file}")
        sys.exit(1)
    
    print("=" * 50)
    print("SecuNik Frontend Startup")
    print("=" * 50)
    
    # Check backend connection
    backend_available = wait_for_backend()
    
    if not backend_available:
        print("\nWARNING: Backend is not responding")
        print("INFO: To start the backend:")
        print("      cd ../backend")
        print("      python run.py")
        print("\nQUESTION: Continue anyway? (y/n): ", end="")
        
        try:
            choice = input().lower().strip()
            if choice not in ['y', 'yes']:
                print("INFO: Startup cancelled.")
                sys.exit(1)
        except KeyboardInterrupt:
            print("\nINFO: Startup cancelled.")
            sys.exit(1)
    
    print("\nINFO: Starting Streamlit application...")
    print("INFO: Frontend URL: http://localhost:8501")
    print("INFO: Backend URL:  http://localhost:8000")
    print("INFO: Press Ctrl+C to stop")
    print("-" * 50)
    
    try:
        # Start Streamlit with basic parameters
        cmd = [
            sys.executable, "-m", "streamlit", "run", str(app_file),
            "--server.port", "8501",
            "--server.address", "localhost"
        ]
        
        # Add optional parameters if they work
        try:
            subprocess.run(cmd + [
                "--server.headless", "true",
                "--browser.gatherUsageStats", "false"
            ])
        except subprocess.CalledProcessError:
            # Fallback to basic command if advanced options fail
            print("INFO: Using basic Streamlit options...")
            subprocess.run(cmd)
            
    except KeyboardInterrupt:
        print("\nINFO: Frontend stopped by user")
    except FileNotFoundError:
        print("\nERROR: Streamlit not found!")
        print("SOLUTION: Install with: pip install streamlit")
        sys.exit(1)
    except Exception as e:
        print(f"\nERROR: Error starting frontend: {e}")
        print("SOLUTION: Check that Streamlit is properly installed")
        print("SOLUTION: Try: pip install --upgrade streamlit")
        sys.exit(1)


if __name__ == "__main__":
    main()