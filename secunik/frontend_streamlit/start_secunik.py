#!/usr/bin/env python3
"""
SecuNik Complete Startup Script
Starts both backend and frontend with proper checks
"""

import subprocess
import sys
import time
import os
from pathlib import Path
import threading
import signal

# Try to import requests for backend checking
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

class SecuNikLauncher:
    def __init__(self):
        self.backend_process = None
        self.frontend_process = None
        self.running = True
        
        # Paths
        self.project_root = Path(__file__).parent
        self.backend_dir = self.project_root / "backend"
        self.frontend_dir = self.project_root / "frontend_streamlit"
        
        # Process tracking
        self.processes = []
    
    def print_banner(self):
        """Print SecuNik banner"""
        print("=" * 60)
        print("🔐 SecuNik - Ultimate Local Cybersecurity Analysis Platform")
        print("=" * 60)
        print("🚀 Starting up SecuNik...")
        print(f"📁 Project root: {self.project_root}")
        print(f"🐍 Python: {sys.executable}")
        print("-" * 60)
    
    def check_dependencies(self):
        """Check if required dependencies are installed"""
        print("🔍 Checking dependencies...")
        
        required_backend = [
            "fastapi", "uvicorn", "pydantic", "aiofiles", "python-multipart"
        ]
        
        required_frontend = [
            "streamlit", "plotly", "pandas", "requests"
        ]
        
        missing_backend = []
        missing_frontend = []
        
        # Check backend dependencies
        for package in required_backend:
            try:
                __import__(package.replace("-", "_"))
            except ImportError:
                missing_backend.append(package)
        
        # Check frontend dependencies
        for package in required_frontend:
            try:
                __import__(package)
            except ImportError:
                missing_frontend.append(package)
        
        if missing_backend or missing_frontend:
            print("❌ Missing dependencies found!")
            
            if missing_backend:
                print(f"📋 Backend missing: {', '.join(missing_backend)}")
                print(f"🔧 Install with: cd {self.backend_dir} && pip install -r requirements.txt")
            
            if missing_frontend:
                print(f"📋 Frontend missing: {', '.join(missing_frontend)}")
                print(f"🔧 Install with: cd {self.frontend_dir} && pip install -r requirements.txt")
            
            choice = input("\n❓ Continue anyway? (y/n): ").lower().strip()
            if choice not in ['y', 'yes']:
                print("⏹️ Startup cancelled.")
                sys.exit(1)
        else:
            print("✅ All dependencies available!")
    
    def check_file_structure(self):
        """Check if required files exist"""
        print("📁 Checking file structure...")
        
        required_files = [
            self.backend_dir / "main.py",
            self.backend_dir / "run.py", 
            self.frontend_dir / "app.py",
            self.frontend_dir / "utils" / "api_client.py"
        ]
        
        missing_files = []
        for file_path in required_files:
            if not file_path.exists():
                missing_files.append(str(file_path.relative_to(self.project_root)))
        
        if missing_files:
            print("❌ Missing required files:")
            for file in missing_files:
                print(f"   📄 {file}")
            
            print("\n🔧 Please ensure all required files are present.")
            choice = input("❓ Continue anyway? (y/n): ").lower().strip()
            if choice not in ['y', 'yes']:
                print("⏹️ Startup cancelled.")
                sys.exit(1)
        else:
            print("✅ File structure OK!")
    
    def start_backend(self):
        """Start the backend server"""
        print("\n🐍 Starting backend server...")
        
        if not self.backend_dir.exists():
            print(f"❌ Backend directory not found: {self.backend_dir}")
            return False
        
        try:
            # Try using run.py first, then main.py
            run_py = self.backend_dir / "run.py"
            main_py = self.backend_dir / "main.py"
            
            if run_py.exists():
                cmd = [sys.executable, str(run_py)]
                print(f"🚀 Executing: {' '.join(cmd)}")
            elif main_py.exists():
                cmd = [sys.executable, str(main_py)]
                print(f"🚀 Executing: {' '.join(cmd)}")
            else:
                print("❌ No backend startup script found (run.py or main.py)")
                return False
            
            self.backend_process = subprocess.Popen(
                cmd,
                cwd=self.backend_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1
            )
            
            self.processes.append(self.backend_process)
            
            # Start backend output monitoring thread
            backend_thread = threading.Thread(
                target=self.monitor_backend_output,
                daemon=True
            )
            backend_thread.start()
            
            return True
            
        except Exception as e:
            print(f"❌ Error starting backend: {e}")
            return False
    
    def monitor_backend_output(self):
        """Monitor backend output"""
        if not self.backend_process:
            return
        
        for line in iter(self.backend_process.stdout.readline, ''):
            if not self.running:
                break
            print(f"[BACKEND] {line.strip()}")
    
    def wait_for_backend(self, max_attempts=12, delay=5):
        """Wait for backend to become available"""
        if not REQUESTS_AVAILABLE:
            print("⚠️ Cannot check backend status (requests not available)")
            print(f"⏱️ Waiting {delay * 2} seconds for backend startup...")
            time.sleep(delay * 2)
            return True
        
        print("⏱️ Waiting for backend to start...")
        
        for attempt in range(max_attempts):
            try:
                response = requests.get("http://localhost:8000/health", timeout=3)
                if response.status_code == 200:
                    data = response.json()
                    print(f"✅ Backend online! (v{data.get('version', 'unknown')})")
                    return True
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
                pass
            except Exception as e:
                print(f"⚠️ Backend check error: {e}")
            
            if attempt < max_attempts - 1:
                print(f"⏱️ Backend not ready, waiting... ({attempt + 1}/{max_attempts})")
                time.sleep(delay)
        
        print("⚠️ Backend may not be ready, but continuing...")
        return False
    
    def start_frontend(self):
        """Start the frontend application"""
        print("\n🎨 Starting frontend application...")
        
        if not self.frontend_dir.exists():
            print(f"❌ Frontend directory not found: {self.frontend_dir}")
            return False
        
        app_py = self.frontend_dir / "app.py"
        if not app_py.exists():
            print(f"❌ Frontend app.py not found: {app_py}")
            return False
        
        try:
            cmd = [
                sys.executable, "-m", "streamlit", "run", str(app_py),
                "--server.port", "8501",
                "--server.address", "localhost",
                "--server.headless", "true",
                "--browser.gatherUsageStats", "false"
            ]
            
            print(f"🚀 Executing: {' '.join(cmd)}")
            
            self.frontend_process = subprocess.Popen(
                cmd,
                cwd=self.frontend_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1
            )
            
            self.processes.append(self.frontend_process)
            
            # Start frontend output monitoring thread
            frontend_thread = threading.Thread(
                target=self.monitor_frontend_output,
                daemon=True
            )
            frontend_thread.start()
            
            return True
            
        except Exception as e:
            print(f"❌ Error starting frontend: {e}")
            return False
    
    def monitor_frontend_output(self):
        """Monitor frontend output"""
        if not self.frontend_process:
            return
        
        for line in iter(self.frontend_process.stdout.readline, ''):
            if not self.running:
                break
            print(f"[FRONTEND] {line.strip()}")
    
    def print_access_info(self):
        """Print access information"""
        print("\n" + "=" * 60)
        print("🎉 SecuNik is now running!")
        print("=" * 60)
        print("🌐 Frontend URL:  http://localhost:8501")
        print("🔧 Backend API:   http://localhost:8000")
        print("📚 API Docs:      http://localhost:8000/docs")
        print("-" * 60)
        print("💡 Tips:")
        print("   • Upload files via the frontend interface")
        print("   • Check API documentation for integration")
        print("   • Configure OpenAI API key for AI features")
        print("   • Press Ctrl+C to stop all services")
        print("=" * 60)
    
    def setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown"""
        def signal_handler(signum, frame):
            print("\n⏹️ Shutdown requested...")
            self.shutdown()
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    
    def shutdown(self):
        """Shutdown all processes"""
        print("🛑 Shutting down SecuNik...")
        self.running = False
        
        for process in self.processes:
            if process and process.poll() is None:
                try:
                    process.terminate()
                    # Give process time to terminate gracefully
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
                except Exception as e:
                    print(f"⚠️ Error stopping process: {e}")
        
        print("✅ Shutdown complete!")
    
    def run(self):
        """Main run method"""
        try:
            self.print_banner()
            self.check_dependencies()
            self.check_file_structure()
            self.setup_signal_handlers()
            
            # Start backend
            if not self.start_backend():
                print("❌ Failed to start backend")
                return 1
            
            # Wait for backend to be ready
            backend_ready = self.wait_for_backend()
            
            # Start frontend
            if not self.start_frontend():
                print("❌ Failed to start frontend")
                self.shutdown()
                return 1
            
            # Give frontend time to start
            print("⏱️ Starting frontend interface...")
            time.sleep(3)
            
            self.print_access_info()
            
            # Keep running until interrupted
            try:
                while self.running:
                    time.sleep(1)
                    
                    # Check if processes are still running
                    if self.backend_process and self.backend_process.poll() is not None:
                        print("❌ Backend process died!")
                        break
                    
                    if self.frontend_process and self.frontend_process.poll() is not None:
                        print("❌ Frontend process died!")
                        break
            
            except KeyboardInterrupt:
                print("\n⏹️ Interrupted by user")
            
            self.shutdown()
            return 0
            
        except Exception as e:
            print(f"❌ Unexpected error: {e}")
            self.shutdown()
            return 1


def main():
    """Main entry point"""
    launcher = SecuNikLauncher()
    return launcher.run()


if __name__ == "__main__":
    sys.exit(main())