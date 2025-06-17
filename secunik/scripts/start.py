# scripts/start.py
#!/usr/bin/env python3
"""
SecuNik Startup Script
Starts both backend and frontend servers
"""

import subprocess
import sys
import os
import time
import signal
from pathlib import Path
import threading

class SecuNikStarter:
    def __init__(self):
        self.base_path = Path(__file__).parent.parent
        self.backend_process = None
        self.frontend_process = None
        self.running = True
        
    def start_backend(self):
        """Start the FastAPI backend server"""
        print("🚀 Starting SecuNik Backend...")
        
        backend_dir = self.base_path / "backend"
        
        # Check if virtual environment exists
        venv_path = backend_dir / "venv"
        if venv_path.exists():
            if os.name == 'nt':  # Windows
                python_path = venv_path / "Scripts" / "python.exe"
            else:  # Unix/Linux/Mac
                python_path = venv_path / "bin" / "python"
        else:
            python_path = sys.executable
        
        try:
            self.backend_process = subprocess.Popen(
                [str(python_path), "run.py"],
                cwd=backend_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1
            )
            
            # Start thread to read backend output
            threading.Thread(
                target=self._read_process_output,
                args=(self.backend_process, "BACKEND"),
                daemon=True
            ).start()
            
            print("✅ Backend server started successfully")
            return True
            
        except Exception as e:
            print(f"❌ Failed to start backend: {e}")
            return False
    
    def start_frontend(self):
        """Start the Vue.js frontend server"""
        print("🎨 Starting SecuNik Frontend...")
        
        frontend_dir = self.base_path / "frontend"
        
        try:
            # Wait a bit for backend to start
            time.sleep(3)
            
            self.frontend_process = subprocess.Popen(
                ["npm", "run", "dev"],
                cwd=frontend_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1
            )
            
            # Start thread to read frontend output
            threading.Thread(
                target=self._read_process_output,
                args=(self.frontend_process, "FRONTEND"),
                daemon=True
            ).start()
            
            print("✅ Frontend server started successfully")
            return True
            
        except Exception as e:
            print(f"❌ Failed to start frontend: {e}")
            return False
    
    def _read_process_output(self, process, name):
        """Read and display process output"""
        try:
            for line in iter(process.stdout.readline, ''):
                if self.running and line:
                    print(f"[{name}] {line.strip()}")
        except Exception as e:
            if self.running:
                print(f"❌ Error reading {name} output: {e}")
    
    def stop_servers(self):
        """Stop both servers"""
        print("\n🛑 Stopping SecuNik servers...")
        self.running = False
        
        if self.frontend_process:
            try:
                self.frontend_process.terminate()
                self.frontend_process.wait(timeout=5)
                print("✅ Frontend server stopped")
            except Exception as e:
                print(f"⚠️ Error stopping frontend: {e}")
                try:
                    self.frontend_process.kill()
                except:
                    pass
        
        if self.backend_process:
            try:
                self.backend_process.terminate()
                self.backend_process.wait(timeout=5)
                print("✅ Backend server stopped")
            except Exception as e:
                print(f"⚠️ Error stopping backend: {e}")
                try:
                    self.backend_process.kill()
                except:
                    pass
    
    def run(self):
        """Main run method"""
        print("=" * 60)
        print("🔐 SecuNik - Ultimate Cybersecurity Analysis Platform")
        print("=" * 60)
        print()
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, lambda s, f: self.stop_servers())
        signal.signal(signal.SIGTERM, lambda s, f: self.stop_servers())
        
        try:
            # Start backend
            if not self.start_backend():
                return 1
            
            # Start frontend
            if not self.start_frontend():
                self.stop_servers()
                return 1
            
            print()
            print("🎉 SecuNik is now running!")
            print("=" * 40)
            print("📍 Backend API: http://localhost:8000")
            print("📚 API Docs: http://localhost:8000/docs")
            print("🌐 Frontend: http://localhost:3000")
            print("=" * 40)
            print("Press Ctrl+C to stop all servers")
            print()
            
            # Keep the script running
            try:
                while self.running:
                    time.sleep(1)
                    
                    # Check if processes are still running
                    if self.backend_process and self.backend_process.poll() is not None:
                        print("❌ Backend process stopped unexpectedly")
                        break
                    
                    if self.frontend_process and self.frontend_process.poll() is not None:
                        print("❌ Frontend process stopped unexpectedly")
                        break
                        
            except KeyboardInterrupt:
                pass
            
            self.stop_servers()
            return 0
            
        except Exception as e:
            print(f"❌ Startup failed: {e}")
            self.stop_servers()
            return 1

def main():
    starter = SecuNikStarter()
    return starter.run()

if __name__ == "__main__":
    sys.exit(main())