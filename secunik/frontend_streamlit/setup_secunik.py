#!/usr/bin/env python3
"""
SecuNik Setup Script
Automated setup for SecuNik development environment
"""

import subprocess
import sys
import os
from pathlib import Path
import platform

class SecuNikSetup:
    def __init__(self):
        self.project_root = Path(__file__).parent
        self.backend_dir = self.project_root / "backend"
        self.frontend_dir = self.project_root / "frontend_streamlit"
        
    def print_banner(self):
        """Print setup banner"""
        print("=" * 60)
        print("🔐 SecuNik Setup - Development Environment")
        print("=" * 60)
        print("🛠️ Automated setup for SecuNik platform")
        print(f"📁 Project root: {self.project_root}")
        print(f"🐍 Python: {sys.executable}")
        print(f"💻 OS: {platform.system()} {platform.release()}")
        print("-" * 60)
    
    def check_python_version(self):
        """Check Python version compatibility"""
        print("🐍 Checking Python version...")
        
        version = sys.version_info
        if version.major < 3 or (version.major == 3 and version.minor < 8):
            print(f"❌ Python {version.major}.{version.minor} detected")
            print("⚠️ SecuNik requires Python 3.8 or higher")
            print("🔧 Please upgrade Python and try again")
            return False
        
        print(f"✅ Python {version.major}.{version.minor}.{version.micro} is compatible")
        return True
    
    def check_pip(self):
        """Check if pip is available"""
        print("📦 Checking pip availability...")
        
        try:
            subprocess.run([sys.executable, "-m", "pip", "--version"], 
                         check=True, capture_output=True)
            print("✅ pip is available")
            return True
        except subprocess.CalledProcessError:
            print("❌ pip is not available")
            print("🔧 Please install pip and try again")
            return False
    
    def create_directories(self):
        """Create necessary directories"""
        print("📁 Creating directory structure...")
        
        directories = [
            self.project_root / "data",
            self.project_root / "data" / "uploads",
            self.project_root / "data" / "results", 
            self.project_root / "data" / "cases",
            self.project_root / "data" / "exports",
            self.project_root / "data" / "temp",
            self.frontend_dir / "logs"
        ]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
            print(f"📂 Created: {directory.relative_to(self.project_root)}")
        
        print("✅ Directory structure created")
    
    def install_backend_deps(self):
        """Install backend dependencies"""
        print("\n🐍 Installing backend dependencies...")
        
        requirements_file = self.backend_dir / "requirements.txt"
        
        if not requirements_file.exists():
            print(f"⚠️ Backend requirements.txt not found: {requirements_file}")
            return False
        
        try:
            cmd = [sys.executable, "-m", "pip", "install", "-r", str(requirements_file)]
            print(f"🚀 Running: {' '.join(cmd)}")
            
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            print("✅ Backend dependencies installed successfully")
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to install backend dependencies: {e}")
            print(f"📋 Error output: {e.stderr}")
            return False
    
    def install_frontend_deps(self):
        """Install frontend dependencies"""
        print("\n🎨 Installing frontend dependencies...")
        
        requirements_file = self.frontend_dir / "requirements.txt"
        
        if not requirements_file.exists():
            print(f"⚠️ Frontend requirements.txt not found: {requirements_file}")
            print("📝 Creating basic requirements.txt...")
            self.create_frontend_requirements()
        
        try:
            cmd = [sys.executable, "-m", "pip", "install", "-r", str(requirements_file)]
            print(f"🚀 Running: {' '.join(cmd)}")
            
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            print("✅ Frontend dependencies installed successfully")
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to install frontend dependencies: {e}")
            print(f"📋 Error output: {e.stderr}")
            return False
    
    def create_frontend_requirements(self):
        """Create frontend requirements.txt if missing"""
        requirements_content = """# SecuNik Frontend Dependencies
streamlit>=1.28.0
plotly>=5.17.0
pandas>=2.1.0
numpy>=1.25.0
requests>=2.31.0
python-dateutil>=2.8.2
pillow>=10.1.0
"""
        
        requirements_file = self.frontend_dir / "requirements.txt"
        with open(requirements_file, "w") as f:
            f.write(requirements_content)
        
        print(f"📝 Created: {requirements_file}")
    
    def install_system_deps(self):
        """Install system dependencies if needed"""
        print("\n🖥️ Checking system dependencies...")
        
        system = platform.system().lower()
        
        if system == "linux":
            print("🐧 Linux detected - checking for libmagic...")
            try:
                import magic
                print("✅ python-magic is working")
            except ImportError:
                print("⚠️ python-magic not working, may need libmagic1")
                print("🔧 Install with: sudo apt-get install libmagic1")
        
        elif system == "windows":
            print("🪟 Windows detected - checking for python-magic...")
            try:
                import magic
                print("✅ python-magic is working")
            except ImportError:
                print("⚠️ python-magic not working")
                print("🔧 Install with: pip install python-magic-bin")
        
        elif system == "darwin":
            print("🍎 macOS detected - checking for libmagic...")
            try:
                import magic
                print("✅ python-magic is working")
            except ImportError:
                print("⚠️ python-magic not working, may need libmagic")
                print("🔧 Install with: brew install libmagic")
        
        print("✅ System dependencies check complete")
    
    def create_env_template(self):
        """Create environment template file"""
        print("\n🔧 Creating environment template...")
        
        env_template = self.project_root / ".env.example"
        env_content = """# SecuNik Environment Variables
# OpenAI API Key (required for AI features)
OPENAI_API_KEY=your-openai-api-key-here

# Backend Configuration  
BACKEND_HOST=localhost
BACKEND_PORT=8000

# Frontend Configuration
FRONTEND_HOST=localhost
FRONTEND_PORT=8501

# Data Directory
DATA_DIR=./data

# Logging Level (DEBUG, INFO, WARNING, ERROR)
LOG_LEVEL=INFO

# Maximum file size for uploads (in MB)
MAX_FILE_SIZE_MB=100

# Analysis timeout (in seconds)
ANALYSIS_TIMEOUT=300
"""
        
        with open(env_template, "w") as f:
            f.write(env_content)
        
        print(f"📝 Created: {env_template}")
        print("💡 Copy .env.example to .env and configure your settings")
    
    def verify_installation(self):
        """Verify the installation"""
        print("\n🔍 Verifying installation...")
        
        # Check backend imports
        print("🐍 Checking backend imports...")
        try:
            sys.path.insert(0, str(self.backend_dir))
            import fastapi
            import uvicorn
            print("✅ Backend core dependencies available")
        except ImportError as e:
            print(f"❌ Backend import error: {e}")
            return False
        
        # Check frontend imports
        print("🎨 Checking frontend imports...")
        try:
            import streamlit
            import plotly
            import pandas
            print("✅ Frontend core dependencies available")
        except ImportError as e:
            print(f"❌ Frontend import error: {e}")
            return False
        
        # Check file structure
        print("📁 Checking file structure...")
        required_files = [
            self.backend_dir / "main.py",
            self.frontend_dir / "app.py"
        ]
        
        for file_path in required_files:
            if file_path.exists():
                print(f"✅ Found: {file_path.relative_to(self.project_root)}")
            else:
                print(f"❌ Missing: {file_path.relative_to(self.project_root)}")
                return False
        
        print("✅ Installation verification complete")
        return True
    
    def print_next_steps(self):
        """Print next steps for user"""
        print("\n" + "=" * 60)
        print("🎉 SecuNik Setup Complete!")
        print("=" * 60)
        print("📋 Next Steps:")
        print("1. 🔑 Configure OpenAI API key (optional):")
        print("   export OPENAI_API_KEY='your-api-key-here'")
        print()
        print("2. 🚀 Start SecuNik:")
        print("   python start_secunik.py")
        print()
        print("3. 🌐 Access the application:")
        print("   Frontend: http://localhost:8501")
        print("   Backend:  http://localhost:8000")
        print()
        print("💡 Tips:")
        print("• Check the documentation for detailed usage instructions")
        print("• Upload test files to verify the analysis pipeline")
        print("• Configure AI features for enhanced threat detection")
        print("=" * 60)
    
    def run(self):
        """Main setup process"""
        try:
            self.print_banner()
            
            # Pre-checks
            if not self.check_python_version():
                return 1
            
            if not self.check_pip():
                return 1
            
            # Setup process
            self.create_directories()
            
            # Install dependencies
            backend_ok = self.install_backend_deps()
            frontend_ok = self.install_frontend_deps()
            
            if not (backend_ok and frontend_ok):
                print("\n❌ Dependency installation failed")
                print("🔧 Please fix the errors above and try again")
                return 1
            
            # Additional setup
            self.install_system_deps()
            self.create_env_template()
            
            # Verification
            if not self.verify_installation():
                print("\n❌ Installation verification failed")
                return 1
            
            self.print_next_steps()
            return 0
            
        except Exception as e:
            print(f"\n❌ Setup failed with error: {e}")
            import traceback
            traceback.print_exc()
            return 1


def main():
    """Main entry point"""
    setup = SecuNikSetup()
    return setup.run()


if __name__ == "__main__":
    sys.exit(main())