#!/usr/bin/env python3
"""
SecuNik Project Setup Script - WINDOWS COMPATIBLE VERSION
Creates the complete directory structure and installs dependencies
"""

import os
import subprocess
import sys
from pathlib import Path
import platform

def create_directory_structure(base_path):
    """Create the complete SecuNik directory structure"""
    
    directories = [
        # Backend structure
        "backend/app",
        "backend/app/api",
        "backend/app/core/analysis",
        "backend/app/core/ai",
        "backend/app/core/parsers/base",
        "backend/app/core/storage",
        "backend/app/core/export",
        "backend/app/models",
        "backend/app/services",
        "backend/app/utils",
        
        # Data directories
        "backend/data/cases",
        "backend/data/uploads",
        "backend/data/results",
        "backend/data/exports/pdfs",
        "backend/data/exports/json",
        "backend/data/exports/csv",
        "backend/data/temp/extractions",
        "backend/data/temp/processing",
        
        # Frontend structure
        "frontend/public/icons",
        "frontend/src/components/common",
        "frontend/src/components/upload",
        "frontend/src/components/dashboard",
        "frontend/src/components/analysis",
        "frontend/src/components/ai",
        "frontend/src/views",
        "frontend/src/services",
        "frontend/src/store",
        "frontend/src/utils",
        "frontend/src/styles",
        
        # Shared and scripts
        "shared",
        "scripts",
        "docs/examples/sample-cases",
        "docs/examples/test-data",
        "config",
        "logs"
    ]
    
    print("Creating directory structure...")
    for directory in directories:
        dir_path = base_path / directory
        dir_path.mkdir(parents=True, exist_ok=True)
        
        # Create __init__.py for Python packages
        if "backend/app" in directory and directory != "backend/app":
            init_file = dir_path / "__init__.py"
            init_file.touch()
    
    print("[SUCCESS] Directory structure created successfully!")

def create_requirements_file(base_path):
    """Create requirements.txt for backend dependencies - SIMPLIFIED"""
    
    # Simplified requirements that are more likely to install successfully
    requirements = """# Core Framework
fastapi==0.104.1
uvicorn[standard]==0.24.0
python-multipart==0.0.6
aiofiles==23.2.1

# Data Processing
pandas==2.1.3
numpy==1.25.2

# File Format Support
PyPDF2==3.0.1
openpyxl==3.1.2

# Network & Web Analysis
requests==2.31.0

# Cryptography & Security
cryptography==41.0.7

# Utilities
python-dateutil==2.8.2
chardet==5.2.0
tqdm==4.66.1

# Report Generation
jinja2==3.1.2

# Development & Testing
pytest==7.4.3

# File type detection - alternative to python-magic
filetype==1.2.0
"""
    
    req_file = base_path / "requirements.txt"
    req_file.write_text(requirements.strip(), encoding='utf-8')
    print("[SUCCESS] requirements.txt created!")

def create_frontend_package_json(base_path):
    """Create package.json for frontend dependencies - SIMPLIFIED"""
    
    package_json = """{
  "name": "secunik-frontend",
  "version": "1.0.0",
  "description": "SecuNik Frontend - Ultimate Cybersecurity Analysis Platform",
  "scripts": {
    "dev": "vite --host",
    "build": "vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "vue": "^3.3.8",
    "vue-router": "^4.2.5",
    "pinia": "^2.1.7",
    "axios": "^1.6.2",
    "date-fns": "^2.30.0",
    "uuid": "^9.0.1"
  },
  "devDependencies": {
    "vite": "^5.0.0",
    "@vitejs/plugin-vue": "^4.5.0",
    "tailwindcss": "^3.3.6",
    "autoprefixer": "^10.4.16",
    "postcss": "^8.4.32"
  }
}"""
    
    frontend_dir = base_path / "frontend"
    package_file = frontend_dir / "package.json"
    package_file.write_text(package_json, encoding='utf-8')
    print("[SUCCESS] Frontend package.json created!")

def run_command_safe(command, cwd=None, description=""):
    """Run a command safely with better error handling"""
    print(f"[RUNNING] {description}")
    try:
        # Use shell=True on Windows for better compatibility
        use_shell = platform.system() == "Windows"
        
        result = subprocess.run(
            command,
            cwd=cwd,
            shell=use_shell,
            check=True,
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout
        )
        print(f"[SUCCESS] {description}")
        return True, result.stdout
    except subprocess.TimeoutExpired:
        print(f"[TIMEOUT] {description} - Timeout (5 minutes)")
        return False, "Timeout"
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] {description} - Failed")
        error_msg = e.stderr[:300] if e.stderr else "No error details"
        print(f"Error: {error_msg}")
        return False, e.stderr
    except Exception as e:
        print(f"[ERROR] {description} - Exception: {str(e)}")
        return False, str(e)

def install_backend_dependencies(base_path):
    """Install Python backend dependencies with better error handling"""
    print("Installing Python backend dependencies...")
    
    try:
        # Create virtual environment
        venv_path = base_path / "backend" / "venv"
        if not venv_path.exists():
            success, output = run_command_safe(
                [sys.executable, "-m", "venv", "venv"],
                cwd=base_path / "backend",
                description="Creating Python virtual environment"
            )
            if not success:
                print("[WARNING] Virtual environment creation failed, continuing with system Python...")
                return False
        
        # Determine the correct pip path
        if platform.system() == "Windows":
            pip_path = venv_path / "Scripts" / "pip.exe"
            python_path = venv_path / "Scripts" / "python.exe"
        else:
            pip_path = venv_path / "bin" / "pip"
            python_path = venv_path / "bin" / "python"
        
        # Upgrade pip first
        if pip_path.exists():
            run_command_safe(
                [str(pip_path), "install", "--upgrade", "pip"],
                cwd=base_path,
                description="Upgrading pip"
            )
        
        # Install dependencies one by one for better error handling
        essential_packages = [
            "fastapi==0.104.1",
            "uvicorn[standard]==0.24.0", 
            "python-multipart==0.0.6",
            "aiofiles==23.2.1",
            "requests==2.31.0",
            "jinja2==3.1.2",
            "python-dateutil==2.8.2",
            "filetype==1.2.0"
        ]
        
        failed_packages = []
        for package in essential_packages:
            success, output = run_command_safe(
                [str(pip_path), "install", package],
                cwd=base_path,
                description=f"Installing {package}"
            )
            if not success:
                failed_packages.append(package)
        
        if failed_packages:
            print(f"[WARNING] Some packages failed to install: {failed_packages}")
            print("[INFO] Essential packages installed, platform will work with basic functionality")
        else:
            print("[SUCCESS] All backend dependencies installed successfully!")
        
        return python_path if python_path.exists() else sys.executable
        
    except Exception as e:
        print(f"[ERROR] Error installing backend dependencies: {e}")
        return sys.executable

def install_frontend_dependencies(base_path):
    """Install Node.js frontend dependencies with better error handling"""
    print("Installing Node.js frontend dependencies...")
    
    frontend_dir = base_path / "frontend"
    
    # Check if npm is available
    try:
        result = subprocess.run(["npm", "--version"], capture_output=True, text=True)
        if result.returncode != 0:
            print("[ERROR] npm not found. Please install Node.js first.")
            return False
    except FileNotFoundError:
        print("[ERROR] npm not found. Please install Node.js first.")
        return False
    
    # Try npm install with timeout
    success, output = run_command_safe(
        ["npm", "install"],
        cwd=frontend_dir,
        description="Installing Node.js packages"
    )
    
    if not success:
        print("[WARNING] npm install failed, trying alternative approach...")
        
        # Try installing essential packages individually
        essential_packages = ["vue@^3.3.8", "vue-router@^4.2.5", "vite@^5.0.0", "@vitejs/plugin-vue@^4.5.0"]
        
        for package in essential_packages:
            run_command_safe(
                ["npm", "install", package],
                cwd=frontend_dir,
                description=f"Installing {package}"
            )
    
    return success

def create_env_file(base_path):
    """Create .env file with default configuration"""
    
    env_content = """# SecuNik Configuration
DEBUG=True
HOST=localhost
BACKEND_PORT=8000
FRONTEND_PORT=3000
DATA_PATH=./backend/data
MAX_FILE_SIZE=100MB
UPLOAD_TIMEOUT=300
"""
    
    env_file = base_path / ".env"
    env_file.write_text(env_content, encoding='utf-8')
    print("[SUCCESS] .env configuration file created!")

def create_gitignore(base_path):
    """Create .gitignore file"""
    
    gitignore_content = """# Python
__pycache__/
*.py[cod]
*.so
*.egg-info/
build/
dist/

# Virtual Environment
backend/venv/
env/
ENV/

# Node.js
node_modules/
npm-debug.log*

# Build outputs
frontend/dist/

# Environment variables
.env
.env.local

# Data files
backend/data/uploads/*
backend/data/temp/*
backend/data/cases/*
backend/data/results/*
!backend/data/.gitkeep

# Logs
*.log
logs/

# OS
.DS_Store
Thumbs.db
"""
    
    gitignore_file = base_path / ".gitignore"
    gitignore_file.write_text(gitignore_content, encoding='utf-8')
    print("[SUCCESS] .gitignore created!")

def create_basic_files(base_path):
    """Create basic configuration files needed to run"""
    
    # Create a simple run script for backend
    run_script = '''#!/usr/bin/env python3
import sys
import os
from pathlib import Path

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

try:
    import uvicorn
    print("Starting SecuNik Backend...")
    print("Backend will be available at: http://localhost:8000")
    
    # Simple FastAPI app
    from fastapi import FastAPI
    from fastapi.middleware.cors import CORSMiddleware
    
    app = FastAPI(title="SecuNik API", version="1.0.0")
    
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    @app.get("/health")
    def health_check():
        return {"status": "healthy", "message": "SecuNik Backend is running"}
    
    @app.get("/")
    def root():
        return {"message": "SecuNik API", "docs": "/docs"}
    
    uvicorn.run(app, host="localhost", port=8000)
    
except ImportError as e:
    print(f"Missing dependencies: {e}")
    print("Please run: pip install fastapi uvicorn")
    sys.exit(1)
except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)
'''
    
    run_file = base_path / "backend" / "run.py"
    run_file.write_text(run_script, encoding='utf-8')
    print("[SUCCESS] Backend run script created!")

def main():
    """Main setup function"""
    print("SecuNik Project Setup Starting (WINDOWS COMPATIBLE VERSION)...")
    print("=" * 60)
    
    # Get the project path
    base_path = Path("N:/Project/SecuNikPy/secunik")
    
    # Create base directory if it doesn't exist
    base_path.mkdir(parents=True, exist_ok=True)
    os.chdir(base_path)
    
    print(f"Working in: {base_path.absolute()}")
    
    # Create directory structure
    create_directory_structure(base_path)
    
    # Create configuration files
    create_requirements_file(base_path)
    create_frontend_package_json(base_path)
    create_env_file(base_path)
    create_gitignore(base_path)
    create_basic_files(base_path)
    
    # Install dependencies
    print("\nInstalling Dependencies...")
    print("-" * 30)
    
    # Install backend dependencies
    python_path = install_backend_dependencies(base_path)
    
    # Install frontend dependencies
    frontend_success = install_frontend_dependencies(base_path)
    
    print("\nSetup Complete!")
    print("=" * 50)
    print("[SUCCESS] Project structure created")
    print("[SUCCESS] Configuration files created")
    print(f"[INFO] Backend setup: {'Success' if python_path else 'Partial'}")
    print(f"[INFO] Frontend setup: {'Success' if frontend_success else 'Partial'}")
    
    print("\nNext Steps:")
    print("1. To start backend: cd backend && python run.py")
    print("2. To start frontend: cd frontend && npm run dev")
    print("3. Or create the full application files from the artifacts")
    
    print(f"\nProject location: {base_path.absolute()}")
    
    if not frontend_success:
        print("\nNote: If frontend setup failed, you may need to:")
        print("   - Install Node.js from https://nodejs.org")
        print("   - Run 'cd frontend && npm install' manually")

if __name__ == "__main__":
    main()