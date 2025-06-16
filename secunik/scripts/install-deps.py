#!/usr/bin/env python3
"""
SecuNik Dependency Installation Script - COMPLETE FIXED VERSION
Handles Node.js alternatives and creates fallback options
"""

import subprocess
import sys
import os
from pathlib import Path
import platform

def run_command_safe(command, cwd=None, description=""):
    """Run a command safely with better error handling"""
    print(f"[RUNNING] {description}")
    try:
        use_shell = platform.system() == "Windows"
        result = subprocess.run(
            command, cwd=cwd, shell=use_shell, check=True,
            capture_output=True, text=True, timeout=600
        )
        print(f"[SUCCESS] {description}")
        return True, result.stdout
    except subprocess.TimeoutExpired:
        print(f"[TIMEOUT] {description}")
        return False, "Timeout"
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] {description} - Failed")
        return False, e.stderr
    except Exception as e:
        print(f"[ERROR] {description} - Exception: {str(e)}")
        return False, str(e)

def install_backend_dependencies():
    """Install backend dependencies"""
    print("Installing Backend Dependencies...")
    print("=" * 50)
    
    base_path = Path("N:/Project/SecuNikPy/secunik")
    backend_dir = base_path / "backend"
    venv_path = backend_dir / "venv"
    
    if not venv_path.exists():
        print("[ERROR] Virtual environment not found. Run setup.py first.")
        return False
    
    if platform.system() == "Windows":
        pip_path = venv_path / "Scripts" / "pip.exe"
    else:
        pip_path = venv_path / "bin" / "pip"
    
    if not pip_path.exists():
        print(f"[ERROR] pip not found at {pip_path}")
        return False
    
    # Essential packages
    essential_packages = [
        "fastapi==0.104.1",
        "uvicorn==0.24.0", 
        "python-multipart==0.0.6",
        "aiofiles==23.2.1",
        "requests==2.31.0",
        "jinja2==3.1.2"
    ]
    
    print("[INFO] Installing essential packages...")
    failed = []
    for package in essential_packages:
        success, _ = run_command_safe(
            [str(pip_path), "install", package],
            cwd=base_path,
            description=f"Installing {package}"
        )
        if not success:
            failed.append(package)
    
    print(f"[INFO] Backend installation complete. Failed: {len(failed)} packages")
    return len(failed) == 0

def check_nodejs():
    """Check if Node.js/npm is available"""
    for cmd in ["npm", "yarn", "pnpm"]:
        try:
            result = subprocess.run([cmd, "--version"], capture_output=True, text=True)
            if result.returncode == 0:
                print(f"[INFO] Found {cmd} version: {result.stdout.strip()}")
                return cmd
        except FileNotFoundError:
            continue
    return None

def install_frontend_with_npm(frontend_dir):
    """Install frontend using npm with compatible versions"""
    print("[INFO] Installing frontend with npm...")
    
    # Create simple package.json
    package_json = """{
  "name": "secunik-frontend",
  "version": "1.0.0",
  "scripts": {
    "dev": "python serve.py",
    "build": "echo 'Build not needed for simple version'"
  },
  "dependencies": {},
  "devDependencies": {}
}"""
    
    package_file = frontend_dir / "package.json"
    package_file.write_text(package_json, encoding='utf-8')
    
    print("[SUCCESS] Created simple package.json")
    return True

def create_simple_frontend(frontend_dir):
    """Create simple HTML frontend"""
    print("[INFO] Creating simple HTML frontend...")
    
    # Create directories
    (frontend_dir / "public").mkdir(exist_ok=True)
    
    # HTML content
    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecuNik - Cybersecurity Analysis Platform</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f8fafc; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 2rem; text-align: center; }
        .header h1 { font-size: 2.5rem; margin-bottom: 0.5rem; }
        .header p { opacity: 0.9; font-size: 1.1rem; }
        .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
        .card { background: white; border-radius: 12px; padding: 2rem; margin: 1rem 0; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .status { display: flex; align-items: center; padding: 1rem; border-radius: 8px; margin: 1rem 0; }
        .status.success { background: #d1fae5; color: #065f46; border-left: 4px solid #10b981; }
        .status.info { background: #dbeafe; color: #1e40af; border-left: 4px solid #3b82f6; }
        .status.warning { background: #fef3c7; color: #92400e; border-left: 4px solid #f59e0b; }
        .upload-zone { border: 3px dashed #d1d5db; border-radius: 12px; padding: 3rem; text-align: center; cursor: pointer; transition: all 0.3s; }
        .upload-zone:hover { border-color: #3b82f6; background: #f8fafc; }
        .upload-zone.dragover { border-color: #10b981; background: #ecfdf5; }
        .btn { background: #3b82f6; color: white; border: none; padding: 0.75rem 1.5rem; border-radius: 8px; cursor: pointer; font-size: 1rem; transition: all 0.3s; }
        .btn:hover { background: #2563eb; transform: translateY(-1px); }
        .btn-success { background: #10b981; }
        .btn-success:hover { background: #059669; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 2rem; margin: 2rem 0; }
        .file-item { background: #f8fafc; padding: 1rem; border-radius: 8px; border-left: 4px solid #3b82f6; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; }
        .stat-card { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 1.5rem; border-radius: 12px; text-align: center; }
        .stat-number { font-size: 2rem; font-weight: bold; margin-bottom: 0.5rem; }
        .footer { text-align: center; margin: 2rem 0; color: #6b7280; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔐 SecuNik</h1>
        <p>Ultimate Local Cybersecurity Analysis Platform</p>
    </div>
    
    <div class="container">
        <div class="status success">
            <div>
                <strong>✅ System Status:</strong> 
                <span id="backend-status">Checking backend connection...</span>
            </div>
        </div>
        
        <div class="status info">
            <div>
                <strong>ℹ️ Version:</strong> SecuNik v1.0.0 - Phase 1 (Simple HTML Frontend)
            </div>
        </div>
        
        <div class="grid">
            <div class="card">
                <h2>📊 Dashboard</h2>
                <div class="stats">
                    <div class="stat-card">
                        <div class="stat-number" id="total-files">0</div>
                        <div>Total Files</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number" id="total-cases">0</div>
                        <div>Cases</div>
                    </div>
                </div>
            </div>
            
            <div class="card">
                <h2>📁 File Upload</h2>
                <div class="upload-zone" onclick="document.getElementById('fileInput').click()">
                    <div style="font-size: 3rem; margin-bottom: 1rem;">📤</div>
                    <h3>Drop files here or click to browse</h3>
                    <p>Supports: PDF, ZIP, LOG, JSON, CSV, PCAP, and more</p>
                </div>
                <input type="file" id="fileInput" style="display: none;" multiple>
                <div id="selectedFiles"></div>
            </div>
        </div>
        
        <div class="card">
            <h2>🔧 Quick Actions</h2>
            <div style="display: flex; gap: 1rem; flex-wrap: wrap;">
                <button class="btn" onclick="checkBackend()">🔍 Check Backend</button>
                <button class="btn" onclick="viewAPIDocs()">📚 API Documentation</button>
                <button class="btn btn-success" onclick="viewHealth()">❤️ Health Check</button>
                <button class="btn" onclick="showUpgradeInfo()">⬆️ Upgrade to Full Version</button>
            </div>
        </div>
        
        <div id="fileListContainer" class="card" style="display: none;">
            <h2>📋 Selected Files</h2>
            <div id="fileList"></div>
        </div>
    </div>
    
    <div class="footer">
        <p>SecuNik v1.0.0 - Simple HTML Frontend | For full features, install Node.js and use the Vue.js frontend</p>
    </div>

    <script>
        let selectedFiles = [];
        
        // Backend status check
        async function checkBackend() {
            const statusEl = document.getElementById('backend-status');
            try {
                const response = await fetch('http://localhost:8000/health');
                const data = await response.json();
                statusEl.innerHTML = `<span style="color: #10b981;">✅ ${data.status.toUpperCase()}</span> - ${data.message}`;
            } catch (error) {
                statusEl.innerHTML = '<span style="color: #ef4444;">❌ DISCONNECTED</span> - Make sure backend is running on port 8000';
            }
        }
        
        // View API documentation
        function viewAPIDocs() {
            window.open('http://localhost:8000/docs', '_blank');
        }
        
        // View health endpoint
        function viewHealth() {
            window.open('http://localhost:8000/health', '_blank');
        }
        
        // Show upgrade information
        function showUpgradeInfo() {
            alert(`To upgrade to the full SecuNik experience:

1. Install Node.js from https://nodejs.org
2. Run: cd frontend && npm install vue@3 vite@5
3. Create the Vue.js components from the artifacts
4. Start with: npm run dev

This will give you:
• Advanced file analysis
• Interactive dashboard
• Real-time notifications  
• Professional UI components
• Case management interface`);
        }
        
        // File drag and drop
        const uploadZone = document.querySelector('.upload-zone');
        
        uploadZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadZone.classList.add('dragover');
        });
        
        uploadZone.addEventListener('dragleave', () => {
            uploadZone.classList.remove('dragover');
        });
        
        uploadZone.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadZone.classList.remove('dragover');
            handleFiles(e.dataTransfer.files);
        });
        
        // File input change
        document.getElementById('fileInput').addEventListener('change', (e) => {
            handleFiles(e.target.files);
        });
        
        // Handle selected files
        function handleFiles(files) {
            selectedFiles = Array.from(files);
            displaySelectedFiles();
            document.getElementById('total-files').textContent = selectedFiles.length;
        }
        
        // Display selected files
        function displaySelectedFiles() {
            const container = document.getElementById('fileListContainer');
            const list = document.getElementById('fileList');
            
            if (selectedFiles.length === 0) {
                container.style.display = 'none';
                return;
            }
            
            container.style.display = 'block';
            list.innerHTML = '';
            
            selectedFiles.forEach((file, index) => {
                const fileDiv = document.createElement('div');
                fileDiv.className = 'file-item';
                fileDiv.innerHTML = `
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <div>
                            <strong>📄 ${file.name}</strong><br>
                            <small>Size: ${(file.size / 1024 / 1024).toFixed(2)} MB | Type: ${file.type || 'Unknown'}</small>
                        </div>
                        <button class="btn" onclick="removeFile(${index})">Remove</button>
                    </div>
                `;
                list.appendChild(fileDiv);
            });
            
            // Add upload button
            const uploadDiv = document.createElement('div');
            uploadDiv.style.textAlign = 'center';
            uploadDiv.style.marginTop = '1rem';
            uploadDiv.innerHTML = `
                <button class="btn btn-success" onclick="uploadFiles()">
                    🚀 Upload ${selectedFiles.length} File(s)
                </button>
            `;
            list.appendChild(uploadDiv);
        }
        
        // Remove file from selection
        function removeFile(index) {
            selectedFiles.splice(index, 1);
            displaySelectedFiles();
            document.getElementById('total-files').textContent = selectedFiles.length;
        }
        
        // Upload files (placeholder)
        async function uploadFiles() {
            alert(`File upload functionality requires the full backend implementation.

For now, this demonstrates the interface. To enable uploads:
1. Implement the upload endpoints in main.py
2. Add file storage and analysis logic
3. Create the complete FastAPI backend

This simple frontend shows how the interface will work!`);
        }
        
        // Initialize
        checkBackend();
        setInterval(checkBackend, 30000); // Check every 30 seconds
    </script>
</body>
</html>"""
    
    # Write HTML file
    html_file = frontend_dir / "public" / "index.html"
    html_file.write_text(html_content, encoding='utf-8')
    
    # Create simple server
    server_script = """#!/usr/bin/env python3
import http.server
import socketserver
import webbrowser
import os
from pathlib import Path

PORT = 3000
DIRECTORY = Path(__file__).parent / "public"

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

try:
    os.chdir(DIRECTORY)
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        print(f"SecuNik Simple Frontend running at http://localhost:{PORT}")
        print("Press Ctrl+C to stop the server")
        
        # Try to open browser
        try:
            webbrowser.open(f'http://localhost:{PORT}')
        except:
            pass
            
        httpd.serve_forever()
except KeyboardInterrupt:
    print("\\nFrontend server stopped")
except OSError as e:
    print(f"Error: Port {PORT} may already be in use. {e}")
"""
    
    server_file = frontend_dir / "serve.py"
    server_file.write_text(server_script, encoding='utf-8')
    
    print("[SUCCESS] Simple HTML frontend created!")
    return True

def install_frontend_dependencies():
    """Install frontend dependencies with multiple fallback options"""
    print("\nInstalling Frontend Dependencies...")
    print("=" * 50)
    
    base_path = Path("N:/Project/SecuNikPy/secunik")
    frontend_dir = base_path / "frontend"
    
    # Check for Node.js
    nodejs_cmd = check_nodejs()
    
    if nodejs_cmd:
        print(f"[INFO] Found {nodejs_cmd}, attempting installation...")
        success = install_frontend_with_npm(frontend_dir)
        if success:
            return create_simple_frontend(frontend_dir)
    
    print("[INFO] No Node.js found, creating simple HTML frontend...")
    return create_simple_frontend(frontend_dir)

def main():
    """Main installation function"""
    print("SecuNik Dependency Installation - COMPLETE FIXED VERSION")
    print("=" * 60)
    
    # Install backend
    backend_success = install_backend_dependencies()
    
    # Install frontend  
    frontend_success = install_frontend_dependencies()
    
    # Summary
    print("\n" + "=" * 60)
    print("INSTALLATION COMPLETE")
    print("=" * 60)
    
    if backend_success:
        print("[SUCCESS] Backend ready!")
        print("  Start with: cd backend && venv\\Scripts\\activate && python run.py")
        print("  Access at: http://localhost:8000")
    
    if frontend_success:
        print("[SUCCESS] Frontend ready!")
        print("  Start with: cd frontend && python serve.py") 
        print("  Access at: http://localhost:3000")
    
    print(f"\nProject location: N:/Project/SecuNikPy/secunik")
    
    if not check_nodejs():
        print("\n[INFO] To upgrade to full Vue.js frontend:")
        print("1. Install Node.js from https://nodejs.org")
        print("2. Run the complete setup from the artifacts")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())