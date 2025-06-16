# Create this as: scripts/create-simple-files.py  
"""
Creates basic working files if they're missing
"""

import os
from pathlib import Path

def create_simple_backend():
    """Create a simple working backend/run.py"""
    
    base_path = Path(__file__).parent.parent
    backend_dir = base_path / "backend"
    run_file = backend_dir / "run.py"
    
    if run_file.exists():
        print("backend/run.py already exists")
        return
    
    backend_dir.mkdir(exist_ok=True)
    
    simple_backend = '''#!/usr/bin/env python3
"""
Simple SecuNik Backend
Basic FastAPI server for testing
"""

import sys
from pathlib import Path

try:
    from fastapi import FastAPI
    from fastapi.middleware.cors import CORSMiddleware
    import uvicorn
except ImportError as e:
    print(f"Missing packages: {e}")
    print("Please install: pip install fastapi uvicorn")
    sys.exit(1)

# Create FastAPI app
app = FastAPI(
    title="SecuNik API",
    description="Ultimate Cybersecurity Analysis Platform",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def root():
    return {
        "message": "SecuNik API - Ultimate Cybersecurity Analysis Platform",
        "version": "1.0.0",
        "status": "running",
        "docs": "/docs",
        "health": "/health"
    }

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "message": "SecuNik Backend is running",
        "version": "1.0.0"
    }

@app.get("/api/dashboard")
def dashboard():
    return {
        "total_cases": 0,
        "total_files": 0,
        "total_size": 0,
        "total_size_human": "0 MB",
        "recent_files": []
    }

if __name__ == "__main__":
    print("Starting SecuNik Backend...")
    print("Backend available at: http://localhost:8000")
    print("API docs at: http://localhost:8000/docs")
    print("Press Ctrl+C to stop")
    
    try:
        uvicorn.run(app, host="localhost", port=8000, log_level="info")
    except KeyboardInterrupt:
        print("\\nBackend stopped")
'''
    
    run_file.write_text(simple_backend, encoding='utf-8')
    print(f"Created simple backend at: {run_file}")

def create_simple_frontend():
    """Create a simple working frontend"""
    
    base_path = Path(__file__).parent.parent
    frontend_dir = base_path / "frontend"
    public_dir = frontend_dir / "public"
    
    # Create directories
    public_dir.mkdir(parents=True, exist_ok=True)
    
    # Create simple HTML
    html_file = public_dir / "index.html"
    if not html_file.exists():
        simple_html = '''<!DOCTYPE html>
<html>
<head>
    <title>SecuNik - Test Frontend</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }
        .status { padding: 10px; margin: 10px 0; border-radius: 4px; }
        .success { background: #d4edda; color: #155724; }
        .info { background: #d1ecf1; color: #0c5460; }
        button { background: #007bff; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 SecuNik - Test Frontend</h1>
        <p>Simple HTML frontend for testing backend connection</p>
        
        <div class="status info">
            <strong>Backend Status:</strong> <span id="status">Checking...</span>
        </div>
        
        <button onclick="checkBackend()">Check Backend</button>
        <button onclick="viewDocs()">View API Docs</button>
        
        <h3>Test Results:</h3>
        <div id="results"></div>
    </div>

    <script>
        async function checkBackend() {
            const statusEl = document.getElementById('status');
            const resultsEl = document.getElementById('results');
            
            try {
                const response = await fetch('http://localhost:8000/health');
                const data = await response.json();
                
                statusEl.innerHTML = `<span style="color: green;">✅ ${data.status.toUpperCase()}</span> - ${data.message}`;
                
                resultsEl.innerHTML = `
                    <div class="status success">
                        <strong>✅ Backend Connected Successfully!</strong><br>
                        Version: ${data.version}<br>
                        Status: ${data.status}
                    </div>
                `;
            } catch (error) {
                statusEl.innerHTML = '<span style="color: red;">❌ DISCONNECTED</span>';
                resultsEl.innerHTML = `
                    <div class="status" style="background: #f8d7da; color: #721c24;">
                        <strong>❌ Backend Connection Failed</strong><br>
                        Error: ${error.message}<br>
                        Make sure backend is running on port 8000
                    </div>
                `;
            }
        }
        
        function viewDocs() {
            window.open('http://localhost:8000/docs', '_blank');
        }
        
        // Auto-check on load
        checkBackend();
    </script>
</body>
</html>'''
        html_file.write_text(simple_html, encoding='utf-8')
        print(f"Created simple HTML at: {html_file}")
    
    # Create serve.py
    serve_file = frontend_dir / "serve.py"
    if not serve_file.exists():
        simple_server = '''#!/usr/bin/env python3
import http.server
import socketserver
import webbrowser
import os
from pathlib import Path

PORT = 3000
DIRECTORY = Path(__file__).parent / "public"

print(f"Starting simple frontend server...")
print(f"Serving from: {DIRECTORY}")
print(f"Available at: http://localhost:{PORT}")

try:
    os.chdir(DIRECTORY)
    Handler = http.server.SimpleHTTPRequestHandler
    
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        print("Server started successfully!")
        print("Press Ctrl+C to stop")
        
        # Try to open browser
        try:
            webbrowser.open(f'http://localhost:{PORT}')
        except:
            pass
        
        httpd.serve_forever()
except KeyboardInterrupt:
    print("\\nServer stopped")
except Exception as e:
    print(f"Error: {e}")
'''
        serve_file.write_text(simple_server, encoding='utf-8')
        print(f"Created serve.py at: {serve_file}")

def main():
    print("Creating Simple SecuNik Files")
    print("=" * 40)
    
    create_simple_backend()
    create_simple_frontend()
    
    print("\nFiles created! Test with:")
    print("1. Backend: cd backend && python run.py")
    print("2. Frontend: cd frontend && python serve.py")

if __name__ == "__main__":
    main()