#!/usr/bin/env python3
"""
SecuNik Backend Run Script
Starts the complete FastAPI application
"""

import sys
import os
from pathlib import Path

# Add current directory and app directory to path
current_dir = Path(__file__).parent
app_dir = current_dir / "app"

# Add both to Python path
sys.path.insert(0, str(current_dir))
sys.path.insert(0, str(app_dir))

# Set environment variable for module resolution
os.environ['PYTHONPATH'] = f"{current_dir}:{app_dir}:{os.environ.get('PYTHONPATH', '')}"

if __name__ == "__main__":
    try:
        # Import from app.main
        from app.main import app
        import uvicorn
        
        print("🚀 Starting SecuNik Complete Backend...")
        print(f"📁 Working directory: {current_dir}")
        print(f"📁 App directory: {app_dir}")
        
        uvicorn.run(
            "app.main:app",  # Pass as string for reload to work
            host="0.0.0.0",
            port=8000,
            reload=True,
            log_level="info"
        )
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print(f"Current directory: {current_dir}")
        print(f"Python path: {sys.path}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n🛑 Server stopped by user")
        sys.exit(0)