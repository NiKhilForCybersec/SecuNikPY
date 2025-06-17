#!/usr/bin/env python3
"""
SecuNik Backend Run Script
Starts the complete FastAPI application
"""

import sys
from pathlib import Path

# Add current directory to path
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

if __name__ == "__main__":
    try:
        # Import from app.main since main.py is in the app subdirectory
        from app.main import app
        import uvicorn
        
        print("🚀 Starting SecuNik Complete Backend...")
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