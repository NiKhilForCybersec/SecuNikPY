#!/usr/bin/env python3
"""
SecuNik Backend Run Script
Starts the complete FastAPI application
"""

import sys
from pathlib import Path

# Add app directory to path
current_dir = Path(__file__).parent
app_dir = current_dir / "app"
sys.path.insert(0, str(app_dir))

if __name__ == "__main__":
    try:
        from app.main import app
        import uvicorn
        
        print("🚀 Starting SecuNik Complete Backend...")
        uvicorn.run(app, host="localhost", port=8000, log_level="info")
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("Make sure you're in the backend directory")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n🛑 Server stopped by user")
        sys.exit(0)
