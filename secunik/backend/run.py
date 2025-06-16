#!/usr/bin/env python3
"""
SecuNik Backend Run Script
Simple script to start the FastAPI backend server
"""

import sys
import os
from pathlib import Path

# Add the app directory to Python path
current_dir = Path(__file__).parent
app_dir = current_dir / "app"
sys.path.insert(0, str(app_dir))

# Import and run the main application
if __name__ == "__main__":
    try:
        from app.main import main
        print("🚀 Starting SecuNik Backend...")
        print("📍 Backend will be available at: http://localhost:8000")
        print("📚 API Documentation at: http://localhost:8000/docs")
        print("🔄 Health Check at: http://localhost:8000/health")
        print("-" * 50)
        main()
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("Make sure you're in the correct directory and dependencies are installed")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n🛑 Server stopped by user")
        sys.exit(0)
    except Exception as e:
        print(f"❌ Error starting server: {e}")
        sys.exit(1)