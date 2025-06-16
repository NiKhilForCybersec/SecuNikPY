# scripts/clean.py
#!/usr/bin/env python3
"""
SecuNik Cleanup Script
Cleans temporary files and caches
"""

import shutil
import os
from pathlib import Path

def main():
    print("🧹 Cleaning SecuNik temporary files...")
    
    base_path = Path(__file__).parent.parent
    
    # Directories to clean
    clean_dirs = [
        base_path / "backend" / "data" / "temp",
        base_path / "frontend" / "dist",
        base_path / "frontend" / "node_modules" / ".cache",
    ]
    
    # File patterns to clean
    clean_patterns = [
        "**/__pycache__",
        "**/*.pyc",
        "**/*.pyo",
        "**/.pytest_cache",
        "**/npm-debug.log*",
        "**/yarn-debug.log*",
        "**/yarn-error.log*"
    ]
    
    cleaned_count = 0
    
    # Clean directories
    for dir_path in clean_dirs:
        if dir_path.exists():
            try:
                shutil.rmtree(dir_path)
                print(f"✅ Cleaned: {dir_path}")
                cleaned_count += 1
            except Exception as e:
                print(f"⚠️ Could not clean {dir_path}: {e}")
    
    # Clean file patterns
    for pattern in clean_patterns:
        for file_path in base_path.rglob(pattern):
            try:
                if file_path.is_file():
                    file_path.unlink()
                elif file_path.is_dir():
                    shutil.rmtree(file_path)
                cleaned_count += 1
            except Exception as e:
                print(f"⚠️ Could not clean {file_path}: {e}")
    
    print(f"\n🎉 Cleanup complete! Cleaned {cleaned_count} items.")

if __name__ == "__main__":
    main()