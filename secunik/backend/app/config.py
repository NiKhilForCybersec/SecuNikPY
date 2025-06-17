"""
SecuNik Backend Configuration
Application settings and configuration management
"""

import os
from pathlib import Path
from typing import Optional
import json
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class Settings:
    """Application settings and configuration"""
    
    def __init__(self):
        # Base paths
        self.base_path = Path(__file__).parent.parent
        self.app_path = Path(__file__).parent
        
        # Server configuration
        self.host = os.getenv("HOST", "localhost")
        self.backend_port = int(os.getenv("BACKEND_PORT", 8000))
        self.frontend_port = int(os.getenv("FRONTEND_PORT", 3000))
        self.debug = os.getenv("DEBUG", "True").lower() == "true"
        
        # File handling
        self.max_file_size = self._parse_size(os.getenv("MAX_FILE_SIZE", "100MB"))
        self.upload_timeout = int(os.getenv("UPLOAD_TIMEOUT", 300))
        
        # Data paths
        self.data_path = Path(os.getenv("DATA_PATH", str(self.base_path / "data")))
        self.uploads_path = self.data_path / "uploads"
        self.cases_path = self.data_path / "cases"
        self.results_path = self.data_path / "results"
        
        # Initialize paths
        self._ensure_paths()
    
    def _parse_size(self, size_str: str) -> int:
        """Parse size string (e.g., '100MB') to bytes"""
        size_str = size_str.upper().strip()
        
        multipliers = {
            'B': 1,
            'KB': 1024,
            'MB': 1024 * 1024,
            'GB': 1024 * 1024 * 1024
        }
        
        for unit, multiplier in multipliers.items():
            if size_str.endswith(unit):
                try:
                    number = float(size_str[:-len(unit)])
                    return int(number * multiplier)
                except ValueError:
                    break
        
        return 100 * 1024 * 1024  # Default 100MB
    
    def _ensure_paths(self):
        """Ensure all required directories exist"""
        paths_to_create = [
            self.data_path,
            self.uploads_path,
            self.cases_path,
            self.results_path
        ]
        
        for path in paths_to_create:
            path.mkdir(parents=True, exist_ok=True)

# Global settings instance
settings = Settings()
