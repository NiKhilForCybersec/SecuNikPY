import requests
import streamlit as st
from typing import Optional, Dict, Any

class APIClient:
    """API client for backend communication"""
    
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })
    
    def health_check(self) -> bool:
        """Check if backend is healthy"""
        try:
            response = self.session.get(f"{self.base_url}/health", timeout=5)
            return response.status_code == 200
        except:
            return False
    
    def upload_file(self, file_data, filename: str) -> Optional[Dict[str, Any]]:
        """Upload file to backend"""
        try:
            files = {'file': (filename, file_data)}
            response = self.session.post(
                f"{self.base_url}/api/upload",
                files=files,
                timeout=30
            )
            return response.json() if response.status_code == 200 else None
        except Exception as e:
            st.error(f"Upload failed: {str(e)}")
            return None
    
    def get_dashboard_data(self) -> Optional[Dict[str, Any]]:
        """Get dashboard data from backend"""
        try:
            response = self.session.get(f"{self.base_url}/api/dashboard", timeout=10)
            return response.json() if response.status_code == 200 else None
        except:
            return None
    
    def get_analysis_results(self) -> Optional[Dict[str, Any]]:
        """Get analysis results from backend"""
        try:
            response = self.session.get(f"{self.base_url}/api/analysis", timeout=10)
            return response.json() if response.status_code == 200 else None
        except:
            return None