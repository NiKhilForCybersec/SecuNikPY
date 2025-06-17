"""
API Client for SecuNik Backend
Updated for new API structure
"""

import requests
import streamlit as st
from typing import Dict, List, Any, Optional
import json
import os
from datetime import datetime

class SecuNikAPIClient:
    """API client for SecuNik backend"""
    
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url
        self.session = requests.Session()
        
    def _make_request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """Make HTTP request with error handling"""
        try:
            url = f"{self.base_url}{endpoint}"
            response = self.session.request(method, url, **kwargs)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.ConnectionError:
            st.error("❌ Cannot connect to backend server. Please ensure it's running on localhost:8000")
            return {"error": "connection_failed"}
        except requests.exceptions.HTTPError as e:
            st.error(f"❌ API Error: {e}")
            return {"error": f"http_error: {e}"}
        except Exception as e:
            st.error(f"❌ Unexpected error: {e}")
            return {"error": f"unexpected: {e}"}
    
    # Health and Status
    def check_health(self) -> Dict[str, Any]:
        """Check backend health"""
        return self._make_request("GET", "/health")
    
    def get_api_info(self) -> Dict[str, Any]:
        """Get API information"""
        return self._make_request("GET", "/")
    
    # Dashboard APIs
    def get_dashboard_data(self) -> Dict[str, Any]:
        """Get main dashboard data"""
        return self._make_request("GET", "/api/dashboard")
    
    def get_threat_dashboard(self) -> Dict[str, Any]:
        """Get threat-focused dashboard data"""
        return self._make_request("GET", "/api/dashboard/threats")
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get system status and health"""
        return self._make_request("GET", "/api/dashboard/system")
    
    def get_recent_activity(self) -> Dict[str, Any]:
        """Get recent activity"""
        return self._make_request("GET", "/api/dashboard/activity")
    
    def get_trends_data(self) -> Dict[str, Any]:
        """Get trend data for charts"""
        return self._make_request("GET", "/api/dashboard/trends")
    
    # File Upload APIs
    def upload_file(self, file_data, filename: str) -> Dict[str, Any]:
        """Upload file for analysis"""
        files = {"file": (filename, file_data, "application/octet-stream")}
        return self._make_request("POST", "/api/upload", files=files)
    
    def list_files(self) -> Dict[str, Any]:
        """List all uploaded files"""
        return self._make_request("GET", "/api/files")
    
    def get_file_analysis(self, file_id: str) -> Dict[str, Any]:
        """Get analysis for specific file"""
        return self._make_request("GET", f"/api/files/{file_id}")
    
    def delete_file(self, file_id: str) -> Dict[str, Any]:
        """Delete file and its analysis"""
        return self._make_request("DELETE", f"/api/files/{file_id}")
    
    # Analysis APIs
    def get_all_analyses(self) -> Dict[str, Any]:
        """Get all analysis results"""
        return self._make_request("GET", "/api/analysis")
    
    def get_analysis(self, file_id: str) -> Dict[str, Any]:
        """Get detailed analysis for file"""
        return self._make_request("GET", f"/api/analysis/{file_id}")
    
    def get_analysis_stats(self) -> Dict[str, Any]:
        """Get analysis statistics"""
        return self._make_request("GET", "/api/analysis/stats/summary")
    
    def get_file_threats(self, file_id: str) -> Dict[str, Any]:
        """Get threats for specific file"""
        return self._make_request("GET", f"/api/analysis/{file_id}/threats")
    
    def get_file_recommendations(self, file_id: str) -> Dict[str, Any]:
        """Get recommendations for specific file"""
        return self._make_request("GET", f"/api/analysis/{file_id}/recommendations")
    
    def reanalyze_file(self, file_id: str, analysis_type: str = "standard", options: Dict = None) -> Dict[str, Any]:
        """Reanalyze file with different parameters"""
        data = {
            "file_id": file_id,
            "analysis_type": analysis_type,
            "options": options or {}
        }
        return self._make_request("POST", f"/api/analysis/{file_id}/reanalyze", json=data)
    
    # AI APIs
    def get_ai_status(self) -> Dict[str, Any]:
        """Get AI system status"""
        return self._make_request("GET", "/api/ai/status")
    
    def chat_with_ai(self, message: str, context: str = None, file_id: str = None) -> Dict[str, Any]:
        """Chat with AI assistant"""
        data = {
            "message": message,
            "context": context,
            "file_id": file_id
        }
        return self._make_request("POST", "/api/ai/chat", json=data)
    
    def ai_analyze_file(self, file_id: str, analysis_type: str = "comprehensive") -> Dict[str, Any]:
        """AI-powered file analysis"""
        data = {
            "file_id": file_id,
            "analysis_type": analysis_type
        }
        return self._make_request("POST", "/api/ai/analyze", json=data)
    
    def get_ai_insights(self, file_id: str) -> Dict[str, Any]:
        """Get AI insights for file"""
        return self._make_request("GET", f"/api/ai/insights/{file_id}")
    
    def correlate_files(self) -> Dict[str, Any]:
        """AI-powered file correlation"""
        return self._make_request("POST", "/api/ai/correlate")
    
    def get_ai_capabilities(self) -> Dict[str, Any]:
        """Get AI capabilities"""
        return self._make_request("GET", "/api/ai/capabilities")
    
    def bulk_ai_analysis(self) -> Dict[str, Any]:
        """Bulk AI analysis of all files"""
        return self._make_request("POST", "/api/ai/bulk-analyze")


# Global API client instance
@st.cache_resource
def get_api_client() -> SecuNikAPIClient:
    """Get cached API client instance"""
    return SecuNikAPIClient()


# Helper functions for Streamlit
def check_backend_connection() -> bool:
    """Check if backend is available"""
    try:
        client = get_api_client()
        health = client.check_health()
        return "error" not in health
    except Exception:
        return False


def display_api_status():
    """Display API connection status in sidebar"""
    with st.sidebar:
        if check_backend_connection():
            st.success("🟢 Backend Connected")
            
            # Get API info
            client = get_api_client()
            api_info = client.get_api_info()
            
            if "error" not in api_info:
                st.caption(f"📡 API v{api_info.get('version', 'unknown')}")
                
                # Show models status
                models_status = api_info.get('models_status', 'unknown')
                if models_status == 'available':
                    st.caption("📊 Models: ✅ Available")
                else:
                    st.caption("📊 Models: ⚠️ Basic")
                    
                # Show AI status
                ai_status = client.get_ai_status()
                if "error" not in ai_status:
                    if ai_status.get('ai_available', False):
                        st.caption("🤖 AI: ✅ Ready")
                    else:
                        st.caption("🤖 AI: ⚠️ Config Required")
        else:
            st.error("🔴 Backend Offline")
            st.caption("Start backend: `python run.py`")


def format_file_size(size_bytes: int) -> str:
    """Format file size in human readable format"""
    if size_bytes == 0:
        return "0B"
    size_names = ["B", "KB", "MB", "GB"]
    import math
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return f"{s} {size_names[i]}"


def format_timestamp(timestamp_str: str) -> str:
    """Format timestamp for display"""
    try:
        if isinstance(timestamp_str, str):
            dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        else:
            dt = timestamp_str
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except:
        return str(timestamp_str)


def get_severity_color(severity: str) -> str:
    """Get color for severity level"""
    colors = {
        "LOW": "green",
        "MEDIUM": "orange", 
        "HIGH": "red",
        "CRITICAL": "darkred"
    }
    return colors.get(severity.upper(), "gray")


def get_risk_score_color(risk_score: float) -> str:
    """Get color for risk score"""
    if risk_score >= 0.8:
        return "darkred"
    elif risk_score >= 0.6:
        return "red"
    elif risk_score >= 0.4:
        return "orange"
    elif risk_score >= 0.2:
        return "yellow"
    else:
        return "green"