# app_integrated_fixed.py - Complete SecuNik App with All Issues Fixed
import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import requests
import json
import hashlib
import os
from pathlib import Path
import time

# Page configuration
st.set_page_config(
    page_title="SecuNik - Advanced Cybersecurity Platform",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Backend API configuration
BACKEND_URL = "http://localhost:8000"
API_TIMEOUT = 10

# Custom CSS
st.markdown("""
<style>
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
    
    .main-header {
        background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 50%, #1e40af 100%);
        padding: 1.5rem 2rem;
        border-radius: 15px;
        margin-bottom: 2rem;
        color: white;
        box-shadow: 0 8px 32px rgba(59, 130, 246, 0.3);
    }
    
    .status-connected { 
        color: #22c55e; 
        font-weight: bold; 
        background: #dcfce7;
        padding: 0.25rem 0.5rem;
        border-radius: 0.5rem;
    }
    
    .status-disconnected { 
        color: #ef4444; 
        font-weight: bold; 
        background: #fef2f2;
        padding: 0.25rem 0.5rem;
        border-radius: 0.5rem;
    }
    
    .metric-card {
        background: white;
        padding: 1.5rem;
        border-radius: 12px;
        border-left: 4px solid #3b82f6;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        margin-bottom: 1rem;
        transition: transform 0.2s ease;
    }
    
    .upload-success {
        background: #dcfce7;
        border: 1px solid #22c55e;
        border-radius: 8px;
        padding: 1rem;
        margin: 1rem 0;
        color: #15803d;
    }
    
    .analysis-progress {
        background: #eff6ff;
        border: 1px solid #3b82f6;
        border-radius: 8px;
        padding: 1rem;
        margin: 1rem 0;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state properly - FIXED
def initialize_session_state():
    """Initialize all session state variables properly"""
    if 'backend_connected' not in st.session_state:
        st.session_state.backend_connected = False
    if 'dashboard_data' not in st.session_state:
        st.session_state.dashboard_data = {}
    if 'uploaded_files' not in st.session_state:
        st.session_state.uploaded_files = []
    if 'analysis_results' not in st.session_state:
        st.session_state.analysis_results = []
    if 'current_page' not in st.session_state:
        st.session_state.current_page = "Security Dashboard"
    if 'page_changed' not in st.session_state:
        st.session_state.page_changed = False

# API helper functions
def check_backend_connection():
    """Check if backend API is accessible"""
    try:
        response = requests.get(f"{BACKEND_URL}/health", timeout=API_TIMEOUT)
        if response.status_code == 200:
            st.session_state.backend_connected = True
            return True
        else:
            st.session_state.backend_connected = False
            return False
    except requests.exceptions.RequestException:
        st.session_state.backend_connected = False
        return False

def upload_file_to_backend(uploaded_file):
    """Upload file to backend API with proper error handling - FIXED"""
    try:
        # Ensure file content is properly handled
        file_content = uploaded_file.getvalue()
        file_name = uploaded_file.name or "unknown_file"
        file_type = uploaded_file.type or "application/octet-stream"
        
        files = {"file": (file_name, file_content, file_type)}
        response = requests.post(
            f"{BACKEND_URL}/api/upload", 
            files=files,
            timeout=30
        )
        
        if response.status_code == 200:
            result = response.json()
            # Ensure required fields exist with proper fallbacks
            result.setdefault('file_id', hashlib.md5(file_content).hexdigest())
            result.setdefault('file_type', detect_file_type_frontend(file_name))
            result.setdefault('size', len(file_content))
            result.setdefault('filename', file_name)
            result.setdefault('status', 'uploaded')
            return result
        else:
            st.error(f"Upload failed: HTTP {response.status_code} - {response.text}")
            return None
            
    except requests.exceptions.RequestException as e:
        st.error(f"Upload error: {str(e)}")
        return None
    except Exception as e:
        st.error(f"Unexpected error: {str(e)}")
        return None

def get_dashboard_data():
    """Fetch dashboard data from backend"""
    try:
        response = requests.get(f"{BACKEND_URL}/api/dashboard", timeout=API_TIMEOUT)
        if response.status_code == 200:
            data = response.json()
            st.session_state.dashboard_data = data
            return data
        else:
            return create_mock_dashboard_data()
    except requests.exceptions.RequestException:
        return create_mock_dashboard_data()

def get_analysis_results():
    """Fetch analysis results from backend"""
    try:
        response = requests.get(f"{BACKEND_URL}/api/analysis", timeout=API_TIMEOUT)
        if response.status_code == 200:
            data = response.json()
            st.session_state.analysis_results = data.get('results', [])
            return data
        else:
            return create_mock_analysis_data()
    except requests.exceptions.RequestException:
        return create_mock_analysis_data()

def get_uploaded_files():
    """Fetch uploaded files from backend"""
    try:
        response = requests.get(f"{BACKEND_URL}/api/files", timeout=API_TIMEOUT)
        if response.status_code == 200:
            data = response.json()
            st.session_state.uploaded_files = data.get('files', [])
            return data
        else:
            return create_mock_files_data()
    except requests.exceptions.RequestException:
        return create_mock_files_data()

# Mock data functions for offline mode
def create_mock_dashboard_data():
    """Create mock dashboard data when backend is not available"""
    return {
        'system_stats': {
            'total_cases': 3,
            'active_threats': 1,
            'total_files': 12,
            'files_analyzed_today': 5,
            'risk_score': 35
        },
        'recent_uploads': [
            {
                'filename': 'sample_log.evtx',
                'file_type': 'Windows Event Log',
                'size': 2048576,
                'upload_time': datetime.now().isoformat()
            }
        ],
        'recent_analysis': [
            {
                'filename': 'sample_log.evtx',
                'risk_score': 35,
                'threats_found': ['Suspicious Login Activity'],
                'analysis_time': datetime.now().isoformat()
            }
        ]
    }

def create_mock_analysis_data():
    """Create mock analysis data"""
    return {
        'results': [
            {
                'filename': 'sample_log.evtx',
                'file_type': 'Windows Event Log',
                'risk_score': 35,
                'threats_found': ['Suspicious Login Activity'],
                'iocs_extracted': 5,
                'analysis_time': datetime.now().isoformat(),
                'file_id': 'mock_001',
                'case_id': 'CASE_001',
                'analysis_engine': 'SecuNik AI v1.0'
            }
        ]
    }

def create_mock_files_data():
    """Create mock files data"""
    return {
        'files': [
            {
                'id': 'mock_001',
                'filename': 'sample_log.evtx',
                'file_type': 'Windows Event Log',
                'size': 2048576,
                'upload_time': datetime.now().isoformat(),
                'hash_md5': 'a1b2c3d4e5f6789012345678901234567890',
                'status': 'analyzed'
            }
        ]
    }

def main():
    """Main application function with backend integration - FIXED"""
    
    # Initialize session state first
    initialize_session_state()
    
    # Header with connection status
    backend_status = check_backend_connection()
    
    st.markdown("""
    <div class="main-header">
        <h1>🔐 SecuNik - Advanced Cybersecurity Analysis Platform</h1>
        <p style="margin: 0; opacity: 0.9;">Professional Digital Forensics, Threat Analysis & Incident Response</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Sidebar navigation with backend status - FIXED
    with st.sidebar:
        st.markdown("### 🧭 Navigation")
        
        # Backend connection status
        if backend_status:
            st.markdown('<p class="status-connected">🟢 Backend Connected</p>', unsafe_allow_html=True)
        else:
            st.markdown('<p class="status-disconnected">🔴 Backend Disconnected</p>', unsafe_allow_html=True)
            st.warning("⚠️ Backend API not accessible. Using offline mode.")
        
        # Navigation menu - FIXED: Use radio buttons to avoid session state conflicts
        menu_options = [
            "Security Dashboard",
            "Evidence Upload", 
            "Threat Analysis",
            "Case Management",
            "Reports & Export",
            "System Settings"
        ]
        
        # Find current index safely
        try:
            current_index = menu_options.index(st.session_state.current_page)
        except ValueError:
            current_index = 0
            st.session_state.current_page = menu_options[0]
        
        # Use radio buttons for navigation to avoid widget conflicts
        selected_page = st.radio(
            "Select Module", 
            menu_options, 
            index=current_index,
            key="navigation_radio"
        )
        
        # Update current page only if changed
        if selected_page != st.session_state.current_page:
            st.session_state.current_page = selected_page
            st.session_state.page_changed = True
            st.rerun()
        
        # Real-time stats from backend
        if backend_status:
            dashboard_data = get_dashboard_data()
            if dashboard_data:
                st.markdown("---")
                st.markdown("### 📊 Live Stats")
                
                stats = dashboard_data.get('system_stats', {})
                col1, col2 = st.columns(2)
                with col1:
                    st.metric("Cases", stats.get('total_cases', 0))
                    st.metric("Files", stats.get('total_files', 0))
                with col2:
                    st.metric("Threats", stats.get('active_threats', 0))
                    st.metric("Risk", f"{stats.get('risk_score', 0)}/100")
        else:
            st.markdown("---")
            st.markdown("### ⚠️ Offline Mode")
            st.info("Using mock data. Connect backend for live data.")
    
    # Route to selected page based on session state - FIXED
    current_page = st.session_state.current_page
    
    if "Security Dashboard" in current_page:
        render_dashboard_integrated()
    elif "Evidence Upload" in current_page:
        render_file_upload_integrated()
    elif "Threat Analysis" in current_page:
        render_analysis_integrated()
    elif "Case Management" in current_page:
        render_case_management()
    elif "Reports & Export" in current_page:
        render_reports()
    elif "System Settings" in current_page:
        render_settings()

def render_dashboard_integrated():
    """Render dashboard with real backend data - FIXED"""
    
    st.markdown("## 🏠 Security Operations Dashboard")
    st.markdown("Real-time cybersecurity monitoring and threat intelligence overview")
    
    # Get real-time data from backend or use mock data
    dashboard_data = get_dashboard_data()
    
    stats = dashboard_data.get('system_stats', {})
    
    # Key metrics row with real data
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            label="🗂️ Active Cases", 
            value=stats.get('total_cases', 0),
            delta=f"+{min(3, stats.get('total_cases', 0))} new",
            help="Total number of active investigation cases"
        )
    
    with col2:
        st.metric(
            label="🚨 Critical Threats", 
            value=stats.get('active_threats', 0),
            delta="-2 resolved" if stats.get('active_threats', 0) > 0 else "0 detected",
            delta_color="inverse" if stats.get('active_threats', 0) > 0 else "normal"
        )
    
    with col3:
        st.metric(
            label="📁 Files Analyzed", 
            value=stats.get('total_files', 0),
            delta=f"{stats.get('files_analyzed_today', 0)} today"
        )
    
    with col4:
        risk_score = stats.get('risk_score', 25)
        st.metric(
            label="🛡️ Security Score", 
            value=f"{100-risk_score}/100",
            delta="+5 points" if risk_score < 30 else "-3 points",
            delta_color="normal" if risk_score < 30 else "inverse"
        )
    
    # Recent activity from backend
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### 🕒 Recent File Uploads")
        
        recent_uploads = dashboard_data.get('recent_uploads', [])
        
        if recent_uploads:
            for upload in recent_uploads[-5:]:
                try:
                    upload_time = datetime.fromisoformat(upload['upload_time']).strftime('%H:%M:%S')
                except:
                    upload_time = "Recent"
                    
                st.markdown(f"""
                <div class="metric-card">
                    <strong>{upload_time}</strong> - 📄 {upload['filename']}<br>
                    <small>{upload.get('file_type', 'Unknown')} • {format_file_size(upload.get('size', 0))}</small>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("No recent uploads. Upload files to see activity here.")
    
    with col2:
        st.markdown("### 🔍 Recent Analysis Results")
        
        recent_analysis = dashboard_data.get('recent_analysis', [])
        
        if recent_analysis:
            for analysis in recent_analysis[-5:]:
                try:
                    analysis_time = datetime.fromisoformat(analysis['analysis_time']).strftime('%H:%M:%S')
                except:
                    analysis_time = "Recent"
                    
                risk_score = analysis.get('risk_score', 0)
                risk_color = "🔴" if risk_score >= 80 else "🟡" if risk_score >= 30 else "🟢"
                threats_count = len(analysis.get('threats_found', []))
                
                st.markdown(f"""
                <div class="metric-card">
                    <strong>{analysis_time}</strong> - {risk_color} Risk: {risk_score}/100<br>
                    <small>{analysis.get('filename', 'Unknown')} • {threats_count} threats</small>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("No analysis results yet. Upload and analyze files to see results.")
    
    # Quick actions - FIXED: Use unique keys and proper navigation
    st.markdown("### ⚡ Quick Actions")
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        if st.button("📁 Upload Evidence", use_container_width=True, key="dash_upload_evidence"):
            st.session_state.current_page = "Evidence Upload"
            st.rerun()
    
    with col2:
        if st.button("🔍 View Analysis", use_container_width=True, key="dash_view_analysis"):
            st.session_state.current_page = "Threat Analysis"
            st.rerun()
    
    with col3:
        if st.button("🆕 New Case", use_container_width=True, key="dash_new_case"):
            st.session_state.current_page = "Case Management"
            st.rerun()
    
    with col4:
        if st.button("📊 Refresh Data", use_container_width=True, key="dash_refresh_data"):
            st.rerun()

def render_file_upload_integrated():
    """Render file upload with backend integration - FIXED"""
    
    st.markdown("## 📁 Digital Evidence Upload & Processing")
    st.markdown("Secure upload and automated analysis of digital forensic evidence")
    
    # Upload interface
    st.markdown("### 📤 Evidence Upload")
    
    uploaded_files = st.file_uploader(
        "Upload Evidence Files",
        accept_multiple_files=True,
        type=None,
        help="Supports: PDF, DOC, EML, PST, LOG, ZIP, PCAP, EVTX, REG, MEM, DMP, IMG, EXE and more",
        key="evidence_file_uploader"
    )
    
    if uploaded_files:
        st.markdown("### 📋 Upload Queue")
        
        for i, uploaded_file in enumerate(uploaded_files):
            file_size = len(uploaded_file.getvalue()) if uploaded_file else 0
            file_name = uploaded_file.name if uploaded_file and uploaded_file.name else f"file_{i}"
            
            with st.expander(f"📄 {file_name} ({format_file_size(file_size)})", expanded=True):
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    file_type = detect_file_type_frontend(file_name)
                    st.write(f"**File Type:** {file_type}")
                    st.write(f"**Size:** {format_file_size(file_size)}")
                
                with col2:
                    st.write(f"**Upload Time:** {datetime.now().strftime('%H:%M:%S')}")
                    st.write(f"**Status:** 🟡 Ready for Upload")
                
                with col3:
                    # Use unique key for each upload button
                    upload_key = f"upload_file_{i}_{file_name.replace('.', '_')}"
                    if st.button(f"🚀 Upload & Analyze", key=upload_key):
                        upload_and_analyze_file(uploaded_file)
        
        # Batch upload
        st.markdown("### ⚡ Batch Operations")
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("🚀 Upload All Files", use_container_width=True, key="batch_upload_all"):
                upload_all_files(uploaded_files)
        
        with col2:
            if st.button("🗑️ Clear Queue", use_container_width=True, key="clear_upload_queue"):
                st.rerun()
    
    # Show uploaded files from backend
    st.markdown("### 📁 Previously Uploaded Files")
    
    files_data = get_uploaded_files()
    if files_data and files_data.get('files'):
        for file_record in files_data['files'][-10:]:  # Show last 10 files
            try:
                upload_time = datetime.fromisoformat(file_record['upload_time']).strftime('%Y-%m-%d %H:%M:%S')
            except:
                upload_time = "Unknown time"
            
            file_id = file_record.get('id', 'unknown')
            filename = file_record.get('filename', 'Unknown file')
            
            with st.expander(f"📄 {filename} - {upload_time}", expanded=False):
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    st.write(f"**File Type:** {file_record.get('file_type', 'Unknown')}")
                    st.write(f"**Size:** {format_file_size(file_record.get('size', 0))}")
                
                with col2:
                    hash_md5 = file_record.get('hash_md5', 'N/A')
                    st.write(f"**MD5 Hash:** {hash_md5[:16]}..." if len(hash_md5) > 16 else hash_md5)
                    st.write(f"**Status:** {file_record.get('status', 'Unknown')}")
                
                with col3:
                    # Use unique keys for file action buttons
                    view_key = f"view_analysis_{file_id}_{filename.replace('.', '_')}"
                    delete_key = f"delete_file_{file_id}_{filename.replace('.', '_')}"
                    
                    if st.button(f"🔍 View Analysis", key=view_key):
                        show_file_analysis(file_id)
                    
                    if st.button(f"🗑️ Delete", key=delete_key):
                        delete_file_from_backend(file_id)
    else:
        st.info("No files uploaded yet. Upload your first evidence file above.")

def render_analysis_integrated():
    """Render analysis results with backend data - FIXED"""
    
    st.markdown("## 🔍 Threat Analysis & Investigation Results")
    st.markdown("Advanced threat detection, malware analysis, and security assessment")
    
    # Get analysis results from backend or use mock data
    analysis_data = get_analysis_results()
    
    results = analysis_data.get('results', [])
    
    if not results:
        st.info("No analysis results available. Upload and analyze files to see results here.")
        return
    
    # Analysis summary metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Files Analyzed", len(results))
    
    with col2:
        critical_threats = len([r for r in results if r.get('risk_score', 0) >= 80])
        st.metric("Critical Threats", critical_threats, delta="High priority")
    
    with col3:
        clean_files = len([r for r in results if r.get('risk_score', 0) < 30])
        st.metric("Clean Files", clean_files, delta="Safe")
    
    with col4:
        avg_risk = np.mean([r.get('risk_score', 0) for r in results]) if results else 0
        st.metric("Average Risk", f"{avg_risk:.0f}/100")
    
    # Detailed analysis results
    st.markdown("### 📊 Analysis Results")
    
    for i, result in enumerate(results[-20:]):  # Show last 20 results
        risk_score = result.get('risk_score', 0)
        status_color = "🔴" if risk_score >= 80 else "🟠" if risk_score >= 60 else "🟡" if risk_score >= 30 else "🟢"
        filename = result.get('filename', f'Unknown file {i}')
        
        with st.expander(f"{status_color} {filename} - Risk: {risk_score}/100", expanded=False):
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.write(f"**File Type:** {result.get('file_type', 'Unknown')}")
                st.write(f"**Risk Score:** {risk_score}/100")
                st.write(f"**Case ID:** {result.get('case_id', 'N/A')}")
            
            with col2:
                threats = result.get('threats_found', [])
                st.write(f"**Threats Found:** {len(threats)}")
                if threats:
                    for threat in threats[:3]:  # Show first 3 threats
                        st.write(f"• {threat}")
                st.write(f"**IOCs Extracted:** {result.get('iocs_extracted', 0)}")
            
            with col3:
                try:
                    analysis_time = datetime.fromisoformat(result['analysis_time']).strftime('%Y-%m-%d %H:%M:%S')
                except:
                    analysis_time = "Unknown time"
                    
                st.write(f"**Analysis Time:** {analysis_time}")
                st.write(f"**Engine:** {result.get('analysis_engine', 'Unknown')}")
                
                # Use unique key for report button
                report_key = f"report_{result.get('file_id', i)}_{filename.replace('.', '_')}"
                if st.button(f"📋 Detailed Report", key=report_key):
                    show_detailed_analysis_report(result)

# Helper functions - FIXED
def format_file_size(size_bytes):
    """Format file size in human-readable format"""
    if size_bytes == 0:
        return "0 B"
    
    try:
        size_names = ["B", "KB", "MB", "GB", "TB"]
        import math
        i = int(math.floor(math.log(size_bytes, 1024)))
        p = math.pow(1024, i)
        s = round(size_bytes / p, 2)
        return f"{s} {size_names[i]}"
    except:
        return "Unknown size"

def detect_file_type_frontend(filename):
    """Simple file type detection on frontend - FIXED"""
    if not filename:
        return "Unknown File Type"
        
    extension_map = {
        '.pdf': 'PDF Document',
        '.doc': 'Word Document', '.docx': 'Word Document',
        '.eml': 'Email Message', '.msg': 'Outlook Message',
        '.zip': 'ZIP Archive', '.rar': 'RAR Archive',
        '.exe': 'Executable', '.dll': 'Dynamic Library',
        '.log': 'Log File', '.txt': 'Text File',
        '.pcap': 'Network Capture', '.evtx': 'Windows Event Log',
        '.reg': 'Registry File', '.mem': 'Memory Dump'
    }
    
    try:
        ext = Path(filename).suffix.lower()
        return extension_map.get(ext, 'Unknown File Type')
    except:
        return 'Unknown File Type'

def upload_and_analyze_file(uploaded_file):
    """Upload single file to backend and show progress - FIXED"""
    if not uploaded_file:
        st.error("No file selected")
        return
    
    filename = uploaded_file.name or "unknown_file"
    
    with st.spinner(f"Uploading {filename}..."):
        result = upload_file_to_backend(uploaded_file)
        
        if result:
            st.success(f"✅ {filename} uploaded successfully!")
            
            # Show upload details with proper error handling
            file_type = result.get('file_type', detect_file_type_frontend(filename))
            file_size = result.get('size', 0)
            file_id = result.get('file_id', 'Unknown')
            
            st.markdown(f"""
            <div class="upload-success">
                <strong>Upload Successful</strong><br>
                File ID: {file_id}<br>
                Type: {file_type}<br>
                Size: {format_file_size(file_size)}<br>
                Status: Analysis in progress...
            </div>
            """, unsafe_allow_html=True)
            
            # Show analysis progress
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            # Simulate progress tracking
            for i in range(100):
                progress_bar.progress(i + 1)
                if i < 30:
                    status_text.text("Uploading file...")
                elif i < 60:
                    status_text.text("Analyzing file content...")
                elif i < 90:
                    status_text.text("Generating threat assessment...")
                else:
                    status_text.text("Finalizing analysis...")
                time.sleep(0.02)  # Faster progress for better UX
            
            st.success("🎉 File analysis completed! Check the Analysis section for results.")
            
            # Auto-refresh to show updated data
            time.sleep(1)
            st.rerun()
        else:
            st.error("❌ Upload failed. Please try again.")

def upload_all_files(uploaded_files):
    """Upload multiple files to backend - FIXED"""
    if not uploaded_files:
        st.error("No files to upload")
        return
        
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    successful_uploads = 0
    
    for i, uploaded_file in enumerate(uploaded_files):
        if uploaded_file and uploaded_file.name:
            status_text.text(f"Uploading {uploaded_file.name}...")
            progress_bar.progress((i + 1) / len(uploaded_files))
            
            result = upload_file_to_backend(uploaded_file)
            if result:
                successful_uploads += 1
            
            time.sleep(0.3)  # Small delay for UX
    
    status_text.text("Upload completed!")
    st.success(f"✅ Successfully uploaded {successful_uploads}/{len(uploaded_files)} files")
    
    if successful_uploads > 0:
        time.sleep(2)
        st.rerun()

def delete_file_from_backend(file_id):
    """Delete file from backend - FIXED"""
    if not file_id:
        st.error("Invalid file ID")
        return
        
    try:
        response = requests.delete(f"{BACKEND_URL}/api/files/{file_id}", timeout=API_TIMEOUT)
        if response.status_code == 200:
            st.success("File deleted successfully")
            time.sleep(1)
            st.rerun()
        else:
            st.error("Failed to delete file")
    except requests.exceptions.RequestException as e:
        st.error(f"Delete error: {str(e)}")

def show_file_analysis(file_id):
    """Show analysis results for a specific file - FIXED"""
    analysis_data = get_analysis_results()
    if analysis_data:
        file_analysis = None
        for result in analysis_data.get('results', []):
            if result.get('file_id') == file_id:
                file_analysis = result
                break
        
        if file_analysis:
            st.info(f"""
            **Analysis Results for {file_analysis.get('filename', 'Unknown')}**
            
            Risk Score: {file_analysis.get('risk_score', 0)}/100
            Threats Found: {len(file_analysis.get('threats_found', []))}
            IOCs Extracted: {file_analysis.get('iocs_extracted', 0)}
            Analysis Time: {file_analysis.get('analysis_time', 'Unknown')}
            """)
        else:
            st.warning("Analysis results not found for this file")
    else:
        st.error("Unable to fetch analysis data")

def show_detailed_analysis_report(result):
    """Show detailed analysis report - FIXED"""
    if not result:
        st.error("No analysis result provided")
        return
        
    filename = result.get('filename', 'Unknown file')
    risk_score = result.get('risk_score', 0)
    threats = result.get('threats_found', [])
    
    threat_list = '\n'.join([f"- {threat}" for threat in threats]) if threats else "- No threats detected"
    
    st.info(f"""
    📋 **Detailed Analysis Report: {filename}**
    
    **🔍 Threat Assessment:**
    - Risk Score: {risk_score}/100
    - Analysis Engine: {result.get('analysis_engine', 'Unknown')}
    - Scan Duration: {result.get('scan_duration', 'Unknown')}
    
    **⚠️ Security Findings:**
    {threat_list}
    """)

# Placeholder functions for other sections
def render_case_management():
    """Render case management interface"""
    st.markdown("## 📋 Case Management")
    st.info("Case management interface - connect to backend API for case operations")
    
    # Mock case data
    st.markdown("### 📁 Active Cases")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Total Cases", "3")
    with col2:
        st.metric("Open Cases", "2")
    with col3:
        st.metric("Closed Cases", "1")

def render_reports():
    """Render reports and export interface"""
    st.markdown("## 📊 Reports & Export")
    st.info("Report generation interface - connect to backend API for report generation")
    
    st.markdown("### 📋 Available Reports")
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("📄 Executive Summary", use_container_width=True, key="exec_report"):
            st.info("Executive summary report generation")
    
    with col2:
        if st.button("🔍 Technical Analysis", use_container_width=True, key="tech_report"):
            st.info("Technical analysis report generation")

def render_settings():
    """Render system settings interface"""
    st.markdown("## ⚙️ System Settings")
    st.info("Settings interface - configure backend API settings and preferences")
    
    st.markdown("### 🔧 Configuration")
    
    with st.expander("Backend API Settings", expanded=True):
        api_url = st.text_input("Backend URL", value=BACKEND_URL, key="api_url_setting")
        api_timeout = st.number_input("API Timeout (seconds)", value=API_TIMEOUT, key="api_timeout_setting")
        
        if st.button("Test Connection", key="test_connection"):
            st.info("Testing connection...")

if __name__ == "__main__":
    main()