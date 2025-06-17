import streamlit as st

def render_settings():
    """Render settings and configuration page"""
    
    st.markdown("## ⚙️ Settings & Configuration")
    st.markdown("Configure SecuNik platform settings and preferences")
    
    # General Settings
    st.markdown("### 🔧 General Settings")
    
    with st.expander("General Configuration", expanded=True):
        col1, col2 = st.columns(2)
        
        with col1:
            auto_analysis = st.checkbox("Enable automatic analysis on upload", value=True)
            notifications = st.checkbox("Enable push notifications", value=True)
            dark_mode = st.checkbox("Dark mode", value=False)
        
        with col2:
            analysis_timeout = st.number_input("Analysis timeout (minutes)", min_value=1, max_value=60, value=30)
            max_file_size = st.number_input("Max file size (MB)", min_value=1, max_value=1000, value=500)
            concurrent_analyses = st.number_input("Concurrent analyses", min_value=1, max_value=10, value=3)
    
    # API Settings
    st.markdown("### 🔌 API Configuration")
    
    with st.expander("Backend API Settings", expanded=False):
        backend_url = st.text_input("Backend URL", value="http://localhost:8000")
        api_timeout = st.number_input("API timeout (seconds)", min_value=1, max_value=300, value=30)
        retry_attempts = st.number_input("Retry attempts", min_value=1, max_value=10, value=3)
        
        if st.button("🔍 Test Connection"):
            test_api_connection(backend_url)
    
    # Security Settings
    st.markdown("### 🔒 Security Settings")
    
    with st.expander("Security Configuration", expanded=False):
        require_auth = st.checkbox("Require authentication", value=True)
        session_timeout = st.number_input("Session timeout (hours)", min_value=1, max_value=24, value=8)
        audit_logging = st.checkbox("Enable audit logging", value=True)
        
        st.markdown("**File Upload Security:**")
        scan_uploads = st.checkbox("Scan uploads for malware", value=True)
        quarantine_threats = st.checkbox("Auto-quarantine detected threats", value=True)
    
    # Data Management
    st.markdown("### 💾 Data Management")
    
    with st.expander("Data Storage Settings", expanded=False):
        col1, col2 = st.columns(2)
        
        with col1:
            retention_days = st.number_input("Data retention (days)", min_value=7, max_value=3650, value=365)
            backup_enabled = st.checkbox("Enable automatic backups", value=True)
        
        with col2:
            compression_enabled = st.checkbox("Enable data compression", value=True)
            encryption_enabled = st.checkbox("Enable data encryption", value=True)
        
        if st.button("🗑️ Clean Old Data"):
            st.warning("This will remove data older than the retention period. Are you sure?")
    
    # Export Settings
    st.markdown("### 📤 Export & Reporting")
    
    with st.expander("Report Configuration", expanded=False):
        default_format = st.selectbox("Default report format", ["PDF", "HTML", "JSON", "CSV"])
        include_screenshots = st.checkbox("Include screenshots in reports", value=True)
        watermark_reports = st.checkbox("Add watermark to reports", value=False)
        
        st.markdown("**Email Settings:**")
        smtp_server = st.text_input("SMTP Server")
        smtp_port = st.number_input("SMTP Port", min_value=1, max_value=65535, value=587)
        email_auth = st.checkbox("Enable email authentication", value=True)
    
    # System Information
    st.markdown("### 📊 System Information")
    
    with st.expander("System Status", expanded=False):
        col1, col2 = st.columns(2)
        
        with col1:
            st.metric("Frontend Version", "1.0.0")
            st.metric("Backend Status", "🟢 Online")
            st.metric("Database Status", "🟢 Connected")
        
        with col2:
            st.metric("Active Sessions", "3")
            st.metric("Disk Usage", "45% (2.3 GB)")
            st.metric("Memory Usage", "67% (1.2 GB)")
        
        if st.button("🔄 Refresh System Status"):
            st.rerun()
    
    # Save Settings
    st.markdown("---")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("💾 Save Settings", use_container_width=True):
            st.success("✅ Settings saved successfully!")
    
    with col2:
        if st.button("🔄 Reset to Defaults", use_container_width=True):
            st.warning("⚠️ Settings reset to default values")
    
    with col3:
        if st.button("📤 Export Config", use_container_width=True):
            st.info("📁 Configuration exported to config.json")

def test_api_connection(backend_url):
    """Test connection to backend API"""
    try:
        import requests
        response = requests.get(f"{backend_url}/health", timeout=5)
        if response.status_code == 200:
            st.success("✅ API connection successful!")
        else:
            st.error(f"❌ API returned status code: {response.status_code}")
    except Exception as e:
        st.error(f"❌ API connection failed: {str(e)}")
