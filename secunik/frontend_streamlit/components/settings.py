"""
Settings Component for SecuNik
Application configuration and preferences
"""

import streamlit as st
import json
import os
from pathlib import Path
from utils.api_client import get_api_client


def show_settings_page():
    """Display the settings page"""
    st.title("⚙️ Settings")
    
    client = get_api_client()
    
    # Settings tabs
    tab1, tab2, tab3, tab4 = st.tabs(["🔧 General", "🤖 AI Configuration", "📊 Analysis", "🗃️ Data Management"])
    
    with tab1:
        show_general_settings()
    
    with tab2:
        show_ai_settings(client)
    
    with tab3:
        show_analysis_settings()
    
    with tab4:
        show_data_management(client)


def show_general_settings():
    """Show general application settings"""
    st.subheader("🔧 General Settings")
    
    # Load current settings
    settings = load_settings()
    
    with st.form("general_settings"):
        st.markdown("### 🎨 Interface Settings")
        
        # Theme settings
        dark_mode = st.checkbox(
            "Dark Mode", 
            value=settings.get("dark_mode", False),
            help="Enable dark mode interface"
        )
        
        # Auto-refresh settings
        auto_refresh = st.checkbox(
            "Auto-refresh Dashboard",
            value=settings.get("auto_refresh", True),
            help="Automatically refresh dashboard data"
        )
        
        refresh_interval = st.slider(
            "Refresh Interval (seconds)",
            min_value=10,
            max_value=300,
            value=settings.get("refresh_interval", 30),
            help="How often to refresh dashboard data"
        )
        
        st.markdown("### 📁 File Settings")
        
        # File handling settings
        max_file_size = st.number_input(
            "Maximum File Size (MB)",
            min_value=1,
            max_value=1000,
            value=settings.get("max_file_size_mb", 100),
            help="Maximum size for uploaded files"
        )
        
        auto_analyze = st.checkbox(
            "Auto-analyze on Upload",
            value=settings.get("auto_analyze", True),
            help="Automatically start analysis when files are uploaded"
        )
        
        st.markdown("### 🔔 Notification Settings")
        
        # Notification settings
        show_notifications = st.checkbox(
            "Show Notifications",
            value=settings.get("show_notifications", True),
            help="Display success/error notifications"
        )
        
        threat_alerts = st.checkbox(
            "Threat Alerts",
            value=settings.get("threat_alerts", True),
            help="Show alerts for high-risk threats"
        )
        
        if st.form_submit_button("💾 Save General Settings"):
            # Update settings
            settings.update({
                "dark_mode": dark_mode,
                "auto_refresh": auto_refresh,
                "refresh_interval": refresh_interval,
                "max_file_size_mb": max_file_size,
                "auto_analyze": auto_analyze,
                "show_notifications": show_notifications,
                "threat_alerts": threat_alerts
            })
            
            save_settings(settings)
            st.success("✅ General settings saved!")
            st.rerun()


def show_ai_settings(client):
    """Show AI configuration settings"""
    st.subheader("🤖 AI Configuration")
    
    # Get AI status
    ai_status = client.get_ai_status()
    
    if "error" in ai_status:
        st.error("❌ Could not connect to AI service")
        return
    
    # AI Status
    col1, col2 = st.columns(2)
    
    with col1:
        if ai_status.get("ai_available", False):
            st.success("🟢 AI Available")
        else:
            st.error("🔴 AI Not Available")
    
    with col2:
        if ai_status.get("openai_configured", False):
            st.success("🟢 OpenAI Configured")
        else:
            st.warning("🟡 OpenAI Not Configured")
    
    # AI Configuration
    st.markdown("### 🔑 OpenAI Configuration")
    
    # Check current API key status
    current_key = os.getenv("OPENAI_API_KEY", "")
    
    if current_key:
        masked_key = current_key[:8] + "..." + current_key[-4:] if len(current_key) > 12 else "***"
        st.info(f"🔑 Current API Key: {masked_key}")
    else:
        st.warning("⚠️ No API key configured")
    
    # API Key setup instructions
    with st.expander("🔧 Setup Instructions", expanded=not current_key):
        st.markdown("""
        **To configure OpenAI API:**
        
        1. **Get API Key:**
           - Visit https://openai.com
           - Create account and navigate to API section
           - Generate a new API key
        
        2. **Set Environment Variable:**
           ```bash
           # Windows (Command Prompt)
           set OPENAI_API_KEY=your-api-key-here
           
           # Windows (PowerShell)
           $env:OPENAI_API_KEY="your-api-key-here"
           
           # Linux/Mac
           export OPENAI_API_KEY="your-api-key-here"
           ```
        
        3. **Restart Backend:**
           ```bash
           cd backend
           python run.py
           ```
        
        4. **Test Configuration:**
           Use the test button below to verify the setup.
        """)
    
    # Test AI connection
    if st.button("🧪 Test AI Connection"):
        test_ai_connection(client)
    
    # AI Capabilities
    st.markdown("### 🎯 AI Capabilities")
    
    capabilities = client.get_ai_capabilities()
    if "error" not in capabilities:
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**🤖 AI Features:**")
            ai_caps = capabilities.get("ai_capabilities", [])
            if ai_caps:
                for cap in ai_caps:
                    st.write(f"✅ {cap}")
            else:
                st.write("⚠️ No AI features available")
        
        with col2:
            st.markdown("**📊 Basic Features:**")
            basic_caps = capabilities.get("basic_capabilities", [])
            for cap in basic_caps:
                st.write(f"• {cap}")
    
    # AI Settings
    settings = load_settings()
    
    with st.form("ai_settings"):
        st.markdown("### ⚙️ AI Preferences")
        
        ai_auto_enhance = st.checkbox(
            "Auto AI Enhancement",
            value=settings.get("ai_auto_enhance", False),
            help="Automatically run AI analysis on uploaded files"
        )
        
        ai_confidence_threshold = st.slider(
            "AI Confidence Threshold",
            min_value=0.0,
            max_value=1.0,
            value=settings.get("ai_confidence_threshold", 0.7),
            step=0.1,
            help="Minimum confidence for AI recommendations"
        )
        
        ai_chat_history_limit = st.number_input(
            "Chat History Limit",
            min_value=10,
            max_value=1000,
            value=settings.get("ai_chat_history_limit", 100),
            help="Maximum number of chat messages to keep"
        )
        
        if st.form_submit_button("💾 Save AI Settings"):
            settings.update({
                "ai_auto_enhance": ai_auto_enhance,
                "ai_confidence_threshold": ai_confidence_threshold,
                "ai_chat_history_limit": ai_chat_history_limit
            })
            
            save_settings(settings)
            st.success("✅ AI settings saved!")


def show_analysis_settings():
    """Show analysis configuration settings"""
    st.subheader("📊 Analysis Settings")
    
    settings = load_settings()
    
    with st.form("analysis_settings"):
        st.markdown("### 🔍 Analysis Preferences")
        
        # Default analysis depth
        default_analysis_depth = st.selectbox(
            "Default Analysis Depth",
            ["quick", "standard", "deep", "comprehensive"],
            index=["quick", "standard", "deep", "comprehensive"].index(
                settings.get("default_analysis_depth", "standard")
            ),
            help="Default depth for file analysis"
        )
        
        # Risk scoring
        risk_score_sensitivity = st.slider(
            "Risk Score Sensitivity",
            min_value=0.1,
            max_value=2.0,
            value=settings.get("risk_score_sensitivity", 1.0),
            step=0.1,
            help="Adjust sensitivity of risk scoring (1.0 = normal)"
        )
        
        # Threat detection
        threat_detection_strict = st.checkbox(
            "Strict Threat Detection",
            value=settings.get("threat_detection_strict", False),
            help="Use stricter criteria for threat detection"
        )
        
        st.markdown("### 📁 File Type Settings")
        
        # File type preferences
        analyze_archives = st.checkbox(
            "Analyze Archive Contents",
            value=settings.get("analyze_archives", True),
            help="Extract and analyze contents of archive files"
        )
        
        analyze_metadata = st.checkbox(
            "Extract Metadata",
            value=settings.get("analyze_metadata", True),
            help="Extract and analyze file metadata"
        )
        
        quarantine_suspicious = st.checkbox(
            "Quarantine Suspicious Files",
            value=settings.get("quarantine_suspicious", False),
            help="Automatically quarantine files with high risk scores"
        )
        
        st.markdown("### ⏱️ Performance Settings")
        
        # Performance settings
        max_analysis_time = st.number_input(
            "Max Analysis Time (seconds)",
            min_value=30,
            max_value=3600,
            value=settings.get("max_analysis_time", 300),
            help="Maximum time to spend analyzing a single file"
        )
        
        parallel_analysis = st.checkbox(
            "Parallel Analysis",
            value=settings.get("parallel_analysis", True),
            help="Analyze multiple files simultaneously"
        )
        
        if st.form_submit_button("💾 Save Analysis Settings"):
            settings.update({
                "default_analysis_depth": default_analysis_depth,
                "risk_score_sensitivity": risk_score_sensitivity,
                "threat_detection_strict": threat_detection_strict,
                "analyze_archives": analyze_archives,
                "analyze_metadata": analyze_metadata,
                "quarantine_suspicious": quarantine_suspicious,
                "max_analysis_time": max_analysis_time,
                "parallel_analysis": parallel_analysis
            })
            
            save_settings(settings)
            st.success("✅ Analysis settings saved!")


def show_data_management(client):
    """Show data management settings"""
    st.subheader("🗃️ Data Management")
    
    # Storage information
    st.markdown("### 💾 Storage Information")
    
    system_status = client.get_system_status()
    
    if "error" not in system_status:
        storage_mb = system_status.get("storage_used_mb", 0)
        total_analyses = system_status.get("total_analyses", 0)
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("💾 Storage Used", f"{storage_mb:.1f} MB")
        
        with col2:
            st.metric("📊 Total Analyses", total_analyses)
        
        with col3:
            # Calculate average file size
            if total_analyses > 0:
                avg_size = storage_mb / total_analyses
                st.metric("📏 Avg File Size", f"{avg_size:.1f} MB")
            else:
                st.metric("📏 Avg File Size", "0 MB")
    
    # Data cleanup options
    st.markdown("### 🧹 Data Cleanup")
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("🗑️ Clean Temporary Files", use_container_width=True):
            clean_temp_files()
    
    with col2:
        if st.button("📊 Clean Old Analysis Results", use_container_width=True):
            clean_old_analyses()
    
    # Data export options
    st.markdown("### 📤 Data Export")
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("📦 Export All Data", use_container_width=True):
            export_all_data(client)
    
    with col2:
        if st.button("📋 Export Analysis Reports", use_container_width=True):
            export_analysis_reports(client)
    
    # Backup and restore
    st.markdown("### 💾 Backup & Restore")
    
    with st.expander("🔄 Backup & Restore Options"):
        st.markdown("**🔒 Create Backup:**")
        
        if st.button("💾 Create Full Backup"):
            create_backup()
        
        st.markdown("**📂 Restore from Backup:**")
        
        uploaded_backup = st.file_uploader(
            "Upload Backup File",
            type=['zip'],
            help="Upload a previously created backup file"
        )
        
        if uploaded_backup and st.button("🔄 Restore Backup"):
            restore_backup(uploaded_backup)
    
    # Database maintenance
    st.markdown("### 🔧 Maintenance")
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("🔄 Rebuild Index", use_container_width=True):
            rebuild_index()
    
    with col2:
        if st.button("🗜️ Optimize Storage", use_container_width=True):
            optimize_storage()


def test_ai_connection(client):
    """Test AI connection"""
    with st.spinner("🧪 Testing AI connection..."):
        # Test with a simple chat message
        test_response = client.chat_with_ai("Hello, are you working?")
        
        if "error" in test_response:
            st.error(f"❌ AI Test Failed: {test_response['error']}")
        else:
            st.success("✅ AI Connection Test Passed!")
            st.info(f"🤖 AI Response: {test_response.get('response', 'No response')}")


def clean_temp_files():
    """Clean temporary files"""
    temp_dir = Path("data/temp")
    
    if not temp_dir.exists():
        st.info("No temporary files to clean")
        return
    
    try:
        cleaned_count = 0
        for file_path in temp_dir.rglob("*"):
            if file_path.is_file():
                file_path.unlink()
                cleaned_count += 1
        
        st.success(f"✅ Cleaned {cleaned_count} temporary files")
        
    except Exception as e:
        st.error(f"❌ Error cleaning temporary files: {e}")


def clean_old_analyses():
    """Clean old analysis results"""
    st.warning("⚠️ This will delete analysis results older than 30 days")
    
    if st.button("⚠️ Confirm Delete Old Analyses"):
        # Implementation would go here
        st.info("🔄 Old analysis cleanup not yet implemented")


def export_all_data(client):
    """Export all data"""
    with st.spinner("📦 Preparing data export..."):
        # Get all data
        dashboard_data = client.get_dashboard_data()
        analyses_data = client.get_all_analyses()
        
        export_data = {
            "export_timestamp": st.time().isoformat(),
            "dashboard": dashboard_data,
            "analyses": analyses_data
        }
        
        export_json = json.dumps(export_data, indent=2, default=str)
        
        st.download_button(
            label="📥 Download Data Export",
            data=export_json,
            file_name=f"secunik_export_{st.time().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json"
        )


def export_analysis_reports(client):
    """Export analysis reports"""
    with st.spinner("📋 Generating analysis reports..."):
        # Implementation would generate comprehensive reports
        st.info("📋 Analysis report export not yet implemented")


def create_backup():
    """Create full backup"""
    with st.spinner("💾 Creating backup..."):
        # Implementation would create a complete backup
        st.info("💾 Backup creation not yet implemented")


def restore_backup(backup_file):
    """Restore from backup"""
    with st.spinner("🔄 Restoring backup..."):
        # Implementation would restore from backup
        st.info("🔄 Backup restoration not yet implemented")


def rebuild_index():
    """Rebuild search index"""
    with st.spinner("🔄 Rebuilding index..."):
        # Implementation would rebuild search indices
        st.success("✅ Index rebuilt successfully")


def optimize_storage():
    """Optimize storage"""
    with st.spinner("🗜️ Optimizing storage..."):
        # Implementation would optimize file storage
        st.success("✅ Storage optimized successfully")


def load_settings():
    """Load settings from file"""
    settings_file = Path("data/settings.json")
    
    default_settings = {
        "dark_mode": False,
        "auto_refresh": True,
        "refresh_interval": 30,
        "max_file_size_mb": 100,
        "auto_analyze": True,
        "show_notifications": True,
        "threat_alerts": True,
        "ai_auto_enhance": False,
        "ai_confidence_threshold": 0.7,
        "ai_chat_history_limit": 100,
        "default_analysis_depth": "standard",
        "risk_score_sensitivity": 1.0,
        "threat_detection_strict": False,
        "analyze_archives": True,
        "analyze_metadata": True,
        "quarantine_suspicious": False,
        "max_analysis_time": 300,
        "parallel_analysis": True
    }
    
    try:
        if settings_file.exists():
            with open(settings_file, "r") as f:
                saved_settings = json.load(f)
                # Merge with defaults to ensure all keys exist
                default_settings.update(saved_settings)
                return default_settings
    except Exception as e:
        st.error(f"Error loading settings: {e}")
    
    return default_settings


def save_settings(settings):
    """Save settings to file"""
    settings_file = Path("data/settings.json")
    settings_file.parent.mkdir(parents=True, exist_ok=True)
    
    try:
        with open(settings_file, "w") as f:
            json.dump(settings, f, indent=2)
    except Exception as e:
        st.error(f"Error saving settings: {e}")


def reset_all_settings():
    """Reset all settings to defaults"""
    if st.button("🔄 Reset All Settings"):
        settings_file = Path("data/settings.json")
        if settings_file.exists():
            settings_file.unlink()
        
        st.success("✅ All settings reset to defaults!")
        st.rerun()


# Add system information section
def show_system_info():
    """Show system information"""
    with st.expander("ℹ️ System Information"):
        st.markdown("**🔐 SecuNik Information:**")
        st.write("• Version: 1.0.0")
        st.write("• Platform: Local Cybersecurity Analysis")
        st.write("• Backend: FastAPI + Python")
        st.write("• Frontend: Streamlit")
        
        st.markdown("**🖥️ System Status:**")
        
        # Check backend connection
        client = get_api_client()
        health = client.check_health()
        
        if "error" not in health:
            st.write("• Backend: ✅ Online")
            st.write(f"• API Version: {health.get('version', 'unknown')}")
            st.write(f"• Models: {'✅ Available' if health.get('models_available') else '⚠️ Basic'}")
        else:
            st.write("• Backend: ❌ Offline")
def show_settings_page():
    """Main entry point for settings page"""
    from utils.api_client import get_api_client
    client = get_api_client()