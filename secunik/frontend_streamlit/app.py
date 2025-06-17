"""
SecuNik - Ultimate Local Cybersecurity Analysis Platform
Main Streamlit Application - FIXED PATHS VERSION
"""

import streamlit as st
import sys
import traceback
from pathlib import Path

# Configure Streamlit page first (must be first Streamlit command)
st.set_page_config(
    page_title="SecuNik - Cybersecurity Analysis Platform",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Add utils and components to path - FIXED PATHS
current_dir = Path(__file__).parent  # frontend_streamlit directory
utils_dir = current_dir / "utils"
components_dir = current_dir / "components"

# Debug path information
print(f"🔍 Current directory: {current_dir}")
print(f"🔍 Utils directory: {utils_dir}")
print(f"🔍 Components directory: {components_dir}")
print(f"🔍 Utils exists: {utils_dir.exists()}")
print(f"🔍 Components exists: {components_dir.exists()}")

if str(utils_dir) not in sys.path:
    sys.path.insert(0, str(utils_dir))
if str(components_dir) not in sys.path:
    sys.path.insert(0, str(components_dir))

# Import utilities with corrected paths
try:
    # Import from utils subdirectory
    sys.path.insert(0, str(utils_dir))
    from api_client import get_api_client, display_api_status, check_backend_connection
    from state_manager import StateManager
    UTILS_AVAILABLE = True
    print("✅ Utils imported successfully")
except ImportError as e:
    print(f"❌ Could not import utilities: {e}")
    print(f"🔍 Attempted to import from: {utils_dir}")
    UTILS_AVAILABLE = False

# Import components with individual error handling
COMPONENTS_AVAILABLE = {}

components_to_import = [
    'dashboard', 'file_upload', 'analysis', 'cases', 'settings', 'ai_chat'
]

for component_name in components_to_import:
    try:
        # Import from components subdirectory
        sys.path.insert(0, str(components_dir))
        module = __import__(component_name)
        globals()[component_name] = module
        COMPONENTS_AVAILABLE[component_name] = True
        print(f"✅ {component_name} imported successfully")
    except ImportError as e:
        print(f"⚠️ {component_name} component not available: {e}")
        COMPONENTS_AVAILABLE[component_name] = False

# Custom CSS for SecuNik
st.markdown("""
<style>
/* SecuNik Custom Styling */
.main-header {
    background: linear-gradient(90deg, #1e3c72 0%, #2a5298 100%);
    padding: 1.5rem;
    border-radius: 10px;
    color: white;
    text-align: center;
    margin-bottom: 2rem;
    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
}

.main-header h1 {
    margin: 0;
    font-size: 2.5rem;
    font-weight: bold;
}

.main-header p {
    margin: 0.5rem 0 0 0;
    font-size: 1.1rem;
    opacity: 0.9;
}

.metric-card {
    background: #f8f9fa;
    padding: 1.2rem;
    border-radius: 8px;
    border-left: 4px solid #2a5298;
    margin: 0.5rem 0;
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
}

.threat-critical {
    background-color: #ffebee;
    border-left: 4px solid #8B0000;
    padding: 1rem;
    border-radius: 4px;
    margin: 0.5rem 0;
}

.threat-high {
    background-color: #ffebee;
    border-left: 4px solid #f44336;
    padding: 1rem;
    border-radius: 4px;
    margin: 0.5rem 0;
}

.threat-medium {
    background-color: #fff3e0;
    border-left: 4px solid #ff9800;
    padding: 1rem;
    border-radius: 4px;
    margin: 0.5rem 0;
}

.threat-low {
    background-color: #e8f5e8;
    border-left: 4px solid #4caf50;
    padding: 1rem;
    border-radius: 4px;
    margin: 0.5rem 0;
}

.upload-area {
    border: 2px dashed #ccc;
    border-radius: 10px;
    padding: 2rem;
    text-align: center;
    background: #fafafa;
    transition: border-color 0.3s ease;
}

.upload-area:hover {
    border-color: #2a5298;
}

.ai-chat {
    background: #f0f2f6;
    border-radius: 10px;
    padding: 1rem;
    border: 1px solid #e0e2e6;
    margin: 1rem 0;
}

.sidebar-section {
    background: #f8f9fa;
    padding: 1rem;
    border-radius: 8px;
    margin: 1rem 0;
    border: 1px solid #e9ecef;
}

.status-online {
    color: #28a745;
    font-weight: bold;
}

.status-offline {
    color: #dc3545;
    font-weight: bold;
}

.component-status {
    font-size: 0.9rem;
    margin: 0.2rem 0;
}

/* Hide Streamlit default elements */
#MainMenu {visibility: hidden;}
footer {visibility: hidden;}
header {visibility: hidden;}

/* Improve spacing */
.block-container {
    padding-top: 1rem;
}

/* Error message styling */
.error-box {
    background-color: #ffebee;
    border: 1px solid #f44336;
    border-radius: 4px;
    padding: 1rem;
    margin: 1rem 0;
}

.warning-box {
    background-color: #fff3e0;
    border: 1px solid #ff9800;
    border-radius: 4px;
    padding: 1rem;
    margin: 1rem 0;
}

.success-box {
    background-color: #e8f5e8;
    border: 1px solid #4caf50;
    border-radius: 4px;
    padding: 1rem;
    margin: 1rem 0;
}
</style>
""", unsafe_allow_html=True)


def show_debug_info():
    """Show debug information in an expander"""
    with st.expander("🔍 Debug Information"):
        st.write("**Directory Information:**")
        st.write(f"• Current directory: {current_dir}")
        st.write(f"• Utils directory: {utils_dir}")
        st.write(f"• Components directory: {components_dir}")
        st.write(f"• Utils exists: {utils_dir.exists()}")
        st.write(f"• Components exists: {components_dir.exists()}")
        
        st.write("**Import Status:**")
        st.write(f"• Utils available: {UTILS_AVAILABLE}")
        for component, available in COMPONENTS_AVAILABLE.items():
            status = "✅" if available else "❌"
            st.write(f"• {component}: {status}")
        
        if utils_dir.exists():
            st.write("**Files in utils directory:**")
            for file in utils_dir.glob("*.py"):
                st.write(f"  - {file.name}")
        
        if components_dir.exists():
            st.write("**Files in components directory:**")
            for file in components_dir.glob("*.py"):
                st.write(f"  - {file.name}")


def show_fallback_dashboard():
    """Fallback dashboard when dashboard component isn't available"""
    st.title("🏠 Dashboard")
    
    if not UTILS_AVAILABLE:
        st.markdown("""
        <div class="error-box">
            <h4>❌ Utilities not available</h4>
            <p>Cannot connect to backend - utils/api_client.py not found or has import errors.</p>
        </div>
        """, unsafe_allow_html=True)
        
        st.info("**To fix this:**")
        st.code("""
1. Check that utils/api_client.py exists
2. Check that utils/state_manager.py exists  
3. Install missing dependencies: pip install requests streamlit
4. Restart the application
        """)
        return
    
    try:
        client = get_api_client()
        dashboard_data = client.get_dashboard_data()
        
        if "error" in dashboard_data:
            st.markdown("""
            <div class="error-box">
                <h4>❌ Could not load dashboard data from backend</h4>
                <p>Backend server may not be running or reachable.</p>
            </div>
            """, unsafe_allow_html=True)
            
            st.info("**To fix this:**")
            st.code("cd backend && python run.py", language="bash")
            st.info("Backend should be available at: http://localhost:8000")
            
            # Test backend button
            if st.button("🔗 Test Backend Connection"):
                try:
                    health = client.check_health()
                    if "error" not in health:
                        st.success(f"✅ Backend is responding! Version: {health.get('version', 'unknown')}")
                    else:
                        st.error(f"❌ Backend error: {health.get('error', 'Unknown error')}")
                except Exception as e:
                    st.error(f"❌ Connection failed: {e}")
        else:
            # Basic dashboard metrics
            st.subheader("📊 System Overview")
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric("📁 Total Files", dashboard_data.get("total_files", 0))
            
            with col2:
                st.metric("📊 Analyses", dashboard_data.get("total_analyses", 0))
            
            with col3:
                st.metric("📋 Cases", dashboard_data.get("active_cases", 0))
            
            with col4:
                st.metric("⚠️ Alerts", dashboard_data.get("threat_alerts", 0))
            
            # Recent activity
            if dashboard_data.get("recent_activity"):
                st.subheader("📋 Recent Activity")
                for activity in dashboard_data.get("recent_activity", [])[:5]:
                    st.write(f"📄 {activity}")
            
            st.markdown("""
            <div class="success-box">
                <p>✅ Basic dashboard loaded successfully!</p>
                <p>Install the dashboard component for full features.</p>
            </div>
            """, unsafe_allow_html=True)
    
    except Exception as e:
        st.markdown(f"""
        <div class="error-box">
            <h4>❌ Dashboard Error</h4>
            <p>{str(e)}</p>
        </div>
        """, unsafe_allow_html=True)


def show_error_page(page_name, error_msg):
    """Show error page with helpful information"""
    st.title(f"📋 {page_name.title()}")
    
    st.markdown(f"""
    <div class="warning-box">
        <h4>⚠️ {page_name.title()} component not available</h4>
        <p>{error_msg}</p>
    </div>
    """, unsafe_allow_html=True)
    
    st.info("**Possible solutions:**")
    st.write(f"1. Check that `components/{page_name}.py` exists")
    st.write(f"2. Check for import errors in the component file")
    st.write(f"3. Install any missing dependencies")
    st.write(f"4. Restart the application")
    
    if st.button(f"🔄 Try to reload {page_name}"):
        st.rerun()


def main():
    """Main application entry point"""
    
    # Initialize state manager if available
    if UTILS_AVAILABLE:
        try:
            state = StateManager()
        except Exception as e:
            st.warning(f"⚠️ State manager initialization failed: {e}")
            state = None
    else:
        state = None
    
    # Display header
    st.markdown("""
    <div class="main-header">
        <h1>🔐 SecuNik</h1>
        <p>Ultimate Local Cybersecurity Analysis Platform</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Show debug info in development
    show_debug_info()
    
    # Check backend connection if utilities are available
    backend_connected = False
    if UTILS_AVAILABLE:
        try:
            backend_connected = check_backend_connection()
            if not backend_connected:
                st.error("❌ **Backend Server Not Available**")
                st.warning("Please start the backend server:")
                st.code("cd backend && python run.py", language="bash")
                st.info("🌐 Backend should be running on: http://localhost:8000")
                
                # Allow continuing in offline mode
                if st.button("Continue in Offline Mode"):
                    st.session_state.offline_mode = True
                    st.rerun()
                
                if not st.session_state.get("offline_mode", False):
                    st.stop()
        except Exception as e:
            st.warning(f"⚠️ Could not check backend connection: {e}")
    
    # Sidebar navigation
    with st.sidebar:
        st.markdown("### 🔐 SecuNik Navigation")
        
        # Display API status if available
        if UTILS_AVAILABLE and backend_connected:
            try:
                display_api_status()
            except Exception as e:
                st.warning(f"⚠️ Could not display API status: {e}")
        else:
            if not UTILS_AVAILABLE:
                st.error("🔴 Utilities Unavailable")
            elif not backend_connected:
                st.error("🔴 Backend Offline")
        
        # Navigation menu
        page_options = ["🏠 Dashboard"]
        
        # Add pages based on available components
        if COMPONENTS_AVAILABLE.get('file_upload', False):
            page_options.append("📤 Upload & Analyze")
        
        if COMPONENTS_AVAILABLE.get('analysis', False):
            page_options.append("📊 Analysis Results")
        
        if COMPONENTS_AVAILABLE.get('cases', False):
            page_options.append("📋 Case Management")
        
        if COMPONENTS_AVAILABLE.get('ai_chat', False):
            page_options.append("🤖 AI Assistant")
        
        if COMPONENTS_AVAILABLE.get('settings', False):
            page_options.append("⚙️ Settings")
        
        # Page selection
        selected_page = st.selectbox(
            "Select Page",
            options=page_options,
            index=0,
            key="main_page_selector"
        )
        
        # Map display names to component names
        page_mapping = {
            "🏠 Dashboard": "dashboard",
            "📤 Upload & Analyze": "file_upload",
            "📊 Analysis Results": "analysis",
            "📋 Case Management": "cases",
            "🤖 AI Assistant": "ai_chat",
            "⚙️ Settings": "settings"
        }
        
        page = page_mapping.get(selected_page, "dashboard")
        
        # Component status in sidebar
        st.markdown("---")
        with st.expander("🧩 Component Status"):
            for component, available in COMPONENTS_AVAILABLE.items():
                icon = "✅" if available else "❌"
                st.markdown(f'<div class="component-status">{icon} {component.replace("_", " ").title()}</div>', 
                           unsafe_allow_html=True)
        
        # Quick actions
        st.markdown("---")
        st.markdown("### ⚡ Quick Actions")
        
        col1, col2 = st.columns(2)
        with col1:
            if st.button("🔄 Refresh", use_container_width=True, key="sidebar_refresh"):
                st.rerun()
        
        with col2:
            if st.button("🗑️ Clear Cache", use_container_width=True, key="sidebar_clear_cache"):
                st.cache_data.clear()
                st.cache_resource.clear()
                st.success("Cache cleared!")
                st.rerun()
        
        # AI status in sidebar (if utilities available)
        if UTILS_AVAILABLE and backend_connected:
            try:
                client = get_api_client()
                ai_status = client.get_ai_status()
                
                if "error" not in ai_status:
                    if ai_status.get('ai_available', False):
                        st.markdown('<div class="status-online">🤖 AI Ready</div>', unsafe_allow_html=True)
                    else:
                        st.markdown('<div class="status-offline">🤖 AI Config Required</div>', unsafe_allow_html=True)
                        with st.expander("ℹ️ Setup AI"):
                            st.markdown("""
                            **To enable AI features:**
                            1. Get OpenAI API key from https://openai.com
                            2. Set environment variable:
                            ```bash
                            # Windows
                            set OPENAI_API_KEY=your-key-here
                            
                            # Linux/Mac  
                            export OPENAI_API_KEY=your-key-here
                            ```
                            3. Restart backend server
                            """)
            except Exception as e:
                st.warning(f"⚠️ Could not check AI status: {e}")
    
    # Main content area
    try:
        if page == "dashboard":
            if COMPONENTS_AVAILABLE['dashboard']:
                dashboard.show_dashboard()
            else:
                show_fallback_dashboard()
        
        elif page == "file_upload":
            if COMPONENTS_AVAILABLE['file_upload']:
                file_upload.show_upload_page()
            else:
                show_error_page("file_upload", "File upload component not available")
        
        elif page == "analysis":
            if COMPONENTS_AVAILABLE['analysis']:
                analysis.show_analysis_page()
            else:
                show_error_page("analysis", "Analysis component not available")
        
        elif page == "cases":
            if COMPONENTS_AVAILABLE['cases']:
                cases.show_cases_page()
            else:
                show_error_page("cases", "Cases component not available")
        
        elif page == "ai_chat":
            if COMPONENTS_AVAILABLE['ai_chat']:
                ai_chat.show_ai_chat()
            else:
                show_error_page("ai_chat", "AI Chat component not available")
        
        elif page == "settings":
            if COMPONENTS_AVAILABLE['settings']:
                settings.show_settings_page()
            else:
                show_error_page("settings", "Settings component not available")
        
        else:
            st.error(f"Page '{page}' not found")
            
    except Exception as e:
        st.error(f"❌ Error loading page: {e}")
        
        with st.expander("🔍 Error Details"):
            st.code(traceback.format_exc())
        
        if st.button("🔄 Reload Page", key="reload_page_button"):
            st.rerun()

    # Footer
    st.markdown("---")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.caption("🔐 SecuNik v1.0.0")
    
    with col2:
        st.caption("🏠 Local Analysis Platform")
    
    with col3:
        if UTILS_AVAILABLE and backend_connected:
            st.caption('<span class="status-online">🟢 Backend Online</span>', unsafe_allow_html=True)
        else:
            st.caption('<span class="status-offline">🔴 Backend Offline</span>', unsafe_allow_html=True)


if __name__ == "__main__":
    main()