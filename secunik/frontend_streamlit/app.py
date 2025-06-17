"""
SecuNik - Ultimate Local Cybersecurity Analysis Platform
Main Streamlit Application
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

# Add utils and components to path
current_dir = Path(__file__).parent
utils_dir = current_dir / "utils"
components_dir = current_dir / "components"

if str(utils_dir) not in sys.path:
    sys.path.insert(0, str(utils_dir))
if str(components_dir) not in sys.path:
    sys.path.insert(0, str(components_dir))

# Import utilities first
try:
    from api_client import get_api_client, display_api_status, check_backend_connection
    from state_manager import StateManager
    UTILS_AVAILABLE = True
except ImportError as e:
    st.error(f"❌ Could not import utilities: {e}")
    st.warning("Please ensure utils/api_client.py and utils/state_manager.py exist")
    UTILS_AVAILABLE = False

# Import components with error handling
COMPONENTS_AVAILABLE = {}

# Try importing each component individually
try:
    import dashboard
    COMPONENTS_AVAILABLE['dashboard'] = True
except ImportError as e:
    st.warning(f"⚠️ Dashboard component not available: {e}")
    COMPONENTS_AVAILABLE['dashboard'] = False

try:
    import file_upload
    COMPONENTS_AVAILABLE['file_upload'] = True
except ImportError as e:
    st.warning(f"⚠️ File upload component not available: {e}")
    COMPONENTS_AVAILABLE['file_upload'] = False

try:
    import analysis
    COMPONENTS_AVAILABLE['analysis'] = True
except ImportError as e:
    st.warning(f"⚠️ Analysis component not available: {e}")
    COMPONENTS_AVAILABLE['analysis'] = False

try:
    import cases
    COMPONENTS_AVAILABLE['cases'] = True
except ImportError as e:
    st.warning(f"⚠️ Cases component not available: {e}")
    COMPONENTS_AVAILABLE['cases'] = False

try:
    import settings
    COMPONENTS_AVAILABLE['settings'] = True
except ImportError as e:
    st.warning(f"⚠️ Settings component not available: {e}")
    COMPONENTS_AVAILABLE['settings'] = False

# Try to import AI chat component
try:
    import ai_chat
    COMPONENTS_AVAILABLE['ai_chat'] = True
    AI_AVAILABLE = True
except ImportError:
    COMPONENTS_AVAILABLE['ai_chat'] = False
    AI_AVAILABLE = False

# Custom CSS
st.markdown("""
<style>
/* Custom styling for SecuNik */
.main-header {
    background: linear-gradient(90deg, #1e3c72 0%, #2a5298 100%);
    padding: 1rem;
    border-radius: 10px;
    color: white;
    text-align: center;
    margin-bottom: 2rem;
}

.metric-card {
    background: #f8f9fa;
    padding: 1rem;
    border-radius: 8px;
    border-left: 4px solid #2a5298;
    margin: 0.5rem 0;
}

.threat-high {
    background-color: #ffebee;
    border-left: 4px solid #f44336;
    padding: 1rem;
    border-radius: 4px;
}

.threat-medium {
    background-color: #fff3e0;
    border-left: 4px solid #ff9800;
    padding: 1rem;
    border-radius: 4px;
}

.threat-low {
    background-color: #e8f5e8;
    border-left: 4px solid #4caf50;
    padding: 1rem;
    border-radius: 4px;
}

.upload-area {
    border: 2px dashed #ccc;
    border-radius: 10px;
    padding: 2rem;
    text-align: center;
    background: #fafafa;
}

.ai-chat {
    background: #f0f2f6;
    border-radius: 10px;
    padding: 1rem;
    border: 1px solid #e0e2e6;
}

.sidebar-section {
    background: #f8f9fa;
    padding: 1rem;
    border-radius: 8px;
    margin: 1rem 0;
}
</style>
""", unsafe_allow_html=True)


def show_fallback_dashboard():
    """Fallback dashboard when components aren't available"""
    st.title("🏠 Dashboard")
    
    if not UTILS_AVAILABLE:
        st.error("❌ Utilities not available - cannot connect to backend")
        return
    
    try:
        client = get_api_client()
        dashboard_data = client.get_dashboard_data()
        
        if "error" in dashboard_data:
            st.error("❌ Could not load dashboard data from backend")
            st.info("Make sure the backend is running on localhost:8000")
        else:
            # Basic dashboard metrics
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric("📁 Total Files", dashboard_data.get("total_files", 0))
            
            with col2:
                st.metric("📊 Analyses", dashboard_data.get("total_analyses", 0))
            
            with col3:
                st.metric("📋 Cases", dashboard_data.get("active_cases", 0))
            
            with col4:
                st.metric("⚠️ Alerts", dashboard_data.get("threat_alerts", 0))
            
            st.success("✅ Basic dashboard loaded - install components for full features")
    
    except Exception as e:
        st.error(f"❌ Error loading dashboard: {e}")


def show_fallback_upload():
    """Fallback upload page"""
    st.title("📤 Upload & Analyze Files")
    st.warning("⚠️ Upload component not available")
    st.info("Please install the file_upload component for full functionality")
    
    # Basic file uploader
    uploaded_file = st.file_uploader("Choose a file", type=['pdf', 'doc', 'zip', 'exe', 'log'])
    
    if uploaded_file:
        st.success(f"File selected: {uploaded_file.name}")
        st.info("Install components for analysis functionality")


def show_fallback_page(page_name):
    """Show fallback page for missing components"""
    st.title(f"📋 {page_name.title()}")
    st.warning(f"⚠️ {page_name.title()} component not available")
    st.info("Please install the component files to enable this feature")
    
    with st.expander("🔧 Installation Instructions"):
        st.markdown(f"""
        **To enable {page_name}:**
        1. Ensure `components/{page_name}.py` exists
        2. Verify the file contains the required functions
        3. Check for any import errors in the component
        4. Restart the application
        """)


def main():
    """Main application"""
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
        pages = {
            "🏠 Dashboard": "dashboard"
        }
        
        # Add pages based on available components
        if COMPONENTS_AVAILABLE.get('file_upload', False):
            pages["📤 Upload & Analyze"] = "upload"
        
        if COMPONENTS_AVAILABLE.get('analysis', False):
            pages["📊 Analysis Results"] = "analysis"
        
        if COMPONENTS_AVAILABLE.get('cases', False):
            pages["📋 Case Management"] = "cases"
        
        if COMPONENTS_AVAILABLE.get('settings', False):
            pages["⚙️ Settings"] = "settings"
        
        # Add AI Chat if available
        if COMPONENTS_AVAILABLE.get('ai_chat', False):
            pages["🤖 AI Assistant"] = "ai_chat"
        
        # Page selection
        selected_page = st.selectbox(
            "Select Page",
            options=list(pages.keys()),
            index=0,
            key="page_selector"
        )
        
        page = pages[selected_page]
        
        # Component status
        st.markdown("---")
        st.markdown("### 📊 Component Status")
        
        for component, available in COMPONENTS_AVAILABLE.items():
            icon = "✅" if available else "❌"
            st.write(f"{icon} {component.replace('_', ' ').title()}")
        
        # Quick actions
        st.markdown("---")
        st.markdown("### ⚡ Quick Actions")
        
        col1, col2 = st.columns(2)
        with col1:
            if st.button("🔄 Refresh", use_container_width=True):
                st.rerun()
        
        with col2:
            if st.button("🗑️ Clear Cache", use_container_width=True):
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
                        st.success("🤖 AI Ready")
                    else:
                        st.warning("🤖 AI Config Required")
                        with st.expander("ℹ️ Setup AI"):
                            st.markdown("""
                            **To enable AI features:**
                            1. Get OpenAI API key
                            2. Set environment variable:
                            ```bash
                            export OPENAI_API_KEY="your-key"
                            ```
                            3. Restart backend
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
        
        elif page == "upload":
            if COMPONENTS_AVAILABLE['file_upload']:
                file_upload.show_upload_page()
            else:
                show_fallback_upload()
        
        elif page == "analysis":
            if COMPONENTS_AVAILABLE['analysis']:
                analysis.show_analysis_page()
            else:
                show_fallback_page("analysis")
        
        elif page == "cases":
            if COMPONENTS_AVAILABLE['cases']:
                cases.show_cases_page()
            else:
                show_fallback_page("cases")
        
        elif page == "ai_chat":
            if COMPONENTS_AVAILABLE['ai_chat']:
                ai_chat.show_ai_chat()
            else:
                show_fallback_page("ai_chat")
        
        elif page == "settings":
            if COMPONENTS_AVAILABLE['settings']:
                settings.show_settings_page()
            else:
                show_fallback_page("settings")
        
        else:
            st.error(f"Page '{page}' not found")
            
    except Exception as e:
        st.error(f"❌ Error loading page: {e}")
        
        with st.expander("🔍 Error Details"):
            st.code(traceback.format_exc())
        
        if st.button("🔄 Reload Page"):
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
            st.caption("🟢 Backend Online")
        else:
            st.caption("🔴 Backend Offline")


if __name__ == "__main__":
    main()