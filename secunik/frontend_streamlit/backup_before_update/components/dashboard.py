"""
SecuNik - Ultimate Local Cybersecurity Analysis Platform
Main Streamlit Application
"""

import streamlit as st
import sys
from pathlib import Path

# Add utils to path
current_dir = Path(__file__).parent
utils_dir = current_dir / "utils"
if str(utils_dir) not in sys.path:
    sys.path.insert(0, str(utils_dir))

# Add components to path
components_dir = current_dir / "components"
if str(components_dir) not in sys.path:
    sys.path.insert(0, str(components_dir))

# Import components and utilities
from utils.api_client import get_api_client, display_api_status, check_backend_connection
from utils.state_manager import StateManager

# Import component modules
import dashboard
import file_upload
import analysis
import cases
import settings

# Try to import AI chat component
try:
    import ai_chat
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False

# Configure Streamlit page
st.set_page_config(
    page_title="SecuNik - Cybersecurity Analysis Platform",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

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

def main():
    """Main application"""
    # Initialize state manager
    state = StateManager()
    
    # Display header
    st.markdown("""
    <div class="main-header">
        <h1>🔐 SecuNik</h1>
        <p>Ultimate Local Cybersecurity Analysis Platform</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Check backend connection
    if not check_backend_connection():
        st.error("❌ **Backend Server Not Available**")
        st.warning("Please start the backend server:")
        st.code("cd backend && python run.py", language="bash")
        st.info("🌐 Backend should be running on: http://localhost:8000")
        st.stop()
    
    # Sidebar navigation
    with st.sidebar:
        st.markdown("### 🔐 SecuNik Navigation")
        
        # Display API status
        display_api_status()
        
        # Navigation menu
        pages = {
            "🏠 Dashboard": "dashboard",
            "📤 Upload & Analyze": "upload", 
            "📊 Analysis Results": "analysis",
            "📋 Case Management": "cases",
            "⚙️ Settings": "settings"
        }
        
        # Add AI Chat if available
        if AI_AVAILABLE:
            pages["🤖 AI Assistant"] = "ai_chat"
        
        # Page selection
        selected_page = st.selectbox(
            "Select Page",
            options=list(pages.keys()),
            index=0,
            key="page_selector"
        )
        
        page = pages[selected_page]
        
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
        
        # AI status in sidebar
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
    
    # Main content area
    try:
        if page == "dashboard":
            dashboard.show_dashboard()
        elif page == "upload":
            file_upload.show_upload_page()
        elif page == "analysis":
            analysis.show_analysis_page()
        elif page == "cases":
            cases.show_cases_page()
        elif page == "ai_chat" and AI_AVAILABLE:
            ai_chat.show_ai_chat()
        elif page == "settings":
            settings.show_settings_page()
        else:
            st.error(f"Page '{page}' not found or not available")
            
    except Exception as e:
        st.error(f"❌ Error loading page: {e}")
        
        with st.expander("🔍 Error Details"):
            st.code(str(e))
        
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
        if check_backend_connection():
            st.caption("🟢 Backend Online")
        else:
            st.caption("🔴 Backend Offline")

if __name__ == "__main__":
    main()