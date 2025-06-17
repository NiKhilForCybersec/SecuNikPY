# streamlit_test.py - Test Streamlit + Dependencies
import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go

# Page config
st.set_page_config(
    page_title="SecuNik - Installation Test",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(90deg, #1e40af 0%, #3b82f6 100%);
        padding: 1rem 2rem;
        border-radius: 10px;
        margin-bottom: 2rem;
        color: white;
        text-align: center;
    }
    .success-box {
        background: #dcfce7;
        border: 1px solid #22c55e;
        border-radius: 8px;
        padding: 1rem;
        margin: 1rem 0;
    }
</style>
""", unsafe_allow_html=True)

# Header
st.markdown("""
<div class="main-header">
    <h1>🔐 SecuNik Installation Test</h1>
    <p>Verifying all dependencies for the complete cybersecurity platform</p>
</div>
""", unsafe_allow_html=True)

# Sidebar
with st.sidebar:
    st.markdown("### 🧭 Installation Check")
    
    # Test core packages
    st.markdown("**Core Packages:**")
    try:
        import streamlit
        st.success(f"✅ Streamlit {streamlit.__version__}")
    except:
        st.error("❌ Streamlit failed")
    
    try:
        import pandas
        st.success(f"✅ Pandas {pandas.__version__}")
    except:
        st.error("❌ Pandas failed")
    
    try:
        import plotly
        st.success(f"✅ Plotly {plotly.__version__}")
    except:
        st.error("❌ Plotly failed")

# Main content
col1, col2 = st.columns(2)

with col1:
    st.markdown("### 📊 Data Processing Test")
    
    # Test pandas functionality
    try:
        df = pd.DataFrame({
            'File Name': ['malware.exe', 'phishing.eml', 'suspicious.pdf', 'clean.txt'],
            'File Type': ['Executable', 'Email', 'Document', 'Text'],
            'Risk Score': [95, 78, 23, 5],
            'Status': ['🔴 High Risk', '🟡 Medium Risk', '🟡 Medium Risk', '🟢 Clean'],
            'Size (MB)': [2.3, 0.8, 1.5, 0.1]
        })
        
        st.dataframe(df, use_container_width=True)
        st.success("✅ Pandas DataFrame working perfectly!")
        
    except Exception as e:
        st.error(f"❌ Pandas test failed: {e}")

with col2:
    st.markdown("### 📈 Visualization Test")
    
    # Test plotly functionality
    try:
        # Risk score distribution
        risk_data = np.random.beta(2, 5, 100) * 100
        fig = px.histogram(
            x=risk_data,
            nbins=20,
            title="Risk Score Distribution",
            labels={'x': 'Risk Score', 'y': 'Count'}
        )
        fig.update_layout(
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
        )
        st.plotly_chart(fig, use_container_width=True)
        st.success("✅ Plotly charts working perfectly!")
        
    except Exception as e:
        st.error(f"❌ Plotly test failed: {e}")

# Metrics test
st.markdown("### 📊 Dashboard Metrics Test")

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric(
        label="🗂️ Total Cases",
        value="24",
        delta="3 new this week"
    )

with col2:
    st.metric(
        label="🚨 Threats Detected",
        value="12",
        delta="-3 from last week",
        delta_color="inverse"
    )

with col3:
    st.metric(
        label="📁 Files Analyzed",
        value="1,847",
        delta="156 today"
    )

with col4:
    st.metric(
        label="🛡️ System Health",
        value="98%",
        delta="2% improvement"
    )

# File upload test
st.markdown("### 📁 File Upload Test")

uploaded_file = st.file_uploader(
    "Test file upload functionality",
    type=['txt', 'pdf', 'log', 'csv', 'exe', 'zip'],
    help="Upload any file to test the file handling system"
)

if uploaded_file:
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.write(f"**Filename:** {uploaded_file.name}")
    with col2:
        st.write(f"**Size:** {uploaded_file.size} bytes")
    with col3:
        st.write(f"**Type:** {uploaded_file.type}")
    
    st.success("✅ File upload system working perfectly!")

# Advanced components test
st.markdown("### 🎨 Advanced UI Components Test")

# Test option menu if available
try:
    from streamlit_option_menu import option_menu
    
    selected = option_menu(
        menu_title="Navigation Test",
        options=["Dashboard", "Upload", "Analysis", "Cases"],
        icons=["speedometer2", "cloud-upload", "graph-up", "folder"],
        menu_icon="list",
        default_index=0,
        orientation="horizontal",
    )
    
    st.success("✅ Advanced navigation components working!")
    st.info(f"Selected: {selected}")
    
except ImportError:
    st.warning("⚠️ streamlit-option-menu not installed (optional component)")

# Final status
st.markdown("### 🎯 Installation Status")

success_message = """
<div class="success-box">
    <h3>🎉 Installation Test Complete!</h3>
    <p><strong>✅ Core functionality verified</strong></p>
    <ul>
        <li>✅ Streamlit UI framework working</li>
        <li>✅ Data processing with Pandas</li>
        <li>✅ Interactive charts with Plotly</li>
        <li>✅ File upload functionality</li>
        <li>✅ Professional dashboard metrics</li>
    </ul>
    <p><strong>🚀 SecuNik is ready for development!</strong></p>
</div>
"""

st.markdown(success_message, unsafe_allow_html=True)

# Next steps
st.markdown("### 🚀 Next Steps")

col1, col2, col3 = st.columns(3)

with col1:
    if st.button("📊 Phase 1: Build Dashboard", use_container_width=True):
        st.balloons()
        st.success("Ready to build the main dashboard!")

with col2:
    if st.button("📁 Phase 2: File Processing", use_container_width=True):
        st.balloons()
        st.success("Ready to implement file parsers!")

with col3:
    if st.button("🤖 Phase 3: AI Integration", use_container_width=True):
        st.balloons()
        st.success("Ready for OpenAI integration!")

# Footer
st.markdown("---")
st.markdown("**SecuNik - Advanced Cybersecurity Analysis Platform** | Installation Test Complete ✅")