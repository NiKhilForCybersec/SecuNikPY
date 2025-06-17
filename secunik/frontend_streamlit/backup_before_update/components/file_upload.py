"""
File Upload Component for SecuNik
Handles file uploads and immediate analysis
"""

import streamlit as st
import time
from utils.api_client import get_api_client, format_file_size, format_timestamp, get_severity_color, get_risk_score_color


def show_upload_page():
    """Display the file upload page"""
    st.title("📤 Upload & Analyze Files")
    
    client = get_api_client()
    
    # Upload section
    show_upload_section(client)
    
    st.markdown("---")
    
    # File management section
    show_file_management(client)


def show_upload_section(client):
    """Show file upload interface"""
    st.subheader("📁 Upload File for Analysis")
    
    # File uploader
    uploaded_file = st.file_uploader(
        "Choose a file to analyze",
        type=['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 
              'zip', 'rar', '7z', 'tar', 'gz',
              'exe', 'dll', 'sys', 'bat', 'ps1',
              'log', 'txt', 'csv', 'json', 'xml',
              'pcap', 'pcapng', 'cap',
              'pst', 'ost', 'eml', 'msg',
              'reg', 'dat'],
        help="Supported: Documents, Archives, Executables, Logs, Network captures, Email files, Registry files"
    )
    
    if uploaded_file is not None:
        # Display file info
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.info(f"📄 **File:** {uploaded_file.name}")
        
        with col2:
            st.info(f"📊 **Size:** {format_file_size(uploaded_file.size)}")
        
        with col3:
            file_type = uploaded_file.name.split('.')[-1].upper()
            st.info(f"🏷️ **Type:** {file_type}")
        
        # Upload and analyze button
        if st.button("🚀 Upload & Analyze", type="primary", use_container_width=True):
            analyze_uploaded_file(client, uploaded_file)


def analyze_uploaded_file(client, uploaded_file):
    """Upload and analyze the file"""
    # Progress indicators
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    try:
        # Step 1: Upload file
        status_text.text("📤 Uploading file...")
        progress_bar.progress(25)
        
        # Read file data
        file_data = uploaded_file.read()
        
        # Upload to backend
        upload_result = client.upload_file(file_data, uploaded_file.name)
        
        if "error" in upload_result:
            st.error(f"❌ Upload failed: {upload_result['error']}")
            return
        
        progress_bar.progress(50)
        status_text.text("🔍 Analyzing file...")
        
        # Small delay to show progress
        time.sleep(1)
        
        progress_bar.progress(75)
        status_text.text("📊 Processing results...")
        
        # Get analysis results
        file_id = upload_result.get("file_id")
        analysis = upload_result.get("analysis", {})
        
        progress_bar.progress(100)
        status_text.text("✅ Analysis complete!")
        
        # Display results
        time.sleep(0.5)
        progress_bar.empty()
        status_text.empty()
        
        display_analysis_results(analysis, file_id, uploaded_file.name)
        
        # Success message
        st.success(f"✅ **{uploaded_file.name}** uploaded and analyzed successfully!")
        
        # Offer additional analysis options
        show_additional_analysis_options(client, file_id)
        
    except Exception as e:
        progress_bar.empty()
        status_text.empty()
        st.error(f"❌ Error during upload/analysis: {str(e)}")


def display_analysis_results(analysis, file_id, filename):
    """Display the analysis results"""
    st.subheader("📊 Analysis Results")
    
    # Basic info
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        parser_name = analysis.get("parser_name", "unknown")
        st.metric("🔧 Parser", parser_name.replace("_", " ").title())
    
    with col2:
        analysis_type = analysis.get("analysis_type", "unknown")
        st.metric("📋 Type", analysis_type.title())
    
    with col3:
        severity = analysis.get("severity", "LOW")
        color = get_severity_color(severity)
        st.metric("⚠️ Severity", severity)
        st.markdown(f"<div style='color: {color}'>■ {severity}</div>", unsafe_allow_html=True)
    
    with col4:
        risk_score = analysis.get("risk_score", 0.0)
        color = get_risk_score_color(risk_score)
        st.metric("🎯 Risk Score", f"{risk_score:.2f}")
        st.markdown(f"<div style='color: {color}'>■ Risk: {risk_score:.1%}</div>", unsafe_allow_html=True)
    
    # Summary
    summary = analysis.get("summary", "")
    if summary:
        st.markdown("**📝 Summary:**")
        st.info(summary)
    
    # Threats detected
    threats = analysis.get("threats_detected", [])
    if threats:
        st.markdown("**⚠️ Threats Detected:**")
        
        for i, threat in enumerate(threats):
            threat_type = threat.get("type", "unknown")
            description = threat.get("description", "No description")
            threat_severity = threat.get("severity", "LOW")
            
            color = get_severity_color(threat_severity)
            
            with st.expander(f"🚨 Threat {i+1}: {threat_type}"):
                st.markdown(f"**Type:** {threat_type}")
                st.markdown(f"**Severity:** <span style='color: {color}'>{threat_severity}</span>", unsafe_allow_html=True)
                st.markdown(f"**Description:** {description}")
    else:
        st.success("✅ No threats detected")
    
    # Recommendations
    recommendations = analysis.get("recommendations", [])
    if recommendations:
        st.markdown("**💡 Recommendations:**")
        for i, rec in enumerate(recommendations, 1):
            st.markdown(f"{i}. {rec}")
    
    # File details
    details = analysis.get("details", {})
    if details:
        with st.expander("🔍 File Details"):
            for key, value in details.items():
                if key != "original_filename":  # Skip redundant info
                    st.write(f"**{key.replace('_', ' ').title()}:** {value}")


def show_additional_analysis_options(client, file_id):
    """Show additional analysis options"""
    st.subheader("🔬 Additional Analysis")
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("🤖 AI Enhanced Analysis", use_container_width=True):
            perform_ai_analysis(client, file_id)
    
    with col2:
        if st.button("🔄 Reanalyze", use_container_width=True):
            perform_reanalysis(client, file_id)


def perform_ai_analysis(client, file_id):
    """Perform AI-enhanced analysis"""
    with st.spinner("🤖 Running AI analysis..."):
        ai_result = client.ai_analyze_file(file_id)
        
        if "error" in ai_result:
            if "unavailable" in ai_result.get("status", ""):
                st.warning("⚠️ AI analysis requires OpenAI API key configuration")
                with st.expander("ℹ️ Setup Instructions"):
                    st.markdown("""
                    **To enable AI analysis:**
                    1. Get an OpenAI API key from https://openai.com
                    2. Set environment variable: `export OPENAI_API_KEY="your-key"`
                    3. Restart the backend server
                    """)
            else:
                st.error(f"❌ AI analysis failed: {ai_result['error']}")
            return
        
        st.success("✅ AI analysis completed!")
        
        # Display AI insights
        ai_insights = ai_result.get("ai_insights", [])
        if ai_insights:
            st.markdown("**🧠 AI Insights:**")
            for insight in ai_insights:
                st.markdown(f"• {insight}")
        
        # Display AI recommendations
        ai_recommendations = ai_result.get("ai_recommendations", [])
        if ai_recommendations:
            st.markdown("**🤖 AI Recommendations:**")
            for rec in ai_recommendations:
                st.markdown(f"• {rec}")
        
        confidence = ai_result.get("confidence", 0.0)
        st.metric("🎯 AI Confidence", f"{confidence:.1%}")


def perform_reanalysis(client, file_id):
    """Perform reanalysis with different parameters"""
    with st.form("reanalysis_form"):
        st.markdown("**🔄 Reanalysis Options**")
        
        analysis_type = st.selectbox(
            "Analysis Type",
            ["standard", "deep", "quick", "comprehensive"],
            help="Choose analysis depth"
        )
        
        enable_ai = st.checkbox("Enable AI Enhancement", help="Use AI for enhanced analysis")
        
        if st.form_submit_button("🚀 Start Reanalysis"):
            with st.spinner("🔄 Reanalyzing..."):
                options = {"enable_ai": enable_ai}
                result = client.reanalyze_file(file_id, analysis_type, options)
                
                if "error" in result:
                    st.error(f"❌ Reanalysis failed: {result['error']}")
                else:
                    st.success("✅ Reanalysis completed!")
                    # Refresh to show new results
                    st.rerun()


def show_file_management(client):
    """Show uploaded files management"""
    st.subheader("📁 File Management")
    
    # Get list of files
    files_data = client.list_files()
    
    if "error" in files_data:
        st.error("❌ Could not load file list")
        return
    
    files = files_data.get("files", [])
    
    if not files:
        st.info("📭 No files uploaded yet. Upload a file above to get started!")
        return
    
    # Display files in a table format
    st.markdown(f"**📊 Total Files: {len(files)}**")
    
    for file_info in files:
        with st.container():
            col1, col2, col3, col4, col5 = st.columns([3, 1, 1, 1, 1])
            
            with col1:
                filename = file_info.get("filename", "unknown")
                file_id = file_info.get("file_id", "")
                st.markdown(f"**📄 {filename}**")
                st.caption(f"ID: {file_id[:8]}...")
            
            with col2:
                analysis_type = file_info.get("analysis_type", "unknown")
                st.write(f"🔧 {analysis_type.title()}")
            
            with col3:
                severity = file_info.get("severity", "LOW")
                color = get_severity_color(severity)
                st.markdown(f"<span style='color: {color}'>⚠️ {severity}</span>", unsafe_allow_html=True)
            
            with col4:
                risk_score = file_info.get("risk_score", 0.0)
                color = get_risk_score_color(risk_score)
                st.markdown(f"<span style='color: {color}'>🎯 {risk_score:.2f}</span>", unsafe_allow_html=True)
            
            with col5:
                if st.button("🗑️", key=f"delete_{file_id}", help="Delete file"):
                    delete_file(client, file_id, filename)
        
        st.markdown("---")


def delete_file(client, file_id, filename):
    """Delete a file"""
    if st.session_state.get(f"confirm_delete_{file_id}", False):
        # Actually delete
        result = client.delete_file(file_id)
        
        if "error" in result:
            st.error(f"❌ Failed to delete {filename}")
        else:
            st.success(f"✅ Deleted {filename}")
            # Clear confirmation state
            if f"confirm_delete_{file_id}" in st.session_state:
                del st.session_state[f"confirm_delete_{file_id}"]
            st.rerun()
    else:
        # Ask for confirmation
        st.session_state[f"confirm_delete_{file_id}"] = True
        st.warning(f"⚠️ Really delete {filename}? Click delete again to confirm.")
        st.rerun()


def show_upload_tips():
    """Show upload tips and supported formats"""
    with st.expander("💡 Upload Tips & Supported Formats"):
        st.markdown("""
        **📋 Supported File Types:**
        
        **📄 Documents:**
        - PDF files (.pdf)
        - Microsoft Office (.doc, .docx, .xls, .xlsx, .ppt, .pptx)
        
        **📦 Archives:**
        - ZIP, RAR, 7-Zip (.zip, .rar, .7z)
        - TAR, GZIP (.tar, .gz)
        
        **💻 Executables:**
        - PE files (.exe, .dll, .sys)
        - Scripts (.bat, .ps1)
        
        **📝 Log Files:**
        - Text logs (.log, .txt)
        - Structured data (.csv, .json, .xml)
        
        **🌐 Network Captures:**
        - PCAP files (.pcap, .pcapng, .cap)
        
        **📧 Email Files:**
        - Outlook files (.pst, .ost)
        - Email messages (.eml, .msg)
        
        **🪟 Windows Registry:**
        - Registry files (.reg, .dat)
        
        **💡 Tips:**
        - Maximum file size: 100MB
        - Files are analyzed locally (never uploaded to cloud)
        - Analysis results are stored locally
        - Enable AI for enhanced threat detection
        """)