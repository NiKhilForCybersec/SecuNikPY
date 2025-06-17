# components/file_upload.py
import streamlit as st
import os
import tempfile
import magic
from pathlib import Path
import requests

def render_file_upload():
    """Render file upload interface"""
    
    st.markdown("## 📁 Evidence File Upload")
    st.markdown("Upload and analyze digital evidence files for cybersecurity investigation")
    
    # Upload area
    st.markdown("### 📤 Upload Files")
    
    uploaded_files = st.file_uploader(
        "Choose files to upload",
        accept_multiple_files=True,
        type=None,  # Accept all file types
        help="Supports: PDF, DOC, EML, PST, LOG, ZIP, PCAP, EVTX, REG, MEM, DMP, IMG and more"
    )
    
    if uploaded_files:
        st.markdown("### 📋 File Queue")
        
        for i, uploaded_file in enumerate(uploaded_files):
            with st.expander(f"📄 {uploaded_file.name}", expanded=True):
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    st.write(f"**Size:** {format_file_size(uploaded_file.size)}")
                
                with col2:
                    file_type = get_file_type(uploaded_file)
                    st.write(f"**Type:** {file_type}")
                
                with col3:
                    st.write(f"**Status:** 🟡 Pending")
                
                # File actions
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    if st.button(f"🔍 Analyze", key=f"analyze_{i}"):
                        analyze_file(uploaded_file)
                
                with col2:
                    if st.button(f"ℹ️ Details", key=f"details_{i}"):
                        show_file_details(uploaded_file)
                
                with col3:
                    if st.button(f"🗑️ Remove", key=f"remove_{i}"):
                        st.success(f"Removed {uploaded_file.name}")
        
        # Batch actions
        st.markdown("### ⚡ Batch Actions")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if st.button("🚀 Analyze All Files", use_container_width=True):
                analyze_all_files(uploaded_files)
        
        with col2:
            if st.button("📊 Generate Report", use_container_width=True):
                generate_batch_report(uploaded_files)
        
        with col3:
            if st.button("🗑️ Clear All", use_container_width=True):
                st.rerun()
    
    # File format support
    st.markdown("### 📋 Supported File Formats")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown("""
        **Documents**
        - PDF, DOC, DOCX
        - TXT, RTF, ODT
        - XLS, XLSX, CSV
        """)
    
    with col2:
        st.markdown("""
        **Email & Communication**
        - EML, MSG, PST
        - OST, MBOX
        - Outlook files
        """)
    
    with col3:
        st.markdown("""
        **Forensic Images**
        - DD, IMG, RAW
        - E01 (Expert Witness)
        - VMDK, VHD
        """)
    
    with col4:
        st.markdown("""
        **System Files**
        - LOG, EVTX, REG
        - MEM, DMP
        - PCAP, CAP
        """)
    
    # Upload statistics
    with st.sidebar:
        st.markdown("### 📊 Upload Stats")
        st.metric("Files in Queue", len(uploaded_files) if uploaded_files else 0)
        
        if uploaded_files:
            total_size = sum(f.size for f in uploaded_files)
            st.metric("Total Size", format_file_size(total_size))

def analyze_file(uploaded_file):
    """Analyze a single file"""
    with st.spinner(f"Analyzing {uploaded_file.name}..."):
        # Simulate analysis
        import time
        time.sleep(2)
        
        st.success(f"✅ Analysis completed for {uploaded_file.name}")
        
        # Show analysis results
        with st.expander("📊 Analysis Results", expanded=True):
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric("Risk Score", "23/100", delta="-12 points")
            
            with col2:
                st.metric("Threats Found", "0", delta="Safe")
            
            with col3:
                st.metric("IOCs Extracted", "15", delta="5 new")

def analyze_all_files(uploaded_files):
    """Analyze all uploaded files"""
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    for i, file in enumerate(uploaded_files):
        status_text.text(f"Analyzing {file.name}...")
        progress_bar.progress((i + 1) / len(uploaded_files))
        
        # Simulate processing time
        import time
        time.sleep(1)
    
    status_text.text("Analysis completed!")
    st.success(f"✅ Successfully analyzed {len(uploaded_files)} files")

def show_file_details(uploaded_file):
    """Show detailed file information"""
    st.info(f"""
    **File Details for {uploaded_file.name}:**
    - Size: {format_file_size(uploaded_file.size)}
    - Type: {get_file_type(uploaded_file)}
    - Upload Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    """)

def generate_batch_report(uploaded_files):
    """Generate report for all files"""
    st.info(f"📄 Generating comprehensive report for {len(uploaded_files)} files...")

def get_file_type(uploaded_file):
    """Detect file type"""
    if uploaded_file.name.endswith('.pdf'):
        return 'PDF Document'
    elif uploaded_file.name.endswith(('.doc', '.docx')):
        return 'Word Document'
    elif uploaded_file.name.endswith('.eml'):
        return 'Email Message'
    elif uploaded_file.name.endswith('.zip'):
        return 'ZIP Archive'
    elif uploaded_file.name.endswith('.log'):
        return 'Log File'
    else:
        return 'Unknown'

def format_file_size(size_bytes):
    """Format file size in human-readable format"""
    if size_bytes == 0:
        return "0 B"
    
    size_names = ["B", "KB", "MB", "GB", "TB"]
    import math
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return f"{s} {size_names[i]}"