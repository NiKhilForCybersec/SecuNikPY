import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

def render_analysis():
    """Render analysis results page"""
    
    st.markdown("## 🔍 Analysis Results")
    st.markdown("Review cybersecurity analysis findings and threat assessments")
    
    # Filters
    col1, col2, col3 = st.columns(3)
    
    with col1:
        filter_type = st.selectbox(
            "Filter by Type",
            ["All Results", "Threats Only", "Clean Files", "Suspicious"]
        )
    
    with col2:
        filter_date = st.date_input("Date Range")
    
    with col3:
        filter_case = st.selectbox(
            "Filter by Case",
            ["All Cases", "Case #047", "Case #046", "Case #045"]
        )
    
    # Summary metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Files Analyzed", "47", delta="12 today")
    
    with col2:
        st.metric("Threats Detected", "8", delta="3 high risk")
    
    with col3:
        st.metric("Clean Files", "39", delta="83% clean rate")
    
    with col4:
        st.metric("Avg Risk Score", "15/100", delta="-5 points")
    
    # Analysis results table
    st.markdown("### 📊 Detailed Analysis Results")
    
    # Sample data
    analysis_data = {
        'File Name': [
            'suspicious_email.eml',
            'system_backup.zip',
            'user_document.pdf',
            'network_capture.pcap',
            'registry_dump.reg'
        ],
        'Type': ['Email', 'Archive', 'Document', 'Network', 'Registry'],
        'Risk Score': [85, 23, 5, 67, 34],
        'Status': ['🔴 High Risk', '🟡 Medium Risk', '🟢 Clean', '🟡 Medium Risk', '🟡 Medium Risk'],
        'Threats': [3, 1, 0, 2, 1],
        'IOCs': [15, 3, 0, 8, 5],
        'Case ID': ['#047', '#046', '#047', '#045', '#046'],
        'Analysis Date': [
            '2024-01-30 14:32',
            '2024-01-30 13:45',
            '2024-01-30 12:15',
            '2024-01-30 11:30',
            '2024-01-30 10:22'
        ]
    }
    
    df = pd.DataFrame(analysis_data)
    
    # Interactive table with actions
    for i, row in df.iterrows():
        with st.expander(f"📄 {row['File Name']} - {row['Status']}", expanded=False):
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.write(f"**Type:** {row['Type']}")
                st.write(f"**Risk Score:** {row['Risk Score']}/100")
                st.write(f"**Case ID:** {row['Case ID']}")
            
            with col2:
                st.write(f"**Threats Found:** {row['Threats']}")
                st.write(f"**IOCs Extracted:** {row['IOCs']}")
                st.write(f"**Analyzed:** {row['Analysis Date']}")
            
            with col3:
                if st.button(f"📋 Full Report", key=f"report_{i}"):
                    show_detailed_report(row['File Name'])
                
                if st.button(f"🔍 Re-analyze", key=f"reanalyze_{i}"):
                    st.info(f"Re-analysis queued for {row['File Name']}")
                
                if st.button(f"📤 Export", key=f"export_{i}"):
                    st.success(f"Exported analysis for {row['File Name']}")
    
    # Risk distribution chart
    st.markdown("### 📈 Risk Score Distribution")
    
    fig = px.histogram(
        df, 
        x='Risk Score', 
        nbins=10,
        title="Distribution of Risk Scores",
        labels={'Risk Score': 'Risk Score (0-100)', 'count': 'Number of Files'}
    )
    fig.update_layout(
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
    )
    st.plotly_chart(fig, use_container_width=True)
    
    # Export options
    st.markdown("### 📤 Export Options")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("📄 Export PDF Report", use_container_width=True):
            st.success("PDF report generated successfully!")
    
    with col2:
        if st.button("📊 Export CSV Data", use_container_width=True):
            csv = df.to_csv(index=False)
            st.download_button(
                label="📥 Download CSV",
                data=csv,
                file_name='analysis_results.csv',
                mime='text/csv'
            )
    
    with col3:
        if st.button("📋 Export JSON", use_container_width=True):
            json_data = df.to_json(orient='records', indent=2)
            st.download_button(
                label="📥 Download JSON",
                data=json_data,
                file_name='analysis_results.json',
                mime='application/json'
            )

def show_detailed_report(filename):
    """Show detailed analysis report for a file"""
    st.info(f"""
    📋 **Detailed Analysis Report for {filename}**
    
    **Threat Assessment:**
    - Malware signatures: 2 detected
    - Suspicious patterns: 5 found
    - Network connections: 3 external IPs
    
    **IOC Analysis:**
    - Domains: 4 suspicious
    - IP Addresses: 8 flagged
    - File hashes: 2 in threat database
    
    **Recommendations:**
    - Quarantine immediately
    - Block network connections
    - Update security policies
    """)