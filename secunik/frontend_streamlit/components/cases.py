import streamlit as st
import pandas as pd
from datetime import datetime, timedelta

def render_cases():
    """Render case management interface"""
    
    st.markdown("## 📁 Case Management")
    st.markdown("Manage cybersecurity investigation cases and evidence tracking")
    
    # Cases overview
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Cases", "24", delta="3 new")
    
    with col2:
        st.metric("Active Cases", "8", delta="2 urgent")
    
    with col3:
        st.metric("Completed", "16", delta="4 this week")
    
    with col4:
        st.metric("Avg Resolution", "5.2 days", delta="-1.3 days")
    
    # Case creation
    st.markdown("### ➕ Create New Case")
    
    with st.expander("🆕 New Case Form", expanded=False):
        col1, col2 = st.columns(2)
        
        with col1:
            case_name = st.text_input("Case Name")
            case_priority = st.selectbox("Priority", ["Low", "Medium", "High", "Critical"])
            case_type = st.selectbox("Case Type", 
                ["Malware Analysis", "Phishing Investigation", "Data Breach", "Insider Threat", "Other"])
        
        with col2:
            case_description = st.text_area("Description")
            assigned_to = st.selectbox("Assigned To", ["John Doe", "Jane Smith", "Mike Johnson"])
            due_date = st.date_input("Due Date")
        
        if st.button("🚀 Create Case", use_container_width=True):
            st.success(f"✅ Case '{case_name}' created successfully!")
    
    # Active cases
    st.markdown("### 📋 Active Cases")
    
    # Sample case data
    cases_data = {
        'Case ID': ['#047', '#046', '#045', '#044', '#043'],
        'Name': [
            'Phishing Email Campaign Analysis',
            'Ransomware Incident Response',
            'Suspicious Network Traffic',
            'Malware Sample Investigation',
            'Data Exfiltration Analysis'
        ],
        'Priority': ['🔴 High', '🔴 Critical', '🟡 Medium', '🟡 Medium', '🟢 Low'],
        'Status': ['🔍 Active', '🔍 Active', '⏸️ On Hold', '🔍 Active', '✅ Completed'],
        'Assigned To': ['John Doe', 'Jane Smith', 'Mike Johnson', 'John Doe', 'Jane Smith'],
        'Files': [8, 15, 3, 12, 6],
        'Created': ['2024-01-28', '2024-01-25', '2024-01-24', '2024-01-22', '2024-01-20'],
        'Due Date': ['2024-02-05', '2024-01-31', '2024-02-10', '2024-02-01', '2024-01-28']
    }
    
    df = pd.DataFrame(cases_data)
    
    # Interactive case cards
    for i, row in df.iterrows():
        with st.expander(f"{row['Case ID']} - {row['Name']} ({row['Status']})", expanded=False):
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.write(f"**Priority:** {row['Priority']}")
                st.write(f"**Status:** {row['Status']}")
                st.write(f"**Assigned:** {row['Assigned To']}")
            
            with col2:
                st.write(f"**Files:** {row['Files']} evidence files")
                st.write(f"**Created:** {row['Created']}")
                st.write(f"**Due:** {row['Due Date']}")
            
            with col3:
                if st.button(f"👁️ View Details", key=f"view_{i}"):
                    show_case_details(row['Case ID'], row['Name'])
                
                if st.button(f"📝 Edit Case", key=f"edit_{i}"):
                    st.info(f"Edit mode for {row['Case ID']}")
                
                if st.button(f"📊 Generate Report", key=f"case_report_{i}"):
                    st.success(f"Report generated for {row['Case ID']}")
    
    # Case analytics
    st.markdown("### 📊 Case Analytics")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Priority distribution
        priority_counts = df['Priority'].value_counts()
        import plotly.express as px
        
        fig = px.pie(
            values=priority_counts.values,
            names=priority_counts.index,
            title="Cases by Priority"
        )
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        # Status distribution
        status_counts = df['Status'].value_counts()
        
        fig = px.bar(
            x=status_counts.index,
            y=status_counts.values,
            title="Cases by Status"
        )
        st.plotly_chart(fig, use_container_width=True)

def show_case_details(case_id, case_name):
    """Show detailed case information"""
    st.info(f"""
    📁 **Case Details: {case_id}**
    
    **Name:** {case_name}
    
    **Timeline:**
    - Case created: 2024-01-28
    - First evidence uploaded: 2024-01-28
    - Analysis started: 2024-01-29
    - Current status: Active investigation
    
    **Evidence Summary:**
    - Email messages: 5 files
    - Network captures: 2 files
    - System logs: 1 file
    
    **Key Findings:**
    - Phishing domains identified
    - Malicious attachments detected
    - C&C communication observed
    """)