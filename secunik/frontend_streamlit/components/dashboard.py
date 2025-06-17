import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
from datetime import datetime, timedelta
import numpy as np

def render_dashboard():
    """Render the main dashboard"""
    
    st.markdown("## 📊 Security Dashboard")
    st.markdown("Real-time cybersecurity analysis overview")
    
    # Key metrics row
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            label="🗂️ Total Cases",
            value="24",
            delta="3 this week",
            delta_color="normal"
        )
    
    with col2:
        st.metric(
            label="🚨 Active Threats",
            value="7",
            delta="-2 resolved",
            delta_color="inverse"
        )
    
    with col3:
        st.metric(
            label="📁 Files Analyzed",
            value="1,847",
            delta="156 today",
            delta_color="normal"
        )
    
    with col4:
        st.metric(
            label="🛡️ Risk Score",
            value="73/100",
            delta="-5 points",
            delta_color="inverse"
        )
    
    # Charts row
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### 📈 Threat Trends")
        
        # Generate sample data
        dates = pd.date_range(start='2024-01-01', end='2024-01-30', freq='D')
        threat_data = np.random.randint(0, 20, size=len(dates))
        
        fig = px.line(
            x=dates, 
            y=threat_data,
            title="Daily Threat Detection",
            labels={'x': 'Date', 'y': 'Threats Detected'}
        )
        fig.update_layout(
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
        )
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.markdown("### 🎯 Threat Categories")
        
        # Pie chart for threat types
        threat_types = ['Malware', 'Phishing', 'Ransomware', 'Trojan', 'Adware']
        threat_counts = [25, 18, 12, 15, 8]
        
        fig = px.pie(
            values=threat_counts,
            names=threat_types,
            title="Threat Distribution"
        )
        fig.update_layout(
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
        )
        st.plotly_chart(fig, use_container_width=True)
    
    # Recent activity
    st.markdown("### 🕒 Recent Activity")
    
    # Sample recent activity data
    activity_data = {
        'Timestamp': [
            '2024-01-30 14:32:15',
            '2024-01-30 14:28:42',
            '2024-01-30 14:15:33',
            '2024-01-30 13:45:21',
            '2024-01-30 13:22:18'
        ],
        'Activity': [
            'New malware sample analyzed',
            'Phishing email detected in Case #047',
            'File upload completed: suspicious.exe',
            'Threat level updated for Case #045',
            'Analysis report generated for Case #046'
        ],
        'Status': ['✅ Complete', '🔍 Analyzing', '✅ Complete', '⚠️ High Risk', '✅ Complete'],
        'Case ID': ['#048', '#047', '#048', '#045', '#046']
    }
    
    df = pd.DataFrame(activity_data)
    st.dataframe(df, use_container_width=True, hide_index=True)
    
    # Quick actions
    st.markdown("### ⚡ Quick Actions")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        if st.button("📁 Upload Evidence", use_container_width=True):
            st.switch_page("pages/file_upload.py")
    
    with col2:
        if st.button("🆕 New Case", use_container_width=True):
            st.switch_page("pages/cases.py")
    
    with col3:
        if st.button("📊 Generate Report", use_container_width=True):
            st.success("Report generation started!")
    
    with col4:
        if st.button("🔍 Run Analysis", use_container_width=True):
            st.info("Analysis queue updated!")