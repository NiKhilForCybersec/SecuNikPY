"""
Dashboard Component for SecuNik
Shows system overview, metrics, and real-time status
"""

import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from datetime import datetime, timedelta
import time
from utils.api_client import get_api_client, format_timestamp, format_file_size, get_severity_color, get_risk_score_color


def show_dashboard():
    """Display the main dashboard"""
    st.title("🏠 SecuNik Dashboard")
    
    client = get_api_client()
    
    # Auto-refresh option
    col1, col2 = st.columns([3, 1])
    with col1:
        st.markdown("**Real-time Cybersecurity Analysis Overview**")
    
    with col2:
        auto_refresh = st.checkbox("🔄 Auto-refresh", value=False)
        if auto_refresh:
            time.sleep(5)
            st.rerun()
    
    # Main dashboard sections
    show_system_metrics(client)
    
    col1, col2 = st.columns(2)
    with col1:
        show_threat_overview(client)
        show_recent_activity(client)
    
    with col2:
        show_analysis_trends(client)
        show_system_status(client)


def show_system_metrics(client):
    """Show main system metrics"""
    st.subheader("📊 System Overview")
    
    # Get dashboard data
    dashboard_data = client.get_dashboard_data()
    
    if "error" in dashboard_data:
        st.error("❌ Could not load dashboard data")
        return
    
    # Main metrics row
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        total_files = dashboard_data.get("total_files", 0)
        st.metric(
            label="📁 Total Files",
            value=total_files,
            delta=dashboard_data.get("files_delta", None)
        )
    
    with col2:
        total_analyses = dashboard_data.get("total_analyses", 0)
        st.metric(
            label="📊 Analyses",
            value=total_analyses,
            delta=dashboard_data.get("analyses_delta", None)
        )
    
    with col3:
        threat_alerts = dashboard_data.get("threat_alerts", 0)
        st.metric(
            label="⚠️ Threats",
            value=threat_alerts,
            delta=dashboard_data.get("threats_delta", None),
            delta_color="inverse"  # Red for increases
        )
    
    with col4:
        active_cases = dashboard_data.get("active_cases", 0)
        st.metric(
            label="📋 Active Cases",
            value=active_cases,
            delta=dashboard_data.get("cases_delta", None)
        )
    
    with col5:
        avg_risk = dashboard_data.get("average_risk_score", 0.0)
        st.metric(
            label="🎯 Avg Risk",
            value=f"{avg_risk:.2f}",
            delta=dashboard_data.get("risk_delta", None),
            delta_color="inverse"  # Red for increases
        )
    
    # Additional metrics row
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        storage_used = dashboard_data.get("storage_used_mb", 0)
        st.metric("💾 Storage", f"{storage_used:.1f} MB")
    
    with col2:
        clean_files = dashboard_data.get("clean_files", 0)
        st.metric("✅ Clean Files", clean_files)
    
    with col3:
        high_risk_files = dashboard_data.get("high_risk_files", 0)
        st.metric("🔴 High Risk", high_risk_files)
    
    with col4:
        ai_enhanced = dashboard_data.get("ai_enhanced_files", 0)
        st.metric("🤖 AI Enhanced", ai_enhanced)


def show_threat_overview(client):
    """Show threat analysis overview"""
    st.subheader("🚨 Threat Overview")
    
    # Get threat dashboard data
    threat_data = client.get_threat_dashboard()
    
    if "error" in threat_data:
        st.warning("⚠️ Could not load threat data")
        return
    
    # Threat distribution
    severity_counts = threat_data.get("severity_distribution", {})
    
    if severity_counts:
        # Create pie chart
        fig = px.pie(
            values=list(severity_counts.values()),
            names=list(severity_counts.keys()),
            title="Threats by Severity",
            color_discrete_map={
                "CRITICAL": "#8B0000",
                "HIGH": "#FF0000",
                "MEDIUM": "#FFA500",
                "LOW": "#90EE90"
            }
        )
        fig.update_traces(
            textinfo='value+percent',
            textfont_size=12
        )
        fig.update_layout(
            height=300,
            margin=dict(t=40, b=0, l=0, r=0)
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("🎉 No threats detected!")
    
    # Recent threats
    recent_threats = threat_data.get("recent_threats", [])
    if recent_threats:
        st.markdown("**🚨 Recent Threats:**")
        for threat in recent_threats[:3]:
            severity = threat.get("severity", "LOW")
            color = get_severity_color(severity)
            file_name = threat.get("filename", "unknown")
            threat_type = threat.get("type", "unknown")
            
            st.markdown(
                f'<div class="threat-{severity.lower()}">'
                f'<strong>{file_name}</strong><br>'
                f'<span style="color: {color}">⚠️ {severity}</span> - {threat_type}'
                f'</div>',
                unsafe_allow_html=True
            )


def show_recent_activity(client):
    """Show recent activity feed"""
    st.subheader("📋 Recent Activity")
    
    # Get recent activity
    activity_data = client.get_recent_activity()
    
    if "error" in activity_data:
        st.warning("⚠️ Could not load activity data")
        return
    
    activities = activity_data.get("activities", [])
    
    if not activities:
        st.info("📭 No recent activity")
        return
    
    # Display activities
    for activity in activities[:5]:  # Show last 5 activities
        timestamp = activity.get("timestamp", "")
        action = activity.get("action", "unknown")
        filename = activity.get("filename", "")
        severity = activity.get("severity", "LOW")
        
        # Format activity display
        icon_map = {
            "file_uploaded": "📤",
            "analysis_completed": "📊",
            "threat_detected": "⚠️",
            "case_created": "📋",
            "ai_analysis": "🤖"
        }
        
        icon = icon_map.get(action, "📄")
        formatted_time = format_timestamp(timestamp)
        
        with st.container():
            col1, col2 = st.columns([3, 1])
            
            with col1:
                if filename:
                    st.write(f"{icon} **{action.replace('_', ' ').title()}** - {filename}")
                else:
                    st.write(f"{icon} **{action.replace('_', ' ').title()}**")
                st.caption(f"🕒 {formatted_time}")
            
            with col2:
                if severity and severity != "NONE":
                    color = get_severity_color(severity)
                    st.markdown(f'<span style="color: {color}">⚠️ {severity}</span>', unsafe_allow_html=True)
        
        st.markdown("---")


def show_analysis_trends(client):
    """Show analysis trends and charts"""
    st.subheader("📈 Analysis Trends")
    
    # Get trends data
    trends_data = client.get_trends_data()
    
    if "error" in trends_data:
        st.warning("⚠️ Could not load trends data")
        return
    
    # Risk score trend
    risk_trend = trends_data.get("risk_score_trend", [])
    
    if risk_trend:
        # Create line chart for risk scores over time
        df = pd.DataFrame(risk_trend)
        
        if not df.empty and 'timestamp' in df.columns and 'risk_score' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            
            fig = px.line(
                df,
                x='timestamp',
                y='risk_score',
                title='Risk Score Trend (Last 24h)',
                labels={'risk_score': 'Average Risk Score', 'timestamp': 'Time'}
            )
            fig.update_layout(
                height=250,
                margin=dict(t=40, b=0, l=0, r=0),
                showlegend=False
            )
            fig.update_traces(line_color='#2a5298')
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("📊 Insufficient data for trend analysis")
    
    # File type distribution
    file_type_dist = trends_data.get("file_type_distribution", {})
    
    if file_type_dist:
        st.markdown("**📁 File Types Analyzed:**")
        
        # Create horizontal bar chart
        types = list(file_type_dist.keys())
        counts = list(file_type_dist.values())
        
        fig = go.Figure(data=[
            go.Bar(
                y=types,
                x=counts,
                orientation='h',
                marker_color='#2a5298'
            )
        ])
        fig.update_layout(
            height=200,
            margin=dict(t=20, b=0, l=0, r=0),
            showlegend=False
        )
        st.plotly_chart(fig, use_container_width=True)


def show_system_status(client):
    """Show system health and status"""
    st.subheader("🔧 System Status")
    
    # Get system status
    system_data = client.get_system_status()
    
    if "error" in system_data:
        st.warning("⚠️ Could not load system status")
        return
    
    # System health indicators
    backend_status = system_data.get("backend_status", "unknown")
    ai_status = system_data.get("ai_status", "unknown")
    storage_status = system_data.get("storage_status", "unknown")
    
    # Status indicators
    status_colors = {
        "healthy": "🟢",
        "warning": "🟡",
        "error": "🔴",
        "unknown": "⚪"
    }
    
    st.markdown("**🖥️ Service Status:**")
    
    col1, col2 = st.columns(2)
    
    with col1:
        backend_icon = status_colors.get(backend_status, "⚪")
        st.write(f"{backend_icon} **Backend:** {backend_status.title()}")
        
        storage_icon = status_colors.get(storage_status, "⚪")
        st.write(f"{storage_icon} **Storage:** {storage_status.title()}")
    
    with col2:
        ai_icon = status_colors.get(ai_status, "⚪")
        st.write(f"{ai_icon} **AI Service:** {ai_status.title()}")
    
    # Performance metrics
    performance = system_data.get("performance", {})
    
    if performance:
        st.markdown("**⚡ Performance:**")
        
        avg_analysis_time = performance.get("avg_analysis_time", 0)
        st.write(f"⏱️ **Avg Analysis Time:** {avg_analysis_time:.1f}s")
        
        success_rate = performance.get("success_rate", 0)
        st.write(f"✅ **Success Rate:** {success_rate:.1%}")
        
        queue_size = performance.get("queue_size", 0)
        if queue_size > 0:
            st.write(f"📋 **Queue Size:** {queue_size}")
    
    # System resources
    resources = system_data.get("resources", {})
    
    if resources:
        st.markdown("**💾 Resources:**")
        
        memory_usage = resources.get("memory_usage_mb", 0)
        st.write(f"🧠 **Memory:** {memory_usage:.1f} MB")
        
        disk_usage = resources.get("disk_usage_mb", 0)
        st.write(f"💽 **Disk:** {disk_usage:.1f} MB")


def show_quick_actions():
    """Show quick action buttons"""
    st.subheader("⚡ Quick Actions")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        if st.button("📤 Upload File", use_container_width=True):
            st.session_state.page_selector = "📤 Upload & Analyze"
            st.rerun()
    
    with col2:
        if st.button("📊 View Analysis", use_container_width=True):
            st.session_state.page_selector = "📊 Analysis Results"
            st.rerun()
    
    with col3:
        if st.button("📋 Create Case", use_container_width=True):
            st.session_state.page_selector = "📋 Case Management"
            st.rerun()
    
    with col4:
        if st.button("🤖 AI Chat", use_container_width=True):
            st.session_state.page_selector = "🤖 AI Assistant"
            st.rerun()


def show_alerts_panel():
    """Show system alerts and notifications"""
    st.subheader("🔔 System Alerts")
    
    client = get_api_client()
    
    # Get system alerts (this would be a new API endpoint)
    # For now, we'll show some sample alerts based on dashboard data
    dashboard_data = client.get_dashboard_data()
    
    alerts = []
    
    # Check for high-risk files
    high_risk_files = dashboard_data.get("high_risk_files", 0)
    if high_risk_files > 0:
        alerts.append({
            "type": "warning",
            "message": f"{high_risk_files} high-risk files detected",
            "action": "Review Analysis Results"
        })
    
    # Check for threat alerts
    threat_alerts = dashboard_data.get("threat_alerts", 0)
    if threat_alerts > 5:
        alerts.append({
            "type": "error",
            "message": f"{threat_alerts} active threats require attention",
            "action": "View Threat Dashboard"
        })
    
    # Check storage usage
    storage_used = dashboard_data.get("storage_used_mb", 0)
    if storage_used > 1000:  # > 1GB
        alerts.append({
            "type": "info",
            "message": f"Storage usage: {storage_used:.1f} MB",
            "action": "Clean up old files"
        })
    
    if alerts:
        for alert in alerts:
            alert_type = alert["type"]
            message = alert["message"]
            action = alert.get("action", "")
            
            if alert_type == "error":
                st.error(f"🚨 {message}")
            elif alert_type == "warning":
                st.warning(f"⚠️ {message}")
            else:
                st.info(f"ℹ️ {message}")
            
            if action:
                st.caption(f"💡 Recommended action: {action}")
    else:
        st.success("✅ No active alerts")


# Additional dashboard widgets can be added here
def show_ai_insights_widget(client):
    """Show AI insights widget"""
    st.subheader("🤖 AI Insights")
    
    # This would connect to AI insights API
    # For now, show placeholder
    st.info("🔄 AI insights will be displayed here when available")
    
    if st.button("🚀 Generate AI Insights"):
        with st.spinner("🤖 Generating insights..."):
            # This would call the AI insights API
            time.sleep(2)  # Simulate processing
            st.success("✅ AI insights generated!")


def show_security_score_widget(client):
    """Show overall security score widget"""
    st.subheader("🛡️ Security Score")
    
    # Calculate overall security score based on various factors
    dashboard_data = client.get_dashboard_data()
    
    total_files = dashboard_data.get("total_files", 0)
    clean_files = dashboard_data.get("clean_files", 0)
    threat_alerts = dashboard_data.get("threat_alerts", 0)
    
    if total_files > 0:
        clean_ratio = clean_files / total_files
        threat_penalty = min(threat_alerts * 0.1, 0.5)  # Max 50% penalty
        security_score = max(0, clean_ratio - threat_penalty) * 100
        
        # Display score with color coding
        if security_score >= 80:
            color = "green"
            status = "Excellent"
        elif security_score >= 60:
            color = "orange"
            status = "Good"
        elif security_score >= 40:
            color = "red"
            status = "Needs Attention"
        else:
            color = "darkred"
            status = "Critical"
        
        st.metric("🛡️ Security Score", f"{security_score:.0f}/100")
        st.markdown(f'<span style="color: {color}; font-size: 1.2em;">● {status}</span>', unsafe_allow_html=True)
        
        # Progress bar
        st.progress(security_score / 100)
    else:
        st.info("Upload files to see security score")