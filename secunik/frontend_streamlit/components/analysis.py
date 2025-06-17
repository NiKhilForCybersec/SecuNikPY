"""
Analysis Component for SecuNik
Shows detailed analysis results and insights - FIXED VERSION
"""

import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from utils.api_client import get_api_client, format_timestamp, get_severity_color, get_risk_score_color


def show_analysis_page():
    """Display the analysis results page"""
    st.title("📊 Analysis Results")
    
    client = get_api_client()
    
    # Get all analyses
    analyses_data = client.get_all_analyses()
    
    if "error" in analyses_data:
        st.error("❌ Failed to load analysis results")
        st.info("Make sure backend is running: cd backend && python run.py")
        return
    
    analyses = analyses_data.get("analyses", [])
    
    if not analyses:
        st.info("📭 No analysis results yet. Upload files to see results here!")
        
        # Quick upload link
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            if st.button("📤 Go to Upload Page", use_container_width=True, key="goto_upload"):
                st.session_state.page_selector = "📤 Upload & Analyze"
                st.rerun()
        return
    
    # Analysis overview
    show_analysis_overview(analyses_data)
    
    st.markdown("---")
    
    # Analysis filters and selection
    show_analysis_browser(client, analyses)


def show_analysis_overview(analyses_data):
    """Show analysis overview metrics"""
    st.subheader("📈 Analysis Overview")
    
    total_analyses = analyses_data.get("total_analyses", 0)
    analyses = analyses_data.get("analyses", [])
    
    # Calculate metrics
    severity_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    type_counts = {}
    risk_scores = []
    
    for analysis in analyses:
        severity = analysis.get("severity", "LOW")
        if severity in severity_counts:
            severity_counts[severity] += 1
        
        analysis_type = analysis.get("analysis_type", "unknown")
        type_counts[analysis_type] = type_counts.get(analysis_type, 0) + 1
        
        risk_score = analysis.get("risk_score", 0.0)
        risk_scores.append(risk_score)
    
    # Metrics row
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("📊 Total Analyses", total_analyses)
    
    with col2:
        avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0.0
        st.metric("🎯 Average Risk", f"{avg_risk:.2f}")
    
    with col3:
        high_risk_count = sum(1 for score in risk_scores if score > 0.6)
        st.metric("⚠️ High Risk", high_risk_count)
    
    with col4:
        clean_count = sum(1 for score in risk_scores if score == 0.0)
        st.metric("✅ Clean Files", clean_count)
    
    # Charts row
    col1, col2 = st.columns(2)
    
    with col1:
        # Severity distribution pie chart
        if sum(severity_counts.values()) > 0:
            fig = px.pie(
                values=list(severity_counts.values()),
                names=list(severity_counts.keys()),
                title="Distribution by Severity",
                color_discrete_map={
                    "CRITICAL": "#8B0000",
                    "HIGH": "#FF0000",
                    "MEDIUM": "#FFA500", 
                    "LOW": "#90EE90"
                }
            )
            fig.update_traces(textinfo='value+percent')
            fig.update_layout(height=300)
            st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        # Analysis types bar chart
        if type_counts:
            fig = px.bar(
                x=list(type_counts.keys()),
                y=list(type_counts.values()),
                title="Analysis Types",
                labels={"x": "Analysis Type", "y": "Count"}
            )
            fig.update_layout(height=300)
            st.plotly_chart(fig, use_container_width=True)


def show_analysis_browser(client, analyses):
    """Show analysis browser with filters"""
    st.subheader("🔍 Analysis Browser")
    
    # Filters
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        severity_filter = st.selectbox(
            "Filter by Severity",
            ["All"] + ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
            key="analysis_severity_filter"
        )
    
    with col2:
        # Get unique analysis types
        analysis_types = ["All"] + list(set(a.get("analysis_type", "") for a in analyses))
        type_filter = st.selectbox(
            "Filter by Type",
            analysis_types,
            key="analysis_type_filter"
        )
    
    with col3:
        sort_by = st.selectbox(
            "Sort by",
            ["Timestamp (Newest)", "Timestamp (Oldest)", "Risk Score (High)", "Risk Score (Low)", "Filename"],
            key="analysis_sort_by"
        )
    
    with col4:
        # FIXED: Added unique key to prevent duplication
        if st.button("🔄 Refresh", use_container_width=True, key="analysis_refresh_button"):
            st.rerun()
    
    # Apply filters
    filtered_analyses = filter_analyses(analyses, severity_filter, type_filter)
    
    # Apply sorting
    filtered_analyses = sort_analyses(filtered_analyses, sort_by)
    
    # Display results
    st.markdown(f"**📊 Showing {len(filtered_analyses)} of {len(analyses)} analyses**")
    
    # Analysis cards
    for i, analysis in enumerate(filtered_analyses):
        show_analysis_card(client, analysis, i)


def filter_analyses(analyses, severity_filter, type_filter):
    """Filter analyses based on selected criteria"""
    filtered = analyses
    
    if severity_filter != "All":
        filtered = [a for a in filtered if a.get("severity") == severity_filter]
    
    if type_filter != "All":
        filtered = [a for a in filtered if a.get("analysis_type") == type_filter]
    
    return filtered


def sort_analyses(analyses, sort_by):
    """Sort analyses based on selected criteria"""
    if sort_by == "Timestamp (Newest)":
        return sorted(analyses, key=lambda x: x.get("timestamp", ""), reverse=True)
    elif sort_by == "Timestamp (Oldest)":
        return sorted(analyses, key=lambda x: x.get("timestamp", ""))
    elif sort_by == "Risk Score (High)":
        return sorted(analyses, key=lambda x: x.get("risk_score", 0), reverse=True)
    elif sort_by == "Risk Score (Low)":
        return sorted(analyses, key=lambda x: x.get("risk_score", 0))
    elif sort_by == "Filename":
        return sorted(analyses, key=lambda x: x.get("filename", "").lower())
    else:
        return analyses


def show_analysis_card(client, analysis, card_index):
    """Show individual analysis card with unique keys"""
    filename = analysis.get("filename", "unknown")
    file_id = analysis.get("file_id", "")
    severity = analysis.get("severity", "LOW")
    risk_score = analysis.get("risk_score", 0.0)
    analysis_type = analysis.get("analysis_type", "unknown")
    timestamp = analysis.get("timestamp", "")
    summary = analysis.get("summary", "")
    threat_count = analysis.get("threat_count", 0)
    
    # Use card_index to make unique keys
    unique_prefix = f"card_{card_index}_{file_id[:8]}"
    
    # Card container
    with st.container():
        # Header row
        col1, col2, col3, col4 = st.columns([3, 1, 1, 1])
        
        with col1:
            st.markdown(f"### 📄 {filename}")
            st.caption(f"🔧 {analysis_type.title()} | 🕒 {format_timestamp(timestamp)}")
        
        with col2:
            severity_color = get_severity_color(severity)
            st.markdown(f"**Severity:**")
            st.markdown(f"<span style='color: {severity_color}; font-size: 1.2em;'>⚠️ {severity}</span>", unsafe_allow_html=True)
        
        with col3:
            risk_color = get_risk_score_color(risk_score)
            st.markdown(f"**Risk Score:**")
            st.markdown(f"<span style='color: {risk_color}; font-size: 1.2em;'>🎯 {risk_score:.2f}</span>", unsafe_allow_html=True)
        
        with col4:
            threat_color = "red" if threat_count > 0 else "green"
            st.markdown(f"**Threats:**")
            st.markdown(f"<span style='color: {threat_color}; font-size: 1.2em;'>🚨 {threat_count}</span>", unsafe_allow_html=True)
        
        # Summary
        if summary:
            st.markdown(f"**📝 Summary:** {summary}")
        
        # Action buttons with unique keys
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            if st.button("🔍 View Details", key=f"{unique_prefix}_details"):
                show_detailed_analysis(client, file_id, filename)
        
        with col2:
            if st.button("🚨 View Threats", key=f"{unique_prefix}_threats"):
                show_threats_analysis(client, file_id, filename)
        
        with col3:
            if st.button("💡 Recommendations", key=f"{unique_prefix}_recs"):
                show_recommendations(client, file_id, filename)
        
        with col4:
            if st.button("🤖 AI Insights", key=f"{unique_prefix}_ai"):
                show_ai_insights(client, file_id, filename)
        
        st.markdown("---")


def show_detailed_analysis(client, file_id, filename):
    """Show detailed analysis for a file"""
    st.subheader(f"🔍 Detailed Analysis: {filename}")
    
    # Get detailed analysis
    analysis_data = client.get_analysis(file_id)
    
    if "error" in analysis_data:
        st.error("❌ Could not load detailed analysis")
        st.info("This might be because the analysis data is not available or the backend API is not properly connected.")
        return
    
    analysis = analysis_data.get("analysis", {})
    
    # Basic information
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("**📋 Basic Information:**")
        st.write(f"• **Parser:** {analysis.get('parser_name', 'unknown')}")
        st.write(f"• **Analysis Type:** {analysis.get('analysis_type', 'unknown')}")
        st.write(f"• **Timestamp:** {format_timestamp(analysis.get('timestamp', ''))}")
    
    with col2:
        st.markdown("**🎯 Risk Assessment:**")
        severity = analysis.get("severity", "LOW")
        risk_score = analysis.get("risk_score", 0.0)
        
        severity_color = get_severity_color(severity)
        risk_color = get_risk_score_color(risk_score)
        
        st.markdown(f"• **Severity:** <span style='color: {severity_color}'>{severity}</span>", unsafe_allow_html=True)
        st.markdown(f"• **Risk Score:** <span style='color: {risk_color}'>{risk_score:.2f}</span>", unsafe_allow_html=True)
    
    # File details
    details = analysis.get("details", {})
    if details:
        st.markdown("**🔍 File Details:**")
        
        details_df = pd.DataFrame([
            {"Property": key.replace("_", " ").title(), "Value": str(value)}
            for key, value in details.items()
        ])
        
        st.dataframe(details_df, use_container_width=True, hide_index=True)
    
    # Summary
    summary = analysis.get("summary", "")
    if summary:
        st.markdown("**📝 Analysis Summary:**")
        st.info(summary)


def show_threats_analysis(client, file_id, filename):
    """Show threats analysis for a file"""
    st.subheader(f"🚨 Threats Analysis: {filename}")
    
    # Get threats
    threats_data = client.get_file_threats(file_id)
    
    if "error" in threats_data:
        st.error("❌ Could not load threats data")
        st.info("Threats data may not be available for this file.")
        return
    
    threats = threats_data.get("threats", [])
    threat_count = threats_data.get("threat_count", 0)
    severity = threats_data.get("severity", "LOW")
    risk_score = threats_data.get("risk_score", 0.0)
    
    # Threat summary
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("🚨 Total Threats", threat_count)
    
    with col2:
        severity_color = get_severity_color(severity)
        st.metric("⚠️ Overall Severity", severity)
        st.markdown(f"<div style='color: {severity_color}'>■ {severity}</div>", unsafe_allow_html=True)
    
    with col3:
        risk_color = get_risk_score_color(risk_score)
        st.metric("🎯 Risk Score", f"{risk_score:.2f}")
        st.markdown(f"<div style='color: {risk_color}'>■ Risk: {risk_score:.1%}</div>", unsafe_allow_html=True)
    
    # Individual threats
    if threats:
        st.markdown("**🚨 Detected Threats:**")
        
        for i, threat in enumerate(threats, 1):
            threat_type = threat.get("type", "unknown")
            description = threat.get("description", "No description available")
            threat_severity = threat.get("severity", "LOW")
            
            color = get_severity_color(threat_severity)
            
            with st.expander(f"🚨 Threat {i}: {threat_type} ({threat_severity})"):
                st.markdown(f"**Type:** {threat_type}")
                st.markdown(f"**Severity:** <span style='color: {color}'>{threat_severity}</span>", unsafe_allow_html=True)
                st.markdown(f"**Description:** {description}")
                
                # Additional threat details
                for key, value in threat.items():
                    if key not in ["type", "description", "severity"]:
                        st.markdown(f"**{key.replace('_', ' ').title()}:** {value}")
    else:
        st.success("✅ No threats detected in this file!")


def show_recommendations(client, file_id, filename):
    """Show recommendations for a file"""
    st.subheader(f"💡 Recommendations: {filename}")
    
    # Get recommendations
    recs_data = client.get_file_recommendations(file_id)
    
    if "error" in recs_data:
        st.error("❌ Could not load recommendations")
        st.info("Recommendations may not be available for this file.")
        return
    
    recommendations = recs_data.get("recommendations", [])
    priority = recs_data.get("priority", "normal")
    
    # Priority indicator
    if priority == "high":
        st.warning("⚠️ **High Priority Recommendations**")
    else:
        st.info("ℹ️ **Standard Recommendations**")
    
    # Display recommendations
    if recommendations:
        for i, rec in enumerate(recommendations, 1):
            st.markdown(f"**{i}.** {rec}")
    else:
        st.success("✅ No specific recommendations needed for this file.")


def show_ai_insights(client, file_id, filename):
    """Show AI insights for a file"""
    st.subheader(f"🤖 AI Insights: {filename}")
    
    # Check AI status first
    ai_status = client.get_ai_status()
    
    if "error" in ai_status or not ai_status.get("ai_available", False):
        st.warning("⚠️ AI features are not available")
        st.info("To enable AI features, configure your OpenAI API key:")
        st.code("export OPENAI_API_KEY='your-api-key-here'")
        st.info("Then restart the backend server.")
        return
    
    # Get AI insights
    ai_data = client.get_ai_insights(file_id)
    
    if "error" in ai_data:
        st.error("❌ Could not load AI insights")
        return
    
    if not ai_data.get("ai_insights_available", False):
        st.warning("⚠️ No AI insights available for this file.")
        
        if st.button("🚀 Generate AI Insights", key=f"generate_ai_{file_id}"):
            with st.spinner("🤖 Generating AI insights..."):
                ai_result = client.ai_analyze_file(file_id)
                
                if "error" not in ai_result:
                    st.success("✅ AI insights generated!")
                    st.rerun()
                else:
                    st.error("❌ Failed to generate AI insights")
        return
    
    # Display AI insights
    insights = ai_data.get("insights", [])
    recommendations = ai_data.get("recommendations", [])
    confidence = ai_data.get("confidence", 0.0)
    risk_assessment = ai_data.get("risk_assessment", "Unknown")
    
    # AI confidence
    st.metric("🎯 AI Confidence", f"{confidence:.1%}")
    
    # Risk assessment
    st.markdown(f"**🔍 AI Risk Assessment:** {risk_assessment}")
    
    # AI insights
    if insights:
        st.markdown("**🧠 AI Insights:**")
        for insight in insights:
            st.markdown(f"• {insight}")
    
    # AI recommendations
    if recommendations:
        st.markdown("**🤖 AI Recommendations:**")
        for rec in recommendations:
            st.markdown(f"• {rec}")


def show_analysis_statistics():
    """Show detailed analysis statistics"""
    st.subheader("📈 Analysis Statistics")
    
    client = get_api_client()
    stats_data = client.get_analysis_stats()
    
    if "error" in stats_data:
        st.error("❌ Could not load analysis statistics")
        return
    
    # Display detailed statistics
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("📊 Total Files", stats_data.get("total_files", 0))
        st.metric("🚨 Total Threats", stats_data.get("total_threats", 0))
    
    with col2:
        st.metric("⚠️ High Risk Files", stats_data.get("high_risk_files", 0))
        st.metric("✅ Clean Files", stats_data.get("clean_files", 0))
    
    with col3:
        avg_risk = stats_data.get("average_risk_score", 0.0)
        st.metric("🎯 Average Risk Score", f"{avg_risk:.3f}")
    
    # Severity breakdown
    by_severity = stats_data.get("by_severity", {})
    if by_severity:
        st.markdown("**📊 Files by Severity:**")
        severity_df = pd.DataFrame([
            {"Severity": k, "Count": v, "Color": get_severity_color(k)}
            for k, v in by_severity.items()
        ])
        st.dataframe(severity_df, hide_index=True)
    
    # Analysis types breakdown
    by_type = stats_data.get("by_analysis_type", {})
    if by_type:
        st.markdown("**🔧 Analysis Types:**")
        for analysis_type, count in by_type.items():
            st.write(f"• **{analysis_type.title()}:** {count}")