"""
Cases Component for SecuNik
Manages investigation cases and organizes analysis results
"""

import streamlit as st
import json
from datetime import datetime
from pathlib import Path
from utils.api_client import get_api_client, format_timestamp, get_severity_color


def show_cases_page():
    """Display the cases management page"""
    st.title("📋 Case Management")
    
    client = get_api_client()
    
    # Initialize cases in session state
    if "cases" not in st.session_state:
        st.session_state.cases = load_cases()
    
    # Cases overview
    show_cases_overview()
    
    st.markdown("---")
    
    # Case management interface
    col1, col2 = st.columns([2, 1])
    
    with col1:
        show_cases_list(client)
    
    with col2:
        show_case_actions(client)


def show_cases_overview():
    """Show cases overview metrics"""
    st.subheader("📊 Cases Overview")
    
    cases = st.session_state.cases
    
    # Calculate metrics
    total_cases = len(cases)
    active_cases = sum(1 for case in cases if case.get("status") == "active")
    closed_cases = sum(1 for case in cases if case.get("status") == "closed")
    
    # Count files across all cases
    total_files = sum(len(case.get("files", [])) for case in cases)
    
    # Metrics row
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("📋 Total Cases", total_cases)
    
    with col2:
        st.metric("🟢 Active Cases", active_cases)
    
    with col3:
        st.metric("🔴 Closed Cases", closed_cases)
    
    with col4:
        st.metric("📁 Total Files", total_files)


def show_cases_list(client):
    """Show list of all cases"""
    st.subheader("📋 Investigation Cases")
    
    cases = st.session_state.cases
    
    if not cases:
        st.info("📭 No cases created yet. Create your first case using the sidebar!")
        return
    
    # Cases filter
    status_filter = st.selectbox(
        "Filter by Status",
        ["All", "Active", "Closed", "On Hold"],
        key="case_status_filter"
    )
    
    # Filter cases
    filtered_cases = cases
    if status_filter != "All":
        filtered_cases = [c for c in cases if c.get("status", "").lower() == status_filter.lower()]
    
    # Display cases
    for case in filtered_cases:
        show_case_card(client, case)


def show_case_card(client, case):
    """Display individual case card"""
    case_id = case.get("id", "")
    name = case.get("name", "Unnamed Case")
    description = case.get("description", "")
    status = case.get("status", "active")
    created_date = case.get("created_date", "")
    files = case.get("files", [])
    
    # Status color
    status_colors = {
        "active": "green",
        "closed": "red", 
        "on hold": "orange"
    }
    status_color = status_colors.get(status.lower(), "gray")
    
    with st.container():
        # Header
        col1, col2, col3 = st.columns([3, 1, 1])
        
        with col1:
            st.markdown(f"### 📋 {name}")
            if description:
                st.caption(description)
        
        with col2:
            st.markdown(f"**Status:**")
            st.markdown(f"<span style='color: {status_color}'>● {status.title()}</span>", unsafe_allow_html=True)
        
        with col3:
            st.markdown(f"**Files:** {len(files)}")
            st.caption(f"Created: {format_timestamp(created_date)}")
        
        # Case details
        if files:
            with st.expander(f"📁 Case Files ({len(files)})"):
                for file_info in files:
                    file_id = file_info.get("file_id", "")
                    filename = file_info.get("filename", "unknown")
                    added_date = file_info.get("added_date", "")
                    
                    col1, col2, col3 = st.columns([2, 1, 1])
                    
                    with col1:
                        st.write(f"📄 {filename}")
                    
                    with col2:
                        st.caption(f"Added: {format_timestamp(added_date)}")
                    
                    with col3:
                        if st.button("🔍 Analyze", key=f"analyze_{file_id}_{case_id}"):
                            show_file_analysis(client, file_id, filename)
        
        # Case actions
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            if st.button("📝 Edit", key=f"edit_{case_id}"):
                edit_case(case)
        
        with col2:
            if st.button("📄 Report", key=f"report_{case_id}"):
                generate_case_report(client, case)
        
        with col3:
            if status == "active":
                if st.button("🔒 Close", key=f"close_{case_id}"):
                    close_case(case_id)
            else:
                if st.button("🔓 Reopen", key=f"reopen_{case_id}"):
                    reopen_case(case_id)
        
        with col4:
            if st.button("🗑️ Delete", key=f"delete_{case_id}"):
                delete_case(case_id)
        
        st.markdown("---")


def show_case_actions(client):
    """Show case action sidebar"""
    st.subheader("⚡ Case Actions")
    
    # Create new case
    with st.expander("➕ Create New Case", expanded=False):
        with st.form("new_case_form"):
            case_name = st.text_input("Case Name", placeholder="Investigation Case #1")
            case_description = st.text_area("Description", placeholder="Brief description of the investigation")
            
            if st.form_submit_button("🚀 Create Case"):
                if case_name.strip():
                    create_new_case(case_name.strip(), case_description.strip())
                else:
                    st.error("Case name is required!")
    
    # Add files to case
    cases = st.session_state.cases
    active_cases = [c for c in cases if c.get("status") == "active"]
    
    if active_cases:
        with st.expander("📁 Add Files to Case"):
            # Get available files
            files_data = client.list_files()
            
            if "error" not in files_data:
                files = files_data.get("files", [])
                
                if files:
                    case_options = [f"{c['name']} ({c['id'][:8]})" for c in active_cases]
                    selected_case = st.selectbox("Select Case", case_options)
                    
                    file_options = [f"{f['filename']} ({f['file_id'][:8]})" for f in files]
                    selected_files = st.multiselect("Select Files", file_options)
                    
                    if st.button("📁 Add Files to Case") and selected_files:
                        case_id = selected_case.split("(")[-1].replace(")", "")
                        add_files_to_case(case_id, selected_files, files)
                else:
                    st.info("No files available. Upload files first.")
            else:
                st.error("Could not load files list")
    
    # Case statistics
    with st.expander("📊 Case Statistics"):
        show_case_statistics()


def create_new_case(name, description):
    """Create a new investigation case"""
    case_id = f"case_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    new_case = {
        "id": case_id,
        "name": name,
        "description": description,
        "status": "active",
        "created_date": datetime.now().isoformat(),
        "files": [],
        "notes": [],
        "tags": []
    }
    
    st.session_state.cases.append(new_case)
    save_cases(st.session_state.cases)
    
    st.success(f"✅ Created case: {name}")
    st.rerun()


def add_files_to_case(case_id, selected_files, available_files):
    """Add files to a case"""
    # Find the case
    case = next((c for c in st.session_state.cases if c["id"] == case_id), None)
    
    if not case:
        st.error("Case not found!")
        return
    
    # Extract file info from selections
    added_count = 0
    
    for selection in selected_files:
        file_id = selection.split("(")[-1].replace(")", "")
        filename = selection.split(" (")[0]
        
        # Check if file already in case
        if not any(f.get("file_id") == file_id for f in case["files"]):
            case["files"].append({
                "file_id": file_id,
                "filename": filename,
                "added_date": datetime.now().isoformat()
            })
            added_count += 1
    
    if added_count > 0:
        save_cases(st.session_state.cases)
        st.success(f"✅ Added {added_count} files to case")
        st.rerun()
    else:
        st.warning("No new files added (files may already be in case)")


def edit_case(case):
    """Edit case details"""
    st.subheader(f"📝 Edit Case: {case['name']}")
    
    with st.form("edit_case_form"):
        new_name = st.text_input("Case Name", value=case["name"])
        new_description = st.text_area("Description", value=case.get("description", ""))
        new_status = st.selectbox("Status", ["active", "closed", "on hold"], 
                                 index=["active", "closed", "on hold"].index(case.get("status", "active")))
        
        # Tags
        current_tags = ", ".join(case.get("tags", []))
        new_tags = st.text_input("Tags (comma-separated)", value=current_tags)
        
        if st.form_submit_button("💾 Save Changes"):
            # Update case
            case["name"] = new_name.strip()
            case["description"] = new_description.strip() 
            case["status"] = new_status
            case["tags"] = [tag.strip() for tag in new_tags.split(",") if tag.strip()]
            case["last_modified"] = datetime.now().isoformat()
            
            save_cases(st.session_state.cases)
            st.success("✅ Case updated successfully!")
            st.rerun()


def close_case(case_id):
    """Close a case"""
    case = next((c for c in st.session_state.cases if c["id"] == case_id), None)
    if case:
        case["status"] = "closed"
        case["closed_date"] = datetime.now().isoformat()
        save_cases(st.session_state.cases)
        st.success(f"🔒 Closed case: {case['name']}")
        st.rerun()


def reopen_case(case_id):
    """Reopen a case"""
    case = next((c for c in st.session_state.cases if c["id"] == case_id), None)
    if case:
        case["status"] = "active"
        if "closed_date" in case:
            del case["closed_date"]
        save_cases(st.session_state.cases)
        st.success(f"🔓 Reopened case: {case['name']}")
        st.rerun()


def delete_case(case_id):
    """Delete a case"""
    if f"confirm_delete_case_{case_id}" not in st.session_state:
        st.session_state[f"confirm_delete_case_{case_id}"] = True
        st.warning("⚠️ Really delete this case? This cannot be undone. Click delete again to confirm.")
        st.rerun()
    else:
        # Actually delete
        st.session_state.cases = [c for c in st.session_state.cases if c["id"] != case_id]
        save_cases(st.session_state.cases)
        
        # Clear confirmation state
        del st.session_state[f"confirm_delete_case_{case_id}"]
        
        st.success("✅ Case deleted")
        st.rerun()


def generate_case_report(client, case):
    """Generate a case report"""
    st.subheader(f"📄 Case Report: {case['name']}")
    
    # Report header
    report_content = []
    report_content.append(f"# Case Report: {case['name']}")
    report_content.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report_content.append(f"**Case ID:** {case['id']}")
    report_content.append(f"**Status:** {case.get('status', 'unknown').title()}")
    report_content.append(f"**Created:** {format_timestamp(case.get('created_date', ''))}")
    
    if case.get("description"):
        report_content.append(f"**Description:** {case['description']}")
    
    report_content.append("")
    
    # Files analysis
    files = case.get("files", [])
    report_content.append(f"## Files Analysis ({len(files)} files)")
    
    for file_info in files:
        file_id = file_info.get("file_id", "")
        filename = file_info.get("filename", "unknown")
        
        report_content.append(f"### 📄 {filename}")
        
        # Get analysis for this file
        analysis_data = client.get_analysis(file_id)
        
        if "error" not in analysis_data:
            analysis = analysis_data.get("analysis", {})
            
            report_content.append(f"- **Parser:** {analysis.get('parser_name', 'unknown')}")
            report_content.append(f"- **Severity:** {analysis.get('severity', 'LOW')}")
            report_content.append(f"- **Risk Score:** {analysis.get('risk_score', 0.0):.2f}")
            
            threats = analysis.get("threats_detected", [])
            if threats:
                report_content.append(f"- **Threats Detected:** {len(threats)}")
                for threat in threats:
                    report_content.append(f"  - {threat.get('type', 'unknown')}: {threat.get('description', 'No description')}")
            else:
                report_content.append("- **Threats:** None detected")
            
            recommendations = analysis.get("recommendations", [])
            if recommendations:
                report_content.append("- **Recommendations:**")
                for rec in recommendations:
                    report_content.append(f"  - {rec}")
        else:
            report_content.append("- **Status:** Analysis not available")
        
        report_content.append("")
    
    # Case summary
    report_content.append("## Summary")
    
    # Calculate overall risk
    all_analyses = []
    for file_info in files:
        analysis_data = client.get_analysis(file_info.get("file_id", ""))
        if "error" not in analysis_data:
            all_analyses.append(analysis_data.get("analysis", {}))
    
    if all_analyses:
        total_threats = sum(len(a.get("threats_detected", [])) for a in all_analyses)
        avg_risk = sum(a.get("risk_score", 0.0) for a in all_analyses) / len(all_analyses)
        
        report_content.append(f"- **Total files analyzed:** {len(all_analyses)}")
        report_content.append(f"- **Total threats detected:** {total_threats}")
        report_content.append(f"- **Average risk score:** {avg_risk:.2f}")
        
        if avg_risk > 0.7:
            report_content.append("- **Overall assessment:** HIGH RISK - Immediate action required")
        elif avg_risk > 0.4:
            report_content.append("- **Overall assessment:** MEDIUM RISK - Monitor closely")
        else:
            report_content.append("- **Overall assessment:** LOW RISK - Standard precautions sufficient")
    
    # Display report
    report_text = "\n".join(report_content)
    st.markdown(report_text)
    
    # Download button
    st.download_button(
        label="📥 Download Report",
        data=report_text,
        file_name=f"case_report_{case['id']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
        mime="text/markdown"
    )


def show_file_analysis(client, file_id, filename):
    """Show analysis for a specific file"""
    st.subheader(f"🔍 Analysis: {filename}")
    
    analysis_data = client.get_analysis(file_id)
    
    if "error" in analysis_data:
        st.error("❌ Could not load analysis")
        return
    
    analysis = analysis_data.get("analysis", {})
    
    # Basic metrics
    col1, col2, col3 = st.columns(3)
    
    with col1:
        severity = analysis.get("severity", "LOW")
        color = get_severity_color(severity)
        st.metric("⚠️ Severity", severity)
        st.markdown(f"<div style='color: {color}'>■ {severity}</div>", unsafe_allow_html=True)
    
    with col2:
        risk_score = analysis.get("risk_score", 0.0)
        st.metric("🎯 Risk Score", f"{risk_score:.2f}")
    
    with col3:
        threats = analysis.get("threats_detected", [])
        st.metric("🚨 Threats", len(threats))
    
    # Summary and recommendations
    summary = analysis.get("summary", "")
    if summary:
        st.markdown(f"**📝 Summary:** {summary}")
    
    recommendations = analysis.get("recommendations", [])
    if recommendations:
        st.markdown("**💡 Recommendations:**")
        for rec in recommendations:
            st.write(f"• {rec}")


def show_case_statistics():
    """Show case statistics"""
    cases = st.session_state.cases
    
    if not cases:
        st.info("No cases to analyze")
        return
    
    # Status distribution
    status_counts = {}
    for case in cases:
        status = case.get("status", "unknown")
        status_counts[status] = status_counts.get(status, 0) + 1
    
    st.markdown("**📊 Cases by Status:**")
    for status, count in status_counts.items():
        st.write(f"• {status.title()}: {count}")
    
    # File distribution
    total_files = sum(len(case.get("files", [])) for case in cases)
    avg_files = total_files / len(cases) if cases else 0
    
    st.markdown(f"**📁 Average files per case:** {avg_files:.1f}")


def load_cases():
    """Load cases from file"""
    cases_file = Path("data/cases.json")
    
    try:
        if cases_file.exists():
            with open(cases_file, "r") as f:
                return json.load(f)
    except Exception as e:
        st.error(f"Error loading cases: {e}")
    
    return []


def save_cases(cases):
    """Save cases to file"""
    cases_file = Path("data/cases.json")
    cases_file.parent.mkdir(parents=True, exist_ok=True)
    
    try:
        with open(cases_file, "w") as f:
            json.dump(cases, f, indent=2, default=str)
    except Exception as e:
        st.error(f"Error saving cases: {e}")
def show_cases_page():
    """Main entry point for cases page"""
    from utils.api_client import get_api_client
    client = get_api_client()
    