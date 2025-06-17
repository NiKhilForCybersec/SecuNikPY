"""
AI Chat Component for SecuNik Frontend
Provides interactive AI-powered security analysis chat
"""

import streamlit as st
import json
from datetime import datetime
from typing import Dict, List, Optional
import asyncio

def render_ai_chat(api_client):
    """Render AI chat interface"""
    st.title("🤖 AI Security Assistant")
    
    # Initialize chat history in session state
    if "chat_history" not in st.session_state:
        st.session_state.chat_history = []
    
    if "ai_context" not in st.session_state:
        st.session_state.ai_context = None
    
    # Check AI availability
    if not api_client.check_ai_availability():
        st.warning("⚠️ AI features require OpenAI API key configuration")
        with st.expander("Setup Instructions"):
            st.markdown("""
            **To enable AI features:**
            1. Get an API key from [OpenAI](https://platform.openai.com/api-keys)
            2. Set the environment variable: `export OPENAI_API_KEY="your-key"`
            3. Restart the backend server
            4. Refresh this page
            """)
        return
    
    # Context selection
    col1, col2 = st.columns([3, 1])
    
    with col1:
        st.markdown("### Chat with AI about your security analysis")
    
    with col2:
        if st.button("🔄 Clear Chat", use_container_width=True):
            st.session_state.chat_history = []
            st.rerun()
    
    # Analysis context selector
    with st.expander("📎 Attach Analysis Context", expanded=False):
        available_analyses = get_available_analyses(api_client)
        
        if available_analyses:
            selected_file = st.selectbox(
                "Select analysis to discuss:",
                options=["None"] + [f"{a['filename']} ({a['timestamp']})" for a in available_analyses],
                help="Attach a completed analysis for context-aware discussion"
            )
            
            if selected_file != "None" and st.button("📎 Attach Context"):
                # Find the selected analysis
                for analysis in available_analyses:
                    if f"{analysis['filename']} ({analysis['timestamp']})" == selected_file:
                        st.session_state.ai_context = analysis
                        st.success(f"✅ Attached context: {analysis['filename']}")
                        break
        else:
            st.info("No analyses available. Upload and analyze files first.")
    
    # Display current context
    if st.session_state.ai_context:
        context = st.session_state.ai_context
        st.info(f"📎 Context: {context['filename']} - {context.get('summary', 'No summary')[:100]}...")
    
    # Chat interface
    chat_container = st.container()
    
    # Display chat history
    with chat_container:
        for message in st.session_state.chat_history:
            render_message(message)
    
    # Input area
    with st.form("chat_form", clear_on_submit=True):
        col1, col2 = st.columns([5, 1])
        
        with col1:
            user_input = st.text_area(
                "Ask about security threats, IOCs, or analysis results...",
                height=100,
                placeholder="Example: What are the main threats in this analysis? Are there any suspicious IP addresses?",
                label_visibility="collapsed"
            )
        
        with col2:
            submitted = st.form_submit_button("🚀 Send", use_container_width=True)
        
        # Quick action buttons
        st.markdown("**Quick Actions:**")
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            threat_summary = st.form_submit_button("🎯 Threat Summary", use_container_width=True)
        with col2:
            ioc_list = st.form_submit_button("🔍 List IOCs", use_container_width=True)
        with col3:
            recommendations = st.form_submit_button("💡 Recommendations", use_container_width=True)
        with col4:
            timeline = st.form_submit_button("📅 Timeline", use_container_width=True)
    
    # Handle submissions
    if submitted and user_input:
        handle_chat_message(api_client, user_input, chat_container)
    
    # Handle quick actions
    if threat_summary:
        handle_chat_message(api_client, "Provide a comprehensive threat summary of the current analysis.", chat_container)
    elif ioc_list:
        handle_chat_message(api_client, "List all IOCs found in the analysis with their types and confidence levels.", chat_container)
    elif recommendations:
        handle_chat_message(api_client, "What are your security recommendations based on this analysis?", chat_container)
    elif timeline:
        handle_chat_message(api_client, "Create a timeline of events based on the analysis.", chat_container)
    
    # Sidebar with chat options
    with st.sidebar:
        st.markdown("### 🤖 AI Chat Settings")
        
        # Model selection
        model = st.selectbox(
            "AI Model",
            ["gpt-4-turbo-preview", "gpt-3.5-turbo"],
            help="Select the AI model to use"
        )
        
        # Temperature slider
        temperature = st.slider(
            "Creativity",
            min_value=0.0,
            max_value=1.0,
            value=0.7,
            step=0.1,
            help="Higher values make responses more creative"
        )
        
        # Export chat
        if st.session_state.chat_history:
            if st.button("💾 Export Chat", use_container_width=True):
                export_chat_history()
        
        # AI capabilities info
        with st.expander("AI Capabilities"):
            st.markdown("""
            **The AI can help with:**
            - 🎯 Threat identification and analysis
            - 🔍 IOC extraction and correlation
            - 📊 Risk assessment
            - 💡 Security recommendations
            - 📅 Timeline reconstruction
            - 🔗 Event correlation
            - 📝 Report generation
            - ❓ Answering security questions
            """)


def handle_chat_message(api_client, user_input: str, container):
    """Handle sending a chat message"""
    # Add user message to history
    user_message = {
        "role": "user",
        "content": user_input,
        "timestamp": datetime.now().isoformat()
    }
    st.session_state.chat_history.append(user_message)
    
    # Display user message immediately
    with container:
        render_message(user_message)
    
    # Get AI response
    with st.spinner("🤔 AI is thinking..."):
        # Prepare context
        context = None
        if st.session_state.ai_context:
            context = {
                "file_id": st.session_state.ai_context.get("file_id"),
                "filename": st.session_state.ai_context.get("filename"),
                "analysis_summary": st.session_state.ai_context.get("summary"),
                "threats": st.session_state.ai_context.get("threats", []),
                "iocs": st.session_state.ai_context.get("iocs", [])
            }
        
        # Get conversation history for context
        conversation_history = [
            {"role": msg["role"], "content": msg["content"]} 
            for msg in st.session_state.chat_history[-10:]  # Last 10 messages
        ]
        
        # Call AI chat endpoint
        response = api_client.ai_chat(
            message=user_input,
            conversation_history=conversation_history,
            context=context
        )
        
        if "error" in response:
            ai_message = {
                "role": "assistant",
                "content": f"❌ Error: {response.get('error', 'Unknown error')}",
                "timestamp": datetime.now().isoformat()
            }
        else:
            ai_message = {
                "role": "assistant",
                "content": response.get("response", "I couldn't generate a response."),
                "timestamp": datetime.now().isoformat()
            }
        
        # Add AI response to history
        st.session_state.chat_history.append(ai_message)
        
        # Display AI response
        with container:
            render_message(ai_message)
        
        # Auto-scroll to bottom
        st.rerun()


def render_message(message: Dict):
    """Render a chat message"""
    role = message["role"]
    content = message["content"]
    timestamp = message.get("timestamp", "")
    
    if role == "user":
        with st.chat_message("user"):
            st.markdown(content)
            if timestamp:
                st.caption(f"You • {format_timestamp(timestamp)}")
    else:
        with st.chat_message("assistant"):
            # Check if content has special formatting
            if "```" in content:
                # Contains code blocks
                st.markdown(content)
            elif any(indicator in content for indicator in ["##", "**", "- ", "1. "]):
                # Contains markdown formatting
                st.markdown(content)
            else:
                # Plain text
                st.write(content)
            
            if timestamp:
                st.caption(f"AI Assistant • {format_timestamp(timestamp)}")


def get_available_analyses(api_client) -> List[Dict]:
    """Get list of available analyses for context"""
    try:
        # Get recent analyses
        analyses = api_client.list_analyses()
        
        if "error" not in analyses:
            # Format for display
            formatted = []
            for analysis in analyses.get("analyses", [])[:10]:  # Last 10
                formatted.append({
                    "file_id": analysis.get("file_id"),
                    "filename": analysis.get("filename", "Unknown"),
                    "timestamp": analysis.get("timestamp", ""),
                    "summary": analysis.get("summary", ""),
                    "threats": analysis.get("threats", []),
                    "iocs": analysis.get("iocs", [])
                })
            return formatted
    except:
        pass
    
    return []


def format_timestamp(timestamp: str) -> str:
    """Format timestamp for display"""
    try:
        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        now = datetime.now()
        
        # If today, show time only
        if dt.date() == now.date():
            return dt.strftime("%I:%M %p")
        # If this year, show month and day
        elif dt.year == now.year:
            return dt.strftime("%b %d, %I:%M %p")
        # Otherwise show full date
        else:
            return dt.strftime("%b %d, %Y")
    except:
        return ""


def export_chat_history():
    """Export chat history to JSON"""
    if not st.session_state.chat_history:
        return
    
    export_data = {
        "export_date": datetime.now().isoformat(),
        "context": st.session_state.ai_context,
        "messages": st.session_state.chat_history
    }
    
    json_str = json.dumps(export_data, indent=2)
    
    st.download_button(
        label="📥 Download Chat History",
        data=json_str,
        file_name=f"secunik_chat_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
        mime="application/json",
        use_container_width=True
    )


def render_ai_insights_panel(api_client, analysis_data: Dict):
    """Render AI insights panel for analysis results"""
    st.markdown("### 🧠 AI Insights")
    
    if not api_client.check_ai_availability():
        st.info("Enable AI features for advanced insights")
        return
    
    # Generate insights based on analysis
    with st.spinner("Generating AI insights..."):
        insights = api_client.generate_insights(analysis_data)
        
        if "error" not in insights:
            # Threat Assessment
            if insights.get("threat_assessment"):
                st.markdown("**🎯 Threat Assessment**")
                st.write(insights["threat_assessment"])
            
            # Key Findings
            if insights.get("key_findings"):
                st.markdown("**🔍 Key Findings**")
                for finding in insights["key_findings"]:
                    st.write(f"• {finding}")
            
            # Risk Score Explanation
            if insights.get("risk_explanation"):
                st.markdown("**📊 Risk Analysis**")
                st.write(insights["risk_explanation"])
            
            # Recommended Actions
            if insights.get("recommended_actions"):
                st.markdown("**💡 Recommended Actions**")
                for i, action in enumerate(insights["recommended_actions"], 1):
                    st.write(f"{i}. {action}")
        else:
            st.error("Failed to generate AI insights")


# Example usage in main app
def main():
    """Example usage"""
    # This would be imported and used in your main Streamlit app
    from utils.api_client import APIClient
    
    # Initialize API client
    api_client = APIClient()
    
    # Render AI chat
    render_ai_chat(api_client)


if __name__ == "__main__":
    # For testing
    st.set_page_config(
        page_title="SecuNik AI Chat",
        page_icon="🤖",
        layout="wide"
    )
    main()
def show_ai_chat():
    """Main entry point for AI chat page - wrapper for render_ai_chat"""
    from utils.api_client import get_api_client
    client = get_api_client()
    render_ai_chat(client)