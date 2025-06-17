"""
AI Chat Component for SecuNik
Provides natural language interface for cybersecurity analysis
"""

import streamlit as st
import time
from datetime import datetime
from utils.api_client import get_api_client


def show_ai_chat():
    """Display the AI chat interface"""
    st.title("🤖 AI Assistant")
    
    client = get_api_client()
    
    # Check AI status
    ai_status = client.get_ai_status()
    
    if "error" in ai_status:
        st.error("❌ Could not connect to AI service")
        return
    
    if not ai_status.get("ai_available", False):
        show_ai_setup_instructions()
        return
    
    # AI capabilities overview
    show_ai_capabilities(client)
    
    st.markdown("---")
    
    # Chat interface
    show_chat_interface(client)
    
    st.markdown("---")
    
    # AI tools section
    show_ai_tools(client)


def show_ai_setup_instructions():
    """Show AI setup instructions"""
    st.warning("⚠️ AI Assistant requires configuration")
    
    with st.expander("🔧 Setup Instructions", expanded=True):
        st.markdown("""
        **To enable the AI Assistant:**
        
        1. **Get OpenAI API Key:**
           - Visit https://openai.com
           - Create an account or sign in
           - Go to API section and create a new API key
        
        2. **Configure the key:**
           ```bash
           # Windows (Command Prompt)
           set OPENAI_API_KEY=your-api-key-here
           
           # Windows (PowerShell)
           $env:OPENAI_API_KEY="your-api-key-here"
           
           # Linux/Mac
           export OPENAI_API_KEY="your-api-key-here"
           ```
        
        3. **Restart the backend:**
           ```bash
           cd backend
           python run.py
           ```
        
        4. **Refresh this page**
        
        **💡 Once configured, the AI Assistant can:**
        - Answer questions about your analysis results
        - Provide threat intelligence insights
        - Help interpret cybersecurity findings
        - Correlate evidence across multiple files
        - Generate detailed security reports
        """)
    
    if st.button("🔄 Check AI Status Again"):
        st.rerun()


def show_ai_capabilities(client):
    """Show AI capabilities overview"""
    st.subheader("🎯 AI Capabilities")
    
    capabilities_data = client.get_ai_capabilities()
    
    if "error" in capabilities_data:
        st.warning("⚠️ Could not load AI capabilities")
        return
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("**🤖 AI Features:**")
        ai_capabilities = capabilities_data.get("ai_capabilities", [])
        for capability in ai_capabilities:
            st.write(f"✅ {capability}")
    
    with col2:
        st.markdown("**📊 Basic Features:**")
        basic_capabilities = capabilities_data.get("basic_capabilities", [])
        for capability in basic_capabilities:
            st.write(f"• {capability}")
    
    # Supported file types
    with st.expander("📁 Supported File Types"):
        supported_types = capabilities_data.get("supported_file_types", [])
        for file_type in supported_types:
            st.write(f"• {file_type}")


def show_chat_interface(client):
    """Show the chat interface"""
    st.subheader("💬 Chat with AI Assistant")
    
    # Initialize chat history
    if "chat_history" not in st.session_state:
        st.session_state.chat_history = []
        # Add welcome message
        st.session_state.chat_history.append({
            "role": "assistant",
            "content": "Hello! I'm your SecuNik AI Assistant. I can help you analyze cybersecurity threats, interpret analysis results, and provide security recommendations. What would you like to know?",
            "timestamp": datetime.now()
        })
    
    # Display chat history
    chat_container = st.container()
    
    with chat_container:
        for message in st.session_state.chat_history:
            if message["role"] == "user":
                show_user_message(message)
            else:
                show_ai_message(message)
    
    # Chat input
    with st.form("chat_form", clear_on_submit=True):
        col1, col2 = st.columns([4, 1])
        
        with col1:
            user_input = st.text_area(
                "Ask me anything about cybersecurity analysis:",
                placeholder="e.g., 'What threats were detected in my recent uploads?' or 'Explain this analysis result'",
                height=80,
                key="chat_input"
            )
        
        with col2:
            # File context selector
            files_data = client.list_files()
            file_options = ["None"]
            
            if "error" not in files_data:
                files = files_data.get("files", [])
                file_options.extend([f"{f['filename']} ({f['file_id'][:8]})" for f in files])
            
            selected_file = st.selectbox(
                "File Context:",
                file_options,
                help="Select a file to ask questions about"
            )
            
            submit_button = st.form_submit_button("💬 Send", use_container_width=True)
    
    if submit_button and user_input.strip():
        # Extract file ID if selected
        file_id = None
        if selected_file != "None":
            file_id = selected_file.split("(")[-1].replace(")", "")
        
        # Add user message to history
        st.session_state.chat_history.append({
            "role": "user",
            "content": user_input,
            "timestamp": datetime.now(),
            "file_context": selected_file if selected_file != "None" else None
        })
        
        # Get AI response
        with st.spinner("🤖 AI is thinking..."):
            response = client.chat_with_ai(user_input, file_id=file_id)
            
            if "error" not in response:
                # Add AI response to history
                st.session_state.chat_history.append({
                    "role": "assistant",
                    "content": response.get("response", "I couldn't process that request."),
                    "timestamp": datetime.now(),
                    "confidence": response.get("confidence", 0.0),
                    "sources": response.get("sources", []),
                    "suggestions": response.get("suggestions", [])
                })
            else:
                st.error(f"❌ AI Error: {response['error']}")
        
        st.rerun()


def show_user_message(message):
    """Display user message"""
    st.markdown(f"""
    <div style="display: flex; justify-content: flex-end; margin: 10px 0;">
        <div style="background: #e3f2fd; padding: 10px; border-radius: 10px; max-width: 70%; border: 1px solid #2196f3;">
            <div style="font-weight: bold; color: #1976d2;">👤 You</div>
            <div style="margin-top: 5px;">{message['content']}</div>
            <div style="font-size: 0.8em; color: #666; margin-top: 5px;">
                {message['timestamp'].strftime("%H:%M:%S")}
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)


def show_ai_message(message):
    """Display AI message"""
    content = message['content']
    confidence = message.get('confidence', 0.0)
    sources = message.get('sources', [])
    suggestions = message.get('suggestions', [])
    
    st.markdown(f"""
    <div style="display: flex; justify-content: flex-start; margin: 10px 0;">
        <div style="background: #f0f2f6; padding: 10px; border-radius: 10px; max-width: 70%; border: 1px solid #666;">
            <div style="font-weight: bold; color: #2a5298;">🤖 AI Assistant</div>
            <div style="margin-top: 5px;">{content}</div>
            <div style="font-size: 0.8em; color: #666; margin-top: 5px;">
                {message['timestamp'].strftime("%H:%M:%S")}
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    # Show confidence and sources if available
    if confidence > 0 or sources:
        col1, col2 = st.columns(2)
        
        with col1:
            if confidence > 0:
                st.caption(f"🎯 Confidence: {confidence:.1%}")
        
        with col2:
            if sources:
                st.caption(f"📚 Sources: {', '.join(sources)}")
    
    # Show suggestions
    if suggestions:
        st.markdown("**💡 Suggested follow-ups:**")
        for suggestion in suggestions:
            if st.button(suggestion, key=f"suggest_{hash(suggestion)}_{message['timestamp']}"):
                # Add suggestion as user message
                st.session_state.chat_history.append({
                    "role": "user",
                    "content": suggestion,
                    "timestamp": datetime.now()
                })
                st.rerun()


def show_ai_tools(client):
    """Show AI-powered analysis tools"""
    st.subheader("🛠️ AI Analysis Tools")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # File correlation tool
        st.markdown("**🔗 File Correlation Analysis**")
        st.write("Find connections between uploaded files using AI")
        
        if st.button("🚀 Run Correlation Analysis", use_container_width=True):
            run_correlation_analysis(client)
    
    with col2:
        # Bulk AI analysis tool
        st.markdown("**📊 Bulk AI Analysis**")
        st.write("Enhance all uploaded files with AI insights")
        
        if st.button("🤖 Run Bulk AI Analysis", use_container_width=True):
            run_bulk_ai_analysis(client)


def run_correlation_analysis(client):
    """Run AI-powered correlation analysis"""
    with st.spinner("🔗 Running correlation analysis..."):
        result = client.correlate_files()
        
        if "error" in result:
            st.error(f"❌ Correlation analysis failed: {result['error']}")
            return
        
        correlations = result.get("correlations", [])
        total_files = result.get("total_files", 0)
        
        st.success(f"✅ Correlation analysis complete!")
        st.info(f"📊 Analyzed {total_files} files, found {len(correlations)} correlations")
        
        if correlations:
            st.markdown("**🔗 Found Correlations:**")
            
            for correlation in correlations:
                file1 = correlation.get("file1", {})
                file2 = correlation.get("file2", {})
                correlation_type = correlation.get("correlation_type", "unknown")
                confidence = correlation.get("confidence", 0.0)
                common_elements = correlation.get("common_elements", [])
                
                with st.expander(f"🔗 {file1.get('filename', 'Unknown')} ↔ {file2.get('filename', 'Unknown')}"):
                    st.write(f"**Type:** {correlation_type}")
                    st.write(f"**Confidence:** {confidence:.1%}")
                    st.write(f"**Common Elements:** {', '.join(common_elements)}")
        else:
            st.info("ℹ️ No correlations found between uploaded files")


def run_bulk_ai_analysis(client):
    """Run bulk AI analysis on all files"""
    with st.spinner("🤖 Running bulk AI analysis..."):
        result = client.bulk_ai_analysis()
        
        if "error" in result:
            st.error(f"❌ Bulk AI analysis failed: {result['error']}")
            return
        
        total_files = result.get("total_files", 0)
        processed = result.get("successfully_processed", 0)
        results = result.get("results", [])
        
        st.success(f"✅ Bulk AI analysis complete!")
        st.info(f"📊 Processed {processed} of {total_files} files")
        
        # Show results summary
        if results:
            enhanced_count = sum(1 for r in results if r.get("ai_enhanced", False))
            st.metric("🤖 AI Enhanced Files", enhanced_count)
            
            # Show individual results
            with st.expander("📋 Detailed Results"):
                for result_item in results:
                    filename = result_item.get("filename", "unknown")
                    status = result_item.get("status", "unknown")
                    
                    if status == "completed":
                        st.success(f"✅ {filename} - Enhanced")
                    else:
                        error = result_item.get("error", "unknown error")
                        st.error(f"❌ {filename} - {error}")


def clear_chat_history():
    """Clear chat history"""
    if st.button("🗑️ Clear Chat History"):
        st.session_state.chat_history = []
        st.success("Chat history cleared!")
        st.rerun()


def export_chat_history():
    """Export chat history"""
    if "chat_history" not in st.session_state or not st.session_state.chat_history:
        st.info("No chat history to export")
        return
    
    # Create export content
    export_content = []
    export_content.append("# SecuNik AI Chat History")
    export_content.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    export_content.append("")
    
    for message in st.session_state.chat_history:
        role = "👤 User" if message["role"] == "user" else "🤖 AI Assistant"
        timestamp = message["timestamp"].strftime("%H:%M:%S")
        content = message["content"]
        
        export_content.append(f"## {role} ({timestamp})")
        export_content.append(content)
        export_content.append("")
    
    export_text = "\n".join(export_content)
    
    st.download_button(
        label="📥 Export Chat History",
        data=export_text,
        file_name=f"secunik_chat_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
        mime="text/markdown"
    )


# Add quick actions at the bottom
def show_quick_actions():
    """Show quick action buttons"""
    st.markdown("---")
    st.markdown("### ⚡ Quick Actions")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        clear_chat_history()
    
    with col2:
        export_chat_history()
    
    with col3:
        if st.button("🔄 Refresh AI Status"):
            st.rerun()