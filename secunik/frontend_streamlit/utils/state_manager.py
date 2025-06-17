import streamlit as st
from typing import Dict, Any

class StateManager:
    """Manage application state"""
    
    def __init__(self):
        if 'app_data' not in st.session_state:
            st.session_state.app_data = {
                'total_cases': 0,
                'total_files': 0,
                'risk_score': 0,
                'uploaded_files': [],
                'analysis_results': []
            }
    
    def get_total_cases(self) -> int:
        return st.session_state.app_data.get('total_cases', 0)
    
    def get_total_files(self) -> int:
        return st.session_state.app_data.get('total_files', 0)
    
    def get_risk_score(self) -> int:
        return st.session_state.app_data.get('risk_score', 0)
    
    def add_uploaded_file(self, file_info: Dict[str, Any]):
        st.session_state.app_data['uploaded_files'].append(file_info)
        st.session_state.app_data['total_files'] += 1
    
    def update_dashboard_data(self, data: Dict[str, Any]):
        st.session_state.app_data.update(data)