"""
State Manager for SecuNik Frontend
Manages application state and session data
"""

import streamlit as st
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, Optional, List


class StateManager:
    """Manages application state and persistence"""
    
    def __init__(self):
        self.initialize_session_state()
    
    def initialize_session_state(self):
        """Initialize session state with default values"""
        
        # Page state
        if "current_page" not in st.session_state:
            st.session_state.current_page = "dashboard"
        
        # File management state
        if "uploaded_files" not in st.session_state:
            st.session_state.uploaded_files = []
        
        if "selected_files" not in st.session_state:
            st.session_state.selected_files = []
        
        # Analysis state
        if "analysis_results" not in st.session_state:
            st.session_state.analysis_results = {}
        
        if "analysis_filters" not in st.session_state:
            st.session_state.analysis_filters = {
                "severity": "All",
                "type": "All",
                "sort_by": "Timestamp (Newest)"
            }
        
        # AI Chat state
        if "chat_history" not in st.session_state:
            st.session_state.chat_history = []
        
        if "ai_context" not in st.session_state:
            st.session_state.ai_context = None
        
        # Cases state
        if "cases" not in st.session_state:
            st.session_state.cases = []
        
        if "active_case" not in st.session_state:
            st.session_state.active_case = None
        
        # Settings state
        if "user_settings" not in st.session_state:
            st.session_state.user_settings = self.load_user_settings()
        
        # UI state
        if "notifications" not in st.session_state:
            st.session_state.notifications = []
        
        if "loading_states" not in st.session_state:
            st.session_state.loading_states = {}
        
        # Cache state
        if "cache_timestamps" not in st.session_state:
            st.session_state.cache_timestamps = {}
    
    def get_user_setting(self, key: str, default: Any = None) -> Any:
        """Get user setting value"""
        return st.session_state.user_settings.get(key, default)
    
    def set_user_setting(self, key: str, value: Any):
        """Set user setting value"""
        st.session_state.user_settings[key] = value
        self.save_user_settings()
    
    def load_user_settings(self) -> Dict[str, Any]:
        """Load user settings from file"""
        settings_file = Path("data/user_settings.json")
        
        default_settings = {
            # UI preferences
            "theme": "light",
            "auto_refresh": True,
            "refresh_interval": 30,
            "show_tooltips": True,
            "compact_view": False,
            
            # Analysis preferences
            "default_analysis_depth": "standard",
            "auto_analyze": True,
            "show_technical_details": False,
            
            # AI preferences
            "ai_auto_enhance": False,
            "ai_chat_suggestions": True,
            "ai_confidence_threshold": 0.7,
            
            # Notification preferences
            "show_notifications": True,
            "threat_alerts": True,
            "sound_alerts": False,
            
            # Display preferences
            "items_per_page": 10,
            "date_format": "YYYY-MM-DD HH:mm:ss",
            "timezone": "local"
        }
        
        try:
            if settings_file.exists():
                with open(settings_file, "r") as f:
                    saved_settings = json.load(f)
                    default_settings.update(saved_settings)
        except Exception as e:
            self.add_notification(f"Error loading settings: {e}", "error")
        
        return default_settings
    
    def save_user_settings(self):
        """Save user settings to file"""
        settings_file = Path("data/user_settings.json")
        settings_file.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            with open(settings_file, "w") as f:
                json.dump(st.session_state.user_settings, f, indent=2)
        except Exception as e:
            self.add_notification(f"Error saving settings: {e}", "error")
    
    def add_notification(self, message: str, type: str = "info", duration: int = 5):
        """Add a notification"""
        notification = {
            "id": f"notif_{datetime.now().timestamp()}",
            "message": message,
            "type": type,  # info, success, warning, error
            "timestamp": datetime.now(),
            "duration": duration,
            "dismissed": False
        }
        
        st.session_state.notifications.append(notification)
        
        # Limit notifications to prevent memory issues
        if len(st.session_state.notifications) > 50:
            st.session_state.notifications = st.session_state.notifications[-50:]
    
    def get_active_notifications(self) -> List[Dict[str, Any]]:
        """Get active (non-dismissed, non-expired) notifications"""
        now = datetime.now()
        active = []
        
        for notif in st.session_state.notifications:
            if not notif["dismissed"]:
                # Check if notification has expired
                expires_at = notif["timestamp"] + timedelta(seconds=notif["duration"])
                if now < expires_at:
                    active.append(notif)
                else:
                    notif["dismissed"] = True
        
        return active
    
    def dismiss_notification(self, notification_id: str):
        """Dismiss a notification"""
        for notif in st.session_state.notifications:
            if notif["id"] == notification_id:
                notif["dismissed"] = True
                break
    
    def clear_all_notifications(self):
        """Clear all notifications"""
        st.session_state.notifications = []
    
    def set_loading_state(self, key: str, loading: bool):
        """Set loading state for a component"""
        st.session_state.loading_states[key] = loading
    
    def is_loading(self, key: str) -> bool:
        """Check if component is in loading state"""
        return st.session_state.loading_states.get(key, False)
    
    def add_to_chat_history(self, role: str, content: str, metadata: Optional[Dict] = None):
        """Add message to chat history"""
        message = {
            "role": role,
            "content": content,
            "timestamp": datetime.now(),
            "metadata": metadata or {}
        }
        
        st.session_state.chat_history.append(message)
        
        # Limit chat history based on settings
        max_history = self.get_user_setting("ai_chat_history_limit", 100)
        if len(st.session_state.chat_history) > max_history:
            st.session_state.chat_history = st.session_state.chat_history[-max_history:]
    
    def clear_chat_history(self):
        """Clear chat history"""
        st.session_state.chat_history = []
        self.add_notification("Chat history cleared", "success")
    
    def set_ai_context(self, context: Optional[Dict[str, Any]]):
        """Set AI context for conversations"""
        st.session_state.ai_context = context
    
    def get_ai_context(self) -> Optional[Dict[str, Any]]:
        """Get current AI context"""
        return st.session_state.ai_context
    
    def add_case(self, case_data: Dict[str, Any]):
        """Add a new case"""
        case_data["id"] = f"case_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        case_data["created_at"] = datetime.now().isoformat()
        
        st.session_state.cases.append(case_data)
        self.save_cases()
        
        self.add_notification(f"Case '{case_data['name']}' created", "success")
    
    def update_case(self, case_id: str, updates: Dict[str, Any]):
        """Update an existing case"""
        for case in st.session_state.cases:
            if case["id"] == case_id:
                case.update(updates)
                case["updated_at"] = datetime.now().isoformat()
                self.save_cases()
                self.add_notification("Case updated", "success")
                return True
        
        self.add_notification("Case not found", "error")
        return False
    
    def delete_case(self, case_id: str):
        """Delete a case"""
        original_count = len(st.session_state.cases)
        st.session_state.cases = [c for c in st.session_state.cases if c["id"] != case_id]
        
        if len(st.session_state.cases) < original_count:
            self.save_cases()
            self.add_notification("Case deleted", "success")
            return True
        
        self.add_notification("Case not found", "error")
        return False
    
    def get_case(self, case_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific case"""
        for case in st.session_state.cases:
            if case["id"] == case_id:
                return case
        return None
    
    def get_active_cases(self) -> List[Dict[str, Any]]:
        """Get all active cases"""
        return [c for c in st.session_state.cases if c.get("status") == "active"]
    
    def save_cases(self):
        """Save cases to file"""
        cases_file = Path("data/cases.json")
        cases_file.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            with open(cases_file, "w") as f:
                json.dump(st.session_state.cases, f, indent=2, default=str)
        except Exception as e:
            self.add_notification(f"Error saving cases: {e}", "error")
    
    def load_cases(self):
        """Load cases from file"""
        cases_file = Path("data/cases.json")
        
        try:
            if cases_file.exists():
                with open(cases_file, "r") as f:
                    st.session_state.cases = json.load(f)
        except Exception as e:
            self.add_notification(f"Error loading cases: {e}", "error")
            st.session_state.cases = []
    
    def cache_data(self, key: str, data: Any, ttl_seconds: int = 300):
        """Cache data with TTL"""
        st.session_state.cache_timestamps[key] = {
            "data": data,
            "timestamp": datetime.now(),
            "ttl": ttl_seconds
        }
    
    def get_cached_data(self, key: str) -> Optional[Any]:
        """Get cached data if not expired"""
        if key not in st.session_state.cache_timestamps:
            return None
        
        cache_entry = st.session_state.cache_timestamps[key]
        expires_at = cache_entry["timestamp"] + timedelta(seconds=cache_entry["ttl"])
        
        if datetime.now() > expires_at:
            # Cache expired
            del st.session_state.cache_timestamps[key]
            return None
        
        return cache_entry["data"]
    
    def clear_cache(self, key: Optional[str] = None):
        """Clear cache (specific key or all)"""
        if key:
            if key in st.session_state.cache_timestamps:
                del st.session_state.cache_timestamps[key]
        else:
            st.session_state.cache_timestamps = {}
        
        self.add_notification("Cache cleared", "success")
    
    def set_analysis_filters(self, filters: Dict[str, str]):
        """Set analysis filters"""
        st.session_state.analysis_filters.update(filters)
    
    def get_analysis_filters(self) -> Dict[str, str]:
        """Get current analysis filters"""
        return st.session_state.analysis_filters.copy()
    
    def add_file_selection(self, file_id: str):
        """Add file to selection"""
        if file_id not in st.session_state.selected_files:
            st.session_state.selected_files.append(file_id)
    
    def remove_file_selection(self, file_id: str):
        """Remove file from selection"""
        if file_id in st.session_state.selected_files:
            st.session_state.selected_files.remove(file_id)
    
    def clear_file_selection(self):
        """Clear file selection"""
        st.session_state.selected_files = []
    
    def get_selected_files(self) -> List[str]:
        """Get selected file IDs"""
        return st.session_state.selected_files.copy()
    
    def export_state(self) -> Dict[str, Any]:
        """Export current state for backup"""
        return {
            "user_settings": st.session_state.user_settings,
            "cases": st.session_state.cases,
            "export_timestamp": datetime.now().isoformat(),
            "version": "1.0.0"
        }
    
    def import_state(self, state_data: Dict[str, Any]):
        """Import state from backup"""
        try:
            if "user_settings" in state_data:
                st.session_state.user_settings = state_data["user_settings"]
                self.save_user_settings()
            
            if "cases" in state_data:
                st.session_state.cases = state_data["cases"]
                self.save_cases()
            
            self.add_notification("State imported successfully", "success")
            
        except Exception as e:
            self.add_notification(f"Error importing state: {e}", "error")
    
    def reset_to_defaults(self):
        """Reset all state to defaults"""
        # Clear session state
        for key in list(st.session_state.keys()):
            if key.startswith(('uploaded_files', 'selected_files', 'analysis_', 'chat_', 'cases', 'notifications')):
                del st.session_state[key]
        
        # Reset to defaults
        self.initialize_session_state()
        
        # Clear persistent files
        data_dir = Path("data")
        if data_dir.exists():
            for file in ["user_settings.json", "cases.json"]:
                file_path = data_dir / file
                if file_path.exists():
                    file_path.unlink()
        
        self.add_notification("Application reset to defaults", "success")


# Global state manager instance
@st.cache_resource
def get_state_manager() -> StateManager:
    """Get cached state manager instance"""
    return StateManager()


# Helper functions for easier access
def add_notification(message: str, type: str = "info", duration: int = 5):
    """Add notification using global state manager"""
    state_manager = get_state_manager()
    state_manager.add_notification(message, type, duration)


def show_notifications():
    """Display active notifications"""
    state_manager = get_state_manager()
    notifications = state_manager.get_active_notifications()
    
    for notif in notifications:
        if notif["type"] == "success":
            st.success(notif["message"])
        elif notif["type"] == "error":
            st.error(notif["message"])
        elif notif["type"] == "warning":
            st.warning(notif["message"])
        else:
            st.info(notif["message"])


def get_setting(key: str, default: Any = None) -> Any:
    """Get user setting"""
    state_manager = get_state_manager()
    return state_manager.get_user_setting(key, default)


def set_setting(key: str, value: Any):
    """Set user setting"""
    state_manager = get_state_manager()
    state_manager.set_user_setting(key, value)