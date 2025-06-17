"""
SecuNik - AI Integration Package
Advanced AI-powered cybersecurity analysis

Location: backend/app/core/ai/__init__.py
"""

from .openai_client import create_ai_client, SecuNikAI
from .prompt_templates import PromptTemplates
from .context_builder import ContextBuilder

__all__ = [
    'create_ai_client',
    'SecuNikAI',
    'PromptTemplates', 
    'ContextBuilder'
]

# Version information
__version__ = "1.0.0"
__author__ = "SecuNik Team"
__description__ = "AI-powered cybersecurity analysis and threat intelligence"