"""
Base abstract parser for all SecuNik parsers
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List
from pathlib import Path

class AbstractParser(ABC):
    """Abstract base class for all parsers"""
    
    name: str = "Abstract Parser"
    supported_extensions: List[str] = []
    
    def can_parse(self, file_path: str) -> bool:
        """Check if this parser can handle the file"""
        return Path(file_path).suffix.lower() in self.supported_extensions
    
    @abstractmethod
    async def parse(self, file_path: str) -> Dict[str, Any]:
        """Parse the file and extract data"""
        pass
    
    @abstractmethod
    async def analyze(self, file_path: str, extracted_data: Dict[str, Any]) -> Any:
        """Analyze the extracted data"""
        pass