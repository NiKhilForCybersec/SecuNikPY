"""
SecuNik - Parser Registry
Central management and discovery of all forensic parsers

Location: backend/app/core/parsers/__init__.py
"""

import logging
from typing import Dict, List, Optional, Any
from pathlib import Path

# Import all parser factories
from .document_forensics.pdf_analyzer import create_parser as create_pdf_parser
from .archive_forensics.zip_parser import create_parser as create_zip_parser
from .log_forensics.windows_logs.evtx_parser import create_parser as create_evtx_parser
from .network_forensics.pcap_parser import create_parser as create_pcap_parser
from .email_forensics.pst_parser import create_parser as create_email_parser
from .registry_forensics.registry_parser import create_parser as create_registry_parser
from .malware_analysis.pe_analyzer import create_parser as create_pe_parser

logger = logging.getLogger(__name__)

class ParserRegistry:
    """Central registry for all forensic parsers"""
    
    def __init__(self):
        self.parsers = {}
        self.parser_factories = {}
        self._register_all_parsers()
    
    def _register_all_parsers(self):
        """Register all available parsers"""
        
        # Document Forensics
        self._register_parser("pdf_analyzer", create_pdf_parser, 
                             [".pdf"], "PDF Document Analysis")
        
        # Archive Forensics  
        self._register_parser("zip_parser", create_zip_parser,
                             [".zip", ".rar", ".7z"], "Archive Analysis")
        
        # Log Forensics
        self._register_parser("evtx_parser", create_evtx_parser,
                             [".evtx"], "Windows Event Log Analysis")
        
        # Network Forensics
        self._register_parser("pcap_parser", create_pcap_parser,
                             [".pcap", ".pcapng", ".cap"], "Network Packet Analysis")
        
        # Email Forensics
        self._register_parser("email_parser", create_email_parser,
                             [".pst", ".ost", ".eml", ".msg"], "Email Forensics Analysis")
        
        # Registry Forensics
        self._register_parser("registry_parser", create_registry_parser,
                             [".reg", ".dat", ".hiv"], "Windows Registry Analysis")
        
        # Malware Analysis
        self._register_parser("pe_analyzer", create_pe_parser,
                             [".exe", ".dll", ".sys", ".scr", ".com"], "PE File Analysis")
        
        logger.info(f"Registered {len(self.parser_factories)} parsers")
    
    def _register_parser(self, name: str, factory_func, supported_extensions: List[str], 
                        description: str):
        """Register a parser with the registry"""
        self.parser_factories[name] = {
            "factory": factory_func,
            "extensions": supported_extensions,
            "description": description
        }
    
    def get_parser_for_file(self, file_path: str):
        """Get appropriate parser for a file"""
        file_extension = Path(file_path).suffix.lower()
        
        # Check for exact extension matches first
        for parser_name, parser_info in self.parser_factories.items():
            if file_extension in parser_info["extensions"]:
                try:
                    parser = parser_info["factory"]()
                    if parser.can_parse(file_path):
                        logger.info(f"Selected {parser_name} for {file_path}")
                        return parser
                except Exception as e:
                    logger.warning(f"Failed to create {parser_name}: {e}")
                    continue
        
        # Check for filename-based detection (e.g., registry files)
        filename = Path(file_path).name.lower()
        registry_files = ["system", "software", "sam", "security", "ntuser.dat"]
        if any(reg_file in filename for reg_file in registry_files):
            try:
                parser = self.parser_factories["registry_parser"]["factory"]()
                if parser.can_parse(file_path):
                    logger.info(f"Selected registry_parser for {file_path}")
                    return parser
            except Exception as e:
                logger.warning(f"Failed to create registry parser: {e}")
        
        logger.warning(f"No suitable parser found for {file_path}")
        return None
    
    def get_all_parsers(self) -> Dict[str, Any]:
        """Get information about all registered parsers"""
        parser_info = {}
        
        for name, info in self.parser_factories.items():
            parser_info[name] = {
                "description": info["description"],
                "supported_extensions": info["extensions"],
                "available": self._test_parser_availability(name)
            }
        
        return parser_info
    
    def _test_parser_availability(self, parser_name: str) -> bool:
        """Test if a parser is available (dependencies satisfied)"""
        try:
            parser = self.parser_factories[parser_name]["factory"]()
            return True
        except Exception as e:
            logger.debug(f"Parser {parser_name} not available: {e}")
            return False
    
    def get_supported_file_types(self) -> List[str]:
        """Get all supported file extensions"""
        extensions = set()
        for parser_info in self.parser_factories.values():
            extensions.update(parser_info["extensions"])
        return sorted(list(extensions))
    
    async def analyze_file_with_ai(self, file_path: str, use_ai: bool = True, analysis_type: str = "comprehensive"):
        """Analyze a file using the appropriate parser and enhance with AI intelligence"""
        parser = self.get_parser_for_file(file_path)
        
        if parser is None:
            return self._create_unsupported_result(file_path)
        
        try:
            # Get raw data extraction from parser
            raw_result = parser.parse(file_path)
            logger.info(f"Data extraction completed for {file_path}")
            
            # Enhance with AI if available and requested
            if use_ai:
                try:
                    from ..ai import create_ai_client
                    ai_client = create_ai_client()
                    
                    if ai_client.is_available:
                        enhanced_result = await ai_client.analyze_file_with_intelligence(raw_result, analysis_type)
                        logger.info(f"AI enhancement completed for {file_path}")
                        return enhanced_result
                    else:
                        logger.warning("AI not available, returning raw extraction result")
                        return raw_result
                        
                except Exception as e:
                    logger.error(f"AI enhancement failed for {file_path}: {e}")
                    logger.info("Returning raw extraction result")
                    return raw_result
            else:
                return raw_result
                
        except Exception as e:
            logger.error(f"Analysis failed for {file_path}: {e}")
            return self._create_error_result(file_path, str(e))

    def analyze_file(self, file_path: str):
        """Legacy sync method - analyze a file using the appropriate parser (no AI enhancement)"""
        parser = self.get_parser_for_file(file_path)
        
        if parser is None:
            return self._create_unsupported_result(file_path)
        
        try:
            result = parser.parse(file_path)
            logger.info(f"Analysis completed for {file_path}")
            return result
        except Exception as e:
            logger.error(f"Analysis failed for {file_path}: {e}")
            return self._create_error_result(file_path, str(e))
    
    def _create_unsupported_result(self, file_path: str):
        """Create result for unsupported file types"""
        from datetime import datetime
        from ..models.analysis import AnalysisResult, Severity
        
        return AnalysisResult(
            file_path=file_path,
            parser_name="Unsupported",
            analysis_type="Unsupported File Type",
            timestamp=datetime.now(),
            summary=f"File type not supported for analysis: {Path(file_path).suffix}",
            details={
                "error": "Unsupported file type",
                "supported_types": self.get_supported_file_types()
            },
            threats_detected=[],
            iocs_found=[],
            severity=Severity.LOW,
            risk_score=0.0,
            recommendations=[
                "Verify file type and format",
                "Check if additional parsers are needed",
                "Consider manual analysis if file contains evidence"
            ]
        )
    
    def _create_error_result(self, file_path: str, error_message: str):
        """Create result for analysis errors"""
        from datetime import datetime
        from ..models.analysis import AnalysisResult, Severity
        
        return AnalysisResult(
            file_path=file_path,
            parser_name="Error",
            analysis_type="Analysis Error",
            timestamp=datetime.now(),
            summary=f"Analysis failed: {error_message}",
            details={"error": error_message},
            threats_detected=[],
            iocs_found=[],
            severity=Severity.LOW,
            risk_score=0.0,
            recommendations=[
                "Check file integrity and format",
                "Verify parser dependencies are installed",
                "Review error logs for details"
            ]
        )

# Global parser registry instance
parser_registry = ParserRegistry()

# Convenience functions
def get_parser_for_file(file_path: str):
    """Get appropriate parser for a file"""
    return parser_registry.get_parser_for_file(file_path)

def analyze_file(file_path: str):
    """Analyze a file using the appropriate parser (raw extraction only)"""
    return parser_registry.analyze_file(file_path)

async def analyze_file_with_ai(file_path: str, use_ai: bool = True, analysis_type: str = "comprehensive"):
    """Analyze a file with AI enhancement"""
    return await parser_registry.analyze_file_with_ai(file_path, use_ai, analysis_type)

def get_all_parsers():
    """Get information about all registered parsers"""
    return parser_registry.get_all_parsers()

def get_supported_file_types():
    """Get all supported file extensions"""
    return parser_registry.get_supported_file_types()

# Export registry for external use
__all__ = [
    'ParserRegistry',
    'parser_registry',
    'get_parser_for_file',
    'analyze_file',
    'get_all_parsers',
    'get_supported_file_types'
]