"""
SecuNik File Manager
Handles file storage, case management, and analysis results storage
Uses JSON-based storage system (no database required)
"""

import json
import shutil
import aiofiles
import aiofiles.os
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime
import uuid
import asyncio
import hashlib
import magic
import logging

from ..models.case import Case
from ..models.analysis import AnalysisResult

logger = logging.getLogger(__name__)

class FileManager:
    """
    File-based storage manager for SecuNik
    Handles all file operations and JSON-based data storage
    """
    
    def __init__(self, data_path: Path):
        self.data_path = Path(data_path)
        self.uploads_path = self.data_path / "uploads"
        self.cases_path = self.data_path / "cases"
        self.results_path = self.data_path / "results"
        self.exports_path = self.data_path / "exports"
        self.temp_path = self.data_path / "temp"
        
        # Ensure directories exist
        self.ensure_directories()
        
        # Initialize file type detector
        try:
            self.magic = magic.Magic(mime=True)
        except Exception as e:
            logger.warning(f"Failed to initialize python-magic: {e}")
            self.magic = None
    
    def ensure_directories(self):
        """Ensure all required directories exist"""
        directories = [
            self.data_path,
            self.uploads_path,
            self.cases_path,
            self.results_path,
            self.exports_path / "pdfs",
            self.exports_path / "json",
            self.exports_path / "csv",
            self.temp_path / "extractions",
            self.temp_path / "processing"
        ]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
    
    async def save_uploaded_file(self, file, file_id: str, case_id: str) -> Dict[str, Any]:
        """
        Save an uploaded file to the storage system
        """
        try:
            # Create case directory if it doesn't exist
            case_upload_path = self.uploads_path / case_id
            case_upload_path.mkdir(parents=True, exist_ok=True)
            
            # Generate unique filename
            original_name = file.filename
            file_extension = Path(original_name).suffix
            safe_filename = f"{file_id}_{original_name}"
            file_path = case_upload_path / safe_filename
            
            # Save file
            async with aiofiles.open(file_path, 'wb') as f:
                content = await file.read()
                await f.write(content)
            
            # Calculate file hash
            file_hash = hashlib.sha256(content).hexdigest()
            
            # Get file info
            file_size = len(content)
            file_type = self._detect_file_type(file_path)
            
            # Create file metadata
            file_metadata = {
                "file_id": file_id,
                "case_id": case_id,
                "original_filename": original_name,
                "stored_filename": safe_filename,
                "file_path": str(file_path),
                "file_size": file_size,
                "file_type": file_type,
                "file_hash": file_hash,
                "upload_timestamp": datetime.utcnow().isoformat(),
                "status": "uploaded"
            }
            
            # Save file metadata
            await self._save_file_metadata(file_id, case_id, file_metadata)
            
            logger.info(f"📁 File saved: {original_name} -> {file_path}")
            
            return {
                "file_id": file_id,
                "path": str(file_path),
                "size": file_size,
                "type": file_type,
                "hash": file_hash
            }
            
        except Exception as e:
            logger.error(f"❌ Error saving file: {str(e)}")
            raise
    
    async def _save_file_metadata(self, file_id: str, case_id: str, metadata: Dict[str, Any]):
        """Save file metadata to JSON"""
        try:
            # Create case results directory
            case_results_path = self.results_path / case_id
            case_results_path.mkdir(parents=True, exist_ok=True)
            
            # Save individual file metadata
            metadata_file = case_results_path / f"{file_id}_metadata.json"
            async with aiofiles.open(metadata_file, 'w') as f:
                await f.write(json.dumps(metadata, indent=2))
            
            # Update case index
            await self._update_case_index(case_id, file_id, metadata)
            
        except Exception as e:
            logger.error(f"❌ Error saving file metadata: {str(e)}")
            raise
    
    async def _update_case_index(self, case_id: str, file_id: str, file_metadata: Dict[str, Any]):
        """Update the case index with new file information"""
        try:
            case_index_file = self.cases_path / f"{case_id}_index.json"
            
            # Load existing index or create new
            if case_index_file.exists():
                async with aiofiles.open(case_index_file, 'r') as f:
                    content = await f.read()
                    case_index = json.loads(content)
            else:
                case_index = {
                    "case_id": case_id,
                    "created_timestamp": datetime.utcnow().isoformat(),
                    "files": {},
                    "status": "active"
                }
            
            # Add/update file entry
            case_index["files"][file_id] = {
                "filename": file_metadata["original_filename"],
                "file_type": file_metadata["file_type"],
                "file_size": file_metadata["file_size"],
                "upload_timestamp": file_metadata["upload_timestamp"],
                "status": file_metadata["status"]
            }
            
            case_index["last_updated"] = datetime.utcnow().isoformat()
            case_index["file_count"] = len(case_index["files"])
            
            # Save updated index
            async with aiofiles.open(case_index_file, 'w') as f:
                await f.write(json.dumps(case_index, indent=2))
            
        except Exception as e:
            logger.error(f"❌ Error updating case index: {str(e)}")
            raise
    
    def _detect_file_type(self, file_path: Path) -> str:
        """Detect file type using python-magic"""
        try:
            if self.magic:
                mime_type = self.magic.from_file(str(file_path))
                return mime_type
            else:
                # Fallback to extension-based detection
                extension = file_path.suffix.lower()
                extension_map = {
                    '.pdf': 'application/pdf',
                    '.txt': 'text/plain',
                    '.json': 'application/json',
                    '.csv': 'text/csv',
                    '.zip': 'application/zip',
                    '.exe': 'application/x-dosexec',
                    '.dll': 'application/x-dosexec',
                    '.log': 'text/plain',
                    '.pcap': 'application/vnd.tcpdump.pcap',
                    '.evtx': 'application/octet-stream'
                }
                return extension_map.get(extension, 'application/octet-stream')
        except Exception as e:
            logger.warning(f"⚠️ Error detecting file type: {str(e)}")
            return 'application/octet-stream'
    
    async def get_file_details(self, file_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a file"""
        try:
            # Search for file metadata across all cases
            for case_dir in self.results_path.iterdir():
                if case_dir.is_dir():
                    metadata_file = case_dir / f"{file_id}_metadata.json"
                    if metadata_file.exists():
                        async with aiofiles.open(metadata_file, 'r') as f:
                            content = await f.read()
                            return json.loads(content)
            
            return None
            
        except Exception as e:
            logger.error(f"❌ Error getting file details: {str(e)}")
            return None
    
    async def list_files(self, case_id: str = None) -> List[Dict[str, Any]]:
        """List files, optionally filtered by case"""
        try:
            files = []
            
            if case_id:
                # List files for specific case
                case_index_file = self.cases_path / f"{case_id}_index.json"
                if case_index_file.exists():
                    async with aiofiles.open(case_index_file, 'r') as f:
                        content = await f.read()
                        case_index = json.loads(content)
                        
                        for file_id, file_info in case_index["files"].items():
                            files.append({
                                "file_id": file_id,
                                "case_id": case_id,
                                **file_info
                            })
            else:
                # List all files across all cases
                for case_dir in self.cases_path.iterdir():
                    if case_dir.is_file() and case_dir.name.endswith('_index.json'):
                        async with aiofiles.open(case_dir, 'r') as f:
                            content = await f.read()
                            case_index = json.loads(content)
                            
                            current_case_id = case_index["case_id"]
                            for file_id, file_info in case_index["files"].items():
                                files.append({
                                    "file_id": file_id,
                                    "case_id": current_case_id,
                                    **file_info
                                })
            
            return files
            
        except Exception as e:
            logger.error(f"❌ Error listing files: {str(e)}")
            return []
    
    async def save_analysis_result(self, analysis_result: AnalysisResult):
        """Save analysis result to storage"""
        try:
            case_results_path = self.results_path / analysis_result.case_id
            case_results_path.mkdir(parents=True, exist_ok=True)
            
            # Save analysis result
            result_file = case_results_path / f"{analysis_result.file_id}_analysis.json"
            result_data = analysis_result.dict() if hasattr(analysis_result, 'dict') else analysis_result.__dict__
            
            async with aiofiles.open(result_file, 'w') as f:
                await f.write(json.dumps(result_data, indent=2, default=str))
            
            logger.info(f"💾 Analysis result saved for file: {analysis_result.file_id}")
            
        except Exception as e:
            logger.error(f"❌ Error saving analysis result: {str(e)}")
            raise
    
    async def get_analysis_results(self, file_id: str) -> Optional[Dict[str, Any]]:
        """Get analysis results for a file"""
        try:
            # Search for analysis results across all cases
            for case_dir in self.results_path.iterdir():
                if case_dir.is_dir():
                    result_file = case_dir / f"{file_id}_analysis.json"
                    if result_file.exists():
                        async with aiofiles.open(result_file, 'r') as f:
                            content = await f.read()
                            return json.loads(content)
            
            return None
            
        except Exception as e:
            logger.error(f"❌ Error getting analysis results: {str(e)}")
            return None
    
    async def update_analysis_status(self, file_id: str, status: str):
        """Update analysis status for a file"""
        try:
            # Find and update file metadata
            for case_dir in self.results_path.iterdir():
                if case_dir.is_dir():
                    metadata_file = case_dir / f"{file_id}_metadata.json"
                    if metadata_file.exists():
                        async with aiofiles.open(metadata_file, 'r') as f:
                            content = await f.read()
                            metadata = json.loads(content)
                        
                        metadata["status"] = status
                        metadata["last_updated"] = datetime.utcnow().isoformat()
                        
                        async with aiofiles.open(metadata_file, 'w') as f:
                            await f.write(json.dumps(metadata, indent=2))
                        
                        break
            
        except Exception as e:
            logger.error(f"❌ Error updating analysis status: {str(e)}")
    
    async def update_analysis_result(self, file_id: str, analysis_data: Dict[str, Any]):
        """Update analysis result with new data"""
        try:
            # Find and update analysis result
            for case_dir in self.results_path.iterdir():
                if case_dir.is_dir():
                    result_file = case_dir / f"{file_id}_analysis.json"
                    if result_file.exists():
                        async with aiofiles.open(result_file, 'r') as f:
                            content = await f.read()
                            existing_result = json.loads(content)
                        
                        # Merge new data
                        existing_result.update(analysis_data)
                        existing_result["last_updated"] = datetime.utcnow().isoformat()
                        
                        async with aiofiles.open(result_file, 'w') as f:
                            await f.write(json.dumps(existing_result, indent=2, default=str))
                        
                        break
            
        except Exception as e:
            logger.error(f"❌ Error updating analysis result: {str(e)}")
    
    async def create_case(self, case: Case):
        """Create a new case"""
        try:
            case_file = self.cases_path / f"{case.case_id}.json"
            case_data = case.dict() if hasattr(case, 'dict') else case.__dict__
            
            async with aiofiles.open(case_file, 'w') as f:
                await f.write(json.dumps(case_data, indent=2, default=str))
            
            # Create case index
            case_index = {
                "case_id": case.case_id,
                "name": case.name,
                "description": case.description,
                "created_timestamp": case.created_timestamp.isoformat() if hasattr(case.created_timestamp, 'isoformat') else str(case.created_timestamp),
                "status": case.status,
                "files": {},
                "file_count": 0
            }
            
            case_index_file = self.cases_path / f"{case.case_id}_index.json"
            async with aiofiles.open(case_index_file, 'w') as f:
                await f.write(json.dumps(case_index, indent=2))
            
            logger.info(f"📋 Case created: {case.name} ({case.case_id})")
            
        except Exception as e:
            logger.error(f"❌ Error creating case: {str(e)}")
            raise
    
    async def list_cases(self) -> List[Dict[str, Any]]:
        """List all cases"""
        try:
            cases = []
            
            for case_file in self.cases_path.iterdir():
                if case_file.is_file() and case_file.name.endswith('.json') and not case_file.name.endswith('_index.json'):
                    async with aiofiles.open(case_file, 'r') as f:
                        content = await f.read()
                        case_data = json.loads(content)
                        cases.append(case_data)
            
            # Sort by creation date (newest first)
            cases.sort(key=lambda x: x.get('created_timestamp', ''), reverse=True)
            
            return cases
            
        except Exception as e:
            logger.error(f"❌ Error listing cases: {str(e)}")
            return []
    
    async def get_dashboard_stats(self) -> Dict[str, Any]:
        """Get dashboard statistics"""
        try:
            total_cases = 0
            total_files = 0
            total_size = 0
            recent_files = []
            
            # Count cases and files
            for case_file in self.cases_path.iterdir():
                if case_file.is_file() and case_file.name.endswith('_index.json'):
                    async with aiofiles.open(case_file, 'r') as f:
                        content = await f.read()
                        case_index = json.loads(content)
                        
                        total_cases += 1
                        case_file_count = len(case_index.get("files", {}))
                        total_files += case_file_count
                        
                        # Collect recent files
                        for file_id, file_info in case_index.get("files", {}).items():
                            recent_files.append({
                                "file_id": file_id,
                                "case_id": case_index["case_id"],
                                "filename": file_info["filename"],
                                "upload_timestamp": file_info["upload_timestamp"],
                                "file_size": file_info["file_size"]
                            })
                            total_size += file_info.get("file_size", 0)
            
            # Sort recent files by upload time
            recent_files.sort(key=lambda x: x["upload_timestamp"], reverse=True)
            recent_files = recent_files[:10]  # Top 10 recent files
            
            return {
                "total_cases": total_cases,
                "total_files": total_files,
                "total_size": total_size,
                "total_size_human": f"{total_size / (1024*1024):.2f} MB",
                "recent_files": recent_files,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"❌ Error getting dashboard stats: {str(e)}")
            return {
                "total_cases": 0,
                "total_files": 0,
                "total_size": 0,
                "recent_files": [],
                "error": str(e)
            }