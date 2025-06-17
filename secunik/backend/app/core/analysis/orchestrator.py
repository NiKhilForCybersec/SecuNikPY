"""
Analysis Orchestrator for SecuNik
Coordinates the complete analysis pipeline
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
from pathlib import Path
import json

from ...models.analysis import AnalysisResult, AnalysisStatus, Severity
from ..parsers import get_parser_for_file
from .correlator import Correlator
from .ioc_extractor import IOCExtractor
from .threat_detector import ThreatDetector
from .timeline_builder import TimelineBuilder
from ..ai.insights_generator import get_insights_generator
from ..storage.file_manager import FileManager

logger = logging.getLogger(__name__)

class AnalysisOrchestrator:
    """Orchestrates the complete analysis pipeline"""
    
    def __init__(self):
        self.correlator = Correlator()
        self.ioc_extractor = IOCExtractor()
        self.threat_detector = ThreatDetector()
        self.timeline_builder = TimelineBuilder()
        self.insights_generator = get_insights_generator()
        self.file_manager = FileManager()
        
        # Analysis configuration
        self.config = {
            'enable_ai': True,
            'enable_correlation': True,
            'enable_timeline': True,
            'max_file_size': 100 * 1024 * 1024,  # 100MB
            'analysis_timeout': 300,  # 5 minutes
            'parallel_analysis': True,
            'max_workers': 4
        }
    
    async def analyze_file(self, 
                          file_path: str, 
                          file_id: str,
                          options: Optional[Dict[str, Any]] = None) -> AnalysisResult:
        """Analyze a single file"""
        start_time = datetime.now()
        
        try:
            # Update status
            await self._update_status(file_id, AnalysisStatus.ANALYZING)
            
            # Get appropriate parser
            parser = get_parser_for_file(file_path)
            if not parser:
                return self._create_error_result(
                    file_path,
                    "No suitable parser found for file type"
                )
            
            logger.info(f"🔍 Analyzing {file_path} with {parser.name}")
            
            # Parse file
            extracted_data = await parser.parse(file_path)
            
            if not extracted_data.get('extraction_successful'):
                return self._create_error_result(
                    file_path,
                    extracted_data.get('error', 'Extraction failed')
                )
            
            # Run parser analysis
            analysis_result = await parser.analyze(file_path, extracted_data)
            
            # Enhance with additional analysis
            analysis_result = await self._enhance_analysis(
                analysis_result,
                extracted_data,
                options or {}
            )
            
            # Update file ID
            analysis_result.file_id = file_id
            
            # Calculate duration
            duration = (datetime.now() - start_time).total_seconds()
            analysis_result.analysis_duration = duration
            
            # Save result
            await self.file_manager.save_analysis_result(file_id, analysis_result)
            
            # Update status
            await self._update_status(file_id, AnalysisStatus.COMPLETED)
            
            logger.info(f"✅ Analysis completed for {file_path} in {duration:.2f}s")
            
            return analysis_result
            
        except asyncio.TimeoutError:
            logger.error(f"Analysis timeout for {file_path}")
            return self._create_error_result(file_path, "Analysis timeout")
        except Exception as e:
            logger.error(f"Analysis failed for {file_path}: {str(e)}")
            return self._create_error_result(file_path, str(e))
    
    async def analyze_multiple_files(self, 
                                   file_paths: List[str],
                                   case_id: Optional[str] = None,
                                   options: Optional[Dict[str, Any]] = None) -> List[AnalysisResult]:
        """Analyze multiple files with correlation"""
        results = []
        
        # Analyze files (parallel or sequential based on config)
        if self.config['parallel_analysis']:
            # Create tasks for parallel analysis
            tasks = []
            for file_path in file_paths:
                file_id = await self.file_manager.generate_file_id(file_path)
                task = self.analyze_file(file_path, file_id, options)
                tasks.append(task)
            
            # Run with limited concurrency
            results = await self._run_with_concurrency(tasks, self.config['max_workers'])
        else:
            # Sequential analysis
            for file_path in file_paths:
                file_id = await self.file_manager.generate_file_id(file_path)
                result = await self.analyze_file(file_path, file_id, options)
                results.append(result)
        
        # Perform correlation analysis if enabled
        if self.config['enable_correlation'] and len(results) > 1:
            correlation_results = await self.correlator.correlate_results(results)
            
            # Add correlation data to results
            for result, correlation in zip(results, correlation_results):
                result.correlations = correlation
        
        # Build unified timeline if enabled
        if self.config['enable_timeline']:
            timeline = await self.timeline_builder.build_unified_timeline(results)
            
            # Store timeline for case
            if case_id:
                await self._save_case_timeline(case_id, timeline)
        
        # Generate AI insights if enabled
        if self.config['enable_ai'] and options.get('enable_ai', True):
            insights = await self.insights_generator.generate_comprehensive_insights(
                [r.dict() if hasattr(r, 'dict') else r.__dict__ for r in results]
            )
            
            # Store insights
            if case_id:
                await self._save_case_insights(case_id, insights)
        
        return results
    
    async def reanalyze_file(self, 
                           file_id: str,
                           analysis_type: str = "standard",
                           options: Optional[Dict[str, Any]] = None) -> AnalysisResult:
        """Reanalyze a previously analyzed file"""
        # Get file info
        file_info = await self.file_manager.get_file_info(file_id)
        if not file_info:
            return self._create_error_result("", f"File {file_id} not found")
        
        file_path = file_info.get('file_path', '')
        
        # Apply analysis type specific options
        analysis_options = options or {}
        
        if analysis_type == "deep":
            analysis_options.update({
                'extract_strings': True,
                'deep_scan': True,
                'extract_all_iocs': True
            })
        elif analysis_type == "quick":
            analysis_options.update({
                'skip_heavy_analysis': True,
                'quick_scan': True
            })
        elif analysis_type == "comprehensive":
            analysis_options.update({
                'enable_all_modules': True,
                'detailed_timeline': True,
                'extended_ioc_extraction': True
            })
        
        # Run analysis
        return await self.analyze_file(file_path, file_id, analysis_options)
    
    async def _enhance_analysis(self, 
                              analysis_result: AnalysisResult,
                              extracted_data: Dict[str, Any],
                              options: Dict[str, Any]) -> AnalysisResult:
        """Enhance analysis with additional modules"""
        
        # Extract additional IOCs
        if not options.get('skip_ioc_extraction'):
            additional_iocs = await self.ioc_extractor.extract_from_data(extracted_data)
            analysis_result.iocs_found.extend(additional_iocs)
        
        # Detect additional threats
        if not options.get('skip_threat_detection'):
            additional_threats = await self.threat_detector.detect_threats(
                extracted_data,
                analysis_result
            )
            analysis_result.threats_detected.extend(additional_threats)
        
        # Build timeline
        if not options.get('skip_timeline'):
            timeline_events = await self.timeline_builder.extract_timeline_events(
                extracted_data,
                analysis_result
            )
            if 'timeline' not in analysis_result.details:
                analysis_result.details['timeline'] = []
            analysis_result.details['timeline'].extend(timeline_events)
        
        # Recalculate risk score based on all findings
        analysis_result.risk_score = self._calculate_risk_score(analysis_result)
        
        # Update severity
        analysis_result.severity = self._determine_severity(analysis_result)
        
        # Add enhanced metadata
        analysis_result.details['analysis_metadata'] = {
            'parser_used': analysis_result.parser_name,
            'enhancement_modules': {
                'ioc_extraction': not options.get('skip_ioc_extraction'),
                'threat_detection': not options.get('skip_threat_detection'),
                'timeline_building': not options.get('skip_timeline')
            },
            'options_applied': options
        }
        
        return analysis_result
    
    def _calculate_risk_score(self, analysis_result: AnalysisResult) -> float:
        """Calculate overall risk score"""
        score = 0.0
        
        # Base score from parser
        score = analysis_result.risk_score
        
        # Adjust based on threats
        threat_scores = {
            'CRITICAL': 0.9,
            'HIGH': 0.7,
            'MEDIUM': 0.5,
            'LOW': 0.3
        }
        
        if analysis_result.threats_detected:
            max_threat_score = max(
                threat_scores.get(t.severity.upper(), 0.0)
                for t in analysis_result.threats_detected
            )
            score = max(score, max_threat_score)
        
        # Adjust based on IOC count
        ioc_count = len(analysis_result.iocs_found)
        if ioc_count > 50:
            score = max(score, 0.8)
        elif ioc_count > 20:
            score = max(score, 0.6)
        elif ioc_count > 10:
            score = max(score, 0.4)
        
        # Ensure score is between 0 and 1
        return min(max(score, 0.0), 1.0)
    
    def _determine_severity(self, analysis_result: AnalysisResult) -> Severity:
        """Determine overall severity"""
        if analysis_result.risk_score >= 0.8:
            return Severity.CRITICAL
        elif analysis_result.risk_score >= 0.6:
            return Severity.HIGH
        elif analysis_result.risk_score >= 0.4:
            return Severity.MEDIUM
        else:
            return Severity.LOW
    
    async def _run_with_concurrency(self, tasks: List, max_workers: int) -> List[Any]:
        """Run tasks with limited concurrency"""
        semaphore = asyncio.Semaphore(max_workers)
        
        async def run_task(task):
            async with semaphore:
                return await task
        
        return await asyncio.gather(*[run_task(task) for task in tasks])
    
    async def _update_status(self, file_id: str, status: AnalysisStatus):
        """Update analysis status"""
        try:
            await self.file_manager.update_analysis_status(file_id, status)
        except Exception as e:
            logger.error(f"Failed to update status for {file_id}: {str(e)}")
    
    async def _save_case_timeline(self, case_id: str, timeline: List[Dict[str, Any]]):
        """Save timeline for a case"""
        try:
            timeline_path = Path(f"data/cases/{case_id}/timeline.json")
            timeline_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(timeline_path, 'w') as f:
                json.dump({
                    'case_id': case_id,
                    'generated_at': datetime.now().isoformat(),
                    'events': timeline
                }, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save timeline for case {case_id}: {str(e)}")
    
    async def _save_case_insights(self, case_id: str, insights: Dict[str, Any]):
        """Save AI insights for a case"""
        try:
            insights_path = Path(f"data/cases/{case_id}/insights.json")
            insights_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(insights_path, 'w') as f:
                json.dump(insights, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save insights for case {case_id}: {str(e)}")
    
    def _create_error_result(self, file_path: str, error_message: str) -> AnalysisResult:
        """Create error analysis result"""
        return AnalysisResult(
            file_path=file_path,
            parser_name="Error",
            analysis_type="Error",
            timestamp=datetime.now(),
            summary=f"Analysis failed: {error_message}",
            details={"error": error_message},
            threats_detected=[],
            iocs_found=[],
            severity=Severity.LOW,
            risk_score=0.0,
            recommendations=["Fix the error and retry analysis"]
        )
    
    def update_config(self, config_updates: Dict[str, Any]):
        """Update orchestrator configuration"""
        self.config.update(config_updates)
        logger.info(f"Updated orchestrator config: {config_updates}")

# Singleton instance
_orchestrator_instance = None

def get_analysis_orchestrator() -> AnalysisOrchestrator:
    """Get or create orchestrator instance"""
    global _orchestrator_instance
    
    if _orchestrator_instance is None:
        _orchestrator_instance = AnalysisOrchestrator()
    
    return _orchestrator_instance