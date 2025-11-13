# core/session.py
"""
Session management for tracking testing activities
"""

import uuid
from datetime import datetime
from typing import Dict, List, Any

class Session:
    """Manages the current testing session"""
    
    def __init__(self):
        self.session_id = str(uuid.uuid4())[:8]
        self.start_time = datetime.now()
        self.results = []
        self.modules_executed = []
    
    def add_result(self, module_name: str, inputs: Dict[str, Any], 
                   scan_results: Any, exploit_results: Any = None):
        """
        Add results from a module execution
        
        Args:
            module_name: Name of the executed module
            inputs: User inputs provided
            scan_results: Results from scan phase
            exploit_results: Results from exploitation phase (if any)
        """
        result_entry = {
            'timestamp': datetime.now().isoformat(),
            'module': module_name,
            'inputs': inputs,
            'scan_results': scan_results,
            'exploit_results': exploit_results
        }
        
        self.results.append(result_entry)
        
        if module_name not in self.modules_executed:
            self.modules_executed.append(module_name)
    
    def get_info(self) -> Dict[str, Any]:
        """Get session information"""
        total_findings = sum(
            len(r['scan_results']) if isinstance(r['scan_results'], list) else 1
            for r in self.results
            if r['scan_results']
        )
        
        return {
            'session_id': self.session_id,
            'start_time': self.start_time.strftime('%Y-%m-%d %H:%M:%S'),
            'modules_run': len(self.modules_executed),
            'total_findings': total_findings,
            'results': self.results
        }
    
    def get_results(self) -> List[Dict[str, Any]]:
        """Get all results from this session"""
        return self.results
    
    def clear(self):
        """Clear session data"""
        self.results = []
        self.modules_executed = []
