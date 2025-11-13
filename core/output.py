# core/output.py
"""
Output and reporting functionality
"""

import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any

class OutputManager:
    """Handles exporting results in various formats"""
    
    def __init__(self):
        self.output_dir = Path("output")
        self.output_dir.mkdir(exist_ok=True)
    
    def export(self, results: List[Dict[str, Any]], filename: str, format: str = 'json') -> bool:
        """
        Export results to file
        
        Args:
            results: List of result dictionaries
            filename: Output filename (without extension)
            format: Output format (json, html, txt)
            
        Returns:
            bool: True if export successful
        """
        try:
            filepath = self.output_dir / f"{filename}.{format}"
            
            if format == 'json':
                return self._export_json(results, filepath)
            elif format == 'html':
                return self._export_html(results, filepath)
            elif format == 'txt':
                return self._export_txt(results, filepath)
            else:
                return False
        except Exception as e:
            print(f"Export error: {e}")
            return False
    
    def _export_json(self, results: List[Dict[str, Any]], filepath: Path) -> bool:
        """Export as JSON"""
        with open(filepath, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        return True
    
    def _export_html(self, results: List[Dict[str, Any]], filepath: Path) -> bool:
        """Export as HTML report"""
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Cloud Red Team Framework - Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 40px;
            background-color: #f5f5f5;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
        }}
        .result {{
            background: white;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .module-name {{
            font-size: 1.5em;
            color: #667eea;
            margin-bottom: 10px;
        }}
        .timestamp {{
            color: #888;
            font-size: 0.9em;
        }}
        .finding {{
            background: #fff3cd;
            padding: 15px;
            margin: 10px 0;
            border-left: 4px solid #ffc107;
            border-radius: 4px;
        }}
        .exploited {{
            background: #f8d7da;
            border-left-color: #dc3545;
        }}
        pre {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 4px;
            overflow-x: auto;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Cloud Red Team Framework</h1>
        <p>Security Assessment Report</p>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
"""
        
        for result in results:
            html += f"""
    <div class="result">
        <div class="module-name">{result.get('module', 'Unknown')}</div>
        <div class="timestamp">{result.get('timestamp', '')}</div>
        <h3>Scan Results:</h3>
"""
            
            if result.get('scan_results'):
                if isinstance(result['scan_results'], list):
                    for finding in result['scan_results']:
                        html += f'<div class="finding"><pre>{json.dumps(finding, indent=2)}</pre></div>'
                else:
                    html += f'<div class="finding"><pre>{json.dumps(result["scan_results"], indent=2)}</pre></div>'
            else:
                html += '<p>No vulnerabilities found</p>'
            
            if result.get('exploit_results'):
                html += f"""
        <h3>Exploitation Results:</h3>
        <div class="finding exploited">
            <pre>{json.dumps(result['exploit_results'], indent=2)}</pre>
        </div>
"""
            
            html += '    </div>'
        
        html += """
</body>
</html>
"""
        
        with open(filepath, 'w') as f:
            f.write(html)
        return True
    
    def _export_txt(self, results: List[Dict[str, Any]], filepath: Path) -> bool:
        """Export as plain text"""
        with open(filepath, 'w') as f:
            f.write("=" * 60 + "\n")
            f.write("Cloud Red Team Framework - Security Assessment Report\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 60 + "\n\n")
            
            for idx, result in enumerate(results, 1):
                f.write(f"\n[Result #{idx}]\n")
                f.write(f"Module: {result.get('module', 'Unknown')}\n")
                f.write(f"Timestamp: {result.get('timestamp', '')}\n")
                f.write(f"\nScan Results:\n")
                f.write(f"{json.dumps(result.get('scan_results'), indent=2)}\n")
                
                if result.get('exploit_results'):
                    f.write(f"\nExploitation Results:\n")
                    f.write(f"{json.dumps(result.get('exploit_results'), indent=2)}\n")
                
                f.write("\n" + "-" * 60 + "\n")
        
        return True
