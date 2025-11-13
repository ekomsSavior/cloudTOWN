# modules/discovery/gcp_storage_scanner.py
"""
GCP Cloud Storage Security Scanner - PRODUCTION VERSION
Performs REAL scans on GCP storage buckets
"""

from typing import Dict, List, Any
from core.base_module import BaseModule
import os

try:
    from google.cloud import storage
    from google.oauth2 import service_account
    GCP_AVAILABLE = True
except ImportError:
    GCP_AVAILABLE = False

class GCPStorageScanner(BaseModule):
    """Scan for GCP Cloud Storage misconfigurations - REAL IMPLEMENTATION"""
    
    def __init__(self):
        super().__init__()
        self.name = "GCP Cloud Storage Scanner"
        self.description = "Scan for misconfigured GCP Cloud Storage buckets (LIVE - REAL DATA)"
        self.category = "discovery"
        self.platform = "gcp"
    
    def get_requirements(self) -> Dict[str, Dict[str, Any]]:
        return {
            'service_account_file': {
                'prompt': 'Path to service account JSON file',
                'type': 'text',
                'default': ''
            },
            'project_id': {
                'prompt': 'GCP Project ID',
                'type': 'text',
                'default': ''
            },
            'scan_mode': {
                'prompt': 'Scan mode',
                'type': 'choice',
                'choices': ['All Buckets in Project', 'Specific Bucket']
            },
            'bucket_name': {
                'prompt': 'Bucket name (if Specific Bucket selected)',
                'type': 'text',
                'default': ''
            }
        }
    
    def validate_input(self, inputs: Dict[str, Any]) -> bool:
        """Validate user inputs"""
        if not GCP_AVAILABLE:
            print("[!] GCP SDK not installed. Run: pip install google-cloud-storage")
            return False
        
        if not inputs.get('service_account_file') or not inputs.get('project_id'):
            print("[!] Service account file and project ID are required")
            return False
        
        if not os.path.exists(inputs['service_account_file']):
            print(f"[!] Service account file not found: {inputs['service_account_file']}")
            return False
        
        if inputs['scan_mode'] == 'Specific Bucket' and not inputs.get('bucket_name'):
            print("[!] Bucket name required for specific bucket scan")
            return False
        
        return True
    
    def scan(self, inputs: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Scan GCP storage buckets for misconfigurations - REAL GCP API CALLS
        """
        results = []
        
        try:
            # Create credentials from service account file
            credentials = service_account.Credentials.from_service_account_file(
                inputs['service_account_file']
            )
            
            # Create storage client
            storage_client = storage.Client(
                credentials=credentials,
                project=inputs['project_id']
            )
            
            # Get buckets
            if inputs['scan_mode'] == 'All Buckets in Project':
                buckets = list(storage_client.list_buckets())
            else:
                bucket = storage_client.get_bucket(inputs['bucket_name'])
                buckets = [bucket]
            
            print(f"[*] Found {len(buckets)} bucket(s) to scan")
            
            # Scan each bucket
            for bucket in buckets:
                print(f"[*] Scanning bucket: {bucket.name}")
                bucket_issues = self._scan_bucket(bucket)
                
                if bucket_issues:
                    results.append(bucket_issues)
            
            return results
            
        except Exception as e:
            print(f"[!] GCP API Error: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _scan_bucket(self, bucket) -> Dict[str, Any]:
        """Scan individual bucket for security issues"""
        issues = []
        
        result = {
            'bucket_name': bucket.name,
            'project_id': bucket.project_number,
            'location': bucket.location,
            'storage_class': bucket.storage_class,
            'issues': [],
            'severity': 'INFO'
        }
        
        try:
            # Check uniform bucket-level access
            if not bucket.iam_configuration.uniform_bucket_level_access_enabled:
                issues.append('Uniform bucket-level access not enabled')
                result['severity'] = 'MEDIUM'
            
            # Check versioning
            if not bucket.versioning_enabled:
                issues.append('Object versioning not enabled')
                if result['severity'] == 'INFO':
                    result['severity'] = 'LOW'
            
            # Check IAM policies for public access
            policy = bucket.get_iam_policy(requested_policy_version=3)
            for binding in policy.bindings:
                members = binding.get('members', [])
                for member in members:
                    if member == 'allUsers' or member == 'allAuthenticatedUsers':
                        issues.append(f'IAM policy grants access to {member}')
                        result['severity'] = 'CRITICAL'
                        break
            
            # Check labels for sensitive data indicators
            labels = bucket.labels or {}
            sensitive_labels = ['production', 'prod', 'backup', 'pii', 'sensitive']
            for label_key, label_value in labels.items():
                if any(sens in label_key.lower() or sens in label_value.lower() for sens in sensitive_labels):
                    if result['severity'] in ['INFO', 'LOW']:
                        issues.append(f'Potentially sensitive bucket (label: {label_key}={label_value})')
            
            result['issues'] = issues
            
            # Only return if there are issues
            if issues:
                return result
            else:
                return None
                
        except Exception as e:
            print(f"[!] Error scanning bucket {bucket.name}: {e}")
            return None
    
    def exploit(self, targets: List[Dict[str, Any]], inputs: Dict[str, Any]) -> Dict[str, Any]:
        """
        Attempt to exploit identified misconfigurations - REAL EXPLOITATION
        """
        exploit_results = {
            'attempted': len(targets),
            'successful': 0,
            'details': []
        }
        
        try:
            credentials = service_account.Credentials.from_service_account_file(
                inputs['service_account_file']
            )
            
            storage_client = storage.Client(
                credentials=credentials,
                project=inputs['project_id']
            )
            
            for target in targets:
                bucket_name = target['bucket_name']
                print(f"[*] Attempting exploitation on: {bucket_name}")
                
                exploit_detail = {
                    'bucket': bucket_name,
                    'actions': []
                }
                
                # Try to list objects
                try:
                    bucket = storage_client.get_bucket(bucket_name)
                    blobs = list(bucket.list_blobs(max_results=10))
                    
                    exploit_detail['actions'].append(f'Successfully listed objects: {len(blobs)} found')
                    exploit_detail['sample_objects'] = [blob.name for blob in blobs[:5]]
                    exploit_detail['status'] = 'SUCCESS'
                    exploit_results['successful'] += 1
                    
                except Exception as e:
                    exploit_detail['actions'].append(f'List objects failed: {e}')
                    exploit_detail['status'] = 'FAILED'
                
                exploit_results['details'].append(exploit_detail)
            
            return exploit_results
            
        except Exception as e:
            print(f"[!] Exploitation error: {e}")
            return exploit_results
