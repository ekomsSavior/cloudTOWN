# modules/discovery/azure_storage_scanner.py
"""
Azure Storage Account Security Scanner - PRODUCTION VERSION
Performs REAL scans on Azure storage accounts
"""

from typing import Dict, List, Any
from core.base_module import BaseModule

try:
    from azure.identity import ClientSecretCredential
    from azure.mgmt.storage import StorageManagementClient
    from azure.storage.blob import BlobServiceClient
    AZURE_AVAILABLE = True
except ImportError:
    AZURE_AVAILABLE = False

class AzureStorageScanner(BaseModule):
    """Scan for Azure Storage Account misconfigurations - REAL IMPLEMENTATION"""
    
    def __init__(self):
        super().__init__()
        self.name = "Azure Storage Account Scanner"
        self.description = "Scan for misconfigured Azure storage accounts (LIVE - REAL DATA)"
        self.category = "discovery"
        self.platform = "azure"
    
    def get_requirements(self) -> Dict[str, Dict[str, Any]]:
        return {
            'tenant_id': {
                'prompt': 'Azure Tenant ID',
                'type': 'text',
                'default': ''
            },
            'client_id': {
                'prompt': 'Azure Client ID (App Registration)',
                'type': 'text',
                'default': ''
            },
            'client_secret': {
                'prompt': 'Azure Client Secret',
                'type': 'password',
                'default': ''
            },
            'subscription_id': {
                'prompt': 'Azure Subscription ID',
                'type': 'text',
                'default': ''
            },
            'scan_mode': {
                'prompt': 'Scan mode',
                'type': 'choice',
                'choices': ['All Storage Accounts', 'Specific Account']
            },
            'storage_account': {
                'prompt': 'Storage account name (if Specific Account selected)',
                'type': 'text',
                'default': ''
            },
            'resource_group': {
                'prompt': 'Resource group (if Specific Account selected)',
                'type': 'text',
                'default': ''
            }
        }
    
    def validate_input(self, inputs: Dict[str, Any]) -> bool:
        """Validate user inputs"""
        if not AZURE_AVAILABLE:
            print("[!] Azure SDK not installed. Run: pip install azure-identity azure-mgmt-storage azure-storage-blob")
            return False
        
        required = ['tenant_id', 'client_id', 'client_secret', 'subscription_id']
        for field in required:
            if not inputs.get(field):
                print(f"[!] {field} is required")
                return False
        
        if inputs['scan_mode'] == 'Specific Account':
            if not inputs.get('storage_account') or not inputs.get('resource_group'):
                print("[!] Storage account name and resource group required for specific account scan")
                return False
        
        return True
    
    def scan(self, inputs: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Scan Azure storage accounts for misconfigurations - REAL AZURE API CALLS
        """
        results = []
        
        try:
            # Create credential
            credential = ClientSecretCredential(
                tenant_id=inputs['tenant_id'],
                client_id=inputs['client_id'],
                client_secret=inputs['client_secret']
            )
            
            # Create storage management client
            storage_client = StorageManagementClient(
                credential=credential,
                subscription_id=inputs['subscription_id']
            )
            
            # Get storage accounts
            if inputs['scan_mode'] == 'All Storage Accounts':
                accounts = list(storage_client.storage_accounts.list())
            else:
                account = storage_client.storage_accounts.get_properties(
                    inputs['resource_group'],
                    inputs['storage_account']
                )
                accounts = [account]
            
            print(f"[*] Found {len(accounts)} storage account(s) to scan")
            
            # Scan each account
            for account in accounts:
                print(f"[*] Scanning: {account.name}")
                account_issues = self._scan_storage_account(storage_client, account, inputs['resource_group'])
                
                if account_issues:
                    results.append(account_issues)
            
            return results
            
        except Exception as e:
            print(f"[!] Azure API Error: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _scan_storage_account(self, storage_client, account, resource_group: str) -> Dict[str, Any]:
        """Scan individual storage account for security issues"""
        issues = []
        
        result = {
            'storage_account': account.name,
            'resource_group': resource_group,
            'location': account.location,
            'issues': [],
            'severity': 'INFO'
        }
        
        try:
            # Check HTTPS enforcement
            if not account.enable_https_traffic_only:
                issues.append('HTTPS-only traffic not enforced')
                result['severity'] = 'HIGH'
            
            # Check minimum TLS version
            if hasattr(account, 'minimum_tls_version'):
                if account.minimum_tls_version != 'TLS1_2':
                    issues.append(f'Weak TLS version: {account.minimum_tls_version}')
                    result['severity'] = 'MEDIUM'
            
            # Check public network access
            if hasattr(account, 'public_network_access'):
                if account.public_network_access == 'Enabled':
                    issues.append('Public network access enabled')
                    result['severity'] = 'HIGH'
            
            # Check if firewall rules exist
            if hasattr(account, 'network_rule_set'):
                if account.network_rule_set.default_action == 'Allow':
                    issues.append('Network firewall default action is Allow')
                    result['severity'] = 'HIGH'
            
            # Check blob public access
            if hasattr(account, 'allow_blob_public_access'):
                if account.allow_blob_public_access:
                    issues.append('Blob public access is allowed')
                    result['severity'] = 'CRITICAL'
            
            result['issues'] = issues
            
            # Only return if there are issues
            if issues:
                return result
            else:
                return None
                
        except Exception as e:
            print(f"[!] Error scanning {account.name}: {e}")
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
            credential = ClientSecretCredential(
                tenant_id=inputs['tenant_id'],
                client_id=inputs['client_id'],
                client_secret=inputs['client_secret']
            )
            
            for target in targets:
                account_name = target['storage_account']
                print(f"[*] Attempting exploitation on: {account_name}")
                
                exploit_detail = {
                    'storage_account': account_name,
                    'actions': []
                }
                
                # Try to list containers
                try:
                    account_url = f"https://{account_name}.blob.core.windows.net"
                    blob_service_client = BlobServiceClient(
                        account_url=account_url,
                        credential=credential
                    )
                    
                    containers = list(blob_service_client.list_containers())
                    exploit_detail['actions'].append(f'Successfully listed containers: {len(containers)} found')
                    exploit_detail['containers'] = [c.name for c in containers[:10]]
                    exploit_detail['status'] = 'SUCCESS'
                    exploit_results['successful'] += 1
                    
                except Exception as e:
                    exploit_detail['actions'].append(f'Container listing failed: {e}')
                    exploit_detail['status'] = 'FAILED'
                
                exploit_results['details'].append(exploit_detail)
            
            return exploit_results
            
        except Exception as e:
            print(f"[!] Exploitation error: {e}")
            return exploit_results
