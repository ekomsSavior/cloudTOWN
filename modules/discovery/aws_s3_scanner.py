# modules/discovery/aws_s3_scanner.py
"""
AWS S3 Bucket Security Scanner - PRODUCTION VERSION
Performs REAL scans on AWS S3 buckets
"""

import re
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from typing import Dict, List, Any
from core.base_module import BaseModule

class AWSS3Scanner(BaseModule):
    """Scan for S3 bucket misconfigurations - REAL IMPLEMENTATION"""
    
    def __init__(self):
        super().__init__()
        self.name = "AWS S3 Bucket Scanner"
        self.description = "Scan for misconfigured S3 buckets (LIVE - REAL DATA)"
        self.category = "discovery"
        self.platform = "aws"
    
    def get_requirements(self) -> Dict[str, Dict[str, Any]]:
        return {
            'aws_access_key': {
                'prompt': 'AWS Access Key ID',
                'type': 'text',
                'default': ''
            },
            'aws_secret_key': {
                'prompt': 'AWS Secret Access Key',
                'type': 'password',
                'default': ''
            },
            'aws_region': {
                'prompt': 'AWS Region',
                'type': 'choice',
                'choices': ['us-east-1', 'us-west-1', 'us-west-2', 'eu-west-1', 'ap-southeast-1']
            },
            'scan_mode': {
                'prompt': 'Scan mode',
                'type': 'choice',
                'choices': ['All Buckets in Account', 'Specific Bucket']
            },
            'bucket_name': {
                'prompt': 'Bucket name (if Specific Bucket selected)',
                'type': 'text',
                'default': ''
            }
        }
    
    def validate_input(self, inputs: Dict[str, Any]) -> bool:
        """Validate user inputs"""
        if not inputs.get('aws_access_key') or not inputs.get('aws_secret_key'):
            print("[!] AWS credentials are required")
            return False
        
        if inputs['scan_mode'] == 'Specific Bucket' and not inputs.get('bucket_name'):
            print("[!] Bucket name required for specific bucket scan")
            return False
        
        return True
    
    def scan(self, inputs: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Scan S3 buckets for misconfigurations - REAL AWS API CALLS
        """
        results = []
        
        try:
            # Create S3 client with provided credentials
            s3_client = boto3.client(
                's3',
                aws_access_key_id=inputs['aws_access_key'],
                aws_secret_access_key=inputs['aws_secret_key'],
                region_name=inputs['aws_region']
            )
            
            # Get bucket list
            if inputs['scan_mode'] == 'All Buckets in Account':
                response = s3_client.list_buckets()
                buckets = [b['Name'] for b in response.get('Buckets', [])]
            else:
                buckets = [inputs['bucket_name']]
            
            print(f"[*] Found {len(buckets)} bucket(s) to scan")
            
            # Scan each bucket
            for bucket_name in buckets:
                print(f"[*] Scanning bucket: {bucket_name}")
                bucket_issues = self._scan_bucket(s3_client, bucket_name)
                
                if bucket_issues:
                    results.append(bucket_issues)
            
            return results
            
        except NoCredentialsError:
            print("[!] Invalid AWS credentials")
            return []
        except ClientError as e:
            print(f"[!] AWS API Error: {e}")
            return []
        except Exception as e:
            print(f"[!] Error: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _scan_bucket(self, s3_client, bucket_name: str) -> Dict[str, Any]:
        """Scan individual bucket for security issues"""
        issues = []
        
        result = {
            'bucket_name': bucket_name,
            'region': None,
            'issues': [],
            'severity': 'INFO'
        }
        
        try:
            # Get bucket location
            location = s3_client.get_bucket_location(Bucket=bucket_name)
            result['region'] = location['LocationConstraint'] or 'us-east-1'
            
            # Check public access block
            try:
                public_access = s3_client.get_public_access_block(Bucket=bucket_name)
                block_config = public_access['PublicAccessBlockConfiguration']
                
                if not all([
                    block_config.get('BlockPublicAcls'),
                    block_config.get('IgnorePublicAcls'),
                    block_config.get('BlockPublicPolicy'),
                    block_config.get('RestrictPublicBuckets')
                ]):
                    issues.append('Public access block not fully enabled')
                    result['severity'] = 'HIGH'
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                    issues.append('No public access block configured')
                    result['severity'] = 'CRITICAL'
            
            # Check bucket ACL
            try:
                acl = s3_client.get_bucket_acl(Bucket=bucket_name)
                for grant in acl.get('Grants', []):
                    grantee = grant.get('Grantee', {})
                    if grantee.get('Type') == 'Group':
                        uri = grantee.get('URI', '')
                        if 'AllUsers' in uri or 'AuthenticatedUsers' in uri:
                            issues.append(f'Bucket ACL grants access to {uri}')
                            result['severity'] = 'CRITICAL'
            except ClientError as e:
                issues.append(f'Cannot read ACL: {e}')
            
            # Check bucket policy
            try:
                policy = s3_client.get_bucket_policy(Bucket=bucket_name)
                policy_str = policy['Policy']
                if '"Principal":"*"' in policy_str or '"Principal":{"AWS":"*"}' in policy_str:
                    issues.append('Bucket policy allows public access')
                    result['severity'] = 'CRITICAL'
            except ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
                    issues.append(f'Cannot read policy: {e}')
            
            # Check versioning
            try:
                versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
                if versioning.get('Status') != 'Enabled':
                    issues.append('Versioning not enabled')
                    if result['severity'] == 'INFO':
                        result['severity'] = 'LOW'
            except ClientError:
                pass
            
            # Check encryption
            try:
                encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
            except ClientError as e:
                if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                    issues.append('No default encryption configured')
                    if result['severity'] == 'INFO':
                        result['severity'] = 'MEDIUM'
            
            # Check logging
            try:
                logging = s3_client.get_bucket_logging(Bucket=bucket_name)
                if not logging.get('LoggingEnabled'):
                    issues.append('Access logging not enabled')
                    if result['severity'] == 'INFO':
                        result['severity'] = 'LOW'
            except ClientError:
                pass
            
            result['issues'] = issues
            
            # Only return if there are issues
            if issues:
                return result
            else:
                return None
                
        except ClientError as e:
            print(f"[!] Error scanning bucket {bucket_name}: {e}")
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
            s3_client = boto3.client(
                's3',
                aws_access_key_id=inputs['aws_access_key'],
                aws_secret_access_key=inputs['aws_secret_key'],
                region_name=inputs['aws_region']
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
                    response = s3_client.list_objects_v2(Bucket=bucket_name, MaxKeys=10)
                    object_count = response.get('KeyCount', 0)
                    exploit_detail['actions'].append(f'Successfully listed objects: {object_count} found')
                    exploit_detail['status'] = 'SUCCESS'
                    exploit_results['successful'] += 1
                    
                    # List first few objects
                    if 'Contents' in response:
                        objects = [obj['Key'] for obj in response['Contents'][:5]]
                        exploit_detail['sample_objects'] = objects
                        
                except ClientError as e:
                    exploit_detail['actions'].append(f'List objects failed: {e}')
                    exploit_detail['status'] = 'FAILED'
                
                exploit_results['details'].append(exploit_detail)
            
            return exploit_results
            
        except Exception as e:
            print(f"[!] Exploitation error: {e}")
            return exploit_results
