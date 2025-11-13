# modules/discovery/saas_subdomain_takeover.py
"""
SaaS Subdomain Takeover Scanner - PRODUCTION VERSION
Performs REAL DNS lookups and HTTP checks
"""

from typing import Dict, List, Any
from core.base_module import BaseModule
import re
import dns.resolver
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

class SaaSSubdomainTakeover(BaseModule):
    """Scan for subdomain takeover vulnerabilities - REAL IMPLEMENTATION"""
    
    def __init__(self):
        super().__init__()
        self.name = "SaaS Subdomain Takeover Scanner"
        self.description = "Detect dangling DNS records vulnerable to subdomain takeover (LIVE - REAL DATA)"
        self.category = "discovery"
        self.platform = "saas"
        
        # Vulnerable service fingerprints
        self.vulnerable_services = {
            'github.io': {
                'cname_pattern': r'\.github\.io$',
                'fingerprints': [
                    'There isn\'t a GitHub Pages site here',
                    'For root URLs (like http://example.com/) you must provide an index.html file'
                ],
                'service': 'GitHub Pages'
            },
            'herokuapp.com': {
                'cname_pattern': r'\.herokuapp\.com$',
                'fingerprints': [
                    'No such app',
                    'There\'s nothing here, yet'
                ],
                'service': 'Heroku'
            },
            'azurewebsites.net': {
                'cname_pattern': r'\.azurewebsites\.net$',
                'fingerprints': [
                    'Error 404 - Web app not found',
                    '404 Web Site not found'
                ],
                'service': 'Azure Web Apps'
            },
            's3.amazonaws.com': {
                'cname_pattern': r's3.*\.amazonaws\.com$',
                'fingerprints': [
                    'NoSuchBucket',
                    'The specified bucket does not exist'
                ],
                'service': 'AWS S3'
            },
            'cloudfront.net': {
                'cname_pattern': r'\.cloudfront\.net$',
                'fingerprints': [
                    'Bad request',
                    'ERROR: The request could not be satisfied'
                ],
                'service': 'AWS CloudFront'
            },
            'zendesk.com': {
                'cname_pattern': r'\.zendesk\.com$',
                'fingerprints': [
                    'Help Center Closed',
                    'this help center no longer exists'
                ],
                'service': 'Zendesk'
            },
            'shopify.com': {
                'cname_pattern': r'\.myshopify\.com$',
                'fingerprints': [
                    'Sorry, this shop is currently unavailable',
                    'Only one step left'
                ],
                'service': 'Shopify'
            },
            'wordpress.com': {
                'cname_pattern': r'\.wordpress\.com$',
                'fingerprints': [
                    'Do you want to register'
                ],
                'service': 'WordPress.com'
            }
        }
    
    def get_requirements(self) -> Dict[str, Dict[str, Any]]:
        return {
            'target_domain': {
                'prompt': 'Target domain to scan (e.g., example.com)',
                'type': 'text',
                'default': ''
            },
            'subdomain_wordlist': {
                'prompt': 'Subdomain wordlist file (or type "default" for built-in list)',
                'type': 'text',
                'default': 'default'
            },
            'threads': {
                'prompt': 'Number of threads',
                'type': 'choice',
                'choices': ['5', '10', '20', '50']
            },
            'timeout': {
                'prompt': 'HTTP request timeout (seconds)',
                'type': 'choice',
                'choices': ['3', '5', '10']
            }
        }
    
    def validate_input(self, inputs: Dict[str, Any]) -> bool:
        """Validate user inputs"""
        domain = inputs.get('target_domain', '')
        
        # Basic domain validation
        domain_pattern = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        )
        
        if not domain_pattern.match(domain):
            print("[!] Invalid domain format")
            return False
        
        return True
    
    def scan(self, inputs: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Scan for subdomain takeover vulnerabilities - REAL DNS AND HTTP CHECKS
        """
        results = []
        domain = inputs['target_domain']
        threads = int(inputs['threads'])
        timeout = int(inputs['timeout'])
        
        # Load subdomain list
        if inputs['subdomain_wordlist'] == 'default':
            subdomains = self._get_default_subdomains()
        else:
            try:
                with open(inputs['subdomain_wordlist'], 'r') as f:
                    subdomains = [line.strip() for line in f if line.strip()]
            except FileNotFoundError:
                print(f"[!] Wordlist file not found: {inputs['subdomain_wordlist']}")
                return []
        
        print(f"[*] Testing {len(subdomains)} subdomains with {threads} threads")
        
        # Scan subdomains in parallel
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {
                executor.submit(self._check_subdomain, subdomain, domain, timeout): subdomain 
                for subdomain in subdomains
            }
            
            for future in as_completed(futures):
                subdomain = futures[future]
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                        print(f"[+] VULNERABLE: {result['subdomain']}")
                except Exception as e:
                    pass  # Silent failures for non-existent subdomains
        
        return results
    
    def _check_subdomain(self, subdomain: str, domain: str, timeout: int) -> Dict[str, Any]:
        """Check individual subdomain for takeover vulnerability"""
        full_domain = f"{subdomain}.{domain}"
        
        try:
            # Resolve CNAME
            answers = dns.resolver.resolve(full_domain, 'CNAME')
            for rdata in answers:
                cname = str(rdata.target).rstrip('.')
                
                # Check if CNAME matches vulnerable service
                for service_key, service_info in self.vulnerable_services.items():
                    if re.search(service_info['cname_pattern'], cname):
                        # Check HTTP response for fingerprint
                        vulnerable = self._check_http_fingerprint(
                            full_domain, 
                            service_info['fingerprints'],
                            timeout
                        )
                        
                        if vulnerable:
                            return {
                                'subdomain': full_domain,
                                'cname': cname,
                                'service': service_info['service'],
                                'vulnerable': True,
                                'severity': 'HIGH',
                                'impact': 'Subdomain takeover possible - can host phishing, steal cookies, damage reputation'
                            }
        
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            pass  # Domain doesn't exist or no CNAME
        except Exception as e:
            pass  # Other DNS errors
        
        return None
    
    def _check_http_fingerprint(self, domain: str, fingerprints: List[str], timeout: int) -> bool:
        """Check HTTP response for vulnerability fingerprints"""
        try:
            # Try HTTPS first
            for protocol in ['https', 'http']:
                try:
                    url = f"{protocol}://{domain}"
                    response = requests.get(url, timeout=timeout, allow_redirects=True, verify=False)
                    response_text = response.text
                    
                    # Check for fingerprints
                    for fingerprint in fingerprints:
                        if fingerprint.lower() in response_text.lower():
                            return True
                    
                    break  # If request succeeded, don't try other protocol
                except requests.exceptions.SSLError:
                    continue  # Try HTTP if HTTPS fails
                except requests.exceptions.RequestException:
                    return False
        
        except Exception:
            return False
        
        return False
    
    def _get_default_subdomains(self) -> List[str]:
        """Return default subdomain wordlist"""
        return [
            'www', 'mail', 'blog', 'dev', 'staging', 'test', 'api', 'cdn',
            'shop', 'store', 'admin', 'portal', 'app', 'beta', 'demo', 'docs',
            'support', 'help', 'status', 'git', 'ftp', 'vpn', 'mx', 'ns1', 'ns2',
            'smtp', 'pop', 'imap', 'webmail', 'remote', 'cloud', 'assets',
            'static', 'media', 'images', 'img', 'css', 'js', 'files', 'download',
            'downloads', 'uploads', 'data', 'db', 'database', 'sql', 'mysql',
            'backup', 'backups', 'old', 'new', 'temp', 'tmp', 'archive',
            'mobile', 'm', 'wap', 'secure', 'payment', 'pay', 'checkout',
            'billing', 'invoice', 'account', 'accounts', 'user', 'users',
            'client', 'clients', 'customer', 'customers', 'partner', 'partners',
            'affiliate', 'affiliates', 'member', 'members', 'login', 'signup',
            'register', 'auth', 'authentication', 'sso', 'oauth', 'api1', 'api2',
            'v1', 'v2', 'v3', 'sandbox', 'qa', 'uat', 'production', 'prod'
        ]
    
    def exploit(self, targets: List[Dict[str, Any]], inputs: Dict[str, Any]) -> Dict[str, Any]:
        """
        Document exploitation steps for subdomain takeover
        
        Note: Actual exploitation (claiming resources) requires manual steps
        specific to each service and should only be done with authorization
        """
        exploit_results = {
            'attempted': len(targets),
            'details': []
        }
        
        for target in targets:
            exploit_detail = {
                'subdomain': target['subdomain'],
                'service': target['service'],
                'cname': target['cname'],
                'exploitation_steps': self._get_exploitation_steps(target['service'], target['cname']),
                'status': 'DOCUMENTED',
                'note': 'Manual exploitation required - automated takeover not performed for safety'
            }
            exploit_results['details'].append(exploit_detail)
        
        return exploit_results
    
    def _get_exploitation_steps(self, service: str, cname: str) -> List[str]:
        """Get service-specific exploitation steps"""
        steps_map = {
            'GitHub Pages': [
                '1. Create a GitHub account if you don\'t have one',
                '2. Create a new repository named after the subdomain',
                f'3. Enable GitHub Pages in repository settings',
                '4. Create an index.html as proof of concept',
                '5. Verify subdomain now resolves to your GitHub Pages site'
            ],
            'Heroku': [
                '1. Create a Heroku account',
                f'2. Create a new app with name from CNAME: {cname.split(".")[0]}',
                '3. Deploy a simple web application',
                '4. Verify subdomain resolves to your Heroku app'
            ],
            'Azure Web Apps': [
                '1. Create an Azure account',
                f'2. Create a new Web App with name from CNAME',
                '3. Deploy a simple application',
                '4. Verify subdomain resolves to your Azure Web App'
            ],
            'AWS S3': [
                '1. Create an AWS account',
                f'2. Create an S3 bucket matching the CNAME',
                '3. Enable static website hosting',
                '4. Upload index.html as proof of concept',
                '5. Verify subdomain resolves to your S3 bucket'
            ]
        }
        
        return steps_map.get(service, [
            '1. Research service-specific registration process',
            '2. Claim the resource identifier from CNAME',
            '3. Deploy proof of concept content',
            '4. Verify takeover successful'
        ])

