# cloudTOWN - Cloud Tactical Offensive Warfare Network
## ✩₊˚.⋆☾⋆⁺₊✧by ek0ms savi0r✩₊˚.⋆☾⋆⁺₊✧

![Screenshot_2025-11-13_14_22_31](https://github.com/user-attachments/assets/80b1dc5a-942b-478c-954d-592e3ef1336d)


## What is cloudTOWN?

**cloudTOWN** (Cloud Tactical Offensive Warfare Network) is a bleeding-edge, interactive framework designed for authorized cloud security assessments. 

### Core Capabilities

- **Real-Time Exploitation** - No simulations. Real attacks on real infrastructure.
- **Multi-Cloud Dominance** - AWS, Azure, GCP, and SaaS platforms in one framework
- **Interactive Warfare** - Zero command-line arguments. The framework guides you.
- **Modular Arsenal** - Easy-to-extend architecture for custom attack modules
- **Session Persistence** - Track findings across multiple engagement phases
- **Professional Reporting** - Export to JSON, HTML, or TXT for client deliverables

---

###  **DISCOVERY MODULES** (Reconnaissance Phase)

####  AWS S3 Bucket Scanner
- Enumerates S3 buckets in target AWS accounts
- Identifies public access misconfigurations
- Checks encryption, versioning, logging status
- Analyzes bucket policies and ACLs
- **REAL boto3 API calls - LIVE data**

####  Azure Storage Account Scanner
- Scans Azure storage accounts for misconfigurations
- Enumerates blob containers
- Checks HTTPS enforcement and TLS versions
- Identifies public access and firewall issues
- **REAL Azure SDK calls - LIVE data**

####  GCP Cloud Storage Scanner
- Analyzes GCP storage bucket security
- Checks IAM policies for overpermissive access
- Validates uniform bucket-level access
- Identifies public exposure
- **REAL GCP API calls - LIVE data**

####  SaaS Subdomain Takeover Scanner
- Performs real DNS enumeration
- Identifies dangling CNAME records
- Tests for subdomain takeover vulnerabilities
- Fingerprints vulnerable services (GitHub, Heroku, Azure, AWS, Shopify, etc.)
- **REAL DNS lookups and HTTP requests**

###  **EXPLOITATION MODULES** (Attack Phase)

####  AWS IAM Privilege Escalation
- Analyzes IAM permissions for escalation paths
- Identifies dangerous permission combinations
- **ACTIVELY EXPLOITS** privilege escalation vectors
- Creates access keys for privileged users
- Attaches AdministratorAccess policies
- Modifies inline policies for privilege gain
- **REAL IAM modifications - WILL CHANGE your AWS environment**


**UNAUTHORIZED ACCESS TO COMPUTER SYSTEMS IS A CRIME. ALWAYS OBTAIN PROPER AUTHORIZATION BEFORE TESTING.**

---


##  Installation

### Prerequisites

- **Operating System**: Kali Linux, ParrotOS, or any Linux distro
- **Python**: 3.8 or higher
- **Permissions**: sudo access for package installation

###  Quick Install 

```bash
# Clone the repository
git clone https://github.com/ekomsSavior/cloudTOWN.git
cd cloudTOWN

# Install dependencies
pip3 install -r requirements.txt

# Make executable
chmod +x main.py

# Launch
python3 main.py
```
---

## Usage Guide

![Screenshot_2025-11-13_14_22_46](https://github.com/user-attachments/assets/01ced779-e903-40f9-87cb-ece652bc4e2e)

###  Basic Workflow

```
1. Launch Framework → 2. Select Module → 3. Provide Credentials → 4. Scan → 5. Exploit → 6. Export Report
```

###  Starting the Framework

```bash
cd cloudTOWN
python3 main.py
```

You'll see the main menu:
```
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║          Cloud Red Team Framework v2.0                    ║
║          Real Cloud Security Testing                      ║
║          AUTHORIZED USE ONLY                              ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝

Main Menu - Select an option:
  1. List All Modules
  2. Select and Run Module
  3. View Session Info
  4. Export Results
  5. Exit
```

---

##  Detailed Usage Examples

###  SCENARIO 1: AWS S3 Bucket Reconnaissance & Exploitation

**Objective**: Find misconfigured S3 buckets and extract data

#### Step 1: Launch and Select Module
```bash
python3 main.py
# Select: 2. Select and Run Module
# Choose: AWS S3 Bucket Scanner
```

#### Step 2: Provide AWS Credentials
```
AWS Access Key ID: AKIAIOSFODNN7EXAMPLE
AWS Secret Access Key: [your-secret-key]
AWS Region: us-east-1
Scan mode: All Buckets in Account
```

#### Step 3: Review Scan Results
The scanner will enumerate ALL buckets and identify issues:
```
[+] Loaded module: AWS S3 Bucket Scanner
[*] Found 12 bucket(s) to scan
[*] Scanning bucket: company-backups
[*] Scanning bucket: production-data
[*] Scanning bucket: public-assets

╔════════════════════════════════════════════════════════╗
║                    Scan Results                         ║
╠════════════════════════════════════════════════════════╣
║ Bucket Name         │ company-backups                   ║
║ Region              │ us-east-1                         ║
║ Severity            │ CRITICAL                          ║
║ Issues              │ • No public access block          ║
║                     │ • Bucket ACL grants AllUsers      ║
║                     │ • No encryption configured        ║
╚════════════════════════════════════════════════════════╝
```

#### Step 4: Exploit Vulnerabilities
```
Vulnerabilities found. Do you want to attempt exploitation? Yes

[*] Starting exploitation phase...
[*] Attempting exploitation on: company-backups
[+] Successfully listed objects: 127 found
```

#### Step 5: Export Report
```
Main Menu → 4. Export Results
Select export format: HTML
Enter output filename: aws_s3_pentest_20250114
[+] Results exported to aws_s3_pentest_20250114.html
```

---

###  SCENARIO 2: Azure Storage Account Assessment

**Objective**: Identify Azure storage misconfigurations

#### Step 1: Prepare Azure Credentials

You need:
- Tenant ID
- Client ID (App Registration)
- Client Secret
- Subscription ID

**How to get these:**
```bash
# In Azure Portal:
# 1. Azure Active Directory → App registrations → New registration
# 2. Create client secret: Certificates & secrets → New client secret
# 3. Get IDs: Overview page shows Tenant ID and Client ID
# 4. Get Subscription ID: Subscriptions page
```

#### Step 2: Run Scanner
```bash
python3 main.py
# Select: 2. Select and Run Module
# Choose: Azure Storage Account Scanner
```

#### Step 3: Enter Credentials
```
Azure Tenant ID: 12345678-1234-1234-1234-123456789abc
Azure Client ID: 87654321-4321-4321-4321-cba987654321
Azure Client Secret: [your-secret]
Azure Subscription ID: abcdef12-3456-7890-abcd-ef1234567890
Scan mode: All Storage Accounts
```

#### Step 4: Review Results
```
[*] Found 5 storage account(s) to scan
[*] Scanning: prodstorageacct01

╔════════════════════════════════════════════════════════╗
║                    Scan Results                         ║
╠════════════════════════════════════════════════════════╣
║ Storage Account     │ prodstorageacct01                 ║
║ Location            │ eastus                            ║
║ Severity            │ HIGH                              ║
║ Issues              │ • HTTPS-only not enforced         ║
║                     │ • Blob public access allowed      ║
║                     │ • Weak TLS version: TLS1_0        ║
╚════════════════════════════════════════════════════════╝
```

---

###  SCENARIO 3: Subdomain Takeover Hunting

**Objective**: Find dangling DNS records vulnerable to takeover

#### Step 1: Run Scanner
```bash
python3 main.py
# Select: 2. Select and Run Module
# Choose: SaaS Subdomain Takeover Scanner
# use provided subdomains-premium.txt for scans
```

#### Step 2: Configure Scan
```
Target domain to scan: targetcompany.com
Subdomain wordlist: default  # or provide custom wordlist file
Number of threads: 20
HTTP request timeout: 5 seconds
```

#### Step 3: Real-Time Results
```
[*] Testing 100 subdomains with 20 threads
[+] VULNERABLE: blog.targetcompany.com
[+] VULNERABLE: staging.targetcompany.com
[+] VULNERABLE: dev.targetcompany.com

╔════════════════════════════════════════════════════════╗
║                    Scan Results                         ║
╠════════════════════════════════════════════════════════╣
║ Subdomain           │ blog.targetcompany.com            ║
║ CNAME               │ oldsite.herokuapp.com             ║
║ Service             │ Heroku                            ║
║ Vulnerable          │ True                              ║
║ Severity            │ HIGH                              ║
║ Impact              │ Subdomain takeover possible       ║
╚════════════════════════════════════════════════════════╝
```

#### Step 4: Exploitation Documentation
```
Vulnerabilities found. Do you want to attempt exploitation? Yes

[*] Starting exploitation phase...

╔════════════════════════════════════════════════════════╗
║              Exploitation Steps (Manual)                ║
╠════════════════════════════════════════════════════════╣
║ Service: Heroku                                         ║
║                                                         ║
║ Steps to claim:                                         ║
║ 1. Create a Heroku account                             ║
║ 2. Create new app: heroku create oldsite               ║
║ 3. Deploy simple web application                       ║
║ 4. Verify subdomain resolves to your app               ║
║                                                         ║
║ POC: Deploy page saying "Claimed by [YourName]"        ║
╚════════════════════════════════════════════════════════╝
```

---

###  SCENARIO 4: AWS IAM Privilege Escalation (CRITICAL)

** WARNING: This module ACTIVELY MODIFIES AWS IAM. Use ONLY in authorized test environments.**

**Objective**: Identify and exploit IAM privilege escalation paths

#### Step 1: Run Module
```bash
python3 main.py
# Select: 2. Select and Run Module
# Choose: AWS IAM Privilege Escalation
```

#### Step 2: Provide Credentials
```
AWS Access Key ID: AKIAIOSFODNN7EXAMPLE
AWS Secret Access Key: [your-secret-key]
AWS Region: us-east-1
Scan mode: Current User  # or All Users / Specific User
```

#### Step 3: Review Escalation Paths
```
[*] Authenticated as: dev-user
[*] Analyzing 1 user(s) for privilege escalation paths
[*] Scanning user: dev-user

╔════════════════════════════════════════════════════════╗
║              Privilege Escalation Found                 ║
╠════════════════════════════════════════════════════════╣
║ User                │ dev-user                          ║
║ Method              │ AttachUserPolicy                  ║
║ Permissions         │ iam:AttachUserPolicy              ║
║ Severity            │ CRITICAL                          ║
║ Description         │ Can attach managed policies       ║
║                     │ to users including self           ║
║ Exploitable         │ True                              ║
╚════════════════════════════════════════════════════════╝
```

#### Step 4: Exploit (DANGER ZONE)
```
Vulnerabilities found. Do you want to attempt exploitation? Yes

[!] WARNING: About to perform real privilege escalation attempts
[!] This will modify IAM resources

[*] Attempting AttachUserPolicy on user: dev-user
[+] Attached AdministratorAccess policy to dev-user

╔════════════════════════════════════════════════════════╗
║              Exploitation Results                       ║
╠════════════════════════════════════════════════════════╣
║ User                │ dev-user                          ║
║ Method              │ AttachUserPolicy                  ║
║ Status              │ SUCCESS                           ║
║ Actions             │ Attached AdministratorAccess      ║
║                     │ policy to dev-user                ║
║ Result              │ User now has admin privileges     ║
╚════════════════════════════════════════════════════════╝
```

** The user now has full AWS administrator access! **

---

##  Advanced Usage Scenarios

###  Multi-Phase Engagement

```bash
# Phase 1: Reconnaissance
python3 main.py
→ Run all discovery modules
→ Document findings

# Phase 2: Vulnerability Analysis
→ Review session results
→ Prioritize targets

# Phase 3: Exploitation
→ Exploit high-severity findings
→ Document access gained

# Phase 4: Reporting
→ Export all results to HTML
→ Generate executive summary
```

###  Session Management

```bash
# View current session
Main Menu → 3. View Session Info

# Output shows:
Session ID: a1b2c3d4
Started: 2025-01-14 10:30:00
Modules Run: 5
Total Findings: 23
```

###  Professional Reporting

```bash
# Export options
Main Menu → 4. Export Results

# Choose format:
1. JSON   - For integration with other tools
2. HTML   - Professional client-facing report with styling
3. TXT    - Plain text for documentation

# Output location:
./output/cloud_pentest_20250114_103000.html
```

---

##  Configuration & Customization

###  Adding Custom Modules

Create new attack modules easily:

```bash
# Copy template
cp templates/module_template.py modules/discovery/my_custom_scanner.py

# Edit the module
nano modules/discovery/my_custom_scanner.py

# Framework auto-loads new modules on next run
```

###  Module Structure

```python
from core.base_module import BaseModule

class MyCustomScanner(BaseModule):
    def __init__(self):
        super().__init__()
        self.name = "My Custom Scanner"
        self.description = "What it does"
        self.category = "discovery"  # or exploitation
        self.platform = "aws"  # or azure, gcp, saas
    
    def get_requirements(self):
        # Define user inputs
        return {...}
    
    def validate_input(self, inputs):
        # Validate inputs
        return True
    
    def scan(self, inputs):
        # Perform reconnaissance
        return results
    
    def exploit(self, targets, inputs):
        # Perform exploitation
        return exploit_results
```

---

##  Tips for Effective Red Teaming

###  Best Practices

1. **Always Obtain Authorization**
   - Written permission from system owner
   - Clear scope definition
   - Rules of engagement documented

2. **Start with Discovery**
   - Run all discovery modules first
   - Document findings thoroughly
   - Prioritize by severity

3. **Controlled Exploitation**
   - Test in isolated environments first
   - Understand the impact of each action
   - Have a rollback plan

4. **Document Everything**
   - Export results after each phase
   - Take screenshots of critical findings
   - Log all commands executed

5. **Professional Reporting**
   - Use HTML export for clients
   - Include remediation recommendations
   - Provide executive summary

###  Common Pitfalls to Avoid

- ❌ Running exploits without understanding impact
- ❌ Not backing up configurations before testing
- ❌ Forgetting to export results before closing
- ❌ Testing production systems without approval
- ❌ Not cleaning up after testing (remove test data, keys, etc.)

---

##  Operational Security (OPSEC)

###  Protecting Yourself

1. **Use VPN/Proxy** - Route traffic through authorized channels
2. **Separate Test Credentials** - Never use production credentials for testing
3. **Clean Up After Testing** - Remove test access keys, policies, and resources
4. **Encrypted Storage** - Store credentials and reports securely
5. **Audit Logs** - Monitor AWS CloudTrail, Azure Monitor, GCP Audit Logs

###  Post-Engagement Cleanup

```bash
# AWS Cleanup Example
aws iam delete-access-key --access-key-id AKIAI44QH8DHBEXAMPLE --user-name test-user
aws iam detach-user-policy --user-name test-user --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam delete-user-policy --user-name test-user --policy-name EscalatedPolicy
```

---

##  Troubleshooting

### Common Issues

#### Issue: "Module not found" error
```bash
# Solution: Ensure __init__.py files exist
touch modules/__init__.py
touch modules/discovery/__init__.py
touch modules/exploitation/__init__.py
touch modules/post_exploit/__init__.py
```

#### Issue: AWS credentials not working
```bash
# Test credentials independently
aws sts get-caller-identity --profile your-profile

# Verify permissions
aws iam get-user
```

#### Issue: Azure authentication fails
```bash
# Verify service principal has permissions
az login --service-principal -u CLIENT_ID -p CLIENT_SECRET --tenant TENANT_ID
az account show
```

#### Issue: GCP service account errors
```bash
# Verify service account file
cat /path/to/service-account.json

# Test authentication
gcloud auth activate-service-account --key-file=/path/to/service-account.json
gcloud projects list
```

#### Issue: DNS resolution fails in subdomain scanner
```bash
# Verify network connectivity
ping 8.8.8.8

# Test DNS resolution
nslookup example.com 8.8.8.8
```

---

##  Additional Resources

### Learning Resources
- [AWS Security Best Practices](https://aws.amazon.com/security/)
- [Azure Security Documentation](https://docs.microsoft.com/en-us/azure/security/)
- [GCP Security Best Practices](https://cloud.google.com/security/best-practices)
- [OWASP Cloud Security](https://owasp.org/www-project-cloud-security/)

### Related Tools
- [ScoutSuite](https://github.com/nccgroup/ScoutSuite) - Multi-cloud security auditing
- [Prowler](https://github.com/prowler-cloud/prowler) - AWS security assessment
- [Pacu](https://github.com/RhinoSecurityLabs/pacu) - AWS exploitation framework
- [ROADtools](https://github.com/dirkjanm/ROADtools) - Azure AD exploration

---

##  Credits

**Author**: ek0ms savi0r (Certified Ethical Hacker, security researcher)  

##  FINAL LEGAL DISCLAIMER ️

```
╔══════════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║  THIS TOOL PERFORMS REAL ATTACKS ON CLOUD INFRASTRUCTURE                 ║
║                                                                          ║
║  The exploitation modules WILL:                                          ║
║  • Create access keys in AWS IAM                                         ║
║  • Modify IAM policies and permissions                                   ║
║  • Access and enumerate cloud storage                                    ║
║  • Make changes to cloud resources                                       ║
║                                                                          ║
║  UNAUTHORIZED USE IS A FEDERAL CRIME                                     ║
║                                                                          ║
║  You are responsible for:                                                ║
║  ✓ Obtaining proper authorization                                        ║
║  ✓ Following all applicable laws                                         ║
║  ✓ Any damage caused by misuse                                           ║
║  ✓ Cleaning up test resources after engagement                           ║
║                                                                          ║
║  The author:                                                             ║
║  ✗ is NOT responsible for misuse                                         ║
║  ✗ Does NOT condone illegal activity                                     ║
║  ✗ Does NOT provide legal advice                                         ║
║  ✗ Assumes NO liability for your actions                                 ║
║                                                                          ║
║  USE AT YOUR OWN RISK                                                    ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
```

![Screenshot 2025-10-14 111008](https://github.com/user-attachments/assets/f23bfcb8-a345-4014-8c60-4f102015d38d)


