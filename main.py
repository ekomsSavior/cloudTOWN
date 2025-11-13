#!/usr/bin/env python3
"""
Cloud Red Team Framework - Production Version
Real exploitation framework for authorized security testing
Author: ek0ms
"""

import sys
import os
from pathlib import Path

# Add the framework to path
sys.path.insert(0, str(Path(__file__).parent))

from core.framework import CloudRedTeamFramework

def main():
    """Main entry point for the framework"""
    banner = """
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║          Cloud Red Team Framework v2.0                    ║
    ║          Real Cloud Security Testing                      ║
    ║          AUTHORIZED USE ONLY                              ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
    """
    
    print(banner)
    print("    [*] Supports: AWS, Azure, GCP, SaaS Platforms")
    print("    [*] Mode: LIVE EXPLOITATION")
    print("    [*] Author: ek0ms")
    print("\n    [!] WARNING: This framework performs REAL attacks")
    print("    [!] Only use on systems you own or have authorization to test\n")
    
    try:
        framework = CloudRedTeamFramework()
        framework.run()
    except KeyboardInterrupt:
        print("\n\n[!] Framework interrupted by user. Exiting...")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
