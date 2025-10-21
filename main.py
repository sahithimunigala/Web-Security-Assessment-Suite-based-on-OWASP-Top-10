#!/usr/bin/env python3
"""
OWASP Top 10 Security Scanner - Main Module
Handles user input, initiates scans, and triggers reporting.
"""

from core.Scanner import Scanner
from core.Reporter import Reporter

def get_target_url():
    """Prompt user to input target URL."""
    print("\n=== OWASP Top 10 Security Scanner ===")
    while True:
        url = input("\nEnter target URL (e.g., https://example.com): ").strip()
        if url.startswith(("http://", "https://")):
            return url
        print("[ERROR] URL must start with 'http://' or 'https://'")

def main():
    # Get user input
    target_url = get_target_url()
    output_file = "./report.txt"  # Default report path

    # Initialize components
    scanner = Scanner(target_url)
    reporter = Reporter(output_file)

    # Run scan and generate report
    try:
        print(f"\n[+] Scanning target: {target_url}")
        vulnerabilities = scanner.run_scan()
        
        print("[+] Generating report...")
        reporter.generate_report(vulnerabilities)
        
        print(f"[!] Report saved to: {output_file}")
    except Exception as e:
        print(f"[ERROR] Scan failed: {str(e)}")

if __name__ == "__main__":
    main()