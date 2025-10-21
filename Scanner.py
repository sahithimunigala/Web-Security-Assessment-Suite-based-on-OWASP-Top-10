#!/usr/bin/env python3
"""
OWASP Top 10 Scanner Core Module
Implements vulnerability checks for OWASP Top 10 security risks.
"""

import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup

class Scanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.vulnerabilities = []

    def run_scan(self):
        """
        Run all security checks and return found vulnerabilities.
        """
        print("\n[+] Starting OWASP Top 10 Security Scan...")
        
        # Run security checks
        self.check_injection()
        self.check_broken_auth()
        self.check_sensitive_data_exposure()
        self.check_xss()
        self.check_broken_access_control()
        self.check_security_misconfig()
        self.check_csrf()
        
        print("[+] Scan completed!")
        return self.vulnerabilities

    # --- Vulnerability Check Methods ---

    def check_injection(self):
        """Check for SQL Injection vulnerabilities"""
        test_url = urljoin(self.target_url, "/?id=1'")
        try:
            response = self.session.get(test_url, timeout=5)  # 5 seconds timeout
            if "SQL syntax" in response.text or "mysql_fetch" in response.text:
                self.vulnerabilities.append({
                    "type": "SQL Injection",
                    "url": test_url,
                    "severity": "High"
                })
        except Exception as e:
            pass

    def check_xss(self):
        """Check for Cross-Site Scripting (XSS) vulnerabilities"""
        test_payload = "<script>alert('XSS')</script>"
        test_url = urljoin(self.target_url, f"/search?q={test_payload}")
        try:
            response = self.session.get(test_url, timeout=5)  # 5 seconds timeout
            if test_payload in response.text:
                self.vulnerabilities.append({
                    "type": "Cross-Site Scripting (XSS)",
                    "url": test_url,
                    "severity": "Medium"
                })
        except Exception as e:
            pass

    def check_broken_auth(self):
        """Check for broken authentication (admin pages accessible without auth)"""
        common_admin_paths = ["/admin", "/wp-admin", "/administrator"]
        for path in common_admin_paths:
            test_url = urljoin(self.target_url, path)
            try:
                response = self.session.get(test_url, timeout=5)  # 5 seconds timeout
                if response.status_code == 200 and "login" not in response.text.lower():
                    self.vulnerabilities.append({
                        "type": "Broken Authentication",
                        "url": test_url,
                        "severity": "High"
                    })
            except Exception as e:
                pass

    def check_sensitive_data_exposure(self):
        """Check for exposed sensitive data (like .env files)"""
        sensitive_files = [".env", "/config.php", "/.git/HEAD"]
        for file in sensitive_files:
            test_url = urljoin(self.target_url, file)
            try:
                response = self.session.get(test_url, timeout=5)  # 5 seconds timeout
                if response.status_code == 200:
                    self.vulnerabilities.append({
                        "type": "Sensitive Data Exposure",
                        "url": test_url,
                        "severity": "High"
                    })
            except Exception as e:
                pass

    def check_broken_access_control(self):
        """Check for insecure direct object references"""
        test_url = urljoin(self.target_url, "/profile/1")
        try:
            response = self.session.get(test_url, timeout=5)  # 5 seconds timeout
            if "Unauthorized" not in response.text and response.status_code == 200:
                self.vulnerabilities.append({
                    "type": "Broken Access Control",
                    "url": test_url,
                    "severity": "Medium"
                })
        except Exception as e:
            pass

    def check_security_misconfig(self):
        """Check for security misconfigurations (like directory listing)"""
        test_url = urljoin(self.target_url, "/static/")
        try:
            response = self.session.get(test_url, timeout=5)  # 5 seconds timeout
            if "Index of /static" in response.text:
                self.vulnerabilities.append({
                    "type": "Security Misconfiguration",
                    "url": test_url,
                    "severity": "Low"
                })
        except Exception as e:
            pass

    def check_csrf(self):
        """Check for missing CSRF protections on forms"""
        try:
            response = self.session.get(test_url, timeout=5)  # 5 seconds timeout
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            for form in forms:
                if not form.find('input', {'name': 'csrf_token'}):
                    self.vulnerabilities.append({
                        "type": "Missing CSRF Protection",
                        "form_action": form.get('action', 'N/A'),
                        "severity": "Medium"
                    })
        except Exception as e:
            pass