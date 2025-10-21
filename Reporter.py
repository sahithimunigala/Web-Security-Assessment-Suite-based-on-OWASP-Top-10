#!/usr/bin/env python3
import json
from datetime import datetime

class Reporter:
    def __init__(self, output_file):
        self.output_file = output_file
        self.report_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def generate_report(self, vulnerabilities):
        if not vulnerabilities:
            self._generate_clean_report()
            return

        if self.output_file.endswith('.html'):
            self._generate_html_report(vulnerabilities)
        else:
            self._generate_text_report(vulnerabilities)

    def _generate_text_report(self, vulnerabilities):
        with open(self.output_file, 'w') as f:
            f.write(f"OWASP Top 10 Security Scan Report\n")
            f.write(f"="*50 + "\n")
            f.write(f"Date: {self.report_date}\n")
            f.write(f"Total vulnerabilities found: {len(vulnerabilities)}\n\n")
            for i, vuln in enumerate(vulnerabilities, 1):
                f.write(f"{i}. {vuln['type']} ({vuln['severity']})\n")
                f.write(f"   URL/Resource: {vuln.get('url', vuln.get('form_action', 'N/A'))}\n")
                f.write("\n")
            f.write("\n" + "="*50 + "\n")
            f.write(self._get_summary_stats(vulnerabilities))

    def _generate_html_report(self, vulnerabilities):
        with open(self.output_file, 'w') as f:
            f.write(f"""<!DOCTYPE html>
<html>
<head>
    <title>OWASP Top 10 Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; }}
        h1 {{ color: #2c3e50; }}
        .vulnerability {{ margin-bottom: 20px; padding: 10px; border-left: 4px solid; }}
        .high {{ border-color: #e74c3c; background: #fadbd8; }}
        .medium {{ border-color: #f39c12; background: #fdebd0; }}
        .low {{ border-color: #3498db; background: #d6eaf8; }}
        .summary {{ margin-top: 30px; padding: 15px; background: #f2f2f2; }}
    </style>
</head>
<body>
    <h1>OWASP Top 10 Security Scan Report</h1>
    <p><strong>Date:</strong> {self.report_date}</p>
    <p><strong>Total vulnerabilities found:</strong> {len(vulnerabilities)}</p>
    <hr>
    <h2>Vulnerabilities Found</h2>
""")
            for i, vuln in enumerate(vulnerabilities, 1):
                severity_class = vuln['severity'].lower()
                f.write(f"""
    <div class="vulnerability {severity_class}">
        <h3>{i}. {vuln['type']} (<span class="severity">{vuln['severity']}</span>)</h3>
        <p><strong>Location:</strong> {vuln.get('url', vuln.get('form_action', 'N/A'))}</p>
    </div>
""")
            f.write(f"""
    <div class="summary">
        <h2>Scan Summary</h2>
        {self._get_summary_stats(vulnerabilities, html=True)}
    </div>
</body>
</html>
""")

    def _generate_clean_report(self):
        if self.output_file.endswith('.html'):
            content = f"""<!DOCTYPE html>
<html>
<head>
    <title>OWASP Top 10 Security Report</title>
</head>
<body>
    <h1>OWASP Top 10 Security Scan Report</h1>
    <p><strong>Date:</strong> {self.report_date}</p>
    <p><strong>Result:</strong> No vulnerabilities found!</p>
</body>
</html>
"""
        else:
            content = f"""OWASP Top 10 Security Scan Report
{"="*50}
Date: {self.report_date}
Result: No vulnerabilities found!
"""

        with open(self.output_file, 'w') as f:
            f.write(content)

    def _get_summary_stats(self, vulnerabilities, html=False):
        """Generate summary statistics"""
        counts = {
            'High': 0,
            'Medium': 0,
            'Low': 0
        }

        for vuln in vulnerabilities:
            counts[vuln['severity']] += 1

        if html:
            return f"""
        <p><strong>High:</strong> {counts['High']} vulnerabilities</p>
        <p><strong>Medium:</strong> {counts['Medium']} vulnerabilities</p>
        <p><strong>Low:</strong> {counts['Low']} vulnerabilities</p>
"""
        else:
            return f"""Summary:
- High severity: {counts['High']}
- Medium severity: {counts['Medium']}
- Low severity: {counts['Low']}
"""