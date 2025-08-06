#!/usr/bin/env python3
"""
MultiThreatScanner - Because one threat vector is for amateurs
Author: Kevin Landry
Version: 1.0.0
Description: A comprehensive cybersecurity scanning tool that doesn't mess around
"""

import nmap
import shodan
import cv2
import smtplib
import argparse
import json
import logging
import sys
import os
import time
import requests
import ssl
import socket
from datetime import datetime
from email.mime.text import MimeText
from email.mime.multipart import MimeMultipart
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class MultiThreatScanner:
    """
    Kevin Landry's MultiThreatScanner - The Swiss Army knife of cybersecurity scanning
    Because hackers don't take coffee breaks, and neither should your security tools.
    """
    
    def __init__(self, target, config_file=None):
        self.target = target
        self.config = self.load_config(config_file)
        self.results = {
            'target': target,
            'scan_time': datetime.now().isoformat(),
            'scanner_author': 'Kevin Landry',
            'threats_found': [],
            'vulnerabilities': [],
            'risk_score': 0
        }
        self.setup_logging()
        
    def setup_logging(self):
        """Setup logging because we're not barbarians"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - MultiThreatScanner - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('multithreat_scan.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def load_config(self, config_file):
        """Load configuration or use sensible defaults"""
        default_config = {
            'shodan_api_key': 'your_api_key_here',
            'email_settings': {
                'smtp_server': 'smtp.gmail.com',
                'smtp_port': 587,
                'username': 'your_email@gmail.com',
                'password': 'your_app_password',
                'alert_recipients': ['admin@example.com']
            },
            'scan_settings': {
                'nmap_args': '-sS -sV -O -A --script vuln',
                'timeout': 300,
                'phishing_threshold': 0.8
            }
        }
        
        if config_file and os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    loaded_config = json.load(f)
                    default_config.update(loaded_config)
            except Exception as e:
                self.logger.warning(f"Failed to load config file: {e}. Using defaults.")
        
        return default_config
    
    def banner(self):
        """Display banner because style matters"""
        banner_text = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                    MultiThreatScanner v1.0                  ║
    ║                      by Kevin Landry                        ║
    ║                                                              ║
    ║    "Scanning threats so you don't have to lose sleep"       ║
    ╚══════════════════════════════════════════════════════════════╝
        """
        print(banner_text)
        
    def nmap_scan(self):
        """Network reconnaissance - the foundation of knowing your enemy"""
        self.logger.info(f"Starting Nmap scan on {self.target}")
        try:
            scanner = nmap.PortScanner()
            scan_args = self.config['scan_settings']['nmap_args']
            
            self.logger.info(f"Running: nmap {scan_args} {self.target}")
            result = scanner.scan(self.target, arguments=scan_args)
            
            if self.target in scanner.all_hosts():
                host_info = scanner[self.target]
                
                # Analyze open ports
                for protocol in host_info.all_protocols():
                    ports = host_info[protocol].keys()
                    for port in ports:
                        port_info = host_info[protocol][port]
                        if port_info['state'] == 'open':
                            vulnerability = {
                                'type': 'open_port',
                                'port': port,
                                'service': port_info.get('name', 'unknown'),
                                'version': port_info.get('version', 'unknown'),
                                'risk_level': self.assess_port_risk(port, port_info)
                            }
                            self.results['vulnerabilities'].append(vulnerability)
                
                self.logger.info(f"Nmap scan completed. Found {len(self.results['vulnerabilities'])} potential issues.")
                return True
            else:
                self.logger.warning(f"Host {self.target} appears to be down or unresponsive")
                return False
                
        except Exception as e:
            self.logger.error(f"Nmap scan failed: {e}")
            return False
    
    def assess_port_risk(self, port, port_info):
        """Assess risk level of open ports - some are worse than others"""
        high_risk_ports = [21, 23, 25, 53, 135, 139, 445, 1433, 3389, 5432, 5900]
        medium_risk_ports = [22, 80, 443, 993, 995]
        
        if port in high_risk_ports:
            return 'HIGH'
        elif port in medium_risk_ports:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def shodan_lookup(self):
        """Shodan intelligence gathering - see what the internet sees"""
        if self.config['shodan_api_key'] == 'your_api_key_here':
            self.logger.warning("Shodan API key not configured. Skipping Shodan lookup.")
            return False
            
        try:
            self.logger.info(f"Querying Shodan for intelligence on {self.target}")
            api = shodan.Shodan(self.config['shodan_api_key'])
            
            # Resolve domain to IP if needed
            try:
                target_ip = socket.gethostbyname(self.target)
            except:
                target_ip = self.target
            
            host_info = api.host(target_ip)
            
            # Analyze Shodan data
            if 'vulns' in host_info:
                for vuln in host_info['vulns']:
                    vulnerability = {
                        'type': 'cve',
                        'cve_id': vuln,
                        'source': 'shodan',
                        'risk_level': 'HIGH'
                    }
                    self.results['vulnerabilities'].append(vulnerability)
            
            if 'ports' in host_info:
                self.logger.info(f"Shodan found {len(host_info['ports'])} open ports")
            
            self.logger.info("Shodan lookup completed successfully")
            return True
            
        except shodan.APIError as e:
            self.logger.error(f"Shodan API error: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Shodan lookup failed: {e}")
            return False
    
    def ssl_analysis(self):
        """SSL/TLS certificate analysis - because encryption matters"""
        try:
            self.logger.info(f"Analyzing SSL/TLS configuration for {self.target}")
            
            context = ssl.create_default_context()
            with socket.create_connection((self.target, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate expiration
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (not_after - datetime.now()).days
                    
                    if days_until_expiry < 30:
                        vulnerability = {
                            'type': 'ssl_expiry',
                            'description': f'SSL certificate expires in {days_until_expiry} days',
                            'risk_level': 'MEDIUM' if days_until_expiry > 7 else 'HIGH'
                        }
                        self.results['vulnerabilities'].append(vulnerability)
                    
                    self.logger.info(f"SSL certificate valid until {not_after}")
                    return True
                    
        except Exception as e:
            self.logger.warning(f"SSL analysis failed: {e}")
            return False
    
    def phishing_detection(self, screenshot_path=None):
        """Visual phishing detection - because looks can be deceiving"""
        if not screenshot_path:
            self.logger.info("No screenshot provided for phishing detection")
            return False
            
        try:
            self.logger.info("Analyzing website for phishing indicators")
            
            # Take screenshot if URL provided
            if screenshot_path.startswith('http'):
                screenshot_path = self.capture_website_screenshot(screenshot_path)
            
            if not os.path.exists(screenshot_path):
                self.logger.warning(f"Screenshot file not found: {screenshot_path}")
                return False
            
            # Load and analyze image
            site_img = cv2.imread(screenshot_path, 0)
            
            # Check for common phishing indicators (simplified)
            # In a real implementation, you'd have a database of known phishing templates
            phishing_templates = ['phishing_sample.png', 'fake_login.png']
            
            threshold = self.config['scan_settings']['phishing_threshold']
            
            for template in phishing_templates:
                if os.path.exists(template):
                    template_img = cv2.imread(template, 0)
                    result = cv2.matchTemplate(site_img, template_img, cv2.TM_CCOEFF_NORMED)
                    _, max_val, _, _ = cv2.minMaxLoc(result)
                    
                    if max_val > threshold:
                        vulnerability = {
                            'type': 'phishing',
                            'description': f'Phishing template match: {template}',
                            'confidence': max_val,
                            'risk_level': 'CRITICAL'
                        }
                        self.results['vulnerabilities'].append(vulnerability)
                        self.logger.warning(f"Phishing detected! Confidence: {max_val:.2f}")
                        return True
            
            self.logger.info("No phishing indicators detected")
            return False
            
        except Exception as e:
            self.logger.error(f"Phishing detection failed: {e}")
            return False
    
    def capture_website_screenshot(self, url):
        """Capture website screenshot for analysis"""
        # This would require additional dependencies like selenium
        # For now, return a placeholder
        self.logger.info(f"Would capture screenshot of {url}")
        return "placeholder_screenshot.png"
    
    def calculate_risk_score(self):
        """Calculate overall risk score - the moment of truth"""
        score = 0
        
        for vuln in self.results['vulnerabilities']:
            risk_level = vuln.get('risk_level', 'LOW')
            if risk_level == 'CRITICAL':
                score += 25
            elif risk_level == 'HIGH':
                score += 15
            elif risk_level == 'MEDIUM':
                score += 10
            elif risk_level == 'LOW':
                score += 5
        
        # Cap at 100
        self.results['risk_score'] = min(score, 100)
        
        if score >= 75:
            threat_level = "CRITICAL - This target is a hacker's playground"
        elif score >= 50:
            threat_level = "HIGH - Significant security concerns detected"
        elif score >= 25:
            threat_level = "MEDIUM - Some issues need attention"
        else:
            threat_level = "LOW - Looking reasonably secure"
        
        self.results['threat_level'] = threat_level
        self.logger.info(f"Risk assessment complete. Score: {score}/100 - {threat_level}")
    
    def send_alert(self, custom_message=None):
        """Send email alert - because someone needs to know"""
        try:
            email_config = self.config['email_settings']
            
            if email_config['username'] == 'your_email@gmail.com':
                self.logger.warning("Email not configured. Skipping alert.")
                return False
            
            self.logger.info("Sending security alert email")
            
            msg = MimeMultipart()
            msg['From'] = email_config['username']
            msg['Subject'] = f"MultiThreatScanner Alert - {self.target}"
            
            # Create alert message
            if custom_message:
                body = custom_message
            else:
                body = f"""
MultiThreatScanner Security Alert
Scan performed by: Kevin Landry's MultiThreatScanner

Target: {self.target}
Scan Time: {self.results['scan_time']}
Risk Score: {self.results['risk_score']}/100
Threat Level: {self.results['threat_level']}

Vulnerabilities Found: {len(self.results['vulnerabilities'])}

Detailed findings available in scan log.

This alert was generated automatically by MultiThreatScanner.
"""
            
            msg.attach(MimeText(body, 'plain'))
            
            server = smtplib.SMTP(email_config['smtp_server'], email_config['smtp_port'])
            server.starttls()
            server.login(email_config['username'], email_config['password'])
            
            for recipient in email_config['alert_recipients']:
                msg['To'] = recipient
                server.send_message(msg)
                self.logger.info(f"Alert sent to {recipient}")
            
            server.quit()
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send alert: {e}")
            return False
    
    def generate_report(self):
        """Generate comprehensive scan report"""
        report = f"""
MultiThreatScanner Report
========================
Created by: Kevin Landry's MultiThreatScanner
Scan Date: {self.results['scan_time']}
Target: {self.target}

EXECUTIVE SUMMARY
=================
Risk Score: {self.results['risk_score']}/100
Threat Level: {self.results['threat_level']}
Total Vulnerabilities: {len(self.results['vulnerabilities'])}

DETAILED FINDINGS
=================
"""
        
        if self.results['vulnerabilities']:
            for i, vuln in enumerate(self.results['vulnerabilities'], 1):
                report += f"\n{i}. {vuln.get('type', 'Unknown').upper()}\n"
                report += f"   Risk Level: {vuln.get('risk_level', 'Unknown')}\n"
                report += f"   Description: {vuln.get('description', 'N/A')}\n"
                if 'port' in vuln:
                    report += f"   Port: {vuln['port']}\n"
                if 'service' in vuln:
                    report += f"   Service: {vuln['service']}\n"
                report += "\n"
        else:
            report += "\nNo significant vulnerabilities detected.\n"
        
        report += "\nScan completed by MultiThreatScanner - Because security never sleeps.\n"
        
        # Save report
        report_file = f"multithreat_report_{self.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(report_file, 'w') as f:
            f.write(report)
        
        self.logger.info(f"Report saved to {report_file}")
        return report
    
    def run_comprehensive_scan(self, screenshot_path=None):
        """Run the full MultiThreatScanner suite - the main event"""
        self.banner()
        self.logger.info(f"Starting comprehensive scan of {self.target}")
        
        # Run all scan modules
        self.nmap_scan()
        self.shodan_lookup()
        self.ssl_analysis()
        if screenshot_path:
            self.phishing_detection(screenshot_path)
        
        # Calculate risk and generate report
        self.calculate_risk_score()
        report = self.generate_report()
        
        # Send alert if high risk
        if self.results['risk_score'] >= 50:
            self.send_alert()
        
        print(report)
        self.logger.info("Comprehensive scan completed")
        return self.results

def main():
    """Main function - where the magic happens"""
    parser = argparse.ArgumentParser(
        description='MultiThreatScanner by Kevin Landry - Comprehensive cybersecurity scanning'
    )
    parser.add_argument('target', help='Target domain or IP address')
    parser.add_argument('--config', help='Configuration file path')
    parser.add_argument('--screenshot', help='Website screenshot for phishing detection')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Initialize and run scanner
    scanner = MultiThreatScanner(args.target, args.config)
    results = scanner.run_comprehensive_scan(args.screenshot)
    
    # Exit with appropriate code
    if results['risk_score'] >= 75:
        sys.exit(2)  # Critical
    elif results['risk_score'] >= 25:
        sys.exit(1)  # Warning
    else:
        sys.exit(0)  # Success

if __name__ == "__main__":
    main()
