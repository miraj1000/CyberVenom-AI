import sys
import argparse
from datetime import datetime
from cryptography.fernet import Fernet
import json
import os

class CyberVenom:
    def __init__(self):
        self.version = "1.0.0"
        self.banner = f"""
        ========================================
        CyberVenom AI - Security Testing Toolkit
        Version: {self.version}
        ========================================
        Developed by Miraz - CyberVenom AI
        ========================================
        """
        self.encrypted_data = {}
        self.key = None

    def initialize(self):
        """Initialize the toolkit with encryption setup"""
        self.setup_encryption()
        self.setup_cli()

    def setup_encryption(self):
        """Setup encryption for sensitive data"""
        key_file = "cybervenom.key"
        if not os.path.exists(key_file):
            self.key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(self.key)
        else:
            with open(key_file, 'rb') as f:
                self.key = f.read()
        self.fernet = Fernet(self.key)

    def setup_cli(self):
        """Setup command line interface"""
        parser = argparse.ArgumentParser(description='CyberVenom AI - Security Testing Toolkit')
        subparsers = parser.add_subparsers(dest='command')

        # Vulnerability Scanner
        scan_parser = subparsers.add_parser('scan', help='Scan website for vulnerabilities')
        scan_parser.add_argument('target', help='Target URL to scan')
        scan_parser.add_argument('--full', action='store_true', help='Perform full scan')

        # Port Scanner
        port_parser = subparsers.add_parser('port', help='Scan open ports')
        port_parser.add_argument('host', help='Target host to scan')
        port_parser.add_argument('--ports', help='Specific ports to scan (comma separated)')

        # Password Checker
        pass_parser = subparsers.add_parser('password', help='Check password strength')
        pass_parser.add_argument('password', help='Password to check')

        # AI Code Generator
        ai_parser = subparsers.add_parser('ai', help='AI code generation')
        ai_parser.add_argument('prompt', help='Prompt for code generation')

        args = parser.parse_args()
        
        if args.command == 'scan':
            scanner = VulnerabilityScanner()
            scanner.scan(args.target, full_scan=args.full)
        elif args.command == 'port':
            scanner = PortScanner()
            scanner.scan(args.host, args.ports)
        elif args.command == 'password':
            checker = PasswordChecker()
            checker.check_strength(args.password)
        elif args.command == 'ai':
            ai = AICodeGenerator()
            ai.generate_code(args.prompt)
        else:
            print(self.banner)
            parser.print_help()

class VulnerabilityScanner:
    def __init__(self):
        self.vulnerabilities = {
            'xss': self.check_xss,
            'sqli': self.check_sql_injection,
            'csrf': self.check_csrf
        }

    def scan(self, target, full_scan=False):
        """Perform vulnerability scan on target URL"""
        print(f"\n[+] Starting scan on {target}")
        print("[+] Scan started at:", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        
        # Basic security headers check
        self.check_security_headers(target)
        
        # Perform vulnerability checks
        for vuln_type, check_func in self.vulnerabilities.items():
            print(f"\n[+] Checking for {vuln_type.upper()} vulnerabilities...")
            check_func(target)

        if full_scan:
            print("\n[+] Performing full scan...")
            self.perform_full_scan(target)

    def check_security_headers(self, url):
        """Check for security headers"""
        try:
            import requests
            response = requests.get(url)
            headers = response.headers
            
            print("\n[+] Security Headers Check:")
            security_headers = ['X-Frame-Options', 'X-XSS-Protection', 'X-Content-Type-Options',
                              'Strict-Transport-Security', 'Content-Security-Policy']
            
            for header in security_headers:
                if header in headers:
                    print(f"[✓] {header}: {headers[header]}")
                else:
                    print(f"[✗] {header}: Missing")
        except Exception as e:
            print(f"[!] Error checking security headers: {str(e)}")

    def check_xss(self, url):
        """Check for Cross-Site Scripting vulnerabilities"""
        try:
            test_payloads = [
                '<script>alert("XSS")</script>',
                '" onerror="alert(1)"",
                '<img src=x onerror=alert(1)>',
                'javascript:alert(1)'
            ]
            
            for payload in test_payloads:
                test_url = f"{url}?test={payload}"
                response = requests.get(test_url)
                if payload in response.text:
                    print(f"[!] Potential XSS vulnerability found with payload: {payload}")
        except Exception as e:
            print(f"[!] Error checking XSS: {str(e)}")

    def check_sql_injection(self, url):
        """Check for SQL Injection vulnerabilities"""
        try:
            test_payloads = [
                "' OR '1'='1",
                "' OR 1=1 --",
                "' OR 1=1 /*",
                "' OR 1=1 #"
            ]
            
            for payload in test_payloads:
                test_url = f"{url}?test={payload}"
                response = requests.get(test_url)
                if "error" in response.text.lower():
                    print(f"[!] Potential SQL Injection vulnerability found with payload: {payload}")
        except Exception as e:
            print(f"[!] Error checking SQL Injection: {str(e)}")

    def check_csrf(self, url):
        """Check for Cross-Site Request Forgery vulnerabilities"""
        try:
            import requests
            response = requests.get(url)
            
            # Look for CSRF token
            if "csrf" not in response.text.lower():
                print("[!] Potential CSRF vulnerability: No CSRF token found")
            
            # Check for anti-CSRF headers
            headers = response.headers
            if "X-CSRF-Token" not in headers:
                print("[!] Potential CSRF vulnerability: Missing X-CSRF-Token header")
        except Exception as e:
            print(f"[!] Error checking CSRF: {str(e)}")

    def perform_full_scan(self, url):
        """Perform additional security checks"""
        try:
            import requests
            response = requests.get(url)
            
            # Check for common vulnerabilities
            print("\n[+] Additional Security Checks:")
            
            # Directory listing
            if "index of" in response.text.lower():
                print("[!] Directory listing enabled")
            
            # Backup files
            common_backups = ['.bak', '.old', '.orig', '.backup']
            for ext in common_backups:
                backup_url = f"{url}{ext}"
                try:
                    backup_response = requests.get(backup_url)
                    if backup_response.status_code == 200:
                        print(f"[!] Found backup file: {backup_url}")
                except:
                    continue
        except Exception as e:
            print(f"[!] Error in full scan: {str(e)}")

class PortScanner:
    def scan(self, host, ports=None):
        """Scan open ports on target host"""
        import nmap
        print(f"\n[+] Starting port scan on {host}")
        
        nm = nmap.PortScanner()
        
        if ports:
            nm.scan(host, ports)
        else:
            nm.scan(host, '1-1024')
        
        print("\n[+] Open Ports:")
        for port in nm[host]['tcp']:
            if nm[host]['tcp'][port]['state'] == 'open':
                print(f"[+] Port {port}: {nm[host]['tcp'][port]['name']}")

class PasswordChecker:
    def check_strength(self, password):
        """Check password strength"""
        import re
        
        print("\n[+] Password Strength Analysis:")
        
        # Length check
        if len(password) < 8:
            print("[!] Warning: Password is too short (less than 8 characters)")
        
        # Complexity checks
        has_upper = bool(re.search(r'[A-Z]', password))
        has_lower = bool(re.search(r'[a-z]', password))
        has_digit = bool(re.search(r'[0-9]', password))
        has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
        
        print(f"[+] Contains uppercase letters: {has_upper}")
        print(f"[+] Contains lowercase letters: {has_lower}
