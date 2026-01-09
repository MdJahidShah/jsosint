#!/usr/bin/env python3
import socket
import re
import requests
import dns.resolver
import whois
import ssl
import json
import concurrent.futures
import urllib3
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from datetime import datetime

# Disable SSL warnings to keep output clean
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from utils.colors import Colors

class WebsiteRecon:
    def __init__(self, domain):
        self.domain = domain
        self.colors = Colors()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) OSINT-Scanner/2.0'
        })

    def get_basic_info(self):
        """Enhanced basic info with visual feedback"""
        info = {'domain': self.domain}
        try:
            ip = socket.gethostbyname(self.domain)
            info['ip_address'] = ip
            print(f"  {self.colors.GREEN}[+] IP Address: {ip}{self.colors.RESET}")
            
            # Try to get Server header
            res = self.session.get(f"http://{self.domain}", timeout=5, verify=False)
            server = res.headers.get('Server', 'Unknown')
            info['server'] = server
            print(f"  {self.colors.GREEN}[+] Web Server: {server}{self.colors.RESET}")
            
            # Check Title
            soup = BeautifulSoup(res.text, 'html.parser')
            title = soup.title.string if soup.title else "No Title Found"
            info['title'] = title
            print(f"  {self.colors.GREEN}[+] Page Title: {title}{self.colors.RESET}")
            
        except Exception as e:
            print(f"  {self.colors.RED}[-] Basic Info Error: {e}{self.colors.RESET}")
        return info

    def enumerate_dns(self):
        """Aggressive DNS Lookup"""
        print(f"  {self.colors.CYAN}[*] Querying DNS Records...{self.colors.RESET}")
        records = {}
        types = ['A', 'MX', 'NS', 'TXT', 'AAAA', 'SOA']
        for rtype in types:
            try:
                answers = dns.resolver.resolve(self.domain, rtype)
                records[rtype] = [str(rdata) for rdata in answers]
                for r in records[rtype]:
                    print(f"    {self.colors.GREEN}✓ {rtype}: {r}{self.colors.RESET}")
            except:
                continue
        return records

    def detect_technologies(self):
        """Advanced Technology Fingerprinting"""
        print(f"  {self.colors.CYAN}[*] Fingerprinting Technologies...{self.colors.RESET}")
        techs = []
        try:
            res = self.session.get(f"http://{self.domain}", timeout=10, verify=False)
            h = str(res.headers).lower()
            c = res.text.lower()

            # Detection Logic
            checks = {
                'Cloudflare': 'cf-ray' in h,
                'WordPress': 'wp-content' in c,
                'jQuery': 'jquery' in c,
                'Nginx': 'nginx' in h,
                'Apache': 'apache' in h,
                'PHP': 'php' in h or '.php' in c,
                'ASP.NET': 'asp.net' in h or 'viewstate' in c,
                'Bootstrap': 'bootstrap' in c,
                'React': 'react' in c
            }
            
            for name, found in checks.items():
                if found:
                    techs.append(name)
                    print(f"    {self.colors.YELLOW}⚡ Found: {name}{self.colors.RESET}")
        except:
            pass
        return techs

    def find_subdomains(self):
        """Concurrent Subdomain Enumeration using wordlist"""
        print(f"  {self.colors.CYAN}[*] Enumerating Subdomains...{self.colors.RESET}")

        import socket
        import concurrent.futures
        from pathlib import Path

        subdomains = []

        # Wordlist path (relative to project root)
        wordlist_path = Path(__file__).parent.parent / "wordlists" / "subdomains.txt"

        if wordlist_path.exists():
            with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                common_subs = [
                    line.strip()
                    for line in f
                    if line.strip() and not line.startswith("#")
                ]
        else:
            print(f"  {self.colors.YELLOW}[!]{self.colors.RESET} subdomains.txt not found, using fallback list")
            common_subs = ['www', 'mail', 'ftp', 'test', 'dev', 'admin', 'blog', 'shop', 'api']

        def check_subdomain(sub):
            full_domain = f"{sub}.{self.domain}"
            try:
                socket.gethostbyname(full_domain)
                return full_domain
            except socket.gaierror:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            for result in executor.map(check_subdomain, common_subs):
                if result:
                    subdomains.append(result)
                    print(f"    {self.colors.GREEN}✓ Found: {result}{self.colors.RESET}")

        return subdomains

    def find_directories(self):
        """Automated Directory Fuzzing"""
        print(f"  {self.colors.CYAN}[*] Fuzzing for sensitive directories...{self.colors.RESET}")
        found = []
        paths = ['admin', 'backup', '.git', '.env', 'config.php', 'wp-admin', 'api', 'v1', 'upload']
        
        def check_path(p):
            url = f"http://{self.domain}/{p}"
            try:
                r = self.session.get(url, timeout=3, verify=False)
                if r.status_code == 200:
                    return url
            except: return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            results = executor.map(check_path, paths)
            for r in results:
                if r:
                    found.append(r)
                    print(f"    {self.colors.RED}[!] Exposed: {r}{self.colors.RESET}")

        return found
    def whois_lookup(self):
        """Resilient WHOIS lookup"""
        print(f"  {self.colors.CYAN}[*] Fetching WHOIS data...{self.colors.RESET}")
        try:
            # Try Python library first
            w = whois.whois(self.domain)
            print(f"    {self.colors.GREEN}✓ Registrar: {w.registrar}{self.colors.RESET}")
            print(f"    {self.colors.GREEN}✓ Creation Date: {w.creation_date}{self.colors.RESET}")
            return {
                "registrar": w.registrar,
                "creation_date": str(w.creation_date),
                "emails": w.emails
            }
        except Exception:
            # Fallback to system command if library fails
            try:
                import subprocess
                raw = subprocess.check_output(['whois', self.domain]).decode()
                print(f"    {self.colors.YELLOW}✓ Fetched via System WHOIS fallback{self.colors.RESET}")
                return {"raw": raw[:500]}
            except:
                return {"error": "WHOIS completely unavailable"}
    def harvest_emails(self):
        """Comprehensive Email Harvesting"""
        print(f"  {self.colors.CYAN}[*] Harvesting Emails...{self.colors.RESET}")
        emails = set()
        try:
            res = self.session.get(f"http://{self.domain}", timeout=10, verify=False)
            found = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', res.text)
            for email in found:
                emails.add(email)
                print(f"    {self.colors.GREEN}✓ Found: {email}{self.colors.RESET}")
        except Exception as e:
            print(f"    {self.colors.RED}[-] Email Harvesting Error: {e}{self.colors.RESET}")
        return list(emails)
    def scan_ports(self):
        """Basic Port Scanning"""
        print(f"  {self.colors.CYAN}[*] Scanning Common Ports...{self.colors.RESET}")
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 8080, 8443, 6379, 27017, 11211, 9200, 27017, 5000, 7000, 9000]
        open_ports = []
        
        def check_port(port):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((self.domain, port))
                if result == 0:
                    return port
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            results = executor.map(check_port, common_ports)
            for r in results:
                if r:
                    open_ports.append(r)
                    print(f"    {self.colors.GREEN}✓ Open Port: {r}{self.colors.RESET}")

        return open_ports
    
    def run_all(self):
        """Run all reconnaissance modules"""
        results = {}
        print(f"{self.colors.BLUE}{'='*70}{self.colors.RESET}")
        print(f"{self.colors.GREEN}[*]{self.colors.RESET} Starting Comprehensive Website Reconnaissance on {self.domain}")
        print(f"{self.colors.BLUE}{'='*70}{self.colors.RESET}\n")
        
        # Module 1: Basic Info
        print(f"{self.colors.CYAN}[1] Basic Information{self.colors.RESET}")
        results['basic_info'] = self.get_basic_info()
        print()
        
        # Module 2: DNS Enumeration
        print(f"{self.colors.CYAN}[2] DNS Enumeration{self.colors.RESET}")
        results['dns_records'] = self.enumerate_dns()
        print()
        
        # Module 3: Technology Fingerprinting
        print(f"{self.colors.CYAN}[3] Technology Fingerprinting{self.colors.RESET}")
        results['technologies'] = self.detect_technologies()
        print()
        
        # Module 4: Directory Fuzzing
        print(f"{self.colors.CYAN}[4] Directory Fuzzing{self.colors.RESET}")
        results['sensitive_directories'] = self.find_directories()
        print()
        
        # Module 5: WHOIS Lookup
        print(f"{self.colors.CYAN}[5] WHOIS Lookup{self.colors.RESET}")
        results['whois'] = self.whois_lookup()
        print()
        
        # Module 6: Email Harvesting
        print(f"{self.colors.CYAN}[6] Email Harvesting{self.colors.RESET}")
        results['emails'] = self.harvest_emails()
        print()
        
        # Module 7: Port Scanning
        print(f"{self.colors.CYAN}[7] Port Scanning{self.colors.RESET}")
        results['ports'] = self.scan_ports()
        print()
        
        print(f"{self.colors.BLUE}{'='*70}{self.colors.RESET}")
        print(f"{self.colors.GREEN}[*]{self.colors.RESET} Reconnaissance Completed")
        print(f"{self.colors.BLUE}{'='*70}{self.colors.RESET}")
        
        return results