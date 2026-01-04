#!/usr/bin/env python3
"""
Kali Linux Tools Integration Module
"""

import subprocess
import os
import re
from datetime import datetime

class KaliTools:
    """Interface with Kali Linux's pre-installed tools"""
    
    @staticmethod
    def run_command(cmd, timeout=30):
        """Run shell command and return output"""
        try:
            result = subprocess.run(
                cmd, 
                shell=True, 
                capture_output=True, 
                text=True, 
                timeout=timeout
            )
            return {
                'success': result.returncode == 0 or result.returncode == 1,  # Some tools return 1 for no results
                'output': result.stdout,
                'error': result.stderr,
                'returncode': result.returncode
            }
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Command timed out'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    # ========== NETWORK RECON TOOLS ==========
    
    @staticmethod
    def nmap_scan(target, scan_type='quick'):
        """Use nmap for comprehensive scanning"""
        scans = {
            'quick': f"nmap -T4 -F {target}",
            'full': f"nmap -T4 -A -v -p- {target}",
            'stealth': f"nmap -T2 -sS -sV -O {target}",
            'udp': f"nmap -sU -T4 {target}",
            'vuln': f"nmap --script vuln {target}"
        }
        cmd = scans.get(scan_type, scans['quick'])
        return KaliTools.run_command(cmd)
    
    @staticmethod
    def masscan_scan(target, ports='1-1000'):
        """Fast port scanning with masscan"""
        cmd = f"masscan -p{ports} --rate=1000 {target}"
        return KaliTools.run_command(cmd)
    
    @staticmethod
    def dnsrecon(domain):
        """DNS reconnaissance"""
        cmd = f"dnsrecon -d {domain} -t std"
        return KaliTools.run_command(cmd)
    
    @staticmethod
    def dig_info(domain, record_type='ANY'):
        """Use dig for DNS information"""
        cmd = f"dig {domain} {record_type} +short"
        return KaliTools.run_command(cmd)
    
    @staticmethod
    def whois_lookup(target):
        """Use system whois command"""
        cmd = f"whois {target}"
        return KaliTools.run_command(cmd)
    
    # ========== WEB RECON TOOLS ==========
    
    @staticmethod
    def whatweb(url):
        """Identify web technologies"""
        cmd = f"whatweb -a 3 {url}"
        return KaliTools.run_command(cmd)
    
    @staticmethod
    def wpscan(url):
        """WordPress security scanner"""
        cmd = f"wpscan --url {url} --enumerate vp,vt,u --no-banner"
        return KaliTools.run_command(cmd, timeout=60)
    
    @staticmethod
    def nikto_scan(url):
        """Web server vulnerability scanner"""
        cmd = f"nikto -h {url} -Format txt"
        return KaliTools.run_command(cmd, timeout=45)
    
    @staticmethod
    def dirb(url):
        """Directory brute force"""
        cmd = f"dirb {url} /usr/share/dirb/wordlists/common.txt -S"
        return KaliTools.run_command(cmd, timeout=60)
    
    @staticmethod
    def gobuster(url, wordlist='/usr/share/wordlists/dirb/common.txt'):
        """Directory and file brute force"""
        cmd = f"gobuster dir -u {url} -w {wordlist} -q"
        return KaliTools.run_command(cmd, timeout=60)
    
    @staticmethod
    def sqlmap_test(url):
        """Check for SQL injection vulnerabilities"""
        cmd = f"sqlmap -u {url} --batch --crawl=2"
        return KaliTools.run_command(cmd, timeout=120)
    
    @staticmethod
    def sublist3r(domain):
        """Subdomain enumeration"""
        output_file = f"/tmp/sublist3r_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        cmd = f"sublist3r -d {domain} -o {output_file}"
        result = KaliTools.run_command(cmd, timeout=60)
        
        if result['success'] and os.path.exists(output_file):
            try:
                with open(output_file, 'r') as f:
                    subdomains = f.read().splitlines()
                os.remove(output_file)
                return subdomains
            except:
                pass
        return []
    
    # ========== PEOPLE SEARCH TOOLS ==========
    
    @staticmethod
    def theharvester(domain, source='all'):
        """Gather emails, subdomains, hosts from public sources"""
        cmd = f"theHarvester -d {domain} -b {source} -l 100 -f /tmp/harvester_{domain}"
        result = KaliTools.run_command(cmd, timeout=90)
        
        results = {'emails': [], 'hosts': [], 'ips': []}
        
        if result['success']:
            output = result['output']
            
            # Parse emails
            email_pattern = r'[\w\.-]+@[\w\.-]+\.\w+'
            emails = re.findall(email_pattern, output)
            results['emails'] = list(set(emails))
            
            # Parse hosts (simplified)
            for line in output.split('\n'):
                if ':' in line and 'Found' in line:
                    results['hosts'].append(line.strip())
        
        return results
    
    @staticmethod
    def sherlock(username):
        """Find social media accounts by username"""
        cmd = f"sherlock {username} --timeout 10 --print-found --no-color"
        return KaliTools.run_command(cmd, timeout=120)
    
    @staticmethod
    def maigret(username):
        """OSINT username search across many platforms"""
        cmd = f"maigret {username} --no-progress --timeout 10"
        return KaliTools.run_command(cmd, timeout=120)
    
    # ========== ADVANCED OSINT ==========
    
    @staticmethod
    def metagoofil(domain):
        """Metadata extraction from public documents"""
        cmd = f"metagoofil -d {domain} -l 10 -t pdf,doc,xls,ppt -o /tmp/metagoofil_{domain}"
        return KaliTools.run_command(cmd, timeout=180)
    
    @staticmethod
    def check_tool_availability():
        """Check which Kali tools are available"""
        tools = {
            'nmap': 'nmap --version',
            'masscan': 'masscan --version',
            'dnsrecon': 'dnsrecon --version',
            'whatweb': 'whatweb --version',
            'nikto': 'nikto -Version',
            'dirb': 'dirb --help',
            'gobuster': 'gobuster --help',
            'sqlmap': 'sqlmap --version',
            'wpscan': 'wpscan --version',
            'sublist3r': 'sublist3r --help',
            'theharvester': 'theHarvester --help',
            'sherlock': 'sherlock --help',
            'maigret': 'maigret --help',
            'metagoofil': 'metagoofil --help'
        }
        
        available = {}
        for tool, cmd in tools.items():
            result = KaliTools.run_command(cmd, timeout=5)
            available[tool] = result['success']
        
        return available