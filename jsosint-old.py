#!/usr/bin/env python3
"""
jsosint - Ultimate OSINT & Pentest Toolkit for Kali Linux
Combines all Kali tools for complete reconnaissance
"""

import argparse
import json
import sys
import os
from datetime import datetime

# Import internal modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from modules.website_intel import WebsiteIntel
from modules.person_intel import PersonIntel
from utils.colors import Colors
from utils.kali_tools import KaliTools

class jsosint:
    """Main jsosint tool class"""
    
    def __init__(self):
        self.colors = Colors()
        self.banner = f"""
{self.colors.CYAN}
╔══════════════════════════════════════════════════════════╗
║     ██╗███████╗ ██████╗ ███████╗██╗███╗   ██╗████████╗   ║
║     ██║██╔════╝██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝   ║
║     ██║███████╗██║   ██║███████╗██║██╔██╗ ██║   ██║      ║
║  ██ ██║╚════██║██║   ██║╚════██║██║██║╚██╗██║   ██║      ║
║  ╚████║███████║╚██████╔╝███████║██║██║ ╚████║   ██║      ║
║   ╚═══╝╚══════╝ ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝      ║
║                                                          ║
║           ULTIMATE OSINT TOOLKIT FOR KALI LINUX          ║
║      Combines all Kali tools for complete reconnaissance ║
╚══════════════════════════════════════════════════════════╝
{self.colors.RESET}
"""
    
    def print_banner(self):
        """Print the tool banner"""
        print(self.banner)
    
    def website_recon(self, target, options):
        """Complete website reconnaissance"""
        self.print_banner()
        print(f"{self.colors.GREEN}[*]{self.colors.RESET} TARGET: {target}")
        print(f"{self.colors.GREEN}[*]{self.colors.RESET} START TIME: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{self.colors.BLUE}{'='*60}{self.colors.RESET}")
        
        website = WebsiteIntel(target)
        results = website.full_recon()
        
        # Print summary
        print(f"\n{self.colors.BLUE}{'='*60}{self.colors.RESET}")
        print(f"{self.colors.GREEN}[+]{self.colors.RESET} RECONNAISSANCE COMPLETE")
        print(f"{self.colors.BLUE}{'='*60}{self.colors.RESET}")
        
        self.print_website_summary(results)
        
        # Save results
        if options.output:
            self.save_results(results, options.output)
        
        return results
    
    def person_recon(self, target, options):
        """Complete person reconnaissance"""
        self.print_banner()
        print(f"{self.colors.GREEN}[*]{self.colors.RESET} TARGET: {target}")
        print(f"{self.colors.GREEN}[*]{self.colors.RESET} START TIME: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{self.colors.BLUE}{'='*60}{self.colors.RESET}")
        
        person = PersonIntel(target)
        results = person.full_recon()
        
        # Print summary
        print(f"\n{self.colors.BLUE}{'='*60}{self.colors.RESET}")
        print(f"{self.colors.GREEN}[+]{self.colors.RESET} PERSON RECONNAISSANCE COMPLETE")
        print(f"{self.colors.BLUE}{'='*60}{self.colors.RESET}")
        
        self.print_person_summary(results)
        
        # Save results
        if options.output:
            self.save_results(results, options.output)
        
        return results
    
    def quick_scan(self, target, options):
        """Quick scan to determine target type and scan"""
        self.print_banner()
        print(f"{self.colors.GREEN}[*]{self.colors.RESET} Quick scanning: {target}")
        
        # Determine target type
        target_type = self.detect_target_type(target)
        print(f"{self.colors.GREEN}[+]{self.colors.RESET} Detected target type: {target_type}")
        
        if target_type == 'website':
            return self.website_recon(target, options)
        else:
            return self.person_recon(target, options)
    
    def detect_target_type(self, target):
        """Detect what type of target this is"""
        import re
        import socket
        
        # Check if it's an IP address
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if re.match(ip_pattern, target):
            return 'website'  # IP can be treated as website
        
        # Check if it's a domain (has dot and no spaces)
        if '.' in target and ' ' not in target:
            # Check if it resolves
            try:
                socket.gethostbyname(target)
                return 'website'
            except:
                pass
        
        # Check if it's an email
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if re.match(email_pattern, target):
            return 'person'
        
        # Otherwise assume it's a username
        return 'person'
    
    def print_website_summary(self, results):
        """Print website scan summary"""
        print(f"\n{self.colors.GREEN}[+]{self.colors.RESET} Basic Information:")
        if 'basic' in results:
            basic = results['basic']
            for key, value in basic.items():
                if value and key not in ['error']:
                    print(f"    {self.colors.YELLOW}{key}:{self.colors.RESET} {value}")
        
        print(f"\n{self.colors.GREEN}[+]{self.colors.RESET} DNS Records:")
        if 'dns' in results and 'A' in results['dns'] and results['dns']['A']:
            print(f"    {self.colors.YELLOW}A Records:{self.colors.RESET} {', '.join(results['dns']['A'])}")
        
        print(f"\n{self.colors.GREEN}[+]{self.colors.RESET} Subdomains Found:")
        subdomain_count = 0
        if 'subdomains' in results:
            for method, subs in results['subdomains'].items():
                if isinstance(subs, list) and subs:
                    subdomain_count += len(subs)
                    print(f"    {self.colors.YELLOW}{method}:{self.colors.RESET} {len(subs)} subdomains")
        
        print(f"\n{self.colors.GREEN}[+]{self.colors.RESET} Technologies Detected:")
        if 'technologies' in results and 'manual' in results['technologies']:
            tech = results['technologies']['manual']
            for key, value in tech.items():
                if value:
                    print(f"    {self.colors.YELLOW}{key}:{self.colors.RESET} {value}")
        
        print(f"\n{self.colors.GREEN}[+]{self.colors.RESET} Open Ports:")
        if 'ports' in results and 'open_ports' in results['ports']:
            ports = results['ports']['open_ports']
            if ports:
                print(f"    {self.colors.YELLOW}Ports:{self.colors.RESET} {', '.join(map(str, ports))}")
            else:
                print(f"    {self.colors.RED}No common ports open{self.colors.RESET}")
        
        print(f"\n{self.colors.GREEN}[+]{self.colors.RESET} Summary:")
        print(f"    {self.colors.YELLOW}Subdomains:{self.colors.RESET} {subdomain_count}")
        tech_count = len(results.get('technologies', {}).get('manual', {})) if results.get('technologies', {}).get('manual') else 0
        print(f"    {self.colors.YELLOW}Technologies:{self.colors.RESET} {tech_count}")
        historical_count = len(results.get('historical', {}).get('wayback', [])) if results.get('historical', {}).get('wayback') else 0
        print(f"    {self.colors.YELLOW}Historical Snapshots:{self.colors.RESET} {historical_count}")
    
    def print_person_summary(self, results):
        """Print person scan summary"""
        print(f"\n{self.colors.GREEN}[+]{self.colors.RESET} Target Type: {results.get('type', 'Unknown')}")
        
        if results.get('type') == 'email' and 'email_recon' in results:
            print(f"\n{self.colors.GREEN}[+]{self.colors.RESET} Email Analysis:")
            email_info = results['email_recon']
            if email_info.get('valid_format'):
                print(f"    {self.colors.GREEN}✓ Valid format{self.colors.RESET}")
                print(f"    {self.colors.YELLOW}Username:{self.colors.RESET} {email_info.get('username')}")
                print(f"    {self.colors.YELLOW}Domain:{self.colors.RESET} {email_info.get('domain')}")
                domain_status = '✓' if email_info.get('domain_has_website') else '✗'
                print(f"    {self.colors.YELLOW}Domain has website:{self.colors.RESET} {domain_status}")
        
        print(f"\n{self.colors.GREEN}[+]{self.colors.RESET} Social Media Presence:")
        social = results.get('social_media', {})
        found_count = sum(1 for platform in social.values() if isinstance(platform, dict) and platform.get('found'))
        print(f"    {self.colors.YELLOW}Found on:{self.colors.RESET} {found_count} platforms")
        
        for platform, data in social.items():
            if isinstance(data, dict) and data.get('found'):
                print(f"    {self.colors.GREEN}✓ {platform}:{self.colors.RESET} {data.get('url')}")
        
        print(f"\n{self.colors.GREEN}[+]{self.colors.RESET} Public Record Searches:")
        records = results.get('public_records', {}).get('search_links', [])
        for link in records[:3]:  # Show first 3
            print(f"    {self.colors.BLUE}{link}{self.colors.RESET}")
        
        if 'username_recon' in results and 'username_variations' in results['username_recon']:
            print(f"\n{self.colors.GREEN}[+]{self.colors.RESET} Username Variations:")
            variations = results['username_recon']['username_variations'][:5]  # First 5
            for var in variations:
                print(f"    {self.colors.YELLOW}{var}{self.colors.RESET}")
    
    def save_results(self, results, filename):
        """Save results to JSON file"""
        try:
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            print(f"\n{self.colors.GREEN}[+]{self.colors.RESET} Results saved to: {filename}")
        except Exception as e:
            print(f"\n{self.colors.RED}[!]{self.colors.RESET} Failed to save results: {e}")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='jsosint - Ultimate OSINT Toolkit for Kali Linux',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Complete website reconnaissance
  jsosint website example.com
  
  # Person reconnaissance (email, username, phone)
  jsosint person john.doe@gmail.com
  jsosint person johndoe
  jsosint person "+1234567890"
  
  # Save results to file
  jsosint website example.com -o results.json
  
  # Quick mode (auto-detect)
  jsosint quick target

Features:
  • Uses Kali Linux tools: nmap, dirb, nikto, sqlmap, wpscan, etc.
  • No API keys required for basic functionality
  • Combines multiple reconnaissance methods
  • Saves results in JSON format for further analysis
        """
    )
    
    parser.add_argument('mode', choices=['website', 'person', 'quick'], 
                       help='Reconnaissance mode')
    parser.add_argument('target', help='Target to investigate')
    parser.add_argument('-o', '--output', help='Save results to JSON file')
    parser.add_argument('-v', '--verbose', action='store_true', 
                       help='Show detailed output')
    
    args = parser.parse_args()
    
    tool = jsosint()
    
    try:
        if args.mode == 'website':
            tool.website_recon(args.target, args)
        elif args.mode == 'person':
            tool.person_recon(args.target, args)
        elif args.mode == 'quick':
            tool.quick_scan(args.target, args)
    
    except KeyboardInterrupt:
        print(f"\n{Colors().RED}[!]{Colors().RESET} Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors().RED}[!]{Colors().RESET} Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()