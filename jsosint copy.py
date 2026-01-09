#!/usr/bin/env python3
"""
jsosint - Ultimate OSINT Suite v2.0
Complete reconnaissance toolkit combining all OSINT methods
"""

import argparse
import json
import sys
import os
from datetime import datetime
import signal

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from modules.website_intel import WebsiteRecon
    from modules.person_intel import PersonRecon
    from modules.network_intel import NetworkScanner
    from modules.social_intel import SocialMediaFinder
    from modules.advanced_intel import AdvancedOSINT
    from utils.colors import Colors
    # Note: ReportGenerator and InputValidator might not exist yet
    # from utils.reporter import ReportGenerator
    # from utils.validator import InputValidator
except ImportError as e:
    print(f"Error importing modules: {e}")
    print("Please run: pip install -r requirements.txt")
    sys.exit(1)

class Jsosint:
    """Main jsosint class - Complete OSINT Suite"""
    
    def __init__(self):
            self.colors = Colors()
            self.banner = self._create_banner()
            self.results = {}
            
    def _create_banner(self):
            """Create tool banner"""
            # Try to use BOLD if it exists, otherwise use empty string
            bold_attr = getattr(self.colors, 'BOLD', '')
            return f"""
{self.colors.CYAN}{bold_attr}
╔══════════════════════════════════════════════════════════════════╗
║    ██╗███████╗ ██████╗ ███████╗██╗███╗   ██╗████████╗            ║
║    ██║██╔════╝██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝            ║
║    ██║███████╗██║   ██║███████╗██║██╔██╗ ██║   ██║               ║
║ ██ ██║╚════██║██║   ██║╚════██║██║██║╚██╗██║   ██║               ║
║ ╚████║███████║╚██████╔╝███████║██║██║ ╚████║   ██║               ║
║  ╚═══╝╚══════╝ ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝               ║
║                                                                  ║
║               ULTIMATE OSINT SUITE v2.0                          ║
║          Complete Reconnaissance Toolkit                         ║
╚══════════════════════════════════════════════════════════════════╝
{self.colors.RESET}
"""
    
    def print_banner(self):
        """Print the banner"""
        print(self.banner)
    
    def run_website_recon(self, target, options):
        """Complete website reconnaissance with error resilience"""
        self.print_banner()
        print(f"{self.colors.GREEN}[*]{self.colors.RESET} Starting Website Reconnaissance")
        print(f"{self.colors.GREEN}[*]{self.colors.RESET} Target: {target}")
        print(f"{self.colors.GREEN}[*]{self.colors.RESET} Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        recon = WebsiteRecon(target)

        # Module 1: Basic Info
        try:
            print(f"\n{self.colors.CYAN}[1] Basic Information Gathering{self.colors.RESET}")
            self.results['basic'] = recon.get_basic_info()
        except Exception as e:
            print(f"  {self.colors.RED}[-] Basic Info Failed: {e}{self.colors.RESET}")

        # Module 2: DNS
        try:
            print(f"\n{self.colors.CYAN}[2] DNS Enumeration{self.colors.RESET}")
            self.results['dns'] = recon.enumerate_dns()
        except Exception as e:
            print(f"  {self.colors.RED}[-] DNS Failed: {e}{self.colors.RESET}")

        # Module 3: WHOIS
        try:
            print(f"\n{self.colors.CYAN}[3] WHOIS Lookup{self.colors.RESET}")
            # Check if method exists before calling to prevent crash
            if hasattr(recon, 'whois_lookup'):
                self.results['whois'] = recon.whois_lookup()
            else:
                print(f"  {self.colors.YELLOW}[!] WHOIS module logic missing in website_intel.py{self.colors.RESET}")
        except Exception as e:
            print(f"  {self.colors.RED}[-] WHOIS Failed: {e}{self.colors.RESET}")

        # Module 4: Subdomains
        try:
            print(f"\n{self.colors.CYAN}[4] Subdomain Discovery{self.colors.RESET}")
            self.results['subdomains'] = recon.find_subdomains()
        except Exception as e:
            print(f"  {self.colors.RED}[-] Subdomain Discovery Failed: {e}{self.colors.RESET}")

        # Module 5: Tech Detection
        try:
            print(f"\n{self.colors.CYAN}[5] Technology Detection{self.colors.RESET}")
            self.results['technologies'] = recon.detect_technologies()
        except Exception as e:
            print(f"  {self.colors.RED}[-] Tech Detection Failed: {e}{self.colors.RESET}")

        try:
            print(f"\n{self.colors.CYAN}[10] Directory Enumeration{self.colors.RESET}")
            self.results['directories'] = recon.enumerate_directories()
        except Exception as e:
            print(f"  {self.colors.RED}[-] Directory Enumeration Failed: {e}{self.colors.RESET}")


        # Final Report
        self._generate_report(target, 'website', options)
    
    def run_person_recon(self, target, options):
        """Complete person reconnaissance"""
        self.print_banner()
        print(f"{self.colors.GREEN}[*]{self.colors.RESET} Starting Person Reconnaissance")
        print(f"{self.colors.GREEN}[*]{self.colors.RESET} Target: {target}")
        print(f"{self.colors.GREEN}[*]{self.colors.RESET} Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{self.colors.BLUE}{'='*70}{self.colors.RESET}")
        
        try:
            recon = PersonRecon(target)
            
            # Run selected modules
            if options.all or options.basic:
                print(f"\n{self.colors.CYAN}[1]{self.colors.RESET} Basic Analysis")
                self.results['basic'] = recon.basic_analysis()
            
            if options.all or options.social:
                print(f"\n{self.colors.CYAN}[2]{self.colors.RESET} Social Media Search")
                finder = SocialMediaFinder()
                self.results['social_media'] = finder.search_all_platforms(
                    recon.username, 
                    deep_search=options.deep
                )
            
            if options.all or options.emails:
                print(f"\n{self.colors.CYAN}[3]{self.colors.RESET} Email Analysis")
                self.results['email_analysis'] = recon.email_analysis()
            
            if options.all or options.breaches:
                print(f"\n{self.colors.CYAN}[4]{self.colors.RESET} Data Breach Check")
                self.results['breaches'] = recon.check_breaches()
            
            if options.all or options.public:
                print(f"\n{self.colors.CYAN}[5]{self.colors.RESET} Public Records")
                self.results['public_records'] = recon.search_public_records()
            
            if options.all or options.advanced:
                print(f"\n{self.colors.CYAN}[6]{self.colors.RESET} Advanced OSINT")
                advanced = AdvancedOSINT()
                self.results['advanced'] = advanced.full_osint(target)
            
            # Generate report
            self._generate_report(target, 'person', options)
            
        except KeyboardInterrupt:
            print(f"\n{self.colors.RED}[!]{self.colors.RESET} Scan interrupted by user")
        except Exception as e:
            print(f"\n{self.colors.RED}[!]{self.colors.RESET} Error: {e}")
    
    def run_network_scan(self, target, options):
        """Network scanning and enumeration"""
        self.print_banner()
        print(f"{self.colors.GREEN}[*]{self.colors.RESET} Starting Network Scan")
        print(f"{self.colors.GREEN}[*]{self.colors.RESET} Target: {target}")
        print(f"{self.colors.BLUE}{'='*70}{self.colors.RESET}")
        
        try:
            scanner = NetworkScanner()
            
            if options.all or options.ports:
                print(f"\n{self.colors.CYAN}[1]{self.colors.RESET} Port Scanning")
                self.results['ports'] = scanner.scan_ports(target, 
                    ports=options.ports_range, 
                    timing=options.timing
                )
            
            if options.all or options.services:
                print(f"\n{self.colors.CYAN}[2]{self.colors.RESET} Service Detection")
                self.results['services'] = scanner.detect_services(target)
            
            if options.all or options.os:
                print(f"\n{self.colors.CYAN}[3]{self.colors.RESET} OS Detection")
                self.results['os_info'] = scanner.os_detection(target)
            
            if options.all or options.vuln:
                print(f"\n{self.colors.CYAN}[4]{self.colors.RESET} Vulnerability Scan")
                self.results['vulnerabilities'] = scanner.vulnerability_scan(target)
            
            # Generate report
            self._generate_report(target, 'network', options)
            
        except KeyboardInterrupt:
            print(f"\n{self.colors.RED}[!]{self.colors.RESET} Scan interrupted by user")
        except Exception as e:
            print(f"\n{self.colors.RED}[!]{self.colors.RESET} Error: {e}")
    
    def _generate_report(self, target, scan_type, options):
        """Generate and save report"""
        if not self.results:
            print(f"\n{self.colors.YELLOW}[!]{self.colors.RESET} No results to report")
            return
        
        # Add metadata
        self.results['metadata'] = {
            'target': target,
            'scan_type': scan_type,
            'timestamp': datetime.now().isoformat(),
            'tool': 'jsosint v2.0'
        }
        
        # Display summary
        print(f"\n{self.colors.GREEN}{'='*70}{self.colors.RESET}")
        print(f"{self.colors.GREEN}[+]{self.colors.RESET} SCAN COMPLETED SUCCESSFULLY")
        print(f"{self.colors.GREEN}{'='*70}{self.colors.RESET}")
        
        # Show summary
        self._display_summary()
        
        # Save to file if requested
        if options.output:
            try:
                # Simple file saving if ReportGenerator doesn't exist
                filename = options.output
                if not filename.endswith('.json'):
                    filename += '.json'
                with open(filename, 'w') as f:
                    json.dump(self.results, f, indent=2)
                print(f"\n{self.colors.GREEN}[+]{self.colors.RESET} Results saved to: {filename}")
            except Exception as e:
                print(f"\n{self.colors.RED}[!]{self.colors.RESET} Failed to save results: {e}")
        
        # Show next steps
        print(f"\n{self.colors.CYAN}[*]{self.colors.RESET} Next steps:")
        print(f"   • Review the results above")
        print(f"   • Use --output to save detailed results")
        print(f"   • Check generated files for further analysis")
    
    def _display_summary(self):
        """Display scan summary"""
        summary = []
        
        if 'basic' in self.results:
            if 'ip_address' in self.results['basic']:
                summary.append(f"IP: {self.results['basic']['ip_address']}")
        
        if 'dns' in self.results:
            if 'A' in self.results['dns']:
                summary.append(f"A Records: {len(self.results['dns']['A'])}")
        
        if 'subdomains' in self.results:
            res = self.results['subdomains']
            # If it's a list, just get the length. If it's a dict, use the old way.
            total_subs = len(res) if isinstance(res, list) else sum(len(v) for v in res.values() if isinstance(v, list))
            summary.append(f"Subdomains: {total_subs}")
        
        if 'social_media' in self.results:
            found = sum(1 for v in self.results['social_media'].values() if v.get('found'))
            summary.append(f"Social Media: {found} platforms")
        
        if 'ports' in self.results:
            if 'open_ports' in self.results['ports']:
                summary.append(f"Open Ports: {len(self.results['ports']['open_ports'])}")
        
        if summary:
            print(f"\n{self.colors.YELLOW}[📊]{self.colors.RESET} Summary: {', '.join(summary)}")

    # --- Version Check ---
    def show_version(self):
        """Display the tool version"""
        print(f"{self.colors.GREEN}[+]{self.colors.RESET} jsosint version: 2.0.0")

    def main():
        """Main entry point"""
        # Handle Ctrl+C
        signal.signal(signal.SIGINT, lambda x, y: sys.exit(0))
        
        parser = argparse.ArgumentParser(
            description='jsosint - Ultimate OSINT Suite v2.0',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""

            EXAMPLES:
            # Complete website reconnaissance
            python3 jsosint.py website example.com --all
            
            # Specific website modules
            python3 jsosint.py website example.com --dns --whois --subdomains --ports
            
            # Complete person reconnaissance
            python3 jsosint.py person username --all --deep
            
            # Network scan
            python3 jsosint.py network 192.168.1.1 --ports --services --vuln
            
            # Save results
            python3 jsosint.py website example.com --all -o results.json
            python3 jsosint.py website example.com --all -o report.html --format html

            MODULES:
            Website: --basic --dns --whois --subdomains --tech --directories --emails --ports --vuln --history
            Person:  --basic --social --emails --breaches --public --advanced
            Network: --ports --services --os --vuln
                    """
        )
        
        # Main command
        parser.add_argument('--version', '-v', action='store_true', help='Show tool version')
        subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
        # WEBSITE COMMAND (Short 'w')
        website_parser = subparsers.add_parser('website', aliases=['w'], help='Website reconnaissance')
        website_parser.add_argument('target', help='Domain or IP address')
        website_parser.add_argument('--all', action='store_true', help='Run all modules')
        website_parser.add_argument('--basic', action='store_true', help='Basic information')
        website_parser.add_argument('--dns', action='store_true', help='DNS enumeration')
        website_parser.add_argument('--whois', action='store_true', help='WHOIS lookup')
        website_parser.add_argument('--subdomains', action='store_true', help='Find subdomains')
        website_parser.add_argument('--tech', action='store_true', help='Technology detection')
        website_parser.add_argument('--directories', action='store_true', help='Directory enumeration')
        website_parser.add_argument('--emails', action='store_true', help='Email harvesting')
        website_parser.add_argument('--ports', action='store_true', help='Port scanning')
        website_parser.add_argument('--vuln', action='store_true', help='Vulnerability scan')
        website_parser.add_argument('--history', action='store_true', help='Historical data')
        
        # PERSON COMMAND (Short 'p')
        person_parser = subparsers.add_parser('person', aliases=['p'], help='Person reconnaissance')
        person_parser.add_argument('target', help='Username, email, or phone')
        person_parser.add_argument('--all', action='store_true', help='Run all modules')
        person_parser.add_argument('--basic', action='store_true', help='Basic analysis')
        person_parser.add_argument('--social', action='store_true', help='Social media search')
        person_parser.add_argument('--deep', action='store_true', help='Deep social media search')
        person_parser.add_argument('--emails', action='store_true', help='Email analysis')
        person_parser.add_argument('--breaches', action='store_true', help='Data breach check')
        person_parser.add_argument('--public', action='store_true', help='Public records')
        person_parser.add_argument('--advanced', action='store_true', help='Advanced OSINT')
        
        # Network command (Short 'n')
        network_parser = subparsers.add_parser('network', aliases=['n'], help='Network scanning')
        network_parser.add_argument('target', help='IP address or network range')
        network_parser.add_argument('--all', action='store_true', help='Run all modules')
        
        # Common options
        for sub_p in [website_parser, person_parser, network_parser]:
            sub_p.add_argument('-o', '--output', help='Output file')
            sub_p.add_argument('--format', choices=['json', 'html', 'txt', 'csv'], default='json')
        
        args = parser.parse_args()
        tool = Jsosint()

        # VERSION CHECK LOGIC
        if args.version:
            tool.show_version()
            return

        if not args.command:
            tool.print_banner()
            parser.print_help()
            return

        try:
            # SHORT COMMAND LOGIC
            if args.command in ['website', 'w']:
                tool.run_website_recon(args.target, args)
            elif args.command in ['person', 'p']:
                tool.run_person_recon(args.target, args)
            elif args.command in ['network', 'n']:
                tool.run_network_scan(args.target, args)
        
        except Exception as e:
            print(f"\n{Colors().RED}[!]{Colors().RESET} Fatal error: {e}")
            sys.exit(1)

    if __name__ == '__main__':
        main()