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

# Ensure local imports work
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(BASE_DIR)

try:
    from modules.website_intel import WebsiteRecon
    from modules.person_intel import PersonRecon
    from modules.network_intel import NetworkScanner
    from modules.social_intel import SocialMediaFinder
    from modules.advanced_intel import AdvancedOSINT
    from utils.colors import Colors
except ImportError as e:
    print(f"[!] Import error: {e}")
    print("[!] Did you install requirements and keep folder structure?")
    sys.exit(1)


class Jsosint:
    """Main jsosint engine"""

    def __init__(self):
        self.colors = Colors()
        self.results = {}
        self.banner = self._create_banner()

    def _create_banner(self):
        bold = getattr(self.colors, "BOLD", "")
        return f"""
{self.colors.CYAN}{bold}
╔══════════════════════════════════════════════════════════════════╗
║    ██╗███████╗ ██████╗ ███████╗██╗███╗   ██╗████████╗            ║
║    ██║██╔════╝██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝            ║
║    ██║███████╗██║   ██║███████╗██║██╔██╗ ██║   ██║               ║
║ ██ ██║╚════██║██║   ██║╚════██║██║██║╚██╗██║   ██║               ║
║ ╚████║███████║╚██████╔╝███████║██║██║ ╚████║   ██║               ║
║  ╚═══╝╚══════╝ ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝               ║
║                                                                  ║
║               ULTIMATE OSINT SUITE v2.0                          ║
╚══════════════════════════════════════════════════════════════════╝
{self.colors.RESET}
"""

    def print_banner(self):
        print(self.banner)

    def show_version(self):
        print(f"{self.colors.GREEN}[+]{self.colors.RESET} jsosint version: 2.0.0")

    # ===================== WEBSITE =====================

    def run_website_recon(self, target, options):
        self.print_banner()
        print(f"{self.colors.GREEN}[*]{self.colors.RESET} Website Recon: {target}")

        recon = WebsiteRecon(target)

        if options.all or options.basic:
            self._safe_run("Basic Info", "basic", recon.get_basic_info)

        if options.all or options.dns:
            self._safe_run("DNS", "dns", recon.enumerate_dns)

        if options.all or options.whois:
            if hasattr(recon, "whois_lookup"):
                self._safe_run("WHOIS", "whois", recon.whois_lookup)
            else:
                print(f"{self.colors.YELLOW}[!] WHOIS not implemented{self.colors.RESET}")

        if options.all or options.subdomains:
            self._safe_run("Subdomains", "subdomains", recon.find_subdomains)

        if options.all or options.tech:
            self._safe_run("Technologies", "technologies", recon.detect_technologies)

        if options.all or options.directories:
            self._safe_run("Directories", "directories", recon.find_directories)
        
        #harvest_emails
        if options.all or options.emails:
            self._safe_run("Emails", "emails", recon.harvest_emails)
        #scan_ports
        if options.all or options.ports:
            self._safe_run("Open Ports", "open_ports", recon.scan_ports)

        self._generate_report(target, "website", options)

    # ===================== PERSON =====================

    def run_person_recon(self, target, options):
        self.print_banner()
        recon = PersonRecon(target)

        if options.all or options.basic:
            self._safe_run("Basic Analysis", "basic", recon.basic_analysis)
        if options.all or options.emails:
            self._safe_run("Emails", "emails", recon._analyze_email)
        #_analyze_phone
        if options.all or options.phone:
            self._safe_run("Phone Numbers", "phone_numbers", recon._analyze_phone)
        #_analyze_ip
        if options.all or options.ip:
            self._safe_run("IP Addresses", "ip_addresses", recon._analyze_ip)
        #_analyze_username
        if options.all or options.username:
            self._safe_run("Usernames", "usernames", recon._analyze_username)
        #extract_possible_name
        if options.all or options.name:
            self._safe_run("Possible Names", "possible_names", recon.extract_possible_name)
        #generate_username_variations
        if options.all or options.variations:
            self._safe_run("Username Variations", "username_variations", recon.generate_username_variations)

        #email_analysis
        if options.all or options.email_analysis:
            self._safe_run("Email Analysis", "email_analysis", recon.email_analysis)
        #check_breaches
        if options.all or options.breaches:
            self._safe_run("Breaches", "breaches", recon.check_breaches)
        #public_records
        if options.all or options.public:
            self._safe_run("Public Records", "public", recon.search_public_records)
        #find_associated_accounts
        if options.all or options.accounts:
            self._safe_run("Associated Accounts", "associated_accounts", recon.find_associated_accounts)
        
        #advanced_osint
        if options.all or options.advanced:
            adv = AdvancedOSINT()
            self._safe_run("Advanced OSINT", "advanced", lambda: adv.full_osint(target))

        self._generate_report(target, "person", options)

    # ===================== NETWORK =====================

    def run_network_scan(self, target, options):
        self.print_banner()
        scanner = NetworkScanner()

        if options.all or options.ports:
            self._safe_run(
                "Ports",
                "ports",
                lambda: scanner.scan_ports(target)
            )

        if options.all or options.services:
            self._safe_run(
                "Services",
                "services",
                lambda: scanner.detect_services(target)
            )
        #_extract_html_title
        if options.all or options.title:
            self._safe_run(
                "HTML Title",
                "html_title",
                lambda: scanner._extract_html_title(target)
            )

        if options.all or options.os:
            self._safe_run(
                "OS Detection",
                "os",
                lambda: scanner.os_detection(target)
            )

        if options.all or options.vuln:
            self._safe_run(
                "Vulnerabilities",
                "vulnerabilities",
                lambda: scanner.vulnerability_scan(target)
            )
        #network_discovery
        if options.all or options.discovery:
            self._safe_run(
                "Network Discovery",
                "network_discovery",
                lambda: scanner.network_discovery(target)
            )
        #_get_mac_vendor
        if options.all or options.mac_vendor:
            self._safe_run(
                "MAC Vendor",
                "mac_vendor",
                lambda: scanner._get_mac_vendor(target)
            )
        #traceroute
        if options.all or options.traceroute:
            self._safe_run(
                "Traceroute",
                "traceroute",
                lambda: scanner.traceroute(target)
            )
        #dns_enumeration
        if options.all or options.dns_enum:
            self._safe_run(
                "DNS Enumeration",
                "dns_enumeration",
                lambda: scanner.dns_enumeration(target)
            )
            #

        self._generate_report(target, "network", options)

    # ===================== HELPERS =====================

    def _safe_run(self, label, key, func):
        try:
            print(f"{self.colors.CYAN}[*]{self.colors.RESET} {label}")
            self.results[key] = func()
        except Exception as e:
            print(f"{self.colors.RED}[-]{self.colors.RESET} {label} failed: {e}")

    def _generate_report(self, target, scan_type, options):
        if not self.results:
            print(f"{self.colors.YELLOW}[!] No results{self.colors.RESET}")
            return

        self.results["metadata"] = {
            "target": target,
            "scan_type": scan_type,
            "timestamp": datetime.now().isoformat(),
            "tool": "jsosint v2.0",
        }

        print(f"{self.colors.GREEN}[+] Scan completed{self.colors.RESET}")
        self._display_summary(scan_type)

        if options.output:
            filename = options.output
            if not filename.endswith(".json"):
                filename += ".json"
            with open(filename, "w") as f:
                json.dump(self.results, f, indent=2)
            print(f"{self.colors.GREEN}[+] Saved: {filename}{self.colors.RESET}")

    def _display_summary(self, scan_type):
        """Display scan summary"""
        summary = []
            # ========== WEBSITE SUMMARY ==========
        if scan_type == "website":
            if "basic" in self.results:
                ip = self.results["basic"].get("ip_address")
                if ip:
                    summary.append(f"IP: {ip}")

            if "dns" in self.results:
                a_records = self.results["dns"].get("A")
                if isinstance(a_records, list):
                    summary.append(f"A Records: {len(a_records)}")
            
            if "technologies" in self.results:
                techs = self.results["technologies"]
                if isinstance(techs, list):
                    summary.append(f"Technologies: {len(techs)}")

            if "subdomains" in self.results:
                subs = self.results["subdomains"]
                if isinstance(subs, list):
                    summary.append(f"Subdomains: {len(subs)}")
            
            if "directories" in self.results:
                dirs = self.results["directories"]
                if isinstance(dirs, list):
                    summary.append(f"Directories Found: {len(dirs)}")
            
            if "emails" in self.results:
                emails = self.results["emails"]
                if isinstance(emails, list):
                    summary.append(f"Emails Found: {len(emails)}")

            if "social_media" in self.results:
                found = sum(
                    1 for v in self.results["social_media"].values()
                    if isinstance(v, dict) and v.get("found")
                )
                summary.append(f"Social Media: {found} platforms")

        # ========== PERSON SUMMARY ==========
        elif scan_type == "person":

            # BASIC
            if "basic" in self.results and isinstance(self.results["basic"], dict):
                name = self.results["basic"].get("name")
                if name:
                    summary.append(f"Name: {name}")

            # EMAILS
            if "emails" in self.results and isinstance(self.results["emails"], dict):
                if self.results["emails"].get("found"):
                    summary.append("Emails: Yes")

            # PHONE
            if "phone_numbers" in self.results and isinstance(self.results["phone_numbers"], dict):
                if self.results["phone_numbers"].get("found"):
                    summary.append("Phone Numbers: Yes")

            # IP
            if "ip_addresses" in self.results and isinstance(self.results["ip_addresses"], dict):
                if self.results["ip_addresses"].get("found"):
                    summary.append("IP Address Data: Yes")

            # USERNAMES
            if "usernames" in self.results and isinstance(self.results["usernames"], dict):
                if self.results["usernames"].get("found"):
                    summary.append("Usernames: Yes")

            # POSSIBLE NAMES
            if "possible_names" in self.results and isinstance(self.results["possible_names"], list):
                summary.append(f"Possible Names Found: {len(self.results['possible_names'])}")

            # USERNAME VARIATIONS
            if "username_variations" in self.results and isinstance(self.results["username_variations"], list):
                summary.append(f"Username Variations Found: {len(self.results['username_variations'])}")

            # EMAIL ANALYSIS
            if "email_analysis" in self.results and isinstance(self.results["email_analysis"], dict):
                a = self.results["email_analysis"]
                summary.append(f"Valid Emails: {a.get('valid', 0)}")
                summary.append(f"Invalid Emails: {a.get('invalid', 0)}")

            # PUBLIC RECORDS
            if "public" in self.results and isinstance(self.results["public"], dict):
                if self.results["public"].get("found"):
                    summary.append("Public Records: Yes")

            # BREACHES
            if "breaches" in self.results and isinstance(self.results["breaches"], dict):
                breaches = self.results["breaches"].get("breaches", [])
                summary.append(f"Breaches Found: {len(breaches)}")

            # SOCIAL MEDIA (BASIC + ADVANCED)
            social_found = 0

            if "social_media" in self.results and isinstance(self.results["social_media"], dict):
                for v in self.results["social_media"].values():
                    if isinstance(v, dict) and v.get("found"):
                        social_found += 1

            if "advanced" in self.results:
                adv = self.results["advanced"]
                if isinstance(adv, dict) and "social_media" in adv:
                    for v in adv["social_media"].values():
                        if isinstance(v, dict) and v.get("found"):
                            social_found += 1

            summary.append(f"Social Platforms Found: {social_found}")

            # ASSOCIATED ACCOUNTS
            if "associated_accounts" in self.results:
                found = 0
                acc = self.results["associated_accounts"]

                if isinstance(acc, dict):
                    for v in acc.values():
                        if isinstance(v, dict) and v.get("found"):
                            found += 1
                        elif isinstance(v, list):
                            found += sum(1 for i in v if isinstance(i, dict) and i.get("found"))

                summary.append(f"Associated Accounts Found: {found}")

        # ========== NETWORK SUMMARY ==========
        elif scan_type == "network":
            if "scan_ports" in self.results:
                ports = self.results["ports"]
                if isinstance(ports, list):
                    summary.append(
                        "Open Ports: Yes" if ports else "Open Ports: No"
                    )

            if "detect_services" in self.results:
                services = self.results["services"]
                if isinstance(services, list):
                    summary.append(f"Services Detected: {len(services)}")
            if "_extract_html_title" in self.results:
                title = self.results["html_title"]
                if title:
                    summary.append(f"HTML Title: {title}")
            
            if "os_detection" in self.results:
                os_data = self.results["os"]
                if os_data:
                    summary.append("OS Fingerprint: Available")

            #vulnerability_scan
            if "vulnerability_scan" in self.results:
                vulns = self.results["vulnerabilities"]
                if isinstance(vulns, list):
                    summary.append(f"Vulnerabilities Found: {len(vulns)}")
            #network_discovery
            if "network_discovery" in self.results:
                hosts = self.results["network_discovery"]
                if isinstance(hosts, list):
                    summary.append(f"Discovered Hosts: {len(hosts)}")
            #traceroute
            if "traceroute" in self.results:
                route = self.results["traceroute"]
                if isinstance(route, list):
                    summary.append(f"Traceroute Hops: {len(route)}")
            #dns_enumeration
            if "dns_enumeration" in self.results:
                records = self.results["dns_enumeration"]
                if isinstance(records, dict):
                    summary.append(f"DNS Records Found: {len(records)}")
            #mac_vendor
            if "mac_vendor" in self.results:
                vendor = self.results["mac_vendor"]
                if vendor:
                    summary.append(f"MAC Vendor: {vendor}")
            #_get_mac_vendor
            if "_get_mac_vendor" in self.results:
                vendor = self.results["mac_vendor"]
                if vendor:
                    summary.append(f"MAC Vendor: {vendor}")

        if summary:
            print(f"\n{self.colors.YELLOW}[📊]{self.colors.RESET} Summary:")
            for item in summary:
                print(f"   • {item}")


# ===================== ENTRY POINT =====================

def main():
    signal.signal(signal.SIGINT, lambda *_: sys.exit(0))

    parser = argparse.ArgumentParser(
        description="jsosint - Ultimate OSINT Suite v2.0"
    )

    parser.add_argument("-v", "--version", action="store_true")

    sub = parser.add_subparsers(dest="command")

    web = sub.add_parser("website", aliases=["w"])
    web.add_argument("target")
    web.add_argument("--all", action="store_true")
    web.add_argument("--basic", action="store_true")
    web.add_argument("--dns", action="store_true")
    web.add_argument("--whois", action="store_true")
    web.add_argument("--subdomains", action="store_true")
    web.add_argument("--tech", action="store_true")
    web.add_argument("--directories", action="store_true")
    web.add_argument("-o", "--output")

    person = sub.add_parser("person", aliases=["p"])
    person.add_argument("target")
    person.add_argument("--all", action="store_true")
    person.add_argument("--basic", action="store_true")
    person.add_argument("--social", action="store_true")
    person.add_argument("--deep", action="store_true")
    person.add_argument("--emails", action="store_true")
    person.add_argument("--breaches", action="store_true")
    person.add_argument("--public", action="store_true")
    person.add_argument("--advanced", action="store_true")
    person.add_argument("-o", "--output")

    net = sub.add_parser("network", aliases=["n"])
    net.add_argument("target")
    net.add_argument("--all", action="store_true")
    net.add_argument("--ports", action="store_true")
    net.add_argument("--services", action="store_true")
    net.add_argument("--os", action="store_true")
    net.add_argument("--vuln", action="store_true")
    net.add_argument("-o", "--output")

    args = parser.parse_args()
    tool = Jsosint()

    if args.version:
        tool.show_version()
        return

    if not args.command:
        tool.print_banner()
        parser.print_help()
        return

    if args.command in ("website", "w"):
        tool.run_website_recon(args.target, args)
    elif args.command in ("person", "p"):
        tool.run_person_recon(args.target, args)
    elif args.command in ("network", "n"):
        tool.run_network_scan(args.target, args)


if __name__ == "__main__":
    main()
