#!/usr/bin/env python3
"""
jsosint - ULTIMATE OSINT SUITE
Complete reconnaissance toolkit combining all OSINT methods
"""

import argparse
import json
import sys
import os
from datetime import datetime
import signal
import shutil
import subprocess

# Ensure local imports work
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(BASE_DIR)

VERSION_FILE = os.path.join(BASE_DIR, "version.txt")

def get_version():
    try:
        with open(VERSION_FILE, "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        return "0.0.0"
JSOSINT_VERSION = get_version()


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
║ ULTIMATE OSINT SUITE jsosint v{JSOSINT_VERSION} code by jahid          ║
╚══════════════════════════════════════════════════════════════════╝
{self.colors.RESET}
"""

    def print_banner(self):
        print(self.banner)
    
    def show_version(self):
        print(f"{self.colors.GREEN}[+]{self.colors.RESET} jsosint version: {JSOSINT_VERSION}")

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

        if options.all:
            self._display_summary("website")
        self._generate_website_report(target, options)

    # ===================== PERSON =====================

    def run_person_recon(self, target, options):
        self.print_banner()
        recon = PersonRecon(target)

        if options.all or options.basic:
            self._safe_run("Basic Analysis", "basic", recon.basic_analysis)

        if options.all or options.username:
            self._safe_run("Username Analysis", "username", recon._analyze_username)

        if options.all or options.email:
            self._safe_run("Email Analysis", "email", recon.email_analysis)

        if options.all or options.phone:
            self._safe_run("Phone Analysis", "phone", recon._analyze_phone)

        if options.all or options.ip:
            self._safe_run("IP Analysis", "ip", recon._analyze_ip)

        if options.possible:
            self._safe_run(
                "Possible Names & Username Variations",
                "possible_names_and_variations",
                recon.extract_possible_and_variations
            )

        if options.all or options.breaches:
            self._safe_run("Breaches", "breaches", recon.check_breaches)

        if options.all or options.public:
            self._safe_run("Public Records", "public", recon.search_public_records)

        # ===================== SOCIAL MEDIA =====================
        if options.all or options.social:
            self._safe_run(
                "Social Media Finder",
                "social_media",
                recon.SocialMediaScan
            )

        # ===================== DOMAIN / URL =====================(need update)
        if options.all or options.domain_url:
            self._safe_run(
                "Domain/URL Analysis",
                "domain_url_analysis",
                recon.domain_url_analysis
            )
        
        self._generate_person_report(target, options)

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
        
        self._generate_network_report(target, options)

    # ===================== HELPERS =====================
    def _safe_run(self, label, key, func):
        try:
            print(f"{self.colors.CYAN}[*]{self.colors.RESET} {label}")
            self.results[key] = func()
        except Exception as e:
            print(f"{self.colors.RED}[-]{self.colors.RESET} {label} failed: {e}")
    
    # ===================== WEBSITE REPORT =====================
    def _generate_website_report(self, target, options):
        if not self.results:
            return

        self.results["metadata"] = {
            "target": target,
            "scan_type": "website",
            "timestamp": datetime.now().isoformat(),
            "tool": f"jsosint v{JSOSINT_VERSION}",
        }

        if options.output:
            filename = options.output
            if not filename.endswith(".json"):
                filename += ".json"

            with open(filename, "w") as f:
                json.dump(self.results, f, indent=2)

            print(f"[+] Report saved: {filename}")


    # ===================== PERSON REPORT =====================
    def _generate_person_report(self, target, options):
        if not self.results:
            print(f"{self.colors.YELLOW}[!] No results{self.colors.RESET}")
            return

        self.results["metadata"] = {
            "target": target,
            "scan_type": "person",
            "timestamp": datetime.now().isoformat(),
            "tool": f"jsosint v{JSOSINT_VERSION}",
        }

        print(f"{self.colors.GREEN}[+] Person scan completed for: {target}{self.colors.RESET}\n")

        GREEN = self.colors.GREEN
        CYAN = self.colors.CYAN
        YELLOW = self.colors.YELLOW
        RESET = self.colors.RESET
        BOLD = getattr(self.colors, "BOLD", "")

        printed_ids = set()

        def is_empty(value):
            if value is None:
                return True
            if isinstance(value, dict):
                return not any(value.values())
            if isinstance(value, list):
                return len(value) == 0
            return False

        def print_data(data, indent=0):
            if id(data) in printed_ids:
                return
            printed_ids.add(id(data))

            prefix = "  " * indent
            if isinstance(data, dict):
                for k, v in data.items():
                    header = f"{BOLD}{CYAN}[{str(k).upper()}]{RESET}"
                    if isinstance(v, (dict, list)):
                        print(f"{prefix}{header}")
                        print_data(v, indent + 1)
                    else:
                        print(f"{prefix}{header}: {v}")
            elif isinstance(data, list):
                if not data:
                    print(f"{prefix}{YELLOW}No data found{RESET}")
                    return
                for item in data:
                    if isinstance(item, (dict, list)):
                        print_data(item, indent)
                    else:
                        print(f"{prefix}- {item}")
            else:
                print(f"{prefix}{data}")

        for key, value in self.results.items():
            if key == "metadata":
                continue
            title = f"{BOLD}{CYAN}[{key.upper()}]{RESET}"
            print(title)
            if is_empty(value):
                print(f"  {YELLOW}No data found{RESET}")
            else:
                print_data(value, indent=1)
            print(f"{BOLD}{'-' * 60}{RESET}")

        if options.output:
            filename = options.output
            if not filename.endswith(".json"):
                filename += ".json"
            with open(filename, "w") as f:
                json.dump(self.results, f, indent=2)
            print(f"{GREEN}[+] Saved: {filename}{RESET}")


    # ===================== NETWORK REPORT =====================
    def _generate_network_report(self, target, options):
        if not self.results:
            print(f"{self.colors.YELLOW}[!] No results{self.colors.RESET}")
            return

        self.results["metadata"] = {
            "target": target,
            "scan_type": "network",
            "timestamp": datetime.now().isoformat(),
            "tool": f"jsosint v{JSOSINT_VERSION}",
        }

        print(f"{self.colors.GREEN}[+] Network scan completed for: {target}{self.colors.RESET}\n")

        GREEN = self.colors.GREEN
        CYAN = self.colors.CYAN
        YELLOW = self.colors.YELLOW
        RESET = self.colors.RESET
        BOLD = getattr(self.colors, "BOLD", "")

        printed_ids = set()

        def is_empty(value):
            if value is None:
                return True
            if isinstance(value, dict):
                return not any(value.values())
            if isinstance(value, list):
                return len(value) == 0
            return False

        def print_data(data, indent=0):
            if id(data) in printed_ids:
                return
            printed_ids.add(id(data))

            prefix = "  " * indent
            if isinstance(data, dict):
                for k, v in data.items():
                    header = f"{BOLD}{CYAN}[{str(k).upper()}]{RESET}"
                    if isinstance(v, (dict, list)):
                        print(f"{prefix}{header}")
                        print_data(v, indent + 1)
                    else:
                        print(f"{prefix}{header}: {v}")
            elif isinstance(data, list):
                if not data:
                    print(f"{prefix}{YELLOW}No data found{RESET}")
                    return
                for item in data:
                    if isinstance(item, (dict, list)):
                        print_data(item, indent)
                    else:
                        print(f"{prefix}- {item}")
            else:
                print(f"{prefix}{data}")

        for key, value in self.results.items():
            if key == "metadata":
                continue
            title = f"{BOLD}{CYAN}[{key.upper()}]{RESET}"
            print(title)
            if is_empty(value):
                print(f"  {YELLOW}No data found{RESET}")
            else:
                print_data(value, indent=1)
            print(f"{BOLD}{'-' * 60}{RESET}")

        if options.output:
            filename = options.output
            if not filename.endswith(".json"):
                filename += ".json"
            with open(filename, "w") as f:
                json.dump(self.results, f, indent=2)
            print(f"{GREEN}[+] Saved: {filename}{RESET}")

    # ===================== SUMMARY REPORT =====================
    def _display_summary(self, scan_type):
        print(f"\n[+] {scan_type.capitalize()} Recon Summary")
        print("-" * 50)

        if scan_type == "website":
            ports = self.results.get("open_ports", [])
            tech = self.results.get("technologies", [])
            emails = self.results.get("emails", [])

            if ports:
                print(f"[PORTS] Open: {', '.join(map(str, ports))}")
            else:
                print("[PORTS] No open ports found")

            if tech:
                print(f"[TECH] {', '.join(tech)}")
            else:
                print("[TECH] No technologies detected")

            if emails:
                print(f"[EMAILS] Found: {len(emails)}")
            else:
                print("[EMAILS] None found")

        elif scan_type == "person":
            usernames = self.results.get("username_variations", [])
            socials = self.results.get("social_media", [])

            if usernames:
                print(f"[USERNAMES] Generated: {len(usernames)}")
            else:
                print("[USERNAMES] None")

            found_socials = [s for s in socials if s.get("found")]
            if found_socials:
                print(f"[SOCIALS] Profiles found: {len(found_socials)}")
            else:
                print("[SOCIALS] No profiles found")

        elif scan_type == "network":
            open_ports = self.results.get("open_ports", [])
            services = self.results.get("services", {})

            if open_ports:
                print(f"[PORTS] Open: {', '.join(map(str, open_ports))}")
            else:
                print("[PORTS] No open ports")

            if services:
                print(f"[SERVICES] Identified: {len(services)}")
            else:
                print("[SERVICES] None identified")

        print("-" * 50)
# ===================== ENTRY POINT =====================

def run_update(colors):
    print(f"\n{colors.YELLOW}[i]{colors.RESET} JSOSINT Update Manager\n")

    if not shutil.which("git"):
        print(f"{colors.RED}[!]{colors.RESET} Git is not installed.")
        sys.exit(1)

    if not os.path.isdir(os.path.join(BASE_DIR, ".git")):
        print(f"{colors.RED}[!]{colors.RESET} JSOSINT was not installed via git.")
        print("    Auto-update is unavailable.\n")
        sys.exit(1)

    current_version = JSOSINT_VERSION
    print(f"{colors.BLUE}[C]{colors.RESET} Current Version: {current_version}")

    confirm = input("\nUpdate JSOSINT now? (Y/N): ").strip().lower()
    if confirm != "y":
        print("\nUpdate cancelled.\n")
        sys.exit(0)

    try:
        subprocess.check_call(["git", "fetch", "--all"])
        subprocess.check_call(["git", "reset", "--hard", "origin/main"])
        subprocess.check_call(["git", "clean", "-fd"])

        if os.path.isfile("requirements.txt"):
            subprocess.check_call([
                sys.executable, "-m", "pip", "install", "-r", "requirements.txt"
            ])

        print(f"\n{colors.GREEN}[✓]{colors.RESET} JSOSINT updated successfully.")
        print("    All tool files were replaced. Restart required.\n")

    except subprocess.CalledProcessError:
        print(f"{colors.RED}[!]{colors.RESET} Update failed. Please update manually.\n")

    sys.exit(0)

def main():
    import argparse
    import sys, signal
    signal.signal(signal.SIGINT, lambda *_: sys.exit(0))

    # 1. Define extra_help first
    extra_help = (
        "python3 jsosint.py w -h, python3 jsosint.py w --help   Check website help options\n"
        "python3 jsosint.py p -h, python3 jsosint.py p --help   Check person help options\n"
        "python3 jsosint.py n -h, python3 jsosint.py n --help   Check network help options"
    )

    # 2. Now create parser with epilog
    parser = argparse.ArgumentParser(
        description=f"jsosint - Ultimate OSINT Suite v{get_version()}",
        epilog=extra_help,
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument("-v", "--version", action="store_true", help="Show jsosint version")
    parser.add_argument("-u", "--update", action="store_true", help="Update JSOSINT")

    sub = parser.add_subparsers(dest="command")

    # Website subparser
    web = sub.add_parser("website", aliases=["w"])
    web.add_argument("target", help="Target website domain or IP (e.g., example.com)")
    web.add_argument("--all", action="store_true", help="Run all website recon modules")
    web.add_argument("--basic", action="store_true", help="Perform basic website analysis")
    web.add_argument("--dns", action="store_true", help="Gather DNS information")
    web.add_argument("--whois", action="store_true", help="Perform WHOIS lookup")
    web.add_argument("--subdomains", action="store_true", help="Find subdomains of the target")
    web.add_argument("--tech", action="store_true", help="Detect technologies used by the website")
    web.add_argument("--directories", action="store_true", help="Scan common directories")
    web.add_argument("--emails", action="store_true", help="Search for publicly listed emails")
    web.add_argument("--ports", action="store_true", help="Scan common ports (HTTP, HTTPS, etc.)")
    web.add_argument("-o", "--output", help="Save results to a JSON file")

    # Person subparser
    person = sub.add_parser("person", aliases=["p"])
    person.add_argument("target", help="Target person's name, username, or identifier")
    person.add_argument("--all", action="store_true", help="Run all person recon modules")
    person.add_argument("--basic", action="store_true", help="Perform basic person analysis")
    person.add_argument("--username", action="store_true", help="Analyze usernames and variations")
    person.add_argument("--email", action="store_true", help="Search for email addresses associated with the person")
    person.add_argument("--phone", action="store_true", help="Search for phone numbers")
    person.add_argument("--ip", action="store_true", help="Check IPs linked to the person")
    person.add_argument("--possible", action="store_true", help="Find possible names of the person")
    person.add_argument("--breaches", action="store_true", help="Check if the person's data appeared in breaches")
    person.add_argument("--public", action="store_true", help="Search public records")
    person.add_argument("--social", action="store_true", help="Search social media accounts")
    person.add_argument("--domain_url", action="store_true", help="Check associated domain URLs")
    person.add_argument("-o", "--output", help="Save results to a JSON file")

    # Network subparser
    net = sub.add_parser("network", aliases=["n"])
    net.add_argument("target", help="Target IP or network range (e.g., 192.168.1.1)")
    net.add_argument("--all", action="store_true", help="Run all network scan modules")
    net.add_argument("--ports", action="store_true", help="Scan for open and closed ports")
    net.add_argument("--services", action="store_true", help="Detect services running on ports")
    net.add_argument("--title", action="store_true", help="Get web page titles from open ports")
    net.add_argument("--os", action="store_true", help="Perform OS detection")
    net.add_argument("--vuln", action="store_true", help="Check for known vulnerabilities")
    net.add_argument("--discovery", action="store_true", help="Run network discovery (hosts, subnets)")
    net.add_argument("--mac_vendor", action="store_true", help="Identify MAC vendor info")
    net.add_argument("--traceroute", action="store_true", help="Perform traceroute to the target")
    net.add_argument("--dns_enum", action="store_true", help="Perform DNS enumeration")
    net.add_argument("-o", "--output", help="Save results to a JSON file")

    args = parser.parse_args()
    tool = Jsosint()

    if args.update:
        run_update(tool.colors)
        return

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

# ===================== UPDATE FUNCTIONALITY =====================


if __name__ == "__main__":
    main()
