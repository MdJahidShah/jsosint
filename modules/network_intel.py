#!/usr/bin/env python3
"""
Complete Network Intelligence Module
"""

import socket
import subprocess
import json
import ipaddress
import concurrent.futures
from datetime import datetime
import nmap
import scapy.all as scapy
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
import netifaces
import psutil

from utils.colors import Colors

class NetworkScanner:
    """Complete network scanning and enumeration"""
    
    def __init__(self):
        self.colors = Colors()
        self.nm = nmap.PortScanner()
        
    def scan_ports(self, target, ports='1-1000', timing=3, services=True, os_detect=False):
        """Comprehensive port scanning"""
        results = {
            'target': target,
            'scan_time': datetime.now().isoformat(),
            'open_ports': [],
            'closed_ports': [],
            'filtered_ports': []
        }
        
        try:
            print(f"{self.colors.CYAN}[*]{self.colors.RESET} Scanning {target} on ports {ports}")
            
            # Nmap scan
            scan_args = f'-T{timing}'
            if services:
                scan_args += ' -sV'
            if os_detect:
                scan_args += ' -O'
            
            self.nm.scan(target, ports, arguments=scan_args)
            
            if target in self.nm.all_hosts():
                host = self.nm[target]
                
                results['hostnames'] = host.hostnames()
                results['state'] = host.state()
                results['addresses'] = host.get('addresses', {})
                
                # Port information
                for proto in host.all_protocols():
                    ports_info = host[proto]
                    for port, info in ports_info.items():
                        port_result = {
                            'port': port,
                            'protocol': proto,
                            'state': info['state'],
                            'service': info.get('name', 'unknown'),
                            'version': info.get('version', ''),
                            'product': info.get('product', ''),
                            'extra_info': info.get('extrainfo', '')
                        }
                        
                        if info['state'] == 'open':
                            results['open_ports'].append(port_result)
                        elif info['state'] == 'closed':
                            results['closed_ports'].append(port_result)
                        elif info['state'] == 'filtered':
                            results['filtered_ports'].append(port_result)
                
                # OS detection
                if 'osmatch' in host:
                    results['os_detection'] = []
                    for os_match in host['osmatch']:
                        results['os_detection'].append({
                            'name': os_match['name'],
                            'accuracy': os_match['accuracy'],
                            'osclass': os_match.get('osclass', [])
                        })
                
                # Service detection summary
                if services:
                    services_summary = {}
                    for port_info in results['open_ports']:
                        service = port_info['service']
                        if service not in services_summary:
                            services_summary[service] = 0
                        services_summary[service] += 1
                    results['services_summary'] = services_summary
            
            # Additional quick socket scan for verification
            print(f"{self.colors.CYAN}[*]{self.colors.RESET} Quick verification scan...")
            common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5900, 8080]
            quick_open = []
            
            def check_port(port):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((target, port))
                    sock.close()
                    if result == 0:
                        return port
                except:
                    pass
                return None
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                future_to_port = {executor.submit(check_port, port): port for port in common_ports}
                for future in concurrent.futures.as_completed(future_to_port):
                    port = future.result()
                    if port:
                        quick_open.append(port)
            
            results['quick_scan_open'] = quick_open
            
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def detect_services(self, target):
        """Service detection and banner grabbing"""
        services = {}
        
        try:
            # Common ports and their services
            common_services = {
                21: 'FTP',
                22: 'SSH',
                23: 'Telnet',
                25: 'SMTP',
                53: 'DNS',
                80: 'HTTP',
                110: 'POP3',
                143: 'IMAP',
                443: 'HTTPS',
                445: 'SMB',
                993: 'IMAPS',
                995: 'POP3S',
                3306: 'MySQL',
                3389: 'RDP',
                5900: 'VNC',
                8080: 'HTTP-Proxy'
            }
            
            for port, service_name in common_services.items():
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result = sock.connect_ex((target, port))
                    
                    if result == 0:
                        # Try to get banner
                        try:
                            if port in [21, 22, 25, 80, 110, 143]:
                                sock.send(b'\r\n')
                                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                            else:
                                banner = "No banner received"
                        except:
                            banner = "Banner grab failed"
                        
                        services[port] = {
                            'service': service_name,
                            'state': 'open',
                            'banner': banner[:500]  # Limit banner length
                        }
                    else:
                        services[port] = {
                            'service': service_name,
                            'state': 'closed'
                        }
                    
                    sock.close()
                    
                except Exception as e:
                    services[port] = {
                        'service': service_name,
                        'state': 'error',
                        'error': str(e)
                    }
            
            # HTTP/HTTPS specific checks
            for protocol, port in [('HTTP', 80), ('HTTPS', 443)]:
                if port in services and services[port]['state'] == 'open':
                    try:
                        url = f"{'https' if port == 443 else 'http'}://{target}"
                        import requests
                        response = requests.get(url, timeout=5, verify=False)
                        
                        services[port]['http_info'] = {
                            'status_code': response.status_code,
                            'server': response.headers.get('Server', 'Unknown'),
                            'content_type': response.headers.get('Content-Type', 'Unknown'),
                            'title': self._extract_html_title(response.text)
                        }
                    except:
                        pass
            
        except Exception as e:
            services['error'] = str(e)
        
        return services
    
    def _extract_html_title(self, html_content):
        """Extract title from HTML"""
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html_content, 'html.parser')
            title = soup.title.string if soup.title else 'No title'
            return title.strip()[:100]
        except:
            return 'Title extraction failed'
    
    def os_detection(self, target):
        """OS detection using multiple methods"""
        os_info = {}
        
        try:
            # Method 1: Nmap OS detection
            try:
                self.nm.scan(target, arguments='-O')
                if target in self.nm.all_hosts():
                    host = self.nm[target]
                    if 'osmatch' in host:
                        os_matches = []
                        for os_match in host['osmatch']:
                            os_matches.append({
                                'name': os_match['name'],
                                'accuracy': os_match['accuracy'],
                                'type': os_match.get('type', ''),
                                'vendor': os_match.get('vendor', ''),
                                'osfamily': os_match.get('osfamily', ''),
                                'osgen': os_match.get('osgen', '')
                            })
                        os_info['nmap_detection'] = os_matches
            except:
                pass
            
            # Method 2: TTL analysis
            try:
                # Send ICMP ping and analyze TTL
                response = subprocess.run(
                    ['ping', '-c', '1', '-W', '2', target],
                    capture_output=True, text=True
                )
                
                if 'ttl=' in response.stdout.lower():
                    import re
                    ttl_match = re.search(r'ttl=(\d+)', response.stdout.lower())
                    if ttl_match:
                        ttl = int(ttl_match.group(1))
                        
                        # Common TTL values
                        # Windows: 128, Linux: 64, Cisco: 255
                        if ttl <= 64:
                            os_info['ttl_guess'] = 'Linux/Unix'
                        elif ttl <= 128:
                            os_info['ttl_guess'] = 'Windows'
                        elif ttl > 200:
                            os_info['ttl_guess'] = 'Network Device (Cisco, etc.)'
                        else:
                            os_info['ttl_guess'] = 'Unknown'
                        
                        os_info['ttl_value'] = ttl
            except:
                pass
            
            # Method 3: TCP/IP fingerprinting (simplified)
            try:
                # Check common ports for OS hints
                common_ports = {
                    135: 'Windows',
                    139: 'Windows',
                    445: 'Windows',
                    3389: 'Windows',
                    111: 'Unix/Linux',
                    2049: 'Unix/Linux',
                    22: 'Unix/Linux (SSH)',
                    23: 'Various (Telnet)'
                }
                
                open_ports = []
                for port, os_hint in common_ports.items():
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(1)
                        result = sock.connect_ex((target, port))
                        sock.close()
                        if result == 0:
                            open_ports.append((port, os_hint))
                    except:
                        pass
                
                if open_ports:
                    os_info['port_based_hints'] = open_ports
                    
                    # Count hints
                    hint_counts = {}
                    for port, hint in open_ports:
                        if hint not in hint_counts:
                            hint_counts[hint] = 0
                        hint_counts[hint] += 1
                    
                    os_info['likely_os'] = max(hint_counts, key=hint_counts.get) if hint_counts else 'Unknown'
            
            except Exception as e:
                os_info['port_scan_error'] = str(e)
            
            # Method 4: NetBIOS detection (Windows)
            try:
                import sys
                if sys.platform != 'win32':
                    # Try nmblookup for NetBIOS
                    result = subprocess.run(
                        ['nmblookup', '-A', target],
                        capture_output=True, text=True
                    )
                    if 'Workstation Service' in result.stdout:
                        os_info['netbios_detected'] = 'Windows machine detected via NetBIOS'
            except:
                pass
            
        except Exception as e:
            os_info['error'] = str(e)
        
        return os_info
    
    def vulnerability_scan(self, target):
        """Basic vulnerability scanning"""
        vulnerabilities = {
            'common_vulnerabilities': [],
            'service_vulnerabilities': [],
            'configuration_issues': [],
            'security_headers': []
        }
        
        try:
            # Check for common vulnerabilities
            
            # 1. Check for HTTP security headers
            try:
                import requests
                for protocol in ['http', 'https']:
                    try:
                        url = f"{protocol}://{target}"
                        response = requests.get(url, timeout=5, verify=False)
                        
                        security_headers = [
                            'X-Frame-Options',
                            'X-Content-Type-Options', 
                            'X-XSS-Protection',
                            'Content-Security-Policy',
                            'Strict-Transport-Security',
                            'Referrer-Policy'
                        ]
                        
                        missing = []
                        for header in security_headers:
                            if header not in response.headers:
                                missing.append(header)
                        
                        if missing:
                            vulnerabilities['security_headers'].append({
                                'protocol': protocol.upper(),
                                'missing_headers': missing,
                                'risk': 'Medium'
                            })
                    except:
                        pass
            except:
                pass
            
            # 2. Check common vulnerable services
            vulnerable_services = [
                (21, 'FTP', 'Anonymous login, weak authentication'),
                (23, 'Telnet', 'Unencrypted communication'),
                (80, 'HTTP', 'Unencrypted web traffic'),
                (110, 'POP3', 'Unencrypted email'),
                (143, 'IMAP', 'Unencrypted email'),
                (445, 'SMB', 'EternalBlue vulnerability potential'),
                (3389, 'RDP', 'BlueKeep vulnerability potential')
            ]
            
            for port, service, issue in vulnerable_services:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((target, port))
                    sock.close()
                    
                    if result == 0:
                        vulnerabilities['service_vulnerabilities'].append({
                            'port': port,
                            'service': service,
                            'issue': issue,
                            'risk': 'High' if port in [445, 3389] else 'Medium'
                        })
                except:
                    pass
            
            # 3. Check for default/weak credentials (simulated)
            common_defaults = [
                ('SSH', 22, 'root:root, admin:admin'),
                ('Telnet', 23, 'Various defaults'),
                ('FTP', 21, 'anonymous:anonymous'),
                ('MySQL', 3306, 'root:(empty)'),
                ('VNC', 5900, '(empty):(empty)')
            ]
            
            for service, port, defaults in common_defaults:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((target, port))
                    sock.close()
                    
                    if result == 0:
                        vulnerabilities['common_vulnerabilities'].append({
                            'service': service,
                            'port': port,
                            'issue': f'Default credentials: {defaults}',
                            'risk': 'High'
                        })
                except:
                    pass
            
            # 4. Check for information disclosure
            info_disclosure_files = [
                '/robots.txt',
                '/.git/HEAD',
                '/.env',
                '/phpinfo.php',
                '/test.php',
                '/info.php',
                '/server-status',
                '/.well-known/security.txt'
            ]
            
            for file in info_disclosure_files:
                try:
                    url = f"http://{target}{file}"
                    response = requests.get(url, timeout=3, verify=False)
                    if response.status_code == 200:
                        vulnerabilities['configuration_issues'].append({
                            'file': file,
                            'url': url,
                            'issue': 'Information disclosure',
                            'risk': 'Low' if 'robots.txt' in file else 'Medium'
                        })
                except:
                    pass
            
            # 5. WordPress specific checks
            try:
                wp_url = f"http://{target}/wp-login.php"
                response = requests.head(wp_url, timeout=3)
                if response.status_code == 200:
                    vulnerabilities['common_vulnerabilities'].append({
                        'service': 'WordPress',
                        'url': wp_url,
                        'issue': 'WordPress login page accessible',
                        'risk': 'Low'
                    })
            except:
                pass
            
        except Exception as e:
            vulnerabilities['error'] = str(e)
        
        return vulnerabilities
    
    def network_discovery(self, network_range='192.168.1.0/24'):
        """Network discovery and host enumeration"""
        discovery = {
            'network_range': network_range,
            'alive_hosts': [],
            'host_details': {},
            'network_info': {}
        }
        
        try:
            # Get network information
            try:
                network = ipaddress.ip_network(network_range, strict=False)
                discovery['network_info'] = {
                    'network_address': str(network.network_address),
                    'broadcast_address': str(network.broadcast_address),
                    'netmask': str(network.netmask),
                    'hostmask': str(network.hostmask),
                    'num_addresses': network.num_addresses,
                    'usable_hosts': network.num_addresses - 2 if network.num_addresses > 2 else network.num_addresses
                }
            except:
                pass
            
            # ARP scan for local network discovery
            print(f"{self.colors.CYAN}[*]{self.colors.RESET} Discovering hosts on {network_range}")
            
            try:
                # Create ARP request
                arp = ARP(pdst=network_range)
                ether = Ether(dst="ff:ff:ff:ff:ff:ff")
                packet = ether/arp
                
                # Send and receive packets
                result = scapy.srp(packet, timeout=2, verbose=False)[0]
                
                for sent, received in result:
                    host_info = {
                        'ip': received.psrc,
                        'mac': received.hwsrc,
                        'vendor': self._get_mac_vendor(received.hwsrc)
                    }
                    discovery['alive_hosts'].append(host_info)
                    
                    # Get hostname if possible
                    try:
                        hostname = socket.gethostbyaddr(received.psrc)[0]
                        host_info['hostname'] = hostname
                    except:
                        pass
                
            except Exception as e:
                discovery['arp_scan_error'] = str(e)
            
            # Ping sweep as fallback
            if not discovery['alive_hosts']:
                print(f"{self.colors.CYAN}[*]{self.colors.RESET} Trying ping sweep...")
                
                def ping_host(ip):
                    try:
                        response = subprocess.run(
                            ['ping', '-c', '1', '-W', '1', str(ip)],
                            capture_output=True, text=True
                        )
                        if response.returncode == 0:
                            return str(ip)
                    except:
                        pass
                    return None
                
                hosts = list(network.hosts())[:254]  # Limit to 254 hosts
                
                with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                    future_to_ip = {executor.submit(ping_host, ip): ip for ip in hosts}
                    for future in concurrent.futures.as_completed(future_to_ip):
                        ip = future.result()
                        if ip:
                            discovery['alive_hosts'].append({'ip': ip})
            
            # Sort hosts by IP
            discovery['alive_hosts'].sort(key=lambda x: [int(octet) for octet in x['ip'].split('.')])
            
            print(f"{self.colors.GREEN}[+]{self.colors.RESET} Found {len(discovery['alive_hosts'])} alive hosts")
            
        except Exception as e:
            discovery['error'] = str(e)
        
        return discovery
    
    def _get_mac_vendor(self, mac_address):
        """Get vendor from MAC address"""
        try:
            # Remove separators and convert to uppercase
            mac = mac_address.replace(':', '').replace('-', '').upper()
            
            # Check first 6 characters (OUI)
            oui = mac[:6]
            
            # Common vendors (simplified)
            vendors = {
                '000C29': 'VMware',
                '005056': 'VMware',
                '000569': 'Netgear',
                '001E8C': 'Cisco',
                '001BFC': 'Cisco',
                '001C10': 'Apple',
                '001E52': 'Apple',
                '001D4F': 'Apple',
                '001EC2': 'TP-Link',
                '0013F7': 'TP-Link',
                '001A2B': 'D-Link',
                '001B11': 'D-Link',
                '0016B6': 'Microsoft',
                '000D3A': 'Microsoft',
                '0019B9': 'Belkin',
                '0022B0': 'Dell',
                '001A4B': 'Dell',
                '0010E0': 'Intel',
                '001B21': 'Intel'
            }
            
            return vendors.get(oui, 'Unknown')
        except:
            return 'Unknown'
    
    def traceroute(self, target, max_hops=30):
        """Perform traceroute to target"""
        trace = {
            'target': target,
            'hops': [],
            'completed': False
        }
        
        try:
            import subprocess
            
            print(f"{self.colors.CYAN}[*]{self.colors.RESET} Tracing route to {target}")
            
            # Different commands for different OS
            import platform
            system = platform.system().lower()
            
            if system == 'windows':
                cmd = ['tracert', '-h', str(max_hops), '-w', '1000', target]
            else:  # Linux/Mac
                cmd = ['traceroute', '-m', str(max_hops), '-w', '1', '-q', '1', target]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            trace['raw_output'] = result.stdout
            
            # Parse output (simplified)
            lines = result.stdout.split('\n')
            for line in lines:
                line = line.strip()
                if line and not line.startswith('Tracing') and not line.startswith('traceroute'):
                    # Parse hop information
                    parts = line.split()
                    if len(parts) >= 2:
                        try:
                            hop_num = int(parts[0])
                            ip_or_host = parts[1]
                            
                            hop_info = {
                                'hop': hop_num,
                                'address': ip_or_host
                            }
                            
                            # Try to get hostname
                            try:
                                if not ip_or_host.replace('.', '').isdigit():
                                    hop_info['hostname'] = ip_or_host
                                    hop_info['ip'] = socket.gethostbyname(ip_or_host)
                                else:
                                    hop_info['ip'] = ip_or_host
                                    try:
                                        hop_info['hostname'] = socket.gethostbyaddr(ip_or_host)[0]
                                    except:
                                        hop_info['hostname'] = 'Unknown'
                            except:
                                pass
                            
                            # Get response times if available
                            if len(parts) > 2:
                                times = []
                                for part in parts[2:]:
                                    if part.endswith('ms'):
                                        try:
                                            time_ms = float(part.replace('ms', ''))
                                            times.append(time_ms)
                                        except:
                                            pass
                                if times:
                                    hop_info['response_times_ms'] = times
                                    hop_info['avg_response_ms'] = sum(times) / len(times)
                            
                            trace['hops'].append(hop_info)
                            
                            # Check if we reached target
                            if ip_or_host == target or (hasattr(hop_info, 'ip') and hop_info.get('ip') == target):
                                trace['completed'] = True
                                break
                                
                        except ValueError:
                            continue
            
        except Exception as e:
            trace['error'] = str(e)
        
        return trace
    
    def dns_enumeration(self, domain):
        """DNS enumeration for a domain"""
        dns_info = {
            'domain': domain,
            'records': {},
            'zone_transfer': {},
            'subdomain_bruteforce': []
        }
        
        try:
            import dns.resolver
            import dns.zone
            import dns.query
            
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5
            
            # Get all record types
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'SRV']
            
            for rtype in record_types:
                try:
                    answers = resolver.resolve(domain, rtype)
                    dns_info['records'][rtype] = [str(r) for r in answers]
                except:
                    dns_info['records'][rtype] = []
            
            # Try zone transfer
            try:
                ns_servers = dns_info['records'].get('NS', [])
                for ns in ns_servers:
                    try:
                        ns_ip = socket.gethostbyname(ns)
                        zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain))
                        if zone:
                            dns_info['zone_transfer'][ns] = {
                                'success': True,
                                'records': list(zone.nodes.keys())[:50]  # Limit to 50
                            }
                    except:
                        dns_info['zone_transfer'][ns] = {'success': False}
            except:
                pass
            
            # Subdomain bruteforce (limited)
            common_subs = ['www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 'blog']
            for sub in common_subs:
                try:
                    full = f"{sub}.{domain}"
                    answers = resolver.resolve(full, 'A')
                    dns_info['subdomain_bruteforce'].append({
                        'subdomain': full,
                        'ip': [str(r) for r in answers]
                    })
                except:
                    pass
            
        except Exception as e:
            dns_info['error'] = str(e)
        
        return dns_info
    
    def generate_network_report(self, target, options=None):
        """Generate comprehensive network report"""
        if options is None:
            options = {}
        
        report = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'scan_summary': {}
        }
        
        # Run selected scans
        if options.get('ports', True):
            report['port_scan'] = self.scan_ports(
                target,
                ports=options.get('ports_range', '1-1000'),
                timing=options.get('timing', 3),
                services=options.get('services', True),
                os_detect=options.get('os_detect', False)
            )
        
        if options.get('vulnerabilities', False):
            report['vulnerability_scan'] = self.vulnerability_scan(target)
        
        if options.get('traceroute', False):
            report['traceroute'] = self.traceroute(target)
        
        if options.get('discovery', False):
            # Determine network range
            try:
                ip = ipaddress.ip_address(target)
                if ip.is_private:
                    # Use /24 network for private IPs
                    network = ipaddress.ip_network(f"{target}/24", strict=False)
                    report['network_discovery'] = self.network_discovery(str(network))
            except:
                pass
        
        # Add summary statistics
        if 'port_scan' in report:
            report['scan_summary']['open_ports'] = len(report['port_scan'].get('open_ports', []))
            report['scan_summary']['services_found'] = len(report['port_scan'].get('services_summary', {}))
        
        if 'vulnerability_scan' in report:
            total_vulns = (
                len(report['vulnerability_scan'].get('common_vulnerabilities', [])) +
                len(report['vulnerability_scan'].get('service_vulnerabilities', [])) +
                len(report['vulnerability_scan'].get('configuration_issues', []))
            )
            report['scan_summary']['vulnerabilities_found'] = total_vulns
        
        return report