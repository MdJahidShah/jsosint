
## File 5: `modules/website_intel.py`

```python
#!/usr/bin/env python3
"""
Website Intelligence Module for jsosint
"""

import socket
import re
import requests
import dns.resolver
import whois
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from datetime import datetime
import ssl
import OpenSSL
import concurrent.futures

from utils.kali_tools import KaliTools

class WebsiteIntel:
    """Complete website intelligence gathering"""
    
    def __init__(self, domain):
        self.domain = domain
        self.results = {}
        self.kali = KaliTools()
    
    def full_recon(self):
        """Perform complete website reconnaissance"""
        print(f"[*] Starting full reconnaissance on: {self.domain}")
        
        # Run all modules
        modules = [
            self.get_basic_info,
            self.get_dns_info,
            self.get_whois_info,
            self.find_subdomains,
            self.detect_technologies,
            self.scan_ports,
            self.find_directories,
            self.harvest_emails,
            self.get_historical_data,
            self.scan_vulnerabilities,
            self.check_ssl
        ]
        
        for module in modules:
            try:
                module_name = module.__name__.replace('_', ' ').title()
                print(f"[*] Running: {module_name}")
                module()
            except Exception as e:
                print(f"[!] Error in {module.__name__}: {e}")
                continue
        
        return self.results
    
    def get_basic_info(self):
        """Get basic website information"""
        info = {}
        
        try:
            # Get IP address
            ip = socket.gethostbyname(self.domain)
            info['ip_address'] = ip
            
            # Try HTTP and HTTPS
            for protocol in ['http', 'https']:
                try:
                    url = f"{protocol}://{self.domain}"
                    response = requests.get(url, timeout=10, verify=False)
                    info['status_code'] = response.status_code
                    info['server'] = response.headers.get('Server', 'Unknown')
                    info['content_type'] = response.headers.get('Content-Type', 'Unknown')
                    
                    # Get page title
                    soup = BeautifulSoup(response.text, 'html.parser')
                    title = soup.title.string if soup.title else 'No title'
                    info['title'] = title
                    
                    # Get page size
                    info['page_size'] = len(response.content)
                    
                    break  # Stop at first successful protocol
                except:
                    continue
            
        except Exception as e:
            info['error'] = str(e)
        
        self.results['basic'] = info
        return info
    
    def get_dns_info(self):
        """Get comprehensive DNS information"""
        records = {}
        
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5
            
            # Common record types
            record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'SRV']
            
            for rtype in record_types:
                try:
                    answers = resolver.resolve(self.domain, rtype)
                    records[rtype] = [str(rdata) for rdata in answers]
                except:
                    records[rtype] = []
            
            # Use system dig command
            dig_result = self.kali.dig_info(self.domain, 'ANY')
            if dig_result['success']:
                records['dig_output'] = dig_result['output'].split('\n')
            
        except Exception as e:
            records['error'] = str(e)
        
        self.results['dns'] = records
        return records
    
    def get_whois_info(self):
        """Get WHOIS information"""
        try:
            # Use python-whois
            w = whois.whois(self.domain)
            
            whois_info = {
                'domain_name': w.domain_name,
                'registrar': w.registrar,
                'whois_server': w.whois_server,
                'creation_date': str(w.creation_date) if w.creation_date else None,
                'expiration_date': str(w.expiration_date) if w.expiration_date else None,
                'updated_date': str(w.updated_date) if w.updated_date else None,
                'name_servers': list(set(w.name_servers)) if w.name_servers else [],
                'status': w.status,
                'emails': list(set(w.emails)) if w.emails else [],
                'org': w.org,
                'country': w.country,
                'city': w.city,
                'state': w.state,
                'zipcode': w.zipcode
            }
            
            # Clean up the data
            for key, value in whois_info.items():
                if isinstance(value, list):
                    whois_info[key] = [str(v) for v in value if v]
                elif value:
                    whois_info[key] = str(value)
            
            self.results['whois'] = whois_info
            return whois_info
            
        except Exception as e:
            error_info = {'error': str(e)}
            self.results['whois'] = error_info
            return error_info
    
    def find_subdomains(self):
        """Find subdomains using multiple methods"""
        subdomains = {
            'certificate': [],
            'bruteforce': [],
            'tools': {}
        }
        
        # Method 1: Certificate Transparency
        try:
            import requests
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = requests.get(url, timeout=15)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get('name_value', '')
                    if self.domain in name:
                        subdomains['certificate'].append(name.strip().lower())
                subdomains['certificate'] = list(set(subdomains['certificate']))[:50]
        except:
            pass
        
        # Method 2: Sublist3r
        try:
            sublist3r_results = self.kali.sublist3r(self.domain)
            if sublist3r_results:
                subdomains['tools']['sublist3r'] = sublist3r_results
        except:
            pass
        
        # Method 3: Common subdomains brute force
        common_subs = [
            'www', 'mail', 'ftp', 'admin', 'webmail', 'server', 'ns1', 'ns2',
            'cdn', 'api', 'dev', 'test', 'staging', 'blog', 'forum', 'shop',
            'store', 'app', 'mobile', 'm', 'static', 'assets', 'img', 'images'
        ]
        
        for sub in common_subs:
            full_domain = f"{sub}.{self.domain}"
            try:
                socket.gethostbyname(full_domain)
                subdomains['bruteforce'].append(full_domain)
            except:
                pass
        
        self.results['subdomains'] = subdomains
        return subdomains
    
    def detect_technologies(self):
        """Detect web technologies"""
        technologies = {'manual': {}, 'tools': {}}
        
        # Method 1: WhatWeb
        try:
            whatweb_result = self.kali.whatweb(self.domain)
            if whatweb_result['success']:
                technologies['tools']['whatweb'] = whatweb_result['output']
        except:
            pass
        
        # Method 2: Manual detection
        try:
            response = requests.get(f"http://{self.domain}", timeout=10, verify=False)
            headers = response.headers
            html_content = response.text.lower()
            
            tech_info = {}
            
            # Server detection
            if 'Server' in headers:
                tech_info['server'] = headers['Server']
            
            # CMS detection
            cms_patterns = {
                'WordPress': ['wp-content', 'wp-includes', 'wordpress'],
                'Joomla': ['joomla', '/media/jui/', 'com_content'],
                'Drupal': ['drupal', 'sites/all/', 'sites/default/'],
                'Magento': ['magento', '/skin/frontend/', '/media/'],
                'Shopify': ['shopify', 'cdn.shopify.com'],
                'Wix': ['wix.com', 'static.parastorage.com'],
                'Squarespace': ['squarespace', 'static.squarespace.com']
            }
            
            for cms, patterns in cms_patterns.items():
                if any(pattern in html_content for pattern in patterns):
                    tech_info['cms'] = cms
                    break
            
            # Framework detection
            framework_patterns = {
                'Laravel': ['laravel', 'csrf-token'],
                'Django': ['django', 'csrftoken'],
                'Rails': ['rails', 'csrf-param'],
                'React': ['react', 'react-dom'],
                'Vue.js': ['vue.js', 'v-app'],
                'Angular': ['angular', 'ng-']
            }
            
            for framework, patterns in framework_patterns.items():
                if any(pattern in html_content for pattern in patterns):
                    tech_info['framework'] = framework
                    break
            
            # JavaScript libraries
            js_libraries = {
                'jQuery': ['jquery', 'jquery.min.js'],
                'Bootstrap': ['bootstrap', 'bootstrap.min.js'],
                'Font Awesome': ['font-awesome', 'fontawesome']
            }
            
            detected_js = []
            for lib, patterns in js_libraries.items():
                if any(pattern in html_content for pattern in patterns):
                    detected_js.append(lib)
            
            if detected_js:
                tech_info['javascript_libraries'] = detected_js
            
            technologies['manual'] = tech_info
            
        except Exception as e:
            technologies['manual']['error'] = str(e)
        
        self.results['technologies'] = technologies
        return technologies
    
    def scan_ports(self):
        """Scan for open ports"""
        ports_info = {'open_ports': [], 'tools': {}}
        
        try:
            # Get IP address
            ip = self.results.get('basic', {}).get('ip_address')
            if not ip:
                ip = socket.gethostbyname(self.domain)
            
            # Method 1: Quick nmap scan
            nmap_result = self.kali.nmap_scan(ip, 'quick')
            if nmap_result['success']:
                ports_info['tools']['nmap'] = nmap_result['output']
            
            # Method 2: Common ports check
            common_ports = [
                21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 
                443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080,
                8443, 9000, 27017, 27018, 27019, 28017
            ]
            
            open_ports = []
            
            def check_port(port):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((ip, port))
                    sock.close()
                    return port if result == 0 else None
                except:
                    return None
            
            # Use threading for faster scanning
            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                future_to_port = {executor.submit(check_port, port): port for port in common_ports}
                for future in concurrent.futures.as_completed(future_to_port):
                    port = future.result()
                    if port:
                        open_ports.append(port)
            
            ports_info['open_ports'] = sorted(open_ports)
            
        except Exception as e:
            ports_info['error'] = str(e)
        
        self.results['ports'] = ports_info
        return ports_info
    
    def find_directories(self):
        """Find hidden directories and files"""
        directories = {'tools': {}}
        
        try:
            # Method 1: Dirb
            dirb_result = self.kali.dirb(f"http://{self.domain}")
            if dirb_result['success']:
                directories['tools']['dirb'] = dirb_result['output'].split('\n')[:20]
            
            # Method 2: Gobuster
            gobuster_result = self.kali.gobuster(f"http://{self.domain}")
            if gobuster_result['success']:
                directories['tools']['gobuster'] = gobuster_result['output'].split('\n')[:20]
            
        except Exception as e:
            directories['error'] = str(e)
        
        self.results['directories'] = directories
        return directories
    
    def harvest_emails(self):
        """Harvest email addresses"""
        emails = {'theharvester': [], 'page_scraping': []}
        
        try:
            # Method 1: TheHarvester
            harvester_result = self.kali.theharvester(self.domain, 'baidu,bing,google')
            if harvester_result and 'emails' in harvester_result:
                emails['theharvester'] = list(set(harvester_result['emails']))
            
            # Method 2: Page scraping
            try:
                response = requests.get(f"http://{self.domain}", timeout=10, verify=False)
                email_pattern = r'[\w\.-]+@[\w\.-]+\.\w+'
                found_emails = re.findall(email_pattern, response.text)
                emails['page_scraping'] = list(set(found_emails))
            except:
                pass
            
        except Exception as e:
            emails['error'] = str(e)
        
        self.results['emails'] = emails
        return emails
    
    def get_historical_data(self):
        """Get historical website data"""
        historical = {'wayback': []}
        
        try:
            import requests
            url = f"http://web.archive.org/cdx/search/cdx?url={self.domain}/*&output=json&fl=timestamp,original&collapse=urlkey&limit=10"
            response = requests.get(url, timeout=15)
            if response.status_code == 200:
                historical['wayback'] = response.json()
        except:
            pass
        
        self.results['historical'] = historical
        return historical
    
    def scan_vulnerabilities(self):
        """Scan for common vulnerabilities"""
        vulnerabilities = {'tools': {}}
        
        try:
            # Method 1: Nikto
            nikto_result = self.kali.nikto_scan(f"http://{self.domain}")
            if nikto_result['success']:
                vulnerabilities['tools']['nikto'] = nikto_result['output'].split('\n')[:30]
            
            # Method 2: WordPress scan if detected
            if self.results.get('technologies', {}).get('manual', {}).get('cms') == 'WordPress':
                wpscan_result = self.kali.wpscan(f"http://{self.domain}")
                if wpscan_result['success']:
                    vulnerabilities['tools']['wpscan'] = wpscan_result['output'].split('\n')[:30]
            
        except Exception as e:
            vulnerabilities['error'] = str(e)
        
        self.results['vulnerabilities'] = vulnerabilities
        return vulnerabilities
    
    def check_ssl(self):
        """Check SSL/TLS configuration"""
        ssl_info = {}
        
        try:
            hostname = self.domain
            port = 443
            
            # Create SSL context
            context = ssl.create_default_context()
            
            # Connect and get certificate
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    ssl_info['certificate'] = cert
                    
                    # Get certificate details using OpenSSL
                    cert_der = ssock.getpeercert(binary_form=True)
                    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_der)
                    
                    ssl_info['issuer'] = x509.get_issuer().CN
                    ssl_info['subject'] = x509.get_subject().CN
                    ssl_info['expires'] = x509.get_notAfter().decode('utf-8')
                    ssl_info['serial'] = str(x509.get_serial_number())
                    
                    # Check if certificate is expired
                    from datetime import datetime
                    expires = datetime.strptime(ssl_info['expires'], '%Y%m%d%H%M%SZ')
                    ssl_info['is_expired'] = expires < datetime.utcnow()
                    
                    # Get SSL version
                    ssl_info['version'] = ssock.version()
                    
        except Exception as e:
            ssl_info['error'] = str(e)
        
        self.results['ssl'] = ssl_info
        return ssl_info