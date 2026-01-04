#!/usr/bin/env python3
"""
Complete Website Intelligence Module
"""

import socket
import re
import requests
import dns.resolver
import whois
import ssl
import json
import concurrent.futures
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from datetime import datetime
import OpenSSL
import ipaddress
import time
import xml.etree.ElementTree as ET

from utils.colors import Colors

class WebsiteRecon:
    """Complete website reconnaissance"""
    
    def __init__(self, domain):
        self.domain = domain
        self.results = {}
        self.colors = Colors()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def get_basic_info(self):
        """Get comprehensive basic information"""
        info = {'domain': self.domain, 'timestamp': datetime.now().isoformat()}
        
        try:
            # Get IP address(es)
            try:
                ip = socket.gethostbyname(self.domain)
                info['ip_address'] = ip
                
                # Get all IPs if multiple
                try:
                    ips = socket.gethostbyname_ex(self.domain)[2]
                    info['all_ips'] = ips
                except:
                    pass
                
                # Check if IPv4 or IPv6
                try:
                    ip_obj = ipaddress.ip_address(ip)
                    info['ip_version'] = 'IPv4' if ip_obj.version == 4 else 'IPv6'
                    info['is_private'] = ip_obj.is_private
                    info['is_reserved'] = ip_obj.is_reserved
                except:
                    pass
                    
            except Exception as e:
                info['ip_error'] = str(e)
            
            # Check HTTP/HTTPS
            for protocol in ['http', 'https']:
                try:
                    url = f"{protocol}://{self.domain}"
                    response = self.session.get(url, timeout=10, verify=False)
                    
                    info[f'{protocol}_status'] = response.status_code
                    info[f'{protocol}_server'] = response.headers.get('Server', 'Unknown')
                    info[f'{protocol}_content_type'] = response.headers.get('Content-Type', 'Unknown')
                    info[f'{protocol}_content_length'] = len(response.content)
                    
                    # Get security headers
                    security_headers = ['X-Frame-Options', 'X-Content-Type-Options', 
                                      'X-XSS-Protection', 'Content-Security-Policy',
                                      'Strict-Transport-Security', 'Referrer-Policy']
                    
                    info[f'{protocol}_security_headers'] = {}
                    for header in security_headers:
                        if header in response.headers:
                            info[f'{protocol}_security_headers'][header] = response.headers[header]
                    
                    # Get page title and meta
                    if protocol == 'http':  # Only do once
                        soup = BeautifulSoup(response.text, 'html.parser')
                        
                        # Title
                        title = soup.title.string if soup.title else 'No title'
                        info['title'] = title
                        
                        # Meta tags
                        meta_tags = {}
                        for meta in soup.find_all('meta'):
                            name = meta.get('name') or meta.get('property') or meta.get('http-equiv')
                            content = meta.get('content')
                            if name and content:
                                meta_tags[name] = content
                        info['meta_tags'] = meta_tags
                        
                        # Links
                        links = []
                        for link in soup.find_all('a', href=True):
                            links.append({
                                'text': link.text.strip()[:100],
                                'href': link['href']
                            })
                        info['links'] = links[:50]  # First 50 links
                        
                        # Forms
                        forms = []
                        for form in soup.find_all('form'):
                            forms.append({
                                'action': form.get('action', ''),
                                'method': form.get('method', 'GET')
                            })
                        info['forms'] = forms
                        
                        # Scripts and styles
                        scripts = len(soup.find_all('script'))
                        styles = len(soup.find_all('style'))
                        info['scripts_count'] = scripts
                        info['styles_count'] = styles
                    
                    break  # Stop at first successful protocol
                    
                except Exception as e:
                    info[f'{protocol}_error'] = str(e)
            
            # Check robots.txt
            try:
                robots_url = f"http://{self.domain}/robots.txt"
                response = self.session.get(robots_url, timeout=5)
                if response.status_code == 200:
                    info['robots_txt'] = response.text[:2000]  # First 2000 chars
            except:
                pass
            
            # Check sitemap.xml
            try:
                sitemap_url = f"http://{self.domain}/sitemap.xml"
                response = self.session.get(sitemap_url, timeout=5)
                if response.status_code == 200:
                    # Try to parse as XML
                    try:
                        root = ET.fromstring(response.content)
                        urls = []
                        for url in root.findall('.//{http://www.sitemaps.org/schemas/sitemap/0.9}loc'):
                            urls.append(url.text)
                        info['sitemap_urls_count'] = len(urls)
                    except:
                        info['sitemap_raw'] = response.text[:1000]
            except:
                pass
            
        except Exception as e:
            info['error'] = str(e)
        
        return info
    
    def enumerate_dns(self):
        """Complete DNS enumeration"""
        records = {}
        
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5
            
            # Use multiple DNS servers
            resolver.nameservers = [
                '8.8.8.8',      # Google
                '1.1.1.1',      # Cloudflare
                '9.9.9.9',      # Quad9
                '208.67.222.222' # OpenDNS
            ]
            
            # All record types to check
            record_types = [
                'A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 
                'SOA', 'SRV', 'PTR', 'CAA', 'DS', 'DNSKEY'
            ]
            
            for rtype in record_types:
                try:
                    answers = resolver.resolve(self.domain, rtype)
                    records[rtype] = [str(rdata) for rdata in answers]
                except:
                    records[rtype] = []
            
            # Zone transfer attempt (if NS records found)
            if records.get('NS'):
                records['zone_transfer'] = []
                for ns in records['NS']:
                    try:
                        transfer_resolver = dns.resolver.Resolver()
                        transfer_resolver.nameservers = [socket.gethostbyname(ns)]
                        transfer_resolver.timeout = 3
                        answers = transfer_resolver.resolve(self.domain, 'AXFR')
                        records['zone_transfer'].append({
                            'server': ns,
                            'success': True,
                            'records': [str(r) for r in answers]
                        })
                    except:
                        records['zone_transfer'].append({
                            'server': ns,
                            'success': False
                        })
            
            # SPF and DMARC records
            try:
                # SPF is usually in TXT records
                for txt in records.get('TXT', []):
                    if 'v=spf1' in txt.lower():
                        records['SPF'] = txt
                        break
            except:
                pass
            
            # Check for DMARC
            try:
                dmarc_domain = f'_dmarc.{self.domain}'
                answers = resolver.resolve(dmarc_domain, 'TXT')
                for rdata in answers:
                    if 'v=dmarc1' in str(rdata).lower():
                        records['DMARC'] = str(rdata)
                        break
            except:
                pass
            
            # Check for DKIM (common selectors)
            common_selectors = ['default', 'google', 'selector1', 'selector2', 'k1', 'dkim']
            records['DKIM'] = {}
            for selector in common_selectors:
                try:
                    dkim_domain = f'{selector}._domainkey.{self.domain}'
                    answers = resolver.resolve(dkim_domain, 'TXT')
                    records['DKIM'][selector] = [str(r) for r in answers]
                except:
                    pass
            
        except Exception as e:
            records['error'] = str(e)
        
        return records
    
    def whois_lookup(self):
        """Comprehensive WHOIS lookup"""
        try:
            w = whois.whois(self.domain)
            
            # Parse all possible fields
            whois_info = {
                'domain_name': w.domain_name,
                'registrar': w.registrar,
                'whois_server': w.whois_server,
                'referral_url': w.referral_url,
                'updated_date': str(w.updated_date) if w.updated_date else None,
                'creation_date': str(w.creation_date) if w.creation_date else None,
                'expiration_date': str(w.expiration_date) if w.expiration_date else None,
                'name_servers': list(set([ns.lower() for ns in w.name_servers])) if w.name_servers else [],
                'status': w.status,
                'emails': list(set([e.lower() for e in w.emails])) if w.emails else [],
                'dnssec': w.dnssec,
                'name': w.name,
                'org': w.org,
                'address': w.address,
                'city': w.city,
                'state': w.state,
                'registrant_postal_code': w.registrant_postal_code,
                'country': w.country,
            }
            
            # Clean up dates
            date_fields = ['updated_date', 'creation_date', 'expiration_date']
            for field in date_fields:
                if whois_info[field] and isinstance(whois_info[field], list):
                    whois_info[field] = str(whois_info[field][0])
            
            # Get raw whois from multiple sources
            whois_info['raw_sources'] = {}
            
            # Try different WHOIS servers
            servers = [
                'whois.verisign-grs.com',  # .com, .net
                'whois.publicinterestregistry.org',  # .org
                'whois.nic.io',  # .io
                'whois.registry.in',  # .in
            ]
            
            for server in servers:
                try:
                    import subprocess
                    result = subprocess.run(
                        ['whois', '-h', server, self.domain],
                        capture_output=True, text=True, timeout=10
                    )
                    if result.returncode == 0:
                        whois_info['raw_sources'][server] = result.stdout[:5000]
                except:
                    pass
            
            return whois_info
            
        except Exception as e:
            return {'error': str(e)}
    
    def find_subdomains(self, use_cert=True, use_bruteforce=True, use_search=True):
        """Find subdomains using multiple methods"""
        subdomains = {
            'certificate_transparency': [],
            'dns_bruteforce': [],
            'search_engines': [],
            'dns_crawl': [],
            'total_unique': set()
        }
        
        # Method 1: Certificate Transparency
        if use_cert:
            try:
                # crt.sh
                url = f"https://crt.sh/?q=%.{self.domain}&output=json"
                response = self.session.get(url, timeout=15)
                if response.status_code == 200:
                    data = response.json()
                    for entry in data:
                        names = entry.get('name_value', '').split('\n')
                        for name in names:
                            if self.domain in name:
                                clean_name = name.strip().lower().replace('*.', '')
                                if clean_name.endswith(self.domain):
                                    subdomains['certificate_transparency'].append(clean_name)
                                    subdomains['total_unique'].add(clean_name)
                
                # Remove duplicates
                subdomains['certificate_transparency'] = list(set(subdomains['certificate_transparency']))
                
            except Exception as e:
                subdomains['certificate_error'] = str(e)
        
        # Method 2: DNS Brute Force
        if use_bruteforce:
            try:
                # Load wordlist
                wordlist = [
                    'www', 'mail', 'ftp', 'admin', 'webmail', 'server', 'ns1', 'ns2',
                    'cdn', 'api', 'dev', 'test', 'staging', 'blog', 'forum', 'shop',
                    'store', 'app', 'mobile', 'm', 'static', 'assets', 'img', 'images',
                    'cdn', 'video', 'download', 'portal', 'support', 'help', 'status',
                    'demo', 'beta', 'alpha', 'secure', 'vpn', 'remote', 'git', 'svn',
                    'cpanel', 'whm', 'webdisk', 'webmin', 'roundcube', 'owa', 'exchange'
                ]
                
                # Try to load external wordlist
                try:
                    with open('wordlists/subdomains.txt', 'r') as f:
                        additional = [line.strip() for line in f if line.strip()]
                        wordlist.extend(additional[:1000])  # Limit to 1000
                except:
                    pass
                
                # Brute force with threading
                def check_subdomain(sub):
                    full = f"{sub}.{self.domain}"
                    try:
                        socket.gethostbyname(full)
                        return full
                    except:
                        return None
                
                with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                    futures = {executor.submit(check_subdomain, sub): sub for sub in wordlist}
                    for future in concurrent.futures.as_completed(futures):
                        result = future.result()
                        if result:
                            subdomains['dns_bruteforce'].append(result)
                            subdomains['total_unique'].add(result)
                
            except Exception as e:
                subdomains['bruteforce_error'] = str(e)
        
        # Method 3: Search Engines (simulated)
        if use_search:
            try:
                # This would use Google/Bing APIs or scraping
                # For now, simulate with common patterns
                patterns = [
                    f'site:*.{self.domain}',
                    f'inurl:{self.domain}',
                    f'intitle:{self.domain}'
                ]
                subdomains['search_queries'] = patterns
                
                # You would implement actual search here
                # Using Google Custom Search API or scraping
                
            except Exception as e:
                subdomains['search_error'] = str(e)
        
        # Method 4: DNS Crawling
        try:
            # Check common services
            services = [
                ('_ldap._tcp', 'SRV'), ('_kerberos._tcp', 'SRV'),
                ('_autodiscover._tcp', 'SRV'), ('_sip._tcp', 'SRV'),
                ('_sipfederationtls._tcp', 'SRV')
            ]
            
            resolver = dns.resolver.Resolver()
            for service, rtype in services:
                try:
                    domain = f"{service}.{self.domain}"
                    answers = resolver.resolve(domain, rtype)
                    for answer in answers:
                        target = str(answer.target).rstrip('.')
                        if target:
                            subdomains['dns_crawl'].append(target)
                            subdomains['total_unique'].add(target)
                except:
                    pass
                    
        except Exception as e:
            subdomains['crawl_error'] = str(e)
        
        # Convert set to list
        subdomains['total_unique'] = list(subdomains['total_unique'])
        
        return subdomains
    
    def detect_technologies(self):
        """Detect web technologies comprehensively"""
        technologies = {
            'web_server': {},
            'programming_languages': [],
            'frameworks': [],
            'cms': [],
            'javascript': [],
            'database': [],
            'operating_system': [],
            'cdn': [],
            'analytics': [],
            'widgets': []
        }
        
        try:
            # Try to get response
            url = f"http://{self.domain}"
            response = self.session.get(url, timeout=10, verify=False)
            content = response.text.lower()
            headers = response.headers
            
            # Web Server detection
            server = headers.get('Server', '').lower()
            if 'apache' in server:
                technologies['web_server']['name'] = 'Apache'
                if 'coyote' in server:
                    technologies['web_server']['version'] = 'Tomcat'
            elif 'nginx' in server:
                technologies['web_server']['name'] = 'Nginx'
            elif 'iis' in server:
                technologies['web_server']['name'] = 'IIS'
            elif 'cloudflare' in server:
                technologies['web_server']['name'] = 'Cloudflare'
            elif 'google' in server:
                technologies['web_server']['name'] = 'Google'
            
            # Powered-by headers
            powered_by = headers.get('X-Powered-By', '')
            if powered_by:
                technologies['powered_by'] = powered_by
            
            # Programming languages
            if 'php' in server or 'x-powered-by' in headers and 'php' in headers['x-powered-by'].lower():
                technologies['programming_languages'].append('PHP')
            
            if '.aspx' in content or 'asp.net' in content.lower() or 'x-aspnet-version' in headers:
                technologies['programming_languages'].append('ASP.NET')
                technologies['frameworks'].append('.NET')
            
            if 'jsp' in content or 'javax.servlet' in content:
                technologies['programming_languages'].append('Java')
            
            if '__VIEWSTATE' in content:
                technologies['frameworks'].append('ASP.NET Web Forms')
            
            # CMS detection
            cms_patterns = {
                'WordPress': ['wp-content', 'wp-includes', 'wp-json', 'wordpress', '/wp-admin/'],
                'Joomla': ['joomla', '/media/jui/', 'com_content', 'index.php?option=com'],
                'Drupal': ['drupal', 'sites/all/', 'sites/default/', 'Drupal.settings'],
                'Magento': ['magento', '/skin/frontend/', '/media/'],
                'Shopify': ['shopify', 'cdn.shopify.com'],
                'Wix': ['wix.com', 'static.parastorage.com'],
                'Squarespace': ['squarespace', 'static.squarespace.com'],
                'Ghost': ['ghost', 'ghost.org'],
                'Blogger': ['blogger', 'blogspot.com'],
                'Webflow': ['webflow', 'assets-global.website-files.com']
            }
            
            for cms, patterns in cms_patterns.items():
                if any(pattern.lower() in content for pattern in patterns):
                    technologies['cms'].append(cms)
            
            # JavaScript frameworks
            js_patterns = {
                'React': ['react', 'react-dom', 'createelement'],
                'Vue.js': ['vue.js', 'v-app', 'v-bind'],
                'Angular': ['angular', 'ng-', 'ng-app'],
                'jQuery': ['jquery', 'jquery.min.js'],
                'Bootstrap': ['bootstrap', 'bootstrap.min.js'],
                'Font Awesome': ['font-awesome', 'fontawesome'],
                'Google Analytics': ['google-analytics', 'ga.js', 'analytics.js'],
                'jQuery UI': ['jquery-ui', 'jqueryui'],
                'Modernizr': ['modernizr'],
                'Moment.js': ['moment.js']
            }
            
            for lib, patterns in js_patterns.items():
                if any(pattern.lower() in content for pattern in patterns):
                    technologies['javascript'].append(lib)
            
            # Database hints
            db_patterns = {
                'MySQL': ['mysql', 'mysqli'],
                'PostgreSQL': ['postgresql', 'pg_'],
                'MongoDB': ['mongodb', 'mongo'],
                'SQLite': ['sqlite'],
                'Oracle': ['oracle']
            }
            
            for db, patterns in db_patterns.items():
                if any(pattern.lower() in content for pattern in patterns):
                    technologies['database'].append(db)
            
            # CDN detection
            cdn_patterns = {
                'Cloudflare': ['cloudflare', 'cf-ray'],
                'CloudFront': ['cloudfront', 'aws'],
                'Akamai': ['akamai'],
                'Fastly': ['fastly'],
                'MaxCDN': ['maxcdn'],
                'KeyCDN': ['keycdn']
            }
            
            for cdn, patterns in cdn_patterns.items():
                if any(pattern.lower() in content or pattern.lower() in server for pattern in patterns):
                    technologies['cdn'].append(cdn)
            
            # Analytics
            analytics_patterns = {
                'Google Analytics': ['google-analytics.com', 'ga.js'],
                'Google Tag Manager': ['googletagmanager.com', 'gtm.js'],
                'Facebook Pixel': ['facebook.net', 'fbq('],
                'Hotjar': ['hotjar.com'],
                'Mixpanel': ['mixpanel.com'],
                'Segment': ['segment.com']
            }
            
            for analytic, patterns in analytics_patterns.items():
                if any(pattern.lower() in content for pattern in patterns):
                    technologies['analytics'].append(analytic)
            
        except Exception as e:
            technologies['error'] = str(e)
        
        return technologies
    
    def find_directories(self):
        """Find directories and files"""
        directories = {
            'common_directories': [],
            'common_files': [],
            'backup_files': [],
            'config_files': [],
            'login_pages': []
        }
        
        try:
            # Common directories to check
            common_dirs = [
                'admin', 'login', 'wp-admin', 'wp-login', 'dashboard',
                'control', 'api', 'test', 'dev', 'staging', 'backup',
                'config', 'install', 'setup', 'cgi-bin', 'images',
                'css', 'js', 'assets', 'static', 'uploads', 'media',
                'private', 'secret', 'hidden', 'secure', 'restricted'
            ]
            
            # Common files to check
            common_files = [
                'robots.txt', 'sitemap.xml', 'crossdomain.xml',
                'phpinfo.php', 'test.php', 'info.php', 'config.php',
                'wp-config.php', 'configuration.php', 'settings.php',
                '.git/config', '.env', '.htaccess', 'web.config',
                'README.md', 'LICENSE', 'CHANGELOG.txt'
            ]
            
            # Backup files
            backup_files = [
                'backup.zip', 'backup.tar', 'backup.tar.gz',
                'database.sql', 'dump.sql', 'backup.sql',
                'wp-content/backup', 'backups/', 'old/'
            ]
            
            # Check directories
            for directory in common_dirs:
                url = f"http://{self.domain}/{directory}/"
                try:
                    response = self.session.head(url, timeout=3)
                    if response.status_code < 400:
                        directories['common_directories'].append({
                            'path': directory,
                            'status': response.status_code,
                            'url': url
                        })
                except:
                    pass
            
            # Check files
            for file in common_files:
                url = f"http://{self.domain}/{file}"
                try:
                    response = self.session.head(url, timeout=3)
                    if response.status_code < 400:
                        directories['common_files'].append({
                            'file': file,
                            'status': response.status_code,
                            'url': url
                        })
                except:
                    pass
            
            # Look for login pages
            login_patterns = ['login', 'signin', 'auth', 'admin', 'wp-login']
            for pattern in login_patterns:
                try:
                    # Try common login URLs
                    urls = [
                        f"http://{self.domain}/{pattern}",
                        f"http://{self.domain}/{pattern}.php",
                        f"http://{self.domain}/{pattern}.html",
                        f"http://{self.domain}/admin/{pattern}"
                    ]
                    
                    for url in urls:
                        response = self.session.head(url, timeout=3)
                        if response.status_code < 400:
                            directories['login_pages'].append({
                                'url': url,
                                'status': response.status_code
                            })
                            break
                except:
                    pass
            
        except Exception as e:
            directories['error'] = str(e)
        
        return directories
    
    def harvest_emails(self):
        """Harvest email addresses"""
        emails = {
            'from_website': [],
            'from_whois': [],
            'from_search': [],
            'social_media': []
        }
        
        try:
            # Get emails from website
            try:
                url = f"http://{self.domain}"
                response = self.session.get(url, timeout=10)
                
                # Find emails in page content
                email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
                page_emails = re.findall(email_pattern, response.text)
                emails['from_website'] = list(set([e.lower() for e in page_emails]))
                
                # Also check contact pages
                contact_pages = ['contact', 'about', 'team', 'staff', 'contact-us']
                for page in contact_pages:
                    try:
                        page_url = f"{url}/{page}"
                        page_response = self.session.get(page_url, timeout=5)
                        page_emails = re.findall(email_pattern, page_response.text)
                        emails['from_website'].extend([e.lower() for e in page_emails])
                    except:
                        continue
                
                # Remove duplicates
                emails['from_website'] = list(set(emails['from_website']))
                
            except Exception as e:
                emails['website_error'] = str(e)
            
            # Get emails from WHOIS
            try:
                w = whois.whois(self.domain)
                if w.emails:
                    emails['from_whois'] = list(set([e.lower() for e in w.emails if isinstance(e, str)]))
            except:
                pass
            
            # Social media patterns (email-like usernames)
            social_patterns = [
                f'@{self.domain}',
                f'contact@{self.domain}',
                f'admin@{self.domain}',
                f'info@{self.domain}',
                f'support@{self.domain}'
            ]
            emails['social_media'] = social_patterns
            
        except Exception as e:
            emails['error'] = str(e)
        
        return emails
    
    def scan_vulnerabilities(self):
        """Scan for common vulnerabilities"""
        vulnerabilities = {
            'security_headers': {},
            'common_vulns': [],
            'wordpress_checks': [],
            'technology_specific': []
        }
        
        try:
            # Check security headers
            url = f"https://{self.domain}"
            try:
                response = self.session.get(url, timeout=10, verify=False)
                headers = response.headers
                
                security_checks = {
                    'X-Frame-Options': 'Prevents clickjacking',
                    'X-Content-Type-Options': 'Prevents MIME sniffing',
                    'X-XSS-Protection': 'Prevents XSS attacks',
                    'Content-Security-Policy': 'Prevents XSS and code injection',
                    'Strict-Transport-Security': 'Enforces HTTPS',
                    'Referrer-Policy': 'Controls referrer information'
                }
                
                for header, description in security_checks.items():
                    if header in headers:
                        vulnerabilities['security_headers'][header] = {
                            'present': True,
                            'value': headers[header],
                            'description': description
                        }
                    else:
                        vulnerabilities['security_headers'][header] = {
                            'present': False,
                            'description': description,
                            'risk': 'Medium' if header == 'Strict-Transport-Security' else 'Low'
                        }
                        
            except:
                pass
            
            # Check for common vulnerabilities
            common_checks = [
                {
                    'name': 'Directory Listing',
                    'test': f"http://{self.domain}/images/",
                    'expected': '403',
                    'vulnerable_if': '200'
                },
                {
                    'name': 'PHP Info',
                    'test': f"http://{self.domain}/phpinfo.php",
                    'expected': '404',
                    'vulnerable_if': '200'
                },
                {
                    'name': 'Test Files',
                    'test': f"http://{self.domain}/test.php",
                    'expected': '404',
                    'vulnerable_if': '200'
                }
            ]
            
            for check in common_checks:
                try:
                    response = self.session.head(check['test'], timeout=3)
                    if str(response.status_code) == check['vulnerable_if']:
                        vulnerabilities['common_vulns'].append({
                            'name': check['name'],
                            'url': check['test'],
                            'status': response.status_code,
                            'risk': 'Low'
                        })
                except:
                    pass
            
            # WordPress specific checks
            try:
                wp_url = f"http://{self.domain}/wp-login.php"
                response = self.session.head(wp_url, timeout=3)
                if response.status_code == 200:
                    vulnerabilities['wordpress_checks'].append({
                        'name': 'WordPress Login Page',
                        'url': wp_url,
                        'status': response.status_code,
                        'note': 'WordPress login page accessible'
                    })
                    
                    # Check for common WordPress files
                    wp_files = [
                        'wp-config.php', 'xmlrpc.php', 'wp-admin/install.php'
                    ]
                    
                    for wp_file in wp_files:
                        try:
                            file_url = f"http://{self.domain}/{wp_file}"
                            file_response = self.session.head(file_url, timeout=3)
                            if file_response.status_code == 200:
                                vulnerabilities['wordpress_checks'].append({
                                    'name': f'WordPress File: {wp_file}',
                                    'url': file_url,
                                    'status': file_response.status_code,
                                    'risk': 'High' if 'config' in wp_file else 'Medium'
                                })
                        except:
                            pass
                            
            except:
                pass
            
        except Exception as e:
            vulnerabilities['error'] = str(e)
        
        return vulnerabilities
    
    def get_historical_data(self):
        """Get historical website data"""
        historical = {
            'wayback_machine': [],
            'dns_history': [],
            'whois_history': []
        }
        
        try:
            # Wayback Machine
            try:
                wayback_url = f"http://web.archive.org/cdx/search/cdx?url={self.domain}/*&output=json&fl=timestamp,original&collapse=urlkey&limit=20"
                response = self.session.get(wayback_url, timeout=15)
                if response.status_code == 200:
                    data = response.json()
                    if len(data) > 1:  # First row is headers
                        historical['wayback_machine'] = [
                            {
                                'timestamp': row[0],
                                'url': row[1],
                                'archive_url': f"https://web.archive.org/web/{row[0]}/{row[1]}"
                            }
                            for row in data[1:]  # Skip header
                        ]
            except:
                pass
            
            # DNS history (simplified)
            historical['dns_history'] = {
                'note': 'For detailed DNS history, use services like SecurityTrails or RiskIQ',
                'services': [
                    'https://securitytrails.com/domain/' + self.domain,
                    'https://community.riskiq.com/search/' + self.domain,
                    'https://www.whoisrequest.com/history/' + self.domain
                ]
            }
            
            # WHOIS history
            historical['whois_history'] = {
                'note': 'WHOIS history available from various sources',
                'sources': [
                    'https://whoisology.com/' + self.domain,
                    'https://viewdns.info/whistory/?domain=' + self.domain,
                    'https://whois.ws/whois-history/' + self.domain
                ]
            }
            
        except Exception as e:
            historical['error'] = str(e)
        
        return historical
    
    def check_ssl_tls(self):
        """Check SSL/TLS configuration"""
        ssl_info = {}
        
        try:
            context = ssl.create_default_context()
            
            with socket.create_connection((self.domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)
                    
                    ssl_info = {
                        'issuer': dict(x509.get_issuer().get_components()),
                        'subject': dict(x509.get_subject().get_components()),
                        'serial_number': str(x509.get_serial_number()),
                        'version': x509.get_version(),
                        'not_before': x509.get_notBefore().decode('utf-8'),
                        'not_after': x509.get_notAfter().decode('utf-8'),
                        'signature_algorithm': x509.get_signature_algorithm().decode('utf-8'),
                        'has_expired': x509.has_expired(),
                        'ssl_version': ssock.version(),
                        'cipher': ssock.cipher()
                    }
                    
                    # Check expiration
                    from datetime import datetime
                    expires = datetime.strptime(ssl_info['not_after'], '%Y%m%d%H%M%SZ')
                    days_left = (expires - datetime.utcnow()).days
                    ssl_info['days_until_expiry'] = days_left
                    
                    if days_left < 30:
                        ssl_info['expiry_warning'] = 'Certificate expires soon!'
                    elif days_left < 0:
                        ssl_info['expiry_warning'] = 'Certificate has expired!'
        
        except Exception as e:
            ssl_info['error'] = str(e)
        
        return ssl_info