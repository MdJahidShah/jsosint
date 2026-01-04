#!/usr/bin/env python3
"""
Advanced OSINT Intelligence Module
Advanced techniques and integration with external services
"""

import requests
import json
import re
import time
import hashlib
import base64
from urllib.parse import quote, urlparse, parse_qs
from datetime import datetime, timedelta
import concurrent.futures
import feedparser
from bs4 import BeautifulSoup
import xml.etree.ElementTree as ET
import csv
import os

from utils.colors import Colors

class AdvancedOSINT:
    """Advanced OSINT techniques and integrations"""
    
    def __init__(self, api_keys=None):
        self.colors = Colors()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        self.api_keys = api_keys or {}
        
        # External service configurations
        self.services = {
            'shodan': {
                'base_url': 'https://api.shodan.io',
                'requires_key': True
            },
            'censys': {
                'base_url': 'https://search.censys.io/api/v2',
                'requires_key': True
            },
            'virustotal': {
                'base_url': 'https://www.virustotal.com/api/v3',
                'requires_key': True
            },
            'hunterio': {
                'base_url': 'https://api.hunter.io/v2',
                'requires_key': True
            },
            'breachdirectory': {
                'base_url': 'https://breachdirectory.p.rapidapi.com',
                'requires_key': True
            },
            'securitytrails': {
                'base_url': 'https://api.securitytrails.com/v1',
                'requires_key': True
            },
            'fullcontact': {
                'base_url': 'https://api.fullcontact.com/v3',
                'requires_key': True
            }
        }
    
    def full_osint(self, target, scan_type='auto'):
        """Complete OSINT gathering with all available methods"""
        results = {
            'target': target,
            'scan_type': scan_type,
            'timestamp': datetime.now().isoformat(),
            'modules': {}
        }
        
        print(f"{self.colors.CYAN}[*]{self.colors.RESET} Starting advanced OSINT on: {target}")
        
        try:
            # Determine target type
            target_type = self._detect_target_type(target)
            results['detected_type'] = target_type
            
            # Run appropriate scans
            if target_type in ['domain', 'ip']:
                results['modules']['network_intel'] = self.network_intelligence(target)
                results['modules']['domain_intel'] = self.domain_intelligence(target)
                results['modules']['threat_intel'] = self.threat_intelligence(target)
                
                if self._has_api_key('shodan'):
                    results['modules']['shodan_scan'] = self.shodan_search(target)
                
                if self._has_api_key('censys'):
                    results['modules']['censys_scan'] = self.censys_search(target)
                
                if self._has_api_key('virustotal'):
                    results['modules']['virustotal_scan'] = self.virustotal_scan(target)
                
                if self._has_api_key('securitytrails'):
                    results['modules']['securitytrails_scan'] = self.securitytrails_scan(target)
            
            elif target_type in ['email', 'username']:
                results['modules']['person_intel'] = self.person_intelligence(target)
                results['modules']['social_intel'] = self.social_intelligence(target)
                
                if target_type == 'email' and self._has_api_key('hunterio'):
                    results['modules']['hunterio_scan'] = self.hunterio_email_search(target)
                
                if self._has_api_key('breachdirectory'):
                    results['modules']['breach_check'] = self.breachdirectory_search(target)
                
                if self._has_api_key('fullcontact'):
                    results['modules']['fullcontact_scan'] = self.fullcontact_lookup(target)
            
            # Always run these
            results['modules']['web_intel'] = self.web_intelligence(target)
            results['modules']['image_intel'] = self.image_intelligence(target)
            results['modules']['metadata_intel'] = self.metadata_intelligence(target)
            results['modules']['dark_web_monitor'] = self.dark_web_monitoring(target)
            
            # Generate intelligence report
            results['intelligence_report'] = self.generate_intelligence_report(results['modules'])
            
        except Exception as e:
            results['error'] = str(e)
            import traceback
            results['traceback'] = traceback.format_exc()
        
        return results
    
    def _detect_target_type(self, target):
        """Detect target type"""
        # IP address pattern
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if re.match(ip_pattern, target):
            return 'ip'
        
        # Domain pattern
        domain_pattern = r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if re.match(domain_pattern, target) and ' ' not in target:
            return 'domain'
        
        # Email pattern
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if re.match(email_pattern, target):
            return 'email'
        
        # Assume username
        return 'username'
    
    def _has_api_key(self, service):
        """Check if API key is available for a service"""
        if service in self.api_keys:
            key = self.api_keys[service]
            if isinstance(key, dict):
                return all(v for v in key.values() if v)
            return bool(key)
        return False
    
    def network_intelligence(self, target):
        """Advanced network intelligence"""
        intel = {
            'target': target,
            'geolocation': {},
            'asn_info': {},
            'reverse_dns': [],
            'dns_history': [],
            'whois_history': []
        }
        
        try:
            # Geolocation using free IP API
            if self._detect_target_type(target) == 'ip':
                try:
                    response = self.session.get(f"http://ip-api.com/json/{target}", timeout=5)
                    if response.status_code == 200:
                        data = response.json()
                        if data.get('status') == 'success':
                            intel['geolocation'] = {
                                'country': data.get('country'),
                                'countryCode': data.get('countryCode'),
                                'region': data.get('regionName'),
                                'city': data.get('city'),
                                'zip': data.get('zip'),
                                'lat': data.get('lat'),
                                'lon': data.get('lon'),
                                'timezone': data.get('timezone'),
                                'isp': data.get('isp'),
                                'org': data.get('org'),
                                'as': data.get('as')
                            }
                except:
                    pass
            
            # ASN information using Team Cymru
            try:
                import socket
                query = f"begin\nverbose\n{target}\nend\n"
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect(("whois.cymru.com", 43))
                sock.send(query.encode())
                response = b""
                while True:
                    data = sock.recv(1024)
                    if not data:
                        break
                    response += data
                sock.close()
                
                lines = response.decode().split('\n')
                if len(lines) > 1:
                    parts = lines[1].split('|')
                    if len(parts) >= 5:
                        intel['asn_info'] = {
                            'asn': parts[0].strip(),
                            'ip_range': parts[1].strip(),
                            'as_name': parts[2].strip(),
                            'country': parts[3].strip(),
                            'registry': parts[4].strip()
                        }
            except:
                pass
            
            # Reverse DNS
            try:
                import socket
                hostname, aliases, ips = socket.gethostbyaddr(target)
                intel['reverse_dns'] = [hostname] + aliases
            except:
                pass
            
            # DNS history links
            intel['dns_history_links'] = [
                f"https://securitytrails.com/domain/{target}",
                f"https://community.riskiq.com/search/{target}",
                f"https://www.whoisrequest.com/history/{target}"
            ]
            
            # WHOIS history links
            intel['whois_history_links'] = [
                f"https://whoisology.com/{target}",
                f"https://viewdns.info/whistory/?domain={target}",
                f"https://whois.ws/whois-history/{target}"
            ]
            
        except Exception as e:
            intel['error'] = str(e)
        
        return intel
    
    def domain_intelligence(self, domain):
        """Advanced domain intelligence"""
        intel = {
            'domain': domain,
            'subdomain_takeover': [],
            'dns_security': {},
            'ssl_certificates': [],
            'historical_changes': []
        }
        
        try:
            # Check for subdomain takeover patterns
            common_services = [
                ('Amazon S3', 'amazonaws.com'),
                ('GitHub Pages', 'github.io'),
                ('Heroku', 'herokuapp.com'),
                ('Azure', 'azurewebsites.net'),
                ('Google Cloud', 'appspot.com'),
                ('Shopify', 'myshopify.com'),
                ('WordPress', 'wordpress.com'),
                ('Tumblr', 'tumblr.com')
            ]
            
            # Check CNAME records for takeover potential
            try:
                import dns.resolver
                resolver = dns.resolver.Resolver()
                try:
                    cname_records = resolver.resolve(domain, 'CNAME')
                    for record in cname_records:
                        cname = str(record.target).rstrip('.')
                        for service_name, pattern in common_services:
                            if pattern in cname:
                                intel['subdomain_takeover'].append({
                                    'service': service_name,
                                    'cname': cname,
                                    'vulnerable': True,
                                    'note': f'Potential subdomain takeover on {service_name}'
                                })
                except:
                    pass
            except:
                pass
            
            # DNS security checks
            dns_checks = {
                'SPF': False,
                'DMARC': False,
                'DKIM': False,
                'DNSSEC': False
            }
            
            try:
                import dns.resolver
                resolver = dns.resolver.Resolver()
                
                # Check SPF
                try:
                    txt_records = resolver.resolve(domain, 'TXT')
                    for record in txt_records:
                        if 'v=spf1' in str(record).lower():
                            dns_checks['SPF'] = True
                            intel['dns_security']['spf_record'] = str(record)
                except:
                    pass
                
                # Check DMARC
                try:
                    dmarc_domain = f'_dmarc.{domain}'
                    dmarc_records = resolver.resolve(dmarc_domain, 'TXT')
                    for record in dmarc_records:
                        if 'v=dmarc1' in str(record).lower():
                            dns_checks['DMARC'] = True
                            intel['dns_security']['dmarc_record'] = str(record)
                except:
                    pass
                
                # Check DNSSEC
                try:
                    dnskey_records = resolver.resolve(domain, 'DNSKEY')
                    if dnskey_records:
                        dns_checks['DNSSEC'] = True
                except:
                    pass
                
            except:
                pass
            
            intel['dns_security']['checks'] = dns_checks
            
            # SSL certificate information
            try:
                import ssl
                import socket
                from cryptography import x509
                from cryptography.hazmat.backends import default_backend
                
                context = ssl.create_default_context()
                with socket.create_connection((domain, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert_bin = ssock.getpeercert(binary_form=True)
                        cert = x509.load_der_x509_certificate(cert_bin, default_backend())
                        
                        intel['ssl_certificates'].append({
                            'issuer': dict(cert.issuer.rdns),
                            'subject': dict(cert.subject.rdns),
                            'serial_number': cert.serial_number,
                            'version': cert.version,
                            'not_valid_before': cert.not_valid_before.isoformat(),
                            'not_valid_after': cert.not_valid_after.isoformat(),
                            'signature_hash_algorithm': cert.signature_hash_algorithm.name if hasattr(cert.signature_hash_algorithm, 'name') else str(cert.signature_hash_algorithm),
                            'has_expired': cert.not_valid_after < datetime.now()
                        })
            except:
                pass
            
            # Historical changes (placeholder for actual historical data)
            intel['historical_changes'] = {
                'note': 'Historical data available from specialized services',
                'services': [
                    'SecurityTrails',
                    'RiskIQ',
                    'DomainTools',
                    'WhoisHistory'
                ]
            }
            
        except Exception as e:
            intel['error'] = str(e)
        
        return intel
    
    def threat_intelligence(self, target):
        """Threat intelligence gathering"""
        threat = {
            'target': target,
            'reputation': {},
            'blacklists': [],
            'malware_checks': [],
            'threat_feeds': []
        }
        
        try:
            # Check various blacklists
            blacklists = [
                ('Google Safe Browsing', f'https://transparencyreport.google.com/safe-browsing/search?url={target}'),
                ('PhishTank', f'https://www.phishtank.com/search.php?q={target}'),
                ('URLhaus', f'https://urlhaus.abuse.ch/browse.php?search={target}'),
                ('ThreatFox', f'https://threatfox.abuse.ch/browse.php?search={target}'),
                ('MalwareDomainList', f'http://www.malwaredomainlist.com/mdl.php?search={target}')
            ]
            
            threat['blacklist_checks'] = []
            for bl_name, bl_url in blacklists:
                threat['blacklist_checks'].append({
                    'service': bl_name,
                    'check_url': bl_url
                })
            
            # Malware checks
            threat['malware_checks'] = [
                {
                    'service': 'VirusTotal',
                    'url': f'https://www.virustotal.com/gui/domain/{target}',
                    'requires_api': True
                },
                {
                    'service': 'AbuseIPDB',
                    'url': f'https://www.abuseipdb.com/check/{target}',
                    'requires_api': False
                },
                {
                    'service': 'AlienVault OTX',
                    'url': f'https://otx.alienvault.com/indicator/domain/{target}',
                    'requires_api': False
                },
                {
                    'service': 'ThreatCrowd',
                    'url': f'https://www.threatcrowd.org/domain.php?domain={target}',
                    'requires_api': False
                }
            ]
            
            # Threat feeds
            threat['threat_feeds'] = [
                'https://feeds.dshield.org/block.txt',
                'https://rules.emergingthreats.net/blockrules/compromised-ips.txt',
                'https://reputation.alienvault.com/reputation.data',
                'https://www.binarydefense.com/banlist.txt'
            ]
            
            # Automated blacklist check (simplified)
            dnsbl_servers = [
                'zen.spamhaus.org',
                'bl.spamcop.net',
                'dnsbl.sorbs.net',
                'b.barracudacentral.org'
            ]
            
            if self._detect_target_type(target) == 'ip':
                threat['dnsbl_checks'] = []
                for dnsbl in dnsbl_servers:
                    try:
                        import socket
                        reversed_ip = '.'.join(reversed(target.split('.')))
                        lookup = f"{reversed_ip}.{dnsbl}"
                        socket.gethostbyname(lookup)
                        threat['dnsbl_checks'].append({
                            'server': dnsbl,
                            'listed': True
                        })
                    except socket.gaierror:
                        threat['dnsbl_checks'].append({
                            'server': dnsbl,
                            'listed': False
                        })
                    except:
                        pass
            
        except Exception as e:
            threat['error'] = str(e)
        
        return threat
    
    def shodan_search(self, query):
        """Search Shodan for information"""
        if not self._has_api_key('shodan'):
            return {'error': 'Shodan API key required'}
        
        results = {}
        
        try:
            api_key = self.api_keys['shodan']
            base_url = self.services['shodan']['base_url']
            
            # Host search
            response = self.session.get(f"{base_url}/shodan/host/search", 
                                       params={'key': api_key, 'query': query},
                                       timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                results['host_search'] = data
            
            # DNS information
            response = self.session.get(f"{base_url}/dns/domain/{query}",
                                       params={'key': api_key},
                                       timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                results['dns_info'] = data
            
            # API info
            response = self.session.get(f"{base_url}/api-info",
                                       params={'key': api_key},
                                       timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                results['api_info'] = data
            
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def censys_search(self, query):
        """Search Censys for information"""
        if not self._has_api_key('censys'):
            return {'error': 'Censys API key required'}
        
        results = {}
        
        try:
            # Censys requires ID and Secret
            if isinstance(self.api_keys['censys'], dict):
                api_id = self.api_keys['censys'].get('id')
                api_secret = self.api_keys['censys'].get('secret')
                
                if not api_id or not api_secret:
                    return {'error': 'Censys requires both ID and Secret'}
                
                # Search hosts
                import base64
                auth = base64.b64encode(f"{api_id}:{api_secret}".encode()).decode()
                headers = {'Authorization': f'Basic {auth}'}
                
                # Determine search endpoint based on query type
                if self._detect_target_type(query) == 'ip':
                    endpoint = f"/hosts/{query}"
                else:
                    endpoint = "/hosts/search"
                    query = f"services.tls.certificates.leaf_data.subject.common_name:\"{query}\""
                
                response = self.session.get(f"{self.services['censys']['base_url']}{endpoint}",
                                           headers=headers,
                                           params={'q': query} if 'search' in endpoint else {},
                                           timeout=10)
                
                if response.status_code == 200:
                    results['search_results'] = response.json()
                
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def virustotal_scan(self, target):
        """Scan with VirusTotal"""
        if not self._has_api_key('virustotal'):
            return {'error': 'VirusTotal API key required'}
        
        results = {}
        
        try:
            api_key = self.api_keys['virustotal']
            headers = {'x-apikey': api_key}
            base_url = self.services['virustotal']['base_url']
            
            target_type = self._detect_target_type(target)
            
            if target_type in ['domain', 'ip']:
                # Get domain/ip report
                endpoint = f"/{'domains' if target_type == 'domain' else 'ip_addresses'}/{target}"
                response = self.session.get(f"{base_url}{endpoint}",
                                           headers=headers,
                                           timeout=10)
                
                if response.status_code == 200:
                    results['report'] = response.json()
                
                # Get comments
                response = self.session.get(f"{base_url}{endpoint}/comments",
                                           headers=headers,
                                           timeout=5)
                
                if response.status_code == 200:
                    results['comments'] = response.json()
                
                # Get votes
                response = self.session.get(f"{base_url}{endpoint}/votes",
                                           headers=headers,
                                           timeout=5)
                
                if response.status_code == 200:
                    results['votes'] = response.json()
            
            elif target_type == 'url':
                # For URLs, we need to submit for analysis
                url_id = base64.urlsafe_b64encode(target.encode()).decode().strip("=")
                
                response = self.session.get(f"{base_url}/urls/{url_id}",
                                           headers=headers,
                                           timeout=10)
                
                if response.status_code == 200:
                    results['url_report'] = response.json()
            
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def hunterio_email_search(self, email):
        """Search Hunter.io for email information"""
        if not self._has_api_key('hunterio'):
            return {'error': 'Hunter.io API key required'}
        
        results = {}
        
        try:
            api_key = self.api_keys['hunterio']
            
            # Email verification
            response = self.session.get(f"{self.services['hunterio']['base_url']}/email-verifier",
                                       params={'email': email, 'api_key': api_key},
                                       timeout=10)
            
            if response.status_code == 200:
                results['verification'] = response.json()
            
            # Email finder (domain search)
            domain = email.split('@')[1]
            response = self.session.get(f"{self.services['hunterio']['base_url']}/domain-search",
                                       params={'domain': domain, 'api_key': api_key, 'limit': 10},
                                       timeout=10)
            
            if response.status_code == 200:
                results['domain_search'] = response.json()
            
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def breachdirectory_search(self, query):
        """Search BreachDirectory for breached data"""
        if not self._has_api_key('breachdirectory'):
            return {'error': 'BreachDirectory API key required'}
        
        results = {}
        
        try:
            api_key = self.api_keys['breachdirectory']
            headers = {
                'x-rapidapi-key': api_key,
                'x-rapidapi-host': 'breachdirectory.p.rapidapi.com'
            }
            
            # Determine query type
            if '@' in query:  # Email
                endpoint = '?func=auto&term='
            else:  # Username
                endpoint = '?func=username&term='
            
            response = self.session.get(f"{self.services['breachdirectory']['base_url']}{endpoint}{query}",
                                       headers=headers,
                                       timeout=10)
            
            if response.status_code == 200:
                results['breach_data'] = response.json()
            
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def securitytrails_scan(self, domain):
        """Scan with SecurityTrails"""
        if not self._has_api_key('securitytrails'):
            return {'error': 'SecurityTrails API key required'}
        
        results = {}
        
        try:
            api_key = self.api_keys['securitytrails']
            headers = {'APIKEY': api_key}
            
            # Domain details
            response = self.session.get(f"{self.services['securitytrails']['base_url']}/domain/{domain}/details",
                                       headers=headers,
                                       timeout=10)
            
            if response.status_code == 200:
                results['domain_details'] = response.json()
            
            # Subdomains
            response = self.session.get(f"{self.services['securitytrails']['base_url']}/domain/{domain}/subdomains",
                                       headers=headers,
                                       timeout=10)
            
            if response.status_code == 200:
                results['subdomains'] = response.json()
            
            # DNS history
            response = self.session.get(f"{self.services['securitytrails']['base_url']}/history/{domain}/dns/a",
                                       headers=headers,
                                       timeout=10)
            
            if response.status_code == 200:
                results['dns_history'] = response.json()
            
            # WHOIS history
            response = self.session.get(f"{self.services['securitytrails']['base_url']}/history/{domain}/whois",
                                       headers=headers,
                                       timeout=10)
            
            if response.status_code == 200:
                results['whois_history'] = response.json()
            
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def fullcontact_lookup(self, identifier):
        """Lookup with FullContact (Person API)"""
        if not self._has_api_key('fullcontact'):
            return {'error': 'FullContact API key required'}
        
        results = {}
        
        try:
            api_key = self.api_keys['fullcontact']
            headers = {'Authorization': f'Bearer {api_key}'}
            
            # Determine identifier type
            if '@' in identifier:  # Email
                endpoint = '/person.enrich'
                data = {'email': identifier}
            else:  # Probably a name/company
                endpoint = '/company.enrich'
                data = {'domain': identifier}
            
            response = self.session.post(f"{self.services['fullcontact']['base_url']}{endpoint}",
                                        headers=headers,
                                        json=data,
                                        timeout=10)
            
            if response.status_code == 200:
                results['enrichment'] = response.json()
            
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def person_intelligence(self, identifier):
        """Advanced person intelligence"""
        intel = {
            'identifier': identifier,
            'digital_footprint': {},
            'professional_info': {},
            'education_info': {},
            'financial_insights': []
        }
        
        try:
            # Digital footprint analysis
            footprint = {}
            
            # Check for common username patterns
            if '@' not in identifier:  # Username
                # Check common platforms
                common_platforms = [
                    'GitHub', 'Twitter', 'LinkedIn', 'Instagram',
                    'Reddit', 'YouTube', 'Facebook', 'Twitch'
                ]
                
                for platform in common_platforms:
                    # This would be implemented with actual API calls
                    # For now, we'll create placeholders
                    footprint[platform] = {
                        'likely_present': True,
                        'confidence': 'medium',
                        'check_method': 'pattern_analysis'
                    }
            
            intel['digital_footprint'] = footprint
            
            # Professional information (placeholder)
            intel['professional_info'] = {
                'sources': ['LinkedIn', 'GitHub', 'Company websites'],
                'note': 'Use professional networking sites and portfolios'
            }
            
            # Education information (placeholder)
            intel['education_info'] = {
                'sources': ['LinkedIn', 'Alumni networks', 'Research papers'],
                'note': 'Check educational institutions and publications'
            }
            
            # Financial insights (very limited public info)
            intel['financial_insights'] = [
                'Property records (public databases)',
                'Business registrations',
                'Professional licenses',
                'Court records (bankruptcy, liens)'
            ]
            
            # Generate investigation leads
            intel['investigation_leads'] = self._generate_person_leads(identifier)
            
        except Exception as e:
            intel['error'] = str(e)
        
        return intel
    
    def social_intelligence(self, identifier):
        """Advanced social intelligence"""
        intel = {
            'identifier': identifier,
            'social_network_analysis': {},
            'influence_metrics': {},
            'content_analysis': {},
            'sentiment_analysis': {}
        }
        
        try:
            # Social network analysis
            network_analysis = {
                'network_size': 'unknown',
                'engagement_level': 'unknown',
                'platform_diversity': 'unknown',
                'network_centrality': 'unknown'
            }
            
            # Influence metrics (placeholder)
            influence = {
                'reach': 'unknown',
                'authority': 'unknown',
                'engagement_rate': 'unknown',
                'content_frequency': 'unknown'
            }
            
            # Content analysis
            content = {
                'topics': [],
                'tone': 'unknown',
                'controversy_level': 'unknown',
                'professionalism': 'unknown'
            }
            
            # Sentiment analysis (would require NLP)
            sentiment = {
                'overall_sentiment': 'neutral',
                'positive_topics': [],
                'negative_topics': [],
                'controversial_topics': []
            }
            
            intel['social_network_analysis'] = network_analysis
            intel['influence_metrics'] = influence
            intel['content_analysis'] = content
            intel['sentiment_analysis'] = sentiment
            
            # Generate social insights
            intel['social_insights'] = self._generate_social_insights(identifier)
            
        except Exception as e:
            intel['error'] = str(e)
        
        return intel
    
    def web_intelligence(self, target):
        """Web intelligence gathering"""
        web_intel = {
            'target': target,
            'wayback_machine': [],
            'archived_content': [],
            'website_changes': [],
            'hidden_content': []
        }
        
        try:
            # Wayback Machine
            try:
                wayback_url = f"http://web.archive.org/cdx/search/cdx?url={target}/*&output=json&fl=timestamp,original,mimetype,statuscode,length&collapse=timestamp:6&limit=20"
                response = self.session.get(wayback_url, timeout=15)
                if response.status_code == 200:
                    data = response.json()
                    if len(data) > 1:
                        web_intel['wayback_machine'] = [
                            {
                                'timestamp': row[0],
                                'url': row[1],
                                'type': row[2],
                                'status': row[3],
                                'size': row[4] if len(row) > 4 else 'N/A',
                                'archive_url': f"https://web.archive.org/web/{row[0]}/{row[1]}"
                            }
                            for row in data[1:]  # Skip header
                        ]
            except:
                pass
            
            # Common hidden paths check
            hidden_paths = [
                '/robots.txt',
                '/sitemap.xml',
                '/.git/HEAD',
                '/.env',
                '/wp-config.php',
                '/config.php',
                '/phpinfo.php',
                '/test.php',
                '/admin/',
                '/administrator/',
                '/backup/',
                '/backups/',
                '/old/',
                '/tmp/',
                '/temp/',
                '/logs/',
                '/error_log'
            ]
            
            for path in hidden_paths:
                try:
                    url = f"http://{target}{path}" if not target.startswith('http') else f"{target}{path}"
                    response = self.session.head(url, timeout=3, allow_redirects=True)
                    if response.status_code < 400:
                        web_intel['hidden_content'].append({
                            'path': path,
                            'url': url,
                            'status': response.status_code
                        })
                except:
                    pass
            
            # Website change detection (placeholder)
            web_intel['website_changes'] = {
                'note': 'For change detection, use services like:',
                'services': [
                    'VisualPing',
                    'ChangeTower',
                    'Versionista',
                    'Distill.io'
                ]
            }
            
        except Exception as e:
            web_intel['error'] = str(e)
        
        return web_intel
    
    def image_intelligence(self, target):
        """Image intelligence and reverse image search"""
        img_intel = {
            'target': target,
            'reverse_image_search': [],
            'exif_data': {},
            'image_analysis': {}
        }
        
        try:
            # Reverse image search links
            # Note: For actual reverse image search, you'd need to download the image
            # and upload to services or use their APIs
            
            encoded_target = quote(target)
            img_intel['reverse_image_search'] = [
                {
                    'service': 'Google Images',
                    'url': f'https://images.google.com/searchbyimage?image_url={encoded_target}',
                    'method': 'URL search'
                },
                {
                    'service': 'TinEye',
                    'url': f'https://tineye.com/search?url={encoded_target}',
                    'method': 'URL search'
                },
                {
                    'service': 'Yandex Images',
                    'url': f'https://yandex.com/images/search?url={encoded_target}&rpt=imageview',
                    'method': 'URL search'
                },
                {
                    'service': 'Bing Visual Search',
                    'url': f'https://www.bing.com/images/search?q=imgurl:{encoded_target}',
                    'method': 'URL search'
                }
            ]
            
            # EXIF data extraction (if target is an image URL)
            try:
                response = self.session.get(target, timeout=5)
                if response.status_code == 200 and 'image' in response.headers.get('Content-Type', ''):
                    # Save image temporarily to extract EXIF
                    import tempfile
                    with tempfile.NamedTemporaryFile(suffix='.jpg', delete=False) as tmp:
                        tmp.write(response.content)
                        tmp_path = tmp.name
                    
                    try:
                        from PIL import Image
                        from PIL.ExifTags import TAGS
                        
                        image = Image.open(tmp_path)
                        exif_data = image._getexif()
                        
                        if exif_data:
                            decoded_exif = {}
                            for tag_id, value in exif_data.items():
                                tag = TAGS.get(tag_id, tag_id)
                                decoded_exif[tag] = value
                            
                            img_intel['exif_data'] = decoded_exif
                        
                        # Basic image analysis
                        img_intel['image_analysis'] = {
                            'format': image.format,
                            'mode': image.mode,
                            'size': image.size,
                            'width': image.width,
                            'height': image.height
                        }
                        
                    except:
                        pass
                    
                    # Clean up
                    import os
                    os.unlink(tmp_path)
                    
            except:
                pass
            
        except Exception as e:
            img_intel['error'] = str(e)
        
        return img_intel
    
    def metadata_intelligence(self, target):
        """Metadata intelligence from various sources"""
        meta_intel = {
            'target': target,
            'document_metadata': {},
            'code_repositories': [],
            'paste_sites': [],
            'forums_discussions': []
        }
        
        try:
            # Document metadata (placeholder for actual extraction)
            meta_intel['document_metadata'] = {
                'note': 'For document metadata analysis, upload files to:',
                'tools': [
                    'MetaShield',
                    'ExifTool',
                    'FOCA',
                    'Metadata2Go'
                ]
            }
            
            # Code repositories search
            if '@' not in target and '.' not in target:  # Likely username
                meta_intel['code_repositories'] = [
                    {
                        'platform': 'GitHub',
                        'url': f'https://github.com/{target}',
                        'search_url': f'https://github.com/search?q={target}&type=users'
                    },
                    {
                        'platform': 'GitLab',
                        'url': f'https://gitlab.com/{target}',
                        'search_url': f'https://gitlab.com/search?search={target}'
                    },
                    {
                        'platform': 'Bitbucket',
                        'url': f'https://bitbucket.org/{target}',
                        'search_url': f'https://bitbucket.org/repo/all?name={target}'
                    }
                ]
            
            # Paste sites search (Need to complete from here)
            paste_sites = [
                ('Pastebin', f'https://pastebin.com/u/{target}'),
                ('Ghostbin', f'https://ghostbin.com/user/{target}'),
                ('Hastebin', f'https://hastebin.com/user/{target}'),
                ('Slexy', f'https://slexy.org/user/{target}')
            ]
            meta_intel['paste_sites'] = [
                {
                    'site': site,
                    'url': url
                }
                for site, url in paste_sites
            ]
            # Forums and discussions search (placeholder)
            meta_intel['forums_discussions'] = {
                'note': 'Search forums and discussion boards using site-specific search or Google dorking',
                'example_dorks': [
                    f'site:reddit.com "{target}"',
                    f'site:stackoverflow.com "{target}"',
                    f'site:quora.com "{target}"',
                    f'site:4chan.org "{target}"'
                ]
            }
        except Exception as e:
            meta_intel['error'] = str(e)
        return meta_intel
            # DNS security checks
            dns_checks = {
                'DNSSEC': False,
                'CNAME_flattening': False,
                'DANE': False
            }
            
            try:
                import dns.resolver
                
                resolver = dns.resolver.Resolver()
                
                # Check CNAME flattening
                try:
                    cname_records = resolver.resolve(domain, 'CNAME')
                    if cname_records:
                        dns_checks['CNAME_flattening'] = True
                except:
                    pass
                
                # Check DANE
                try:
                    tlsa_records = resolver.resolve(domain, 'TLSA')
                    if tlsa_records:
                        dns_checks['DANE'] = True
                except:
                    pass
                # Check DNSSEC
                try:
                    dnssec_records = resolver.resolve(domain, 'DNSKEY')
                    if dnssec_records:
                        dns_checks['DNSSEC'] = True
                except:
                    pass
            intel['dns_security_checks'] = dns_checks
            # SSL/TLS certificate analysis
            try:
                import ssl
                import socket
                from cryptography import x509
                from cryptography.hazmat.backends import default_backend
                
                context = ssl.create_default_context()
                with socket.create_connection((domain, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        der_cert = ssock.getpeercert(binary_form=True)
                        cert = x509.load_der_x509_certificate(der_cert, default_backend())
                        
                        intel['ssl_tls_certificate'] = {
                            'subject': dict(cert.subject.rdns),
                            'issuer': dict(cert.issuer.rdns),
                            'valid_from': cert.not_valid_before.isoformat(),
                            'valid_to': cert.not_valid_after.isoformat(),
                            'serial_number': cert.serial_number,
                            'signature_algorithm': cert.signature_algorithm_oid._name
                        }
            except:
                pass
            # Generate investigation leads
            intel['investigation_leads'] = self._generate_domain_leads(domain)
        except Exception as e:
            intel['error'] = str(e)
        return intel
            # Threat intelligence checks
            threat = {
            'target': target,
            'blacklist_checks': [],
            'malware_checks': [],
            'threat_feeds': [], 
            'dnsbl_checks': []
        }
        try:
            # Blacklist checks
            blacklists = [
                ('Spamhaus', f'https://www.spamhaus.org/query/ip/{target}'),
                ('SURBL', f'http://www.surbl.org/lookup/{target}'),
                ('URIBL', f'http://www.uribl.com/?query={target}'),
                ('Phishing Database', f'https://www.phishingdatabase.com/phishingdb/check.php?domain={target}'),
                ('Malware Domain List', f'https://www.malwaredomainlist.com/mdl.php?search={target}'),
                ('URLhaus', f'https://urlhaus.abuse.ch/browse.php?search={target}'),
                ('OpenPhish', f'https://openphish.com/search/?q={target}'),
                ('ThreatMiner', f'https://www.threatminer.org/domain.php?q={target}'),
                ('VirusTotal', f'https://www.virustotal.com/gui/domain/{target}/detection'),
                ('PhishTank', f'https://www.phishtank.com/checkurl/?url={target}'),
                ('CyberCrime Tracker', f'http://cybercrime-tracker.net/index.php?search={target}'),
                ('Malc0de Database', f'http://malc0de.com/database/index.php?search={target}'),
                ('ZeuS Tracker', f'http://zeustracker.abuse.ch/monitor.php?host={target}'),
                ('Ransomware Tracker', f'https://ransomwaretracker.abuse.ch/tracker/search/?search={target}'),
                ('Botvrij.eu', f'https://botvrij.eu/lookup.php?ip={target}'),
                ('ThreatCrowd', f'https://www.threatcrowd.org/domain.php?domain={target}')
            ]
            for name, url in blacklists:
                threat['blacklist_checks'].append({
                    'service': name,
                    'url': url,
                    'requires_api': False
                })
            # Malware checks (placeholders)
            malware_services = [
                'Malware Domain List',
                'URLhaus',
                'VirusTotal',
                'ThreatMiner'
            ]
            for service in malware_services:
                threat['malware_checks'].append({
                    'service': service,
                    'note': f'Check {service} for malware associations with {target}'
                })
            # Threat feeds (placeholders)
            threat_feeds = [
                'AlienVault OTX',
                'Abuse.ch Feeds',
                'PhishTank',
                'Malware Domain List',
                'URLhaus',
                'Spamhaus DROP Lists'
            ]
            for feed in threat_feeds:
                threat['threat_feeds'].append({
                    'feed': feed,
                    'note': f'Ingest data from {feed} for monitoring {target}'
                })
            # DNSBL checks
            dnsbl_servers = [
                'zen.spamhaus.org',
                'bl.spamcop.net',
                'b.barracudacentral.org',
                'dnsbl.sorbs.net',
                'psbl.surriel.com',
                'cbl.abuseat.org',
                'dnsbl.dronebl.org'
            ]
            for dnsbl in dnsbl_servers:
                threat['dnsbl_checks'].append({
                    'dnsbl': dnsbl,
                    'query': f'{target}.{dnsbl}'
                })
        except Exception as e:
            threat['error'] = str(e)
        return threat
    def shodan_search(self, query):
        """Search Shodan for information"""
        if not self._has_api_key('shodan'):
            return {'error': 'Shodan API key required'}
        results = {}
        try:
            api_key = self.api_keys['shodan']
            base_url = self.services['shodan']['base_url']
            # Host search
            response = self.session.get(f"{base_url}/shodan/host/search",
                                       params={'key': api_key, 'query': query},
                                        timeout=10)
            if response.status_code == 200:
                data = response.json()
                results['host_search'] = data
            # DNS info
            response = self.session.get(f"{base_url}/shodan/dns/info",
                                       params={'key': api_key, 'domain': query},
                                       timeout=5)
            if response.status_code == 200:
                data = response.json()
                results['dns_info'] = data
            # API info
            response = self.session.get(f"{base_url}/shodan/api-info",
                                       params={'key': api_key},
                                       timeout=5)
            if response.status_code == 200:
                data = response.json()
                results['api_info'] = data
        except Exception as e:
            results['error'] = str(e)
        return results
    def censys_search(self, query):
        """Search Censys for information"""
        if not self._has_api_key('censys'):
            return {'error': 'Censys API key required'}
        results = {}
        # Complete the code for Censys search
        try:
            # Censys API ID and Secret
            if isinstance(self.api_keys['censys'], str):
                api_id = self.api_keys['censys']
                api_secret = ''
            elif isinstance(self.api_keys['censys'], dict):
                api_id = self.api_keys['censys'].get('id', '')
                api_secret = self.api_keys['censys'].get('secret', '')
            else:
                api_id = ''
                api_secret = ''
            if api_id and api_secret:
                import base64
                auth = base64.b64encode(f"{api_id}:{api_secret}".encode()).decode()
                headers = {'Authorization: f'Basic {auth}'}
                # Determine query type
                target_type = self._detect_target_type(query)
                if target_type == 'ip':
                    endpoint = f"/v1/hosts/{query}"
                elif target_type == 'domain':
                    endpoint = f"/v1/domains/{query}"
                else:
                    endpoint = "/v1/search/hosts"
                response = self.session.get(f"{self.services['censys']['base_url']}{endpoint}",
                                           headers=headers,
                                           params={'q': query} if target_type not in ['ip', 'domain'] else {},
                                           timeout=10)
                if response.status_code == 200:
                    results['search_results'] = response.json()
        except Exception as e:
            results['error'] = str(e)
        return results
    def virustotal_search(self, target):
        """Search VirusTotal for information"""
        if not self._has_api_key('virustotal'):
            return {'error': 'VirusTotal API key required'}
        results = {}
        try:
            api_key = self.api_keys['virustotal']
            headers = {'x-apikey': api_key}
            base_url = self.services['virustotal']['base_url']
            target_type = self._detect_target_type(target)
            if target_ty    pe in ['domain', 'ip']:
                # Get general report
                endpoint = f"/vtapi/v2/{'domain/report' if target_type == 'domain' else 'ip-address/report'}"
                response = self.session.get(f"{base_url}{endpoint}",
                                             params={'domain' if target_type == 'domain' else 'ip': target},
                                             headers=headers,
                                             timeout=10)
                if response.status_code == 200:
                    results['general_report'] = response.json() 
                # Get comments
                response = self.session.get(f"{base_url}{endpoint}/comments",
                                             headers=headers,
                                             timeout=5)
                if response.status_code == 200:
                    results['comments'] = response.json()
                # Get votes
                response = self.session.get(f"{base_url}{endpoint}/votes",
                                             headers=headers,
                                             timeout=5)
                if response.status_code == 200:
                    results['votes'] = response.json()
            elif target_type == 'url':
                # URL report
                import base64
                url_id = base64.urlsafe_b64encode(target.encode()).decode().strip('=')
                response = self.session.get(f"{base_url}/vtapi/v2/url/report",
                                             params={'resource': url_id},
                                             headers=headers,
                                                timeout=10)
                if response.status_code == 200:
                    results['url_report'] = response.json()
            elif target_type == 'file_hash':
                # File report
                response = self.session.get(f"{base_url}/vtapi/v2/file/report",
                                             params={'resource': target},
                                             headers=headers,
                                             timeout=10)
                if response.status_code == 200:
                    results['file_report'] = response.json()        
        except Exception as e:
            results['error'] = str(e)
    return results

        # Advanced Toolskit end, will update more modules later