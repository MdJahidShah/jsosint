#!/usr/bin/env python3
"""
Complete Person Intelligence Module
"""

import re
import socket
import requests
import dns.resolver
import json
import hashlib
from urllib.parse import quote, urlparse
from datetime import datetime
import concurrent.futures
import phonenumbers
from phonenumbers import carrier, geocoder, timezone
import html

from utils.colors import Colors

class PersonRecon:
    """Complete person reconnaissance"""
    
    def __init__(self, identifier):
        self.identifier = identifier
        self.results = {}
        self.colors = Colors()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Determine identifier type
        self.identifier_type = self._detect_identifier_type()
        
    def _detect_identifier_type(self):
        """Detect what type of identifier this is"""
        # Email pattern
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if re.match(email_pattern, self.identifier):
            return 'email'
        
        # Phone number pattern (international)
        try:
            parsed = phonenumbers.parse(self.identifier, None)
            if phonenumbers.is_valid_number(parsed):
                return 'phone'
        except:
            pass
        
        # IP address pattern
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if re.match(ip_pattern, self.identifier):
            return 'ip'
        
        # Otherwise assume username
        return 'username'
    
    def basic_analysis(self):
        """Basic analysis of the identifier"""
        analysis = {
            'identifier': self.identifier,
            'type': self.identifier_type,
            'timestamp': datetime.now().isoformat()
        }
        return analysis
    
    def _analyze_email(self):
        """Analyze email address"""
        email_info = {}
        
        try:
            # Parse email
            username, domain = self.identifier.split('@')
            email_info['username'] = username
            email_info['domain'] = domain
            
            # Email validation
            email_info['valid_format'] = True
            
            # Check disposable email domains
            disposable_domains = [
                'tempmail.com', 'guerrillamail.com', 'mailinator.com',
                '10minutemail.com', 'yopmail.com', 'trashmail.com',
                'sharklasers.com', 'grr.la', 'guerrillamail.info',
                'dispostable.com', 'maildrop.cc', 'getairmail.com'
            ]
            
            email_info['is_disposable'] = any(
                domain.endswith(d) for d in disposable_domains
            )
            
            # Check domain reputation
            email_info['domain_has_mx'] = False
            email_info['domain_has_website'] = False
            
            # Check MX records
            try:
                resolver = dns.resolver.Resolver()
                mx_records = resolver.resolve(domain, 'MX')
                email_info['mx_records'] = [str(r.exchange) for r in mx_records]
                email_info['domain_has_mx'] = len(email_info['mx_records']) > 0
            except:
                email_info['mx_records'] = []
            
            # Check if domain has website
            try:
                socket.gethostbyname(domain)
                email_info['domain_has_website'] = True
            except:
                pass
            
            # Generate username variations
            email_info['username_variations'] = self._generate_username_variations(username)
            
            # Email provider analysis
            common_providers = {
                'gmail.com': 'Google',
                'yahoo.com': 'Yahoo',
                'outlook.com': 'Microsoft',
                'hotmail.com': 'Microsoft',
                'icloud.com': 'Apple',
                'aol.com': 'AOL',
                'protonmail.com': 'ProtonMail',
                'zoho.com': 'Zoho',
                'mail.com': 'Mail.com',
                'yandex.com': 'Yandex'
            }
            
            for provider_domain, provider_name in common_providers.items():
                if domain.endswith(provider_domain):
                    email_info['provider'] = provider_name
                    break
            
            # Check for patterns in username
            patterns = {
                'contains_numbers': bool(re.search(r'\d', username)),
                'contains_dots': '.' in username,
                'contains_underscores': '_' in username,
                'contains_dashes': '-' in username,
                'all_lowercase': username.islower(),
                'length': len(username),
                'possible_name': self._extract_possible_name(username)
            }
            email_info['patterns'] = patterns
            
            # Generate Gravatar hash
            email_hash = hashlib.md5(self.identifier.strip().lower().encode()).hexdigest()
            email_info['gravatar_hash'] = email_hash
            email_info['gravatar_url'] = f"https://www.gravatar.com/avatar/{email_hash}"
            
        except Exception as e:
            email_info['error'] = str(e)
        
        return email_info
    
    def _analyze_phone(self):
        """Analyze phone number"""
        phone_info = {}
        
        try:
            # Parse phone number
            parsed = phonenumbers.parse(self.identifier)
            
            phone_info = {
                'valid': phonenumbers.is_valid_number(parsed),
                'format_international': phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
                'format_national': phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL),
                'format_e164': phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
                'country_code': parsed.country_code,
                'national_number': parsed.national_number,
                'extension': parsed.extension
            }
            
            # Get carrier info
            try:
                carrier_name = carrier.name_for_number(parsed, "en")
                if carrier_name:
                    phone_info['carrier'] = carrier_name
            except:
                pass
            
            # Get geographic info
            try:
                region = geocoder.description_for_number(parsed, "en")
                if region:
                    phone_info['region'] = region
            except:
                pass
            
            # Get timezone
            try:
                timezones = timezone.time_zones_for_number(parsed)
                if timezones:
                    phone_info['timezones'] = timezones
            except:
                pass
            
            # Check if mobile
            phone_info['is_mobile'] = phonenumbers.number_type(parsed) == phonenumbers.PhoneNumberType.MOBILE
            
            # Number type
            number_types = {
                phonenumbers.PhoneNumberType.MOBILE: 'Mobile',
                phonenumbers.PhoneNumberType.FIXED_LINE: 'Fixed Line',
                phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: 'Fixed Line or Mobile',
                phonenumbers.PhoneNumberType.TOLL_FREE: 'Toll Free',
                phonenumbers.PhoneNumberType.PREMIUM_RATE: 'Premium Rate',
                phonenumbers.PhoneNumberType.SHARED_COST: 'Shared Cost',
                phonenumbers.PhoneNumberType.VOIP: 'VoIP',
                phonenumbers.PhoneNumberType.PERSONAL_NUMBER: 'Personal Number',
                phonenumbers.PhoneNumberType.PAGER: 'Pager',
                phonenumbers.PhoneNumberType.UAN: 'UAN',
                phonenumbers.PhoneNumberType.VOICEMAIL: 'Voicemail',
                phonenumbers.PhoneNumberType.UNKNOWN: 'Unknown'
            }
            
            num_type = phonenumbers.number_type(parsed)
            phone_info['number_type'] = number_types.get(num_type, 'Unknown')
            
            # Generate search links
            clean_number = self.identifier.replace('+', '').replace(' ', '').replace('-', '').replace('(', '').replace(')', '')
            phone_info['search_links'] = [
                f"https://www.google.com/search?q=\"{clean_number}\"",
                f"https://www.whitepages.com/phone/{clean_number}",
                f"https://www.spokeo.com/{clean_number}",
                f"https://www.truepeoplesearch.com/result?phoneno={clean_number}",
                f"https://thatsthem.com/phone/{clean_number}",
                f"https://www.zabasearch.com/phone/{clean_number}"
            ]
            
        except Exception as e:
            phone_info['error'] = str(e)
        
        return phone_info
    
    def _analyze_ip(self):
        """Analyze IP address"""
        ip_info = {}
        
        try:
            import ipaddress
            
            ip_obj = ipaddress.ip_address(self.identifier)
            
            ip_info = {
                'version': 'IPv4' if ip_obj.version == 4 else 'IPv6',
                'is_private': ip_obj.is_private,
                'is_reserved': ip_obj.is_reserved,
                'is_multicast': ip_obj.is_multicast,
                'is_global': ip_obj.is_global,
                'is_loopback': ip_obj.is_loopback,
                'is_link_local': ip_obj.is_link_local
            }
            
            # Try to get geolocation
            try:
                response = self.session.get(f"http://ip-api.com/json/{self.identifier}", timeout=5)
                if response.status_code == 200:
                    geo_data = response.json()
                    if geo_data.get('status') == 'success':
                        ip_info['geolocation'] = {
                            'country': geo_data.get('country'),
                            'countryCode': geo_data.get('countryCode'),
                            'region': geo_data.get('regionName'),
                            'city': geo_data.get('city'),
                            'zip': geo_data.get('zip'),
                            'lat': geo_data.get('lat'),
                            'lon': geo_data.get('lon'),
                            'timezone': geo_data.get('timezone'),
                            'isp': geo_data.get('isp'),
                            'org': geo_data.get('org'),
                            'as': geo_data.get('as')
                        }
            except:
                pass
            
            # Try to get reverse DNS
            try:
                hostname = socket.gethostbyaddr(self.identifier)[0]
                ip_info['reverse_dns'] = hostname
            except:
                ip_info['reverse_dns'] = None
            
            # Threat intelligence links
            ip_info['threat_intel_links'] = [
                f"https://www.virustotal.com/gui/ip-address/{self.identifier}",
                f"https://www.abuseipdb.com/check/{self.identifier}",
                f"https://otx.alienvault.com/indicator/ip/{self.identifier}",
                f"https://www.shodan.io/host/{self.identifier}",
                f"https://censys.io/ipv4/{self.identifier}",
                f"https://www.threatcrowd.org/ip.php?ip={self.identifier}"
            ]
            
        except Exception as e:
            ip_info['error'] = str(e)
        
        return ip_info
    
    def _analyze_username(self):
        """Analyze username"""
        username_info = {}

        try:
            username = self.identifier

            # Basic info
            username_info = {
                'username': username,
                'length': len(username),
                'lowercase': username.lower(),
                'uppercase': username.upper()
            }

            # Pattern analysis
            patterns = {
                'contains_numbers': bool(re.search(r'\d', username)),
                'contains_letters': bool(re.search(r'[a-zA-Z]', username)),
                'contains_special_chars': bool(re.search(r'[._-]', username)),
                'all_lowercase': username.islower(),
                'all_uppercase': username.isupper(),
                'starts_with_number': username[0].isdigit() if username else False,
                'ends_with_number': username[-1].isdigit() if username else False,
                'only_alphanumeric': username.isalnum(),
                'has_spaces': ' ' in username
            }
            username_info['patterns'] = patterns

            # Use merged method to get possible names and variations
            possible_and_variations = self.extract_possible_and_variations()
            if possible_and_variations:
                # Extract possible name part
                if 'first_name' in possible_and_variations:
                    username_info['first_name_guess'] = possible_and_variations['first_name']
                    username_info['last_name_guess'] = possible_and_variations['last_name']
                elif 'name_guess' in possible_and_variations:
                    username_info['name_guess'] = possible_and_variations['name_guess']

                # Add variations list
                username_info['variations'] = possible_and_variations.get('variations', [])

            # Detect common username patterns
            if '.' in username and len(username.split('.')) == 2:
                parts = username.split('.')
                username_info['pattern_detected'] = 'first.last'
                username_info['first_name_guess'] = parts[0].capitalize()
                username_info['last_name_guess'] = parts[1].capitalize()

            # Check for common handles
            common_handles = ['admin', 'root', 'test', 'user', 'demo', 'guest']
            if username.lower() in common_handles:
                username_info['is_common_handle'] = True
                username_info['common_handle_type'] = 'System/Test Account'

        except Exception as e:
            username_info['error'] = str(e)

        return username_info

    def extract_possible_and_variations(self):
        """Extract possible name from username and generate username variations."""
        username = self.identifier
        result = {}

        # ----------------- Extract possible name -----------------
        name_parts = re.split(r'[._-]', username)
        if len(name_parts) >= 2:
            result['first_name'] = name_parts[0].capitalize()
            result['last_name'] = name_parts[1].capitalize()
        elif len(name_parts) == 1 and len(name_parts[0]) > 3:
            result['name_guess'] = name_parts[0].capitalize()
        
        # Ensure result always has something
        if not result:
            result['name_guess'] = username.capitalize()

        # ----------------- Generate username variations -----------------
        variations = set()

        # Basic variations
        variations.add(username)
        variations.add(username.lower())
        variations.add(username.upper())
        variations.add(username.capitalize())

        # Add common prefixes/suffixes
        prefixes = ['the', 'real', 'official', 'its', 'mr', 'ms', 'dr']
        suffixes = ['123', '01', '2020', '2021', 'xyz', 'abc']

        for prefix in prefixes:
            variations.add(f"{prefix}{username}")
            variations.add(f"{prefix}_{username}")
            variations.add(f"{prefix}.{username}")

        for suffix in suffixes:
            variations.add(f"{username}{suffix}")
            variations.add(f"{username}_{suffix}")
            variations.add(f"{username}.{suffix}")

        # Leet speak variations
        leet_map = str.maketrans('aeios', '43105')
        leet_username = username.translate(leet_map)
        variations.add(leet_username)

        # Add variations to result
        result['variations'] = sorted(list(variations))
        result['total_variations'] = len(variations)

        return result

    def email_analysis(self):
        """Comprehensive email analysis"""
        if self.identifier_type != 'email':
            return {'error': 'Identifier is not an email address'}
        
        email_info = self._analyze_email()
        
        # Additional email-specific checks
        try:
            # Check email deliverability (simplified)
            username, domain = self.identifier.split('@')
            
            # Check common email services
            email_services = {
                'gmail.com': {'api': False, 'webmail': 'https://mail.google.com'},
                'yahoo.com': {'api': False, 'webmail': 'https://mail.yahoo.com'},
                'outlook.com': {'api': False, 'webmail': 'https://outlook.live.com'},
                'hotmail.com': {'api': False, 'webmail': 'https://outlook.live.com'},
                'icloud.com': {'api': False, 'webmail': 'https://www.icloud.com/mail'},
                'aol.com': {'api': False, 'webmail': 'https://mail.aol.com'},
                'protonmail.com': {'api': False, 'webmail': 'https://mail.protonmail.com'}
            }
            
            for service_domain, info in email_services.items():
                if domain.endswith(service_domain):
                    email_info['email_service'] = service_domain
                    email_info['webmail_url'] = info['webmail']
                    break
            
            # Check for email patterns in breaches
            email_info['breach_check_note'] = 'Use --breaches flag for detailed breach checking'
            
            # Generate OSINT search links
            encoded_email = quote(self.identifier)
            email_info['osint_links'] = [
                f"https://www.google.com/search?q=\"{self.identifier}\"",
                f"https://epieos.com/?q={encoded_email}",
                f"https://www.thatsthem.com/email/{encoded_email}",
                f"https://www.spokeo.com/email-search?q={encoded_email}",
                f"https://www.peekyou.com/{encoded_email}",
                f"https://haveibeenpwned.com/account/{encoded_email}"
            ]
            
            # Check for social media with email
            email_info['social_with_email'] = [
                f"https://www.facebook.com/search/people/?q={encoded_email}",
                f"https://www.linkedin.com/sales/gmail/profile/viewByEmail/{encoded_email}",
                f"https://twitter.com/search?q={encoded_email}&src=typed_query"
            ]
            
        except Exception as e:
            email_info['analysis_error'] = str(e)
        
        return email_info
    
    def check_breaches(self):
        """Check for data breaches"""
        breaches = {
            'found': False,
            'breaches': [],
            'sources_checked': [],
            'note': 'For detailed breach data, API keys may be required'
        }
        
        try:
            # Have I Been Pwned (public API, rate limited)
            try:
                # Hash the email for privacy
                email_hash = hashlib.sha1(self.identifier.lower().encode()).hexdigest().upper()
                prefix = email_hash[:5]
                
                response = self.session.get(
                    f"https://api.pwnedpasswords.com/range/{prefix}",
                    timeout=10
                )
                
                if response.status_code == 200:
                    hashes = response.text.split('\n')
                    for line in hashes:
                        if line.startswith(email_hash[5:]):
                            count = line.split(':')[1].strip()
                            breaches['found'] = True
                            breaches['breaches'].append({
                                'source': 'Have I Been Pwned',
                                'count': int(count),
                                'note': 'Password exposed in data breaches'
                            })
                            break
                
                breaches['sources_checked'].append('Have I Been Pwned')
                
            except Exception as e:
                breaches['hibp_error'] = str(e)
            
            # DeHashed (would require API key)
            breaches['dehashed_note'] = 'DeHashed requires API key for search'
            
            # Generate search links for manual checking
            encoded_identifier = quote(self.identifier)
            breaches['manual_check_links'] = [
                f"https://www.google.com/search?q=\"{self.identifier}\"+data+breach",
                f"https://www.google.com/search?q=\"{self.identifier}\"+leaked",
                f"https://www.google.com/search?q=\"{self.identifier}\"+password+leak",
                f"https://dehashed.com/search?query={encoded_identifier}",
                f"https://breachdirectory.org/?q={encoded_identifier}",
                f"https://leakcheck.io/search?q={encoded_identifier}"
            ]
            
            # Common breach databases
            breaches['breach_databases'] = [
                'Have I Been Pwned',
                'DeHashed',
                'BreachDirectory',
                'LeakCheck',
                'We Leak Info',
                'Snusbase'
            ]
            
        except Exception as e:
            breaches['error'] = str(e)
        
        return breaches
    
    def search_public_records(self):
        """Search public records"""
        records = {
            'search_engines': [],
            'people_search': [],
            'court_records': [],
            'property_records': [],
            'business_records': [],
            'note': 'These are search links for manual investigation'
        }
        
        try:
            encoded = quote(self.identifier)
            
            # General search engines
            records['search_engines'] = [
                f"https://www.google.com/search?q=\"{self.identifier}\"",
                f"https://www.bing.com/search?q=\"{self.identifier}\"",
                f"https://duckduckgo.com/?q=\"{self.identifier}\"",
                f"https://yandex.com/search/?text=\"{self.identifier}\""
            ]
            
            # People search engines
            records['people_search'] = [
                f"https://www.spokeo.com/{encoded}",
                f"https://www.whitepages.com/name/{encoded}",
                f"https://www.intelius.com/people-search/{encoded}",
                f"https://www.peekyou.com/{encoded}",
                f"https://www.pipl.com/search/?q={encoded}",
                f"https://www.zabasearch.com/people/{encoded}",
                f"https://www.truepeoplesearch.com/results?name={encoded}",
                f"https://www.instantcheckmate.com/search/?q={encoded}",
                f"https://www.beenverified.com/people/{encoded}"
            ]
            
            # Court and legal records (US specific)
            records['court_records'] = [
                "https://www.pacer.gov/ (Federal Court Records)",
                "https://unicourt.com/",
                "https://www.courthousenews.com/",
                "https://www.findlaw.com/case-law.html"
            ]
            
            # Property records
            records['property_records'] = [
                "https://www.zillow.com/",
                "https://www.realtor.com/",
                "https://www.redfin.com/",
                "https://www.trulia.com/"
            ]
            
            # Business records
            records['business_records'] = [
                "https://opencorporates.com/",
                "https://www.bloomberg.com/professional/",
                "https://www.sec.gov/edgar/searchedgar/companysearch.html",
                "https://www.dnb.com/"
            ]
            
            # Specialized OSINT tools
            records['osint_tools'] = [
                "https://osintframework.com/",
                "https://start.me/p/wMdQMQ/osint",
                "https://github.com/jivoi/awesome-osint",
                "https://inteltechniques.com/tools/",
                "https://www.osintcombine.com/"
            ]
            
            # Social media deep search
            if self.identifier_type == 'username':
                records['social_deep_search'] = [
                    f"https://whatsmyname.app/?q={encoded}",
                    f"https://namechk.com/?u={encoded}",
                    f"https://checkusernames.com/",
                    f"https://knowem.com/checkusernames.php"
                ]
            
        except Exception as e:
            records['error'] = str(e)
        
        return records
    
    def find_associated_accounts(self):
        """Find accounts associated with the identifier"""
        accounts = {
            'github': [],
            'gitlab': [],
            'bitbucket': [],
            'stack_overflow': [],
            'reddit': [],
            'hackernews': [],
            'product_hunt': [],
            'other_platforms': []
        }
        
        try:
            username = self.identifier if self.identifier_type == 'username' else self.identifier.split('@')[0]
            
            # Developer platforms
            dev_platforms = [
                ('GitHub', f'https://api.github.com/users/{username}', 'login'),
                ('GitLab', f'https://gitlab.com/api/v4/users?username={username}', 'username'),
                ('Bitbucket', f'https://api.bitbucket.org/2.0/users/{username}', 'username'),
                ('StackOverflow', f'https://api.stackexchange.com/2.3/users?order=desc&sort=reputation&inname={username}&site=stackoverflow', 'display_name')
            ]
            
            for platform_name, api_url, field_name in dev_platforms:
                try:
                    response = self.session.get(api_url, timeout=5)
                    if response.status_code == 200:
                        data = response.json()
                        
                        if platform_name == 'GitHub':
                            if 'login' in data:
                                accounts['github'].append({
                                    'username': data['login'],
                                    'name': data.get('name'),
                                    'company': data.get('company'),
                                    'blog': data.get('blog'),
                                    'location': data.get('location'),
                                    'email': data.get('email'),
                                    'hireable': data.get('hireable'),
                                    'bio': data.get('bio'),
                                    'public_repos': data.get('public_repos'),
                                    'followers': data.get('followers'),
                                    'following': data.get('following'),
                                    'created_at': data.get('created_at'),
                                    'updated_at': data.get('updated_at'),
                                    'url': data.get('html_url')
                                })
                        
                        elif platform_name == 'GitLab':
                            if data and isinstance(data, list) and len(data) > 0:
                                user = data[0]
                                accounts['gitlab'].append({
                                    'username': user.get('username'),
                                    'name': user.get('name'),
                                    'state': user.get('state'),
                                    'avatar_url': user.get('avatar_url'),
                                    'web_url': user.get('web_url'),
                                    'created_at': user.get('created_at')
                                })
                
                except Exception as e:
                    accounts[f'{platform_name.lower()}_error'] = str(e)
            
            # Other platforms (manual check links)
            accounts['other_platforms'] = [
                {'name': 'Reddit', 'url': f'https://www.reddit.com/user/{username}'},
                {'name': 'Hacker News', 'url': f'https://news.ycombinator.com/user?id={username}'},
                {'name': 'Product Hunt', 'url': f'https://www.producthunt.com/@{username}'},
                {'name': 'Keybase', 'url': f'https://keybase.io/{username}'},
                {'name': 'Dev.to', 'url': f'https://dev.to/{username}'},
                {'name': 'Medium', 'url': f'https://medium.com/@{username}'},
                {'name': 'Hashnode', 'url': f'https://hashnode.com/@{username}'},
                {'name': 'Behance', 'url': f'https://www.behance.net/{username}'},
                {'name': 'Dribbble', 'url': f'https://dribbble.com/{username}'},
                {'name': 'Flickr', 'url': f'https://www.flickr.com/people/{username}'}
            ]
            
        except Exception as e:
            accounts['error'] = str(e)
        
        return accounts
    #website domain parser
    def domain_url_analysis(self):
        """
        Check whether domains based on the identifier are registered or available
        """
        results = {
            "query": self.identifier,
            "checked_domains": []
        }

        # Common TLDs to test
        tlds = [
            "com", "net", "org", "io", "info", "ai"
            "co", "xyz", "dev", "app", "me", "online"
        ]

        base = self.identifier.lower().strip()

        try:
            import whois
        except ImportError:
            results["error"] = "python-whois not installed"
            return results

        for tld in tlds:
            domain = f"{base}.{tld}"
            entry = {
                "domain": domain,
                "registered": False,
                "details": {}
            }

            try:
                w = whois.whois(domain)

                # If WHOIS returns domain_name, it is registered
                if w.domain_name:
                    entry["registered"] = True
                    entry["details"] = {
                        "registrar": w.registrar,
                        "creation_date": str(w.creation_date),
                        "expiration_date": str(w.expiration_date),
                        "name_servers": w.name_servers
                    }

            except Exception:
                # WHOIS failed → very likely available
                entry["registered"] = False

            results["checked_domains"].append(entry)

        return results
    
    def SocialMediaScan(self):
        profiles = {
            "found_profiles": [],
            "search_links": []
        }

        # Resolve username safely
        if self.identifier_type == "username":
            username = self.identifier
        elif "@" in self.identifier:
            username = self.identifier.split("@")[0]
        else:
            username = self.identifier

        encoded_username = quote(username)

        platforms = [
            "facebook.com",
            "twitter.com",
            "instagram.com",
            "linkedin.com",
            "github.com",
            "reddit.com",
            "tiktok.com",
            "medium.com",
            "pinterest.com",
            "tumblr.com",
            "youtube.com",
            "threads.com"
        ]

        # Prevent 403 blocks
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (OSINT Research)"
        })

        for platform in platforms:
            profile_url = f"https://{platform}/{username}"

            try:
                r = self.session.get(
                    profile_url,
                    timeout=6,
                    allow_redirects=True
                )

                # 200 = exists
                # 301/302 = exists but redirects
                # 403 = exists but blocked
                if r.status_code in (200, 301, 302, 403):
                    profiles["found_profiles"].append(profile_url)

            except Exception:
                pass

            # Always add manual search links
            profiles["search_links"].append(
                f"https://www.google.com/search?q=site:{platform}+\"{encoded_username}\""
            )

        return profiles


    def generate_report(self, format='json'):
        """Generate comprehensive report"""
        report = {
            'identifier': self.identifier,
            'type': self.identifier_type,
            'timestamp': datetime.now().isoformat(),
            'analysis': self.basic_analysis()
        }
        
        # Add additional sections if available
        if self.identifier_type == 'email':
            report['email_analysis'] = self.email_analysis()
        
        report['breach_check'] = self.check_breaches()
        report['public_records'] = self.search_public_records()
        
        if self.identifier_type in ['username', 'email']:
            username = self.identifier if self.identifier_type == 'username' else self.identifier.split('@')[0]
            report['associated_accounts'] = self.find_associated_accounts()
        
        return report