#!/usr/bin/env python3
"""
Person Intelligence Module for jsosint
"""

import re
import socket
import requests
import dns.resolver
from urllib.parse import quote
from datetime import datetime

from utils.kali_tools import KaliTools

class PersonIntel:
    """Complete person intelligence gathering"""
    
    def __init__(self, identifier):
        self.identifier = identifier
        self.results = {}
        self.kali = KaliTools()
    
    def full_recon(self):
        """Perform complete person reconnaissance"""
        print(f"[*] Starting person reconnaissance on: {self.identifier}")
        
        # Determine target type
        self.results['type'] = self.detect_target_type()
        
        # Run appropriate modules
        if self.results['type'] == 'email':
            self.results.update(self.email_recon())
        elif self.results['type'] == 'username':
            self.results.update(self.username_recon())
        elif self.results['type'] == 'phone':
            self.results.update(self.phone_recon())
        
        # Common modules
        self.results['social_media'] = self.find_social_media()
        self.results['data_breaches'] = self.check_breaches()
        self.results['public_records'] = self.search_public_records()
        
        return self.results
    
    def detect_target_type(self):
        """Detect what type of identifier this is"""
        # Check if it's an email
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if re.match(email_pattern, self.identifier):
            return 'email'
        
        # Check if it's a phone number (simplified)
        phone_pattern = r'^[\d\s\+\(\)-]{10,}$'
        clean_phone = re.sub(r'[^\d+]', '', self.identifier)
        if len(clean_phone) >= 10 and re.match(phone_pattern, self.identifier):
            return 'phone'
        
        # Otherwise assume it's a username
        return 'username'
    
    def email_recon(self):
        """Reconnaissance for email address"""
        email = self.identifier
        results = {'email_recon': {}}
        
        # Basic validation
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        is_valid = bool(re.match(email_pattern, email))
        results['email_recon']['valid_format'] = is_valid
        
        if is_valid:
            # Extract parts
            username, domain = email.split('@')
            results['email_recon']['username'] = username
            results['email_recon']['domain'] = domain
            
            # Check MX records
            try:
                resolver = dns.resolver.Resolver()
                mx_records = resolver.resolve(domain, 'MX')
                results['email_recon']['mx_records'] = [
                    str(rdata.exchange) for rdata in mx_records
                ]
            except:
                results['email_recon']['mx_records'] = []
            
            # Check if domain has website
            try:
                socket.gethostbyname(domain)
                results['email_recon']['domain_has_website'] = True
            except:
                results['email_recon']['domain_has_website'] = False
            
            # Check for disposable email domains
            disposable_domains = [
                'tempmail.com', 'guerrillamail.com', 'mailinator.com',
                '10minutemail.com', 'yopmail.com', 'trashmail.com',
                'sharklasers.com', 'grr.la', 'guerrillamail.info'
            ]
            
            results['email_recon']['is_disposable'] = any(
                domain.endswith(d) for d in disposable_domains
            )
            
            # Generate username variations
            results['email_recon']['username_variations'] = self.generate_username_variations(username)
            
            # Try to find person on the domain
            try:
                response = requests.get(f"http://{domain}", timeout=10)
                if username.lower() in response.text.lower():
                    results['email_recon']['mentioned_on_domain'] = True
                else:
                    results['email_recon']['mentioned_on_domain'] = False
            except:
                results['email_recon']['mentioned_on_domain'] = False
        
        return results
    
    def username_recon(self):
        """Reconnaissance for username"""
        username = self.identifier
        results = {'username_recon': {}}
        
        # Basic username analysis
        results['username_recon']['original'] = username
        results['username_recon']['variations'] = self.generate_username_variations(username)
        
        # Check username patterns
        patterns = {
            'contains_numbers': bool(re.search(r'\d', username)),
            'contains_special_chars': bool(re.search(r'[._-]', username)),
            'all_lowercase': username.islower(),
            'all_uppercase': username.isupper(),
            'mixed_case': username != username.lower() and username != username.upper(),
            'length': len(username)
        }
        results['username_recon']['patterns'] = patterns
        
        # Try to find real name from common patterns
        # This is a simple heuristic
        if '.' in username:
            parts = username.split('.')
            if len(parts) == 2 and len(parts[0]) > 1 and len(parts[1]) > 1:
                results['username_recon']['possible_name'] = f"{parts[0].title()} {parts[1].title()}"
        
        # Search with Sherlock (if available)
        try:
            sherlock_result = self.kali.sherlock(username)
            if sherlock_result['success']:
                # Parse Sherlock output
                lines = sherlock_result['output'].split('\n')
                social_profiles = []
                for line in lines:
                    if '[*]' in line and 'Found:' in line:
                        profile = line.split('Found:')[1].strip()
                        social_profiles.append(profile)
                results['username_recon']['sherlock_results'] = social_profiles[:10]
        except:
            pass
        
        # Search with Maigret (if available)
        try:
            maigret_result = self.kali.maigret(username)
            if maigret_result['success']:
                results['username_recon']['maigret_results'] = maigret_result['output'].split('\n')[:20]
        except:
            pass
        
        # Try to get GitHub profile info
        try:
            github_url = f"https://api.github.com/users/{username}"
            response = requests.get(github_url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                github_info = {
                    'name': data.get('name'),
                    'company': data.get('company'),
                    'location': data.get('location'),
                    'blog': data.get('blog'),
                    'bio': data.get('bio'),
                    'public_repos': data.get('public_repos'),
                    'followers': data.get('followers'),
                    'following': data.get('following'),
                    'created_at': data.get('created_at'),
                    'updated_at': data.get('updated_at')
                }
                results['username_recon']['github_info'] = github_info
        except:
            pass
        
        return results
    
    def phone_recon(self):
        """Reconnaissance for phone number"""
        phone = self.identifier
        results = {'phone_recon': {}}
        
        # Clean phone number
        clean_phone = re.sub(r'[^\d+]', '', phone)
        results['phone_recon']['clean_number'] = clean_phone
        results['phone_recon']['original'] = phone
        
        # Country code detection (simplified)
        country_codes = {
            '1': {'country': 'United States/Canada', 'code': 'US/CA'},
            '44': {'country': 'United Kingdom', 'code': 'GB'},
            '91': {'country': 'India', 'code': 'IN'},
            '61': {'country': 'Australia', 'code': 'AU'},
            '81': {'country': 'Japan', 'code': 'JP'},
            '86': {'country': 'China', 'code': 'CN'},
            '49': {'country': 'Germany', 'code': 'DE'},
            '33': {'country': 'France', 'code': 'FR'},
            '7': {'country': 'Russia', 'code': 'RU'},
            '55': {'country': 'Brazil', 'code': 'BR'}
        }
        
        if clean_phone.startswith('+'):
            results['phone_recon']['has_country_code'] = True
            for code, info in country_codes.items():
                if clean_phone.startswith(f'+{code}'):
                    results['phone_recon']['country'] = info['country']
                    results['phone_recon']['country_code'] = info['code']
                    results['phone_recon']['detected_code'] = code
                    break
        else:
            results['phone_recon']['has_country_code'] = False
        
        # Check if it's a valid length
        local_number = clean_phone.replace('+', '')
        results['phone_recon']['valid_length'] = 10 <= len(local_number) <= 15
        
        # Generate search links
        search_links = [
            f"https://www.google.com/search?q=\"{clean_phone}\"",
            f"https://www.whitepages.com/phone/{clean_phone}",
            f"https://www.spokeo.com/{clean_phone}",
            f"https://www.truepeoplesearch.com/result?phoneno={clean_phone}",
            f"https://thatsthem.com/phone/{clean_phone}"
        ]
        results['phone_recon']['search_links'] = search_links
        
        # Check for VoIP services (simplified)
        voip_patterns = {
            'Google Voice': r'^\d{3}555\d{4}$',
            'Skype': r'^\+',
            'WhatsApp': r'^\+\d{1,3}\d{9,15}$'
        }
        
        detected_services = []
        for service, pattern in voip_patterns.items():
            if re.match(pattern, clean_phone):
                detected_services.append(service)
        
        if detected_services:
            results['phone_recon']['possible_voip'] = detected_services
        
        return results
    
    def generate_username_variations(self, username):
        """Generate username variations for comprehensive searching"""
        variations = set()
        
        # Original
        variations.add(username)
        variations.add(username.lower())
        variations.add(username.upper())
        
        # Remove special characters
        clean = re.sub(r'[._-]', '', username)
        if clean != username:
            variations.add(clean)
            variations.add(clean.lower())
            variations.add(clean.upper())
        
        # Common prefixes and suffixes
        prefixes = ['the', 'real', 'official', 'mr', 'ms', 'dr', 'prof']
        suffixes = ['123', '2024', 'official', 'real', 'tv', 'hd', 'gamer', 'pro', 'x', 'xx']
        
        for prefix in prefixes:
            variations.add(f"{prefix}{username}")
            variations.add(f"{prefix}_{username}")
            variations.add(f"{prefix}{username.lower()}")
        
        for suffix in suffixes:
            variations.add(f"{username}{suffix}")
            variations.add(f"{username}_{suffix}")
            variations.add(f"{username.lower()}{suffix}")
        
        # Reverse if it looks like first.last
        if '.' in username:
            parts = username.split('.')
            if len(parts) == 2:
                variations.add(f"{parts[1]}.{parts[0]}")
                variations.add(f"{parts[1]}{parts[0]}")
                variations.add(f"{parts[0][0]}{parts[1]}")
                variations.add(f"{parts[1][0]}{parts[0]}")
        
        # Common patterns
        if len(username) > 3:
            variations.add(username[:3])
            variations.add(username[-3:])
        
        return list(variations)[:20]  # Limit to 20 variations
    
    def find_social_media(self):
        """Find social media profiles"""
        social = {}
        
        # Determine username to search
        if self.results['type'] == 'email':
            username = self.identifier.split('@')[0]
        else:
            username = self.identifier
        
        # List of social media platforms to check
        platforms = {
            'Facebook': f"https://facebook.com/{username}",
            'Twitter': f"https://twitter.com/{username}",
            'Instagram': f"https://instagram.com/{username}",
            'LinkedIn': f"https://linkedin.com/in/{username}",
            'GitHub': f"https://github.com/{username}",
            'Reddit': f"https://reddit.com/user/{username}",
            'YouTube': f"https://youtube.com/@{username}",
            'TikTok': f"https://tiktok.com/@{username}",
            'Pinterest': f"https://pinterest.com/{username}",
            'Telegram': f"https://t.me/{username}",
            'Keybase': f"https://keybase.io/{username}",
            'Snapchat': f"https://snapchat.com/add/{username}",
            'Twitch': f"https://twitch.tv/{username}",
            'Medium': f"https://medium.com/@{username}",
            'Dev.to': f"https://dev.to/{username}",
            'Hashnode': f"https://hashnode.com/@{username}",
            'Behance': f"https://behance.net/{username}",
            'Dribbble': f"https://dribbble.com/{username}",
            'Flickr': f"https://flickr.com/people/{username}"
        }
        
        # Check each platform
        for platform, url in platforms.items():
            try:
                response = requests.head(url, timeout=5, allow_redirects=True)
                if response.status_code < 400:
                    social[platform] = {
                        'found': True,
                        'url': url,
                        'status_code': response.status_code
                    }
                else:
                    social[platform] = {
                        'found': False,
                        'url': url,
                        'status_code': response.status_code
                    }
            except Exception as e:
                social[platform] = {
                    'found': False,
                    'url': url,
                    'error': str(e)
                }
        
        return social
    
    def check_breaches(self):
        """Check for data breaches"""
        # Note: For actual breach checking, you would integrate with HaveIBeenPwned API
        # This is a placeholder implementation
        breaches = {
            'note': 'For actual breach checking, integrate with HaveIBeenPwned API',
            'simulated_check': {
                'breaches_found': 0,
                'sources': ['HaveIBeenPwned', 'DeHashed', 'BreachDirectory'],
                'recommendation': 'Use --breach option with API key for real checks'
            },
            'search_links': [
                f"https://haveibeenpwned.com/account/{quote(self.identifier)}",
                f"https://dehashed.com/search?query={quote(self.identifier)}",
                f"https://breachdirectory.org/?q={quote(self.identifier)}"
            ]
        }
        
        # If it's an email, add more specific links
        if self.results['type'] == 'email':
            breaches['search_links'].extend([
                f"https://www.google.com/search?q=\"{self.identifier}\"+data+breach",
                f"https://www.google.com/search?q=\"{self.identifier}\"+leaked"
            ])
        
        return breaches
    
    def search_public_records(self):
        """Search public records"""
        records = {
            'search_links': [],
            'note': 'These are public search links. Manual verification required.'
        }
        
        identifier_encoded = quote(self.identifier)
        
        if self.results['type'] == 'email':
            records['search_links'] = [
                f"https://www.google.com/search?q=\"{self.identifier}\"",
                f"https://www.spokeo.com/email-search?q={identifier_encoded}",
                f"https://thatsthem.com/email/{identifier_encoded}",
                f"https://www.peekyou.com/{identifier_encoded}",
                f"https://www.pipl.com/search/?q={identifier_encoded}"
            ]
        
        elif self.results['type'] == 'phone':
            clean_phone = re.sub(r'[^\d+]', '', self.identifier)
            records['search_links'] = [
                f"https://www.google.com/search?q=\"{clean_phone}\"",
                f"https://www.whitepages.com/phone/{clean_phone}",
                f"https://www.spokeo.com/{clean_phone}",
                f"https://www.truepeoplesearch.com/result?phoneno={clean_phone}",
                f"https://thatsthem.com/phone/{clean_phone}"
            ]
        
        else:  # username
            records['search_links'] = [
                f"https://www.google.com/search?q=\"{self.identifier}\"",
                f"https://www.peekyou.com/{identifier_encoded}",
                f"https://www.pipl.com/search/?q={identifier_encoded}",
                f"https://www.zabasearch.com/people/{identifier_encoded}",
                f"https://www.411.com/name/{identifier_encoded}"
            ]
        
        # Add general people search engines
        records['search_links'].extend([
            f"https://www.intelius.com/people-search/{identifier_encoded}",
            f"https://www.instantcheckmate.com/search/?q={identifier_encoded}",
            f"https://www.beenverified.com/people/{identifier_encoded}"
        ])
        
        return records