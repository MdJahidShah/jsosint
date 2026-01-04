#!/usr/bin/env python3
"""
Complete Social Media Intelligence Module
"""

import requests
import json
import re
import time
from urllib.parse import quote
from datetime import datetime
import concurrent.futures
from bs4 import BeautifulSoup

from utils.colors import Colors

class SocialMediaFinder:
    """Social media intelligence gathering"""
    
    def __init__(self):
        self.colors = Colors()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Platform configurations
        self.platforms = {
            'GitHub': {
                'url': 'https://github.com/{}',
                'api': 'https://api.github.com/users/{}',
                'check_method': 'api'
            },
            'Twitter': {
                'url': 'https://twitter.com/{}',
                'check_method': 'status_code'
            },
            'Instagram': {
                'url': 'https://instagram.com/{}',
                'check_method': 'status_code'
            },
            'Facebook': {
                'url': 'https://facebook.com/{}',
                'check_method': 'status_code'
            },
            'LinkedIn': {
                'url': 'https://linkedin.com/in/{}',
                'check_method': 'status_code'
            },
            'Reddit': {
                'url': 'https://reddit.com/user/{}',
                'api': 'https://www.reddit.com/user/{}/about.json',
                'check_method': 'api'
            },
            'YouTube': {
                'url': 'https://youtube.com/@{}',
                'check_method': 'status_code'
            },
            'TikTok': {
                'url': 'https://tiktok.com/@{}',
                'check_method': 'status_code'
            },
            'Pinterest': {
                'url': 'https://pinterest.com/{}',
                'check_method': 'status_code'
            },
            'Telegram': {
                'url': 'https://t.me/{}',
                'check_method': 'status_code'
            },
            'Keybase': {
                'url': 'https://keybase.io/{}',
                'check_method': 'status_code'
            },
            'Snapchat': {
                'url': 'https://snapchat.com/add/{}',
                'check_method': 'status_code'
            },
            'Twitch': {
                'url': 'https://twitch.tv/{}',
                'api': 'https://api.twitch.tv/helix/users?login={}',
                'check_method': 'api',
                'headers': {'Client-ID': 'kimne78kx3ncx6brgo4mv6wki5h1ko'}
            },
            'Medium': {
                'url': 'https://medium.com/@{}',
                'check_method': 'status_code'
            },
            'Dev.to': {
                'url': 'https://dev.to/{}',
                'check_method': 'status_code'
            },
            'Hashnode': {
                'url': 'https://hashnode.com/@{}',
                'check_method': 'status_code'
            },
            'Behance': {
                'url': 'https://behance.net/{}',
                'check_method': 'status_code'
            },
            'Dribbble': {
                'url': 'https://dribbble.com/{}',
                'check_method': 'status_code'
            },
            'Flickr': {
                'url': 'https://flickr.com/people/{}',
                'check_method': 'status_code'
            },
            'GitLab': {
                'url': 'https://gitlab.com/{}',
                'api': 'https://gitlab.com/api/v4/users?username={}',
                'check_method': 'api'
            },
            'Bitbucket': {
                'url': 'https://bitbucket.org/{}',
                'api': 'https://api.bitbucket.org/2.0/users/{}',
                'check_method': 'api'
            },
            'StackOverflow': {
                'url': 'https://stackoverflow.com/users/{}',
                'api': 'https://api.stackexchange.com/2.3/users/{}?order=desc&sort=reputation&site=stackoverflow',
                'check_method': 'api'
            },
            'HackerNews': {
                'url': 'https://news.ycombinator.com/user?id={}',
                'check_method': 'status_code'
            },
            'ProductHunt': {
                'url': 'https://www.producthunt.com/@{}',
                'check_method': 'status_code'
            }
        }
    
    def search_all_platforms(self, username, deep_search=False):
        """Search for username across all platforms"""
        results = {
            'username': username,
            'timestamp': datetime.now().isoformat(),
            'platforms': {},
            'summary': {
                'found': 0,
                'not_found': 0,
                'errors': 0
            }
        }
        
        print(f"{self.colors.CYAN}[*]{self.colors.RESET} Searching for '{username}' across {len(self.platforms)} platforms")
        
        # Use threading for faster searches
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_platform = {
                executor.submit(self._check_platform, platform_name, config, username, deep_search): platform_name
                for platform_name, config in self.platforms.items()
            }
            
            for future in concurrent.futures.as_completed(future_to_platform):
                platform_name = future_to_platform[future]
                try:
                    platform_result = future.result(timeout=10)
                    results['platforms'][platform_name] = platform_result
                    
                    if platform_result.get('found'):
                        results['summary']['found'] += 1
                        print(f"  {self.colors.GREEN}✓{self.colors.RESET} {platform_name}: Found")
                    else:
                        results['summary']['not_found'] += 1
                        if not deep_search:  # Only show not found in quick mode
                            print(f"  {self.colors.RED}✗{self.colors.RESET} {platform_name}: Not found")
                    
                except Exception as e:
                    results['platforms'][platform_name] = {'error': str(e)}
                    results['summary']['errors'] += 1
                    print(f"  {self.colors.YELLOW}!{self.colors.RESET} {platform_name}: Error - {str(e)[:50]}")
        
        print(f"\n{self.colors.GREEN}[+]{self.colors.RESET} Found on {results['summary']['found']} platforms")
        
        # Generate summary
        found_platforms = [name for name, data in results['platforms'].items() if data.get('found')]
        if found_platforms:
            results['found_on'] = found_platforms
        
        return results
    
    def _check_platform(self, platform_name, config, username, deep_search=False):
        """Check a specific platform"""
        result = {
            'platform': platform_name,
            'username': username,
            'url': config['url'].format(username),
            'found': False,
            'checked_at': datetime.now().isoformat()
        }
        
        try:
            check_method = config.get('check_method', 'status_code')
            
            if check_method == 'api' and 'api' in config:
                # Use API if available
                api_url = config['api'].format(username)
                headers = config.get('headers', {})
                
                response = self.session.get(api_url, headers=headers, timeout=5)
                
                if response.status_code == 200:
                    data = response.json()
                    
                    # Platform-specific parsing
                    if platform_name == 'GitHub':
                        if 'login' in data and data['login'].lower() == username.lower():
                            result['found'] = True
                            result['profile_data'] = self._parse_github_profile(data)
                    
                    elif platform_name == 'Reddit':
                        if 'data' in data and data['data'].get('name', '').lower() == username.lower():
                            result['found'] = True
                            result['profile_data'] = self._parse_reddit_profile(data)
                    
                    elif platform_name == 'GitLab':
                        if data and isinstance(data, list) and len(data) > 0:
                            user = data[0]
                            if user.get('username', '').lower() == username.lower():
                                result['found'] = True
                                result['profile_data'] = user
                    
                    elif platform_name == 'Twitch':
                        if 'data' in data and data['data']:
                            user = data['data'][0]
                            if user.get('login', '').lower() == username.lower():
                                result['found'] = True
                                result['profile_data'] = user
                    
                    elif platform_name == 'StackOverflow':
                        if 'items' in data and data['items']:
                            user = data['items'][0]
                            if user.get('display_name', '').lower() == username.lower():
                                result['found'] = True
                                result['profile_data'] = user
            
            else:
                # Use status code check
                url = config['url'].format(username)
                response = self.session.head(url, timeout=5, allow_redirects=True)
                
                # Platform-specific status code logic
                if platform_name == 'Instagram':
                    # Instagram often returns 200 even for non-existent profiles
                    # Need to check page content
                    if response.status_code == 200:
                        try:
                            full_response = self.session.get(url, timeout=5)
                            if 'Sorry, this page isn\'t available.' in full_response.text:
                                result['found'] = False
                            else:
                                result['found'] = True
                        except:
                            result['found'] = False
                
                elif platform_name == 'Twitter':
                    if response.status_code == 200:
                        result['found'] = True
                    elif response.status_code == 404:
                        result['found'] = False
                    else:
                        # Check for rate limiting
                        if response.status_code == 429:
                            result['error'] = 'Rate limited'
                        result['found'] = False
                
                elif platform_name in ['Facebook', 'LinkedIn']:
                    # These often redirect or show different pages
                    if response.status_code in [200, 302]:
                        result['found'] = True
                    else:
                        result['found'] = False
                
                else:
                    # Default logic
                    result['found'] = response.status_code < 400
            
            # Deep search if requested and profile found
            if deep_search and result['found'] and 'profile_data' not in result:
                result['profile_data'] = self._deep_search_profile(platform_name, username, config['url'].format(username))
        
        except requests.exceptions.Timeout:
            result['error'] = 'Request timeout'
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _parse_github_profile(self, data):
        """Parse GitHub profile data"""
        profile = {
            'name': data.get('name'),
            'company': data.get('company'),
            'blog': data.get('blog'),
            'location': data.get('location'),
            'email': data.get('email'),
            'hireable': data.get('hireable'),
            'bio': data.get('bio'),
            'public_repos': data.get('public_repos'),
            'public_gists': data.get('public_gists'),
            'followers': data.get('followers'),
            'following': data.get('following'),
            'created_at': data.get('created_at'),
            'updated_at': data.get('updated_at'),
            'avatar_url': data.get('avatar_url'),
            'html_url': data.get('html_url')
        }
        
        # Clean up company field
        if profile['company']:
            profile['company'] = profile['company'].strip('@')
        
        return profile
    
    def _parse_reddit_profile(self, data):
        """Parse Reddit profile data"""
        user_data = data.get('data', {})
        
        profile = {
            'name': user_data.get('name'),
            'created_utc': user_data.get('created_utc'),
            'link_karma': user_data.get('link_karma'),
            'comment_karma': user_data.get('comment_karma'),
            'is_gold': user_data.get('is_gold'),
            'is_mod': user_data.get('is_mod'),
            'verified': user_data.get('verified'),
            'has_verified_email': user_data.get('has_verified_email'),
            'icon_img': user_data.get('icon_img'),
            'total_karma': user_data.get('total_karma'),
            'subreddit': user_data.get('subreddit', {})
        }
        
        return profile
    
    def _deep_search_profile(self, platform, username, url):
        """Perform deep search on a profile"""
        profile_data = {}
        
        try:
            if platform in ['GitHub', 'GitLab', 'Bitbucket']:
                # Get repositories
                if platform == 'GitHub':
                    repos_url = f"https://api.github.com/users/{username}/repos"
                    response = self.session.get(repos_url, timeout=5)
                    if response.status_code == 200:
                        repos = response.json()
                        profile_data['repositories'] = []
                        for repo in repos[:5]:  # Limit to 5 repos
                            profile_data['repositories'].append({
                                'name': repo.get('name'),
                                'description': repo.get('description'),
                                'language': repo.get('language'),
                                'stars': repo.get('stargazers_count'),
                                'forks': repo.get('forks_count'),
                                'url': repo.get('html_url')
                            })
            
            elif platform == 'Twitter':
                # Try to get tweet count (simplified)
                try:
                    response = self.session.get(url, timeout=5)
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Look for tweet count
                    tweet_count_elements = soup.find_all(string=re.compile(r'\d+\s*[Tt]weets'))
                    if tweet_count_elements:
                        profile_data['tweet_count'] = tweet_count_elements[0].strip()
                    
                    # Look for follower count
                    follower_elements = soup.find_all(string=re.compile(r'\d+\s*[Ff]ollowers'))
                    if follower_elements:
                        profile_data['follower_count'] = follower_elements[0].strip()
                
                except:
                    pass
            
            elif platform == 'Reddit':
                # Get recent posts
                try:
                    posts_url = f"https://www.reddit.com/user/{username}/submitted.json?limit=5"
                    response = self.session.get(posts_url, timeout=5)
                    if response.status_code == 200:
                        data = response.json()
                        if 'data' in data and 'children' in data['data']:
                            posts = []
                            for child in data['data']['children'][:5]:
                                post_data = child['data']
                                posts.append({
                                    'title': post_data.get('title'),
                                    'subreddit': post_data.get('subreddit'),
                                    'score': post_data.get('score'),
                                    'created_utc': post_data.get('created_utc'),
                                    'permalink': f"https://reddit.com{post_data.get('permalink')}"
                                })
                            profile_data['recent_posts'] = posts
                except:
                    pass
        
        except Exception as e:
            profile_data['deep_search_error'] = str(e)
        
        return profile_data
    
    def find_by_email(self, email):
        """Find social media profiles by email"""
        results = {
            'email': email,
            'timestamp': datetime.now().isoformat(),
            'platforms': {},
            'search_methods': []
        }
        
        try:
            # Extract username from email
            username = email.split('@')[0]
            
            # Method 1: Search by username
            results['search_methods'].append('Username search')
            username_results = self.search_all_platforms(username)
            results['by_username'] = username_results
            
            # Method 2: Direct email search on platforms that support it
            platforms_with_email_search = [
                ('Facebook', f'https://www.facebook.com/search/people/?q={quote(email)}'),
                ('LinkedIn', f'https://www.linkedin.com/sales/gmail/profile/viewByEmail/{quote(email)}'),
                ('Twitter', f'https://twitter.com/search?q={quote(email)}&src=typed_query'),
                ('Google', f'https://www.google.com/search?q="{quote(email)}"')
            ]
            
            for platform_name, search_url in platforms_with_email_search:
                try:
                    response = self.session.head(search_url, timeout=5)
                    results['platforms'][platform_name] = {
                        'search_url': search_url,
                        'status_code': response.status_code,
                        'found': response.status_code < 400
                    }
                except:
                    pass
            
            # Method 3: Gravatar
            import hashlib
            email_hash = hashlib.md5(email.strip().lower().encode()).hexdigest()
            gravatar_url = f"https://www.gravatar.com/avatar/{email_hash}"
            gravatar_profile = f"https://www.gravatar.com/{email_hash}.json"
            
            try:
                response = self.session.get(gravatar_profile, timeout=5)
                if response.status_code == 200:
                    gravatar_data = response.json()
                    if 'entry' in gravatar_data and gravatar_data['entry']:
                        results['gravatar'] = {
                            'found': True,
                            'profile': gravatar_data['entry'][0],
                            'avatar_url': gravatar_url
                        }
                else:
                    # Check if gravatar exists at all
                    response = self.session.head(gravatar_url, timeout=5)
                    if response.status_code == 200:
                        results['gravatar'] = {
                            'found': True,
                            'avatar_url': gravatar_url
                        }
            except:
                pass
            
            # Method 4: Have I Been Pwned (for breach data)
            try:
                import hashlib
                sha1_hash = hashlib.sha1(email.lower().encode()).hexdigest().upper()
                prefix = sha1_hash[:5]
                
                response = self.session.get(
                    f"https://api.pwnedpasswords.com/range/{prefix}",
                    timeout=10
                )
                
                if response.status_code == 200:
                    hashes = response.text.split('\n')
                    for line in hashes:
                        if line.startswith(sha1_hash[5:]):
                            count = line.split(':')[1].strip()
                            results['breach_check'] = {
                                'breached': True,
                                'count': int(count)
                            }
                            break
                    else:
                        results['breach_check'] = {'breached': False}
            except:
                pass
            
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def find_by_phone(self, phone_number):
        """Find profiles by phone number"""
        results = {
            'phone': phone_number,
            'timestamp': datetime.now().isoformat(),
            'platforms': {},
            'search_links': []
        }
        
        try:
            # Clean phone number
            clean_phone = re.sub(r'[^\d+]', '', phone_number)
            
            # Platforms that might support phone search
            phone_search_platforms = [
                ('Facebook', f'https://www.facebook.com/search/people/?q={clean_phone}'),
                ('TruePeopleSearch', f'https://www.truepeoplesearch.com/result?phoneno={clean_phone}'),
                ('Spokeo', f'https://www.spokeo.com/{clean_phone}'),
                ('Whitepages', f'https://www.whitepages.com/phone/{clean_phone}'),
                ('ThatsThem', f'https://thatsthem.com/phone/{clean_phone}')
            ]
            
            for platform_name, search_url in phone_search_platforms:
                results['search_links'].append({
                    'platform': platform_name,
                    'url': search_url
                })
            
            # Try to extract possible username from phone patterns
            # (e.g., last 4 digits as username)
            if len(clean_phone) >= 4:
                last_four = clean_phone[-4:]
                results['username_suggestions'] = [
                    last_four,
                    f"user{last_four}",
                    f"phone{last_four}"
                ]
                
                # Search with suggested usernames
                for suggestion in results['username_suggestions']:
                    suggestion_results = self.search_all_platforms(suggestion)
                    if suggestion_results['summary']['found'] > 0:
                        results['found_with_suggestion'] = {
                            'username': suggestion,
                            'results': suggestion_results
                        }
                        break
            
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def find_relationships(self, username):
        """Find relationships between accounts"""
        relationships = {
            'username': username,
            'timestamp': datetime.now().isoformat(),
            'related_accounts': [],
            'network_analysis': {}
        }
        
        try:
            # Get profiles on different platforms
            all_results = self.search_all_platforms(username, deep_search=True)
            
            # Extract information that might link accounts
            profile_info = {}
            
            for platform, data in all_results['platforms'].items():
                if data.get('found') and 'profile_data' in data:
                    profile_info[platform] = data['profile_data']
            
            # Look for common patterns
            common_names = set()
            common_locations = set()
            common_websites = set()
            
            for platform, info in profile_info.items():
                if info.get('name'):
                    common_names.add(info['name'])
                if info.get('location'):
                    common_locations.add(info['location'])
                if info.get('blog') or info.get('website'):
                    if info.get('blog'):
                        common_websites.add(info['blog'])
                    if info.get('website'):
                        common_websites.add(info['website'])
            
            relationships['common_attributes'] = {
                'names': list(common_names),
                'locations': list(common_locations),
                'websites': list(common_websites)
            }
            
            # Generate username variations and search
            username_variations = self._generate_username_variations(username)
            relationships['username_variations'] = username_variations
            
            # Check a few variations
            checked_variations = {}
            for variation in username_variations[:10]:  # Check first 10
                try:
                    quick_check = self._quick_check_platforms(variation)
                    if quick_check['found_count'] > 0:
                        checked_variations[variation] = quick_check
                except:
                    pass
            
            relationships['variation_results'] = checked_variations
            
            # Network analysis
            relationships['network_analysis'] = {
                'total_platforms_checked': len(self.platforms),
                'platforms_found': all_results['summary']['found'],
                'connection_strength': 'Strong' if all_results['summary']['found'] > 5 else 'Medium' if all_results['summary']['found'] > 2 else 'Weak'
            }
            
        except Exception as e:
            relationships['error'] = str(e)
        
        return relationships
    
    def _generate_username_variations(self, username):
        """Generate username variations"""
        variations = set()
        
        # Basic variations
        variations.add(username.lower())
        variations.add(username.upper())
        
        # Remove special characters
        clean = re.sub(r'[._-]', '', username)
        if clean != username:
            variations.add(clean)
            variations.add(clean.lower())
        
        # Common patterns
        if '.' in username:
            parts = username.split('.')
            if len(parts) == 2:
                variations.add(f"{parts[1]}.{parts[0]}")
                variations.add(f"{parts[1]}{parts[0]}")
                variations.add(f"{parts[0][0]}{parts[1]}")
                variations.add(f"{parts[1][0]}{parts[0]}")
        
        # Add numbers
        for i in range(1, 10):
            variations.add(f"{username}{i}")
            variations.add(f"{username}0{i}")
        
        return list(variations)
    
    def _quick_check_platforms(self, username):
        """Quick check on major platforms"""
        major_platforms = ['GitHub', 'Twitter', 'Instagram', 'LinkedIn', 'Reddit']
        
        results = {
            'username': username,
            'checked_platforms': major_platforms,
            'found_count': 0,
            'found_on': []
        }
        
        for platform in major_platforms:
            try:
                config = self.platforms[platform]
                url = config['url'].format(username)
                response = self.session.head(url, timeout=3, allow_redirects=True)
                
                if response.status_code < 400:
                    # Platform-specific checks
                    if platform == 'Instagram':
                        try:
                            full_response = self.session.get(url, timeout=3)
                            if 'Sorry, this page isn\'t available.' not in full_response.text:
                                results['found_count'] += 1
                                results['found_on'].append(platform)
                        except:
                            pass
                    else:
                        results['found_count'] += 1
                        results['found_on'].append(platform)
            except:
                pass
        
        return results
    
    def generate_social_report(self, identifier, identifier_type='username'):
        """Generate comprehensive social media report"""
        report = {
            'identifier': identifier,
            'type': identifier_type,
            'timestamp': datetime.now().isoformat(),
            'executive_summary': {}
        }
        
        try:
            if identifier_type == 'username':
                # Search for username
                search_results = self.search_all_platforms(identifier, deep_search=True)
                report['username_search'] = search_results
                
                # Find relationships
                relationships = self.find_relationships(identifier)
                report['relationship_analysis'] = relationships
                
                # Executive summary
                report['executive_summary'] = {
                    'platforms_found': search_results['summary']['found'],
                    'major_platforms': [p for p in search_results.get('found_on', []) if p in ['GitHub', 'Twitter', 'LinkedIn', 'Instagram']],
                    'network_strength': relationships['network_analysis']['connection_strength'],
                    'recommendations': self._generate_recommendations(search_results)
                }
            
            elif identifier_type == 'email':
                # Search by email
                email_results = self.find_by_email(identifier)
                report['email_search'] = email_results
                
                # Also search by username extracted from email
                username = identifier.split('@')[0]
                username_results = self.search_all_platforms(username)
                report['username_search'] = username_results
                
                # Executive summary
                report['executive_summary'] = {
                    'email_breached': email_results.get('breach_check', {}).get('breached', False),
                    'gravatar_found': 'gravatar' in email_results,
                    'platforms_via_username': username_results['summary']['found'],
                    'recommendations': self._generate_email_recommendations(email_results)
                }
            
            elif identifier_type == 'phone':
                # Search by phone
                phone_results = self.find_by_phone(identifier)
                report['phone_search'] = phone_results
                
                # Executive summary
                report['executive_summary'] = {
                    'search_links_provided': len(phone_results.get('search_links', [])),
                    'username_suggestions': phone_results.get('username_suggestions', []),
                    'recommendations': ['Use provided search links for manual investigation']
                }
        
        except Exception as e:
            report['error'] = str(e)
        
        return report
    
    def _generate_recommendations(self, search_results):
        """Generate recommendations based on search results"""
        recommendations = []
        
        found_count = search_results['summary']['found']
        
        if found_count == 0:
            recommendations.append("No social media profiles found with this username")
            recommendations.append("Try username variations or different identifiers")
        elif found_count <= 3:
            recommendations.append("Limited social media presence detected")
            recommendations.append("Consider checking for username variations")
        elif found_count <= 10:
            recommendations.append("Moderate social media presence")
            recommendations.append("Profile appears to be active on several platforms")
        else:
            recommendations.append("Strong social media presence detected")
            recommendations.append("User is active across multiple platforms")
        
        # Platform-specific recommendations
        found_platforms = search_results.get('found_on', [])
        
        if 'GitHub' in found_platforms:
            recommendations.append("Technical profile found on GitHub - check repositories for skills")
        
        if 'LinkedIn' in found_platforms:
            recommendations.append("Professional profile found on LinkedIn - check for employment history")
        
        if 'Twitter' in found_platforms:
            recommendations.append("Active on Twitter - check tweets for interests and opinions")
        
        return recommendations
    
    def _generate_email_recommendations(self, email_results):
        """Generate recommendations for email search"""
        recommendations = []
        
        if email_results.get('breach_check', {}).get('breached'):
            recommendations.append("Email found in data breaches - recommend password change")
            recommendations.append("Check HaveIBeenPwned for specific breach details")
        
        if 'gravatar' in email_results:
            recommendations.append("Gravatar profile found - may contain additional personal information")
        
        return recommendations