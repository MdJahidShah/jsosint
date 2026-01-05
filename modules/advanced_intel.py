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
    
    # ... (all the existing methods remain the same until the end) ...
    
    def _generate_person_leads(self, identifier):
        """Generate investigation leads for person intelligence"""
        leads = {
            'public_records': [
                'Court records search',
                'Property records search',
                'Business license lookup',
                'Professional license verification'
            ],
            'online_presence': [
                'Username search on major platforms',
                'Email pattern analysis',
                'Image reverse search',
                'Forum and community participation'
            ],
            'professional_networks': [
                'LinkedIn connections analysis',
                'GitHub contributions',
                'Conference speaking engagements',
                'Research publications'
            ],
            'financial_trails': [
                'Company registrations',
                'Patent filings',
                'Trademark applications',
                'SEC filings (if applicable)'
            ]
        }
        return leads
    
    def _generate_social_insights(self, identifier):
        """Generate social insights from intelligence"""
        insights = {
            'platform_presence': {
                'note': 'Check for presence on major social platforms',
                'platforms': [
                    'Twitter (X)',
                    'Facebook',
                    'Instagram',
                    'LinkedIn',
                    'Reddit',
                    'YouTube',
                    'TikTok',
                    'Snapchat'
                ]
            },
            'content_patterns': {
                'note': 'Analyze posting patterns and content types',
                'aspects': [
                    'Posting frequency',
                    'Content themes',
                    'Engagement patterns',
                    'Network connections'
                ]
            },
            'behavioral_insights': {
                'note': 'Behavioral analysis from social activity',
                'indicators': [
                    'Online activity times',
                    'Language and tone',
                    'Interests and hobbies',
                    'Professional affiliations'
                ]
            }
        }
        return insights
    
    def dark_web_monitoring(self, target):
        """Dark web monitoring and search"""
        dark_intel = {
            'target': target,
            'dark_web_searches': [],
            'breach_data': [],
            'leaked_credentials': [],
            'monitoring_sources': []
        }
        
        try:
            # Dark web search sources (these would require API access or specialized tools)
            dark_intel['dark_web_searches'] = [
                {
                    'source': 'Tor search engines',
                    'urls': [
                        'http://darksearch.io',
                        'http://ahmia.fi',
                        'http://onionland.io'
                    ],
                    'note': 'Requires Tor browser/proxy'
                },
                {
                    'source': 'Dark web markets',
                    'search_terms': [
                        f'site:.onion "{target}"',
                        f'"target" inurl:.onion'
                    ],
                    'warning': 'Exercise extreme caution'
                }
            ]
            
            # Breach monitoring services
            dark_intel['breach_data'] = [
                {
                    'service': 'Have I Been Pwned',
                    'url': f'https://haveibeenpwned.com/account/{quote(target)}',
                    'free': True
                },
                {
                    'service': 'DeHashed',
                    'url': f'https://dehashed.com/search?query={quote(target)}',
                    'free': False
                },
                {
                    'service': 'BreachDirectory',
                    'url': 'https://rapidapi.com/rohan-patra/api/breachdirectory',
                    'requires_api': True
                }
            ]
            
            # Monitoring sources
            dark_intel['monitoring_sources'] = [
                {
                    'type': 'RSS Feeds',
                    'sources': [
                        'https://feeds.feedburner.com/TheHackersNews',
                        'https://www.darkreading.com/rss_simple.asp'
                    ]
                },
                {
                    'type': 'Threat Intelligence',
                    'sources': [
                        'https://otx.alienvault.com/api/v1/pulses/subscribed',
                        'https://www.virustotal.com/api/v3/intelligence/hunting_notifications'
                    ]
                }
            ]
            
            # Generate search queries
            if '@' in target:  # Email
                dark_intel['search_queries'] = [
                    f'"{target}" "password"',
                    f'"{target}" "leak"',
                    f'"{target}" "breach"',
                    f'"{target.split("@")[0]}" "credentials"'
                ]
            elif '.' in target and '@' not in target:  # Domain
                dark_intel['search_queries'] = [
                    f'"{target}" "database dump"',
                    f'"{target}" "source code"',
                    f'"{target}" "admin credentials"',
                    f'site:{target} "password"'
                ]
            
        except Exception as e:
            dark_intel['error'] = str(e)
        
        return dark_intel
    
    def generate_intelligence_report(self, modules_data):
        """Generate comprehensive intelligence report"""
        report = {
            'executive_summary': '',
            'key_findings': [],
            'risk_assessment': {},
            'recommendations': [],
            'timeline': [],
            'raw_data_summary': {}
        }
        
        try:
            # Executive summary
            findings_count = 0
            risks = {'high': 0, 'medium': 0, 'low': 0}
            
            # Analyze each module
            for module_name, module_data in modules_data.items():
                if isinstance(module_data, dict):
                    # Count findings
                    if 'error' not in module_data:
                        findings_count += 1
                    
                    # Extract key information
                    key_info = self._extract_key_information(module_name, module_data)
                    if key_info:
                        report['key_findings'].extend(key_info)
                    
                    # Assess risks
                    module_risks = self._assess_module_risks(module_name, module_data)
                    for risk_level, count in module_risks.items():
                        risks[risk_level] += count
            
            # Generate executive summary
            report['executive_summary'] = f"""
            Intelligence Report Summary:
            - Total modules analyzed: {len(modules_data)}
            - Successful intelligence gathering: {findings_count}
            - Risk assessment: {risks['high']} High, {risks['medium']} Medium, {risks['low']} Low
            - Key findings identified: {len(report['key_findings'])}
            """
            
            # Risk assessment
            report['risk_assessment'] = {
                'high_risk_items': [],
                'medium_risk_items': [],
                'low_risk_items': [],
                'overall_risk_level': 'low' if risks['high'] == 0 else 'high' if risks['high'] > 3 else 'medium'
            }
            
            # Generate recommendations
            report['recommendations'] = self._generate_recommendations(modules_data, risks)
            
            # Create timeline
            report['timeline'] = self._create_timeline(modules_data)
            
            # Raw data summary
            report['raw_data_summary'] = {
                'modules_processed': list(modules_data.keys()),
                'data_points_collected': sum(len(str(v)) for v in modules_data.values() if isinstance(v, dict)),
                'external_services_used': [k for k in self.api_keys if self._has_api_key(k)],
                'report_generated': datetime.now().isoformat()
            }
            
        except Exception as e:
            report['error'] = str(e)
        
        return report
    
    def _extract_key_information(self, module_name, module_data):
        """Extract key information from module data"""
        key_findings = []
        
        try:
            if module_name == 'network_intel':
                if 'geolocation' in module_data and module_data['geolocation']:
                    geo = module_data['geolocation']
                    key_findings.append({
                        'type': 'Geolocation',
                        'finding': f"Target located in {geo.get('city', 'Unknown')}, {geo.get('country', 'Unknown')}",
                        'risk': 'low'
                    })
                
                if 'asn_info' in module_data and module_data['asn_info']:
                    asn = module_data['asn_info']
                    key_findings.append({
                        'type': 'Network',
                        'finding': f"ASN: {asn.get('asn', 'Unknown')} - {asn.get('as_name', 'Unknown')}",
                        'risk': 'low'
                    })
            
            elif module_name == 'domain_intel':
                if 'subdomain_takeover' in module_data and module_data['subdomain_takeover']:
                    for takeover in module_data['subdomain_takeover']:
                        if takeover.get('vulnerable'):
                            key_findings.append({
                                'type': 'Security',
                                'finding': f"Potential subdomain takeover: {takeover.get('service')}",
                                'risk': 'high'
                            })
                
                if 'dns_security' in module_data:
                    checks = module_data['dns_security'].get('checks', {})
                    missing = [k for k, v in checks.items() if not v]
                    if missing:
                        key_findings.append({
                            'type': 'DNS Security',
                            'finding': f"Missing DNS security records: {', '.join(missing)}",
                            'risk': 'medium'
                        })
            
            elif module_name == 'threat_intel':
                if 'dnsbl_checks' in module_data:
                    listed = [d['server'] for d in module_data['dnsbl_checks'] if d.get('listed')]
                    if listed:
                        key_findings.append({
                            'type': 'Threat',
                            'finding': f"Listed in DNS blacklists: {', '.join(listed[:3])}",
                            'risk': 'high'
                        })
            
            elif module_name == 'person_intel':
                if 'digital_footprint' in module_data and module_data['digital_footprint']:
                    platforms = list(module_data['digital_footprint'].keys())
                    if platforms:
                        key_findings.append({
                            'type': 'Digital Footprint',
                            'finding': f"Found on platforms: {', '.join(platforms[:3])}",
                            'risk': 'low'
                        })
            
            elif module_name == 'web_intel':
                if 'hidden_content' in module_data and module_data['hidden_content']:
                    sensitive = [h['path'] for h in module_data['hidden_content'] 
                               if any(x in h['path'] for x in ['.git', '.env', 'config.php', 'admin'])]
                    if sensitive:
                        key_findings.append({
                            'type': 'Web Security',
                            'finding': f"Sensitive paths exposed: {', '.join(sensitive[:3])}",
                            'risk': 'medium'
                        })
        
        except:
            pass
        
        return key_findings
    
    def _assess_module_risks(self, module_name, module_data):
        """Assess risks from module data"""
        risks = {'high': 0, 'medium': 0, 'low': 0}
        
        try:
            if module_name == 'threat_intel':
                if 'dnsbl_checks' in module_data:
                    listed_count = sum(1 for d in module_data['dnsbl_checks'] if d.get('listed'))
                    risks['high'] += listed_count
            
            elif module_name == 'domain_intel':
                if 'subdomain_takeover' in module_data:
                    takeover_count = sum(1 for t in module_data['subdomain_takeover'] if t.get('vulnerable'))
                    risks['high'] += takeover_count
                
                if 'dns_security' in module_data:
                    checks = module_data['dns_security'].get('checks', {})
                    missing_count = sum(1 for v in checks.values() if not v)
                    risks['medium'] += missing_count
            
            elif module_name == 'web_intel':
                if 'hidden_content' in module_data:
                    sensitive_count = sum(1 for h in module_data['hidden_content'] 
                                        if any(x in h['path'] for x in ['.git', '.env', 'config.php', 'admin', 'backup']))
                    risks['medium'] += sensitive_count
            
            elif module_name in ['shodan_scan', 'virustotal_scan', 'censys_scan']:
                if 'error' not in module_data:
                    # Check for vulnerabilities in scan results
                    if 'host_search' in module_data:
                        hosts = module_data['host_search'].get('matches', [])
                        vuln_count = sum(1 for h in hosts if 'vulns' in h and h['vulns'])
                        risks['high'] += vuln_count
        
        except:
            pass
        
        return risks
    
    def _generate_recommendations(self, modules_data, risks):
        """Generate recommendations based on findings"""
        recommendations = []
        
        # Security recommendations
        if risks['high'] > 0:
            recommendations.append({
                'priority': 'high',
                'category': 'Security',
                'recommendation': 'Immediate security review required. Address high-risk findings first.',
                'actions': [
                    'Review blacklist status',
                    'Check for subdomain takeovers',
                    'Scan for vulnerabilities'
                ]
            })
        
        # DNS recommendations
        domain_intel = modules_data.get('domain_intel', {})
        if 'dns_security' in domain_intel:
            checks = domain_intel['dns_security'].get('checks', {})
            missing = [k for k, v in checks.items() if not v]
            if missing:
                recommendations.append({
                    'priority': 'medium',
                    'category': 'DNS',
                    'recommendation': f'Implement missing DNS security records: {", ".join(missing)}',
                    'actions': [
                        'Configure SPF record',
                        'Set up DMARC policy',
                        'Enable DNSSEC if supported'
                    ]
                })
        
        # Web security recommendations
        web_intel = modules_data.get('web_intel', {})
        if 'hidden_content' in web_intel and web_intel['hidden_content']:
            sensitive = [h['path'] for h in web_intel['hidden_content'] 
                       if any(x in h['path'] for x in ['.git', '.env', 'config.php'])]
            if sensitive:
                recommendations.append({
                    'priority': 'medium',
                    'category': 'Web Security',
                    'recommendation': 'Remove or secure sensitive files exposed on web server',
                    'actions': [
                        'Remove development files from production',
                        'Restrict access to admin panels',
                        'Implement proper file permissions'
                    ]
                })
        
        # Monitoring recommendations
        recommendations.append({
            'priority': 'low',
            'category': 'Monitoring',
            'recommendation': 'Implement continuous monitoring and threat intelligence',
            'actions': [
                'Set up Google Alerts for brand mentions',
                'Monitor dark web for leaked credentials',
                'Subscribe to threat intelligence feeds'
            ]
        })
        
        return recommendations
    
    def _create_timeline(self, modules_data):
        """Create investigation timeline"""
        timeline = []
        
        try:
            base_time = datetime.now()
            
            # Add module processing events
            for i, (module_name, module_data) in enumerate(modules_data.items()):
                event_time = base_time - timedelta(minutes=len(modules_data) - i)
                
                timeline.append({
                    'timestamp': event_time.isoformat(),
                    'event': f'Processed {module_name} module',
                    'details': f'{"Success" if "error" not in module_data else "Failed"}',
                    'module': module_name
                })
            
            # Sort by timestamp
            timeline.sort(key=lambda x: x['timestamp'])
            
        except:
            pass
        
        return timeline
    
    def export_report(self, report_data, format='json', output_file=None):
        """Export intelligence report in various formats"""
        try:
            if format.lower() == 'json':
                content = json.dumps(report_data, indent=2, default=str)
                extension = '.json'
            
            elif format.lower() == 'html':
                content = self._generate_html_report(report_data)
                extension = '.html'
            
            elif format.lower() == 'csv':
                content = self._generate_csv_report(report_data)
                extension = '.csv'
            
            elif format.lower() == 'markdown':
                content = self._generate_markdown_report(report_data)
                extension = '.md'
            
            else:
                raise ValueError(f"Unsupported format: {format}")
            
            # Save to file if specified
            if output_file:
                if not output_file.endswith(extension):
                    output_file += extension
                
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(content)
                
                print(f"{self.colors.GREEN}[+]{self.colors.RESET} Report saved to: {output_file}")
                return output_file
            
            return content
            
        except Exception as e:
            print(f"{self.colors.RED}[-]{self.colors.RESET} Export failed: {str(e)}")
            return None
    
    def _generate_html_report(self, report_data):
        """Generate HTML report"""
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>OSINT Intelligence Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                h1 { color: #333; }
                h2 { color: #555; border-bottom: 1px solid #ddd; padding-bottom: 10px; }
                .risk-high { color: #d9534f; font-weight: bold; }
                .risk-medium { color: #f0ad4e; }
                .risk-low { color: #5cb85c; }
                .finding { background: #f9f9f9; padding: 10px; margin: 5px 0; border-left: 4px solid #007bff; }
                table { border-collapse: collapse; width: 100%; margin: 20px 0; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
                .timestamp { color: #666; font-size: 0.9em; }
            </style>
        </head>
        <body>
            <h1>OSINT Intelligence Report</h1>
            <p class="timestamp">Generated: {timestamp}</p>
            
            <h2>Executive Summary</h2>
            <pre>{executive_summary}</pre>
            
            <h2>Key Findings</h2>
            {key_findings_html}
            
            <h2>Risk Assessment</h2>
            {risk_assessment_html}
            
            <h2>Recommendations</h2>
            {recommendations_html}
            
            <h2>Investigation Timeline</h2>
            {timeline_html}
            
            <h2>Report Metadata</h2>
            <table>
                <tr><th>Total Modules</th><td>{module_count}</td></tr>
                <tr><th>Report Format</th><td>HTML</td></tr>
                <tr><th>Generated By</th><td>AdvancedOSINT Module</td></tr>
            </table>
        </body>
        </html>
        """
        
        # Generate HTML components
        key_findings_html = ""
        if 'key_findings' in report_data:
            for finding in report_data['key_findings']:
                risk_class = f"risk-{finding.get('risk', 'low')}"
                key_findings_html += f"""
                <div class="finding">
                    <strong>{finding.get('type', 'Unknown')}:</strong> {finding.get('finding', '')}
                    <span class="{risk_class}">[{finding.get('risk', 'low').upper()}]</span>
                </div>
                """
        
        risk_assessment_html = ""
        if 'risk_assessment' in report_data:
            risk = report_data['risk_assessment']
            risk_assessment_html = f"""
            <p><strong>Overall Risk Level:</strong> <span class="risk-{risk.get('overall_risk_level', 'low')}">
            {risk.get('overall_risk_level', 'low').upper()}</span></p>
            """
        
        recommendations_html = ""
        if 'recommendations' in report_data:
            for rec in report_data['recommendations']:
                priority_class = f"risk-{rec.get('priority', 'low')}"
                recommendations_html += f"""
                <div class="finding">
                    <span class="{priority_class}">[{rec.get('priority', 'low').upper()}]</span>
                    <strong>{rec.get('category', 'General')}:</strong> {rec.get('recommendation', '')}
                </div>
                """
        
        timeline_html = ""
        if 'timeline' in report_data:
            for event in report_data['timeline']:
                timeline_html += f"""
                <div>
                    <span class="timestamp">[{event.get('timestamp', '')}]</span>
                    {event.get('event', '')} - {event.get('details', '')}
                </div>
                """
        
        # Fill template
        html_content = html_template.format(
            timestamp=report_data.get('raw_data_summary', {}).get('report_generated', 'Unknown'),
            executive_summary=report_data.get('executive_summary', 'No summary available'),
            key_findings_html=key_findings_html,
            risk_assessment_html=risk_assessment_html,
            recommendations_html=recommendations_html,
            timeline_html=timeline_html,
            module_count=len(report_data.get('raw_data_summary', {}).get('modules_processed', []))
        )
        
        return html_content
    
    def _generate_csv_report(self, report_data):
        """Generate CSV report"""
        import io
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(['Section', 'Field', 'Value'])
        
        # Write executive summary
        writer.writerow(['Executive Summary', 'Summary', report_data.get('executive_summary', '')])
        
        # Write key findings
        for finding in report_data.get('key_findings', []):
            writer.writerow(['Key Finding', finding.get('type', 'Unknown'), 
                           f"{finding.get('finding', '')} [{finding.get('risk', 'low')}]"])
        
        # Write recommendations
        for rec in report_data.get('recommendations', []):
            writer.writerow(['Recommendation', rec.get('category', 'General'),
                           f"{rec.get('recommendation', '')} [{rec.get('priority', 'low')}]"])
        
        # Write metadata
        for key, value in report_data.get('raw_data_summary', {}).items():
            if isinstance(value, list):
                value = ', '.join(str(v) for v in value)
            writer.writerow(['Metadata', key, value])
        
        return output.getvalue()
    
    def _generate_markdown_report(self, report_data):
        """Generate Markdown report"""
        md_content = f"""# OSINT Intelligence Report
        
**Generated:** {report_data.get('raw_data_summary', {}).get('report_generated', 'Unknown')}

## Executive Summary

{report_data.get('executive_summary', 'No summary available')}

## Key Findings

"""
        
        # Add key findings
        for finding in report_data.get('key_findings', []):
            risk_level = finding.get('risk', 'low').upper()
            md_content += f"- **{finding.get('type', 'Unknown')}**: {finding.get('finding', '')} `[{risk_level}]`\n"
        
        # Add risk assessment
        md_content += "\n## Risk Assessment\n\n"
        risk = report_data.get('risk_assessment', {})
        md_content += f"**Overall Risk Level:** {risk.get('overall_risk_level', 'low').upper()}\n\n"
        
        # Add recommendations
        md_content += "## Recommendations\n\n"
        for rec in report_data.get('recommendations', []):
            priority = rec.get('priority', 'low').upper()
            md_content += f"### [{priority}] {rec.get('category', 'General')}\n"
            md_content += f"{rec.get('recommendation', '')}\n\n"
            if 'actions' in rec:
                md_content += "**Actions:**\n"
                for action in rec.get('actions', []):
                    md_content += f"- {action}\n"
            md_content += "\n"
        
        # Add timeline
        md_content += "## Investigation Timeline\n\n"
        for event in report_data.get('timeline', []):
            md_content += f"- **{event.get('timestamp', '')}**: {event.get('event', '')} - {event.get('details', '')}\n"
        
        # Add metadata
        md_content += "\n## Report Metadata\n\n"
        for key, value in report_data.get('raw_data_summary', {}).items():
            if isinstance(value, list):
                value = ', '.join(str(v) for v in value)
            md_content += f"- **{key}**: {value}\n"
        
        return md_content