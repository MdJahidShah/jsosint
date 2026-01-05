#!/usr/bin/env python3
"""
Input validator for jsosint
"""

import re
import ipaddress
from urllib.parse import urlparse

class InputValidator:
    """Validate various types of input"""
    
    @staticmethod
    def validate_domain(domain):
        """Validate domain name"""
        if not domain:
            return False, "Domain cannot be empty"
        
        # Simple domain pattern
        pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        
        if re.match(pattern, domain):
            return True, "Valid domain"
        else:
            return False, "Invalid domain format"
    
    @staticmethod
    def validate_ip(ip):
        """Validate IP address"""
        try:
            ipaddress.ip_address(ip)
            return True, "Valid IP address"
        except ValueError:
            return False, "Invalid IP address"
    
    @staticmethod
    def validate_email(email):
        """Validate email address"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        
        if re.match(pattern, email):
            return True, "Valid email"
        else:
            return False, "Invalid email format"
    
    @staticmethod
    def validate_url(url):
        """Validate URL"""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc]), "Valid URL"
        except:
            return False, "Invalid URL"
    
    @staticmethod
    def validate_port(port):
        """Validate port number"""
        try:
            port_num = int(port)
            if 1 <= port_num <= 65535:
                return True, "Valid port"
            else:
                return False, "Port must be between 1 and 65535"
        except ValueError:
            return False, "Port must be a number"
    
    @staticmethod
    def detect_input_type(input_str):
        """Automatically detect input type"""
        
        # Check if it's an IP address
        if InputValidator.validate_ip(input_str)[0]:
            return "ip"
        
        # Check if it's an email
        if InputValidator.validate_email(input_str)[0]:
            return "email"
        
        # Check if it's a domain
        if InputValidator.validate_domain(input_str)[0]:
            return "domain"
        
        # Check if it's a URL
        if InputValidator.validate_url(input_str)[0]:
            return "url"
        
        # Default to username
        return "username"