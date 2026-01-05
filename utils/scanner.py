#!/usr/bin/env python3
"""
Basic scanner module for jsosint
"""

import socket
import requests
from urllib.parse import urlparse

class BasicScanner:
    """Basic scanning utilities"""
    
    def __init__(self, timeout=10):
        self.timeout = timeout
    
    def is_alive(self, target):
        """Check if target is alive/online"""
        try:
            socket.setdefaulttimeout(self.timeout)
            ip = socket.gethostbyname(target)
            return {"alive": True, "ip": ip}
        except Exception as e:
            return {"alive": False, "error": str(e)}
    
    def check_http_https(self, domain):
        """Check HTTP and HTTPS availability"""
        results = {}
        
        for protocol in ['http', 'https']:
            try:
                url = f"{protocol}://{domain}"
                response = requests.head(url, timeout=self.timeout, verify=False)
                results[protocol] = {
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "accessible": response.status_code < 400
                }
            except Exception as e:
                results[protocol] = {
                    "accessible": False,
                    "error": str(e)
                }
        
        return results