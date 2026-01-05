#!/usr/bin/env python3
"""
jsosint Dependency Checker
Checks if all required dependencies are installed
"""

import importlib
import subprocess
import sys
import platform
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

def check_python_dep(module_name, pip_name=None):
    """Check if a Python module is installed"""
    if pip_name is None:
        pip_name = module_name
    
    try:
        importlib.import_module(module_name)
        return True, f"{Fore.GREEN}✓ {module_name}{Style.RESET_ALL}"
    except ImportError as e:
        return False, f"{Fore.RED}✗ {module_name} - Install with: pip install {pip_name}{Style.RESET_ALL}"

def check_system_tool(tool_name):
    """Check if a system tool is installed"""
    try:
        result = subprocess.run(['which', tool_name], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            return True, f"{Fore.GREEN}✓ {tool_name}{Style.RESET_ALL}"
        else:
            return False, f"{Fore.YELLOW}⚠ {tool_name} - Optional system tool{Style.RESET_ALL}"
    except Exception:
        return False, f"{Fore.YELLOW}⚠ {tool_name} - Optional{Style.RESET_ALL}"

def main():
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}🔍 jsosint Dependency Checker{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    
    print(f"\n{Fore.YELLOW}System Information:{Style.RESET_ALL}")
    print(f"  OS: {platform.system()} {platform.release()}")
    print(f"  Python: {platform.python_version()}")
    
    # Core Python dependencies
    print(f"\n{Fore.YELLOW}Core Python Dependencies:{Style.RESET_ALL}")
    
    python_deps = [
        ('requests', 'requests'),
        ('bs4', 'beautifulsoup4'),
        ('whois', 'python-whois'),
        ('dns', 'dnspython'),
        ('colorama', 'colorama'),
        ('nmap', 'python-nmap'),
        ('scapy', 'scapy'),
        ('OpenSSL', 'pyopenssl'),
        ('jinja2', 'jinja2'),
        ('psutil', 'psutil'),
        ('xmltodict', 'xmltodict'),
        ('rich', 'rich'),
        ('pandas', 'pandas'),
        ('lxml', 'lxml'),
        ('selenium', 'selenium'),
    ]
    
    missing_python = []
    for mod, pip_name in python_deps:
        installed, message = check_python_dep(mod, pip_name)
        print(f"  {message}")
        if not installed:
            missing_python.append(pip_name)
    
    # Advanced/optional Python dependencies
    print(f"\n{Fore.YELLOW}Advanced Dependencies (Optional):{Style.RESET_ALL}")
    
    advanced_deps = [
        ('shodan', 'shodan'),
        ('censys', 'censys'),
        ('vt', 'virustotal-api'),
        ('geoip2', 'geoip2'),
        ('phonenumbers', 'phonenumbers'),
        ('PIL', 'pillow'),
    ]
    
    for mod, pip_name in advanced_deps:
        installed, message = check_python_dep(mod, pip_name)
        print(f"  {message}")
    
    # System tools
    print(f"\n{Fore.YELLOW}System Tools (Optional):{Style.RESET_ALL}")
    
    system_tools = [
        'nmap', 'masscan', 'dig', 'whois', 'dirb',
        'gobuster', 'nikto', 'sqlmap', 'wpscan',
        'sublist3r', 'theHarvester', 'sherlock', 'maigret'
    ]
    
    missing_system = []
    for tool in system_tools:
        installed, message = check_system_tool(tool)
        print(f"  {message}")
        if not installed and 'Optional' not in message:
            missing_system.append(tool)
    
    # Summary
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    
    if missing_python:
        print(f"\n{Fore.RED}❌ Missing Python dependencies:{Style.RESET_ALL}")
        for dep in missing_python:
            print(f"  pip install {dep}")
        
        print(f"\n{Fore.YELLOW}To install all missing Python packages:{Style.RESET_ALL}")
        print(f"  pip install {' '.join(missing_python)}")
    
    if missing_system:
        print(f"\n{Fore.YELLOW}⚠ Missing system tools:{Style.RESET_ALL}")
        for tool in missing_system:
            print(f"  {tool}")
        
        os_type = platform.system().lower()
        if os_type in ['linux', 'darwin']:
            print(f"\n{Fore.YELLOW}Install with:{Style.RESET_ALL}")
            if 'kali' in platform.platform().lower() or 'ubuntu' in platform.platform().lower():
                print(f"  sudo apt install {' '.join(missing_system)}")
            elif 'darwin' in os_type:
                print(f"  brew install {' '.join(missing_system)}")
    
    if not missing_python and not missing_system:
        print(f"\n{Fore.GREEN}✅ All dependencies are installed!{Style.RESET_ALL}")
        print(f"{Fore.GREEN}jsosint is ready to use! 🚀{Style.RESET_ALL}")
    
    print(f"\n{Fore.CYAN}Quick test:{Style.RESET_ALL}")
    print(f"  python3 jsosint.py --help")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    
    return len(missing_python) == 0

if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}⚠ Check interrupted by user{Style.RESET_ALL}")
        sys.exit(1)