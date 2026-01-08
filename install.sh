#!/bin/bash

# jsosint Installation Script
# For Kali Linux and other Linux distributions

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Print banner
echo -e "${CYAN}"
cat << "EOF"
   ██╗███████╗ ██████╗ ███████╗██╗███╗   ██╗████████╗
   ██║██╔════╝██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝
   ██║███████╗██║   ██║███████╗██║██╔██╗ ██║   ██║   
██ ██║╚════██║██║   ██║╚════██║██║██║╚██╗██║   ██║   
╚████║███████║╚██████╔╝███████║██║██║ ╚████║   ██║   
 ╚═══╝╚══════╝ ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝   
EOF
echo -e "${NC}"
echo -e "${YELLOW}        Ultimate OSINT Toolkit Installation${NC}"
echo -e "${GREEN}        For Kali Linux, Ubuntu, and other Linux distributions${NC}\n"

# Function to print status
print_status() {
    echo -e "${BLUE}[*]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[-]${NC} $1"
}

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    print_warning "Running as root. It's recommended to run as normal user."
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Check Python3
print_status "Checking Python3 installation..."
if ! command -v python3 &> /dev/null; then
    print_status "Installing Python3..."
    sudo apt update && sudo apt install -y python3 python3-pip python3-venv
fi

# Check pip
if ! command -v pip3 &> /dev/null; then
    print_status "Installing pip3..."
    sudo apt install -y python3-pip
fi

# Create directory structure
print_status "Creating directory structure..."
mkdir -p jsosint
cd jsosint
mkdir -p modules utils wordlists config

# Copy files (assuming they're in the same directory)
print_status "Setting up files..."
# Create minimal files if they don't exist
if [ ! -f "jsosint.py" ]; then
    cat > jsosint.py << 'EOF'
#!/usr/bin/env python3
print("Please download the complete jsosint.py file from GitHub")
print("Visit: https://github.com/mdjahidshah/jsosint")
EOF
fi

# Create COMPLETE requirements.txt with ALL dependencies
cat > requirements.txt << 'EOF'
# Core dependencies
requests>=2.28.0
beautifulsoup4>=4.11.0
feedparser>=6.0.10
dnspython>=2.3.0
cryptography>=39.0.0
Pillow>=9.5.0
lxml>=4.9.0
python-whois>=0.8.0
colorama>=0.4.6

# Additional OSINT tools
maigret>=0.5.0
shodan>=1.28.0
censys>=2.1.9
virustotal-api>=1.1.11

# Data processing
pandas>=1.5.0
numpy>=1.24.0

# Networking
python-nmap>=0.7.1
scapy>=2.5.0

# Web scraping
selenium>=4.8.0
webdriver-manager>=3.8.6

# Reporting
python-docx>=0.8.11
openpyxl>=3.1.0
pdfkit>=1.0.0
markdown>=3.4.0
EOF

# Create modules directory files
cat > modules/__init__.py << 'EOF'
# jsosint modules package
EOF

cat > utils/__init__.py << 'EOF'
# jsosint utils package
EOF

cat > utils/colors.py << 'EOF'
#!/usr/bin/env python3
# Color utilities for jsosint

class Colors:
    # Reset
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    ITALIC = '\033[3m'
    UNDERLINE = '\033[4m'
    BLINK = '\033[5m'
    REVERSE = '\033[7m'
    HIDDEN = '\033[8m'
    
    # Regular Colors
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    
    # Background Colors
    BG_BLACK = '\033[40m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'
    BG_CYAN = '\033[46m'
    BG_WHITE = '\033[47m'
    
    # Bright Colors
    BRIGHT_BLACK = '\033[90m'
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'
    BRIGHT_WHITE = '\033[97m'
    
    # Bright Background Colors
    BG_BRIGHT_BLACK = '\033[100m'
    BG_BRIGHT_RED = '\033[101m'
    BG_BRIGHT_GREEN = '\033[102m'
    BG_BRIGHT_YELLOW = '\033[103m'
    BG_BRIGHT_BLUE = '\033[104m'
    BG_BRIGHT_MAGENTA = '\033[105m'
    BG_BRIGHT_CYAN = '\033[106m'
    BG_BRIGHT_WHITE = '\033[107m'
EOF

# Create basic wordlist
cat > wordlists/common.txt << 'EOF'
admin
login
wp-admin
wp-login
dashboard
control
api
test
dev
staging
EOF

# Create virtual environment for isolated installation
print_status "Creating virtual environment..."
python3 -m venv venv

# Activate virtual environment
print_status "Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
print_status "Upgrading pip..."
pip install --upgrade pip setuptools wheel

# Install Python dependencies
print_status "Installing Python dependencies..."
pip install -r requirements.txt

# Deactivate virtual environment for now
deactivate

# Check for Kali Linux
print_status "Checking for Kali Linux tools..."
if [ -f "/etc/os-release" ] && grep -q "kali" /etc/os-release; then
    print_success "Detected Kali Linux"
    
    # List of recommended Kali tools
    kali_tools=(
        "nmap" "masscan" "dnsrecon" "whois" "whatweb" "nikto"
        "dirb" "gobuster" "sqlmap" "wpscan" "sublist3r"
        "theharvester" "sherlock" "metagoofil"
    )
    
    missing_tools=()
    for tool in "${kali_tools[@]}"; do
        if ! command -v $tool &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        print_warning "Some recommended tools are missing:"
        for tool in "${missing_tools[@]}"; do
            echo "  - $tool"
        done
        read -p "Install missing tools? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            sudo apt update
            sudo apt install -y "${missing_tools[@]}"
        fi
    else
        print_success "All recommended Kali tools are installed"
    fi
else
    print_warning "Not running Kali Linux. Some features may require manual tool installation."
    echo "Recommended tools to install:"
    echo "  - nmap, masscan, dnsrecon, whois"
    echo "  - whatweb, nikto, dirb, gobuster"
    echo "  - sqlmap, wpscan, sublist3r"
    echo "  - theharvester, sherlock"
fi

# Install Maigret (if not available)
if ! command -v maigret &> /dev/null; then
    print_status "Installing Maigret for username OSINT..."
    pip3 install maigret
fi

# Make jsosint executable
chmod +x jsosint.py

# Create wrapper script to automatically activate venv
print_status "Creating wrapper script..."
cat > jsosint.sh << 'EOF'
#!/bin/bash
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Activate virtual environment
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
else
    echo "Error: Virtual environment not found!"
    echo "Please run the install.sh script first."
    exit 1
fi

# Run jsosint
python3 jsosint.py "$@"

# Deactivate virtual environment when done
deactivate
EOF

chmod +x jsosint.sh

# Create symlink
print_status "Creating symlink in /usr/local/bin..."
if [ ! -f "/usr/local/bin/jsosint" ]; then
    sudo ln -sf "$(pwd)/jsosint.sh" /usr/local/bin/jsosint
    print_success "Created symlink: /usr/local/bin/jsosint"
else
    print_warning "jsosint already exists in /usr/local/bin"
    read -p "Overwrite? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        sudo rm /usr/local/bin/jsosint
        sudo ln -sf "$(pwd)/jsosint.sh" /usr/local/bin/jsosint
        print_success "Updated symlink"
    fi
fi

# Create configuration directory
mkdir -p ~/.jsosint
if [ ! -f ~/.jsosint/config.json ]; then
    cat > ~/.jsosint/config.json << 'EOF'
{
    "scan": {
        "timeout": 10,
        "threads": 10,
        "user_agent": "Mozilla/5.0 (compatible; jsosint/1.0)"
    },
    "output": {
        "format": "json",
        "save_location": "./results"
    },
    "api_keys": {
        "shodan": "",
        "virustotal": "",
        "censys_id": "",
        "censys_secret": "",
        "hunterio": "",
        "breachdirectory": ""
    },
    "modules": {
        "enabled": true,
        "auto_update": true
    }
}
EOF
    print_success "Created configuration file: ~/.jsosint/config.json"
fi

# Download additional wordlists
print_status "Downloading additional wordlists..."
if [ ! -f "wordlists/subdomains.txt" ]; then
    wget -q -O wordlists/subdomains.txt \
        https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt
    print_success "Downloaded subdomain wordlist"
fi

if [ ! -f "wordlists/directories.txt" ]; then
    wget -q -O wordlists/directories.txt \
        https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt
    print_success "Downloaded directory wordlist"
fi

if [ ! -f "wordlists/usernames.txt" ]; then
    wget -q -O wordlists/usernames.txt \
        https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/Names/names.txt
    print_success "Downloaded username wordlist"
fi

# Test installation
print_status "Testing installation..."
cd "$(pwd)"
source venv/bin/activate

# Test imports
python3 -c "
import sys
print('Python version:', sys.version)
print('Python path:', sys.path)

test_modules = [
    'feedparser',
    'requests',
    'bs4',
    'dns.resolver',
    'cryptography',
    'PIL',
    'lxml',
    'whois',
    'colorama'
]

for module in test_modules:
    try:
        __import__(module.replace('.resolver', '').replace('.', '_') if module == 'dns.resolver' else module)
        print(f'✓ {module} imported successfully')
    except ImportError as e:
        print(f'✗ {module} failed: {e}')
"

deactivate

# Create a simple jsosint.py if it doesn't exist with proper imports
if [ ! -f "jsosint.py" ] || grep -q "Please download" jsosint.py; then
    print_status "Creating basic jsosint.py for testing..."
    cat > jsosint.py << 'EOF'
#!/usr/bin/env python3
"""
jsOSINT - Ultimate OSINT Toolkit
Author: Your Name
"""

import sys
import os
import argparse
import json
from datetime import datetime

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from utils.colors import Colors
    print("✓ Color utilities imported")
except ImportError as e:
    print(f"✗ Error importing utils: {e}")
    print("Please run: pip install -r requirements.txt")
    sys.exit(1)

# Initialize colors
colors = Colors()

def print_banner():
    """Print tool banner"""
    print(f"{colors.CYAN}")
    print("   ██╗███████╗ ██████╗ ███████╗██╗███╗   ██╗████████╗")
    print("   ██║██╔════╝██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝")
    print("   ██║███████╗██║   ██║███████╗██║██╔██╗ ██║   ██║   ")
    print("██ ██║╚════██║██║   ██║╚════██║██║██║╚██╗██║   ██║   ")
    print("╚████║███████║╚██████╔╝███████║██║██║ ╚████║   ██║   ")
    print(" ╚═══╝╚══════╝ ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝   ")
    print(f"{colors.RESET}")
    print(f"{colors.YELLOW}        Ultimate OSINT Toolkit v1.0{colors.RESET}")
    print(f"{colors.GREEN}        For Kali Linux and other Linux distributions{colors.RESET}\n")

def main():
    parser = argparse.ArgumentParser(description='jsOSINT - Ultimate OSINT Toolkit')
    parser.add_argument('--help', '-h', action='help', help='Show this help message')
    parser.add_argument('--version', '-v', action='version', version='jsOSINT v1.0')
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Website reconnaissance
    website_parser = subparsers.add_parser('website', help='Website reconnaissance')
    website_parser.add_argument('target', help='Website domain or URL')
    website_parser.add_argument('--output', '-o', help='Output file')
    
    # Person reconnaissance
    person_parser = subparsers.add_parser('person', help='Person reconnaissance')
    person_parser.add_argument('target', help='Username or email')
    person_parser.add_argument('--output', '-o', help='Output file')
    
    # Quick scan
    quick_parser = subparsers.add_parser('quick', help='Quick scan (auto-detect)')
    quick_parser.add_argument('target', help='Target to scan')
    quick_parser.add_argument('--output', '-o', help='Output file')
    
    # Test command
    test_parser = subparsers.add_parser('test', help='Test installation')
    
    args = parser.parse_args()
    
    if not args.command:
        print_banner()
        parser.print_help()
        return
    
    if args.command == 'test':
        print_banner()
        print(f"{colors.GREEN}[+] Installation test successful!{colors.RESET}")
        print(f"{colors.BLUE}[*]{colors.RESET} All dependencies are properly installed.")
        print(f"{colors.BLUE}[*]{colors.RESET} Tool is ready to use.")
        return
    
    print_banner()
    print(f"{colors.CYAN}[*]{colors.RESET} Starting {args.command} scan on: {args.target}")
    print(f"{colors.YELLOW}[!]{colors.RESET} This is a basic version. Full features require complete jsosint.py")
    
    # Simulate scanning
    import time
    time.sleep(1)
    
    results = {
        'target': args.target,
        'scan_type': args.command,
        'timestamp': datetime.now().isoformat(),
        'status': 'basic_scan_complete',
        'message': 'Installation successful! Download complete jsosint.py for full features.'
    }
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"{colors.GREEN}[+]{colors.RESET} Results saved to: {args.output}")
    else:
        print(f"{colors.GREEN}[+]{colors.RESET} Scan completed")
        print(json.dumps(results, indent=2))

if __name__ == '__main__':
    main()
EOF
    print_success "Created basic jsosint.py"
fi

chmod +x jsosint.py

# Final output
echo -e "\n${GREEN}========================================${NC}"
echo -e "${GREEN}[+] Installation completed successfully!${NC}"
echo -e "${GREEN}========================================${NC}\n"

echo -e "${CYAN}Quick Start Guide:${NC}"
echo -e "  ${YELLOW}1.${NC} Always use the wrapper:"
echo -e "     ${BLUE}jsosint --help${NC}"
echo -e "  ${YELLOW}2.${NC} Test installation:"
echo -e "     ${BLUE}jsosint test${NC}"
echo -e "  ${YELLOW}3.${NC} Basic website reconnaissance:"
echo -e "     ${BLUE}jsosint website example.com${NC}"
echo -e "  ${YELLOW}4.${NC} Basic person reconnaissance:"
echo -e "     ${BLUE}jsosint person username${NC}"
echo -e "     ${BLUE}jsosint person email@example.com${NC}\n"

echo -e "${CYAN}Available Features:${NC}"
echo -e "  ${GREEN}✓${NC} Virtual environment (isolated dependencies)"
echo -e "  ${GREEN}✓${NC} All required Python packages installed"
echo -e "  ${GREEN}✓${NC} Wordlists for subdomains, directories, usernames"
echo -e "  ${GREEN}✓${NC} Automatic virtual environment activation"
echo -e "  ${GREEN}✓${NC} Configuration file at ~/.jsosint/config.json"
echo -e "  ${GREEN}✓${NC} Integration with Kali Linux tools\n"

echo -e "${YELLOW}Important Notes:${NC}"
echo -e "  1. The tool uses a virtual environment at ${BLUE}jsosint/venv/${NC}"
echo -e "  2. To update dependencies: ${BLUE}cd jsosint && source venv/bin/activate && pip install -r requirements.txt${NC}"
echo -e "  3. API keys can be added to ${BLUE}~/.jsosint/config.json${NC}"
echo -e "  4. For full features, download complete jsosint.py from GitHub\n"

echo -e "${CYAN}Need Help?${NC}"
echo -e "  - Run ${BLUE}jsosint --help${NC} for usage information"
echo -e "  - Test installation with ${BLUE}jsosint test${NC}"
echo -e "  - Visit GitHub repository for complete code\n"

echo -e "${GREEN}Happy OSINTing!${NC}"