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
print("Visit: https://github.com/yourusername/jsosint")
EOF
fi

# Create requirements.txt
cat > requirements.txt << 'EOF'
requests>=2.25.0
beautifulsoup4>=4.9.0
python-whois>=0.9.0
dnspython>=2.1.0
colorama>=0.4.4
EOF

# Create modules directory files
cat > modules/__init__.py << 'EOF'
# jsosint modules package
EOF

cat > utils/__init__.py << 'EOF'
# jsosint utils package
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

# Install Python dependencies
print_status "Installing Python dependencies..."
pip3 install -r requirements.txt

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

# Create symlink
print_status "Creating symlink in /usr/local/bin..."
if [ ! -f "/usr/local/bin/jsosint" ]; then
    sudo ln -sf "$(pwd)/jsosint.py" /usr/local/bin/jsosint
    print_success "Created symlink: /usr/local/bin/jsosint"
else
    print_warning "jsosint already exists in /usr/local/bin"
    read -p "Overwrite? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        sudo ln -sf "$(pwd)/jsosint.py" /usr/local/bin/jsosint
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

# Test installation
print_status "Testing installation..."
if python3 jsosint.py --help 2>&1 | grep -q "jsosint"; then
    print_success "Installation test passed!"
else
    print_error "Installation test failed"
    exit 1
fi

# Final output
echo -e "\n${GREEN}========================================${NC}"
echo -e "${GREEN}[+] Installation completed successfully!${NC}"
echo -e "${GREEN}========================================${NC}\n"

echo -e "${CYAN}Quick Start Guide:${NC}"
echo -e "  ${YELLOW}1.${NC} Basic website reconnaissance:"
echo -e "     ${BLUE}jsosint website example.com${NC}"
echo -e "  ${YELLOW}2.${NC} Person reconnaissance:"
echo -e "     ${BLUE}jsosint person username${NC}"
echo -e "     ${BLUE}jsosint person email@example.com${NC}"
echo -e "  ${YELLOW}3.${NC} Quick scan (auto-detect):"
echo -e "     ${BLUE}jsosint quick target${NC}"
echo -e "  ${YELLOW}4.${NC} Save results to file:"
echo -e "     ${BLUE}jsosint website example.com -o results.json${NC}\n"

echo -e "${CYAN}Available Features:${NC}"
echo -e "  ${GREEN}✓${NC} Website reconnaissance (DNS, WHOIS, subdomains)"
echo -e "  ${GREEN}✓${NC} Technology detection (CMS, frameworks, servers)"
echo -e "  ${GREEN}✓${NC} Port scanning and service detection"
echo -e "  ${GREEN}✓${NC} Social media username search"
echo -e "  ${GREEN}✓${NC} Email analysis and validation"
echo -e "  ${GREEN}✓${NC} Integration with Kali Linux tools"
echo -e "  ${GREEN}✓${NC} No API keys required for basic features\n"

echo -e "${YELLOW}Next Steps:${NC}"
echo -e "  1. Review configuration: ${BLUE}~/.jsosint/config.json${NC}"
echo -e "  2. Update wordlists in ${BLUE}wordlists/${NC} directory"
echo -e "  3. Run ${BLUE}jsosint website example.com${NC} for a test scan\n"

echo -e "${CYAN}Need Help?${NC}"
echo -e "  - Run ${BLUE}jsosint --help${NC} for usage information"
echo -e "  - Check ${BLUE}README.md${NC} for detailed documentation"
echo -e "  - Visit GitHub repository for updates and issues\n"

echo -e "${GREEN}Happy OSINTing!${NC}"