#!/bin/bash
# install-jsosint.sh

echo "Installing jsosint - Ultimate OSINT Toolkit for Kali Linux"

# Update system
sudo apt update

# Install Python dependencies
pip3 install requests beautifulsoup4 python-whois dnspython

# Ensure Kali tools are installed
echo "Checking/Installing Kali Linux tools..."

tools=(
    "nmap" "masscan" "dnsrecon" "whatweb" "nikto" "dirb" "gobuster"
    "sqlmap" "wpscan" "sublist3r" "theharvester" "sherlock" "metagoofil"
    "recon-ng" "spiderfoot"
)

for tool in "${tools[@]}"; do
    if ! command -v $tool &> /dev/null; then
        echo "Installing $tool..."
        sudo apt install -y $tool
    else
        echo "$tool already installed"
    fi
done

# Install maigret (if not available)
if ! command -v maigret &> /dev/null; then
    echo "Installing Maigret..."
    sudo pip3 install maigret
fi

# Make jsosint executable
chmod +x jsosint.py

# Create symlink
sudo ln -sf "$(pwd)/jsosint.py" /usr/local/bin/jsosint

# Create wordlists directory
mkdir -p ~/.jsosint/wordlists

echo ""
echo "Installation complete!"
echo ""
echo "Usage examples:"
echo "  jsosint website example.com"
echo "  jsosint person username"
echo "  jsosint person email@example.com"
echo "  jsosint quick target"
echo ""
echo "This tool integrates with:"
echo "  • nmap, masscan - Port scanning"
echo "  • dnsrecon, dig - DNS enumeration"
echo "  • whatweb, wpscan - Technology detection"
echo "  • dirb, gobuster - Directory brute force"
echo "  • sqlmap, nikto - Vulnerability scanning"
echo "  • sublist3r, theHarvester - Subdomain & email discovery"
echo "  • sherlock, maigret - Social media search"
echo "  • metagoofil - Metadata extraction"
echo ""
echo "Happy OSINTing!"