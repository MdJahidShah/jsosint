#!/bin/bash
# install-jsosint.sh - Complete installation script

echo "Installing jsosint - Ultimate OSINT Toolkit for Kali Linux"
echo "=========================================================="

# Check if running as root
if [ "$EUID" -eq 0 ]; then 
    echo "ERROR: Do not run as root/sudo. Run as normal user."
    exit 1
fi

# Step 1: Install system dependencies
echo -e "\n[1/4] Installing system dependencies..."
if [ -f "system_requirements.sh" ]; then
    chmod +x system_requirements.sh
    ./system_requirements.sh
else
    echo "Warning: system_requirements.sh not found"
    echo "Please install dependencies manually if needed"
fi

# Step 2: Install Python packages
echo -e "\n[2/4] Installing Python packages..."
pip3 install --upgrade pip
pip3 install -r requirements.txt

# Step 3: Check dependencies
echo -e "\n[3/4] Verifying dependencies..."
if [ -f "check_deps.py" ]; then
    python3 check_deps.py
else
    echo "Warning: check_deps.py not found"
fi

# Step 4: Setup jsosint
echo -e "\n[4/4] Setting up jsosint..."
chmod +x jsosint.py

# Create symlink if not exists
if [ ! -f "/usr/local/bin/jsosint" ]; then
    echo "Creating symlink in /usr/local/bin..."
    sudo ln -sf "$(pwd)/jsosint.py" /usr/local/bin/jsosint
fi

# Create directories
mkdir -p ~/.jsosint/{wordlists,results,logs}
mkdir -p results

# Copy config if exists
if [ -f "config.json" ]; then
    cp config.json ~/.jsosint/config.json 2>/dev/null || true
fi

echo -e "\n✅ Installation complete!"
echo -e "\n📦 Installed components:"
echo "  • System dependencies"
echo "  • Python packages"
echo "  • jsosint CLI tool"
echo -e "\n📁 Directories created:"
echo "  • ~/.jsosint/wordlists"
echo "  • ~/.jsosint/results"
echo "  • ~/.jsosint/logs"
echo "  • ./results"
echo -e "\n🚀 Usage examples:"
echo "  jsosint website example.com"
echo "  jsosint person username"
echo "  jsosint network 192.168.1.1"
echo -e "\n🔧 Tools integrated:"
echo "  • nmap, masscan - Port scanning"
echo "  • dnsrecon, dig - DNS enumeration"
echo "  • whatweb, wpscan - Technology detection"
echo "  • dirb, gobuster - Directory brute force"
echo "  • sqlmap, nikto - Vulnerability scanning"
echo "  • sherlock, maigret - Social media search"
echo -e "\nHappy OSINTing! 🕵️‍♂️"