# JSOSINT
Ultimate OSINT & Pentest Toolkit for KALI LINUX - Combines all Kali tools for complete reconnaissance

# jsosint - Ultimate OSINT & Pentest Toolkit for Kali Linux

![jsosint Banner](https://img.shields.io/badge/jsosint-Ultimate%20OSINT%20and%20Toolkit-blue)
![Python Version](https://img.shields.io/badge/python-3.6%2B-green)
![Platform](https://img.shields.io/badge/platform-Kali%20Linux%20%7C%20Linux-red)
![License](https://img.shields.io/badge/license-MIT-yellow)

**jsosint** is a comprehensive OSINT (Open Source Intelligence) toolkit designed for Kali Linux that combines multiple reconnaissance tools into a single, powerful interface. It automates the process of gathering public information about websites and individuals.

## 🚀 Features

### 🌐 Website Intelligence
- **DNS Reconnaissance**: Full DNS enumeration with multiple record types
- **WHOIS Lookup**: Registrar information, creation/expiration dates
- **Subdomain Discovery**: Multiple methods including brute force and certificate transparency
- **Technology Detection**: CMS, frameworks, server software identification
- **Port Scanning**: Integration with nmap and masscan
- **Directory Brute Force**: Find hidden files and directories
- **Email Harvesting**: Extract email addresses from websites
- **SSL/TLS Analysis**: Certificate information and security checks
- **Historical Data**: Wayback Machine integration

### 👤 Person Intelligence
- **Email Analysis**: Validation, domain information, MX records
- **Username Search**: Across 15+ social media platforms
- **Social Media Discovery**: Automated profile finding
- **Phone Number Analysis**: Validation and carrier detection
- **Public Records**: Generated search links for further investigation
- **Data Breach Checks**: Integration with breach databases
- **Username Variations**: Auto-generated for comprehensive searching

### 🛠️ Tool Integration
- **Nmap**: Comprehensive port scanning
- **Masscan**: Fast port scanning
- **DNSRecon**: Advanced DNS enumeration
- **WhatWeb**: Technology fingerprinting
- **Nikto**: Web vulnerability scanning
- **Dirb/Gobuster**: Directory brute forcing
- **SQLMap**: SQL injection testing
- **WPScan**: WordPress security scanning
- **Sublist3r**: Subdomain enumeration
- **theHarvester**: Email and host discovery
- **Sherlock/Maigret**: Social media username search

## 📦 Installation - Quick Install (Kali Linux)

## Clone the repository
```bash
git clone https://github.com/mdjahidshah/jsosint.git
cd jsosint
```
## Run the installer
```bash
chmod +x install.sh
./install.sh
```

## Manually Installation Process

### Install dependencies
```bash
pip3 install requests beautifulsoup4 python-whois dnspython colorama
```
### Make script executable
```bash
chmod +x jsosint.py
```

### Create symlink (optional)
```bash
sudo ln -s $(pwd)/jsosint.py /usr/local/bin/jsosint
```
## Basic Commands

### Website reconnaissance
```bash
jsosint website example.com
```
### Person reconnaissance by email
```bash
jsosint person john.doe@company.com
```
### Person reconnaissance by username
```bash
jsosint person johndoe
```
### Quick scan (auto-detects target type)
```bash
jsosint quick target
```
### Save results to file
```bash
jsosint website example.com -o results.json
```
<!--## Structure of this Tool

`
jsosint/
├── jsosint.py           **Main tool executable**
├── requirements.txt     ** Python dependencies**
├── install.sh           ** Installation script**
├── README.md            ** This file**
├── LICENSE              ** MIT License**
├── config/
│   └── config.json      ** Configuration file**
├── modules/
│   ├── __init__.py
│   ├── website_intel.py ** Website intelligence module**
│   └── person_intel.py  ** Person intelligence module**
├── utils/
│   ├── __init__.py
│   ├── kali_tools.py    ** Kali Linux tools integration**
│   └── colors.py        ** Color output utilities**
└── wordlists/
    ├── common.txt       **Common directories/files**
    └── subdomains.txt   **Subdomain wordlist**
`
-->
## Output Examples

### Website Scan Output

```bash
[*] TARGET: example.com
[*] START TIME: 2024-01-15 14:30:00
============================================================

[+] Basic Information:
    ip_address: 93.184.216.34
    status_code: 200
    server: ECS (nyb/1D2C)
    title: Example Domain

[+] DNS Records:
    A Records: 93.184.216.34

[+] Subdomains Found:
    certificate: 15 subdomains
    sublist3r: 8 subdomains

[+] Technologies Detected:
    server: ECS
    cms: None detected

[+] Open Ports:
    Ports: 80, 443

[+] Summary:
    Subdomains: 23
    Technologies: 1
    Historical Snapshots: 42
```

### Person Scan Output
```bash
[*] TARGET: johndoe
[*] START TIME: 2024-01-15 14:35:00
============================================================

[+] Target Type: username

[+] Social Media Presence:
    Found on: 8 platforms
    ✓ GitHub: https://github.com/johndoe
    ✓ Twitter: https://twitter.com/johndoe
    ✓ LinkedIn: https://linkedin.com/in/johndoe

[+] Public Record Searches:
    https://www.google.com/search?q="johndoe"
    https://www.peekyou.com/johndoe
    https://www.pipl.com/search/?q=johndoe
```
## 🔄 Updates & Maintenance

```bash
cd jsosint
git pull
pip3 install -r requirements.txt --upgrade
```
## Reporting Issues
Please report bugs and feature requests on the GitHub Issues page.

## 🤝 Contributing

Contributions are welcome! Please:

- Fork the repository
- Create a feature branch
- Make your changes
- Submit a pull request

## Development Setup

**Clone and setup:**
bash ``` git clone https://github.com/mdjahidshah/jsosint.git ```
bash ``` cd jsosint ```
bash ``` python3 -m venv venv ```
bash ``` source venv/bin/activate ```
bash ``` pip3 install -r requirements.txt ```
bash ``` chmod +x install.sh ```
bash ``` ./install.sh  ```


## 📄 License
This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- Kali Linux team for the amazing distribution
- All the open-source tool developers integrated in jsosint
- The security community for continuous inspiration
- Contributors and testers

## 📞 Support

- Documentation: GitHub Wiki
- Issues: GitHub Issues
- Discussions: GitHub Discussions

## Disclaimer:

The developers are not responsible for any misuse or damage caused by this program. Use only for legitimate purposes.


## Installation & Usage

### 1. Clone and install
```bash
git clone https://github.com/mdjahidshah/jsosint.git
cd jsosint
chmod +x install.sh
./install.sh
```
### 2. Test installation
```bash
jsosint --help
```
### 3. Run a scan
```bash
jsosint website example.com
jsosint person username
jsosint quick target.com
```

## Support
👉 Want to Support then, [Buy Me a Coffee](https://buymeacoffee.com/jahidshah)