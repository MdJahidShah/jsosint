# 🕵️‍♂️ JSOSINT - Ultimate OSINT & Pentest Toolkit for Kali Linux

[![GitHub stars](https://img.shields.io/github/stars/mdjahidshah/jsosint?style=for-the-badge)](https://github.com/mdjahidshah/jsosint/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/mdjahidshah/jsosint?style=for-the-badge)](https://github.com/mdjahidshah/jsosint/network)
[![License](https://img.shields.io/github/license/mdjahidshah/jsosint?style=for-the-badge)](https://github.com/mdjahidshah/jsosint/blob/main/LICENSE)
[![Python](https://img.shields.io/badge/Python-3.9%2B-blue?style=for-the-badge&logo=python)](https://python.org)
[![Kali Linux](https://img.shields.io/badge/Kali%20Linux-Compatible-557C94?style=for-the-badge&logo=kalilinux)](https://kali.org)

**JSOSINT** is the ultimate all-in-one reconnaissance toolkit that integrates all major Kali Linux tools into a single, unified interface. Perform complete OSINT investigations, network reconnaissance, and vulnerability assessments with one powerful tool.

---

[![Buy Me A Coffee](https://img.shields.io/badge/Buy_Me_A_Coffee-FFDD00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black)](https://buymeacoffee.com/jahidshah)

## 📖 Table of Contents
- [🚀 Features](#-features)
- [📦 Installation](#-installation)
- [🎯 Quick Start](#-quick-start)
- [🔍 Usage Examples](#-usage-examples)
- [📊 Output Examples](#-output-examples)
- [🛠️ Modules Overview](#️-modules-overview)
- [⚙️ Configuration](#️-configuration)
- [🔄 Updates & Maintenance](#-updates--maintenance)
- [🐛 Reporting Issues](#-reporting-issues)
- [🤝 Contributing](#-contributing)
- [📄 License](#-license)
- [🙏 Acknowledgments](#-acknowledgments)
- [📞 Support](#-support)
- [⚠️ Disclaimer](#️-disclaimer)
- [☕ Support](#-support)

---

## 🚀 Features

### 🌐 **Website Intelligence**
- **DNS Enumeration** - Complete DNS records analysis
- **Subdomain Discovery** - Multiple methods (certificate transparency, brute force, search engines)
- **Technology Detection** - Identify CMS, frameworks, servers, and libraries
- **Port Scanning** - Nmap integration with detailed service detection
- **Vulnerability Assessment** - Common vulnerability checks
- **SSL/TLS Analysis** - Certificate inspection and security checks
- **Historical Data** - Wayback Machine and historical records
- **Email Harvesting** - Extract emails from websites and WHOIS

### 👤 **Person Intelligence**
- **Social Media Search** - 30+ platforms including GitHub, Twitter, LinkedIn, Instagram
- **Username Enumeration** - Cross-platform username checking
- **Email Intelligence** - Breach checking, Gravatar lookup, email pattern analysis
- **Phone Number Analysis** - Reverse lookup and carrier detection
- **Relationship Mapping** - Find connections between accounts
- **Public Records** - Basic public information gathering

### 🌍 **Network Intelligence**
- **Port Scanning** - Comprehensive port enumeration
- **Service Detection** - Banner grabbing and service identification
- **OS Detection** - Multiple fingerprinting methods (Nmap, TTL, port analysis)
- **Network Discovery** - Host discovery and ARP scanning
- **Vulnerability Scanning** - Common service vulnerabilities
- **Traceroute** - Network path analysis
- **DNS Enumeration** - Zone transfers and record analysis

### 🔧 **Advanced Features**
- **Kali Tools Integration** - Direct interface to nmap, masscan, dnsrecon, nikto, sqlmap, etc.
- **Multi-threaded Scanning** - Fast parallel execution
- **Multiple Output Formats** - JSON, HTML, CSV, TXT reports
- **Color-coded CLI** - Beautiful terminal interface with rich formatting
- **API Integration** - Optional Shodan, Censys, VirusTotal integration
- **Wordlist Management** - Custom wordlist support
- **Modular Architecture** - Easy to extend and customize

---

## 📦 Installation

### **Prerequisites**
- **Kali Linux 2023+** (Recommended) or **Ubuntu 20.04+**
- **Python 3.9+** (`python3 --version`)
<!-- - **5GB+ free disk space** for tools and wordlists -->

### **Method 1: Quick Installation (Recommended)**

#### Clone the repository
```bash
git clone https://github.com/mdjahidshah/jsosint.git
cd jsosint
```
#### Create and activate virtual environment
```bash
sudo python3 -m venv venv
source venv/bin/activate
```
#### Install Python dependencies
```bash
pip3 install --upgrade pip
pip3 install -r requirements.txt
```
#### Install system dependencies
```bash
chmod +x system_requirements.sh
./system_requirements.sh
```
#### Run the main installer
```bash
chmod +x install.sh
./install.sh
```
#### Verify installation
```bash
python3 check_deps.py
```

### **Method 2: Manual Installation**

#### Clone repository
```bash
git clone https://github.com/mdjahidshah/jsosint.git
cd jsosint
```
#### Install system packages
```bash
sudo apt update
sudo apt install -y \
    python3 python3-pip python3-venv git \
    nmap masscan dnsrecon whatweb nikto dirb \
    gobuster sqlmap wpscan sublist3r theharvester \
    sherlock maigret metagoofil recon-ng spiderfoot \
    chromium-driver
```
#### Setup virtual environment
```bash
python3 -m venv venv
source venv/bin/activate
```
#### Install Python packages
```bash
pip3 install --upgrade pip wheel setuptools
pip3 install -r requirements.txt
```
#### Setup the tool
```bash
chmod +x jsosint.py
sudo ln -sf "$(pwd)/jsosint.py" /usr/local/bin/jsosint
mkdir -p ~/.jsosint/{wordlists,results,logs}
```

### **Method 3: Docker Installation**

#### Clone and build
```bash
git clone https://github.com/mdjahidshah/jsosint.git
cd jsosint
docker build -t jsosint .
```
#### Run with volume mount for results
<!-- ```bash
docker run -it --rm -v $(pwd)/results:/app/results jsosint website example.com --basic
``` -->
---

## 🎯 Quick Start

### Use Cases

`jsosint` is the **Ultimate OSINT Suite v2.0.1**, designed to perform reconnaissance and information gathering on websites, persons, and networks. Below are the example use cases for each command.

---

#### 1. Website Recon (`website` / `w`)

Scan a target website to gather technical, DNS, port, and directory information.

**Basic Usage:**

```bash
python3 jsosint.py website example.com --besic
```
or

```bash
python3 jsosint.py w example.com --basic
```

**Options:**

* `--all` : Run all available website recon modules
* `--basic` : Perform basic analysis
* `--dns` : Gather DNS information
* `--whois` : Perform WHOIS lookup
* `--subdomains` : Find subdomains
* `--tech` : Detect technologies used
* `--directories` : Scan common directories
* `--emails` : Search for public emails
* `--ports` : Scan common ports
* `-o, --output` : Save results to a JSON file

**Example with Report:**

```bash
python3 jsosint.py w nasa.com --all -o nasa_report.json
```

---

#### 2. Person Recon (`person` / `p`)

Analyze a person’s online footprint using username, email, phone, IP, and other publicly available information.

**Basic Usage:**

```bash
python3 jsosint.py person johndoe --basic
```
or

```bash
python3 jsosint.py p johndoe --basic
```

**Options:**

* `--all` : Run all available person recon modules
* `--basic` : Perform basic analysis
* `--username` : Search by username
* `--email` : Search by email
* `--phone` : Search by phone number
* `--ip` : Search by IP address
* `--possible` : Check possible names
* `--breaches` : Search data breaches
* `--public` : Access public records
* `--social` : Search social media accounts
* `--domain_url` : Check associated domain URLs
* `-o, --output` : Save results to a JSON file

**Example with Report:**

```bash
python3 jsosint.py p janedoe --username --social -o jane_report.json
```

---

#### 3. Network Scan (`network` / `n`)

Perform active reconnaissance on a network, including ports, services, OS detection, and vulnerabilities.

**Basic Usage:**

```bash
python3 jsosint.py network 192.168.1.1 --ports
```
or 

```bash
python3 jsosint.py n 192.168.1.1 --ports
```

**Options:**

* `--all` : Run all available network scan modules
* `--ports` : Scan ports
* `--services` : Identify running services
* `--title` : Retrieve HTTP titles
* `--os` : Detect operating system
* `--vuln` : Check for vulnerabilities
* `--discovery` : Perform host discovery
* `--mac_vendor` : Get MAC vendor info
* `--traceroute` : Perform traceroute
* `--dns_enum` : Enumerate DNS records
* `-o, --output` : Save results to a JSON file

**Example with Report:**

```bash
python3 jsosint.py n 192.168.1.1 --ports --services --vuln -o network_report.json
```

---

#### 4. Version Check

To check the current version of `jsosint`:

```bash
python3 jsosint.py --version
```
or

```bash
python3 jsosint.py -v
```

---

### Notes

* Make sure all **dependencies are installed** and the **folder structure is intact**.
* JSON output files can be used for further analysis or reporting.
---

### **Activate Virtual Environment**
```bash
# Always activate the virtual environment first
source venv/bin/activate

# Your jsosint commands will now work
python3 jsosint.py --help
```
---

## 🔍 Usage Examples

### **Website Reconnaissance**
```bash
# Complete website scan
python3 jsosint.py w example.com --all

# Specific modules only
python3 jsosint.py w example.com --dns --whois --subdomains --ports

# Technology detection
python3 jsosint.py w example.com --tech --directories

# Vulnerability scan
python3 jsosint.py w example.com --vuln --history

# Save results to file
python3 jsosint.py w example.com --all -o results.json
python3 jsosint.py w example.com --all -o report.html --format html
```

### **Person Investigation**
```bash
# Social media search
jsosint person username --social --deep

# Email investigation
jsosint person email@example.com --social --breaches

# Phone number lookup
jsosint person "+1234567890" --social

# Complete person investigation
jsosint person target --all --deep
```

### **Network Scanning**
```bash
# Complete network scan
jsosint network 192.168.1.1 --all

# Port scanning only
jsosint network 192.168.1.0/24 --ports --ports-range "1-65535"

# Service and OS detection
jsosint network 192.168.1.1 --services --os --vuln

# Custom timing
jsosint network 192.168.1.1 --ports --timing 4
```

---

## 📊 Output Examples

### **Website Scan Output**
```bash
╔══════════════════════════════════════════════════════════════════╗
║    ██╗███████╗ ██████╗ ███████╗██╗███╗   ██╗████████╗            ║
║    ██║██╔════╝██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝            ║
║    ██║███████╗██║   ██║███████╗██║██╔██╗ ██║   ██║               ║
║ ██ ██║╚════██║██║   ██║╚════██║██║██║╚██╗██║   ██║               ║
║ ╚████║███████║╚██████╔╝███████║██║██║ ╚████║   ██║               ║
║  ╚═══╝╚══════╝ ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝               ║
║                                                                  ║
║     ULTIMATE OSINT SUITE v2.0.1  code by jahid                   ║
║          Complete Reconnaissance Toolkit                         ║
╚══════════════════════════════════════════════════════════════════╝

[*] Starting Website Reconnaissance
[*] Target: example.com
[*] Time: 2024-01-15 14:30:22
======================================================================

[1] Basic Information Gathering
  ✓ IP Address: 93.184.216.34
  ✓ HTTP Status: 200 OK
  ✓ Server: ECS (dcb/7F83)
  ✓ Title: Example Domain

[2] DNS Enumeration
  ✓ A Records: 93.184.216.34
  ✓ MX Records: mail.example.com
  ✓ NS Records: a.iana-servers.net, b.iana-servers.net
  ✓ TXT Records: v=spf1 -all

[3] Subdomain Discovery
  ✓ Found 12 subdomains
  ✓ www.example.com
  ✓ mail.example.com
  ✓ blog.example.com

[+] SCAN COMPLETED SUCCESSFULLY
======================================================================

[📊] Summary: IP: 93.184.216.34, A Records: 1, Subdomains: 12, Open Ports: 3
```

### **Person Scan Output**
```bash
[*] Starting Person Reconnaissance
[*] Target: johndoe
[*] Time: 2024-01-15 14:35:45
======================================================================

[1] Social Media Search
  ✓ GitHub: Found - 42 repositories, 120 followers
  ✓ Twitter: Found - 1,245 tweets, 890 followers
  ✓ LinkedIn: Found - Senior Developer at TechCorp
  ✗ Instagram: Not found
  ✗ Facebook: Not found

[2] Email Analysis
  ✓ Email: johndoe@gmail.com
  ✓ Breach Check: Found in 3 data breaches
  ✓ Gravatar: Profile found

[3] Relationship Mapping
  ✓ Common username patterns detected
  ✓ Found 2 related accounts
  ✓ Network strength: Medium

[+] SCAN COMPLETED SUCCESSFULLY
======================================================================

[📊] Summary: Social Media: 3 platforms, Breached: Yes, Related Accounts: 2
```

---

## 🛠️ Modules Overview

| Module | Description | Key Features |
|--------|-------------|--------------|
| **website** | Complete website reconnaissance | DNS, subdomains, tech stack, vulnerabilities |
| **person** | People search and investigation | Social media, email, breaches, relationships |
| **network** | Network scanning and enumeration | Ports, services, OS detection, vulnerabilities |
| **advanced** | Advanced OSINT techniques | API integrations, deep web, metadata extraction |

### **Integrated Kali Tools**
- **nmap** - Network exploration and security auditing
- **masscan** - Mass port scanner
- **dnsrecon** - DNS enumeration tool
- **whatweb** - Web technology identifier
- **nikto** - Web server scanner
- **dirb/gobuster** - Directory brute forcer
- **sqlmap** - SQL injection scanner
- **wpscan** - WordPress security scanner
- **sublist3r** - Subdomain enumeration
- **theHarvester** - Email and subdomain harvester
- **sherlock/maigret** - Social media finder
- **metagoofil** - Metadata extractor

---

## ⚙️ Configuration

### **Config File (`config.json`)**
```json
{
  "scan": {
    "timeout": 10,
    "threads": 10,
    "user_agent": "Mozilla/5.0 (compatible; jsosint/1.0)"
  },
  "output": {
    "format": "json",
    "save_location": "./results",
    "color_output": true
  },
  "api_keys": {
    "shodan": "YOUR_SHODAN_API_KEY",
    "censys_id": "YOUR_CENSYS_ID",
    "censys_secret": "YOUR_CENSYS_SECRET",
    "virustotal": "YOUR_VIRUSTOTAL_API_KEY"
  }
}
```

### **Custom Wordlists**
```bash
# Add custom wordlists to ~/.jsosint/wordlists/
cp custom_subdomains.txt ~/.jsosint/wordlists/
cp custom_directories.txt ~/.jsosint/wordlists/

# The tool will automatically detect and use them
```

### **API Keys Setup**
```bash
# Edit config.json to add your API keys for enhanced features
nano config.json

# Available API services:
# - Shodan: External intelligence
# - Censys: Certificate and host data
# - VirusTotal: Malware analysis
# - Hunter.io: Email finding
```

---

## 🔄 Updates & Maintenance

### **Updating JSOSINT**
```bash
cd jsosint

# Pull latest changes
git pull origin main

# Update dependencies
source venv/bin/activate
pip3 install -r requirements.txt --upgrade

# Run system updates if needed
./system_requirements.sh
```

### **Regular Maintenance**
```bash
# Clean old results
rm -rf results/*.json results/*.html

# Update wordlists
cd ~/.jsosint/wordlists
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt

# Check for tool updates
./check_deps.py
```

### **Performance Tips**
```bash
# Increase threads for faster scanning (config.json)
"threads": 20

# Adjust timeouts for slow networks
"timeout": 30

# Use Tor proxy for anonymous scanning
"tor_proxy": "socks5://127.0.0.1:9050"
```

---

## 🐛 Reporting Issues

### **Before Reporting**
1. Check if the issue already exists in [GitHub Issues](https://github.com/mdjahidshah/jsosint/issues)
2. Update to the latest version: `git pull origin main`
3. Run dependency check: `python3 check_deps.py`

### **Creating an Issue**
Provide the following information:
```markdown
## Description
[Brief description of the issue]

## Steps to Reproduce
1. Command: `python3 jsosint.py website example.com --all`
2. Expected: [What should happen]
3. Actual: [What actually happens]

## Environment
- OS: [Kali Linux 2023.4]
- Python: [3.11.4]
- JSOSINT Version: [1.0.0]
- Error Log: [Paste error message]

## Screenshots
[If applicable]
```

---

## 🤝 Contributing

We welcome contributions! Here's how you can help:

### **Ways to Contribute**
1. **Report bugs** - Create detailed bug reports
2. **Suggest features** - Open feature requests
3. **Write code** - Fix bugs or add new features
4. **Improve docs** - Enhance documentation
5. **Share wordlists** - Contribute better wordlists
6. **Test on different systems** - Help with compatibility

### **Development Setup**
```bash
# Fork and clone
git clone https://github.com/MdJahidShah/jsosint.git
cd jsosint

# Setup development environment
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
pip3 install -r requirements-dev.txt  # Development tools

# Create feature branch
git checkout -b feature/amazing-feature

# Make changes and test
python3 -m pytest tests/
black .  # Format code
flake8 .  # Check style

# Commit and push
git add .
git commit -m "Add amazing feature"
git push origin feature/amazing-feature

# Create Pull Request
```

### **Guidelines**
- Follow PEP 8 style guide
- Write meaningful commit messages
- Add tests for new features
- Update documentation
- Keep code modular and reusable

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.
---

## 🙏 Acknowledgments

### **Core Contributors**
- **[Md Jahid Shah](https://github.com/mdjahidshah)** - Creator & Maintainer
- **[Md Jahid Shah]** - Could be you! Contribute today.

### **Tools & Libraries**
- **Kali Linux Team** - Amazing penetration testing distribution
- **Nmap Project** - The world's premier network scanner
- **Shodan.io** - Search engine for Internet-connected devices
- **All open-source tool developers** integrated in jsosint

### **Community**
- **Security researchers** worldwide for continuous inspiration
- **Beta testers** for valuable feedback
- **GitHub community** for support and collaboration

### **Special Thanks To**
- Everyone who reported bugs and suggested features
- Contributors who improved documentation
- Users who shared wordlists and configurations
- The entire open-source security community

---

## 📞 Support

### **Documentation**
- **GitHub Wiki**: Complete documentation and tutorials
- **Examples Directory**: Sample scans and outputs
- **Video Tutorials**: Coming soon on YouTube

### **Community Support**
- **GitHub Issues**: [Report bugs & request features](https://github.com/mdjahidshah/jsosint/issues)
- **GitHub Discussions**: [Ask questions & share ideas](https://github.com/mdjahidshah/jsosint/discussions)
- **Discord Community**: Join our security community (Coming soon)

### **Professional Support**
- **Custom Integrations**: Need specific tool integrations?
- **Enterprise Features**: Require additional security features?
- **Training & Workshops**: Learn advanced OSINT techniques

**Contact**: Open a GitHub issue or discussion for professional inquiries.

---

## ⚠️ Disclaimer

**IMPORTANT LEGAL NOTICE**

This tool is designed for **LEGITIMATE SECURITY TESTING AND RESEARCH PURPOSES ONLY**.

### **Legal Usage**
- Security assessments of your own systems
- Authorized penetration testing
- Educational purposes in controlled environments
- Research with proper authorization

### **Prohibited Usage**
- Unauthorized scanning of systems you don't own
- Violating privacy laws and regulations
- Any illegal activities
- Harassment or stalking individuals

### **Developer Responsibility**
The developers of jsosint are **NOT RESPONSIBLE** for:
- Any misuse or damage caused by this program
- Legal consequences of unauthorized use
- Violation of terms of service of other platforms
- Any actions taken using information gathered by this tool

### **Ethical Guidelines**
1. **Always obtain proper authorization** before scanning
2. **Respect privacy** and applicable laws
3. **Use responsibly** and ethically
4. **Report vulnerabilities** responsibly to owners
5. **Follow platform terms of service**

**By using this tool, you agree to use it only for legitimate, authorized purposes and accept full responsibility for your actions.**

---

## ☕ Support

If you find JSOSINT useful and want to support its development:

### **Buy Me a Coffee**
[![Buy Me A Coffee](https://img.shields.io/badge/Buy_Me_A_Coffee-FFDD00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black)](https://buymeacoffee.com/jahidshah)

### **Other Ways to Support**
1. **Star the repository** ⭐ - It helps others discover the tool
2. **Share with colleagues** - Spread the word in the security community
3. **Contribute code** - Help improve the tool
4. **Report issues** - Help make it better
5. **Write tutorials** - Share your knowledge

### **Why Support?**
Your support helps:
- Maintain and update the tool regularly
- Add new features and integrations
- Fix bugs and improve performance
- Create better documentation
- Support the open-source community

**Thank you for your support! 🙏**

---

## 🌟 Star History

[![Star History Chart](https://api.star-history.com/svg?repos=mdjahidshah/jsosint&type=Date)](https://star-history.com/#mdjahidshah/jsosint&Date)

---

## 📈 Statistics

![GitHub repo size](https://img.shields.io/github/repo-size/mdjahidshah/jsosint?style=flat-square)
![GitHub last commit](https://img.shields.io/github/last-commit/mdjahidshah/jsosint?style=flat-square)
![GitHub issues](https://img.shields.io/github/issues/mdjahidshah/jsosint?style=flat-square)
![GitHub pull requests](https://img.shields.io/github/issues-pr/mdjahidshah/jsosint?style=flat-square)

---

**Happy Reconnaissance! 🕵️‍♂️**

*Remember: With great power comes great responsibility. Use JSOSINT ethically and legally.*