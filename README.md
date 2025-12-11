# Edgerunner

**CDN Bypass & Real IP Discovery Tool**

> A penetration testing tool designed to discover real IP addresses hidden behind Content Delivery Networks (CDNs) like Cloudflare, CloudFront, Akamai, and others.

---

## Features

- **Multi-CDN Detection**: Automatically detects major CDN providers (Cloudflare, CloudFront, Akamai, Fastly, Incapsula, etc.)
- **Advanced Bypass Techniques**: Uses multiple methods to discover origin IPs:
  - MX Record Analysis
  - Subdomain Enumeration (`direct`, `origin`, `admin`, `cpanel`, `ftp`, etc.)
  - Historical DNS Records
  - Direct Connection Probing
  - IPv4/IPv6 Resolution
- **Concurrent Scanning**: Multi-threaded architecture for fast scanning (configurable up to 100 threads)
- **Subdomain Discovery**: Built-in subdomain enumeration with custom wordlist support
- **Multiple Input Methods**: Scan single domains, multiple domains from file, or with subdomain wordlists
- **Professional Output**: 
  - Color-coded terminal output
  - Formatted tables with detailed results
  - JSON export for further processing
  - Comprehensive scan statistics
- **Cross-Platform**: Works on Linux, macOS, and Windows

---

## Table of Contents

- [Installation](#-installation)
- [Usage](#-usage)
- [Examples](#-examples)
- [CDN Bypass Techniques](#-cdn-bypass-techniques)
- [Output Format](#-output-format)
- [Legal Disclaimer](#-legal-disclaimer)
- [Contributing](#-contributing)
- [License](#-license)

---

## Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

### Quick Install

```bash
# Clone the repository
git clone https://github.com/yourusername/edgerunner.git
cd edgerunner

# Create virtual environment (recommended)
python3 -m venv env
source env/bin/activate  # On Windows: env\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Dependencies

```
requests>=2.31.0
dnspython>=2.4.0
colorama>=0.4.6
tabulate>=0.9.0
```

---

## Usage

### Basic Syntax

```bash
python3 edgerunner.py [target] [options]
```

### Command-Line Options

```
positional arguments:
  target                Target domain to scan

options:
  -h, --help            Show this help message and exit
  -d, --domain-list FILE
                        File containing list of domains to scan (one per line)
  -w, --wordlist FILE   Custom subdomain wordlist file (use with -s)
  -s, --subdomains      Scan subdomains using default/custom wordlist
  -t, --threads THREADS
                        Number of threads (default: 20, max: 100)
  --timeout TIMEOUT     Request timeout in seconds (default: 5)
  -o, --output FILE     Output file for JSON results
  -v, --verbose         Verbose output with detailed logging
```

### Important Notes

- **`-d`** flag: Use for a list of **DOMAINS** (e.g., `example.com`, `target.com`)
- **`-w`** flag: Use for a list of **SUBDOMAINS** (e.g., `www`, `api`, `admin`)

---

## Examples

### 1. Scan a Single Domain

```bash
python3 edgerunner.py example.com
```

### 2. Scan Domain with Subdomain Enumeration

```bash
# Using default subdomain wordlist
python3 edgerunner.py example.com --subdomains

# Or short form
python3 edgerunner.py example.com -s
```

### 3. Scan Multiple Domains from File

Create a file `domains.txt`:
```
example.com
target.com
mysite.net
```

Run the scan:
```bash
python3 edgerunner.py -d domains.txt
```

### 4. Use Custom Subdomain Wordlist

Create a file `subdomains.txt`:
```
www
api
admin
dev
staging
mail
ftp
vpn
```

Run the scan:
```bash
python3 edgerunner.py example.com -s -w subdomains.txt
```

### 5. Advanced Scan with Custom Settings

```bash
python3 edgerunner.py example.com \
  --subdomains \
  --threads 50 \
  --timeout 10 \
  --output results.json \
  --verbose
```

### 6. Combine Domain List with Subdomain Scanning

```bash
python3 edgerunner.py -d domains.txt -s -w custom_subs.txt
```

### 7. Quick Scan with Results Export

```bash
python3 edgerunner.py example.com -s -o scan_results.json
```

---

## CDN Bypass Techniques

Edgerunner employs multiple sophisticated techniques to discover origin IPs behind CDN protection:

### 1. **MX Record Analysis**
Many organizations host their mail servers on the same infrastructure as their web servers. By resolving MX records, we can often find IPs that aren't protected by the CDN.

### 2. **Subdomain Enumeration**
Common subdomains like `direct.`, `origin.`, `admin.`, `cpanel.`, and `ftp.` are frequently configured to bypass CDN protection for administrative or technical reasons.

### 3. **Historical DNS Records**
The tool attempts to find DNS records that may not be proxied through the CDN.

### 4. **Direct Connection Probing**
Establishes direct connections to discover real server IPs.

### 5. **IPv4 Prioritization**
Focuses on IPv4 addresses as they're more commonly used for origin servers, filtering out known CDN IP ranges.

### 6. **CDN Range Filtering**
Maintains a database of known CDN IP ranges to filter out proxied addresses and focus on actual origin servers.

---

## Output Format

### Terminal Output

```
[*] Target domain: example.com
[*] Starting scan of 1 targets with 20 threads
[*] Scanning example.com...
[*] CDN detected (cloudflare), attempting bypass...
[+] example.com: 192.168.1.100 - FOUND (CDN: cloudflare) | Origin IPs: 10.0.0.1, 10.0.0.2

════════════════════════════════════════════════════════════════════════════════
Target          | IP Address (Origin) | CDN Status              | Response Time | Status
example.com     | 192.168.1.100       | Yes (cloudflare)        | 1.67s        | Success
                | + 2 more            | [BYPASSED]              |              |
════════════════════════════════════════════════════════════════════════════════

[*] Additional Origin IPs for example.com:
    → 10.0.0.1
    → 10.0.0.2

════════════════════════════════════════════════════════════
SCAN SUMMARY
════════════════════════════════════════════════════════════
Total Targets Scanned: 1
IPs Found: 1
CDN Detected: 1
CDN Bypassed (Origin IPs Found): 1
Errors: 0
Success Rate: 100.0%
Bypass Rate: 100.0%
```

### JSON Output

When using the `-o` flag, results are saved in JSON format:

```json
[
  {
    "target": "example.com",
    "ip_address": "192.168.1.100",
    "cdn_detected": true,
    "cdn_provider": "cloudflare",
    "response_time": 1.67,
    "additional_ips": [
      "10.0.0.1",
      "10.0.0.2"
    ],
    "error": null
  }
]
```

---

## Color Coding

- 🟢 **Green**: Successful operations and found IPs
- 🟡 **Yellow**: Warnings and CDN detections
- 🔵 **Cyan**: Informational messages
- 🔴 **Red**: Errors and failed operations

---

## Performance Tips

1. **Adjust Thread Count**: For scanning many targets, increase threads (max 100)
   ```bash
   python3 edgerunner.py -d large_list.txt -t 80
   ```

2. **Timeout Configuration**: Adjust timeout based on network conditions
   ```bash
   python3 edgerunner.py example.com --timeout 10
   ```

3. **Subdomain Wordlist**: Use focused wordlists for specific industries
   ```bash
   python3 edgerunner.py example.com -s -w tech_company_subs.txt
   ```

4. **Verbose Mode**: Enable for debugging or detailed analysis
   ```bash
   python3 edgerunner.py example.com -v
   ```

---

## Detected CDN Providers

Edgerunner can detect and attempt to bypass the following CDN providers:

- **Cloudflare** - Most common CDN/WAF service
- **AWS CloudFront** - Amazon's CDN service
- **Akamai** - Enterprise-level CDN
- **Fastly** - Modern edge cloud platform
- **Incapsula (Imperva)** - Security-focused CDN
- **MaxCDN (StackPath)** - Content delivery network
- **Sucuri** - Website security and CDN

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/AmazingFeature`)
3. **Commit** your changes (`git commit -m 'Add some AmazingFeature'`)
4. **Push** to the branch (`git push origin feature/AmazingFeature`)
5. **Open** a Pull Request

### Development Setup

```bash
# Install development dependencies
pip install pytest black flake8 mypy

# Run tests
pytest tests/

# Format code
black edgerunner.py

# Lint code
flake8 edgerunner.py
```

---

## Changelog

### Version 1.0 (Current)
- Complete rewrite with professional architecture
- CDN bypass techniques
- Beautiful terminal output with colors
- JSON export functionality
- Configurable threading and timeouts
- IPv4/IPv6 support
- Detailed statistics and reporting
---

## Known Issues

- Some CDNs with strict security configurations may not be bypassable
- IPv6 resolution may vary depending on network configuration
- Rate limiting may occur on DNS queries for large scans

---

## Resources

- [DNS Resolution Techniques](https://www.cloudflare.com/learning/dns/what-is-dns/)
- [CDN Architecture](https://www.cloudflare.com/learning/cdn/what-is-a-cdn/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Penetration Testing Framework](http://www.vulnerabilityassessment.co.uk/Penetration%20Test.html)

---

## 👨‍💻 Author

**Nicollas "M1racle" Alcantara**

- GitHub: [@niklaz4](https://github.com/niklaz4)

---

<div align="center">
  
**⭐ If you find this tool useful, please consider giving it a star! ⭐**

Made with ❤️ for the Security Community

</div>
