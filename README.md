# Edgerunner

**CDN Bypass & Real IP Discovery Tool**

> A penetration testing tool designed to discover real IP addresses hidden behind Content Delivery Networks (CDNs) like Cloudflare, CloudFront, Akamai, and others using advanced bypass techniques including WHOIS block discovery, Shodan integration, and direct CDN probing.

---

## Features

- **Multi-CDN Detection**: Automatically detects major CDN providers (Cloudflare, CloudFront, Akamai, Fastly, Incapsula, etc.)
- **Advanced Bypass Techniques**: Uses multiple methods to discover origin IPs:
  - **WHOIS IP Block Discovery** 🆕 - Identifies corporate infrastructure IP blocks and tests entire ranges
  - **Shodan API Integration** 🆕 - Leverages Shodan's database for comprehensive reconnaissance
  - **Direct CDN IP Testing** 🆕 - Tests direct connections to CDN IPs with custom Host headers (httpx-style)
  - MX Record Analysis
  - Subdomain Enumeration (`direct`, `origin`, `admin`, `cpanel`, `ftp`, etc.)
  - Historical DNS Records
  - Direct Connection Probing
  - IPv4/IPv6 Resolution
  - Complete CIDR Range Matching
- **Concurrent Scanning**: Multi-threaded architecture for fast scanning (configurable up to 100 threads)
- **Subdomain Discovery**: Built-in subdomain enumeration with custom wordlist support
- **Multiple Input Methods**: Scan single domains, multiple domains from file, or with subdomain wordlists
- **Professional Output**: 
  - Color-coded terminal output
  - Formatted tables with detailed results
  - JSON export with comprehensive data
  - Scan statistics with bypass rate metrics
- **Cross-Platform**: Works on Linux, macOS, and Windows

---

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
- [Examples](#examples)
- [CDN Bypass Techniques](#cdn-bypass-techniques)
- [Output Format](#output-format)
- [Legal Disclaimer](#legal-disclaimer)
- [Contributing](#contributing)
- [License](#license)

---

## Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Shodan API key (optional, for enhanced scanning)

### Quick Install

```bash
# Clone the repository
git clone https://github.com/niklaz4/edgerunner.git
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
shodan>=1.30.0
urllib3>=2.0.0
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
  --shodan-api KEY      Shodan API key for enhanced scanning
  -o, --output FILE     Output file for JSON results
  -v, --verbose         Verbose output with detailed logging
```

### Important Notes

- **`-d`** flag: Use for a list of **DOMAINS** (e.g., `example.com`, `target.com`)
- **`-w`** flag: Use for a list of **SUBDOMAINS** (e.g., `www`, `api`, `admin`)
- **`--shodan-api`**: Enables Shodan integration for discovering indexed hosts

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

### 3. Scan with Shodan Integration

```bash
python3 edgerunner.py example.com --shodan-api YOUR_API_KEY
```

### 4. Scan Multiple Domains from File

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

### 5. Use Custom Subdomain Wordlist

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

### 6. Advanced Scan with All Features

```bash
python3 edgerunner.py example.com \
  --subdomains \
  --shodan-api YOUR_API_KEY \
  --threads 50 \
  --timeout 10 \
  --output results.json \
  --verbose
```

### 7. Corporate Infrastructure Discovery

```bash
# Ideal for large organizations with their own IP blocks
python3 edgerunner.py bank.com -s -v
```

### 8. Quick Scan with Results Export

```bash
python3 edgerunner.py example.com -s -o scan_results.json
```

---

## CDN Bypass Techniques

Edgerunner employs multiple sophisticated techniques to discover origin IPs behind CDN protection:

### 1. **WHOIS IP Block Discovery** 🆕
When a subdomain resolves to a non-CDN IP (common in corporate infrastructure), the tool:
- Performs WHOIS lookup on the discovered IP
- Extracts the organization's registered IP block (CIDR range)
- Expands and tests additional IPs from the same block
- Particularly effective for banks, enterprises, and large corporations

**Example**: If `mail.bank.com` → `203.0.113.50`, and WHOIS shows the block `203.0.113.0/24` belongs to the bank, the tool will test other IPs in that range.

### 2. **Shodan API Integration** 🆕
Leverages Shodan's massive database to:
- Search for all hosts associated with the target domain
- Retrieve indexed IPs, open ports, and service information
- Discover historical and current infrastructure
- Access SSL certificate data and hostname information

**Usage**: Provide your Shodan API key with `--shodan-api` parameter.

### 3. **Direct CDN IP Testing** 🆕
Tests direct connections to CDN IP ranges using:
- Custom `Host` header to target domain
- Direct HTTP/HTTPS requests to CDN edge nodes
- SNI (Server Name Indication) manipulation
- Response analysis (status code, content-length, page title)

Similar to `httpx` tool behavior, this technique can reveal:
- CDN configuration issues
- Origin server leaks
- Direct access paths

### 4. **MX Record Analysis**
Many organizations host their mail servers on the same infrastructure as their web servers. By resolving MX records, we can often find IPs that aren't protected by the CDN.

### 5. **Subdomain Enumeration**
Common subdomains like `direct.`, `origin.`, `admin.`, `cpanel.`, and `ftp.` are frequently configured to bypass CDN protection for administrative or technical reasons.

### 6. **Historical DNS Records**
The tool attempts to find DNS records that may not be proxied through the CDN.

### 7. **Direct Connection Probing**
Establishes direct connections to discover real server IPs.

### 8. **IPv4 Prioritization**
Focuses on IPv4 addresses as they're more commonly used for origin servers, filtering out known CDN IP ranges.

### 9. **Complete CIDR Range Filtering**
Maintains an extensive database of known CDN IP ranges (complete CIDR notation) to accurately filter out proxied addresses:
- Cloudflare: 15+ IP ranges
- CloudFront: 12+ IP ranges
- Akamai: 4+ IP ranges
- Fastly: 6+ IP ranges

---

## Output Format

### Terminal Output

```
[*] Target domain: example.com
[*] Starting scan of 1 targets with 20 threads
[*] Scanning example.com...
[*] CDN detected (cloudflare), attempting bypass...
[+] Found organization IP block: 203.0.113.0/24
[*] Querying Shodan for example.com...
[+] Shodan found 3 IPs
[*] Direct CDN hit: cloudflare 104.16.1.1 - Status: 200
[+] example.com: 203.0.113.50 - FOUND (CDN: cloudflare) | Origin IPs: 47 | Block: 203.0.113.0/24

══════════════════════════════════════════════════════════════════════════════════════════
Target       | IP Address (Origin) | CDN Status        | Response Time | Additional Info           | Status
example.com  | 203.0.113.50        | Yes (cloudflare)  | 1.67s        | Block: 203.0.113.0/24     | Success
             | + 47 more           | [BYPASSED]        |              | Shodan: 3 hosts           |
══════════════════════════════════════════════════════════════════════════════════════════

[*] Additional Origin IPs for example.com:
    → 203.0.113.51
    → 203.0.113.52
    → 203.0.113.53
    ... and 44 more

[*] Direct CDN Test Results for example.com:
    → cloudflare 104.16.1.1 - Status: 200 - Title: Example Domain

══════════════════════════════════════════════════════════
SCAN SUMMARY
══════════════════════════════════════════════════════════
Total Targets Scanned: 1
IPs Found: 1
CDN Detected: 1
CDN Bypassed: 1
Shodan Hits: 1
Errors: 0
Success Rate: 100.0%
```

### JSON Output

When using the `-o` flag, results are saved in comprehensive JSON format:

```json
[
  {
    "target": "example.com",
    "ip_address": "203.0.113.50",
    "cdn_detected": true,
    "cdn_provider": "cloudflare",
    "response_time": 1.67,
    "additional_ips": [
      "203.0.113.51",
      "203.0.113.52",
      "203.0.113.53"
    ],
    "whois_block": "203.0.113.0/24",
    "shodan_data": {
      "total": 3,
      "matches": [
        {
          "ip": "203.0.113.50",
          "port": 443,
          "org": "Example Organization",
          "hostnames": ["example.com"],
          "domains": ["example.com"]
        }
      ]
    },
    "direct_cdn_test": [
      {
        "provider": "cloudflare",
        "ip": "104.16.1.1",
        "status_code": 200,
        "content_length": 1256,
        "title": "Example Domain",
        "server": "cloudflare",
        "success": true
      }
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

3. **Shodan Integration**: Use Shodan for comprehensive results (requires API key)
   ```bash
   python3 edgerunner.py example.com --shodan-api YOUR_KEY
   ```

4. **Subdomain Wordlist**: Use focused wordlists for specific industries
   ```bash
   python3 edgerunner.py example.com -s -w tech_company_subs.txt
   ```

5. **Verbose Mode**: Enable for debugging or detailed analysis
   ```bash
   python3 edgerunner.py example.com -v
   ```

6. **Combined Approach**: Use all features for maximum coverage
   ```bash
   python3 edgerunner.py example.com -s --shodan-api KEY -t 50 -v
   ```

---

## Detected CDN Providers

Edgerunner can detect and attempt to bypass the following CDN providers:

- **Cloudflare** - Most common CDN/WAF service (15+ IP ranges)
- **AWS CloudFront** - Amazon's CDN service (12+ IP ranges)
- **Akamai** - Enterprise-level CDN (4+ IP ranges)
- **Fastly** - Modern edge cloud platform (6+ IP ranges)
- **Incapsula (Imperva)** - Security-focused CDN
- **MaxCDN (StackPath)** - Content delivery network
- **Sucuri** - Website security and CDN

---

## Getting a Shodan API Key

1. Create a free account at [shodan.io](https://account.shodan.io/register)
2. Login and go to [Account Overview](https://account.shodan.io/)
3. Copy your API key from the "API Key" section
4. Use it with `--shodan-api` parameter

**Free tier includes**: 100 query credits per month

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

### Version 2.0 (Current) 🆕
- **WHOIS IP Block Discovery** - Automatic corporate infrastructure mapping
- **Shodan API Integration** - Leverage massive host database
- **Direct CDN IP Testing** - httpx-style direct connection probing
- **Complete CIDR Ranges** - Expanded CDN IP range database
- **Enhanced Output** - Additional info columns and statistics
- **Code Refactoring** - Cleaner architecture, removed comments
- **Improved Detection** - Better IPv4/IPv6 handling and filtering

### Version 2.1
- Initial release with core CDN bypass techniques
- Multi-threaded scanning architecture
- Subdomain enumeration
- JSON export functionality
- Professional terminal output

---

## Known Issues

- Some CDNs with strict security configurations may not be bypassable
- IPv6 resolution may vary depending on network configuration
- Rate limiting may occur on DNS queries for large scans
- Shodan API has query limits (100/month for free tier)
- WHOIS lookups may be rate-limited by providers

---

## Legal Disclaimer

⚠️ **IMPORTANT**: This tool is designed for **authorized security testing only**.

- Only use on systems you own or have explicit permission to test
- Unauthorized access to computer systems is illegal
- The author is not responsible for misuse or damage caused by this tool
- Always comply with local laws and regulations
- Obtain proper authorization before testing

**By using this tool, you agree to use it responsibly and legally.**

---

## Resources

- [DNS Resolution Techniques](https://www.cloudflare.com/learning/dns/what-is-dns/)
- [CDN Architecture](https://www.cloudflare.com/learning/cdn/what-is-a-cdn/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Shodan Documentation](https://developer.shodan.io/)
- [WHOIS Protocol](https://www.ietf.org/rfc/rfc3912.txt)
- [Penetration Testing Framework](http://www.vulnerabilityassessment.co.uk/Penetration%20Test.html)

---

## 👨💻 Author

**Nicollas "M1racle" Alcantara**

- GitHub: [@niklaz4](https://github.com/niklaz4)

---

<div align="center">
  
**⭐ If you find this tool useful, please consider giving it a star! ⭐**

Made with ❤️ for the Security Community

</div>
