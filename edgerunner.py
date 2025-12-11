#!/usr/bin/env python3
"""
Edgerunner - Advanced CDN Bypass & Real IP Discovery Tool
Author: Nicollas "M1racle" Alcantara
Purpose: Professional penetration testing tool for authorized security assessments
"""

import argparse
import asyncio
import concurrent.futures
import json
import logging
import socket
import ssl
import sys
import time
import warnings
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import dns.resolver
import requests
from colorama import Fore, Style, init
from tabulate import tabulate

# Disable SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

# Initialize colorama for cross-platform colored output
init(autoreset=True)

# Configuration
DEFAULT_TIMEOUT = 5
DEFAULT_THREADS = 20
MAX_THREADS = 100
DNS_SERVERS = [
    '8.8.8.8',  # Google
    '1.1.1.1',  # Cloudflare
    '208.67.222.222',  # OpenDNS
]

# CDN Indicators
CDN_HEADERS = {
    'cloudflare': ['cf-ray', 'cf-cache-status', '__cfduid'],
    'cloudfront': ['x-amz-cf-id', 'x-amz-cf-pop', 'via'],
    'akamai': ['x-akamai-transformed', 'x-akamai-request-id'],
    'fastly': ['x-fastly-request-id', 'fastly-stats'],
    'incapsula': ['x-iinfo', 'x-cdn'],
    'maxcdn': ['x-cache', 'x-cache-hit'],
    'sucuri': ['x-sucuri-id', 'x-sucuri-cache'],
}

# Known CDN IP Ranges (simplified for demonstration)
CDN_IP_RANGES = {
    'cloudflare': ['173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22'],
    'cloudfront': ['13.32.0.0/15', '13.35.0.0/16'],
}


@dataclass
class ScanResult:
    """Data class for scan results"""
    target: str
    ip_address: Optional[str]
    cdn_detected: bool
    cdn_provider: Optional[str]
    response_time: float
    additional_ips: List[str]
    headers: Dict[str, str]
    error: Optional[str] = None


class Logger:
    """Custom logger with colored output"""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.setup_logging()
    
    def setup_logging(self):
        """Setup logging configuration"""
        log_format = '%(asctime)s - %(levelname)s - %(message)s'
        logging.basicConfig(
            level=logging.DEBUG if self.verbose else logging.INFO,
            format=log_format,
            handlers=[
                logging.FileHandler(f'cdn_bypass_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    @staticmethod
    def info(message: str):
        print(f"{Fore.CYAN}[*]{Style.RESET_ALL} {message}")
    
    @staticmethod
    def success(message: str):
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {message}")
    
    @staticmethod
    def warning(message: str):
        print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {message}")
    
    @staticmethod
    def error(message: str):
        print(f"{Fore.RED}[-]{Style.RESET_ALL} {message}")
    
    @staticmethod
    def banner():
        banner_text = f"""
{Fore.CYAN}
 ███████╗██████╗  ██████╗ ███████╗██████╗ ██╗   ██╗███╗   ██╗███╗   ██╗███████╗██████╗ 
 ██╔════╝██╔══██╗██╔════╝ ██╔════╝██╔══██╗██║   ██║████╗  ██║████╗  ██║██╔════╝██╔══██╗
 █████╗  ██║  ██║██║  ███╗█████╗  ██████╔╝██║   ██║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
 ██╔══╝  ██║  ██║██║   ██║██╔══╝  ██╔══██╗██║   ██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
 ███████╗██████╔╝╚██████╔╝███████╗██║  ██║╚██████╔╝██║ ╚████║██║ ╚████║███████╗██║  ██║
 ╚══════╝╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
{Style.RESET_ALL}
{Fore.GREEN}              Advanced CDN Bypass & Real IP Discovery Tool v1.0{Style.RESET_ALL}
{Fore.YELLOW}              Tool created by N. "M1racle" A.{Style.RESET_ALL}
{Fore.WHITE}              ───────────────────────────────────────────────{Style.RESET_ALL}
"""
        print(banner_text)


class DNSResolver:
    """Advanced DNS resolution with multiple techniques"""
    
    def __init__(self, timeout: int = DEFAULT_TIMEOUT):
        self.timeout = timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = DNS_SERVERS
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
    
    def resolve_a_records(self, domain: str) -> List[str]:
        """Resolve A records for domain"""
        try:
            answers = self.resolver.resolve(domain, 'A')
            return [str(rdata) for rdata in answers]
        except Exception as e:
            logging.debug(f"A record resolution failed for {domain}: {e}")
            return []
    
    def resolve_aaaa_records(self, domain: str) -> List[str]:
        """Resolve AAAA records (IPv6) for domain"""
        try:
            answers = self.resolver.resolve(domain, 'AAAA')
            return [str(rdata) for rdata in answers]
        except Exception:
            return []
    
    def get_all_ips(self, domain: str) -> List[str]:
        """Get all IP addresses (IPv4 and IPv6)"""
        ips = []
        ips.extend(self.resolve_a_records(domain))
        ips.extend(self.resolve_aaaa_records(domain))
        return list(set(ips))  # Remove duplicates


class CDNDetector:
    """Detect CDN presence and provider"""
    
    @staticmethod
    def detect_cdn_from_headers(headers: Dict[str, str]) -> Tuple[bool, Optional[str]]:
        """Detect CDN from HTTP headers"""
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        for cdn_name, indicators in CDN_HEADERS.items():
            for indicator in indicators:
                if indicator.lower() in headers_lower:
                    return True, cdn_name
        
        # Check Server header
        server = headers_lower.get('server', '').lower()
        if 'cloudflare' in server:
            return True, 'cloudflare'
        elif 'cloudfront' in server:
            return True, 'cloudfront'
        
        return False, None
    
    @staticmethod
    def check_cdn_ip_range(ip: str) -> Optional[str]:
        """Check if IP belongs to known CDN range"""
        # Simplified check - in production, use proper CIDR matching
        for cdn_name, ranges in CDN_IP_RANGES.items():
            for ip_range in ranges:
                # This is a placeholder - implement proper CIDR checking
                if ip.startswith(ip_range.split('/')[0].rsplit('.', 1)[0]):
                    return cdn_name
        return None


class CDNBypassScanner:
    """Main scanner class with advanced bypass techniques"""
    
    def __init__(self, timeout: int = DEFAULT_TIMEOUT, threads: int = DEFAULT_THREADS):
        self.timeout = timeout
        self.threads = min(threads, MAX_THREADS)
        self.dns_resolver = DNSResolver(timeout)
        self.cdn_detector = CDNDetector()
        self.session = self._create_session()
        self.results: List[ScanResult] = []
    
    def _create_session(self) -> requests.Session:
        """Create configured requests session"""
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        session.verify = False  # Disable SSL verification for CDN bypass
        return session
    
    def _normalize_domain(self, domain: str) -> str:
        """Normalize domain from URL or plain domain"""
        if domain.startswith(('http://', 'https://')):
            parsed = urlparse(domain)
            return parsed.netloc or parsed.path
        return domain.strip()
    
    def _get_origin_ip_techniques(self, domain: str) -> List[str]:
        """Advanced techniques to find origin IP behind CDN"""
        origin_ips = []
        
        # Technique 1: Check mail server records (MX)
        try:
            mx_records = self.dns_resolver.resolver.resolve(domain, 'MX')
            for mx in mx_records:
                mx_domain = str(mx.exchange).rstrip('.')
                mx_ips = self.dns_resolver.get_all_ips(mx_domain)
                origin_ips.extend(mx_ips)
        except Exception:
            pass
        
        # Technique 2: Historical DNS records via subdomain enumeration
        common_subdomains = ['direct', 'origin', 'admin', 'cpanel', 'ftp', 'mail', 'webmail']
        for sub in common_subdomains:
            try:
                sub_domain = f"{sub}.{domain}"
                ips = self.dns_resolver.get_all_ips(sub_domain)
                origin_ips.extend(ips)
            except Exception:
                pass
        
        # Technique 3: Check for IPv4 specifically
        try:
            ipv4_records = self.dns_resolver.resolve_a_records(domain)
            origin_ips.extend(ipv4_records)
        except Exception:
            pass
        
        # Technique 4: Try to get IP from direct connection
        try:
            direct_ip = socket.gethostbyname(domain)
            if direct_ip:
                origin_ips.append(direct_ip)
        except Exception:
            pass
        
        # Filter out CDN IPs and keep only unique IPs
        unique_ips = list(set(origin_ips))
        filtered_ips = []
        
        for ip in unique_ips:
            # Skip IPv6 if we want IPv4 primarily
            if ':' not in ip:  # IPv4 check
                # Check if IP is not from CDN range
                cdn = self.cdn_detector.check_cdn_ip_range(ip)
                if not cdn:
                    filtered_ips.append(ip)
        
        return filtered_ips
    
    def _probe_http(self, target: str, scheme: str = 'https') -> Tuple[Dict[str, str], float]:
        """Probe target with HTTP/HTTPS"""
        start_time = time.time()
        try:
            url = f"{scheme}://{target}"
            response = self.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=True
            )
            elapsed = time.time() - start_time
            return dict(response.headers), elapsed
        except requests.exceptions.SSLError:
            if scheme == 'https':
                return self._probe_http(target, 'http')
            return {}, 0
        except Exception as e:
            logging.debug(f"HTTP probe failed for {target}: {e}")
            return {}, 0
    
    def _get_ssl_certificate_info(self, domain: str) -> Dict[str, str]:
        """Extract information from SSL certificate"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((domain, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    return {
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'subject': dict(x[0] for x in cert['subject']),
                        'san': cert.get('subjectAltName', [])
                    }
        except Exception as e:
            logging.debug(f"SSL certificate extraction failed for {domain}: {e}")
            return {}
    
    def scan_target(self, target: str) -> ScanResult:
        """Comprehensive scan of a single target"""
        target = self._normalize_domain(target)
        Logger.info(f"Scanning {target}...")
        
        try:
            # DNS Resolution - get all IPs
            all_ips = self.dns_resolver.get_all_ips(target)
            primary_ip = all_ips[0] if all_ips else None
            
            # HTTP Probing
            headers, response_time = self._probe_http(target)
            
            # CDN Detection
            cdn_detected, cdn_provider = self.cdn_detector.detect_cdn_from_headers(headers)
            
            # Additional CDN check from IP
            if primary_ip and not cdn_provider:
                cdn_provider = self.cdn_detector.check_cdn_ip_range(primary_ip)
                if cdn_provider:
                    cdn_detected = True
            
            # If CDN detected, try to find origin IP
            origin_ips = []
            if cdn_detected:
                Logger.info(f"CDN detected ({cdn_provider}), attempting bypass...")
                origin_ips = self._get_origin_ip_techniques(target)
                
                # Prefer IPv4 origin IPs
                ipv4_origins = [ip for ip in origin_ips if ':' not in ip]
                if ipv4_origins:
                    primary_ip = ipv4_origins[0]
                    origin_ips = ipv4_origins[1:]
                elif origin_ips:
                    primary_ip = origin_ips[0]
                    origin_ips = origin_ips[1:]
            
            return ScanResult(
                target=target,
                ip_address=primary_ip,
                cdn_detected=cdn_detected,
                cdn_provider=cdn_provider,
                response_time=response_time,
                additional_ips=origin_ips,
                headers=headers
            )
        
        except Exception as e:
            return ScanResult(
                target=target,
                ip_address=None,
                cdn_detected=False,
                cdn_provider=None,
                response_time=0,
                additional_ips=[],
                headers={},
                error=str(e)
            )
    
    def scan_multiple(self, targets: List[str]) -> List[ScanResult]:
        """Scan multiple targets with threading"""
        Logger.info(f"Starting scan of {len(targets)} targets with {self.threads} threads")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_target = {
                executor.submit(self.scan_target, target): target 
                for target in targets
            }
            
            results = []
            for future in concurrent.futures.as_completed(future_to_target):
                try:
                    result = future.result()
                    results.append(result)
                    
                    if result.ip_address:
                        status = f"{Fore.GREEN}FOUND{Style.RESET_ALL}"
                        bypass_info = ""
                        if result.cdn_detected:
                            status += f" (CDN: {result.cdn_provider or 'Unknown'})"
                            if result.additional_ips:
                                bypass_info = f" | Origin IPs: {', '.join(result.additional_ips[:3])}"
                        Logger.success(f"{result.target}: {result.ip_address} - {status}{bypass_info}")
                    else:
                        Logger.warning(f"{result.target}: No IP found")
                
                except Exception as e:
                    Logger.error(f"Error scanning {future_to_target[future]}: {e}")
        
        self.results = results
        return results
    
    def generate_subdomains(self, domain: str, wordlist: Optional[List[str]] = None) -> List[str]:
        """Generate subdomain list"""
        if wordlist:
            return [f"{sub}.{domain}" for sub in wordlist]
        
        # Default common subdomains
        default_subs = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'mobile', 'api', 'app',
            'dev', 'staging', 'test', 'admin', 'portal', 'vpn', 'backup', 'git', 'cloud'
        ]
        return [f"{sub}.{domain}" for sub in default_subs]


class ReportGenerator:
    """Generate various report formats"""
    
    @staticmethod
    def print_table(results: List[ScanResult]):
        """Print results as formatted table"""
        table_data = []
        for result in results:
            cdn_status = "No"
            if result.cdn_detected:
                cdn_status = f"Yes ({result.cdn_provider or 'Unknown'})"
                if result.additional_ips:
                    cdn_status += " [BYPASSED]"
            
            # Show additional origin IPs if found
            ip_display = result.ip_address or "N/A"
            if result.additional_ips:
                ip_display += f"\n+ {len(result.additional_ips)} more"
            
            table_data.append([
                result.target,
                ip_display,
                cdn_status,
                f"{result.response_time:.2f}s" if result.response_time > 0 else "N/A",
                "Success" if result.ip_address else ("Error" if result.error else "Not Found")
            ])
        
        print("\n" + "="*120)
        print(tabulate(
            table_data,
            headers=['Target', 'IP Address (Origin)', 'CDN Status', 'Response Time', 'Status'],
            tablefmt='grid'
        ))
        print("="*120 + "\n")
        
        # Print detailed origin IPs if found
        for result in results:
            if result.additional_ips:
                print(f"{Fore.CYAN}[*] Additional Origin IPs for {result.target}:{Style.RESET_ALL}")
                for ip in result.additional_ips:
                    print(f"    {Fore.GREEN}→{Style.RESET_ALL} {ip}")
                print()
    
    @staticmethod
    def save_json(results: List[ScanResult], filename: str):
        """Save results to JSON file"""
        data = []
        for result in results:
            data.append({
                'target': result.target,
                'ip_address': result.ip_address,
                'cdn_detected': result.cdn_detected,
                'cdn_provider': result.cdn_provider,
                'response_time': result.response_time,
                'additional_ips': result.additional_ips,
                'error': result.error
            })
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        
        Logger.success(f"Results saved to {filename}")
    
    @staticmethod
    def print_summary(results: List[ScanResult]):
        """Print scan summary"""
        total = len(results)
        found = sum(1 for r in results if r.ip_address)
        cdn_detected = sum(1 for r in results if r.cdn_detected)
        errors = sum(1 for r in results if r.error)
        
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}SCAN SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"Total Targets Scanned: {total}")
        print(f"IPs Found: {Fore.GREEN}{found}{Style.RESET_ALL}")
        print(f"CDN Detected: {Fore.YELLOW}{cdn_detected}{Style.RESET_ALL}")
        print(f"Errors: {Fore.RED}{errors}{Style.RESET_ALL}")
        print(f"Success Rate: {Fore.GREEN}{(found/total*100):.1f}%{Style.RESET_ALL}\n")


def load_wordlist(filepath: str) -> List[str]:
    """Load wordlist from file"""
    try:
        with open(filepath, 'r') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except Exception as e:
        Logger.error(f"Failed to load wordlist: {e}")
        return []


def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(
        description='Edgerunner - Advanced CDN Bypass & Real IP Discovery Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan single domain
  %(prog)s example.com
  
  # Scan domain with subdomains
  %(prog)s example.com --subdomains
  
  # Scan from domain list file
  %(prog)s -d domains.txt
  
  # Use custom subdomain wordlist
  %(prog)s example.com -w wordlist.txt --subdomains
  
  # Save results to JSON
  %(prog)s example.com -o results.json
  
  # Advanced scan with custom threads and timeout
  %(prog)s example.com -s -t 50 --timeout 10 -v
  
For authorized penetration testing only.
        """
    )
    
    parser.add_argument(
        'target',
        nargs='?',
        help='Target domain to scan (use -d for domain list file)'
    )
    parser.add_argument(
        '-d', '--domain-list',
        dest='domains',
        help='File containing list of domains to scan (one per line)'
    )
    parser.add_argument(
        '-w', '--wordlist',
        help='Custom subdomain wordlist file'
    )
    parser.add_argument(
        '-s', '--subdomains',
        action='store_true',
        help='Scan subdomains using default/custom wordlist'
    )
    parser.add_argument(
        '-t', '--threads',
        type=int,
        default=DEFAULT_THREADS,
        help=f'Number of threads (default: {DEFAULT_THREADS}, max: {MAX_THREADS})'
    )
    parser.add_argument(
        '--timeout',
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f'Request timeout in seconds (default: {DEFAULT_TIMEOUT})'
    )
    parser.add_argument(
        '-o', '--output',
        help='Output file for JSON results'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose output'
    )
    
    args = parser.parse_args()
    
    # Validate input
    if not args.target and not args.domains:
        parser.print_help()
        Logger.error("\nError: You must specify either a target domain or a domain list file (-d)")
        Logger.info("Examples:")
        Logger.info("  python edgerunner.py example.com")
        Logger.info("  python edgerunner.py -d domains.txt")
        sys.exit(1)
    
    # Initialize
    Logger.banner()
    logger = Logger(verbose=args.verbose)
    scanner = CDNBypassScanner(timeout=args.timeout, threads=args.threads)
    
    # Prepare targets
    targets = []
    
    if args.domains:
        # Load from file
        Logger.info(f"Loading domains from file: {args.domains}")
        targets = load_wordlist(args.domains)
        if not targets:
            Logger.error(f"No valid domains found in {args.domains}")
            sys.exit(1)
        Logger.success(f"Loaded {len(targets)} domains from file")
    elif args.target:
        # Single domain or domain with subdomains
        targets = [args.target]
        Logger.info(f"Target domain: {args.target}")
        
        if args.subdomains:
            Logger.info("Generating subdomain list...")
            wordlist = load_wordlist(args.wordlist) if args.wordlist else None
            subdomains = scanner.generate_subdomains(args.target, wordlist)
            targets.extend(subdomains)
            Logger.success(f"Generated {len(subdomains)} subdomains to scan")
    
    if not targets:
        Logger.error("No targets to scan!")
        sys.exit(1)
    
    # Execute scan
    start_time = time.time()
    results = scanner.scan_multiple(targets)
    elapsed_time = time.time() - start_time
    
    # Generate reports
    ReportGenerator.print_table(results)
    ReportGenerator.print_summary(results)
    
    Logger.info(f"Scan completed in {elapsed_time:.2f} seconds")
    
    # Save results
    if args.output:
        ReportGenerator.save_json(results, args.output)
    
    # Exit with appropriate code
    sys.exit(0 if any(r.ip_address for r in results) else 1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        Logger.warning("\nScan interrupted by user")
        sys.exit(130)
    except Exception as e:
        Logger.error(f"Fatal error: {e}")
        sys.exit(1)
