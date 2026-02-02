#!/usr/bin/env python3

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
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse
import ipaddress
import re

try:
    import dns.resolver
    import requests
    import shodan
    from colorama import Fore, Style, init
    from tabulate import tabulate
except ImportError as e:
    print(f"Error: Missing required dependency - {e}")
    print("Install with: pip install dnspython requests shodan colorama tabulate --break-system-packages")
    sys.exit(1)

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

init(autoreset=True)

DEFAULT_TIMEOUT = 5
DEFAULT_THREADS = 20
MAX_THREADS = 100
DNS_SERVERS = ['8.8.8.8', '1.1.1.1', '208.67.222.222']

CDN_HEADERS = {
    'cloudflare': ['cf-ray', 'cf-cache-status', '__cfduid'],
    'cloudfront': ['x-amz-cf-id', 'x-amz-cf-pop', 'via'],
    'akamai': ['x-akamai-transformed', 'x-akamai-request-id'],
    'fastly': ['x-fastly-request-id', 'fastly-stats'],
    'incapsula': ['x-iinfo', 'x-cdn'],
    'maxcdn': ['x-cache', 'x-cache-hit'],
    'sucuri': ['x-sucuri-id', 'x-sucuri-cache'],
}

CDN_IP_RANGES = {
    'cloudflare': [
        '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
        '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
        '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
        '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22'
    ],
    'cloudfront': [
        '13.32.0.0/15', '13.35.0.0/16', '13.224.0.0/14', '13.249.0.0/16',
        '18.160.0.0/15', '52.84.0.0/15', '54.230.0.0/16', '54.239.128.0/18',
        '99.84.0.0/16', '205.251.192.0/19', '204.246.172.0/23', '204.246.164.0/22'
    ],
    'akamai': [
        '23.0.0.0/12', '104.64.0.0/10', '184.24.0.0/13', '2.16.0.0/13'
    ],
    'fastly': [
        '23.235.32.0/20', '43.249.72.0/22', '103.244.50.0/24', '103.245.222.0/23',
        '151.101.0.0/16', '157.52.64.0/18'
    ]
}


@dataclass
class ScanResult:
    target: str
    ip_address: Optional[str]
    cdn_detected: bool
    cdn_provider: Optional[str]
    response_time: float
    additional_ips: List[str]
    headers: Dict[str, str]
    shodan_data: Optional[Dict] = None
    whois_block: Optional[str] = None
    direct_cdn_test: Optional[Dict] = None
    error: Optional[str] = None


class Logger:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.setup_logging()
    
    def setup_logging(self):
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
{Fore.GREEN}              CDN Bypass & Real IP Discovery Tool v2.1{Style.RESET_ALL}
{Fore.YELLOW}              Tool created by N. "M1racle" A.{Style.RESET_ALL}
{Fore.WHITE}              ───────────────────────────────────────────────{Style.RESET_ALL}
"""
        print(banner_text)


class WhoisResolver:
    @staticmethod
    def get_ip_block(ip: str) -> Optional[str]:
        try:
            response = requests.get(f'https://ipinfo.io/{ip}/json', timeout=5)
            if response.status_code == 200:
                data = response.json()
                org = data.get('org', '')
                if org:
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+/\d+)', org)
                    if match:
                        return match.group(1)
            
            response = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    return data.get('org', '')
            
            return None
        except Exception as e:
            logging.debug(f"WHOIS lookup failed for {ip}: {e}")
            return None
    
    @staticmethod
    def get_org_ips(org_block: str, count: int = 256) -> List[str]:
        try:
            network = ipaddress.ip_network(org_block, strict=False)
            return [str(ip) for ip in list(network.hosts())[:count]]
        except Exception as e:
            logging.debug(f"Failed to expand IP block {org_block}: {e}")
            return []


class ShodanScanner:
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.client = None
        if api_key:
            try:
                self.client = shodan.Shodan(api_key)
                Logger.success("Shodan API initialized")
            except Exception as e:
                Logger.error(f"Failed to initialize Shodan API: {e}")
    
    def search_domain(self, domain: str) -> Optional[Dict]:
        if not self.client:
            return None
        
        try:
            results = self.client.search(f'hostname:{domain}')
            return {
                'total': results.get('total', 0),
                'matches': [
                    {
                        'ip': match.get('ip_str'),
                        'port': match.get('port'),
                        'org': match.get('org'),
                        'hostnames': match.get('hostnames', []),
                        'domains': match.get('domains', [])
                    }
                    for match in results.get('matches', [])[:10]
                ]
            }
        except Exception as e:
            logging.debug(f"Shodan search failed for {domain}: {e}")
            return None
    
    def get_host_info(self, ip: str) -> Optional[Dict]:
        if not self.client:
            return None
        
        try:
            host = self.client.host(ip)
            return {
                'ip': host.get('ip_str'),
                'org': host.get('org'),
                'ports': host.get('ports', []),
                'hostnames': host.get('hostnames', []),
                'domains': host.get('domains', [])
            }
        except Exception as e:
            logging.debug(f"Shodan host lookup failed for {ip}: {e}")
            return None


class DirectCDNTester:
    def __init__(self, timeout: int = 3):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive'
        })
        self.session.verify = False
    
    def test_cdn_ip(self, cdn_ip: str, domain: str, path: str = "/", schema: str = "https") -> Optional[Dict]:
        try:
            url = f"{schema}://{cdn_ip}{path}"
            
            response = self.session.get(
                url,
                headers={'Host': domain},
                timeout=self.timeout,
                allow_redirects=False
            )
            
            return {
                'ip': cdn_ip,
                'status_code': response.status_code,
                'content_length': len(response.content),
                'title': self._extract_title(response.text),
                'server': response.headers.get('Server', ''),
                'location': response.headers.get('Location', ''),
                'success': 200 <= response.status_code < 400
            }
        except Exception as e:
            logging.debug(f"Direct CDN test failed for {cdn_ip}: {e}")
            return None
    
    @staticmethod
    def _extract_title(html: str) -> str:
        try:
            match = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
            return match.group(1).strip() if match else ''
        except:
            return ''
    
    def test_multiple_cdn_ips(self, domain: str, path: str = "/", schema: str = "https") -> List[Dict]:
        results = []
        
        for provider, ip_ranges in CDN_IP_RANGES.items():
            for ip_range in ip_ranges[:2]:
                try:
                    network = ipaddress.ip_network(ip_range, strict=False)
                    for ip in list(network.hosts())[:5]:
                        result = self.test_cdn_ip(str(ip), domain, path, schema)
                        if result and result['success']:
                            result['provider'] = provider
                            results.append(result)
                            Logger.info(f"Direct CDN hit: {provider} {ip} - Status: {result['status_code']}")
                except Exception as e:
                    logging.debug(f"Failed to test IP range {ip_range}: {e}")
        
        return results


class DNSResolver:
    def __init__(self, timeout: int = DEFAULT_TIMEOUT):
        self.timeout = timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = DNS_SERVERS
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
    
    def resolve_a_records(self, domain: str) -> List[str]:
        try:
            answers = self.resolver.resolve(domain, 'A')
            return [str(rdata) for rdata in answers]
        except Exception as e:
            logging.debug(f"A record resolution failed for {domain}: {e}")
            return []
    
    def resolve_aaaa_records(self, domain: str) -> List[str]:
        try:
            answers = self.resolver.resolve(domain, 'AAAA')
            return [str(rdata) for rdata in answers]
        except Exception:
            return []
    
    def resolve_mx_records(self, domain: str) -> List[str]:
        try:
            answers = self.resolver.resolve(domain, 'MX')
            return [str(rdata.exchange).rstrip('.') for rdata in answers]
        except Exception:
            return []
    
    def resolve_txt_records(self, domain: str) -> List[str]:
        try:
            answers = self.resolver.resolve(domain, 'TXT')
            return [str(rdata) for rdata in answers]
        except Exception:
            return []
    
    def get_all_ips(self, domain: str) -> List[str]:
        ips = []
        ips.extend(self.resolve_a_records(domain))
        ips.extend(self.resolve_aaaa_records(domain))
        return list(set(ips))


class CDNDetector:
    @staticmethod
    def detect_cdn_from_headers(headers: Dict[str, str]) -> Tuple[bool, Optional[str]]:
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        for cdn_name, indicators in CDN_HEADERS.items():
            for indicator in indicators:
                if indicator.lower() in headers_lower:
                    return True, cdn_name
        
        server = headers_lower.get('server', '').lower()
        if 'cloudflare' in server:
            return True, 'cloudflare'
        elif 'cloudfront' in server:
            return True, 'cloudfront'
        elif 'akamai' in server:
            return True, 'akamai'
        
        return False, None
    
    @staticmethod
    def check_cdn_ip_range(ip: str) -> Optional[str]:
        try:
            ip_obj = ipaddress.ip_address(ip)
            for cdn_name, ranges in CDN_IP_RANGES.items():
                for ip_range in ranges:
                    network = ipaddress.ip_network(ip_range, strict=False)
                    if ip_obj in network:
                        return cdn_name
        except Exception as e:
            logging.debug(f"IP range check failed for {ip}: {e}")
        return None


class CDNBypassScanner:
    def __init__(self, timeout: int = DEFAULT_TIMEOUT, threads: int = DEFAULT_THREADS, 
                 shodan_api: Optional[str] = None):
        self.timeout = timeout
        self.threads = min(threads, MAX_THREADS)
        self.dns_resolver = DNSResolver(timeout)
        self.cdn_detector = CDNDetector()
        self.shodan_scanner = ShodanScanner(shodan_api)
        self.direct_tester = DirectCDNTester(timeout)
        self.whois_resolver = WhoisResolver()
        self.session = self._create_session()
        self.results: List[ScanResult] = []
    
    def _create_session(self) -> requests.Session:
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
        session.verify = False
        return session
    
    def _normalize_domain(self, domain: str) -> str:
        if domain.startswith(('http://', 'https://')):
            parsed = urlparse(domain)
            return parsed.netloc or parsed.path
        return domain.strip()
    
    def _get_origin_ip_techniques(self, domain: str) -> Tuple[List[str], Optional[str]]:
        origin_ips = []
        whois_block = None
        
        mx_records = self.dns_resolver.resolve_mx_records(domain)
        for mx in mx_records:
            mx_ips = self.dns_resolver.get_all_ips(mx)
            origin_ips.extend(mx_ips)
        
        common_subdomains = ['direct', 'origin', 'admin', 'cpanel', 'ftp', 'mail', 
                            'webmail', 'smtp', 'pop', 'ns1', 'ns2', 'vpn', 'backup']
        
        for sub in common_subdomains:
            try:
                sub_domain = f"{sub}.{domain}"
                ips = self.dns_resolver.get_all_ips(sub_domain)
                
                for ip in ips:
                    if ':' not in ip:
                        cdn = self.cdn_detector.check_cdn_ip_range(ip)
                        if not cdn:
                            origin_ips.append(ip)
                            
                            if not whois_block:
                                block = self.whois_resolver.get_ip_block(ip)
                                if block and '/' in block:
                                    whois_block = block
                                    Logger.success(f"Found organization IP block: {block}")
                                    
                                    block_ips = self.whois_resolver.get_org_ips(block, 50)
                                    origin_ips.extend(block_ips)
            except Exception as e:
                logging.debug(f"Subdomain enumeration failed for {sub}.{domain}: {e}")
        
        try:
            ipv4_records = self.dns_resolver.resolve_a_records(domain)
            origin_ips.extend(ipv4_records)
        except Exception:
            pass
        
        try:
            direct_ip = socket.gethostbyname(domain)
            if direct_ip:
                origin_ips.append(direct_ip)
        except Exception:
            pass
        
        unique_ips = list(set(origin_ips))
        filtered_ips = []
        
        for ip in unique_ips:
            if ':' not in ip:
                cdn = self.cdn_detector.check_cdn_ip_range(ip)
                if not cdn:
                    filtered_ips.append(ip)
        
        return filtered_ips, whois_block
    
    def _probe_http(self, target: str, scheme: str = 'https') -> Tuple[Dict[str, str], float]:
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
    
    def scan_target(self, target: str) -> ScanResult:
        target = self._normalize_domain(target)
        Logger.info(f"Scanning {target}...")
        
        try:
            all_ips = self.dns_resolver.get_all_ips(target)
            primary_ip = all_ips[0] if all_ips else None
            
            headers, response_time = self._probe_http(target)
            
            cdn_detected, cdn_provider = self.cdn_detector.detect_cdn_from_headers(headers)
            
            if primary_ip and not cdn_provider:
                cdn_provider = self.cdn_detector.check_cdn_ip_range(primary_ip)
                if cdn_provider:
                    cdn_detected = True
            
            origin_ips = []
            whois_block = None
            shodan_data = None
            direct_cdn_results = None
            
            if cdn_detected:
                Logger.info(f"CDN detected ({cdn_provider}), attempting bypass...")
                origin_ips, whois_block = self._get_origin_ip_techniques(target)
                
                ipv4_origins = [ip for ip in origin_ips if ':' not in ip]
                if ipv4_origins:
                    primary_ip = ipv4_origins[0]
                    origin_ips = ipv4_origins[1:]
                elif origin_ips:
                    primary_ip = origin_ips[0]
                    origin_ips = origin_ips[1:]
                
                direct_cdn_results = self.direct_tester.test_multiple_cdn_ips(target)
                if direct_cdn_results:
                    Logger.success(f"Found {len(direct_cdn_results)} direct CDN responses")
            
            if self.shodan_scanner.client:
                Logger.info(f"Querying Shodan for {target}...")
                shodan_data = self.shodan_scanner.search_domain(target)
                
                if shodan_data and shodan_data.get('matches'):
                    shodan_ips = [m['ip'] for m in shodan_data['matches'] if m.get('ip')]
                    origin_ips.extend([ip for ip in shodan_ips if ip not in origin_ips])
                    Logger.success(f"Shodan found {len(shodan_ips)} IPs")
            
            return ScanResult(
                target=target,
                ip_address=primary_ip,
                cdn_detected=cdn_detected,
                cdn_provider=cdn_provider,
                response_time=response_time,
                additional_ips=origin_ips[:20],
                headers=headers,
                shodan_data=shodan_data,
                whois_block=whois_block,
                direct_cdn_test=direct_cdn_results
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
                                bypass_info = f" | Origin IPs: {len(result.additional_ips)}"
                            if result.whois_block:
                                bypass_info += f" | Block: {result.whois_block}"
                        Logger.success(f"{result.target}: {result.ip_address} - {status}{bypass_info}")
                    else:
                        Logger.warning(f"{result.target}: No IP found")
                
                except Exception as e:
                    Logger.error(f"Error scanning {future_to_target[future]}: {e}")
        
        self.results = results
        return results
    
    def generate_subdomains(self, domain: str, wordlist: Optional[List[str]] = None) -> List[str]:
        if wordlist:
            return [f"{sub}.{domain}" for sub in wordlist]
        
        default_subs = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'mobile', 'api', 'app',
            'dev', 'staging', 'test', 'admin', 'portal', 'vpn', 'backup', 'git', 'cloud'
        ]
        return [f"{sub}.{domain}" for sub in default_subs]


class ReportGenerator:
    @staticmethod
    def print_table(results: List[ScanResult]):
        table_data = []
        for result in results:
            cdn_status = "No"
            if result.cdn_detected:
                cdn_status = f"Yes ({result.cdn_provider or 'Unknown'})"
                if result.additional_ips:
                    cdn_status += " [BYPASSED]"
            
            ip_display = result.ip_address or "N/A"
            if result.additional_ips:
                ip_display += f"\n+ {len(result.additional_ips)} more"
            
            extra_info = []
            if result.whois_block:
                extra_info.append(f"Block: {result.whois_block}")
            if result.shodan_data and result.shodan_data.get('total', 0) > 0:
                extra_info.append(f"Shodan: {result.shodan_data['total']} hosts")
            
            table_data.append([
                result.target,
                ip_display,
                cdn_status,
                f"{result.response_time:.2f}s" if result.response_time > 0 else "N/A",
                '\n'.join(extra_info) if extra_info else "N/A",
                "Success" if result.ip_address else ("Error" if result.error else "Not Found")
            ])
        
        print("\n" + "="*140)
        print(tabulate(
            table_data,
            headers=['Target', 'IP Address (Origin)', 'CDN Status', 'Response Time', 'Additional Info', 'Status'],
            tablefmt='grid'
        ))
        print("="*140 + "\n")
        
        for result in results:
            if result.additional_ips:
                print(f"{Fore.CYAN}[*] Additional Origin IPs for {result.target}:{Style.RESET_ALL}")
                for ip in result.additional_ips[:10]:
                    print(f"    {Fore.GREEN}→{Style.RESET_ALL} {ip}")
                if len(result.additional_ips) > 10:
                    print(f"    ... and {len(result.additional_ips) - 10} more")
                print()
            
            if result.direct_cdn_test:
                print(f"{Fore.CYAN}[*] Direct CDN Test Results for {result.target}:{Style.RESET_ALL}")
                for test in result.direct_cdn_test[:5]:
                    print(f"    {Fore.GREEN}→{Style.RESET_ALL} {test['provider']} {test['ip']} - "
                          f"Status: {test['status_code']} - Title: {test['title'][:50]}")
                print()
    
    @staticmethod
    def save_json(results: List[ScanResult], filename: str):
        data = []
        for result in results:
            result_dict = asdict(result)
            data.append(result_dict)
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        
        Logger.success(f"Results saved to {filename}")
    
    @staticmethod
    def print_summary(results: List[ScanResult]):
        total = len(results)
        found = sum(1 for r in results if r.ip_address)
        cdn_detected = sum(1 for r in results if r.cdn_detected)
        bypassed = sum(1 for r in results if r.cdn_detected and r.additional_ips)
        errors = sum(1 for r in results if r.error)
        shodan_hits = sum(1 for r in results if r.shodan_data and r.shodan_data.get('total', 0) > 0)
        
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}SCAN SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"Total Targets Scanned: {total}")
        print(f"IPs Found: {Fore.GREEN}{found}{Style.RESET_ALL}")
        print(f"CDN Detected: {Fore.YELLOW}{cdn_detected}{Style.RESET_ALL}")
        print(f"CDN Bypassed: {Fore.GREEN}{bypassed}{Style.RESET_ALL}")
        if shodan_hits > 0:
            print(f"Shodan Hits: {Fore.CYAN}{shodan_hits}{Style.RESET_ALL}")
        print(f"Errors: {Fore.RED}{errors}{Style.RESET_ALL}")
        print(f"Success Rate: {Fore.GREEN}{(found/total*100):.1f}%{Style.RESET_ALL}\n")


def load_wordlist(filepath: str) -> List[str]:
    try:
        with open(filepath, 'r') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except Exception as e:
        Logger.error(f"Failed to load wordlist: {e}")
        return []


def main():
    parser = argparse.ArgumentParser(
        description='Edgerunner - Advanced CDN Bypass & Real IP Discovery Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python edgerunner.py example.com
  python edgerunner.py example.com --subdomains
  python edgerunner.py -d domains.txt
  python edgerunner.py example.com -w wordlist.txt --subdomains
  python edgerunner.py example.com -o results.json
  python edgerunner.py example.com --shodan-api YOUR_API_KEY
  python edgerunner.py example.com -s -t 50 --timeout 10 -v

For authorized penetration testing only.
        """
    )
    
    parser.add_argument('target', nargs='?', help='Target domain to scan')
    parser.add_argument('-d', '--domain-list', dest='domains', help='File with domain list')
    parser.add_argument('-w', '--wordlist', help='Custom subdomain wordlist file')
    parser.add_argument('-s', '--subdomains', action='store_true', help='Scan subdomains')
    parser.add_argument('-t', '--threads', type=int, default=DEFAULT_THREADS, 
                       help=f'Number of threads (default: {DEFAULT_THREADS})')
    parser.add_argument('--timeout', type=int, default=DEFAULT_TIMEOUT,
                       help=f'Request timeout in seconds (default: {DEFAULT_TIMEOUT})')
    parser.add_argument('-o', '--output', help='Output JSON file')
    parser.add_argument('--shodan-api', help='Shodan API key for enhanced scanning')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    if not args.target and not args.domains:
        parser.print_help()
        Logger.error("\nError: Specify a target domain or domain list file (-d)")
        sys.exit(1)
    
    Logger.banner()
    logger = Logger(verbose=args.verbose)
    scanner = CDNBypassScanner(timeout=args.timeout, threads=args.threads, shodan_api=args.shodan_api)
    
    targets = []
    
    if args.domains:
        Logger.info(f"Loading domains from file: {args.domains}")
        targets = load_wordlist(args.domains)
        if not targets:
            Logger.error(f"No valid domains found in {args.domains}")
            sys.exit(1)
        Logger.success(f"Loaded {len(targets)} domains from file")
    elif args.target:
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
    
    start_time = time.time()
    results = scanner.scan_multiple(targets)
    elapsed_time = time.time() - start_time
    
    ReportGenerator.print_table(results)
    ReportGenerator.print_summary(results)
    
    Logger.info(f"Scan completed in {elapsed_time:.2f} seconds")
    
    if args.output:
        ReportGenerator.save_json(results, args.output)
    
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
