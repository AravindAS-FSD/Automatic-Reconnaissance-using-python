# recon_tool.py (Corrected and Final Version)

import socket
import ssl
import whois
import dns.resolver
import requests
from bs4 import BeautifulSoup
import builtwith
import re
from datetime import datetime
from colorama import init, Fore, Style
import argparse
import os
import sys
import time
import concurrent.futures

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options as ChromeOptions
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

init(autoreset=True)

# --- CONFIGURATION (API KEYS) ---
VIRUSTOTAL_API_KEY = "647aa3ff9c57ecc1862b61d60f76076959588abdd429d7a6f11b2c48b04fb0a7"
SHODAN_API_KEY = "G3vOPzqm664C94hW2TLw4sBgovUM4cEy"
SECURITYTRAILS_API_KEY = "S1VocFXF22WpZVCkXlScwy3dj2TomFaJ"
URLSCAN_API_KEY = "0199134c-9f56-7498-8ea4-6e1f4d500ac6"

# --- Logger Class (No changes needed) ---
class Logger:
    def __init__(self, filename):
        self.terminal = sys.stdout
        self.logfile = open(filename, 'w', encoding='utf-8')
        self.clean_regex = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    def write(self, message):
        self.terminal.write(message)
        clean_message = self.clean_regex.sub('', message)
        self.logfile.write(clean_message)
    def flush(self):
        self.terminal.flush()
        self.logfile.flush()

# --- Print Helper Functions (No changes needed) ---
def print_title(title): print(f"\n{Fore.CYAN}{Style.BRIGHT}{'='*20} {title.upper()} {'='*20}{Style.RESET_ALL}")
def print_entry(key, value):
    if value:
        if isinstance(value, list) and value:
            print(f"{Fore.GREEN}{key:<25}:{Style.RESET_ALL}"); [print(f"  - {item}") for item in value]
        elif isinstance(value, dict):
            print(f"{Fore.GREEN}{key:<25}:{Style.RESET_ALL}"); [print_entry(f"  {k}", v) for k, v in value.items()]
        else: print(f"{Fore.GREEN}{key:<25}:{Style.RESET_ALL} {value}")
    else: print(f"{Fore.RED}{key:<25}:{Style.RESET_ALL} Not Found / Not Applicable")

# --- Recon Functions (No changes needed) ---
def get_basic_info(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        info = {"IP Address": ip_address}
        try: info["Hostname (Reverse DNS)"] = socket.gethostbyaddr(ip_address)[0]
        except socket.herror: info["Hostname (Reverse DNS)"] = "No record found"
        try:
            resp = requests.get(f"https://ipinfo.io/{ip_address}/json", timeout=5); data = resp.json()
            info["Geolocation"] = f"{data.get('city', 'N/A')}, {data.get('region', 'N/A')}, {data.get('country', 'N/A')} ({data.get('org', 'N/A')})"
        except requests.RequestException: info["Geolocation"] = "Lookup failed"
        return ip_address, info
    except socket.gaierror: return None, {"Error": f"Domain '{domain}' could not be resolved."}
def take_screenshot(domain):
    if not SELENIUM_AVAILABLE: return "Selenium library not found. Skipping."
    filename = f"screenshot_{domain}.png"; driver = None
    try:
        options = webdriver.ChromeOptions(); options.add_argument("--headless"); options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage"); options.add_argument("--window-size=1280,720")
        driver = webdriver.Chrome(options=options); driver.get(f"https://{domain}"); driver.save_screenshot(filename)
        return f"Success! Screenshot saved as: {os.path.abspath(filename)}"
    except Exception as e: return f"Could not take screenshot. Error: {e}"
    finally:
        if driver: driver.quit()
def get_whois(domain):
    try: w = whois.whois(domain); return {"Registrar": w.registrar, "Creation Date": w.creation_date, "Expiration Date": w.expiration_date, "Name Servers": w.name_servers}
    except Exception as e: return {"Error": str(e)}
def get_dns_records(domain):
    records = {}
    for r_type in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']:
        try: answers = dns.resolver.resolve(domain, r_type); records[f"{r_type} Records"] = [r.to_text() for r in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers): records[f"{r_type} Records"] = "No records found"
    return records
def get_ssl_certificate(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert(); issuer = dict(x[0] for x in cert.get('issuer', []))
                return {"Issuer": issuer.get('organizationName', 'N/A'), "Valid From": cert['notBefore'], "Valid To": cert['notAfter'], "Subject Alt Names (SANs)": [v for k, v in cert.get('subjectAltName', [])]}
    except Exception as e: return {"Error": str(e)}
def analyze_website(domain):
    try:
        response = requests.get(f"https://{domain}", timeout=10, headers={'User-Agent': 'Mozilla/5.0'}, allow_redirects=True)
        techs = builtwith.parse(response.url)
        return {"Status Code": response.status_code, "Server": response.headers.get('Server'), "Technology Stack": {k.replace('-', ' ').title(): ", ".join(v) for k, v in techs.items()} if techs else "None detected"}
    except Exception as e: return {"Error": str(e)}
def get_subdomains_from_api(domain):
    if not SECURITYTRAILS_API_KEY: return "API key not configured."
    try:
        resp = requests.get(f"https://api.securitytrails.com/v1/domain/{domain}/subdomains", headers={'APIKEY': SECURITYTRAILS_API_KEY})
        if resp.status_code == 200: return [f"{sub}.{domain}" for sub in resp.json()['subdomains']]
        return {"Error": f"API returned status {resp.status_code}"}
    except Exception as e: return {"Error": str(e)}
def check_shodan(ip):
    if not SHODAN_API_KEY: return "API key not configured."
    try:
        resp = requests.get(f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}")
        if resp.status_code == 200: data = resp.json(); return {"Organization": data.get('org', 'N/A'), "OS": data.get('os', 'N/A'), "Open Ports": data.get('ports', [])}
        return "No information found in Shodan."
    except Exception as e: return {"Error": str(e)}
def check_virustotal(domain):
    if not VIRUSTOTAL_API_KEY: return "API key not configured."
    try:
        resp = requests.get(f'https://www.virustotal.com/api/v3/domains/{domain}', headers={'x-apikey': VIRUSTOTAL_API_KEY})
        if resp.status_code == 200: stats = resp.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {}); return {"Malicious": stats.get('malicious', 0), "Suspicious": stats.get('suspicious', 0)}
        return {"Error": f"API returned status {resp.status_code}"}
    except Exception as e: return {"Error": str(e)}

# --- MAIN EXECUTION BLOCK (CORRECTED) ---

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Optimized OSINT Tool.", epilog="Example: python3 recon_tool.py google.com --output report.txt")
    parser.add_argument("domain", help="The target domain to scan")
    
    # ***** FIX #1: ADD THE --output ARGUMENT *****
    parser.add_argument("--output", help="The file path to save the text report to.", required=True)
    
    args = parser.parse_args()
    
    domain_parts = args.domain.split('.')
    target_domain = '.'.join(domain_parts[1:]) if len(domain_parts) > 2 and domain_parts[0] == 'www' else args.domain
    
    # ***** FIX #1 (CONTINUED): USE THE --output ARGUMENT *****
    report_filename = args.output
    sys.stdout = Logger(report_filename)

    print(f"Starting optimized reconnaissance for: {target_domain}")
    print(f"Report will be saved to: {os.path.abspath(report_filename)}")
    start_time = time.perf_counter()

    ip, basic_info = get_basic_info(target_domain)
    all_results = {"Basic Information": basic_info}

    # ***** FIX #2: CHECK FOR DOMAIN RESOLUTION FAILURE *****
    if not ip:
        print(f"\n{Fore.RED}[-] CRITICAL ERROR: Could not resolve the domain '{target_domain}'. Reconnaissance cannot continue.{Style.RESET_ALL}")
        # Exit with a non-zero code to signal failure to the GUI
        sys.exit(1)

    # This part only runs if the IP was found successfully
    tasks = {
        "Homepage Screenshot": (take_screenshot, (target_domain,)), "WHOIS Information": (get_whois, (target_domain,)),
        "DNS Records": (get_dns_records, (target_domain,)), "SSL/TLS Certificate": (get_ssl_certificate, (target_domain,)),
        "Website Analysis": (analyze_website, (target_domain,)), "Shodan Host Information": (check_shodan, (ip,)),
        "Subdomain Discovery (API)": (get_subdomains_from_api, (target_domain,)), "VirusTotal Reputation": (check_virustotal, (target_domain,))
    }
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(tasks)) as executor:
        future_to_task = {executor.submit(func, *args): name for name, (func, args) in tasks.items()}
        for future in concurrent.futures.as_completed(future_to_task):
            task_name = future_to_task[future]
            try: all_results[task_name] = future.result(); print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {task_name} data collected.")
            except Exception as e: all_results[task_name] = {"Error": str(e)}; print(f"{Fore.RED}[-]{Style.RESET_ALL} {task_name} failed: {e}")

    print(f"\n{Fore.MAGENTA}{Style.BRIGHT}--- FINAL REPORT ---{Style.RESET_ALL}")
    report_order = ["Basic Information", "Homepage Screenshot", "WHOIS Information", "DNS Records", "SSL/TLS Certificate", "Website Analysis", "Shodan Host Information", "Subdomain Discovery (API)", "VirusTotal Reputation"]
    for section_title in report_order:
        if section_title in all_results: print_title(section_title); print_entry("Data", all_results[section_title])

    end_time = time.perf_counter()
    print_title("Execution Summary")
    print(f"{Fore.GREEN}Reconnaissance complete in {end_time - start_time:.2f} seconds.{Style.RESET_ALL}")
    
    # Exit with code 0 to signal success
    sys.exit(0)