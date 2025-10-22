# main_gui.py (Final "All-in-One" Build Version)

# ====================================================================================
# ||                 AUTOMATED RECONNAISSANCE TOOL (FINAL BUILD VERSION)              ||
# ||          All team modules are combined into this single file for build.          ||
# ====================================================================================

# --- [SECTION 1: ALL IMPORTS] ---
import tkinter as tk
from tkinter import scrolledtext, messagebox, simpledialog
from PIL import Image, ImageTk
import os
import sys
import threading
import queue
import re
from datetime import datetime
import time
import concurrent.futures

# Backend Imports
import socket
import ssl
import whois
import dns.resolver
import requests
from bs4 import BeautifulSoup
import builtwith
from colorama import init, Fore, Style

# PDF & Email Imports
from fpdf import FPDF
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

# Selenium for Screenshots
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options as ChromeOptions
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

init(autoreset=True)

# ====================================================================================
# ||                 [SECTION 2: PYINSTALLER & BACKEND CONFIGURATION]               ||
# ====================================================================================

def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

# --- API KEYS ---
VIRUSTOTAL_API_KEY = "647aa3ff9c57ecc1862b61d60f76076959588abdd429d7a6f11b2c48b04fb0a7"
SHODAN_API_KEY = "G3vOPzqm664C94hW2TLw4sBgovUM4cEy"
SECURITYTRAILS_API_KEY = "S1VocFXF22WpZVCkXlScwy3dj2TomFaJ"

# --- EMAIL CONFIGURATION ---
SENDER_EMAIL = "asaravind435@gmail.com"
SENDER_PASSWORD = "rotc gsnp hcyj qcph"

# ====================================================================================
# ||                         [SECTION 3: BACKEND LOGIC]                           ||
# ====================================================================================

# --- Recon Functions (from recon_tool.py) ---
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
        options = ChromeOptions(); options.add_argument("--headless"); options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage"); options.add_argument("--window-size=1280,720")
        # Critical for PyInstaller: Tell Selenium where the bundled chromedriver is
        if getattr(sys, 'frozen', False): options.binary_location = sys.executable
        driver = webdriver.Chrome(options=options); driver.get(f"https://{domain}"); driver.save_screenshot(filename)
        return f"Success! Screenshot saved as: {os.path.abspath(filename)}"
    except Exception as e: return f"Could not take screenshot. Error: {e}"
    finally:
        if driver: driver.quit()

def get_whois(domain):
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
        expiration_date = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
        return {
            "Registrar": w.registrar, "Creation Date": creation_date,
            "Expiration Date": expiration_date, "Name Servers": w.name_servers
        }
    except Exception as e: return {"Error": str(e)}

def get_dns_records(domain):
    records = {}
    for r_type in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']:
        try: records[f"{r_type} Records"] = [r.to_text() for r in dns.resolver.resolve(domain, r_type)]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers): records[f"{r_type} Records"] = "No records found"
    return records

def get_ssl_certificate(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = {item[0][0]: item[0][1] for item in cert.get('issuer', [])}
                return {
                    "Issuer": issuer.get('organizationName', 'N/A'), "Valid From": cert.get('notBefore', 'N/A'),
                    "Valid To": cert.get('notAfter', 'N/A'), "Subject Alt Names (SANs)": [v for k, v in cert.get('subjectAltName', [])]
                }
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

# --- PDF Generation Function (from Dynamicreconpdf.py) ---
class PDF(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 15)
        self.cell(0, 10, 'Automated Reconnaissance Report', 0, 1, 'C')
        self.set_font('Arial', '', 10)
        self.cell(0, 10, f'Generated on: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', 0, 1, 'C')
        self.ln(10)
    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

def generate_pdf_report(raw_data, domain):
    pdf_filename = f"PDF_Report_{domain}.pdf"
    try:
        pdf = PDF()
        pdf.add_page()
        pdf.set_font("Courier", size=9)
        for section_title, data in raw_data.items():
            pdf.set_font("Courier", 'B', 12)
            pdf.cell(0, 10, section_title, ln=True)
            pdf.set_font("Courier", size=9)
            if isinstance(data, dict):
                for key, value in data.items():
                    if isinstance(value, list) and value:
                        pdf.multi_cell(0, 5, f"{key}:")
                        for item in value: pdf.multi_cell(0, 5, f"  - {str(item)}")
                    else:
                        pdf.multi_cell(0, 5, f"{key}: {str(value)}")
            else: pdf.multi_cell(0, 5, str(data))
            pdf.ln(5)
        pdf.output(pdf_filename)
        return (True, os.path.abspath(pdf_filename))
    except Exception as e:
        return (False, f"An unexpected error occurred during PDF generation: {e}")

# --- Email Function (from EmailAutomation.py) ---
def send_email_report(recipient_email, attachment_filepath):
    if not os.path.exists(attachment_filepath): return (False, f"Attachment file not found at: {attachment_filepath}")
    msg = MIMEMultipart(); msg['From'] = SENDER_EMAIL; msg['To'] = recipient_email
    filename = os.path.basename(attachment_filepath)
    domain = filename.replace("PDF_Report_", "").replace(".pdf", "")
    msg['Subject'] = f"Automated Reconnaissance Report for {domain}"
    body = f"Please find the attached automated reconnaissance report for the domain: {domain}"
    msg.attach(MIMEText(body, 'plain'))
    try:
        with open(attachment_filepath, "rb") as attachment:
            part = MIMEBase('application', 'octet-stream'); part.set_payload(attachment.read())
        encoders.encode_base64(part); part.add_header('Content-Disposition', f'attachment; filename= {filename}'); msg.attach(part)
    except Exception as e: return (False, f"Could not read or attach the file: {e}")
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587); server.starttls(); server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, recipient_email, msg.as_string()); server.quit()
        return (True, "Email sent successfully!")
    except smtplib.SMTPAuthenticationError: return (False, "Authentication failed. Check SENDER_EMAIL and SENDER_PASSWORD (must be an App Password).")
    except Exception as e: return (False, f"An error occurred while sending the email: {e}")

# ====================================================================================
# ||                     [SECTION 4: GRAPHICAL USER INTERFACE]                      ||
# ====================================================================================

class ReconApp:
    def __init__(self, root):
        self.root = root; self.log_queue = queue.Queue()
        self.report_data = None; self.pdf_filepath = None; self.is_scanning = False
        
        self.STYLE = {'bg': '#0b0c10', 'title': '#ff073a', 'label': '#66fcf1', 'output_fg': '#00ff00', 'btn_start_bg': '#00ff00', 'btn_start_fg': 'black', 'btn_clear_bg': '#ff073a', 'btn_clear_fg': 'white', 'btn_info_bg': '#007bff', 'btn_info_fg': 'white', 'btn_bg': '#45a29e', 'btn_fg': 'white', 'btn_disabled_bg': '#333333', 'btn_disabled_fg': '#888888'}
        self.FONTS = {'title': ("Arial", 32, "bold"), 'label': ("Arial", 14), 'button': ("Arial", 12, "bold")}

        self.root.title("Automated Recon Tool"); self.root.geometry("950x750"); self.root.resizable(False, False); self.root.config(bg=self.STYLE['bg'])
        
        try:
            image_path = resource_path("background.jpg")
            bg_image_pil = Image.open(image_path).resize((950, 750), Image.Resampling.LANCZOS)
            self.bg_image = ImageTk.PhotoImage(bg_image_pil); tk.Label(root, image=self.bg_image).place(x=0, y=0, relwidth=1, relheight=1)
        except Exception as e: print(f"Background image not found or failed to load: {e}")

        self._create_widgets()
        self.root.after(100, self._process_log_queue)

    def _create_widgets(self):
        tk.Label(self.root, text="AUTOMATED RECON TOOL", font=self.FONTS['title'], bg=self.STYLE['bg'], fg=self.STYLE['title']).pack(pady=40)
        input_frame = tk.Frame(self.root, bg=self.STYLE['bg']); input_frame.pack(pady=10)
        tk.Label(input_frame, text="Target Domain:", font=self.FONTS['label'], bg=self.STYLE['bg'], fg=self.STYLE['label']).pack(side=tk.LEFT, padx=10)
        self.domain_entry = tk.Entry(input_frame, width=40, font=self.FONTS['label'], bg="black", fg="white", relief="solid", bd=1, insertbackground="white"); self.domain_entry.pack(side=tk.LEFT)
        buttons_frame = tk.Frame(self.root, bg=self.STYLE['bg']); buttons_frame.pack(pady=25)
        btn_style = {'relief': "raised", 'bd': 3, 'width': 15}
        self.start_button = tk.Button(buttons_frame, text="Start Recon", font=self.FONTS['button'], bg=self.STYLE['btn_start_bg'], fg=self.STYLE['btn_start_fg'], command=self.start_recon_thread, **btn_style)
        self.start_button.pack(side=tk.LEFT, padx=15, ipady=8)
        self.report_button = tk.Button(buttons_frame, text="Generate Report", font=self.FONTS['button'], bg=self.STYLE['btn_disabled_bg'], fg=self.STYLE['btn_disabled_fg'], state="disabled", command=self.generate_report_action, **btn_style)
        self.report_button.pack(side=tk.LEFT, padx=15, ipady=8)
        self.mail_button = tk.Button(buttons_frame, text="Automate Mail", font=self.FONTS['button'], bg=self.STYLE['btn_disabled_bg'], fg=self.STYLE['btn_disabled_fg'], state="disabled", command=self.automate_mail_action, **btn_style)
        self.mail_button.pack(side=tk.LEFT, padx=15, ipady=8)
        self.output_text = scrolledtext.ScrolledText(self.root, height=18, bg="black", fg=self.STYLE['output_fg'], font=("Courier New", 11), relief="solid", bd=2, insertbackground="white"); self.output_text.pack(pady=10, padx=50, fill="x")
        util_frame = tk.Frame(self.root, bg=self.STYLE['bg']); util_frame.pack(pady=20)
        info_button = tk.Button(util_frame, text="Project Info", font=self.FONTS['button'], bg=self.STYLE['btn_info_bg'], fg=self.STYLE['btn_info_fg'], relief="raised", bd=2, width=12, command=self.show_project_info)
        info_button.pack(side=tk.LEFT, padx=10, ipady=5)
        clear_button = tk.Button(util_frame, text="Clear Output", font=self.FONTS['button'], bg=self.STYLE['btn_clear_bg'], fg=self.STYLE['btn_clear_fg'], relief="raised", bd=2, width=12, command=self.clear_output_action)
        clear_button.pack(side=tk.LEFT, padx=10, ipady=5)
        
    def log(self, message): self.log_queue.put(message)
    def _process_log_queue(self):
        try:
            while not self.log_queue.empty(): self.output_text.insert(tk.END, self.log_queue.get_nowait() + "\n"); self.output_text.see(tk.END)
        finally: self.root.after(100, self._process_log_queue)

    def start_recon_thread(self):
        if self.is_scanning: return
        domain = self.domain_entry.get().strip()
        if not domain: messagebox.showerror("Error", "Please enter a target domain."); return
        self.is_scanning = True; self.report_data = None; self.pdf_filepath = None
        self.clear_output_action(is_reset=False)
        self.start_button.config(state="disabled", text="Scanning...")
        self.report_button.config(state="disabled", bg=self.STYLE['btn_disabled_bg']); self.mail_button.config(state="disabled", bg=self.STYLE['btn_disabled_bg'])
        threading.Thread(target=self.run_full_recon_in_thread, args=(domain,), daemon=True).start()

    def run_full_recon_in_thread(self, domain):
        """This function runs all the recon tasks in a background thread."""
        try:
            self.log(f"[+] INITIATING RECONNAISSANCE FOR: {domain}...")
            all_results = {}
            ip, basic_info = get_basic_info(domain)
            all_results["Basic Information"] = basic_info
            
            if not ip:
                self.log(f"[!] CRITICAL ERROR: Could not resolve the domain '{domain}'.")
                self.report_data = all_results
                return

            tasks = {
                "Homepage Screenshot": (take_screenshot, (domain,)), "WHOIS Information": (get_whois, (domain,)),
                "DNS Records": (get_dns_records, (domain,)), "SSL/TLS Certificate": (get_ssl_certificate, (domain,)),
                "Website Analysis": (analyze_website, (domain,)), "Shodan Host Information": (check_shodan, (ip,)),
                "Subdomain Discovery (API)": (get_subdomains_from_api, (domain,)), "VirusTotal Reputation": (check_virustotal, (domain,))
            }
            with concurrent.futures.ThreadPoolExecutor(max_workers=len(tasks)) as executor:
                future_to_task = {executor.submit(func, *args): name for name, (func, args) in tasks.items()}
                for future in concurrent.futures.as_completed(future_to_task):
                    task_name = future_to_task[future]
                    try:
                        result = future.result()
                        all_results[task_name] = result
                        self.log(f"[+] {task_name} data collected.")
                    except Exception as e:
                        error_result = {"Error": str(e)}
                        all_results[task_name] = error_result
                        self.log(f"[!] {task_name} failed: {e}")
            self.report_data = all_results
        except Exception as e:
            self.log(f"[!] A critical error occurred in the scan thread: {e}")
        finally:
            self.is_scanning = False
            self.root.after(0, self.on_scan_complete)

    def on_scan_complete(self):
        self.start_button.config(state="normal", text="Start Recon")
        if self.report_data and "Error" not in self.report_data.get("Basic Information", {}):
            self.report_button.config(state="normal", bg=self.STYLE['btn_bg'])
            self.log("\n[+] TARGET ANALYSIS COMPLETE. Data is ready for report generation.")
        else:
            self.report_button.config(state="disabled", bg=self.STYLE['btn_disabled_bg'])
            self.log("[!] Scan failed or domain was invalid. PDF generation is disabled.")
    
    def generate_report_action(self):
        if not self.report_data: messagebox.showerror("Error", "No data available. Please run a scan first."); return
        self.log("\n[+] GENERATING SECURE PDF REPORT..."); success, result = generate_pdf_report(self.report_data, self.domain_entry.get())
        if success:
            self.pdf_filepath = result; self.log(f"[+] REPORT CREATED SUCCESSFULLY: {self.pdf_filepath}")
            self.mail_button.config(state="normal", bg=self.STYLE['btn_bg'])
            if messagebox.askyesno("Success", f"PDF report saved to:\n{self.pdf_filepath}\n\nDo you want to open it now?"):
                try: os.startfile(self.pdf_filepath)
                except AttributeError: import subprocess; subprocess.call(['open', self.pdf_filepath])
        else: self.log(f"[!] PDF GENERATION FAILED: {result}"); messagebox.showerror("Error", result)

    def automate_mail_action(self):
        if not self.pdf_filepath: messagebox.showerror("Error", "No PDF report found. Please generate the report first."); return
        recipient = simpledialog.askstring("Send Email", "Enter recipient's email address:")
        if not recipient: self.log("[!] Email dispatch cancelled by user."); return
        self.log(f"\n[+] ESTABLISHING SECURE CONNECTION TO SMTP SERVER...")
        success, message = send_email_report(recipient, self.pdf_filepath)
        if success: self.log(f"[+] REPORT DISPATCHED to {recipient}."); messagebox.showinfo("Success", message)
        else: self.log(f"[!] EMAIL FAILED: {message}"); messagebox.showerror("Error", message)

    def clear_output_action(self, is_reset=True):
        if is_reset: self.log("\n[+] SCRUBBING DATA... RESETTING INTERFACE...")
        self.output_text.delete('1.0', tk.END)
        if is_reset: self.domain_entry.delete(0, tk.END)
        self.report_button.config(state="disabled", bg=self.STYLE['btn_disabled_bg']); self.mail_button.config(state="disabled", bg=self.STYLE['btn_disabled_bg'])
        self.start_button.config(state="normal", text="Start Recon"); self.is_scanning = False

    def show_project_info(self):
        info_text = """
        Project Information
        -------------------
        - This  project  was  developed  by  P.Sanjay,  A.S.Aravind,  S.HariSiva  Balan,  S.Sri  Ganesh, M.ArunKumar, and GiriSankar as part of a Cyber Security Internship. 
        - This project is designed for the purpose of our Automatic Reconnaissance With Python project

        Project Details
        ---------------
        - Project Name :  Automatic Reconnaissance with Python
        - Description  :  An automated Python-based reconnaissance tool for efficient and comprehensive security information gathering.
        - Start Date   :  28-AUG-2025
        - End Date     :  10-SEP-2025
        - Status       :  Completed

        Developer Details
        -----------------
        - Sanjay P         (ST#IS#8175): 953622104086@ritrjpm.ac.in
        - Aravind A S      (ST#IS#8196): 953622104006@ritrjpm.ac.in
        - Harisiva Balan S (ST#IS#8191): 953622104033@ritrjpm.ac.in
        - Sri Ganesh S     (ST#IS#8193): 953622104099@ritrjpm.ac.in
        - Arun Kumar M     (ST#IS#8195): 953622104057@ritrjpm.ac.in
        - Giri Sankar      (ST#IS#8167): 953622104022@ritrjpm.ac.in

        Company Details
        ---------------
        - Company Name: Supraja Technologies
        """
        info_window = tk.Toplevel(self.root); info_window.title("Project Information"); info_window.geometry("600x600"); info_window.config(bg="white")
        tk.Label(info_window, text=info_text, justify=tk.LEFT, font=("Arial", 10), bg="white", wraplength=580).pack(padx=10, pady=10)

# ====================================================================================
# ||                           [SECTION 5: APP STARTUP]                           ||
# ====================================================================================

if __name__ == "__main__":
    root = tk.Tk()
    app = ReconApp(root)
    root.mainloop()