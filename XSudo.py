#!/usr/bin/env python3
"""
     ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ ██╗ █████╗ ███╗   ██╗  
    ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗██║██╔══██╗████╗  ██║  
    ██║  ███╗██║   ██║███████║██████╔╝██║  ██║██║███████║██╔██╗ ██║  
    ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║██║██╔══██║██║╚██╗██║  
    ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝██║██║  ██║██║ ╚████║  
     ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  
    """

import os
import sys
import socket
import hashlib
import subprocess
import requests
import json
import re
import datetime
import ipaddress
from urllib.parse import urlparse
import whois
import dns.resolver
import ssl
import concurrent.futures
import zipfile
import tarfile
import platform
import getpass
import threading
import queue
import base64
from colorama import init, Fore, Back, Style

# Initialize colorama
init(autoreset=True)

class SUDO_CyberSuite:
    def __init__(self):
        self.version = "3.0"
        self.author = "SUDO Security Collective"
        self.session_id = hashlib.md5(str(datetime.datetime.now()).encode()).hexdigest()[:8]
        
        # Tools Dictionary - Tetap sama seperti menu pertama
        self.tools = {
            "1": "Password Security Checker",
            "2": "Network Scanner", 
            "3": "Website Security Analyzer",
            "4": "File Integrity Monitor",
            "5": "Email Verifier",
            "6": "DNS Security Check",
            "7": "SSL/TLS Analyzer",
            "8": "Data Leak Checker",
            "9": "System Hardening Assistant",
            "10": "Incident Response Helper",
            "11": "Security Awareness Quiz",
            "12": "Privacy Tools Guide",
            "13": "Backup Utility",
            "14": "Malware Detection Helper",
            "15": "Firewall Configuration Helper",
            "0": "Exit"
        }
    
    def display_banner(self):
        banner = f"""
{Fore.RED}╔═══════════════════════════════════════════════════════════════╗
{Fore.RED}║                                                               ║
{Fore.RED}║   {Fore.WHITE}██╗  ██╗     {Fore.CYAN}███████╗██╗   ██╗██████╗  ██████╗     {Fore.RED}         ║
{Fore.RED}║   {Fore.WHITE}╚██╗██╔╝     {Fore.CYAN}██╔════╝██║   ██║██╔══██╗██╔═══██╗    {Fore.RED}         ║
{Fore.RED}║   {Fore.WHITE} ╚███╔╝      {Fore.CYAN}███████╗██║   ██║██║  ██║██║   ██║    {Fore.RED}         ║
{Fore.RED}║   {Fore.WHITE} ██╔██╗      {Fore.CYAN}╚════██║██║   ██║██║  ██║██║   ██║    {Fore.RED}         ║
{Fore.RED}║   {Fore.WHITE}██╔╝ ██╗     {Fore.CYAN}███████║╚██████╔╝██████╔╝╚██████╔╝    {Fore.RED}         ║
{Fore.RED}║   {Fore.WHITE}╚═╝  ╚═╝     {Fore.CYAN}╚══════╝ ╚═════╝ ╚═════╝  ╚═════╝     {Fore.RED}         ║
{Fore.RED}║                                                               ║
{Fore.RED}║        {Fore.YELLOW} DON'T FORGET TO GIVE A STAR TO THIS TOOL :)           {Fore.RED}║
{Fore.RED}║             {Fore.GREEN}A U T H O R  :  R U Y Y N N          {Fore.RED}             ║
{Fore.RED}╚═══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

{Fore.LIGHTBLUE_EX}
     ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ ██╗ █████╗ ███╗   ██╗  
    ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗██║██╔══██╗████╗  ██║  
    ██║  ███╗██║   ██║███████║██████╔╝██║  ██║██║███████║██╔██╗ ██║  
    ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║██║██╔══██║██║╚██╗██║  
    ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝██║██║  ██║██║ ╚████║  
     ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  
{Style.RESET_ALL}
"""
        print(banner)
        
        menu = f"""
{Fore.GREEN}╔═══════════════════════════════════════════════════════════════╗
{Fore.GREEN}║                    {Fore.LIGHTYELLOW_EX}M A I N    M E N U                   {Fore.GREEN}      ║
{Fore.GREEN}╠═══════════════════════════════════════════════════════════════╣
{Fore.GREEN}║  {Fore.LIGHTMAGENTA_EX}1.  Password Security Checker                    {Fore.GREEN}            ║
{Fore.GREEN}║  {Fore.LIGHTMAGENTA_EX}2.  Network Scanner                               {Fore.GREEN}           ║
{Fore.GREEN}║  {Fore.LIGHTMAGENTA_EX}3.  Website Security Analyzer                    {Fore.GREEN}            ║
{Fore.GREEN}║  {Fore.LIGHTMAGENTA_EX}4.  File Integrity Monitor                       {Fore.GREEN}            ║
{Fore.GREEN}║  {Fore.LIGHTMAGENTA_EX}5.  Email Verifier                              {Fore.GREEN}             ║
{Fore.GREEN}║  {Fore.LIGHTMAGENTA_EX}6.  DNS Security Check                           {Fore.GREEN}            ║
{Fore.GREEN}║  {Fore.LIGHTMAGENTA_EX}7.  SSL/TLS Analyzer                             {Fore.GREEN}            ║
{Fore.GREEN}║  {Fore.LIGHTMAGENTA_EX}8.  Data Leak Checker                            {Fore.GREEN}            ║
{Fore.GREEN}║  {Fore.LIGHTMAGENTA_EX}9.  System Hardening Assistant                   {Fore.GREEN}            ║
{Fore.GREEN}║  {Fore.LIGHTMAGENTA_EX}10. Incident Response Helper                     {Fore.GREEN}            ║
{Fore.GREEN}║  {Fore.LIGHTMAGENTA_EX}11. Security Awareness Quiz                      {Fore.GREEN}            ║
{Fore.GREEN}║  {Fore.LIGHTMAGENTA_EX}12. Privacy Tools Guide                          {Fore.GREEN}            ║
{Fore.GREEN}║  {Fore.LIGHTMAGENTA_EX}13. Backup Utility                               {Fore.GREEN}            ║
{Fore.GREEN}║  {Fore.LIGHTMAGENTA_EX}14. Malware Detection Helper                     {Fore.GREEN}            ║
{Fore.GREEN}║  {Fore.LIGHTMAGENTA_EX}15. Firewall Configuration Helper                {Fore.GREEN}            ║
{Fore.GREEN}║  {Fore.LIGHTRED_EX}0.  Exit                                          {Fore.GREEN}           ║
{Fore.GREEN}╚═══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
        print(menu)
    
    # ==================== TOOL 1: PASSWORD CHECKER ====================
    def password_checker(self):
        print(f"\n{Fore.CYAN}[🔐 PASSWORD SECURITY CHECKER]{Style.RESET_ALL}")
        password = getpass.getpass("Enter password to check (won't be displayed): ")
        
        score = 0
        feedback = []
        
        # Length check
        if len(password) >= 12:
            score += 2
            feedback.append(f"{Fore.GREEN}✓ Good length (12+ characters){Style.RESET_ALL}")
        elif len(password) >= 8:
            score += 1
            feedback.append(f"{Fore.YELLOW}⚠ Minimum length (10 characters){Style.RESET_ALL}")
        else:
            feedback.append(f"{Fore.RED}✗ Too short (< 10 characters){Style.RESET_ALL}")
        
        # Complexity checks
        if re.search(r'[A-Z]', password):
            score += 1
            feedback.append(f"{Fore.GREEN}✓ Contains uppercase letters{Style.RESET_ALL}")
        else:
            feedback.append(f"{Fore.RED}✗ Missing uppercase letters{Style.RESET_ALL}")
        
        if re.search(r'[a-z]', password):
            score += 1
            feedback.append(f"{Fore.GREEN}✓ Contains lowercase letters{Style.RESET_ALL}")
        else:
            feedback.append(f"{Fore.RED}✗ Missing lowercase letters{Style.RESET_ALL}")
        
        if re.search(r'\d', password):
            score += 1
            feedback.append(f"{Fore.GREEN}✓ Contains numbers{Style.RESET_ALL}")
        else:
            feedback.append(f"{Fore.RED}✗ Missing numbers{Style.RESET_ALL}")
        
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 1
            feedback.append(f"{Fore.GREEN}✓ Contains special characters{Style.RESET_ALL}")
        else:
            feedback.append(f"{Fore.RED}✗ Missing special characters{Style.RESET_ALL}")
        
        # Common password check
        common_passwords = ["password", "123456", "qwerty", "admin", "welcome"]
        if password.lower() in common_passwords:
            score = 0
            feedback.append(f"{Fore.RED}✗ Extremely common password!{Style.RESET_ALL}")
        
        # Display results
        print(f"\n{Fore.CYAN}Security Score: {score}/6{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Detailed Analysis:{Style.RESET_ALL}")
        for item in feedback:
            print(f"  {item}")
        
        # Generate strong password suggestion
        print(f"\n{Fore.GREEN}💡 Suggested Strong Password Pattern:{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}Use 12+ characters with mix of: Upper, Lower, Numbers, Symbols{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}Example: Secure@Pass123!{Style.RESET_ALL}")

    # ==================== TOOL 2: NETWORK SCANNER ====================
    def network_scanner(self):
        print(f"\n{Fore.CYAN}[🌐 NETWORK SCANNER]{Style.RESET_ALL}")
        
        try:
            # Get local IP
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            print(f"{Fore.WHITE}Your IP: {local_ip}{Style.RESET_ALL}")
            
            # Scan local network
            network = '.'.join(local_ip.split('.')[:3]) + '.0/24'
            print(f"{Fore.WHITE}Scanning network: {network}{Style.RESET_ALL}")
            
            # Simple ping scan
            live_hosts = []
            for i in range(1, 11):  # Scan first 10 hosts (adjustable)
                ip = f"{network.split('.')[0]}.{network.split('.')[1]}.{network.split('.')[2]}.{i}"
                if ip == local_ip:
                    continue
                    
                response = os.system(f"ping -c 1 -W 1 {ip} > /dev/null 2>&1" if platform.system() != "Windows" else f"ping -n 1 -w 1000 {ip} > nul")
                if response == 0:
                    live_hosts.append(ip)
                    print(f"  {Fore.GREEN}✓ {ip} - Active{Style.RESET_ALL}")
                else:
                    print(f"  {Fore.RED}✗ {ip} - Inactive{Style.RESET_ALL}")
            
            print(f"\n{Fore.CYAN}Found {len(live_hosts)} active devices{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")

    # ==================== TOOL 3: WEBSITE SECURITY ANALYZER ====================
    def website_analyzer(self):
        print(f"\n{Fore.CYAN}[🌐 WEBSITE SECURITY ANALYZER]{Style.RESET_ALL}")
        url = input("Enter website URL (e.g., https://example.com): ")
        
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        try:
            response = requests.get(url, timeout=10)
            
            security_headers = {
                'X-Frame-Options': 'Prevents clickjacking',
                'X-XSS-Protection': 'Cross-site scripting protection',
                'X-Content-Type-Options': 'Prevents MIME sniffing',
                'Strict-Transport-Security': 'Enforces HTTPS',
                'Content-Security-Policy': 'Prevents XSS attacks'
            }
            
            print(f"\n{Fore.WHITE}Analyzing: {url}{Style.RESET_ALL}")
            print(f"{Fore.WHITE}Status Code: {response.status_code}{Style.RESET_ALL}")
            
            print(f"\n{Fore.CYAN}Security Headers Found:{Style.RESET_ALL}")
            headers_found = 0
            for header, description in security_headers.items():
                if header in response.headers:
                    print(f"  {Fore.GREEN}✓ {header}: {response.headers[header]}{Style.RESET_ALL}")
                    print(f"    {Fore.WHITE}{description}{Style.RESET_ALL}")
                    headers_found += 1
                else:
                    print(f"  {Fore.RED}✗ {header}: Missing{Style.RESET_ALL}")
            
            print(f"\n{Fore.CYAN}Security Headers Score: {headers_found}/5{Style.RESET_ALL}")
            
            # Check for HTTPS
            if url.startswith('https://'):
                print(f"{Fore.GREEN}✓ HTTPS is enabled{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}✗ Not using HTTPS{Style.RESET_ALL}")
            
            # Check for sensitive information
            sensitive_patterns = ['password', 'creditcard', 'ssn', 'secret']
            page_text = response.text.lower()
            for pattern in sensitive_patterns:
                if pattern in page_text:
                    print(f"{Fore.YELLOW}⚠ Warning: Potential '{pattern}' field detected{Style.RESET_ALL}")
            
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")

    # ==================== TOOL 4: FILE INTEGRITY MONITOR ====================
    def file_integrity(self):
        print(f"\n{Fore.CYAN}[📁 FILE INTEGRITY MONITOR]{Style.RESET_ALL}")
        print(f"{Fore.WHITE}1. Generate file hash{Style.RESET_ALL}")
        print(f"{Fore.WHITE}2. Verify file integrity{Style.RESET_ALL}")
        choice = input("Choice: ")
        
        if choice == "1":
            filepath = input("Enter file path: ")
            if os.path.exists(filepath):
                with open(filepath, 'rb') as f:
                    file_hash = hashlib.sha256(f.read()).hexdigest()
                print(f"\n{Fore.WHITE}File: {filepath}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}SHA256: {file_hash}{Style.RESET_ALL}")
                print(f"\n{Fore.GREEN}Save this hash to verify file integrity later.{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}File not found!{Style.RESET_ALL}")
        
        elif choice == "2":
            filepath = input("Enter file path: ")
            stored_hash = input("Enter stored SHA256 hash: ")
            
            if os.path.exists(filepath):
                with open(filepath, 'rb') as f:
                    current_hash = hashlib.sha256(f.read()).hexdigest()
                
                if current_hash == stored_hash:
                    print(f"\n{Fore.GREEN}✓ File integrity verified!{Style.RESET_ALL}")
                    print(f"{Fore.WHITE}Current hash: {current_hash}{Style.RESET_ALL}")
                else:
                    print(f"\n{Fore.RED}✗ File has been modified!{Style.RESET_ALL}")
                    print(f"{Fore.WHITE}Expected: {stored_hash}{Style.RESET_ALL}")
                    print(f"{Fore.WHITE}Actual:   {current_hash}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}File not found!{Style.RESET_ALL}")

    # ==================== TOOL 5: EMAIL VERIFIER ====================
    def email_verifier(self):
        print(f"\n{Fore.CYAN}[📧 EMAIL VERIFIER]{Style.RESET_ALL}")
        email = input("Enter email to verify: ")
        
        # Basic email format validation
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        
        if re.match(email_regex, email):
            print(f"{Fore.GREEN}✓ Valid email format{Style.RESET_ALL}")
            
            # Check for disposable emails
            disposable_domains = ['tempmail.com', 'mailinator.com', '10minutemail.com']
            domain = email.split('@')[1]
            if domain in disposable_domains:
                print(f"{Fore.YELLOW}⚠ Disposable email detected{Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}✓ Not a disposable email{Style.RESET_ALL}")
            
            # Check for data breaches (simulated)
            print(f"\n{Fore.WHITE}Checking for data breaches...{Style.RESET_ALL}")
            print(f"{Fore.WHITE}(For actual breach check, visit: haveibeenpwned.com){Style.RESET_ALL}")
            
        else:
            print(f"{Fore.RED}✗ Invalid email format{Style.RESET_ALL}")

    # ==================== TOOL 6: DNS SECURITY CHECK ====================
    def dns_security_check(self):
        print(f"\n{Fore.CYAN}[🔗 DNS SECURITY CHECK]{Style.RESET_ALL}")
        domain = input("Enter domain (e.g., example.com): ")
        
        try:
            print(f"\n{Fore.WHITE}Checking DNS records for: {domain}{Style.RESET_ALL}")
            
            # Check for DNSSEC (simplified check)
            print(f"\n{Fore.CYAN}DNSSEC Status:{Style.RESET_ALL}")
            try:
                answers = dns.resolver.resolve(domain, 'DNSKEY')
                print(f"{Fore.GREEN}✓ DNSSEC is configured{Style.RESET_ALL}")
            except:
                print(f"{Fore.YELLOW}✗ DNSSEC not detected (may not be implemented){Style.RESET_ALL}")
            
            # Check SPF record
            print(f"\n{Fore.CYAN}SPF Record (Email authentication):{Style.RESET_ALL}")
            try:
                answers = dns.resolver.resolve(domain, 'TXT')
                spf_found = False
                for rdata in answers:
                    if 'v=spf1' in str(rdata):
                        spf_found = True
                        print(f"{Fore.GREEN}✓ SPF found: {rdata}{Style.RESET_ALL}")
                if not spf_found:
                    print(f"{Fore.RED}✗ No SPF record found{Style.RESET_ALL}")
            except:
                print(f"{Fore.RED}✗ No SPF record found{Style.RESET_ALL}")
            
            # Check DMARC
            print(f"\n{Fore.CYAN}DMARC Record:{Style.RESET_ALL}")
            try:
                answers = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
                for rdata in answers:
                    if 'v=DMARC1' in str(rdata):
                        print(f"{Fore.GREEN}✓ DMARC found: {rdata}{Style.RESET_ALL}")
            except:
                print(f"{Fore.RED}✗ No DMARC record found{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")

    # ==================== TOOL 7: SSL/TLS ANALYZER ====================
    def ssl_analyzer(self):
        print(f"\n{Fore.CYAN}[🔒 SSL/TLS ANALYZER]{Style.RESET_ALL}")
        domain = input("Enter domain (e.g., example.com): ")
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    print(f"\n{Fore.WHITE}SSL Certificate for: {domain}{Style.RESET_ALL}")
                    print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
                    
                    # Certificate info
                    print(f"{Fore.WHITE}Issued To:{Style.RESET_ALL}")
                    for field in cert['subject']:
                        for key, value in field:
                            print(f"  {Fore.GREEN}{key}: {value}{Style.RESET_ALL}")
                    
                    print(f"\n{Fore.WHITE}Issued By:{Style.RESET_ALL}")
                    for field in cert['issuer']:
                        for key, value in field:
                            print(f"  {Fore.GREEN}{key}: {value}{Style.RESET_ALL}")
                    
                    # Validity period
                    not_before = cert['notBefore']
                    not_after = cert['notAfter']
                    print(f"\n{Fore.WHITE}Validity Period:{Style.RESET_ALL}")
                    print(f"  {Fore.WHITE}From: {not_before}{Style.RESET_ALL}")
                    print(f"  {Fore.WHITE}Until: {not_after}{Style.RESET_ALL}")
                    
                    # Check expiration
                    expiry_date = datetime.datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                    days_left = (expiry_date - datetime.datetime.now()).days
                    
                    if days_left > 30:
                        print(f"  {Fore.GREEN}✓ Certificate expires in {days_left} days{Style.RESET_ALL}")
                    elif days_left > 0:
                        print(f"  {Fore.YELLOW}⚠ Certificate expires in {days_left} days{Style.RESET_ALL}")
                    else:
                        print(f"  {Fore.RED}✗ Certificate has expired!{Style.RESET_ALL}")
                    
                    # Protocol version
                    print(f"\n{Fore.WHITE}Protocol: {ssock.version()}{Style.RESET_ALL}")
                    
        except Exception as e:
            print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")

    # ==================== TOOL 8: DATA LEAK CHECKER ====================
    def data_leak_checker(self):
        print(f"\n{Fore.CYAN}[🔍 DATA LEAK CHECKER]{Style.RESET_ALL}")
        print(f"{Fore.WHITE}1. Check password in breaches{Style.RESET_ALL}")
        print(f"{Fore.WHITE}2. Check email in breaches{Style.RESET_ALL}")
        choice = input("Choice: ")
        
        if choice == "1":
            # Never send actual password to any service!
            print(f"\n{Fore.YELLOW}⚠ IMPORTANT SECURITY NOTE:{Style.RESET_ALL}")
            print(f"{Fore.WHITE}Never enter your actual password here!{Style.RESET_ALL}")
            print(f"{Fore.WHITE}Instead, check your passwords at:{Style.RESET_ALL}")
            print(f"{Fore.CYAN}- https://haveibeenpwned.com/Passwords{Style.RESET_ALL}")
            print(f"{Fore.CYAN}- Use the 'k-Anonymity' feature for safety{Style.RESET_ALL}")
            
            # Simulate with hash
            test_password = input("\nEnter a test password (not your real one): ")
            password_hash = hashlib.sha1(test_password.encode()).hexdigest().upper()
            first_5 = password_hash[:5]
            
            print(f"\n{Fore.WHITE}To check safely, visit:{Style.RESET_ALL}")
            print(f"{Fore.CYAN}https://api.pwnedpasswords.com/range/{first_5}{Style.RESET_ALL}")
            print(f"{Fore.WHITE}Then look for: {password_hash[5:]}{Style.RESET_ALL}")
            
        elif choice == "2":
            email = input("Enter email to check: ")
            print(f"\n{Fore.WHITE}Check email breaches at:{Style.RESET_ALL}")
            print(f"{Fore.CYAN}https://haveibeenpwned.com/account/{email}{Style.RESET_ALL}")
            print(f"\n{Fore.WHITE}Or use their official API for programmatic access.{Style.RESET_ALL}")

    # ==================== TOOL 9: SYSTEM HARDENING ====================
    def system_hardening(self):
        print(f"\n{Fore.CYAN}[🛡️ SYSTEM HARDENING ASSISTANT]{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Select your OS:{Style.RESET_ALL}")
        print(f"{Fore.CYAN}1. Linux{Style.RESET_ALL}")
        print(f"{Fore.CYAN}2. Windows{Style.RESET_ALL}")
        print(f"{Fore.CYAN}3. macOS{Style.RESET_ALL}")
        
        os_choice = input("Choice: ")
        
        print(f"\n{Fore.CYAN}Recommended Security Practices:{Style.RESET_ALL}")
        
        if os_choice == "1":  # Linux
            print(f"""
{Fore.GREEN}1. User Management:{Style.RESET_ALL}
   {Fore.WHITE}- Use strong passwords{Style.RESET_ALL}
   {Fore.WHITE}- Disable root SSH login{Style.RESET_ALL}
   {Fore.WHITE}- Create separate user accounts{Style.RESET_ALL}

{Fore.GREEN}2. Firewall:{Style.RESET_ALL}
   {Fore.WHITE}- Enable ufw: sudo ufw enable{Style.RESET_ALL}
   {Fore.WHITE}- Configure: sudo ufw default deny incoming{Style.RESET_ALL}
   {Fore.WHITE}- Allow specific ports only{Style.RESET_ALL}

{Fore.GREEN}3. Updates:{Style.RESET_ALL}
   {Fore.WHITE}- Regular updates: sudo apt update && sudo apt upgrade{Style.RESET_ALL}
   {Fore.WHITE}- Enable automatic security updates{Style.RESET_ALL}

{Fore.GREEN}4. SSH Security:{Style.RESET_ALL}
   {Fore.WHITE}- Change default port{Style.RESET_ALL}
   {Fore.WHITE}- Use key-based authentication{Style.RESET_ALL}
   {Fore.WHITE}- Disable password authentication{Style.RESET_ALL}

{Fore.GREEN}5. File Permissions:{Style.RESET_ALL}
   {Fore.WHITE}- Review: find / -type f -perm /o+w -ls{Style.RESET_ALL}
   {Fore.WHITE}- Set proper permissions{Style.RESET_ALL}
            """)
            
        elif os_choice == "2":  # Windows
            print(f"""
{Fore.GREEN}1. User Accounts:{Style.RESET_ALL}
   {Fore.WHITE}- Use strong passwords{Style.RESET_ALL}
   {Fore.WHITE}- Enable Windows Hello/Biometrics{Style.RESET_ALL}
   {Fore.WHITE}- Use standard user for daily tasks{Style.RESET_ALL}

{Fore.GREEN}2. Windows Defender:{Style.RESET_ALL}
   {Fore.WHITE}- Enable real-time protection{Style.RESET_ALL}
   {Fore.WHITE}- Enable cloud-delivered protection{Style.RESET_ALL}
   {Fore.WHITE}- Run regular scans{Style.RESET_ALL}

{Fore.GREEN}3. Updates:{Style.RESET_ALL}
   {Fore.WHITE}- Enable automatic updates{Style.RESET_ALL}
   {Fore.WHITE}- Install security updates promptly{Style.RESET_ALL}

{Fore.GREEN}4. Firewall:{Style.RESET_ALL}
   {Fore.WHITE}- Ensure Windows Firewall is on{Style.RESET_ALL}
   {Fore.WHITE}- Review inbound/outbound rules{Style.RESET_ALL}

{Fore.GREEN}5. BitLocker:{Style.RESET_ALL}
   {Fore.WHITE}- Enable device encryption{Style.RESET_ALL}
   {Fore.WHITE}- Backup recovery key securely{Style.RESET_ALL}
            """)
            
        elif os_choice == "3":  # macOS
            print(f"""
{Fore.GREEN}1. System Preferences:{Style.RESET_ALL}
   {Fore.WHITE}- Enable FileVault encryption{Style.RESET_ALL}
   {Fore.WHITE}- Set firmware password{Style.RESET_ALL}
   {Fore.WHITE}- Enable firewall{Style.RESET_ALL}

{Fore.GREEN}2. User Accounts:{Style.RESET_ALL}
   {Fore.WHITE}- Use strong passwords{Style.RESET_ALL}
   {Fore.WHITE}- Enable Touch ID{Style.RESET_ALL}
   {Fore.WHITE}- Create standard user account{Style.RESET_ALL}

{Fore.GREEN}3. Privacy Settings:{Style.RESET_ALL}
   {Fore.WHITE}- Review app permissions{Style.RESET_ALL}
   {Fore.WHITE}- Limit location services{Style.RESET_ALL}
   {Fore.WHITE}- Review accessibility access{Style.RESET_ALL}

{Fore.GREEN}4. Updates:{Style.RESET_ALL}
   {Fore.WHITE}- Enable automatic updates{Style.RESET_ALL}
   {Fore.WHITE}- Install security updates{Style.RESET_ALL}

{Fore.GREEN}5. Gatekeeper:{Style.RESET_ALL}
   {Fore.WHITE}- Allow apps from App Store and identified developers{Style.RESET_ALL}
   {Fore.WHITE}- Be cautious with third-party apps{Style.RESET_ALL}
            """)

    # ==================== TOOL 10: INCIDENT RESPONSE ====================
    def incident_response(self):
        print(f"\n{Fore.CYAN}[🚨 INCIDENT RESPONSE HELPER]{Style.RESET_ALL}")
        print(f"{Fore.WHITE}What type of incident?{Style.RESET_ALL}")
        print(f"{Fore.CYAN}1. Malware Infection{Style.RESET_ALL}")
        print(f"{Fore.CYAN}2. Phishing Attack{Style.RESET_ALL}")
        print(f"{Fore.CYAN}3. Unauthorized Access{Style.RESET_ALL}")
        print(f"{Fore.CYAN}4. Data Breach{Style.RESET_ALL}")
        print(f"{Fore.CYAN}5. Ransomware{Style.RESET_ALL}")
        
        incident = input("Choice: ")
        
        print(f"\n{Fore.CYAN}IMMEDIATE ACTIONS:{Style.RESET_ALL}")
        
        if incident == "1":  # Malware
            print(f"""
{Fore.GREEN}1. ISOLATE the affected system{Style.RESET_ALL}
{Fore.GREEN}2. DISCONNECT from network{Style.RESET_ALL}
{Fore.GREEN}3. DO NOT turn off (preserve evidence){Style.RESET_ALL}
{Fore.GREEN}4. Document everything{Style.RESET_ALL}
{Fore.GREEN}5. Contact IT security team{Style.RESET_ALL}
{Fore.GREEN}6. Scan with updated antivirus{Style.RESET_ALL}
            """)
            
        elif incident == "2":  # Phishing
            print(f"""
{Fore.GREEN}1. DO NOT click any links{Style.RESET_ALL}
{Fore.GREEN}2. DO NOT reply to sender{Style.RESET_ALL}
{Fore.GREEN}3. Forward email to abuse@domain{Style.RESET_ALL}
{Fore.GREEN}4. Change passwords if clicked{Style.RESET_ALL}
{Fore.GREEN}5. Enable 2FA immediately{Style.RESET_ALL}
{Fore.GREEN}6. Report to security team{Style.RESET_ALL}
            """)
            
        elif incident == "3":  # Unauthorized Access
            print(f"""
{Fore.GREEN}1. Change ALL passwords immediately{Style.RESET_ALL}
{Fore.GREEN}2. Enable 2FA everywhere possible{Style.RESET_ALL}
{Fore.GREEN}3. Check login history/audit logs{Style.RESET_ALL}
{Fore.GREEN}4. Review account permissions{Style.RESET_ALL}
{Fore.GREEN}5. Contact support for affected services{Style.RESET_ALL}
            """)
            
        elif incident == "4":  # Data Breach
            print(f"""
{Fore.GREEN}1. Identify compromised data{Style.RESET_ALL}
{Fore.GREEN}2. Notify affected parties{Style.RESET_ALL}
{Fore.GREEN}3. Contact legal counsel{Style.RESET_ALL}
{Fore.GREEN}4. Reset all related credentials{Style.RESET_ALL}
{Fore.GREEN}5. Implement additional monitoring{Style.RESET_ALL}
            """)
            
        elif incident == "5":  # Ransomware
            print(f"""
{Fore.GREEN}1. IMMEDIATELY disconnect from network{Style.RESET_ALL}
{Fore.GREEN}2. DO NOT pay the ransom{Style.RESET_ALL}
{Fore.GREEN}3. Identify infection source{Style.RESET_ALL}
{Fore.GREEN}4. Restore from clean backup{Style.RESET_ALL}
{Fore.GREEN}5. Report to authorities (FBI, etc.){Style.RESET_ALL}
            """)
        
        print(f"\n{Fore.YELLOW}📞 Emergency Contacts:{Style.RESET_ALL}")
        print(f"{Fore.WHITE}- Local IT Security: [Your IT Dept]{Style.RESET_ALL}")
        print(f"{Fore.WHITE}- National Cyber Security: 117 (Indonesia){Style.RESET_ALL}")
        print(f"{Fore.WHITE}- Police: 110{Style.RESET_ALL}")
        print(f"\n{Fore.CYAN}Always document: What, When, Who, How{Style.RESET_ALL}")

    # ==================== TOOL 11: SECURITY AWARENESS QUIZ ====================
    def security_quiz(self):
        print(f"\n{Fore.CYAN}[🧠 SECURITY AWARENESS QUIZ]{Style.RESET_ALL}")
        
        questions = [
            {
                "question": "What's the best practice for passwords?",
                "options": ["A. Use same password everywhere", "B. Write down in notebook", "C. Use password manager", "D. Use pet's name"],
                "answer": "C"
            },
            {
                "question": "What should you do with suspicious emails?",
                "options": ["A. Click links to check", "B. Reply asking for proof", "C. Delete immediately", "D. Forward to others"],
                "answer": "C"
            },
            {
                "question": "When should you update software?",
                "options": ["A. Never", "B. When convenient", "C. Immediately when available", "D. Once a year"],
                "answer": "C"
            },
            {
                "question": "What is 2FA?",
                "options": ["A. Two File Access", "B. Two Factor Authentication", "C. Two Firewall Apps", "D. Two Form Approval"],
                "answer": "B"
            },
            {
                "question": "Public WiFi should be used for:",
                "options": ["A. Banking", "B. Shopping", "C. General browsing", "D. Work emails"],
                "answer": "C"
            }
        ]
        
        score = 0
        for i, q in enumerate(questions, 1):
            print(f"\n{Fore.WHITE}Q{i}: {q['question']}{Style.RESET_ALL}")
            for opt in q['options']:
                print(f"  {Fore.CYAN}{opt}{Style.RESET_ALL}")
            
            user_answer = input(f"{Fore.YELLOW}Your answer (A/B/C/D): {Style.RESET_ALL}").upper()
            
            if user_answer == q['answer']:
                print(f"  {Fore.GREEN}✓ Correct!{Style.RESET_ALL}")
                score += 1
            else:
                print(f"  {Fore.RED}✗ Wrong. Correct: {q['answer']}{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}Final Score: {score}/{len(questions)}{Style.RESET_ALL}")
        if score == len(questions):
            print(f"{Fore.GREEN}🎉 Excellent! You're security aware!{Style.RESET_ALL}")
        elif score >= len(questions)/2:
            print(f"{Fore.YELLOW}👍 Good! Keep learning about security.{Style.RESET_ALL}")
        else:
            print(f"{Fore.CYAN}📚 Review security basics and try again.{Style.RESET_ALL}")

    # ==================== TOOL 12: PRIVACY TOOLS GUIDE ====================
    def privacy_tools(self):
        print(f"\n{Fore.CYAN}[🕵️ PRIVACY TOOLS GUIDE]{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}🔐 Password Managers:{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}• Bitwarden (Free & Open Source){Style.RESET_ALL}")
        print(f"  {Fore.WHITE}• 1Password (Paid){Style.RESET_ALL}")
        print(f"  {Fore.WHITE}• KeePassXC (Local, Open Source){Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}🌐 Privacy Browsers:{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}• Firefox with privacy extensions{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}• Brave Browser{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}• Tor Browser for anonymity{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}📱 Encrypted Messaging:{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}• Signal (Recommended){Style.RESET_ALL}")
        print(f"  {Fore.WHITE}• Telegram (Secret Chats){Style.RESET_ALL}")
        print(f"  {Fore.WHITE}• WhatsApp (End-to-end){Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}☁️ Secure Cloud Storage:{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}• Nextcloud (Self-hosted){Style.RESET_ALL}")
        print(f"  {Fore.WHITE}• ProtonDrive{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}• Cryptomator (Encrypt any cloud){Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}🎭 VPN Services:{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}• Mullvad (No logs, accepts cash){Style.RESET_ALL}")
        print(f"  {Fore.WHITE}• ProtonVPN (Free tier available){Style.RESET_ALL}")
        print(f"  {Fore.WHITE}• IVPN (Transparent){Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}📧 Secure Email:{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}• ProtonMail (Swiss privacy){Style.RESET_ALL}")
        print(f"  {Fore.WHITE}• Tutanota (German privacy){Style.RESET_ALL}")
        print(f"  {Fore.WHITE}• Mailbox.org (German){Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}🔍 Search Engines:{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}• DuckDuckGo (Privacy focused){Style.RESET_ALL}")
        print(f"  {Fore.WHITE}• Startpage (Google results private){Style.RESET_ALL}")
        print(f"  {Fore.WHITE}• Searx (Self-hostable){Style.RESET_ALL}")
        
        print(f"\n{Fore.YELLOW}💡 Remember: No single tool guarantees complete privacy.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Use combination of tools and practice good habits.{Style.RESET_ALL}")

    # ==================== TOOL 13: BACKUP UTILITY ====================
    def backup_utility(self):
        print(f"\n{Fore.CYAN}[💾 BACKUP UTILITY]{Style.RESET_ALL}")
        
        backup_types = {
            "1": "Important Documents",
            "2": "Photos & Videos", 
            "3": "System Configuration",
            "4": "Code/Projects",
            "5": "Custom Path"
        }
        
        print(f"{Fore.WHITE}Select what to backup:{Style.RESET_ALL}")
        for key, value in backup_types.items():
            print(f"{Fore.CYAN}{key}. {value}{Style.RESET_ALL}")
        
        choice = input("Choice: ")
        
        if choice in backup_types:
            print(f"\n{Fore.WHITE}Backup Strategy for: {backup_types[choice]}{Style.RESET_ALL}")
            print(f"\n{Fore.CYAN}3-2-1 Backup Rule:{Style.RESET_ALL}")
            print(f"{Fore.WHITE}• 3 copies of your data{Style.RESET_ALL}")
            print(f"{Fore.WHITE}• 2 different media types{Style.RESET_ALL}")
            print(f"{Fore.WHITE}• 1 copy offsite{Style.RESET_ALL}")
            
            print(f"\n{Fore.CYAN}Recommended Tools:{Style.RESET_ALL}")
            print(f"{Fore.WHITE}• Windows: File History, Backup and Restore{Style.RESET_ALL}")
            print(f"{Fore.WHITE}• macOS: Time Machine{Style.RESET_ALL}")
            print(f"{Fore.WHITE}• Linux: rsync, deja-dup, Timeshift{Style.RESET_ALL}")
            print(f"{Fore.WHITE}• Cross-platform: Duplicati, BorgBackup{Style.RESET_ALL}")
            
            print(f"\n{Fore.CYAN}Cloud Options:{Style.RESET_ALL}")
            print(f"{Fore.WHITE}• Encrypted: Cryptomator + any cloud{Style.RESET_ALL}")
            print(f"{Fore.WHITE}• Privacy: Nextcloud, ProtonDrive{Style.RESET_ALL}")
            print(f"{Fore.WHITE}• Commercial: Backblaze, iDrive{Style.RESET_ALL}")
            
            print(f"\n{Fore.YELLOW}⏰ Schedule regular backups!{Style.RESET_ALL}")
            print(f"{Fore.WHITE}Weekly for documents, monthly for full system{Style.RESET_ALL}")

    # ==================== TOOL 14: MALWARE DETECTION ====================
    def malware_detection(self):
        print(f"\n{Fore.CYAN}[🦠 MALWARE DETECTION HELPER]{Style.RESET_ALL}")
        
        print(f"{Fore.WHITE}Signs of malware infection:{Style.RESET_ALL}")
        print(f"{Fore.CYAN}1. Slow computer performance{Style.RESET_ALL}")
        print(f"{Fore.CYAN}2. Unexpected pop-ups{Style.RESET_ALL}")
        print(f"{Fore.CYAN}3. Changed browser homepage{Style.RESET_ALL}")
        print(f"{Fore.CYAN}4. Unknown programs running{Style.RESET_ALL}")
        print(f"{Fore.CYAN}5. High network activity{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}Detection Steps:{Style.RESET_ALL}")
        print(f"{Fore.WHITE}1. Run antivirus scan{Style.RESET_ALL}")
        print(f"{Fore.WHITE}2. Check startup programs{Style.RESET_ALL}")
        print(f"{Fore.WHITE}3. Monitor network connections{Style.RESET_ALL}")
        print(f"{Fore.WHITE}4. Review recent installations{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}Recommended Scanners:{Style.RESET_ALL}")
        print(f"{Fore.WHITE}• Windows: Windows Defender, Malwarebytes{Style.RESET_ALL}")
        print(f"{Fore.WHITE}• macOS: Malwarebytes, BlockBlock{Style.RESET_ALL}")
        print(f"{Fore.WHITE}• Linux: ClamAV, rkhunter, chkrootkit{Style.RESET_ALL}")
        print(f"{Fore.WHITE}• Online scanners: VirusTotal{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}Prevention Tips:{Style.RESET_ALL}")
        print(f"{Fore.WHITE}• Keep software updated{Style.RESET_ALL}")
        print(f"{Fore.WHITE}• Don't click suspicious links{Style.RESET_ALL}")
        print(f"{Fore.WHITE}• Use ad-blocker{Style.RESET_ALL}")
        print(f"{Fore.WHITE}• Regular backups{Style.RESET_ALL}")
        print(f"{Fore.WHITE}• Least privilege principle{Style.RESET_ALL}")

    # ==================== TOOL 15: FIREWALL HELPER ====================
    def firewall_helper(self):
        print(f"\n{Fore.CYAN}[🔥 FIREWALL CONFIGURATION HELPER]{Style.RESET_ALL}")
        
        print(f"{Fore.WHITE}Select your OS:{Style.RESET_ALL}")
        print(f"{Fore.CYAN}1. Windows{Style.RESET_ALL}")
        print(f"{Fore.CYAN}2. Linux{Style.RESET_ALL}")
        print(f"{Fore.CYAN}3. macOS{Style.RESET_ALL}")
        
        os_choice = input("Choice: ")
        
        if os_choice == "1":
            print(f"\n{Fore.CYAN}Windows Firewall Commands:{Style.RESET_ALL}")
            print(f"{Fore.WHITE}• Check status: Get-NetFirewallProfile{Style.RESET_ALL}")
            print(f"{Fore.WHITE}• Enable: Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True{Style.RESET_ALL}")
            print(f"{Fore.WHITE}• Add rule: New-NetFirewallRule -DisplayName 'Allow App' -Direction Inbound -Program 'C:\\app.exe' -Action Allow{Style.RESET_ALL}")
            print(f"{Fore.WHITE}• Block port: New-NetFirewallRule -DisplayName 'Block Port' -Direction Inbound -LocalPort 80 -Protocol TCP -Action Block{Style.RESET_ALL}")
            
        elif os_choice == "2":
            print(f"\n{Fore.CYAN}Linux Firewall (UFW):{Style.RESET_ALL}")
            print(f"{Fore.WHITE}• Enable: sudo ufw enable{Style.RESET_ALL}")
            print(f"{Fore.WHITE}• Status: sudo ufw status verbose{Style.RESET_ALL}")
            print(f"{Fore.WHITE}• Allow SSH: sudo ufw allow 22/tcp{Style.RESET_ALL}")
            print(f"{Fore.WHITE}• Allow HTTP/HTTPS: sudo ufw allow 80,443/tcp{Style.RESET_ALL}")
            print(f"{Fore.WHITE}• Deny all incoming: sudo ufw default deny incoming{Style.RESET_ALL}")
            print(f"{Fore.WHITE}• Allow all outgoing: sudo ufw default allow outgoing{Style.RESET_ALL}")
            
        elif os_choice == "3":
            print(f"\n{Fore.CYAN}macOS Firewall:{Style.RESET_ALL}")
            print(f"{Fore.WHITE}• Enable: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on{Style.RESET_ALL}")
            print(f"{Fore.WHITE}• Check status: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate{Style.RESET_ALL}")
            print(f"{Fore.WHITE}• GUI: System Preferences > Security & Privacy > Firewall{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}General Rules:{Style.RESET_ALL}")
        print(f"{Fore.WHITE}1. Default deny incoming{Style.RESET_ALL}")
        print(f"{Fore.WHITE}2. Allow only necessary ports{Style.RESET_ALL}")
        print(f"{Fore.WHITE}3. Monitor logs regularly{Style.RESET_ALL}")
        print(f"{Fore.WHITE}4. Test firewall with online tools{Style.RESET_ALL}")
        print(f"{Fore.WHITE}5. Keep firewall rules documented{Style.RESET_ALL}")

    # ==================== MAIN EXECUTION ====================
    def run(self):
        while True:
            self.display_banner()
            choice = input(f"\n{Fore.YELLOW}Select tool (0-15): {Style.RESET_ALL}")
            
            if choice == "0":
                print(f"\n{Fore.GREEN}Thank you for using SUDO Cybersecurity Toolkit! Stay secure! 🔒{Style.RESET_ALL}")
                break
            
            elif choice in self.tools:
                print(f"\n{Fore.MAGENTA}{'='*60}{Style.RESET_ALL}")
                print(f"{Fore.MAGENTA}Starting: {self.tools[choice]}{Style.RESET_ALL}")
                print(f"{Fore.MAGENTA}{'='*60}{Style.RESET_ALL}")
                
                # Call the selected tool
                tool_methods = {
                    "1": self.password_checker,
                    "2": self.network_scanner,
                    "3": self.website_analyzer,
                    "4": self.file_integrity,
                    "5": self.email_verifier,
                    "6": self.dns_security_check,
                    "7": self.ssl_analyzer,
                    "8": self.data_leak_checker,
                    "9": self.system_hardening,
                    "10": self.incident_response,
                    "11": self.security_quiz,
                    "12": self.privacy_tools,
                    "13": self.backup_utility,
                    "14": self.malware_detection,
                    "15": self.firewall_helper
                }
                
                try:
                    tool_methods[choice]()
                except Exception as e:
                    print(f"\n{Fore.RED}Error: {e}{Style.RESET_ALL}")
                
                input(f"\n{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")
                
            else:
                print(f"\n{Fore.RED}Invalid choice! Please select 0-15{Style.RESET_ALL}")

# ==================== INSTALLATION & SETUP ====================
def check_dependencies():
    required = ['requests', 'colorama']
    missing = []
    
    for package in required:
        try:
            __import__(package.replace('-', '_'))
        except ImportError:
            missing.append(package)
    
    if missing:
        print(f"\n{Fore.YELLOW}Missing dependencies: {missing}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Install with: pip install " + " ".join(missing) + f"{Style.RESET_ALL}")
        return False
    return True

# ==================== MAIN ====================
if __name__ == "__main__":
    try:
        if not check_dependencies():
            print(f"\n{Fore.YELLOW}Some dependencies are missing. Tool may not work fully.{Style.RESET_ALL}")
            print(f"{Fore.WHITE}Continue anyway? (y/n): {Style.RESET_ALL}", end="")
            if input().lower() != 'y':
                sys.exit(1)
        
        tool = SUDO_CyberSuite()
        tool.run()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}Tool interrupted by user. Stay secure! 🔒{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}Unexpected error: {e}{Style.RESET_ALL}")
        sys.exit(1)
