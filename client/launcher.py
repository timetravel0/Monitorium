import os
import sys
import time
import requests
import socket
import subprocess
import signal
import ipaddress

VERSION_FILE = "version.txt"
server_ip = "127.0.0.1"
TEMP_PROBE_FILE = "probe_new.py"  # Temporary file for the new version
probe_process = None  # Global variable to store the probe process
shutdown_flag = False  # Flag to indicate shutdown
CA_CERT_PATH = "server-cert.pem"  # Path to the CA certificate for SSL verification
SERVER_FILE = "server.txt"

def get_ip_address():
    try:
        with open(SERVER_FILE, "r") as file:
            ip = file.read().strip()
            try:
                # Verifica se la stringa è un indirizzo IP valido
                ipaddress.ip_address(ip)
                return ip
            except ValueError:
                # La stringa non è un indirizzo IP valido
                return False
    except FileNotFoundError:
        # Il file non esiste
        return False

# Function to handle shutdown signals
def handle_shutdown(signal, frame):
    global shutdown_flag
    shutdown_flag = True
    print("Received shutdown signal. Stopping probe...")
    stop_probe()  # Stop the probe process properly
    sys.exit(0)

# Register signal handlers
signal.signal(signal.SIGINT, handle_shutdown)
signal.signal(signal.SIGTERM, handle_shutdown)


# Read the current version from version.txt
def get_current_version():
    try:
        with open(VERSION_FILE, "r") as file:
            return file.read().strip()
    except FileNotFoundError:
        return "0.0.0"  # Default version if version.txt doesn't exist


# Write the new version to version.txt
def set_current_version(version):
    with open(VERSION_FILE, "w") as file:
        file.write(version)


# Discover server IP
def discover_server_ip():
    DISCOVERY_PORT = 5002  # Same port as server listens on for discovery
    DISCOVERY_MESSAGE = "DISCOVER_SERVER"
    broadcast_ip = '<broadcast>'  # Broadcast address to reach all devices on the network

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(5)  # Timeout after 5 seconds if no response is received

        try:
            # Broadcast the discovery message
            sock.sendto(DISCOVERY_MESSAGE.encode('utf-8'), (broadcast_ip, DISCOVERY_PORT))
            print("Broadcasting discovery message...")

            # Wait for a response from the server
            response, addr = sock.recvfrom(1024)  # Buffer size of 1024 bytes
            print(f"Received response from server: {addr[0]}")
            return addr[0]  # Return the server IP address

        except socket.timeout:
            print("Server discovery timed out.")
            return None


# Check for updates
def check_for_updates():
    try:
        response = requests.get(f"https://{server_ip}:8080/latest-version", verify=CA_CERT_PATH)
        if response.status_code == 200:
            latest_version = response.json().get("latest_version")
            current_version = get_current_version()

            if latest_version and latest_version != current_version:
                print(f"Update available: {latest_version} (current: {current_version})")
                return latest_version
            else:
                print("Client is up to date.")
                return None
        else:
            print(f"Failed to fetch the latest version: {response.status_code}")
            return None
    except Exception as e:
        print(f"Error checking for updates: {e}")
        return None


# Download the new probe script and save it as a temp file
def download_new_version():
    try:
        response = requests.get(f"https://{server_ip}:8080/download-probe", verify=CA_CERT_PATH)
        if response.status_code == 200:
            probe_code = response.json().get("probe_code")
            with open(TEMP_PROBE_FILE, "w") as file:
                file.write(probe_code)
            print("New version downloaded successfully.")
            return True
        else:
            print(f"Failed to download the update: {response.status_code}")
            return False
    except Exception as e:
        print(f"Error downloading update: {e}")
        return False


# Start the probe.py as a separate process
def start_probe():
    global probe_process
    print("Starting probe.py...")
    probe_process = subprocess.Popen([sys.executable, "probe.py"])


# Stop the running probe process and clean up
def stop_probe():
    global probe_process
    if probe_process:
        print("Stopping probe.py...")
        probe_process.terminate()  # Gracefully stop the probe
        probe_process.wait()  # Wait for the process to terminate
        probe_process = None


# Apply the update by renaming the temp file and restarting
def apply_update(new_version):
    print("Applying update...")

    # Stop the probe and rename the new file
    try:
        stop_probe()  # Stop the running probe process
        
        if os.path.exists("probe.py"):
            os.remove("probe.py")
        
        os.rename(TEMP_PROBE_FILE, "probe.py")
        set_current_version(new_version)  # Update the version file
        print("Probe updated successfully. Restarting...")

        # Restart the probe
        start_probe()
    except Exception as e:
        print(f"Error applying update: {e}")


# Main function to check for updates and run the probe
def run_probe():
    global server_ip
    ip = get_ip_address()
    if ip:
        server_ip = ip
    
    # Start the probe initially
    start_probe()

    while not shutdown_flag:
        new_version = check_for_updates()
        if new_version:
            if download_new_version():
                # Stop and apply the update if a new version is found
                apply_update(new_version)

        # Wait for a while before checking for updates again
        time.sleep(300)  # Example sleep for 5 minutes




if __name__ == "__main__":
    run_probe()
