import subprocess
import sys
import os
import platform
import socket
import psutil
import datetime
import time
import requests
import signal
from flask import Flask, request, jsonify
from getmac import get_mac_address as gma
from threading import Thread

## I AM NEWER VERSION

# List of external packages to ensure they are installed
required_packages = [
    "psutil",
    "getmac",
    "requests",
    "flask"
]

def install(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])

# Install missing packages
for package in required_packages:
    try:
        __import__(package)
    except ImportError:
        install(package)

app = Flask(__name__)
SERVER_URL = "http://127.0.0.1:8080/update"

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

# Update SERVER_URL dynamically
def update_server_url():
    server_ip = discover_server_ip()
    if server_ip:
        return f"http://{server_ip}:8080/update"
    else:
        print("Using default server URL.")
        return SERVER_URL  # Fallback to default server URL

def delayed_shutdown_or_reboot(command):
    time.sleep(1)  # Delay to allow response to be sent
    os.system(command)

@app.route('/reboot', methods=['POST'])
def reboot():
    if platform.system() == "Windows":
        command = "shutdown /r /t 0"
    else:  # Linux
        command = "sudo reboot"
    
    Thread(target=delayed_shutdown_or_reboot, args=(command,)).start()
    return jsonify({"status": "rebooting"}), 200

@app.route('/shutdown', methods=['POST'])
def shutdown():
    if platform.system() == "Windows":
        command = "shutdown /s /t 0"
    else:  # Linux
        command = "sudo shutdown now"
    
    Thread(target=delayed_shutdown_or_reboot, args=(command,)).start()
    return jsonify({"status": "shutting down"}), 200

def get_last_boot_time():
    return datetime.datetime.fromtimestamp(psutil.boot_time()).strftime('%Y-%m-%d %H:%M:%S')

def get_system_uptime():
    uptime_seconds = (datetime.datetime.now() - datetime.datetime.fromtimestamp(psutil.boot_time())).total_seconds()
    return str(datetime.timedelta(seconds=uptime_seconds))

def get_current_users():
    users = psutil.users()
    return [f"{user.name} (since {datetime.datetime.fromtimestamp(user.started).strftime('%Y-%m-%d %H:%M:%S')})" for user in users]

def get_disk_io():
    try:
        # Retrieve the disk I/O counters, ignoring devices like `ram0`, `loop*`, etc.
        io_counters = psutil.disk_io_counters(perdisk=True)
        
        # Filter out virtual devices that aren't relevant
        relevant_counters = {k: v for k, v in io_counters.items() if not k.startswith(('ram', 'loop'))}

        # Aggregate the relevant disk I/O stats
        read_bytes = sum(v.read_bytes for v in relevant_counters.values())
        write_bytes = sum(v.write_bytes for v in relevant_counters.values())

        return {
            "read_bytes": read_bytes,
            "write_bytes": write_bytes
        }
    except Exception as e:
        print(f"Error while fetching disk I/O counters: {e}")
        return {
            "read_bytes": 0,
            "write_bytes": 0
        }

def get_network_io():
    net_io = psutil.net_io_counters()
    return {
        "bytes_sent": net_io.bytes_sent,
        "bytes_recv": net_io.bytes_recv
    }

def get_public_ip_address():
    try:
        response = requests.get('https://api.ipify.org?format=json')
        return response.json()['ip']
    except Exception as e:
        return f"Error: {e}"

def get_local_ip():
    try:
        # Create a socket and connect to a remote server (e.g., Google's public DNS server)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        
        # Use an external address (this does not send data, just opens the socket to determine the interface)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception as e:
        print(f"Error getting local IP: {e}")
        local_ip = "127.0.0.1"  # Fallback in case of error

    return local_ip

def get_hdd_usage():
    usage = psutil.disk_usage('/')
    return {
        "total": usage.total // (2**30),  # in GB
        "used": usage.used // (2**30),    # in GB
        "free": usage.free // (2**30),    # in GB
        "percent": usage.percent          # in %
    }

def get_running_processes():
    processes = []
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            processes.append(f"{proc.info['pid']} - {proc.info['name']}")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return processes

def get_used_ports():
    ports = []
    for conn in psutil.net_connections(kind='inet'):
        laddr = f"{conn.laddr.ip}:{conn.laddr.port}"
        raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "LISTENING"
        try:
            service = socket.getservbyport(conn.laddr.port, "tcp") if conn.status == psutil.CONN_LISTEN else "UNKNOWN"
        except OSError:
            service = "UNKNOWN"
        ports.append(f"{laddr} -> {raddr} ({service})")
    return ports

def get_system_info():
    hostname = socket.gethostname()
    ip_address = get_public_ip_address()
    local_ip_address = get_local_ip()
    #local_ip_address = socket.gethostbyname(hostname)
    platform_info = platform.platform()
    mac_address = gma()
    cpu_usage = psutil.cpu_percent(interval=1)
    memory_usage = psutil.virtual_memory().percent
    hdd_usage = get_hdd_usage()
    running_processes = get_running_processes()
    used_ports = get_used_ports()

    return {
        "hostname": hostname,
        "public_ip_address": ip_address,
        "local_ip_address": local_ip_address,
        "platform": platform_info,
        "mac_address": mac_address,
        "cpu_usage": cpu_usage,
        "memory_usage": memory_usage,
        "hdd_usage": hdd_usage,
        "running_processes": running_processes,
        "used_ports": used_ports,
        "last_reboot": get_last_boot_time(),
        "uptime": get_system_uptime(),
        "current_users": get_current_users(),
        "disk_io": get_disk_io(),
        "network_io": get_network_io(),
        "last_updated": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }

def send_data_to_server(data):

    server_url = update_server_url()  # Get the server IP dynamically

    try:
        response = requests.post(server_url, json=data)
        if response.status_code == 200:
            print(f"Data sent to server successfully")
        else:
            print(f"Failed to send data to server: {response.status_code}, Reason: {response.json().get('reason', 'No reason provided')}")
    except Exception as e:
        print(f"Error sending data to server: {e}")

def run_probe():
    while True:    
        data = get_system_info()
        send_data_to_server(data)
        time.sleep(300)  # Wait for 5 minutes before sending the next update

@app.route('/trigger-update', methods=['POST'])
def trigger_update():
    data = get_system_info()
    send_data_to_server(data)
    return jsonify({"status": "updated"}), 200

def signal_handler(sig, frame):
    print('Shutting down...')
    sys.exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)  # Handle Ctrl+C

    # Run the Flask app in a separate thread
    Thread(target=lambda: app.run(host='0.0.0.0', port=5001)).start()

    run_probe()  # Run the probe loop
