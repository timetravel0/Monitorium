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
import jwt
import ipaddress
import logging

LOG_FILE = "probe.log"
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s %(levelname)s:%(message)s')

script_dir = os.path.dirname(os.path.abspath(__file__))
os.chdir(script_dir)

JWT_TOKEN = None
DEFAULT_INTERVAL = 300
MIN_INTERVAL = 60
MAX_INTERVAL = 600


def env_required(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


SECRET_KEY = env_required('JWT_SECRET_KEY')
ADMIN_USERNAME = env_required('ADMIN_USERNAME')
ADMIN_PASSWORD = env_required('ADMIN_PASSWORD')

SERVER_FILE = "server.txt"
SERVER_PORT = os.getenv("SERVER_PORT", "5454")
SERVER_SCHEME = os.getenv("SERVER_SCHEME", "https")
CA_CERT_PATH = os.getenv("SERVER_CA_CERT", "server-cert.pem")

reporting_interval = DEFAULT_INTERVAL
admin_set_interval = None

app = Flask(__name__)
SERVER_URL = f"{SERVER_SCHEME}://127.0.0.1:{SERVER_PORT}/update"


def get_ip_address():
    try:
        with open(SERVER_FILE, "r", encoding="utf-8") as file:
            ip = file.read().strip()
            try:
                ipaddress.ip_address(ip)
                return ip
            except ValueError:
                return False
    except FileNotFoundError:
        return False


def verify_server_cert_value():
    if SERVER_SCHEME != "https":
        return None
    if os.path.exists(CA_CERT_PATH):
        return CA_CERT_PATH
    logging.warning("CA certificate not found at %s; TLS verification disabled", CA_CERT_PATH)
    return False


def login():
    global JWT_TOKEN
    server_ip = discover_server_ip()
    if not server_ip:
        logging.error("Unable to discover server IP during login")
        return False

    login_url = f"{SERVER_SCHEME}://{server_ip}:{SERVER_PORT}/api/auth/token"
    verify = verify_server_cert_value()

    try:
        response = requests.post(
            login_url,
            json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD},
            verify=verify,
            timeout=10,
        )
        if response.status_code == 200:
            JWT_TOKEN = response.json().get('token')
            logging.info("Login successful, token obtained.")
            return True

        logging.error("Login failed: %s", response.text)
        return False
    except Exception:
        logging.exception("Error during login")
        return False


def send_authenticated_request(url, data=None):
    global JWT_TOKEN

    if not JWT_TOKEN and not login():
        return None

    verify = verify_server_cert_value()
    headers = {"Authorization": f"Bearer {JWT_TOKEN}"}

    try:
        response = requests.post(url, json=data, headers=headers, verify=verify, timeout=10)
        if response.status_code == 403:
            # Expired token: login again and retry once.
            if login():
                headers = {"Authorization": f"Bearer {JWT_TOKEN}"}
                response = requests.post(url, json=data, headers=headers, verify=verify, timeout=10)
        return response
    except Exception:
        logging.exception("Error while sending authenticated request")
        return None


def adjust_interval_based_on_load():
    global reporting_interval

    cpu_usage = psutil.cpu_percent(interval=1)
    memory_usage = psutil.virtual_memory().percent

    if cpu_usage < 30 and memory_usage < 40:
        reporting_interval = MIN_INTERVAL
    elif cpu_usage > 80 or memory_usage > 80:
        reporting_interval = MAX_INTERVAL
    else:
        reporting_interval = DEFAULT_INTERVAL

    logging.info("Adjusted reporting interval to: %s seconds", reporting_interval)


@app.route('/login', methods=['POST'])
def login_from_server():
    data = request.json or {}
    username = data.get('username')
    password = data.get('password')

    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        token = jwt.encode(
            {
                'user': 'admin',
                'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
            },
            SECRET_KEY,
            algorithm="HS256"
        )
        return jsonify({'token': token}), 200

    return jsonify({'message': 'Invalid credentials!'}), 401


@app.route('/set-interval', methods=['POST'])
def set_interval():
    global admin_set_interval
    data = request.json or {}

    if 'interval' in data:
        try:
            new_interval = int(data['interval'])
            if MIN_INTERVAL <= new_interval <= MAX_INTERVAL:
                admin_set_interval = new_interval
                return jsonify({"status": "success", "new_interval": admin_set_interval}), 200
            return jsonify({"status": "error", "message": "Interval out of bounds"}), 400
        except ValueError:
            return jsonify({"status": "error", "message": "Invalid interval format"}), 400

    return jsonify({"status": "error", "message": "Missing interval"}), 400


def discover_server_ip():
    ip = get_ip_address()
    if ip:
        return ip

    discovery_port = 5002
    discovery_message = "DISCOVER_SERVER"
    broadcast_ip = '<broadcast>'

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(5)

        try:
            sock.sendto(discovery_message.encode('utf-8'), (broadcast_ip, discovery_port))
            logging.info("Broadcasting discovery message...")

            _, addr = sock.recvfrom(1024)
            logging.info("Received response from server: %s", addr[0])
            return addr[0]
        except socket.timeout:
            logging.error("Server discovery timed out.")
            return None


def update_server_url():
    server_ip = discover_server_ip()
    if server_ip:
        return f"{SERVER_SCHEME}://{server_ip}:{SERVER_PORT}/update"

    logging.warning("Using default server URL.")
    return SERVER_URL


def delayed_shutdown_or_reboot(command):
    time.sleep(1)
    os.system(command)


def verify_server_token(token):
    try:
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return decoded_token.get('user') == 'admin'
    except jwt.ExpiredSignatureError:
        logging.error("Token has expired")
        return False
    except jwt.InvalidTokenError:
        logging.error("Invalid token")
        return False


@app.route('/reboot', methods=['POST'])
def reboot():
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify({"status": "failed", "reason": "Missing token"}), 403

    token = auth_header.split(" ", 1)[1]
    if not verify_server_token(token):
        return jsonify({"status": "failed", "reason": "Invalid or missing token"}), 403

    command = "shutdown /r /t 0" if platform.system() == "Windows" else "sudo reboot"
    Thread(target=delayed_shutdown_or_reboot, args=(command,)).start()
    return jsonify({"status": "rebooting"}), 200


@app.route('/shutdown', methods=['POST'])
def shutdown():
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify({"status": "failed", "reason": "Missing token"}), 403

    token = auth_header.split(" ", 1)[1]
    if not verify_server_token(token):
        return jsonify({"status": "failed", "reason": "Invalid or missing token"}), 403

    command = "shutdown /s /t 0" if platform.system() == "Windows" else "sudo shutdown now"
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
        io_counters = psutil.disk_io_counters(perdisk=True)
        relevant_counters = {k: v for k, v in io_counters.items() if not k.startswith(('ram', 'loop'))}
        read_bytes = sum(v.read_bytes for v in relevant_counters.values())
        write_bytes = sum(v.write_bytes for v in relevant_counters.values())
        return {"read_bytes": read_bytes, "write_bytes": write_bytes}
    except Exception:
        logging.exception("Error while fetching disk I/O counters")
        return {"read_bytes": 0, "write_bytes": 0}


def get_network_io():
    net_io = psutil.net_io_counters()
    return {"bytes_sent": net_io.bytes_sent, "bytes_recv": net_io.bytes_recv}


def get_public_ip_address():
    try:
        response = requests.get('https://api.ipify.org?format=json', timeout=5)
        return response.json()['ip']
    except Exception as exc:
        logging.error("Error getting public IP address: %s", exc)
        return f"Error: {exc}"


def get_local_ip():
    try:
        conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        conn.settimeout(2)
        conn.connect(("8.8.8.8", 80))
        local_ip = conn.getsockname()[0]
        conn.close()
        return local_ip
    except Exception:
        logging.exception("Error getting local IP")
        return "127.0.0.1"


def get_hdd_usage():
    usage = psutil.disk_usage('/')
    return {
        "total": usage.total // (2**30),
        "used": usage.used // (2**30),
        "free": usage.free // (2**30),
        "percent": usage.percent,
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
    return {
        "hostname": socket.gethostname(),
        "public_ip_address": get_public_ip_address(),
        "local_ip_address": get_local_ip(),
        "platform": platform.platform(),
        "mac_address": gma(),
        "cpu_usage": psutil.cpu_percent(interval=1),
        "memory_usage": psutil.virtual_memory().percent,
        "hdd_usage": get_hdd_usage(),
        "running_processes": get_running_processes(),
        "used_ports": get_used_ports(),
        "last_reboot": get_last_boot_time(),
        "uptime": get_system_uptime(),
        "current_users": get_current_users(),
        "disk_io": get_disk_io(),
        "network_io": get_network_io(),
        "last_updated": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }


def send_data_to_server(data):
    server_url = update_server_url()
    response = send_authenticated_request(server_url, data)
    if response and response.status_code == 200:
        logging.info("Data sent to server successfully")
    else:
        status = response.status_code if response else "no response"
        body = response.text if response else ""
        logging.error("Failed to send data to server: %s %s", status, body)


def run_probe():
    global reporting_interval, admin_set_interval

    while True:
        data = get_system_info()
        send_data_to_server(data)

        if admin_set_interval:
            reporting_interval = admin_set_interval
        else:
            adjust_interval_based_on_load()

        time.sleep(reporting_interval)


@app.route('/trigger-update', methods=['POST'])
def trigger_update():
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify({"status": "failed", "reason": "Missing token"}), 403

    token = auth_header.split(" ", 1)[1]
    if not verify_server_token(token):
        return jsonify({"status": "failed", "reason": "Invalid or missing token"}), 403

    data = get_system_info()
    send_data_to_server(data)
    return jsonify({"status": "updated"}), 200


def signal_handler(sig, frame):
    logging.info('Shutting down...')
    sys.exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    logging.info("Starting probe script")

    if not login():
        logging.error("Unable to authenticate with server at startup")

    Thread(target=lambda: app.run(host='0.0.0.0', port=5001)).start()
    run_probe()
