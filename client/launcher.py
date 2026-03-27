import os
import sys
import time
import requests
import socket
import subprocess
import signal
import ipaddress
import logging

LOG_FILE = "probe_manager.log"
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s %(levelname)s:%(message)s')

script_dir = os.path.dirname(os.path.abspath(__file__))
os.chdir(script_dir)

VERSION_FILE = "version.txt"
server_ip = "127.0.0.1"
server_port = os.getenv("SERVER_PORT", "5454")
server_scheme = os.getenv("SERVER_SCHEME", "https")
TEMP_PROBE_FILE = "probe_new.py"
probe_process = None
shutdown_flag = False
CA_CERT_PATH = os.getenv("SERVER_CA_CERT", "server-cert.pem")
SERVER_FILE = "server.txt"

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
SERVER_TOKEN = None


def verify_server_cert_value():
    if server_scheme != "https":
        return None
    if os.path.exists(CA_CERT_PATH):
        return CA_CERT_PATH
    logging.warning("CA certificate not found at %s; TLS verification disabled", CA_CERT_PATH)
    return False


def get_server_token(force_refresh=False):
    global SERVER_TOKEN

    if SERVER_TOKEN and not force_refresh:
        return SERVER_TOKEN

    if not ADMIN_USERNAME or not ADMIN_PASSWORD:
        logging.error("ADMIN_USERNAME and ADMIN_PASSWORD are required for authenticated updates")
        return None

    try:
        response = requests.post(
            f"{server_scheme}://{server_ip}:{server_port}/api/auth/token",
            json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD},
            verify=verify_server_cert_value(),
            timeout=10,
        )
        if response.status_code == 200:
            SERVER_TOKEN = response.json().get("token")
            return SERVER_TOKEN

        logging.error("Failed to acquire auth token: %s", response.text)
        return None
    except Exception:
        logging.exception("Error acquiring auth token")
        return None


def auth_headers(force_refresh=False):
    token = get_server_token(force_refresh=force_refresh)
    if not token:
        return None
    return {"Authorization": f"Bearer {token}"}


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


def handle_shutdown(signal_number, frame):
    global shutdown_flag
    shutdown_flag = True
    logging.info("Received shutdown signal. Stopping probe...")
    stop_probe()
    sys.exit(0)


signal.signal(signal.SIGINT, handle_shutdown)
signal.signal(signal.SIGTERM, handle_shutdown)


def get_current_version():
    try:
        with open(VERSION_FILE, "r", encoding="utf-8") as file:
            return file.read().strip()
    except FileNotFoundError:
        return "0.0.0"


def set_current_version(version):
    with open(VERSION_FILE, "w", encoding="utf-8") as file:
        file.write(version)


def discover_server_ip():
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
            logging.info("Server discovery timed out.")
            return None


def check_for_updates():
    headers = auth_headers()
    if not headers:
        return None

    verify = verify_server_cert_value()

    try:
        response = requests.get(
            f"{server_scheme}://{server_ip}:{server_port}/latest-version",
            headers=headers,
            verify=verify,
            timeout=10,
        )

        if response.status_code == 403:
            headers = auth_headers(force_refresh=True)
            if not headers:
                return None
            response = requests.get(
                f"{server_scheme}://{server_ip}:{server_port}/latest-version",
                headers=headers,
                verify=verify,
                timeout=10,
            )

        if response.status_code == 200:
            latest_version = response.json().get("latest_version")
            current_version = get_current_version()
            if latest_version and latest_version != current_version:
                logging.info("Update available: %s (current: %s)", latest_version, current_version)
                return latest_version
            logging.info("Client is up to date.")
            return None

        logging.error("Failed to fetch the latest version: %s", response.status_code)
        return None
    except Exception:
        logging.exception("Error checking for updates")
        return None


def download_new_version():
    headers = auth_headers()
    if not headers:
        return False

    verify = verify_server_cert_value()

    try:
        response = requests.get(
            f"{server_scheme}://{server_ip}:{server_port}/download-probe",
            headers=headers,
            verify=verify,
            timeout=20,
        )

        if response.status_code == 403:
            headers = auth_headers(force_refresh=True)
            if not headers:
                return False
            response = requests.get(
                f"{server_scheme}://{server_ip}:{server_port}/download-probe",
                headers=headers,
                verify=verify,
                timeout=20,
            )

        if response.status_code == 200:
            probe_code = response.json().get("probe_code")
            with open(TEMP_PROBE_FILE, "w", encoding="utf-8") as file:
                file.write(probe_code)
            logging.info("New version downloaded successfully.")
            return True

        logging.error("Failed to download the update: %s", response.status_code)
        return False
    except Exception:
        logging.exception("Error downloading update")
        return False


def start_probe():
    global probe_process
    logging.info("Starting probe.py...")
    probe_process = subprocess.Popen([sys.executable, "probe.py"])


def stop_probe():
    global probe_process
    if probe_process:
        logging.info("Stopping probe.py...")
        probe_process.terminate()
        probe_process.wait()
        probe_process = None


def apply_update(new_version):
    logging.info("Applying update...")
    try:
        stop_probe()

        if os.path.exists("probe.py"):
            os.remove("probe.py")

        os.rename(TEMP_PROBE_FILE, "probe.py")
        set_current_version(new_version)
        logging.info("Probe updated successfully. Restarting...")
        start_probe()
    except Exception:
        logging.exception("Error applying update")


def run_probe():
    global server_ip
    ip = get_ip_address()
    if ip:
        server_ip = ip
    else:
        discovered = discover_server_ip()
        if discovered:
            server_ip = discovered

    start_probe()

    while not shutdown_flag:
        new_version = check_for_updates()
        if new_version and download_new_version():
            apply_update(new_version)

        time.sleep(300)


if __name__ == "__main__":
    logging.info("Starting probe manager.")
    run_probe()
