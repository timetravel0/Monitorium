import subprocess
import sys
import os
import sqlite3
import json
from flask import Flask, request, render_template, jsonify
import requests
from flask_socketio import SocketIO, emit
import logging
import threading
import socket

# List of required packages
required_packages = [
    "Flask",
    "psutil",
    "getmac",
    "requests",
    "flask-socketio"
]

def install(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])

# Install missing packages
for package in required_packages:
    try:
        __import__(package.lower())
    except ImportError:
        install(package)

app = Flask(__name__)
socketio = SocketIO(app)

DATABASE_PATH = 'local_data.db'
CLIENT_PORT = 5001  # The port where the client Flask server listens

# Set up logging
logging.basicConfig(level=logging.DEBUG)

def handle_discovery_requests():
    DISCOVERY_PORT = 5002  # Port to listen for discovery broadcasts
    server_ip = socket.gethostbyname(socket.gethostname())
    
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(("", DISCOVERY_PORT))
        print(f"Listening for discovery requests on port {DISCOVERY_PORT}...")

        while True:
            data, addr = sock.recvfrom(1024)  # Buffer size of 1024 bytes
            if data.decode('utf-8') == "DISCOVER_SERVER":
                print(f"Discovery request received from {addr}")
                sock.sendto(server_ip.encode('utf-8'), addr)  # Send the server IP to the client


def get_db_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def recreate_database():
    if os.path.exists(DATABASE_PATH):
        os.remove(DATABASE_PATH)
    conn = get_db_connection()
    cursor = conn.cursor()
    ensure_table_exists(cursor)
    conn.commit()
    conn.close()

def check_and_recreate_db():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('PRAGMA table_info(pc_info)')
        existing_columns = [col[1] for col in cursor.fetchall()]

        expected_columns = [
            'id', 'mac_address', 'hostname', 'local_ip_address', 'public_ip_address', 'platform',
            'cpu_usage', 'memory_usage', 'hdd_total', 'hdd_used', 'hdd_free', 'hdd_percent',
            'running_processes', 'used_ports', 'last_reboot', 'uptime', 'current_users',
            'disk_io_read_bytes', 'disk_io_write_bytes', 'net_io_bytes_sent', 'net_io_bytes_recv', 'last_updated'
        ]

        if set(existing_columns) != set(expected_columns):
            print("Database schema mismatch. Recreating the database...")
            conn.close()
            recreate_database()
        else:
            print("Database schema is up to date.")
            conn.close()
    except Exception as e:
        print(f"Error checking database schema: {e}")
        recreate_database()

def ensure_table_exists(cursor):
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS pc_info (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        mac_address TEXT UNIQUE,
        hostname TEXT,
        local_ip_address TEXT,
        public_ip_address TEXT,
        platform TEXT,
        cpu_usage REAL,
        memory_usage REAL,
        hdd_total INTEGER,
        hdd_used INTEGER,
        hdd_free INTEGER,
        hdd_percent REAL,
        running_processes TEXT,
        used_ports TEXT,
        last_reboot TEXT,
        uptime TEXT,
        current_users TEXT,
        disk_io_read_bytes INTEGER,
        disk_io_write_bytes INTEGER,
        net_io_bytes_sent INTEGER,
        net_io_bytes_recv INTEGER,
        last_updated DATETIME
    )
    ''')

# Check and recreate the database if needed when the server starts
check_and_recreate_db()

def get_db_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row  # This allows us to access columns by name.
    return conn

@app.route('/')
def dashboard():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM pc_info')
    pc_info_rows = cursor.fetchall()
    
    # Convert each Row object to a dictionary
    pc_info = [dict(row) for row in pc_info_rows]

    conn.close()
    return render_template('dashboard.html', pc_info=pc_info)

def resolve_client_ip(mac_address):
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    # Query to find the local IP address corresponding to the MAC address
    cursor.execute('SELECT local_ip_address FROM pc_info WHERE mac_address = ?', (mac_address,))
    result = cursor.fetchone()
    
    conn.close()
    
    if result:
        return result[0]  # Return the local IP address
    else:
        return None  # MAC address not found

@app.route('/action', methods=['POST'])
def perform_action():
    data = request.json
    mac_address = data.get('mac_address')
    action = data.get('action')

    logging.debug(f"Received action request: {action} for MAC: {mac_address}")

    if not mac_address or not action:
        logging.error("Invalid parameters received")
        return jsonify({"status": "failed", "reason": "Invalid parameters"}), 400

    client_ip = resolve_client_ip(mac_address)
    if not client_ip:
        logging.error(f"Client IP not found for MAC: {mac_address}")
        return jsonify({"status": "failed", "reason": "Client IP not found"}), 404

    try:
        url = f'http://{client_ip}:{CLIENT_PORT}/{action}'
        logging.debug(f"Sending {action} request to {url}")
        response = requests.post(url)
        logging.debug(f"Response from client: {response.status_code} - {response.text}")
        if response.status_code == 200:
            return jsonify({"status": "success"}), 200
        else:
            logging.error(f"Client error: {response.status_code}")
            return jsonify({"status": "failed", "reason": f"Client error: {response.status_code}"}), 500
    except Exception as e:
        logging.error(f"Error sending {action} to client: {str(e)}")
        return jsonify({"status": "failed", "reason": f"Error: {str(e)}"}), 500


@app.route('/update', methods=['POST'])
def update_data():
    try:
        data = request.json
        if data is None:
            return jsonify({"status": "failed", "reason": "No JSON payload provided"}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('''
            INSERT INTO pc_info (mac_address, hostname, local_ip_address, public_ip_address, platform, cpu_usage, 
                                 memory_usage, hdd_total, hdd_used, hdd_free, hdd_percent, running_processes, used_ports, 
                                 last_reboot, uptime, current_users, disk_io_read_bytes, disk_io_write_bytes, 
                                 net_io_bytes_sent, net_io_bytes_recv, last_updated)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(mac_address) DO UPDATE SET
                hostname=excluded.hostname,
                local_ip_address=excluded.local_ip_address,
                public_ip_address=excluded.public_ip_address,
                platform=excluded.platform,
                cpu_usage=excluded.cpu_usage,
                memory_usage=excluded.memory_usage,
                hdd_total=excluded.hdd_total,
                hdd_used=excluded.hdd_used,
                hdd_free=excluded.hdd_free,
                hdd_percent=excluded.hdd_percent,
                running_processes=excluded.running_processes,
                used_ports=excluded.used_ports,
                last_reboot=excluded.last_reboot,
                uptime=excluded.uptime,
                current_users=excluded.current_users,
                disk_io_read_bytes=excluded.disk_io_read_bytes,
                disk_io_write_bytes=excluded.disk_io_write_bytes,
                net_io_bytes_sent=excluded.net_io_bytes_sent,
                net_io_bytes_recv=excluded.net_io_bytes_recv,
                last_updated=excluded.last_updated
        ''', (
            data['mac_address'], data['hostname'], data['local_ip_address'], data['public_ip_address'],
            data['platform'], data['cpu_usage'], data['memory_usage'], data['hdd_usage']['total'], data['hdd_usage']['used'],
            data['hdd_usage']['free'], data['hdd_usage']['percent'], 
            json.dumps(data['running_processes']), json.dumps(data['used_ports']),
            data['last_reboot'], data['uptime'], json.dumps(data['current_users']),
            data['disk_io']['read_bytes'], data['disk_io']['write_bytes'],
            data['network_io']['bytes_sent'], data['network_io']['bytes_recv'], data['last_updated']
        ))

        conn.commit()
        conn.close()

        socketio.emit('update_received')  # Notify clients about the update

        return jsonify({"status": "success"}), 200
    except sqlite3.DatabaseError as db_err:
        return jsonify({"status": "failed", "reason": f"Database error: {db_err}"}), 500
    except KeyError as key_err:
        return jsonify({"status": "failed", "reason": f"Missing key in data: {key_err}"}), 400
    except Exception as e:
        return jsonify({"status": "failed", "reason": f"An unexpected error occurred: {e}"}), 500


@app.route('/request-update', methods=['POST'])
def request_update():
    mac_address = request.json.get('mac_address')    
    client_port = 5001  # Port where the client Flask server is listening
    
    if not mac_address:
        logging.error("Invalid parameters received")
        return jsonify({"status": "failed", "reason": "Invalid parameters"}), 400

    client_ip = resolve_client_ip(mac_address)
    if not client_ip:
        logging.error(f"Client IP not found for MAC: {mac_address}")
        return jsonify({"status": "failed", "reason": "Client IP not found"}), 404

    try:
        # Send the request to the client
        url = f'http://{client_ip}:{client_port}/trigger-update'
        response = requests.post(url)
        if response.status_code == 200:
            return jsonify({"status": "update-requested"}), 200
        else:
            return jsonify({"status": "failed", "reason": "Command failed"}), 500
    except Exception as e:
        print(f"Error requesting update: {e}")
        return jsonify({"status": "failed", "reason": str(e)}), 500

if __name__ == '__main__':

    discovery_thread = threading.Thread(target=handle_discovery_requests, daemon=True)
    discovery_thread.start()

    socketio.run(app, debug=True, host='0.0.0.0', port=8080)