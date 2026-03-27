import os
import sqlite3
import json
import jwt
import datetime
from pathlib import Path
from collections import defaultdict
import logging
import threading
import socket
from functools import wraps

import requests
from cachetools import TTLCache
from flask import Flask, request, render_template, jsonify, redirect, url_for, session, send_file
from flask_socketio import SocketIO


def env_required(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


JWT_SECRET_KEY = env_required("JWT_SECRET_KEY")
ADMIN_USERNAME = env_required("ADMIN_USERNAME")
ADMIN_PASSWORD = env_required("ADMIN_PASSWORD")
FLASK_SECRET_KEY = env_required("FLASK_SECRET_KEY")

LATEST_VERSION = os.getenv("LATEST_VERSION", "1.0.2")
DATABASE_PATH = os.getenv("DATABASE_PATH", "local_data.db")
CLIENT_PORT = int(os.getenv("CLIENT_PORT", "5001"))
PROBE_SCHEME = os.getenv("PROBE_SCHEME", "http").lower()
PROBE_CA_CERT = os.getenv("PROBE_CA_CERT")
SERVER_PORT = int(os.getenv("SERVER_PORT", "5454"))
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))
RATE_LIMIT_MAX_REQUESTS = int(os.getenv("RATE_LIMIT_MAX_REQUESTS", "30"))
AUTH_RATE_LIMIT_MAX_REQUESTS = int(os.getenv("AUTH_RATE_LIMIT_MAX_REQUESTS", "10"))
CLIENT_INSTALLER_PATH = os.getenv(
    "CLIENT_INSTALLER_PATH",
    str(Path(__file__).resolve().parents[1] / "client" / "distribution" / "windows" / "output" / "ClientServiceSetup.exe"),
)

PROBE_TOKENS = TTLCache(maxsize=1024, ttl=1500)
RATE_LIMIT_STATE = defaultdict(list)
RATE_LIMIT_LOCK = threading.Lock()

app = Flask(__name__)
app.secret_key = FLASK_SECRET_KEY
socketio = SocketIO(app)

logging.basicConfig(level=logging.INFO)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"message": "Token is missing!"}), 403

        token = auth_header.split(" ", 1)[1]
        try:
            jwt.decode(token, JWT_SECRET_KEY, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token has expired!"}), 403
        except jwt.InvalidTokenError:
            return jsonify({"message": "Invalid token!"}), 403

        return f(*args, **kwargs)

    return decorated


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("authenticated"):
            if request.path.startswith("/api/") or request.is_json:
                return jsonify({"message": "Unauthorized"}), 401
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)

    return decorated


def get_db_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def ensure_table_exists(cursor):
    cursor.execute(
        """
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
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            event_type TEXT NOT NULL,
            actor TEXT,
            target TEXT,
            outcome TEXT NOT NULL,
            details TEXT
        )
        """
    )


def write_audit_log(event_type, outcome, actor=None, target=None, details=None):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO audit_log (event_type, actor, target, outcome, details)
            VALUES (?, ?, ?, ?, ?)
            """,
            (event_type, actor, target, outcome, details),
        )
        conn.commit()
        conn.close()
    except Exception as exc:
        logging.exception("Failed to write audit log: %s", exc)


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

        cursor.execute("PRAGMA table_info(pc_info)")
        existing_columns = [col[1] for col in cursor.fetchall()]

        expected_columns = [
            "id",
            "mac_address",
            "hostname",
            "local_ip_address",
            "public_ip_address",
            "platform",
            "cpu_usage",
            "memory_usage",
            "hdd_total",
            "hdd_used",
            "hdd_free",
            "hdd_percent",
            "running_processes",
            "used_ports",
            "last_reboot",
            "uptime",
            "current_users",
            "disk_io_read_bytes",
            "disk_io_write_bytes",
            "net_io_bytes_sent",
            "net_io_bytes_recv",
            "last_updated",
        ]

        if set(existing_columns) != set(expected_columns):
            logging.warning("Database schema mismatch. Recreating the database...")
            conn.close()
            recreate_database()
        else:
            logging.info("Database schema is up to date.")
            conn.close()
    except Exception as exc:
        logging.exception("Error checking database schema: %s", exc)
        recreate_database()


def _rate_limit_key_by_ip():
    return f"{request.path}:{request.remote_addr or 'unknown'}"


def _rate_limit_allow(key, max_requests, window_seconds):
    now = datetime.datetime.utcnow().timestamp()
    with RATE_LIMIT_LOCK:
        events = RATE_LIMIT_STATE[key]
        cutoff = now - window_seconds
        while events and events[0] < cutoff:
            events.pop(0)
        if len(events) >= max_requests:
            return False
        events.append(now)
        return True


def rate_limit(max_requests, window_seconds=RATE_LIMIT_WINDOW_SECONDS, key_func=_rate_limit_key_by_ip):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            key = key_func()
            if not _rate_limit_allow(key, max_requests, window_seconds):
                return jsonify({"message": "Too many requests"}), 429
            return f(*args, **kwargs)

        return wrapped

    return decorator


def handle_discovery_requests():
    discovery_port = 5002
    server_ip = socket.gethostbyname(socket.gethostname())

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(("", discovery_port))
        logging.info("Listening for discovery requests on port %s", discovery_port)

        while True:
            data, addr = sock.recvfrom(1024)
            if data.decode("utf-8") == "DISCOVER_SERVER":
                logging.info("Discovery request received from %s", addr)
                sock.sendto(server_ip.encode("utf-8"), addr)


def resolve_client_ip(mac_address):
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT local_ip_address FROM pc_info WHERE mac_address = ?", (mac_address,))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else None


def probe_verify_value():
    if PROBE_SCHEME != "https":
        return None
    if PROBE_CA_CERT:
        return PROBE_CA_CERT
    logging.warning("PROBE_SCHEME=https without PROBE_CA_CERT; TLS verification disabled for probe calls")
    return False


def login_to_probe(probe_ip):
    if probe_ip in PROBE_TOKENS:
        return PROBE_TOKENS[probe_ip]

    verify = probe_verify_value()
    login_url = f"{PROBE_SCHEME}://{probe_ip}:{CLIENT_PORT}/login"
    try:
        response = requests.post(
            login_url,
            json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD},
            verify=verify,
            timeout=10,
        )
        if response.status_code == 200:
            token = response.json().get("token")
            PROBE_TOKENS[probe_ip] = token
            return token
        logging.error("Login to probe %s failed: %s", probe_ip, response.text)
        return None
    except Exception as exc:
        logging.exception("Error during probe login: %s", exc)
        return None


@app.route("/login", methods=["GET", "POST"])
@rate_limit(AUTH_RATE_LIMIT_MAX_REQUESTS)
def login_page():
    if request.method == "GET":
        return render_template("login.html")

    username = request.form.get("username") or (request.json or {}).get("username")
    password = request.form.get("password") or (request.json or {}).get("password")

    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        session["authenticated"] = True
        write_audit_log("dashboard_login", "success", actor=username)
        if request.is_json:
            return jsonify({"status": "ok"}), 200
        return redirect(url_for("dashboard"))

    write_audit_log("dashboard_login", "failure", actor=username, details="Invalid credentials")
    if request.is_json:
        return jsonify({"message": "Invalid credentials"}), 401
    return render_template("login.html", error="Invalid credentials"), 401


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    return redirect(url_for("login_page"))


@app.route("/api/auth/token", methods=["POST"])
@rate_limit(AUTH_RATE_LIMIT_MAX_REQUESTS)
def issue_token():
    payload = request.json or {}
    if payload.get("username") == ADMIN_USERNAME and payload.get("password") == ADMIN_PASSWORD:
        token = jwt.encode(
            {"user": "probe", "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
            JWT_SECRET_KEY,
            algorithm="HS256",
        )
        write_audit_log("api_token_issue", "success", actor=payload.get("username"))
        return jsonify({"token": token})

    write_audit_log("api_token_issue", "failure", actor=payload.get("username"), details="Invalid credentials")
    return jsonify({"message": "Invalid credentials"}), 401


@app.route("/latest-version", methods=["GET"])
@token_required
def get_latest_version():
    return jsonify({"latest_version": LATEST_VERSION}), 200


@app.route("/download-probe", methods=["GET"])
@token_required
def download_probe():
    try:
        with open("probe.py", "r", encoding="utf-8") as file:
            probe_code = file.read()
        return jsonify({"probe_code": probe_code}), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/download-client", methods=["GET"])
@login_required
def download_client():
    installer_path = Path(CLIENT_INSTALLER_PATH)
    if not installer_path.exists():
        return jsonify({"status": "failed", "reason": "Installer not found"}), 404
    return send_file(installer_path, as_attachment=True)


@app.route("/")
@login_required
def dashboard():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM pc_info")
    pc_info_rows = cursor.fetchall()
    pc_info = [dict(row) for row in pc_info_rows]
    conn.close()
    return render_template("dashboard.html", pc_info=pc_info)


@app.route("/action", methods=["POST"])
@login_required
@rate_limit(RATE_LIMIT_MAX_REQUESTS)
def perform_action():
    data = request.json or {}
    mac_address = data.get("mac_address")
    action = data.get("action")

    if action not in {"reboot", "shutdown"} or not mac_address:
        write_audit_log("client_action", "failure", actor="dashboard", target=mac_address, details="Invalid parameters")
        return jsonify({"status": "failed", "reason": "Invalid parameters"}), 400

    client_ip = resolve_client_ip(mac_address)
    if not client_ip:
        write_audit_log("client_action", "failure", actor="dashboard", target=mac_address, details="Client IP not found")
        return jsonify({"status": "failed", "reason": "Client IP not found"}), 404

    token = login_to_probe(client_ip)
    if not token:
        write_audit_log("client_action", "failure", actor="dashboard", target=mac_address, details="Login to probe failed")
        return jsonify({"status": "failed", "reason": "Login to probe failed"}), 500

    verify = probe_verify_value()
    try:
        headers = {"Authorization": f"Bearer {token}"}
        url = f"{PROBE_SCHEME}://{client_ip}:{CLIENT_PORT}/{action}"
        response = requests.post(url, headers=headers, verify=verify, timeout=10)

        if response.status_code == 200:
            write_audit_log("client_action", "success", actor="dashboard", target=mac_address, details=action)
            return jsonify({"status": "success"}), 200

        write_audit_log("client_action", "failure", actor="dashboard", target=mac_address, details=f"Probe error {response.status_code}")
        return jsonify({"status": "failed", "reason": f"Probe error: {response.status_code}"}), 500
    except Exception as exc:
        write_audit_log("client_action", "failure", actor="dashboard", target=mac_address, details=str(exc))
        return jsonify({"status": "failed", "reason": f"Error: {str(exc)}"}), 500


@app.route("/update", methods=["POST"])
@token_required
def update_data():
    try:
        data = request.json
        if data is None:
            return jsonify({"status": "failed", "reason": "No JSON payload provided"}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
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
            """,
            (
                data["mac_address"],
                data["hostname"],
                data["local_ip_address"],
                data["public_ip_address"],
                data["platform"],
                data["cpu_usage"],
                data["memory_usage"],
                data["hdd_usage"]["total"],
                data["hdd_usage"]["used"],
                data["hdd_usage"]["free"],
                data["hdd_usage"]["percent"],
                json.dumps(data["running_processes"]),
                json.dumps(data["used_ports"]),
                data["last_reboot"],
                data["uptime"],
                json.dumps(data["current_users"]),
                data["disk_io"]["read_bytes"],
                data["disk_io"]["write_bytes"],
                data["network_io"]["bytes_sent"],
                data["network_io"]["bytes_recv"],
                data["last_updated"],
            ),
        )

        conn.commit()
        conn.close()

        socketio.emit("update_received")
        return jsonify({"status": "success"}), 200
    except sqlite3.DatabaseError as db_err:
        return jsonify({"status": "failed", "reason": f"Database error: {db_err}"}), 500
    except KeyError as key_err:
        return jsonify({"status": "failed", "reason": f"Missing key in data: {key_err}"}), 400
    except Exception as exc:
        return jsonify({"status": "failed", "reason": f"An unexpected error occurred: {exc}"}), 500


@app.route("/request-update", methods=["POST"])
@login_required
@rate_limit(RATE_LIMIT_MAX_REQUESTS)
def request_update():
    mac_address = (request.json or {}).get("mac_address")

    if not mac_address:
        write_audit_log("client_request_update", "failure", actor="dashboard", details="Invalid parameters")
        return jsonify({"status": "failed", "reason": "Invalid parameters"}), 400

    client_ip = resolve_client_ip(mac_address)
    if not client_ip:
        write_audit_log("client_request_update", "failure", actor="dashboard", target=mac_address, details="Client IP not found")
        return jsonify({"status": "failed", "reason": "Client IP not found"}), 404

    token = login_to_probe(client_ip)
    if not token:
        write_audit_log("client_request_update", "failure", actor="dashboard", target=mac_address, details="Login to probe failed")
        return jsonify({"status": "failed", "reason": "Login to probe failed"}), 500

    verify = probe_verify_value()
    try:
        url = f"{PROBE_SCHEME}://{client_ip}:{CLIENT_PORT}/trigger-update"
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.post(url, headers=headers, verify=verify, timeout=10)
        if response.status_code == 200:
            write_audit_log("client_request_update", "success", actor="dashboard", target=mac_address)
            return jsonify({"status": "update-requested"}), 200

        write_audit_log("client_request_update", "failure", actor="dashboard", target=mac_address, details=f"Probe error {response.status_code}")
        return jsonify({"status": "failed", "reason": "Command failed"}), 500
    except Exception as exc:
        logging.exception("Error requesting update: %s", exc)
        write_audit_log("client_request_update", "failure", actor="dashboard", target=mac_address, details=str(exc))
        return jsonify({"status": "failed", "reason": str(exc)}), 500


check_and_recreate_db()


if __name__ == "__main__":
    discovery_thread = threading.Thread(target=handle_discovery_requests, daemon=True)
    discovery_thread.start()

    debug_mode = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    cert_path = os.getenv("TLS_CERT_PATH", "cert.pem")
    key_path = os.getenv("TLS_KEY_PATH", "key.pem")

    ssl_context = None
    if Path(cert_path).exists() and Path(key_path).exists():
        ssl_context = (cert_path, key_path)
    else:
        logging.warning("TLS certificate/key not found. Starting server without TLS.")

    socketio.run(
        app,
        debug=debug_mode,
        host="0.0.0.0",
        port=SERVER_PORT,
        ssl_context=ssl_context,
        allow_unsafe_werkzeug=debug_mode,
    )
