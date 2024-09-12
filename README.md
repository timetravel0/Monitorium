# Monitorium
Lightweight, real-time system and network monitoring tool. It features a client-side probe that gathers system metrics and a server-side dashboard that displays the data in a clean, interactive interface. Designed to provide insights on CPU, memory, disk, and network usage, Monitorium helps you keep track of your local infrastructure health.

- Real-time Monitoring: Continuous monitoring of CPU, memory, disk usage, and network I/O, providing real-time metrics for connected clients.
- Automated Server Discovery: Clients automatically discover the server via network broadcast, simplifying the setup process.
- Client-Side Control Actions: The server can issue client-side control actions such as reboot and shutdown, securely authenticated with JWT tokens.
- Interactive Dashboard: A web-based dashboard provides real-time updates on client status, including process and port information.
- Detailed Process and Port Monitoring: Clients send detailed lists of running processes and active network ports to the server for centralized monitoring.
- Customizable Update Intervals: Update intervals for monitoring data can be customized dynamically based on system load or administrator preferences.
- Automated Client Updates: Clients automatically update to the latest version when a new probe version is available on the server.
- Built with Flask, Socket.IO, and SQLite: The system uses Flask for the backend, Socket.IO for real-time communication, and SQLite for lightweight data storage.
- JWT-Based Authentication: Secure authentication using JWT tokens between the server and clients ensures only authenticated actions (such as reboot or shutdown) are allowed.
- Server-to-Client Handshake: Before any action (like reboot) is performed, the server securely logs into the client to obtain a JWT token, ensuring authenticated requests.
- Token Validation on Clients: Clients validate incoming requests from the server by verifying JWT tokens, ensuring actions are performed only by trusted servers.
- SSL/TLS Support: Secure communication between server and clients is supported using SSL/TLS to prevent man-in-the-middle attacks during data transfer.
- Environment-Based Credential Management: Server and client login credentials are securely managed using environment variables, reducing the risk of hardcoded secrets.

## Getting Started

### Prerequisites

Ensure you have the following dependencies installed:

- Python 3.x
- Flask
- psutil
- getmac
- requests
- Flask-SocketIO
- SQLite3

## Installation

### Clone the repository:

git clone https://github.com/timetravel0/Monitorium.git
cd monitorium

### Run the server:

```bash
python app.py
```

This will start the Flask server for the dashboard.

### Run the client probe:

On the target machine you want to monitor, run:

```bash
python launcher.py
```

The client will discover the server automatically and begin sending system metrics.

## Usage

- **Dashboard:** Navigate to `http://localhost:8080` to view the dashboard.
- **Client Actions:** You can initiate reboots or shutdowns of client machines directly from the dashboard.

## Configuration

You can customize the update interval and discovery settings by modifying the `probe.py` file:

```python
# Modify the probe interval (default is 5 minutes)
time.sleep(300)  # 300 seconds = 5 minutes
```

## Troubleshooting

- If the server discovery fails, make sure both the client and server are on the same network.
- Ensure no firewall is blocking communication on ports 5001 (client) and 8080 (server).
