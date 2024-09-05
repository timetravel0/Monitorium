# Monitorium
Lightweight, real-time system and network monitoring tool. It features a client-side probe that gathers system metrics and a server-side dashboard that displays the data in a clean, interactive interface. Designed to provide insights on CPU, memory, disk, and network usage, Monitorium helps you keep track of your local infrastructure health.

## Features

- Real-time monitoring of CPU, memory, disk, and network I/O.
- Automated discovery of server via network broadcast.
- Client-side control actions (reboot, shutdown).
- Interactive dashboard with real-time updates.
- Detailed process and port information.
- Customizable update intervals.
- Built with Flask, Socket.IO, and SQLite.

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
python probe.py
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
