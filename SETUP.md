# Network Topology Visualizer - Setup Guide

## Installation

### 1. Install system dependencies

```bash
# Debian/Ubuntu
sudo apt update
sudo apt install nmap arp-scan python3-pip python3-venv

# Fedora/RHEL
sudo dnf install nmap arp-scan python3-pip
```

### 2. Create Python virtual environment

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Python dependencies

```bash
pip install -r requirements.txt
```

Or install individually:

```bash
pip install fastapi uvicorn python-nmap scapy netifaces
```

## Permissions Setup

Network discovery requires elevated privileges. Choose one method:

### Option 1: Run with sudo (simplest)

```bash
sudo venv/bin/python -m uvicorn backend.main:app --reload
```

### Option 2: Grant capabilities (recommended for production)

```bash
# For system Python
sudo setcap cap_net_raw,cap_net_admin+eip $(which python3)

# For venv Python
sudo setcap cap_net_raw,cap_net_admin+eip $(pwd)/venv/bin/python3

# Then run normally
python -m uvicorn backend.main:app --reload
```

### Option 3: Run venv Python with sudo

```bash
sudo /absolute/path/to/venv/bin/python -m uvicorn backend.main:app --reload
```

## Running the Application

### Development Mode (separate frontend/backend)

1. **Start backend:**
   ```bash
   source venv/bin/activate
   sudo venv/bin/python -m uvicorn backend.main:app --reload
   ```
   Backend runs at: http://127.0.0.1:8000

2. **Start frontend (separate terminal):**
   ```bash
   cd frontend
   npm install
   npm run dev
   ```
   Frontend runs at: http://localhost:5173

### Production Mode (single uvicorn process)

1. **Build frontend:**
   ```bash
   cd frontend
   npm install
   npm run build
   ```

2. **Start backend:**
   ```bash
   source venv/bin/activate
   sudo venv/bin/python -m uvicorn backend.main:app --reload
   ```
   Visit: http://127.0.0.1:8000

## Testing Network Discovery

### Manual verification commands

1. **Check interface and subnet:**
   ```bash
   ip addr show
   ip route show default
   ```

2. **Test ARP discovery:**
   ```bash
   sudo arp-scan --local
   # Or with nmap:
   sudo nmap -sn 192.168.1.0/24
   ```

3. **Test port scanning:**
   ```bash
   sudo nmap -sV -p 1-1024 192.168.1.1
   ```

4. **Monitor ARP traffic:**
   ```bash
   sudo tcpdump -i eth0 arp
   ```

### What to look for

- **Multiple devices** in `arp-scan` output (not just router)
- **ARP requests/replies** in `tcpdump` output
- **Open ports** in `nmap` output for each device

## API Endpoints

- `GET /api/health` - Health check
- `GET /api/scan?force=false&debug=false` - Trigger network scan
  - `force=true`: Force fresh scan (ignore cache)
  - `debug=true`: Include raw ARP and nmap data in response

## Troubleshooting

### Only router detected

- Check if ARP discovery is working: `sudo arp-scan --local`
- Verify interface detection: Check logs for "Detected interface: ..."
- Ensure devices are on the same subnet
- Try increasing scan timeouts in `backend/main.py`

### MAC addresses missing or inconsistent

- Ensure running with proper privileges (sudo or capabilities)
- Check if nmap can see MACs: `sudo nmap -sn 192.168.1.0/24`
- Verify ARP discovery is finding devices

### Permission errors

- Ensure running with sudo or capabilities set
- Check `capsh --print` to verify capabilities
- Try: `sudo setcap cap_net_raw,cap_net_admin+eip $(which python3)`

### Frontend shows blank page

- Ensure frontend is built: `cd frontend && npm run build`
- Check that `frontend/dist/index.html` exists
- Verify backend is serving static files correctly

