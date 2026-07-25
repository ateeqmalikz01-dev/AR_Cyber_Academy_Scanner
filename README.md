# AR Academy Scanner

A modern network scanning GUI built with Python and CustomTkinter, wrapping Nmap for powerful network reconnaissance.

**Developer:** Ateeq ur Rehman

## Features

- 17+ scan types (SYN, Connect, UDP, Aggressive, Vulnerability, etc.)
- Real-time scan output
- Results table with host, port, protocol, state, service, and version
- Statistics dashboard (open/closed/filtered ports, scan duration)
- Export results to JSON, CSV, or TXT
- Custom Nmap arguments support
- Dark-themed modern UI

## Prerequisites

- **Python 3.10+**
- **Nmap** installed and available in your system PATH
- **pip** (Python package manager)

### Install Nmap

#### Windows
Download and install from: https://nmap.org/download.html

During installation, make sure to check **"Add Nmap to the system PATH"**.

Verify installation:
```cmd
nmap --version
```

#### Linux (Debian/Ubuntu)
```bash
sudo apt update
sudo apt install nmap
```

#### Linux (Fedora/RHEL)
```bash
sudo dnf install nmap
```

#### Linux (Arch)
```bash
sudo pacman -S nmap
```

Verify installation:
```bash
nmap --version
```

---

## Setup & Installation

### Linux

```bash
# Clone the repository
git clone https://github.com/<your-username>/AR_Academy.git
cd AR_Academy

# Create a virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r AR_Academy_Scanner/requirements.txt

# Run the application (some scans require root)
sudo python3 AR_Academy_Scanner/main.py
```

### Windows

```cmd
:: Clone the repository
git clone https://github.com/<your-username>/AR_Academy.git
cd AR_Academy

:: Create a virtual environment (recommended)
python -m venv venv
venv\Scripts\activate

:: Install dependencies
pip install -r AR_Academy_Scanner\requirements.txt

:: Run the application (some scans require admin)
python AR_Academy_Scanner\main.py
```

> **Note:** Run as Administrator / root for SYN scan (`-sS`) and OS detection (`-O`).

---

## Usage

1. Launch the application
2. Accept the legal disclaimer
3. Enter a target (IP address, hostname, or CIDR range like `192.168.1.0/24`)
4. Select a scan type from the dropdown
5. Configure timing, port range, and extra options as needed
6. Click **Start Scan**
7. View results in the **Results** and **Statistics** tabs
8. Export results using the **Export** button (JSON, CSV, or TXT)

## Scan Types

| Scan Type | Description |
|---|---|
| Ping / Host Discovery | `-sn` - Discover live hosts |
| TCP SYN Scan | `-sS` - Stealth scan (requires root/admin) |
| TCP Connect Scan | `-sT` - Full TCP connection |
| UDP Scan | `-sU` - Scan UDP ports |
| Fast Scan | `-F` - Quick scan of common ports |
| All Ports Scan | `-p-` - Scan all 65535 ports |
| Service Detection | `-sV` - Detect service versions |
| OS Detection | `-O` - Detect operating system |
| Aggressive Scan | `-A` - OS + version + scripts + traceroute |
| Vulnerability Scan | `--script=vuln` - Run NSE vulnerability scripts |

## Legal Disclaimer

This tool is for **authorized security testing and educational purposes only**. Only scan networks you own or have explicit written permission to test. Unauthorized scanning is illegal.

## License

For educational use only.
