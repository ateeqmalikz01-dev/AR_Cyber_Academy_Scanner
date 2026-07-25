"""
AR Cyber Academy Scanner - Nmap Wrapper Module
Developer: Ateeq ur Rehman

Wraps the python-nmap library to provide various network scanning capabilities.
Each scan method maps to specific Nmap flags and parses results into structured data.

Scan Type Mapping Reference:
    - Ping scan / Host discovery     -> -sn
    - TCP SYN scan                   -> -sS   (requires root/admin)
    - TCP Connect scan               -> -sT
    - UDP scan                       -> -sU
    - Fast scan                       -> -F
    - Service/version detection       -> -sV
    - OS detection                    -> -O
    - Aggressive scan                 -> -A  (-sV -O -sC --traceroute)
    - NSE default scripts            -> -sC
    - Vulnerability scripts          -> --script=vuln
    - All ports scan                  -> -p-
    - Custom port range               -> -p <range>
    - Firewall/IDS evasion           -> -f (fragment), -D RND:10 (decoy)
    - Timing template                 -> -T0 through -T5
    - Idle scan                       -> -sI <zombie>
    - ACK scan                        -> -sA
    - Null scan                       -> -sN
    - FIN scan                        -> -sF
    - Xmas scan                       -> -sX
    - Traceroute                      -> --traceroute
    - No-ping scan                    -> -Pn
"""

import nmap
import threading
import time
import json
import csv
import io
import re
from datetime import datetime
from typing import Optional, Callable


class ScanResult:
    """Holds structured results from a single scan run."""

    def __init__(self):
        self.raw_output: str = ""
        self.hosts: list[dict] = []
        self.total_ports_scanned: int = 0
        self.open_ports: int = 0
        self.closed_ports: int = 0
        self.filtered_ports: int = 0
        self.scan_duration: float = 0.0
        self.scan_type: str = ""
        self.target: str = ""
        self.nmap_command: str = ""
        self.timestamp: str = ""
        self.errors: list[str] = []

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "scan_type": self.scan_type,
            "nmap_command": self.nmap_command,
            "timestamp": self.timestamp,
            "scan_duration_seconds": round(self.scan_duration, 2),
            "total_ports_scanned": self.total_ports_scanned,
            "open_ports": self.open_ports,
            "closed_ports": self.closed_ports,
            "filtered_ports": self.filtered_ports,
            "hosts": self.hosts,
            "errors": self.errors,
            "raw_output": self.raw_output,
        }


class NmapScanner:
    """
    Thread-safe Nmap scanner wrapper.
    Scans run in a background thread; results are delivered via callbacks.
    """

    # Valid scan presets: display name -> nmap arguments
    SCAN_PRESETS: dict[str, str] = {
        "Ping / Host Discovery": "-sn",
        "TCP SYN Scan": "-sS",
        "TCP Connect Scan": "-sT",
        "UDP Scan": "-sU",
        "Fast Scan": "-F",
        "All Ports Scan": "-p-",
        "Service Detection": "-sV",
        "OS Detection": "-O",
        "Aggressive Scan": "-A",
        "NSE Default Scripts": "-sC",
        "Vulnerability Scan": "--script=vuln",
        "ACK Scan": "-sA",
        "Null Scan": "-sN",
        "FIN Scan": "-sF",
        "Xmas Scan": "-sX",
        "Traceroute": "--traceroute",
        "No-Ping Scan": "-Pn",
    }

    TIMING_TEMPLATES = {
        "T0 - Paranoid": "-T0",
        "T1 - Sneaky": "-T1",
        "T2 - Polite": "-T2",
        "T3 - Normal (Default)": "-T3",
        "T4 - Aggressive": "-T4",
        "T5 - Insane": "-T5",
    }

    def __init__(self):
        self._nm: Optional[nmap.PortScanner] = None
        self._scan_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._is_scanning = False

        self._on_output: Optional[Callable[[str], None]] = None
        self._on_progress: Optional[Callable[[float], None]] = None
        self._on_status: Optional[Callable[[str], None]] = None
        self._on_complete: Optional[Callable[[ScanResult], None]] = None
        self._on_error: Optional[Callable[[str], None]] = None

    def _init_nmap(self) -> bool:
        """Lazy-initialize the PortScanner. Returns True if nmap is available."""
        try:
            if self._nm is None:
                self._nm = nmap.PortScanner()
            return True
        except nmap.PortScannerError:
            return False
        except Exception:
            return False

    @property
    def is_scanning(self) -> bool:
        with self._lock:
            return self._is_scanning

    def stop(self):
        """Request the current scan to stop."""
        self._stop_event.set()

    def start_scan(
        self,
        target: str,
        arguments: str,
        scan_label: str = "Custom",
        on_output: Optional[Callable[[str], None]] = None,
        on_progress: Optional[Callable[[float], None]] = None,
        on_status: Optional[Callable[[str], None]] = None,
        on_complete: Optional[Callable[[ScanResult], None]] = None,
        on_error: Optional[Callable[[str], None]] = None,
    ):
        """
        Launch a scan in a background thread.

        Args:
            target: IP, hostname, or CIDR range to scan.
            arguments: Raw nmap CLI arguments string.
            scan_label: Human-readable name for the scan type.
            on_output: Callback for raw text output lines.
            on_progress: Callback with progress float 0-1.
            on_status: Callback for status text updates.
            on_complete: Callback with ScanResult when finished.
            on_error: Callback for error messages.
        """
        if self.is_scanning:
            on_error and on_error("A scan is already in progress. Stop it first.")
            return

        self._on_output = on_output
        self._on_progress = on_progress
        self._on_status = on_status
        self._on_complete = on_complete
        self._on_error = on_error
        self._stop_event.clear()

        self._scan_thread = threading.Thread(
            target=self._run_scan,
            args=(target, arguments, scan_label),
            daemon=True,
        )
        self._scan_thread.start()

    def _emit(self, callback, msg: str):
        """Safely invoke a callback if set."""
        if callback:
            try:
                callback(msg)
            except Exception:
                pass

    def _run_scan(self, target: str, arguments: str, scan_label: str):
        """Background worker that executes the nmap scan."""
        with self._lock:
            self._is_scanning = True

        result = ScanResult()
        result.target = target
        result.scan_type = scan_label
        result.timestamp = datetime.now().isoformat()
        start_time = time.time()

        self._emit(self._on_status, f"Initializing nmap for target: {target}")
        self._emit(self._on_progress, 0.0)

        if not self._init_nmap():
            self._emit(self._on_error, "Nmap is not installed or not found in PATH.")
            result.errors.append("Nmap not found")
            self._emit(self._on_complete, result)
            with self._lock:
                self._is_scanning = False
            return

        nmap_cmd = f"nmap {arguments} {target}"
        result.nmap_command = nmap_cmd
        self._emit(self._on_output, f"[CMD] {nmap_cmd}")
        self._emit(self._on_status, f"Running: {nmap_cmd}")

        try:
            # python-nmap does not natively support stop, but we run in a thread
            # and can check _stop_event periodically via the scan method.
            self._nm.scan(hosts=target, arguments=arguments)

            if self._stop_event.is_set():
                result.errors.append("Scan was stopped by user.")
                self._emit(self._on_status, "Scan stopped by user.")
                self._emit(self._on_complete, result)
                with self._lock:
                    self._is_scanning = False
                return

            self._emit(self._on_progress, 0.8)
            self._emit(self._on_status, "Parsing results...")

            # Build raw output string
            result.raw_output = self._nm.csv()

            # Parse structured results
            self._parse_results(self._nm, result)

        except nmap.PortScannerError as e:
            msg = f"Nmap error: {e}"
            result.errors.append(msg)
            self._emit(self._on_error, msg)
        except PermissionError as e:
            msg = f"Permission denied. Some scans (e.g. SYN -sS) require admin/root privileges. Error: {e}"
            result.errors.append(msg)
            self._emit(self._on_error, msg)
        except Exception as e:
            msg = f"Unexpected error: {e}"
            result.errors.append(msg)
            self._emit(self._on_error, msg)

        result.scan_duration = time.time() - start_time
        self._emit(self._on_progress, 1.0)
        self._emit(self._on_status, f"Scan complete in {result.scan_duration:.1f}s")
        self._emit(self._on_complete, result)

        with self._lock:
            self._is_scanning = False

    def _parse_results(self, nm: nmap.PortScanner, result: ScanResult):
        """Extract structured host/port data from the nmap result object."""
        hosts_list = []

        for host in nm.all_hosts():
            host_data = {
                "hostname": nm[host].hostname() if nm[host].hostname() else host,
                "ip": host,
                "state": nm[host].state(),
                "protocols": [],
            }

            for proto in nm[host].all_protocols():
                ports_data = []
                port_list = nm[host][proto].keys()

                for port in sorted(port_list):
                    port_info = nm[host][proto][port]
                    state = port_info.get("state", "unknown")
                    service = port_info.get("name", "")
                    version = port_info.get("version", "")
                    product = port_info.get("product", "")
                    extra = port_info.get("extrainfo", "")
                    cpe = port_info.get("cpe", "")

                    version_str = f"{product} {version}".strip()
                    if extra:
                        version_str = f"{version_str} ({extra})" if version_str else extra

                    result.total_ports_scanned += 1
                    if state == "open":
                        result.open_ports += 1
                    elif state == "closed":
                        result.closed_ports += 1
                    elif state == "filtered":
                        result.filtered_ports += 1

                    port_entry = {
                        "port": port,
                        "protocol": proto,
                        "state": state,
                        "service": service,
                        "version": version_str.strip(),
                        "cpe": cpe,
                    }
                    ports_data.append(port_entry)

                host_data["protocols"].append(
                    {"protocol": proto, "ports": ports_data}
                )

            hosts_list.append(host_data)

        result.hosts = hosts_list

    @staticmethod
    def export_json(result: ScanResult, filepath: str):
        """Export scan results to a JSON file."""
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(result.to_dict(), f, indent=2, default=str)

    @staticmethod
    def export_csv(result: ScanResult, filepath: str):
        """Export scan results to a CSV file."""
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(
                ["Host", "IP", "Port", "Protocol", "State", "Service", "Version", "CPE"]
            )
            for host in result.hosts:
                for proto_data in host["protocols"]:
                    for port in proto_data["ports"]:
                        writer.writerow(
                            [
                                host["hostname"],
                                host["ip"],
                                port["port"],
                                port["protocol"],
                                port["state"],
                                port["service"],
                                port["version"],
                                port["cpe"],
                            ]
                        )

    @staticmethod
    def export_txt(result: ScanResult, filepath: str):
        """Export scan results to a plain text file."""
        lines = []
        lines.append("=" * 70)
        lines.append("AR Academy Scanner - Scan Report")
        lines.append(f"Developer: Ateeq ur Rehman")
        lines.append("=" * 70)
        lines.append(f"Target:       {result.target}")
        lines.append(f"Scan Type:    {result.scan_type}")
        lines.append(f"Command:      {result.nmap_command}")
        lines.append(f"Timestamp:    {result.timestamp}")
        lines.append(f"Duration:     {result.scan_duration:.2f}s")
        lines.append(f"Total Ports:  {result.total_ports_scanned}")
        lines.append(f"Open:         {result.open_ports}")
        lines.append(f"Closed:       {result.closed_ports}")
        lines.append(f"Filtered:     {result.filtered_ports}")
        lines.append("-" * 70)

        for host in result.hosts:
            lines.append(f"\nHost: {host['hostname']} ({host['ip']}) - {host['state']}")
            for proto_data in host["protocols"]:
                lines.append(f"  Protocol: {proto_data['protocol']}")
                for port in proto_data["ports"]:
                    lines.append(
                        f"    {port['port']}/{port['protocol']}  "
                        f"{port['state']:10s}  {port['service']:15s}  {port['version']}"
                    )

        if result.errors:
            lines.append("\nErrors:")
            for err in result.errors:
                lines.append(f"  - {err}")

        lines.append("\n" + "=" * 70)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

    @staticmethod
    def validate_target(target: str) -> tuple[bool, str]:
        """
        Basic validation for IP / hostname / CIDR.
        Returns (is_valid, message).
        """
        target = target.strip()
        if not target:
            return False, "Target cannot be empty."

        # CIDR notation  (e.g. 192.168.1.0/24)
        cidr_pattern = re.compile(
            r"^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$"
        )
        ip_pattern = re.compile(
            r"^(\d{1,3}\.){3}\d{1,3}$"
        )
        hostname_pattern = re.compile(
            r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$"
        )

        # Allow nmap-style ranges like 192.168.1.1-100
        range_pattern = re.compile(
            r"^(\d{1,3}\.){3}\d{1,3}-\d{1,3}$"
        )

        if cidr_pattern.match(target):
            return True, "Valid CIDR range."
        if ip_pattern.match(target):
            octets = target.split(".")
            for o in octets:
                if int(o) > 255:
                    return False, f"Invalid IP octet: {o}"
            return True, "Valid IP address."
        if range_pattern.match(target):
            return True, "Valid IP range."
        if hostname_pattern.match(target):
            return True, "Valid hostname."
        if target.startswith("localhost") or target == "127.0.0.1":
            return True, "Loopback target (local machine)."

        return False, "Invalid target format. Use IP, hostname, or CIDR range."
