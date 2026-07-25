"""
AR_Cyber_Academy Scanner - Main GUI Entry Point
Developer: Ateeq ur Rehman

Advanced network scanning GUI built with customtkinter.
Provides a modern dark-themed interface for performing various
Nmap scans with real-time output, statistics, and result export.

Legal Notice: This tool is for authorized security testing and
educational purposes only. Only scan networks you own or have
explicit permission to test.
"""

import customtkinter as ctk
import tkinter as tk
from tkinter import messagebox, filedialog
from tkinter import ttk
import threading
import time
import os
import sys
from datetime import datetime

from scanner import NmapScanner, ScanResult

# ---------------------------------------------------------------------------
# Theme configuration
# ---------------------------------------------------------------------------
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# Colour palette
CLR_BG = "#1a1a2e"
CLR_PANEL = "#16213e"
CLR_ACCENT = "#0f3460"
CLR_HIGHLIGHT = "#e94560"
CLR_TEXT = "#eaeaea"
CLR_TEXT_DIM = "#8892b0"
CLR_GREEN = "#00e676"
CLR_RED = "#ff5252"
CLR_YELLOW = "#ffd740"
CLR_BLUE = "#448aff"

FONT_TITLE = ("Segoe UI", 20, "bold")
FONT_HEADER = ("Segoe UI", 14, "bold")
FONT_BODY = ("Segoe UI", 12)
FONT_BODY_BOLD = ("Segoe UI", 12, "bold")
FONT_SMALL = ("Segoe UI", 10)
FONT_MONO = ("Consolas", 11)
FONT_MONO_SMALL = ("Consolas", 9)


# ---------------------------------------------------------------------------
# Disclaimer Dialog
# ---------------------------------------------------------------------------
class DisclaimerDialog(ctk.CTkToplevel):
    """Modal disclaimer / legal notice shown on first launch."""

    def __init__(self, parent):
        super().__init__(parent)
        self.result = False
        self.title("AR Academy Scanner - Legal Notice")
        self.geometry("560x420")
        self.resizable(False, False)
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.grab_set()

        # Centre on parent
        self.update_idletasks()
        px = parent.winfo_x() + (parent.winfo_width() - 560) // 2
        py = parent.winfo_y() + (parent.winfo_height() - 420) // 2
        self.geometry(f"+{px}+{py}")

        self.configure(fg_color=CLR_BG)

        ctk.CTkLabel(
            self,
            text="AR Academy Scanner",
            font=FONT_TITLE,
            text_color=CLR_HIGHLIGHT,
        ).pack(pady=(24, 4))

        ctk.CTkLabel(
            self,
            text="Developer: Ateeq ur Rehman",
            font=FONT_BODY,
            text_color=CLR_TEXT_DIM,
        ).pack(pady=(0, 16))

        disclaimer_text = (
            "DISCLAIMER / LEGAL NOTICE\n\n"
            "This software is provided strictly for AUTHORIZED security "
            "testing and educational/learning purposes.\n\n"
            "By using this tool you agree that:\n\n"
            "1. You will ONLY scan networks, hosts, and systems that you "
            "OWN or have EXPLICIT WRITTEN PERMISSION to test.\n\n"
            "2. Unauthorized scanning of networks or systems you do not "
            "own or lack permission for is ILLEGAL and may violate "
            "computer fraud and abuse laws.\n\n"
            "3. The developers of this tool accept NO LIABILITY for misuse "
            "or damage caused by improper use.\n\n"
            "4. You are solely responsible for ensuring compliance with "
            "all applicable local, state, national, and international laws.\n\n"
            "5. Some scans (SYN, OS detection) may require administrator / "
            "root privileges."
        )

        text_box = ctk.CTkTextbox(
            self,
            width=500,
            height=260,
            font=FONT_SMALL,
            fg_color=CLR_PANEL,
            text_color=CLR_TEXT,
            border_width=1,
            border_color=CLR_ACCENT,
            corner_radius=6,
            wrap="word",
        )
        text_box.insert("1.0", disclaimer_text)
        text_box.configure(state="disabled")
        text_box.pack(padx=28, pady=(0, 16))

        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.pack(pady=(0, 20))

        ctk.CTkButton(
            btn_frame,
            text="I Understand - Proceed",
            width=200,
            height=36,
            font=FONT_BODY_BOLD,
            fg_color=CLR_GREEN,
            hover_color="#00c864",
            text_color="#000000",
            command=self._on_accept,
        ).pack(side="left", padx=8)

        ctk.CTkButton(
            btn_frame,
            text="Exit",
            width=120,
            height=36,
            font=FONT_BODY,
            fg_color=CLR_RED,
            hover_color="#d32f2f",
            command=self._on_close,
        ).pack(side="left", padx=8)

    def _on_accept(self):
        self.result = True
        self.grab_release()
        self.destroy()

    def _on_close(self):
        self.result = False
        self.grab_release()
        self.destroy()


# ---------------------------------------------------------------------------
# Settings Dialog
# ---------------------------------------------------------------------------
class SettingsDialog(ctk.CTkToplevel):
    """Advanced settings: custom nmap arguments, extra flags."""

    def __init__(self, parent, current_args: str = ""):
        super().__init__(parent)
        self.result_args = None
        self.title("Settings - Custom Nmap Arguments")
        self.geometry("540x340")
        self.resizable(False, False)
        self.grab_set()
        self.configure(fg_color=CLR_BG)

        self.update_idletasks()
        px = parent.winfo_x() + (parent.winfo_width() - 540) // 2
        py = parent.winfo_y() + (parent.winfo_height() - 340) // 2
        self.geometry(f"+{px}+{py}")

        ctk.CTkLabel(
            self, text="Advanced: Custom Nmap Arguments",
            font=FONT_HEADER, text_color=CLR_HIGHLIGHT,
        ).pack(pady=(20, 4))

        ctk.CTkLabel(
            self,
            text=(
                "Enter raw nmap flags below. These will be appended to the\n"
                "command after any preset arguments. Use with caution."
            ),
            font=FONT_SMALL,
            text_color=CLR_TEXT_DIM,
        ).pack(pady=(0, 10))

        self.entry = ctk.CTkTextbox(
            self,
            width=480,
            height=120,
            font=FONT_MONO,
            fg_color=CLR_PANEL,
            text_color=CLR_GREEN,
            border_width=1,
            border_color=CLR_ACCENT,
            corner_radius=6,
        )
        self.entry.pack(padx=28)
        self.entry.insert("1.0", current_args)

        hint = (
            "Examples:\n"
            "  --top-ports 100          Scan top 100 most common ports\n"
            "  -p 80,443,8080           Scan specific ports\n"
            "  --script=vuln            Run vulnerability NSE scripts\n"
            "  -f -D RND:10             Fragment packets with decoys\n"
            "  -T4 --min-rate 1000      Fast timing with minimum packet rate"
        )
        ctk.CTkLabel(
            self, text=hint, font=FONT_MONO_SMALL,
            text_color=CLR_TEXT_DIM, justify="left",
        ).pack(padx=28, pady=(8, 16), anchor="w")

        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.pack(pady=(0, 16))

        ctk.CTkButton(
            btn_frame, text="Apply", width=120, height=32,
            font=FONT_BODY_BOLD, fg_color=CLR_GREEN, hover_color="#00c864",
            text_color="#000000", command=self._on_apply,
        ).pack(side="left", padx=8)

        ctk.CTkButton(
            btn_frame, text="Cancel", width=100, height=32,
            font=FONT_BODY, fg_color=CLR_RED, hover_color="#d32f2f",
            command=self._on_cancel,
        ).pack(side="left", padx=8)

    def _on_apply(self):
        self.result_args = self.entry.get("1.0", "end").strip()
        self.grab_release()
        self.destroy()

    def _on_cancel(self):
        self.result_args = None
        self.grab_release()
        self.destroy()


# ---------------------------------------------------------------------------
# Main Application
# ---------------------------------------------------------------------------
class ARScannerApp(ctk.CTk):
    """Main application window."""

    def __init__(self):
        super().__init__()

        self.title("AR Academy Scanner")
        self.geometry("1280x820")
        self.minsize(1100, 700)
        self.configure(fg_color=CLR_BG)

        self.scanner = NmapScanner()
        self.scan_result: ScanResult | None = None
        self._timer_running = False
        self._elapsed_seconds = 0.0
        self._timer_job = None

        # Build UI
        self._build_sidebar()
        self._build_main_area()
        self._build_status_bar()

        # Show disclaimer on start
        self.after(200, self._show_disclaimer)

    # ------------------------------------------------------------------
    # Disclaimer
    # ------------------------------------------------------------------
    def _show_disclaimer(self):
        dlg = DisclaimerDialog(self)
        self.wait_window(dlg)
        if not dlg.result:
            self.destroy()
            sys.exit(0)

    # ------------------------------------------------------------------
    # Scan Type Change Handler
    # ------------------------------------------------------------------
    def _on_scan_type_change(self, choice: str):
        """Called when the user selects a different scan type preset."""
        self._set_status(f"Scan type: {choice}")

    # ------------------------------------------------------------------
    # Sidebar
    # ------------------------------------------------------------------
    def _build_sidebar(self):
        self.sidebar = ctk.CTkFrame(
            self, width=260, fg_color=CLR_PANEL, corner_radius=0,
        )
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        # Logo / Title
        ctk.CTkLabel(
            self.sidebar, text="AR Academy",
            font=FONT_TITLE, text_color=CLR_HIGHLIGHT,
        ).pack(pady=(24, 2))
        ctk.CTkLabel(
            self.sidebar, text="Scanner",
            font=("Segoe UI", 16, "bold"), text_color=CLR_TEXT,
        ).pack(pady=(0, 4))
        ctk.CTkLabel(
            self.sidebar, text="Developer: Ateeq ur Rehman",
            font=FONT_SMALL, text_color=CLR_TEXT_DIM,
        ).pack(pady=(0, 20))

        sep = ctk.CTkFrame(self.sidebar, height=2, fg_color=CLR_ACCENT)
        sep.pack(fill="x", padx=16, pady=(0, 12))

        # Scan Type Selection
        ctk.CTkLabel(
            self.sidebar, text="Scan Type",
            font=FONT_BODY_BOLD, text_color=CLR_BLUE,
        ).pack(anchor="w", padx=16, pady=(8, 2))

        self.scan_type_var = ctk.StringVar(value="TCP SYN Scan")
        scan_types = list(NmapScanner.SCAN_PRESETS.keys())

        self.scan_type_menu = ctk.CTkOptionMenu(
            self.sidebar,
            variable=self.scan_type_var,
            values=scan_types,
            width=228,
            height=32,
            font=FONT_SMALL,
            fg_color=CLR_ACCENT,
            button_color=CLR_HIGHLIGHT,
            button_hover_color="#c73550",
            dropdown_fg_color=CLR_PANEL,
            dropdown_hover_color=CLR_ACCENT,
            command=self._on_scan_type_change,
        )
        self.scan_type_menu.pack(padx=16, pady=(0, 8))

        # Timing Template
        ctk.CTkLabel(
            self.sidebar, text="Timing Template",
            font=FONT_BODY_BOLD, text_color=CLR_BLUE,
        ).pack(anchor="w", padx=16, pady=(8, 2))

        self.timing_var = ctk.StringVar(value="T3 - Normal (Default)")
        timing_opts = list(NmapScanner.TIMING_TEMPLATES.keys())

        self.timing_menu = ctk.CTkOptionMenu(
            self.sidebar,
            variable=self.timing_var,
            values=timing_opts,
            width=228,
            height=32,
            font=FONT_SMALL,
            fg_color=CLR_ACCENT,
            button_color=CLR_HIGHLIGHT,
            button_hover_color="#c73550",
            dropdown_fg_color=CLR_PANEL,
            dropdown_hover_color=CLR_ACCENT,
        )
        self.timing_menu.pack(padx=16, pady=(0, 8))

        # Port range
        ctk.CTkLabel(
            self.sidebar, text="Port Range (optional)",
            font=FONT_BODY_BOLD, text_color=CLR_BLUE,
        ).pack(anchor="w", padx=16, pady=(8, 2))

        self.port_entry = ctk.CTkEntry(
            self.sidebar,
            placeholder_text="e.g. 1-1000, 80,443 or leave blank",
            width=228,
            height=30,
            font=FONT_SMALL,
            fg_color=CLR_BG,
            border_color=CLR_ACCENT,
            text_color=CLR_TEXT,
        )
        self.port_entry.pack(padx=16, pady=(0, 8))

        # Checkboxes for extra flags
        ctk.CTkLabel(
            self.sidebar, text="Extra Options",
            font=FONT_BODY_BOLD, text_color=CLR_BLUE,
        ).pack(anchor="w", padx=16, pady=(8, 2))

        self.sv_var = ctk.BooleanVar(value=False)
        self.os_var = ctk.BooleanVar(value=False)
        self.traceroute_var = ctk.BooleanVar(value=False)
        self.pn_var = ctk.BooleanVar(value=False)
        self.scripts_var = ctk.BooleanVar(value=False)

        checkbox_style = {
            "font": FONT_SMALL,
            "text_color": CLR_TEXT,
            "fg_color": CLR_ACCENT,
            "hover_color": CLR_HIGHLIGHT,
            "checkmark_color": CLR_GREEN,
        }

        ctk.CTkCheckBox(
            self.sidebar, text="Service Detection (-sV)",
            variable=self.sv_var, **checkbox_style,
        ).pack(anchor="w", padx=20, pady=1)

        ctk.CTkCheckBox(
            self.sidebar, text="OS Detection (-O)",
            variable=self.os_var, **checkbox_style,
        ).pack(anchor="w", padx=20, pady=1)

        ctk.CTkCheckBox(
            self.sidebar, text="Traceroute",
            variable=self.traceroute_var, **checkbox_style,
        ).pack(anchor="w", padx=20, pady=1)

        ctk.CTkCheckBox(
            self.sidebar, text="No Ping (-Pn)",
            variable=self.pn_var, **checkbox_style,
        ).pack(anchor="w", padx=20, pady=1)

        ctk.CTkCheckBox(
            self.sidebar, text="NSE Scripts (-sC)",
            variable=self.scripts_var, **checkbox_style,
        ).pack(anchor="w", padx=20, pady=1)

        # Spacer
        ctk.CTkFrame(self.sidebar, fg_color="transparent", height=8).pack()

        # Custom arguments button
        self.custom_args: str = ""

        ctk.CTkButton(
            self.sidebar,
            text="Custom Arguments...",
            width=228,
            height=30,
            font=FONT_SMALL,
            fg_color=CLR_ACCENT,
            hover_color=CLR_HIGHLIGHT,
            border_width=1,
            border_color=CLR_BLUE,
            command=self._open_settings,
        ).pack(padx=16, pady=(0, 16))

        # Separator
        sep2 = ctk.CTkFrame(self.sidebar, height=2, fg_color=CLR_ACCENT)
        sep2.pack(fill="x", padx=16, pady=(0, 12))

        # Bottom branding
        ctk.CTkLabel(
            self.sidebar,
            text="For authorized testing only.\nUse responsibly.",
            font=FONT_MONO_SMALL,
            text_color=CLR_YELLOW,
            justify="center",
        ).pack(side="bottom", pady=(0, 12))

    # ------------------------------------------------------------------
    # Main Content Area
    # ------------------------------------------------------------------
    def _build_main_area(self):
        self.main = ctk.CTkFrame(self, fg_color="transparent", corner_radius=0)
        self.main.pack(side="left", fill="both", expand=True)

        # --- Top Bar: Target input + buttons ---
        topbar = ctk.CTkFrame(self.main, fg_color=CLR_PANEL, corner_radius=0, height=64)
        topbar.pack(fill="x")
        topbar.pack_propagate(False)

        ctk.CTkLabel(
            topbar, text="Target:",
            font=FONT_BODY_BOLD, text_color=CLR_BLUE,
        ).pack(side="left", padx=(16, 6), pady=16)

        self.target_entry = ctk.CTkEntry(
            topbar,
            placeholder_text="IP address, hostname, or CIDR range (e.g. 192.168.1.0/24)",
            width=420,
            height=34,
            font=FONT_BODY,
            fg_color=CLR_BG,
            border_color=CLR_ACCENT,
            text_color=CLR_TEXT,
        )
        self.target_entry.pack(side="left", padx=(0, 12), pady=16)
        self.target_entry.bind("<Return>", lambda e: self._start_scan())

        # Start button
        self.start_btn = ctk.CTkButton(
            topbar,
            text="Start Scan",
            width=130,
            height=34,
            font=FONT_BODY_BOLD,
            fg_color=CLR_GREEN,
            hover_color="#00c864",
            text_color="#000000",
            command=self._start_scan,
        )
        self.start_btn.pack(side="left", padx=(0, 8), pady=16)

        # Stop button
        self.stop_btn = ctk.CTkButton(
            topbar,
            text="Stop",
            width=80,
            height=34,
            font=FONT_BODY,
            fg_color=CLR_RED,
            hover_color="#d32f2f",
            command=self._stop_scan,
            state="disabled",
        )
        self.stop_btn.pack(side="left", padx=(0, 8), pady=16)

        # Timer label
        self.timer_label = ctk.CTkLabel(
            topbar,
            text="00:00",
            font=("Consolas", 16, "bold"),
            text_color=CLR_YELLOW,
            width=80,
        )
        self.timer_label.pack(side="left", padx=(16, 0), pady=16)

        # Export button
        self.export_btn = ctk.CTkButton(
            topbar,
            text="Export",
            width=90,
            height=34,
            font=FONT_BODY,
            fg_color=CLR_ACCENT,
            hover_color=CLR_HIGHLIGHT,
            border_width=1,
            border_color=CLR_BLUE,
            command=self._export_results,
            state="disabled",
        )
        self.export_btn.pack(side="right", padx=16, pady=16)

        # --- Notebook-like area using tabs ---
        self.tabview = ctk.CTkTabview(
            self.main,
            fg_color=CLR_BG,
            segmented_button_fg_color=CLR_PANEL,
            segmented_button_selected_color=CLR_ACCENT,
            segmented_button_unselected_color=CLR_PANEL,
        )
        self.tabview.pack(fill="both", expand=True, padx=8, pady=(8, 0))

        # Tabs
        self.tab_output = self.tabview.add("Output")
        self.tab_results = self.tabview.add("Results")
        self.tab_stats = self.tabview.add("Statistics")

        self._build_output_tab()
        self._build_results_tab()
        self._build_stats_tab()

    # ---- Output Tab ----
    def _build_output_tab(self):
        self.output_box = ctk.CTkTextbox(
            self.tab_output,
            font=FONT_MONO,
            fg_color=CLR_BG,
            text_color=CLR_GREEN,
            border_width=1,
            border_color=CLR_ACCENT,
            corner_radius=4,
            wrap="word",
            state="disabled",
        )
        self.output_box.pack(fill="both", expand=True, padx=4, pady=4)

    def _append_output(self, text: str):
        """Thread-safe append to the output textbox."""
        def _do():
            self.output_box.configure(state="normal")
            self.output_box.insert("end", text + "\n")
            self.output_box.see("end")
            self.output_box.configure(state="disabled")
        self.after(0, _do)

    # ---- Results Tab ----
    def _build_results_tab(self):
        # Treeview via tkinter for a proper table
        tree_frame = tk.Frame(self.tab_results, bg=CLR_BG)
        tree_frame.pack(fill="both", expand=True, padx=4, pady=4)

        style = ttk.Style()
        style.theme_use("clam")
        style.configure(
            "Treeview",
            background=CLR_BG,
            foreground=CLR_TEXT,
            fieldbackground=CLR_BG,
            font=("Consolas", 11),
            rowheight=24,
        )
        style.configure(
            "Treeview.Heading",
            background=CLR_PANEL,
            foreground=CLR_BLUE,
            font=("Segoe UI", 11, "bold"),
        )
        style.map("Treeview", background=[("selected", CLR_ACCENT)])

        columns = ("host", "port", "protocol", "state", "service", "version")
        self.tree = ttk.Treeview(
            tree_frame,
            columns=columns,
            show="headings",
            selectmode="browse",
        )

        self.tree.heading("host", text="Host")
        self.tree.heading("port", text="Port")
        self.tree.heading("protocol", text="Proto")
        self.tree.heading("state", text="State")
        self.tree.heading("service", text="Service")
        self.tree.heading("version", text="Version")

        self.tree.column("host", width=180, minwidth=120)
        self.tree.column("port", width=70, minwidth=50)
        self.tree.column("protocol", width=60, minwidth=45)
        self.tree.column("state", width=80, minwidth=60)
        self.tree.column("service", width=140, minwidth=80)
        self.tree.column("version", width=260, minwidth=100)

        vsb = tk.Scrollbar(
            tree_frame, orient="vertical", command=self.tree.yview,
            bg=CLR_PANEL, troughcolor=CLR_BG,
        )
        self.tree.configure(yscrollcommand=vsb.set)

        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        # Tag colours for port states
        self.tree.tag_configure("open", foreground=CLR_GREEN)
        self.tree.tag_configure("closed", foreground=CLR_RED)
        self.tree.tag_configure("filtered", foreground=CLR_YELLOW)

    # ---- Statistics Tab ----
    def _build_stats_tab(self):
        stats_container = ctk.CTkFrame(self.tab_stats, fg_color="transparent")
        stats_container.pack(fill="both", expand=True, padx=16, pady=16)

        # Row of stat cards
        cards_frame = ctk.CTkFrame(stats_container, fg_color="transparent")
        cards_frame.pack(fill="x", pady=(0, 16))

        self.stat_cards: dict[str, dict] = {}
        card_defs = [
            ("total", "Total Ports Scanned", "0", CLR_BLUE),
            ("open", "Open Ports", "0", CLR_GREEN),
            ("closed", "Closed Ports", "0", CLR_RED),
            ("filtered", "Filtered Ports", "0", CLR_YELLOW),
            ("duration", "Scan Duration", "0.0s", CLR_HIGHLIGHT),
        ]

        for key, label, default, color in card_defs:
            card = ctk.CTkFrame(
                cards_frame, fg_color=CLR_PANEL, corner_radius=8,
                border_width=2, border_color=color,
            )
            card.pack(side="left", expand=True, fill="x", padx=4)

            ctk.CTkLabel(
                card, text=label, font=FONT_SMALL, text_color=CLR_TEXT_DIM,
            ).pack(pady=(12, 2))

            val_label = ctk.CTkLabel(
                card, text=default, font=("Consolas", 26, "bold"),
                text_color=color,
            )
            val_label.pack(pady=(2, 12))
            self.stat_cards[key] = {"frame": card, "label": val_label}

        # Detail info area
        info_frame = ctk.CTkFrame(
            stats_container, fg_color=CLR_PANEL, corner_radius=8,
        )
        info_frame.pack(fill="both", expand=True)

        self.info_text = ctk.CTkTextbox(
            info_frame,
            font=FONT_MONO,
            fg_color=CLR_BG,
            text_color=CLR_TEXT,
            border_width=0,
            corner_radius=4,
            state="disabled",
        )
        self.info_text.pack(fill="both", expand=True, padx=4, pady=4)

    def _update_stats(self, result: ScanResult):
        """Update the stats panel with scan result data."""
        def _do():
            self.stat_cards["total"]["label"].configure(
                text=str(result.total_ports_scanned)
            )
            self.stat_cards["open"]["label"].configure(
                text=str(result.open_ports)
            )
            self.stat_cards["closed"]["label"].configure(
                text=str(result.closed_ports)
            )
            self.stat_cards["filtered"]["label"].configure(
                text=str(result.filtered_ports)
            )
            self.stat_cards["duration"]["label"].configure(
                text=f"{result.scan_duration:.1f}s"
            )

            # Info text
            lines = [
                f"Target:       {result.target}",
                f"Scan Type:    {result.scan_type}",
                f"Command:      {result.nmap_command}",
                f"Timestamp:    {result.timestamp}",
                f"Duration:     {result.scan_duration:.2f} seconds",
                "",
                f"Hosts Found:  {len(result.hosts)}",
                "",
            ]

            for host in result.hosts:
                lines.append(
                    f"Host: {host['hostname']} ({host['ip']}) - {host['state']}"
                )
                for proto_data in host["protocols"]:
                    for port in proto_data["ports"]:
                        lines.append(
                            f"  {port['port']}/{port['protocol']:4s} "
                            f"{port['state']:10s} {port['service']:15s} {port['version']}"
                        )
                lines.append("")

            if result.errors:
                lines.append("Errors:")
                for err in result.errors:
                    lines.append(f"  ! {err}")

            self.info_text.configure(state="normal")
            self.info_text.delete("1.0", "end")
            self.info_text.insert("1.0", "\n".join(lines))
            self.info_text.configure(state="disabled")
        self.after(0, _do)

    def _populate_results_table(self, result: ScanResult):
        """Fill the results treeview with scan data."""
        def _do():
            for item in self.tree.get_children():
                self.tree.delete(item)

            for host in result.hosts:
                for proto_data in host["protocols"]:
                    for port in proto_data["ports"]:
                        state = port["state"]
                        tag = "open" if state == "open" else (
                            "filtered" if state == "filtered" else "closed"
                        )
                        self.tree.insert(
                            "",
                            "end",
                            values=(
                                host["ip"],
                                port["port"],
                                port["protocol"],
                                state,
                                port["service"],
                                port["version"],
                            ),
                            tags=(tag,),
                        )
        self.after(0, _do)

    # ------------------------------------------------------------------
    # Status Bar
    # ------------------------------------------------------------------
    def _build_status_bar(self):
        self.status_bar = ctk.CTkFrame(
            self, height=32, fg_color=CLR_PANEL, corner_radius=0,
        )
        self.status_bar.pack(side="bottom", fill="x")
        self.status_bar.pack_propagate(False)

        self.status_label = ctk.CTkLabel(
            self.status_bar,
            text="Ateeq ur Rehman | Ready",
            font=FONT_SMALL,
            text_color=CLR_TEXT_DIM,
        )
        self.status_label.pack(side="left", padx=12, pady=6)

        self.progress = ctk.CTkProgressBar(
            self.status_bar,
            width=300,
            height=14,
            fg_color=CLR_BG,
            progress_color=CLR_GREEN,
        )
        self.progress.pack(side="right", padx=12, pady=6)
        self.progress.set(0)

    def _set_status(self, text: str):
        """Update the status bar text."""
        def _do():
            self.status_label.configure(text=f"Ateeq ur Rehman | {text}")
        self.after(0, _do)

    def _set_progress(self, value: float):
        """Update the progress bar (0 to 1)."""
        def _do():
            self.progress.set(min(max(value, 0), 1))
        self.after(0, _do)

    # ------------------------------------------------------------------
    # Scan Logic
    # ------------------------------------------------------------------
    def _build_arguments(self) -> tuple[str, str]:
        """
        Assemble nmap arguments from the UI state.
        Returns (arguments_string, scan_label).
        """
        scan_name = self.scan_type_var.get()
        preset = NmapScanner.SCAN_PRESETS.get(scan_name, "")
        args_parts = [preset] if preset else []

        # Timing
        timing_name = self.timing_var.get()
        timing_flag = NmapScanner.TIMING_TEMPLATES.get(timing_name, "")
        if timing_flag:
            args_parts.append(timing_flag)

        # Port range
        port_range = self.port_entry.get().strip()
        if port_range:
            args_parts.append(f"-p {port_range}")

        # Extra checkboxes
        if self.sv_var.get():
            args_parts.append("-sV")
        if self.os_var.get():
            args_parts.append("-O")
        if self.traceroute_var.get():
            args_parts.append("--traceroute")
        if self.pn_var.get():
            args_parts.append("-Pn")
        if self.scripts_var.get():
            args_parts.append("-sC")

        # Custom user arguments
        if self.custom_args.strip():
            args_parts.append(self.custom_args.strip())

        args_str = " ".join(args_parts)
        return args_str, scan_name

    def _start_scan(self):
        """Validate input and start a scan."""
        if self.scanner.is_scanning:
            messagebox.showwarning("Busy", "A scan is already running.")
            return

        target = self.target_entry.get().strip()
        valid, msg = NmapScanner.validate_target(target)
        if not valid:
            messagebox.showerror("Invalid Target", msg)
            return

        arguments, scan_label = self._build_arguments()

        # Clear previous results
        self.output_box.configure(state="normal")
        self.output_box.delete("1.0", "end")
        self.output_box.configure(state="disabled")

        for item in self.tree.get_children():
            self.tree.delete(item)

        # Reset stats
        for key in ["total", "open", "closed", "filtered"]:
            self.stat_cards[key]["label"].configure(text="0")
        self.stat_cards["duration"]["label"].configure(text="0.0s")
        self.info_text.configure(state="normal")
        self.info_text.delete("1.0", "end")
        self.info_text.configure(state="disabled")

        self.progress.set(0)
        self.export_btn.configure(state="disabled")

        # Update UI state
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")

        # Start timer
        self._elapsed_seconds = 0.0
        self._timer_running = True
        self._tick_timer()

        # Start scan
        self._append_output(f"[INFO] Starting scan: {scan_label}")
        self._append_output(f"[INFO] Target: {target}")
        self._append_output(f"[INFO] Arguments: {arguments}")
        self._append_output("-" * 60)

        self._set_status(f"Scanning {target}...")
        self.scanner.start_scan(
            target=target,
            arguments=arguments,
            scan_label=scan_label,
            on_output=self._append_output,
            on_progress=self._set_progress,
            on_status=self._set_status,
            on_complete=self._on_scan_complete,
            on_error=self._on_scan_error,
        )

    def _stop_scan(self):
        """Request the scanner to stop."""
        self.scanner.stop()
        self._set_status("Stopping scan...")
        self._append_output("[INFO] Stop requested by user...")

    def _on_scan_complete(self, result: ScanResult):
        """Called when the scan finishes (from scanner thread)."""
        self.scan_result = result

        # Stop timer
        self._timer_running = False

        self._append_output("-" * 60)
        self._append_output(f"[DONE] Scan completed in {result.scan_duration:.1f}s")

        if result.errors:
            for err in result.errors:
                self._append_output(f"[ERROR] {err}")

        # Populate UI
        self._populate_results_table(result)
        self._update_stats(result)
        self.export_btn.configure(state="normal")

        # Switch to results tab
        self.after(100, lambda: self.tabview.set("Results"))

        # Re-enable buttons
        self.after(0, lambda: self.start_btn.configure(state="normal"))
        self.after(0, lambda: self.stop_btn.configure(state="disabled"))

    def _on_scan_error(self, message: str):
        """Called on scanner errors (from scanner thread)."""
        self._append_output(f"[ERROR] {message}")
        self._set_status(f"Error: {message}")

    # ------------------------------------------------------------------
    # Timer
    # ------------------------------------------------------------------
    def _tick_timer(self):
        """Update the elapsed-time display every second."""
        if not self._timer_running:
            return
        self._elapsed_seconds += 1
        mins = int(self._elapsed_seconds) // 60
        secs = int(self._elapsed_seconds) % 60
        self.timer_label.configure(text=f"{mins:02d}:{secs:02d}")
        self._timer_job = self.after(1000, self._tick_timer)

    # ------------------------------------------------------------------
    # Settings / Custom Arguments
    # ------------------------------------------------------------------
    def _open_settings(self):
        dlg = SettingsDialog(self, current_args=self.custom_args)
        self.wait_window(dlg)
        if dlg.result_args is not None:
            self.custom_args = dlg.result_args
            if self.custom_args:
                self._set_status(f"Custom args set: {self.custom_args}")
            else:
                self._set_status("Custom arguments cleared.")

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------
    def _export_results(self):
        if not self.scan_result:
            messagebox.showinfo("No Results", "No scan results to export.")
            return

        filetypes = [
            ("JSON File", "*.json"),
            ("CSV File", "*.csv"),
            ("Text File", "*.txt"),
            ("All Files", "*.*"),
        ]

        filepath = filedialog.asksaveasfilename(
            title="Export Scan Results",
            defaultextension=".json",
            filetypes=filetypes,
            initialfile=f"scan_result_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
        )

        if not filepath:
            return

        try:
            ext = os.path.splitext(filepath)[1].lower()
            if ext == ".csv":
                NmapScanner.export_csv(self.scan_result, filepath)
            elif ext == ".txt":
                NmapScanner.export_txt(self.scan_result, filepath)
            else:
                NmapScanner.export_json(self.scan_result, filepath)

            self._set_status(f"Results exported to {os.path.basename(filepath)}")
            messagebox.showinfo("Export Complete", f"Results saved to:\n{filepath}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export:\n{e}")


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------
def main():
    app = ARScannerApp()
    app.mainloop()


if __name__ == "__main__":
    main()



