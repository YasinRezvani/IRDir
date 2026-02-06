from __future__ import annotations
import sys
import os
import threading
import time
import queue
import json
import csv
import logging
import math
import traceback
import webbrowser
from dataclasses import dataclass
from typing import List, Dict, Optional, Any, Set
from urllib.parse import urljoin, urlparse, quote
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
try:
    import requests
except Exception as e:
    print("Missing dependency: requests. Install with: pip install requests", file=sys.stderr)
    raise

# Application constants
APP_DIR = os.path.abspath(os.path.dirname(__file__))
WORDLIST_DIR = os.path.join(APP_DIR, "wordlists")
MAX_LOG_ENTRIES = 1000
UI_UPDATE_INTERVAL_MS = 150
DEFAULT_DELAY = 0.1
DEFAULT_TIMEOUT = 10.0
DEFAULT_CONCURRENCY = 35
STATUS_FILTERS = [200, 301, 302, 401, 403, 404]

# Data class for scan results
@dataclass
class ScanResult:
    index: int
    path: str
    full_url: str
    status: Optional[int]
    size: Optional[int]
    time_ms: Optional[float]
    content_type: Optional[str]
    note: str
    headers: Dict[str, Any]
    snippet: str

# Class for managing wordlist files
class WordlistManager:
    def __init__(self, folder: str = WORDLIST_DIR):
        """Initialize the WordlistManager with the specified folder."""
        self.folder = folder
        os.makedirs(self.folder, exist_ok=True)

    def list_files(self) -> List[str]:
        """List wordlist files in the folder, prioritizing specific files."""
        try:
            items = [
                f for f in os.listdir(self.folder)
                if os.path.isfile(os.path.join(self.folder, f))
            ]
            priority_files = [
                "irdir-iranian-common.txt",
                "irdir-iranian-common-encoded.txt"
            ]
            priority_found = []
            for pf in priority_files:
                if pf in items:
                    items.remove(pf)
                    priority_found.append(pf)
            items.sort()
            items = priority_found + items
            logging.debug("Wordlist files found: %s", items)
            return items
        except Exception as e:
            logging.exception("Error listing wordlists: %s", e)
            return []

    def load_selected(self, filenames: List[str]) -> List[str]:
        """Load and merge selected wordlist files, deduplicating entries."""
        seen: Set[str] = set()
        merged: List[str] = []
        for fn in filenames:
            path = os.path.join(self.folder, fn)
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    for raw in fh:
                        line = raw.strip()
                        if not line or line.startswith("#"):
                            continue
                        if line not in seen:
                            seen.add(line)
                            merged.append(line)
            except Exception as e:
                logging.exception("Failed to read wordlist %s: %s", path, e)
        return merged

# Class for handling scanning operations
from concurrent.futures import ThreadPoolExecutor, Future

class Scanner:
    def __init__(
        self,
        target_base: str,
        paths: List[str],
        result_queue: "queue.Queue[ScanResult]",
        log_callback,
        concurrency: int = DEFAULT_CONCURRENCY,
        delay: float = DEFAULT_DELAY,
        timeout: float = DEFAULT_TIMEOUT,
    ):
        """Initialize the Scanner with target and configuration parameters."""
        self.target_base = target_base
        self.paths = list(paths)
        self.result_queue = result_queue
        self.log = log_callback
        self.concurrency = max(1, int(concurrency))
        self.delay = max(0.0, float(delay))
        self.timeout = float(timeout)
        self._executor: Optional[ThreadPoolExecutor] = None
        self._session: Optional[requests.Session] = None
        self._stop_event = threading.Event()
        self._suppress_results = False
        self._futures: Set[Future] = set()
        self._submitted_count = 0
        self._index_counter = 0
        self._lock = threading.Lock()
        self._submitter_thread: Optional[threading.Thread] = None

    def _make_session(self) -> requests.Session:
        """Create a new requests Session with configured redirects."""
        s = requests.Session()
        s.max_redirects = 10
        return s

    def start(self):
        """Start the scanning process by initializing threads and executor."""
        with self._lock:
            self._stop_event.clear()
            self._suppress_results = False
            self._submitted_count = 0
            self._index_counter = 0
            self._futures.clear()
        self._session = self._make_session()
        self._executor = ThreadPoolExecutor(max_workers=self.concurrency)
        self._submitter_thread = threading.Thread(target=self._submitter, daemon=True)
        self._submitter_thread.start()
        self.log(f"Scanner started with concurrency={self.concurrency}, delay={self.delay}, timeout={self.timeout}")

    def stop(self):
        """Stop the scanning process, suppressing further results."""
        with self._lock:
            self._stop_event.set()
            self._suppress_results = True
        self.log("Stopping scanner: new submissions halted; in-flight workers will finish but their results will be suppressed.")
        try:
            if self._executor:
                self._executor.shutdown(wait=False)
        except Exception:
            logging.exception("Error shutting down executor")

    def _submitter(self):
        """Submit scanning tasks to the executor."""
        try:
            for p in self.paths:
                if self._stop_event.is_set():
                    logging.info("Submitter: stop requested; halting further submission.")
                    break
                if not self._executor:
                    break
                try:
                    with self._lock:
                        submitted_index = self._submitted_count
                        self._submitted_count += 1
                    future = self._executor.submit(self._worker, p, submitted_index)
                    with self._lock:
                        self._futures.add(future)
                    future.add_done_callback(self._future_done)
                except Exception as e:
                    logging.exception("Failed to submit task for path %s: %s", p, e)
                    self.log(f"Failed to submit task for path {p}: {e}")
                time.sleep(self.delay / 10 if self.delay > 0 else 0.001)
            logging.info("Submitter: finished submitting tasks (or stopped).")
            self.log("Submitter finished.")
        except Exception as e:
            logging.exception("Submitter thread error: %s", e)
            self.log(f"Submitter thread error: {e}")

    def _future_done(self, fut: Future):
        """Remove completed future from tracking set."""
        with self._lock:
            try:
                self._futures.discard(fut)
            except Exception:
                pass

    def _safe_quote_path(self, path: str) -> str:
        """Safely quote the path for URL construction."""
        return quote(path, safe="/:@&?=+,$-_.!~*'()#%")

    def _build_full_url(self, path: str) -> str:
        """Build the full URL from base and path."""
        path = path.lstrip("/")
        quoted = self._safe_quote_path(path)
        if not self.target_base.endswith("/"):
            return f"{self.target_base}/{quoted}"
        else:
            return f"{self.target_base}{quoted}"

    def _worker(self, path: str, submitted_index: int):
        """Perform HTTP request for a single path and process result."""
        start_time = time.time()
        full_url = self._build_full_url(path)
        status = None
        size = None
        content_type = None
        note = ""
        headers = {}
        snippet = ""
        try:
            r = None
            try:
                if not self._session:
                    self._session = self._make_session()
                r = self._session.get(full_url, timeout=self.timeout, allow_redirects=True)
            except Exception as e:
                elapsed = (time.time() - start_time) * 1000.0
                note = f"error: {e}"
                logging.debug("Worker exception for %s: %s", path, e)
                res_obj = ScanResult(
                    index=submitted_index,
                    path=path,
                    full_url=full_url,
                    status=None,
                    size=None,
                    time_ms=elapsed,
                    content_type=None,
                    note=str(e),
                    headers={},
                    snippet="",
                )
                with self._lock:
                    suppress = self._suppress_results
                if suppress:
                    logging.debug("Worker result suppressed (error) for %s after stop requested.", path)
                    return
                try:
                    self.result_queue.put(res_obj)
                except Exception:
                    logging.exception("Failed to put error ScanResult into queue for %s", path)
                return

            if r is not None:
                status = r.status_code
                headers = dict(r.headers or {})
                content_type = headers.get("Content-Type", "")
                body = r.content or b""
                size = len(body)
                elapsed = (time.time() - start_time) * 1000.0
                try:
                    snippet = body.decode("utf-8", errors="replace")[:1024]
                except Exception:
                    snippet = str(body)[:1024]
                if 200 <= status < 300:
                    note = "OK"
                elif status in (301, 302):
                    note = "redirect"
                elif status == 401:
                    note = "unauthorized"
                elif status == 403:
                    note = "forbidden"
                elif status == 404:
                    note = "not found"
                else:
                    note = ""
                res_obj = ScanResult(
                    index=submitted_index,
                    path=path,
                    full_url=full_url,
                    status=status,
                    size=size,
                    time_ms=elapsed,
                    content_type=content_type,
                    note=note,
                    headers=headers,
                    snippet=snippet,
                )
                with self._lock:
                    suppress = self._suppress_results
                if suppress:
                    logging.debug("Worker result suppressed for %s (status=%s) after stop requested.", path, status)
                    return
                try:
                    self.result_queue.put(res_obj)
                    logging.debug("Worker result queued for %s: %s %dB in %.1fms", path, status, size or 0, elapsed)
                except Exception:
                    logging.exception("Failed to put ScanResult into queue for %s", path)
        finally:
            if self.delay:
                time.sleep(self.delay)

    def active_workers_count(self) -> int:
        """Get the count of active workers."""
        with self._lock:
            return len(self._futures)

    def submitted_count(self) -> int:
        """Get the count of submitted tasks."""
        with self._lock:
            return self._submitted_count

    def total_to_submit(self) -> int:
        """Get the total number of paths to submit."""
        return len(self.paths)

# Class for creating tooltips
class ToolTip:
    def __init__(self, widget, text: str):
        """Initialize tooltip for a widget."""
        self.widget = widget
        self.text = text
        self.tipwindow = None
        self.id = None
        widget.bind("<Enter>", self.enter)
        widget.bind("<Leave>", self.leave)

    def enter(self, _=None):
        """Show the tooltip on mouse enter."""
        if self.tipwindow or not self.text:
            return
        x, y, cx, cy = self.widget.bbox("insert") if hasattr(self.widget, "bbox") else (0, 0, 0, 0)
        x = x + self.widget.winfo_rootx() + 25
        y = y + cy + self.widget.winfo_rooty() + 20
        self.tipwindow = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        label = tk.Label(tw, text=self.text, justify=tk.LEFT, 
                         background="#1e293b", foreground="#f8fafc",
                         relief=tk.FLAT, borderwidth=0,
                         font=("Segoe UI", 9, "normal"), padx=8, pady=6)
        label.pack()

    def leave(self, _=None):
        """Hide the tooltip on mouse leave."""
        tw = self.tipwindow
        self.tipwindow = None
        if tw:
            tw.destroy()

# Main GUI application class
class AppGUI:
    def __init__(self, root: tk.Tk):
        """Initialize the GUI application."""
        self.root = root
        self.root.title("IRDir - Iranian-focused Directory Enumerator")
        try:
            self.root.state("zoomed")
        except Exception:
            try:
                self.root.attributes("-zoomed", True)
            except Exception:
                self.root.geometry(f"{self.root.winfo_screenwidth()}x{self.root.winfo_screenheight()}+0+0")
        self.style = ttk.Style()
        for theme in ("clam", "vista", "alt", "xpnative"):
            try:
                self.style.theme_use(theme)
                break
            except Exception:
                continue
        self._apply_modern_styling()
        self.wordlist_manager = WordlistManager(WORDLIST_DIR)
        self.available_files: List[str] = []
        self.selected_files_vars: Dict[str, tk.IntVar] = {}
        self.merged_list: List[str] = []
        self.scanner: Optional[Scanner] = None
        self.results_master: List[ScanResult] = []
        self.results_lock = threading.Lock()
        self.result_queue: "queue.Queue[ScanResult]" = queue.Queue()
        self._log_list: List[str] = []
        self._last_selected_url: Optional[str] = None
        self._build_ui()
        self.available_files = self.wordlist_manager.list_files()
        for i, fn in enumerate(self.available_files):
            var = tk.IntVar(value=1)
            cb = ttk.Checkbutton(self.wordlist_inner_frame, text=fn, variable=var)
            cb.pack(fill="x", anchor="w", pady=0)
            self.selected_files_vars[fn] = var
        self.wordlist_inner_frame.update_idletasks()
        self.file_check_canvas.configure(scrollregion=self.file_check_canvas.bbox("all"))
        self._log(f"Found {len(self.available_files)} wordlist files.")
        self._running = True
        self._poll_queue()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _apply_modern_styling(self):
        """Apply modern styling to the GUI components."""
        colors = {
            "primary": "#0066cc",
            "primary_hover": "#0052a3",
            "secondary": "#0099cc",
            "bg_light": "#f5f5f5",
            "bg_base": "#ffffff",
            "bg_dark": "#e8e8e8",
            "text_primary": "#1a1a1a",
            "text_secondary": "#555555",
            "border": "#cccccc",
            "success": "#22aa22",
            "warning": "#ff8800",
            "error": "#cc0000",
            "selected": "#cce5ff",
        }
        self.root.configure(bg=colors["bg_light"])
        self.style.configure("TFrame", background=colors["bg_base"], borderwidth=0)
        self.style.configure("TLabel", background=colors["bg_base"], foreground=colors["text_primary"], font=("Segoe UI", 10))
        self.style.configure("TButton", font=("Segoe UI", 9, "normal"), padding=(8, 4))
        self.style.map("TButton",
                       background=[("active", colors["primary_hover"]), ("!active", colors["primary"])],
                       foreground=[("active", "white"), ("!active", "white")],
                       relief=[("pressed", "sunken"), ("!pressed", "raised")])
        self.style.configure("TEntry", fieldbackground=colors["bg_base"], borderwidth=1, 
                             relief="solid", padding=4, font=("Segoe UI", 9))
        self.style.map("TEntry",
                       focuscolor=[("focus", colors["primary"])],
                       bordercolor=[("focus", colors["primary"])])
        self.style.configure("TSpinbox", fieldbackground=colors["bg_base"], borderwidth=1,
                             relief="solid", padding=4, font=("Segoe UI", 10))
        self.style.map("TSpinbox",
                       focuscolor=[("focus", colors["primary"])],
                       bordercolor=[("focus", colors["primary"])])
        self.style.configure("TCheckbutton", background=colors["bg_base"], foreground=colors["text_primary"],
                             font=("Segoe UI", 10))
        self.style.map("TCheckbutton",
                       background=[("active", colors["bg_base"])])
        self.style.configure("TProgressbar", background=colors["primary"], troughcolor=colors["bg_dark"],
                             borderwidth=0, lightcolor=colors["primary"], darkcolor=colors["primary"])
        self.style.configure("TScale", background=colors["bg_dark"], troughcolor=colors["bg_dark"],
                             sliderthickness=12, borderwidth=0)
        self.style.map("TScale",
                       background=[("active", colors["primary"])])
        self.style.configure("Treeview", background=colors["bg_base"], foreground=colors["text_primary"],
                             fieldbackground=colors["bg_base"], font=("Segoe UI", 10), rowheight=24)
        self.style.map("Treeview",
                       background=[("selected", colors["selected"])],
                       foreground=[("selected", colors["text_primary"])])
        self.style.configure("Treeview.Heading", background=colors["bg_dark"], foreground=colors["text_primary"],
                             font=("Segoe UI", 10, "bold"), relief="flat", padding=(8, 6))
        self.style.map("Treeview.Heading",
                       background=[("active", colors["border"])])
        self.style.configure("Vertical.TScrollbar", background=colors["bg_dark"], troughcolor=colors["bg_base"],
                             borderwidth=0, arrowcolor=colors["text_secondary"], width=12)
        self.style.map("Vertical.TScrollbar",
                       background=[("active", colors["border"])])
        self.style.configure("Horizontal.TScrollbar", background=colors["bg_dark"], troughcolor=colors["bg_base"],
                             borderwidth=0, arrowcolor=colors["text_secondary"], width=12)
        self.style.map("Horizontal.TScrollbar",
                       background=[("active", colors["border"])])
        btn_color = "#0078d7"  
        btn_hover = "#005a9e"
        self.style.configure("Browser.TButton", 
                             font=("Segoe UI", 9, "bold"),
                             padding=(10, 5),
                             background=btn_color)
        self.style.map("Browser.TButton",
                       background=[("active", btn_hover), ("!active", btn_color)],
                       foreground=[("active", "white"), ("!active", "white")],
                       relief=[("pressed", "sunken"), ("!pressed", "raised")])
        start_color = colors["success"]
        start_hover = "#1b881b"
        self.style.configure("Start.TButton",
                             font=("Segoe UI", 9, "bold"),
                             padding=(8, 4),
                             background=start_color)
        self.style.map("Start.TButton",
                       background=[("active", start_hover), ("!active", start_color)],
                       foreground=[("active", "white"), ("!active", "white")],
                       relief=[("pressed", "sunken"), ("!pressed", "raised")])
        stop_color = colors["error"]
        stop_hover = "#990000"
        self.style.configure("Stop.TButton",
                             font=("Segoe UI", 9, "bold"),
                             padding=(8, 4),
                             background=stop_color)
        self.style.map("Stop.TButton",
                       background=[("active", stop_hover), ("!active", stop_color)],
                       foreground=[("active", "white"), ("!active", "white")],
                       relief=[("pressed", "sunken"), ("!pressed", "raised")])
        self.colors = colors

    def _create_section(self, parent, title, header_font=("Segoe UI", 12, "bold"), padding=(16, 16)):
        """Create a GUI section with header and content."""
        outer = ttk.Frame(parent, padding=padding)
        header_row = ttk.Frame(outer)
        header_row.pack(side="top", fill="x", pady=(0, 0))
        header_label = ttk.Label(header_row, text=title, font=header_font, foreground=self.colors["text_primary"])
        header_label.pack(side="left", anchor="w")
        content = ttk.Frame(outer)
        content.pack(side="top", fill="both", expand=True)
        return outer, header_row, content

    def _adjust_left_paned_sizes(self, left_paned, results_frame, details_frame, log_frame, retries=5):
        """Adjust sash positions for paned window."""
        try:
            total_h = left_paned.winfo_height()
            if total_h <= 10 and retries > 0:
                self.root.after(100, lambda: self._adjust_left_paned_sizes(left_paned, results_frame, details_frame, log_frame, retries-1))
                return
            y1 = int(total_h * 0.44)
            y2 = int(total_h * 0.74)
            try:
                left_paned.sash_place(0, 0, y1)
                left_paned.sash_place(1, 0, y2)
            except Exception:
                try:
                    left_paned.sash_coord(0, 0, y1)
                    left_paned.sash_coord(1, 0, y2)
                except Exception:
                    pass
        except Exception:
            logging.exception("Failed to set left paned sizes.")

    def _build_ui(self):
        """Build the main user interface."""
        header = ttk.Frame(self.root, padding=(24, 16))
        header.pack(side="top", fill="x")
        title_container = ttk.Frame(header, padding=0)
        title_container.pack(side="left", padx=(0, 12), pady=(0, 1))
        ir_label = ttk.Label(
            title_container, 
            text="IR", 
            font=("Segoe UI", 25, "bold"), 
            foreground=self.colors["primary"],
            padding=0
        )
        ir_label.pack(side="left", padx=0, pady=0)
        dir_label = ttk.Label(
            title_container, 
            text="Dir", 
            font=("Segoe UI", 25, "bold"), 
            foreground="#000000",
            padding=0
        )
        dir_label.pack(side="left", padx=0, pady=0)
        subtitle_label = ttk.Label(
            header, 
            text="Iranian-focused Directory Enumerator", 
            font=("Segoe UI", 16), 
            foreground=self.colors["text_secondary"]
        )
        subtitle_label.pack(side="left")
        main_container = ttk.Frame(self.root)
        main_container.pack(side="top", fill="both", expand=True, padx=16, pady=16)
        main_paned = tk.PanedWindow(main_container, orient="horizontal", sashwidth=10, 
                                    sashrelief="flat", bg=self.colors["bg_light"], 
                                    bd=0)
        main_paned.pack(fill="both", expand=True)
        left_frame = ttk.Frame(main_paned)
        main_paned.add(left_frame, width=int(main_container.winfo_screenwidth() * 0.28))
        left_frame.grid_columnconfigure(0, weight=1)
        left_frame.grid_rowconfigure(0, weight=45)
        left_frame.grid_rowconfigure(1, weight=35)
        left_frame.grid_rowconfigure(2, weight=20)
        left_frame.grid_rowconfigure(3, weight=0)
        config_outer, config_header, config_content = self._create_section(left_frame, "Test Configuration", 
                                                                           header_font=("Segoe UI", 13, "bold"))
        config_outer.grid(row=0, column=0, sticky="nsew", padx=0, pady=(0, 0))
        config_content.grid_columnconfigure(1, weight=1)
        ttk.Label(config_content, text="Target domain:", font=("Segoe UI", 9, "normal"),
                  foreground=self.colors["text_primary"]).grid(
            row=0, column=0, sticky="w", pady=(0, 2))
        self.target_entry = ttk.Entry(config_content, font=("Segoe UI", 9))
        self.target_entry.grid(row=0, column=1, sticky="we", pady=(0, 4), padx=(8, 0))
        self.target_entry.insert(0, "https://shahroodut.ac.ir")
        ttk.Label(config_content, text="Concurrency:", font=("Segoe UI", 9, "normal"),
                  foreground=self.colors["text_primary"]).grid(
            row=1, column=0, sticky="w", pady=(0, 4))
        concurrency_frame = ttk.Frame(config_content)
        concurrency_frame.grid(row=1, column=1, sticky="we", padx=(8, 0), pady=(0, 4))
        concurrency_frame.grid_columnconfigure(0, weight=1)
        concurrency_frame.grid_columnconfigure(1, weight=0)
        self.concurrency_var = tk.IntVar(value=DEFAULT_CONCURRENCY)
        self.concurrency_slider = ttk.Scale(concurrency_frame, from_=1, to=100, 
                                            orient="horizontal", command=self._on_concurrency_slide)
        self.concurrency_slider.set(DEFAULT_CONCURRENCY)
        self.concurrency_slider.grid(row=0, column=0, sticky="we", padx=(0, 8))
        self.concurrency_spin = ttk.Spinbox(concurrency_frame, from_=1, to=100, 
                                            textvariable=self.concurrency_var, width=6,
                                            command=self._on_concurrency_spin, font=("Segoe UI", 10))
        self.concurrency_spin.grid(row=0, column=1)
        delay_timeout_frame = ttk.Frame(config_content)
        delay_timeout_frame.grid(row=2, column=0, columnspan=2, sticky="we", pady=(0, 4))
        delay_timeout_frame.grid_columnconfigure(0, weight=1)
        delay_timeout_frame.grid_columnconfigure(1, weight=1)
        ttk.Label(delay_timeout_frame, text="Delay (s):", font=("Segoe UI", 9, "normal"),
                  foreground=self.colors["text_primary"]).grid(
            row=0, column=0, sticky="w")
        self.delay_var = tk.DoubleVar(value=DEFAULT_DELAY)
        self.delay_spin = ttk.Spinbox(delay_timeout_frame, from_=0.0, to=60.0, 
                                      increment=0.1, textvariable=self.delay_var, width=8,
                                      font=("Segoe UI", 9))
        self.delay_spin.grid(row=1, column=0, sticky="w", pady=(2, 0))
        ttk.Label(delay_timeout_frame, text="Timeout (s):", font=("Segoe UI", 9, "normal"),
                  foreground=self.colors["text_primary"]).grid(
            row=0, column=1, sticky="w", padx=(12, 0))
        self.timeout_var = tk.DoubleVar(value=DEFAULT_TIMEOUT)
        self.timeout_spin = ttk.Spinbox(delay_timeout_frame, from_=1.0, to=300.0, 
                                        increment=0.5, textvariable=self.timeout_var, width=8,
                                        font=("Segoe UI", 9))
        self.timeout_spin.grid(row=1, column=1, sticky="w", padx=(12, 0), pady=(2, 0))
        button_frame = ttk.Frame(config_content)
        button_frame.grid(row=3, column=0, columnspan=2, sticky="we", pady=(4, 0))
        button_frame.grid_columnconfigure(0, weight=1)
        button_frame.grid_columnconfigure(1, weight=1)
        self.start_btn = ttk.Button(button_frame, text="Start Scan", command=self.start_scan, 
                                    style="Start.TButton")
        self.start_btn.grid(row=0, column=0, sticky="ew", padx=(0, 6))
        self.stop_btn = ttk.Button(button_frame, text="Stop Scan", command=self.stop_scan, state="disabled",
                                   style="Stop.TButton")
        self.stop_btn.grid(row=0, column=1, sticky="ew", padx=(6, 0))
        progress_frame = ttk.Frame(config_content)
        progress_frame.grid(row=4, column=0, columnspan=2, sticky="we", pady=(4, 0))
        self.progress = ttk.Progressbar(progress_frame, orient="horizontal", mode="determinate")
        self.progress.pack(fill="x", side="top", pady=(0, 4))
        stats_frame = ttk.Frame(progress_frame)
        stats_frame.pack(fill="x", side="top")
        self.progress_var = tk.StringVar(value="0 / 0")
        progress_label = ttk.Label(stats_frame, textvariable=self.progress_var, font=("Segoe UI", 9),
                                   foreground=self.colors["text_primary"])
        progress_label.pack(side="left")
        wordlist_outer, wordlist_header, wordlist_content = self._create_section(left_frame, "Wordlists", 
                                                                                 header_font=("Segoe UI", 13, "bold"))
        wordlist_outer.grid(row=1, column=0, sticky="nsew", padx=0, pady=(0, 8))
        wordlist_content.grid_rowconfigure(0, weight=1)
        wordlist_content.grid_columnconfigure(0, weight=1)
        wordlist_container = ttk.Frame(wordlist_content)
        wordlist_container.pack(fill="both", expand=True)
        self.file_check_canvas = tk.Canvas(wordlist_container, highlightthickness=0, 
                                           bg=self.colors["bg_base"], bd=0, relief="flat")
        self.file_check_scroll = ttk.Scrollbar(wordlist_container, orient="vertical", 
                                               command=self.file_check_canvas.yview,
                                               style="Vertical.TScrollbar")
        self.file_check_canvas.configure(yscrollcommand=self.file_check_scroll.set)
        self.file_check_canvas.pack(side="left", fill="both", expand=True)
        self.file_check_scroll.pack(side="right", fill="y")
        self.wordlist_inner_frame = ttk.Frame(self.file_check_canvas)
        self._wordlist_window_id = self.file_check_canvas.create_window((0, 0), window=self.wordlist_inner_frame, anchor="nw")

        def _on_wordlist_canvas_configure(event):
            try:
                self.file_check_canvas.itemconfig(self._wordlist_window_id, width=event.width)
            except Exception:
                logging.exception("Failed to itemconfig wordlist window")
            finally:
                self.file_check_canvas.configure(scrollregion=self.file_check_canvas.bbox("all"))

        self.file_check_canvas.bind("<Configure>", _on_wordlist_canvas_configure)
        self.wordlist_inner_frame.bind("<Configure>", lambda e: self.file_check_canvas.configure(scrollregion=self.file_check_canvas.bbox("all")))

        def _on_wordlist_mousewheel(event):
            if event.num == 5 or (event.delta and event.delta < 0):
                self.file_check_canvas.yview_scroll(1, "units")
            elif event.num == 4 or (event.delta and event.delta > 0):
                self.file_check_canvas.yview_scroll(-1, "units")

        def _bind_scroll_handlers(event):
            self.file_check_canvas.bind_all("<MouseWheel>", _on_wordlist_mousewheel)
            self.file_check_canvas.bind_all("<Button-4>", _on_wordlist_mousewheel)
            self.file_check_canvas.bind_all("<Button-5>", _on_wordlist_mousewheel)

        def _unbind_scroll_handlers(event):
            self.file_check_canvas.unbind_all("<MouseWheel>")
            self.file_check_canvas.unbind_all("<Button-4>")
            self.file_check_canvas.unbind_all("<Button-5>")

        wordlist_container.bind("<Enter>", _bind_scroll_handlers)
        wordlist_container.bind("<Leave>", _unbind_scroll_handlers)
        filters_outer, filters_header, filters_content = self._create_section(left_frame, "Filters", 
                                                                              header_font=("Segoe UI", 13, "bold"))
        filters_outer.grid(row=2, column=0, sticky="nsew", padx=0, pady=(0, 8))
        filters_content.grid_columnconfigure(0, weight=1)
        status_frame = ttk.Frame(filters_content)
        status_frame.pack(fill="x", side="top", pady=(0, 12))
        self.status_vars: Dict[int, tk.IntVar] = {}
        default_checked = {200, 401, 403}
        for i, code in enumerate(STATUS_FILTERS):
            var = tk.IntVar(value=1 if code in default_checked else 0)
            cb = ttk.Checkbutton(status_frame, text=str(code), variable=var, 
                                 command=self.apply_filters)
            cb.pack(side="left", padx=(0, 6))
            self.status_vars[code] = var
        error_var = tk.IntVar(value=0)  
        error_cb = ttk.Checkbutton(status_frame, text="Error", variable=error_var, command=self.apply_filters)
        error_cb.pack(side="left", padx=(0, 6))
        self.status_vars["Error"] = error_var
        size_frame = ttk.Frame(filters_content)
        size_frame.pack(fill="x", side="top", pady=(0, 6))
        ttk.Label(size_frame, text="Size min (bytes):", font=("Segoe UI", 9),
                  foreground=self.colors["text_primary"]).pack(side="left", padx=(0, 2))
        self.size_min_var = tk.StringVar(value="")
        size_min_entry = ttk.Entry(size_frame, textvariable=self.size_min_var, width=8,
                                   font=("Segoe UI", 9))
        size_min_entry.pack(side="left", padx=(0, 6))
        ttk.Label(size_frame, text="Size max (bytes):", font=("Segoe UI", 9),
                  foreground=self.colors["text_primary"]).pack(side="left", padx=(0, 2))
        self.size_max_var = tk.StringVar(value="")
        size_max_entry = ttk.Entry(size_frame, textvariable=self.size_max_var, width=8,
                                   font=("Segoe UI", 9))
        size_max_entry.pack(side="left")
        contains_frame = ttk.Frame(filters_content)
        contains_frame.pack(fill="x", side="top", pady=(6, 0))
        ttk.Label(contains_frame, text="Contains (keyword):", font=("Segoe UI", 9),
                  foreground=self.colors["text_primary"]).pack(side="left", padx=(0, 4))
        self.keyword_var = tk.StringVar(value="")
        keyword_entry = ttk.Entry(contains_frame, textvariable=self.keyword_var,
                                  font=("Segoe UI", 9), width=15)
        keyword_entry.pack(side="left", fill="x", expand=True)
        self.size_min_var.trace("w", self._on_filter_change)
        self.size_max_var.trace("w", self._on_filter_change)
        self.keyword_var.trace("w", self._on_filter_change)
        export_frame = ttk.Frame(left_frame)
        export_frame.grid(row=3, column=0, sticky="ew", padx=0, pady=(0, 0))
        export_frame.grid_columnconfigure(0, weight=1)
        export_frame.grid_columnconfigure(1, weight=1)
        ttk.Button(export_frame, text="Export All CSV", 
                   command=lambda: self.export_results(all_results=True, fmt="csv")).grid(
            row=0, column=0, sticky="ew", padx=(0, 6))
        ttk.Button(export_frame, text="Export All JSON", 
                   command=lambda: self.export_results(all_results=True, fmt="json")).grid(
            row=0, column=1, sticky="ew", padx=(6, 0))
        right_frame = ttk.Frame(main_paned)
        main_paned.add(right_frame, width=int(main_container.winfo_screenwidth() * 0.65))
        right_paned = tk.PanedWindow(right_frame, orient="vertical", sashwidth=8, 
                                     sashrelief="flat", bg=self.colors["bg_light"],
                                     bd=0)
        right_paned.pack(fill="both", expand=True)
        results_outer, results_header, results_content = self._create_section(right_frame, "Live Results", 
                                                                              header_font=("Segoe UI", 13, "bold"))
        right_paned.add(results_outer, minsize=100)
        self._build_results_table(results_content)
        details_outer, details_header, details_content = self._create_section(right_frame, "Details", 
                                                                              header_font=("Segoe UI", 13, "bold"))
        right_paned.add(details_outer, minsize=80)
        self.open_browser_btn = ttk.Button(details_header, text="Open in browser", 
                                           command=self._open_selected_in_browser, width=18)
        self.open_browser_btn.pack(side="right", padx=(8, 0), pady=(0, 12))
        detail_text_frame = ttk.Frame(details_content)
        detail_text_frame.pack(fill="both", expand=True)
        self.detail_text = tk.Text(detail_text_frame, wrap="word", font=("Consolas", 10),
                                   bg="#fefefe", fg=self.colors["text_primary"],
                                   selectbackground=self.colors["primary"],
                                   selectforeground="white", relief="flat", padx=12, pady=12,
                                   borderwidth=1, highlightthickness=1,
                                   highlightcolor=self.colors["primary"],
                                   highlightbackground=self.colors["border"])
        detail_vscroll = ttk.Scrollbar(detail_text_frame, orient="vertical", 
                                       command=self.detail_text.yview, style="Vertical.TScrollbar")
        self.detail_text.configure(yscrollcommand=detail_vscroll.set)
        self.detail_text.pack(side="left", fill="both", expand=True)
        detail_vscroll.pack(side="right", fill="y")
        self.detail_text.configure(state="disabled")
        log_outer, log_header, log_content = self._create_section(right_frame, "Log", 
                                                                  header_font=("Segoe UI", 13, "bold"))
        right_paned.add(log_outer, minsize=60)
        log_text_frame = ttk.Frame(log_content)
        log_text_frame.pack(fill="both", expand=True)
        self.log_text = tk.Text(log_text_frame, wrap="word", height=4, font=("Consolas", 9),
                                bg="#fefefe", fg=self.colors["text_primary"],
                                selectbackground=self.colors["primary"],
                                selectforeground="white", relief="flat", padx=12, pady=12,
                                borderwidth=1, highlightthickness=1,
                                highlightcolor=self.colors["primary"],
                                highlightbackground=self.colors["border"])
        log_vscroll = ttk.Scrollbar(log_text_frame, orient="vertical", 
                                    command=self.log_text.yview, style="Vertical.TScrollbar")
        self.log_text.configure(yscrollcommand=log_vscroll.set)
        self.log_text.pack(side="left", fill="both", expand=True)
        log_vscroll.pack(side="right", fill="y")
        self.log_text.configure(state="disabled")
        self._log("IRDir started.")
        self.root.after(150, lambda: self._adjust_left_paned_sizes(right_paned, results_outer, details_outer, log_outer))

    def _build_results_table(self, parent):
        """Build the results table Treeview."""
        columns = ("index", "path", "url", "status", "size", "time", "type", "note")
        self.tree = ttk.Treeview(parent, columns=columns, show="headings", selectmode="extended")
        self.tree.tag_configure("status_error", foreground=self.colors["error"])
        tree_vscroll = ttk.Scrollbar(parent, orient="vertical", command=self.tree.yview,
                                     style="Vertical.TScrollbar")
        tree_hscroll = ttk.Scrollbar(parent, orient="horizontal", command=self.tree.xview,
                                     style="Horizontal.TScrollbar")
        self.tree.configure(yscrollcommand=tree_vscroll.set, xscrollcommand=tree_hscroll.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        tree_vscroll.grid(row=0, column=1, sticky="ns")
        tree_hscroll.grid(row=1, column=0, sticky="ew", columnspan=2)
        parent.grid_rowconfigure(0, weight=1)
        parent.grid_columnconfigure(0, weight=1)
        column_configs = [
            ("#", "index", 50, "center"),
            ("Path", "path", 140, "w"),
            ("Full URL", "url", 220, "w"),
            ("Status", "status", 80, "center"),
            ("Size", "size", 90, "e"),
            ("Time ms", "time", 90, "e"),
            ("Content-Type", "type", 160, "w"),
            ("Note", "note", 130, "w")
        ]
        for heading_text, column_id, width, anchor in column_configs:
            self.tree.heading(column_id, text=heading_text, 
                              command=lambda col=column_id: self._sort_tree(col, col in ["index", "status", "size", "time"]))
            self.tree.column(column_id, width=width, anchor=anchor, minwidth=50)
        self.tree.tag_configure("status_2xx", foreground=self.colors["success"])
        self.tree.tag_configure("status_3xx", foreground=self.colors["warning"])
        self.tree.tag_configure("status_4xx", foreground=self.colors["error"])
        self.tree.tag_configure("status_other", foreground=self.colors["text_secondary"])
        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)
        self._sort_col = None
        self._sort_reverse = False

    def _on_filter_change(self, *args):
        """Handle filter changes."""
        self.apply_filters()

    def _on_concurrency_slide(self, val):
        """Handle concurrency slider changes."""
        try:
            ival = int(float(val))
            self.concurrency_var.set(ival)
        except Exception:
            pass

    def _on_concurrency_spin(self):
        """Handle concurrency spinbox changes."""
        try:
            v = int(self.concurrency_var.get())
            self.concurrency_slider.set(v)
        except Exception:
            pass

    def get_selected_filenames(self) -> List[str]:
        """Get selected wordlist filenames."""
        return [fn for fn, var in self.selected_files_vars.items() if var.get()]

    def get_merged_list(self) -> List[str]:
        """Get merged wordlist entries."""
        sel = self.get_selected_filenames()
        return self.wordlist_manager.load_selected(sel)

    def start_scan(self):
        """Start the scanning process."""
        self.merged_list = self.get_merged_list()
        if not self.merged_list:
            messagebox.showwarning("No entries", "No wordlist entries selected. Please select files from wordlists/.")
            return
        target_text = self.target_entry.get().strip()
        if not target_text:
            messagebox.showwarning("No target", "Please enter a target domain or URL.")
            return
        try:
            target_base = self._normalize_base_url(target_text)
        except Exception as e:
            messagebox.showerror("Invalid URL", f"Invalid target: {e}")
            return
        concurrency = int(self.concurrency_var.get())
        delay = float(self.delay_var.get())
        timeout = float(self.timeout_var.get())
        with self.results_lock:
            self.results_master.clear()
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        self.detail_text.configure(state="normal")
        self.detail_text.delete("1.0", tk.END)
        self.detail_text.configure(state="disabled")
        self.progress["value"] = 0
        self.progress_var.set("0 / 0")
        self._log("Results cleared.")
        self.scanner = Scanner(
            target_base=target_base,
            paths=self.merged_list,
            result_queue=self.result_queue,
            log_callback=self._log,
            concurrency=concurrency,
            delay=delay,
            timeout=timeout,
        )
        try:
            self.scanner.start()
        except Exception:
            logging.exception("Failed to start scanner")
            messagebox.showerror("Start error", "Failed to start scanner. See log.")
            return
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.open_browser_btn.config(state="normal")
        self.progress.configure(maximum=len(self.merged_list))
        self.progress["value"] = 0
        self.progress_var.set(f"0 / {len(self.merged_list)}")
        with self.results_lock:
            self.results_master.clear()
        self._log(f"Scan started against {target_base} with {len(self.merged_list)} paths.")

    def stop_scan(self):
        """Stop the scanning process."""
        if not self.scanner:
            return
        self.scanner.stop()
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self._log("Stop requested. In-flight requests will finish but their results will NOT be added to the results table.")

    def _poll_queue(self):
        updated = False
        try:
            while True:
                try:
                    res: ScanResult = self.result_queue.get_nowait()
                except queue.Empty:
                    break
                keep_result = True
                if self.scanner:
                    with self.scanner._lock:
                        if self.scanner._suppress_results:
                            logging.debug("Dropping result for %s because suppress is set.", res.full_url)
                            keep_result = False
                if keep_result:
                    with self.results_lock:
                        self.results_master.append(res)
                    updated = True
        except Exception:
            logging.exception("Error polling queue")
        if updated:
            self.apply_filters()
        if self.scanner:
            total = self.scanner.total_to_submit()
            completed = len(self.results_master)
            self.progress["value"] = completed
            self.progress_var.set(f"{completed} / {total}")
            active = self.scanner.active_workers_count()
            submitted = self.scanner.submitted_count()
            if submitted >= total and active == 0:
                self.start_btn.config(state="normal")
                self.stop_btn.config(state="disabled")
        if self._running:
            self.root.after(UI_UPDATE_INTERVAL_MS, self._poll_queue)

    def apply_filters(self):
        with self.results_lock:
            res_list = list(self.results_master)
        selected_codes = set()
        for code, var in self.status_vars.items():
            if var.get():
                selected_codes.add(code)
        size_min = None
        size_max = None
        try:
            if self.size_min_var.get().strip():
                size_min = int(self.size_min_var.get().strip())
        except:
            size_min = None
        try:
            if self.size_max_var.get().strip():
                size_max = int(self.size_max_var.get().strip())
        except:
            size_max = None
        keyword = self.keyword_var.get().strip().lower()
        filtered = []
        for r in res_list:
            eff_status = r.status if r.status is not None else "Error"
            if len(selected_codes) > 0 and eff_status not in selected_codes:
                continue
            if size_min is not None and (r.size is None or r.size < size_min):
                continue
            if size_max is not None and (r.size is None or r.size > size_max):
                continue
            if keyword:
                combined = f"{r.path} {r.full_url} {r.note} {r.snippet}".lower()
                if keyword not in combined:
                    continue
            filtered.append(r)
        if self._sort_col:
            filtered.sort(key=self._sort_key_func(self._sort_col), reverse=self._sort_reverse)
        self.tree.delete(*self.tree.get_children())
        for r in filtered:
            status_val = "Error" if r.status is None else r.status
            vals = (
                r.index + 1,
                r.path,
                r.full_url,
                status_val,
                r.size if r.size is not None else "",
                f"{r.time_ms:.1f}" if (r.time_ms is not None) else "",
                (r.content_type or "")[:120],
                r.note,
            )
            tag = "status_other"
            if r.status is not None:
                if 200 <= r.status < 300:
                    tag = "status_2xx"
                elif 300 <= r.status < 400:
                    tag = "status_3xx"
                elif 400 <= r.status < 500:
                    tag = "status_4xx"
            else:
                tag = "status_error"  
            self.tree.insert("", "end", values=vals, tags=(tag,))
        self._log(f"Displayed {len(filtered)} results (filtered from {len(res_list)}).")  

    def _sort_tree(self, col, numeric: bool):
        """Sort the results table."""
        if self._sort_col == col:
            self._sort_reverse = not self._sort_reverse
        else:
            self._sort_col = col
            self._sort_reverse = False
        self.apply_filters()

    def _sort_key_func(self, col):
        """Get sort key function for column."""
        def key(r: ScanResult):
            if col == "index":
                return r.index
            if col == "path":
                return r.path or ""
            if col == "url":
                return r.full_url or ""
            if col == "status":
                return -2 if r.status is None else (r.status if r.status is not None else float('inf'))
            if col == "size":
                return r.size if r.size is not None else -1
            if col == "time":
                return r.time_ms if r.time_ms is not None else float("inf")
            if col == "type":
                return r.content_type or ""
            if col == "note":
                return r.note or ""
            return 0
        return key

    def _on_tree_select(self, _):
        """Handle tree selection event."""
        sel = self.tree.selection()
        if not sel:
            return
        item = sel[0]
        values = self.tree.item(item, "values")
        url = values[2]
        target_res = None
        with self.results_lock:
            for r in self.results_master:
                if r.full_url == url:
                    target_res = r
                    break
        if not target_res:
            return
        self._last_selected_url = target_res.full_url
        self.detail_text.configure(state="normal")
        self.detail_text.delete("1.0", tk.END)
        out = []
        out.append(f"Full URL: {target_res.full_url}")
        out.append(f"Path: {target_res.path}")
        out.append(f"Status: {target_res.status}")
        out.append(f"Size: {target_res.size}")
        out.append(f"Time (ms): {target_res.time_ms}")
        out.append(f"Content-Type: {target_res.content_type}")
        out.append("Headers:")
        for k, v in (target_res.headers or {}).items():
            out.append(f" {k}: {v}")
        out.append("\nSnippet (first 2000 chars):\n")
        out.append(target_res.snippet[:2000])
        self.detail_text.insert("1.0", "\n".join(out))
        self.detail_text.configure(state="disabled")

    def _open_selected_in_browser(self):
        """Open selected URL in browser."""
        sel = self.tree.selection()
        url = None
        if sel:
            item = sel[0]
            vals = self.tree.item(item, "values")
            url = vals[2]
        if not url and self._last_selected_url:
            url = self._last_selected_url
        if url:
            try:
                webbrowser.open(url)
            except Exception:
                logging.exception("Failed to open URL in browser: %s", url)

    def export_results(self, all_results: bool = True, fmt: str = "csv"):
        """Export results to file."""
        if all_results:
            with self.results_lock:
                data = list(self.results_master)
        else:
            sel = self.tree.selection()
            if not sel:
                messagebox.showinfo("Export", "No rows selected.")
                return
            urls = [self.tree.item(iid, "values")[2] for iid in sel]
            with self.results_lock:
                data = [r for r in self.results_master if r.full_url in urls]
        if not data:
            messagebox.showinfo("Export", "No data to export.")
            return
        if fmt == "csv":
            fpath = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
            if not fpath:
                return
            try:
                with open(fpath, "w", encoding="utf-8-sig", newline='') as fh:
                    writer = csv.writer(fh)
                    writer.writerow(["index", "path", "full_url", "status", "size", "time_ms", "content_type", "note"])
                    for r in data:
                        writer.writerow([r.index + 1, r.path, r.full_url, r.status, r.size, r.time_ms, r.content_type, r.note])
                self._log(f"Exported {len(data)} rows to {fpath}")
                messagebox.showinfo("Export", f"Exported {len(data)} rows to {fpath}")
            except Exception as e:
                logging.exception("Export CSV failed: %s", e)
                messagebox.showerror("Export error", f"Failed to export CSV: {e}")
        elif fmt == "json":
            fpath = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
            if not fpath:
                return
            try:
                obj = []
                for r in data:
                    obj.append({
                        "index": r.index + 1,
                        "path": r.path,
                        "full_url": r.full_url,
                        "status": r.status,
                        "size": r.size,
                        "time_ms": r.time_ms,
                        "content_type": r.content_type,
                        "note": r.note,
                        "headers": r.headers,
                        "snippet": r.snippet,
                    })
                with open(fpath, "w", encoding="utf-8") as fh:
                    json.dump(obj, fh, ensure_ascii=False, indent=2)
                self._log(f"Exported {len(data)} rows to {fpath}")
                messagebox.showinfo("Export", f"Exported {len(data)} rows to {fpath}")
            except Exception as e:
                logging.exception("Export JSON failed: %s", e)
                messagebox.showerror("Export error", f"Failed to export JSON: {e}")

    def _normalize_base_url(self, text: str) -> str:
        """Normalize the base URL."""
        text = text.strip()
        parsed = urlparse(text)
        if not parsed.scheme:
            text = "https://" + text
            parsed = urlparse(text)
        base = f"{parsed.scheme}://{parsed.netloc}"
        if parsed.path and parsed.path != "/":
            base += parsed.path.rstrip("/") + "/"
        return base

    def _log(self, msg: str):
        """Log a message to the UI and logger."""
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        self._log_list.append(f"{ts} {msg}")
        if len(self._log_list) > MAX_LOG_ENTRIES:
            self._log_list = self._log_list[-MAX_LOG_ENTRIES:]
        try:
            self.log_text.configure(state="normal")
            self.log_text.insert("end", f"{ts} {msg}\n")
            self.log_text.see("end")
            self.log_text.configure(state="disabled")
        except Exception:
            pass
        logging.info(msg)

    def _on_close(self):
        """Handle window close event."""
        if self.scanner:
            try:
                self.scanner.stop()
            except Exception:
                pass
        self._running = False
        self.root.after(200, self.root.destroy)

# Main entry point
def main():
    """Run the main application."""
    root = tk.Tk()
    app = AppGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()