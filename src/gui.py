import tkinter as tk
import customtkinter as ctk
from tkinter import filedialog, messagebox
import asyncio
import threading
import sys
import os
import logging
import queue
import time
import shutil
from pathlib import Path
import socket
from cryptography.fernet import Fernet

# Ensure project root is in path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.storage.chunker import FileManager
from src.security.encryptor import SecurityManager
from src.core.connection import P2PServer, P2PClient

# Configuration for CustomTkinter
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class QueueHandler(logging.Handler):
    """Redirects logging records to a queue for the GUI to consume."""
    def __init__(self, log_queue):
        super().__init__()
        self.log_queue = log_queue

    def emit(self, record):
        msg = self.format(record)
        self.log_queue.put({"type": "log", "text": msg})

class ModernFilePicker(ctk.CTkToplevel):
    def __init__(self, master, start_path=None, selection_type="file", title="Browse"):
        super().__init__(master)
        self.selection_type = selection_type
        self.result = None
        self.title(title)
        self.geometry("800x600")
        self.after(100, self.lift)

        self.current_path = os.path.abspath(start_path if start_path and os.path.exists(start_path) else os.getcwd())
        self.show_hidden = ctk.BooleanVar(value=False)
        self.selected_file_path = None
        
        # Layout
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)
        
        # Top Bar
        self.top_frame = ctk.CTkFrame(self)
        self.top_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        
        self.btn_up = ctk.CTkButton(self.top_frame, text="⬆ Up", width=60, command=self.go_up)
        self.btn_up.pack(side="left", padx=5)
        
        self.path_entry = ctk.CTkEntry(self.top_frame)
        self.path_entry.pack(side="left", fill="x", expand=True, padx=5)
        self.path_entry.bind("<Return>", self.on_path_entry)
        
        self.btn_go = ctk.CTkButton(self.top_frame, text="Go", width=40, command=self.on_path_entry)
        self.btn_go.pack(side="left", padx=5)

        self.chk_hidden = ctk.CTkCheckBox(self.top_frame, text="Hidden", variable=self.show_hidden, command=self.refresh_list, width=60)
        self.chk_hidden.pack(side="right", padx=5)

        if self.selection_type == "folder":
            self.btn_new_folder = ctk.CTkButton(self.top_frame, text="+ Folder", width=80, command=self.create_folder)
            self.btn_new_folder.pack(side="right", padx=5)

        # File List
        self.scroll = ctk.CTkScrollableFrame(self)
        self.scroll.grid(row=1, column=0, sticky="nsew", padx=10, pady=5)
        
        # Bottom Bar
        self.bottom_frame = ctk.CTkFrame(self)
        self.bottom_frame.grid(row=2, column=0, sticky="ew", padx=10, pady=10)
        
        self.selected_label = ctk.CTkLabel(self.bottom_frame, text="Selected: " + self.current_path, anchor="w")
        self.selected_label.pack(side="left", padx=10, fill="x", expand=True)
        
        self.btn_cancel = ctk.CTkButton(self.bottom_frame, text="Cancel", fg_color="transparent", border_width=1, command=self.destroy)
        self.btn_cancel.pack(side="right", padx=5)
        
        self.btn_select = ctk.CTkButton(self.bottom_frame, text="Select", command=self.confirm_selection)
        self.btn_select.pack(side="right", padx=5)

        self.refresh_list()
        self.transient(master)
        self.grab_set()
        self.wait_window()

    def refresh_list(self):
        for widget in self.scroll.winfo_children(): widget.destroy()
        self.path_entry.delete(0, "end")
        self.path_entry.insert(0, self.current_path)
        try: items = sorted(os.listdir(self.current_path))
        except Exception: return

        for item in items:
            if not self.show_hidden.get() and item.startswith('.'): continue
            full_path = os.path.join(self.current_path, item)
            is_dir = os.path.isdir(full_path)
            
            if not is_dir and self.selection_type == "folder": continue

            icon = "📁" if is_dir else "📄"
            cmd = (lambda p=full_path: self.enter_folder(p)) if is_dir else (lambda p=full_path: self.select_file(p))
            color = ("gray85", "gray25") if is_dir else "transparent"
            
            btn = ctk.CTkButton(self.scroll, text=f"{icon}  {item}", anchor="w", fg_color=color, text_color=("black", "white"), height=30, command=cmd)
            btn.pack(fill="x", padx=2, pady=1)

    def enter_folder(self, path):
        self.current_path = path
        self.selected_label.configure(text=f"Selected: {path}")
        self.refresh_list()

    def select_file(self, path):
        self.selected_file_path = path
        self.selected_label.configure(text=f"Selected: {os.path.basename(path)}")

    def go_up(self):
        parent = os.path.dirname(self.current_path)
        if parent != self.current_path: self.enter_folder(parent)

    def on_path_entry(self, event=None):
        p = self.path_entry.get()
        if os.path.exists(p) and os.path.isdir(p): self.enter_folder(p)

    def create_folder(self):
        dialog = ctk.CTkInputDialog(text="Folder Name:", title="New Folder")
        name = dialog.get_input()
        if name:
            try: os.mkdir(os.path.join(self.current_path, name)); self.refresh_list()
            except Exception as e: messagebox.showerror("Error", str(e))

    def confirm_selection(self):
        if self.selection_type == "folder": self.result = self.current_path
        else: self.result = self.selected_file_path
        if self.result: self.destroy()

class P2PGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("P2P File Sharer - Pro Dashboard")
        
        # Maximize window to cover full page
        self.geometry(f"{self.winfo_screenwidth()}x{self.winfo_screenheight()}")
        self.minsize(900, 600)
        try:
            self.attributes('-zoomed', True)
        except Exception:
            self.state('zoomed')

        # --- Fonts ---
        self.font_text = ctk.CTkFont(family="Segoe UI", size=14)
        self.font_bold = ctk.CTkFont(family="Segoe UI", size=18, weight="bold")

        # --- Configuration ---
        self.port = 8888
        if len(sys.argv) > 1:
            try:
                self.port = int(sys.argv[1])
            except ValueError:
                pass
        
        # --- Internal Logic & State ---
        self.msg_queue = queue.Queue()
        self.download_dest_path = Path.home() / "Downloads"
        self.active_download = None
        
        # Initialize Core Components
        self.fm = FileManager(storage_dir="./shared_files")
        
        key_path = "secret.key"
        if not os.path.exists(key_path):
            with open(key_path, "wb") as f:
                f.write(Fernet.generate_key())
            self.msg_queue.put({"type": "log", "text": "⚠️ Generated new secret.key"})
            self.msg_queue.put({"type": "log", "text": "ℹ️ Peers must share this key to communicate."})
            
        self.sm = SecurityManager(key_path=key_path)
        self.client = P2PClient(self.fm, self.sm)
        self.server = P2PServer("0.0.0.0", self.port, self.fm, self.sm)
        
        # Setup Asyncio Loop in Background Thread
        self.loop = asyncio.new_event_loop()
        self.server_thread = threading.Thread(target=self.start_async_loop, daemon=True)
        self.server_thread.start()

        self._setup_ui()
        
        # Start Polling Loop
        self.after(100, self.check_queue)
        self.log_message(f"System started on port {self.port}")
        
        # Setup Logging Redirect
        handler = QueueHandler(self.msg_queue)
        formatter = logging.Formatter('%(levelname)s: %(message)s')
        handler.setFormatter(formatter)
        logging.getLogger().addHandler(handler)
        logging.getLogger().setLevel(logging.INFO)

    def start_async_loop(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self.server.start())

    def _setup_ui(self):
        # Grid Layout: Row 0 = Tabs (weight 1), Row 1 = Log (weight 0)
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # 1. Tabview
        self.tabview = ctk.CTkTabview(self)
        self.tabview.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")
        
        # Make tab buttons fill the whole column/width
        self.tabview.grid_columnconfigure(0, weight=1)
        self.tabview._segmented_button.configure(
            font=ctk.CTkFont(family="Segoe UI", size=18, weight="bold"),
            height=50
        )
        self.tabview._segmented_button.grid(sticky="ew")
        self.tabview.add("Upload/Share")
        self.tabview.add("Download/Receive")

        self._setup_upload_tab()
        self._setup_download_tab()

        # 2. Log Window
        self.log_box = ctk.CTkTextbox(self, height=150, font=self.font_text)
        self.log_box.grid(row=1, column=0, padx=20, pady=(0, 20), sticky="ew")
        self.log_box.insert("0.0", "--- Event Log ---\n")
        self.log_box.configure(state="disabled")

    def _setup_upload_tab(self):
        tab = self.tabview.tab("Upload/Share")
        tab.grid_columnconfigure(0, weight=1)

        # Select Button
        self.btn_select = ctk.CTkButton(tab, text="Select File to Share", font=self.font_bold, height=50, command=self.select_file)
        self.btn_select.grid(row=0, column=0, padx=20, pady=30, sticky="ew")

        # Info Box
        self.info_frame = ctk.CTkFrame(tab)
        self.info_frame.grid(row=1, column=0, padx=20, pady=10, sticky="ew")
        self.info_frame.grid_columnconfigure(1, weight=1)

        self.vars_upload = {
            "path": ctk.StringVar(value="No file selected"),
            "size": ctk.StringVar(value="--"),
            "hash": ctk.StringVar(value="--")
        }

        rows = [
            ("File Path:", self.vars_upload["path"]),
            ("Size:", self.vars_upload["size"]),
            ("SHA-256 Hash:", self.vars_upload["hash"])
        ]

        for i, (label, var) in enumerate(rows):
            ctk.CTkLabel(self.info_frame, text=label, font=self.font_bold).grid(row=i, column=0, padx=10, pady=10, sticky="w")
            entry = ctk.CTkEntry(self.info_frame, textvariable=var, font=self.font_text, state="readonly")
            entry.grid(row=i, column=1, padx=10, pady=10, sticky="ew")
            
            if "Hash" in label:
                btn_copy = ctk.CTkButton(self.info_frame, text="Copy", width=100, height=40, font=self.font_bold, command=self.copy_hash)
                btn_copy.grid(row=i, column=2, padx=10, pady=10)

        # Start Seeding Button
        self.btn_seed = ctk.CTkButton(tab, text="Start Seeding", font=self.font_bold, height=50, fg_color="green", command=self.start_seeding)
        self.btn_seed.grid(row=2, column=0, padx=20, pady=30, sticky="ew")

        # Export Key Button
        self.btn_export = ctk.CTkButton(tab, text="Export Security Key", font=self.font_bold, height=40, fg_color="gray", command=self.export_key)
        self.btn_export.grid(row=3, column=0, padx=20, pady=(0, 20), sticky="ew")

    def _setup_download_tab(self):
        tab = self.tabview.tab("Download/Receive")
        tab.grid_columnconfigure(0, weight=1)

        # Destination Section
        dest_frame = ctk.CTkFrame(tab)
        dest_frame.grid(row=0, column=0, padx=10, pady=(30, 10), sticky="ew")
        dest_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(dest_frame, text="Destination:", font=self.font_bold).grid(row=0, column=0, padx=10, pady=10)
        self.entry_dest = ctk.CTkEntry(dest_frame, font=self.font_text)
        self.entry_dest.grid(row=0, column=1, padx=10, pady=10, sticky="ew")
        self.entry_dest.insert(0, str(self.download_dest_path))
        
        btn_browse = ctk.CTkButton(dest_frame, text="Browse Folder", font=self.font_bold, height=40, command=self.browse_dest)
        btn_browse.grid(row=0, column=2, padx=10, pady=10)

        # Source Section
        src_frame = ctk.CTkFrame(tab)
        src_frame.grid(row=1, column=0, padx=10, pady=10, sticky="ew")
        src_frame.grid_columnconfigure(1, weight=1)

        # IP/Port
        conn_frame = ctk.CTkFrame(src_frame, fg_color="transparent")
        conn_frame.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 10))
        
        ctk.CTkLabel(conn_frame, text="Peer IPs (comma sep):", font=self.font_text).pack(side="left", padx=5)
        self.entry_ip = ctk.CTkEntry(conn_frame, width=150, font=self.font_text)
        self.entry_ip.pack(side="left", padx=5)
        # Default empty to encourage auto-discovery, or keep 127.0.0.1

        ctk.CTkLabel(conn_frame, text="Port:", font=self.font_text).pack(side="left", padx=5)
        self.entry_port = ctk.CTkEntry(conn_frame, width=80, font=self.font_text)
        self.entry_port.pack(side="left", padx=5)
        self.entry_port.insert(0, "8888")

        # Hash
        ctk.CTkLabel(src_frame, text="Source File Hash:", font=self.font_bold).grid(row=1, column=0, padx=10, pady=10, sticky="w")
        self.entry_hash = ctk.CTkEntry(src_frame, font=self.font_text, placeholder_text="Paste SHA-256 Hash here...")
        self.entry_hash.grid(row=1, column=1, padx=10, pady=10, sticky="ew")
        
        btn_paste = ctk.CTkButton(src_frame, text="Paste", width=100, height=40, font=self.font_bold, command=self.paste_hash)
        btn_paste.grid(row=1, column=2, padx=10, pady=10)

        # Action Buttons (Connect & Test)
        action_frame = ctk.CTkFrame(tab, fg_color="transparent")
        action_frame.grid(row=2, column=0, padx=20, pady=20, sticky="ew")
        action_frame.grid_columnconfigure(0, weight=3)
        action_frame.grid_columnconfigure(1, weight=1)

        self.btn_connect = ctk.CTkButton(action_frame, text="Initiate Peer Connection", font=self.font_bold, height=50, command=self.initiate_download)
        self.btn_connect.grid(row=0, column=0, padx=(0, 10), sticky="ew")

        self.btn_test = ctk.CTkButton(action_frame, text="Test Ping", font=self.font_bold, height=50, fg_color="gray", command=self.test_connection)
        self.btn_test.grid(row=0, column=1, padx=(10, 0), sticky="ew")

        # Progress Section
        prog_frame = ctk.CTkFrame(tab)
        prog_frame.grid(row=3, column=0, padx=10, pady=10, sticky="ew")
        prog_frame.grid_columnconfigure(0, weight=1)

        self.lbl_status = ctk.CTkLabel(prog_frame, text="Status: Idle", font=self.font_text)
        self.lbl_status.grid(row=0, column=0, sticky="w", padx=10, pady=5)

        self.lbl_speed = ctk.CTkLabel(prog_frame, text="Speed: 0.0 MB/s", font=self.font_text)
        self.lbl_speed.grid(row=0, column=1, sticky="e", padx=10, pady=5)

        self.progress_bar = ctk.CTkProgressBar(prog_frame, height=20)
        self.progress_bar.grid(row=1, column=0, columnspan=2, padx=10, pady=(5, 15), sticky="ew")
        self.progress_bar.set(0)

    # --- Logic & Threading ---

    def log_message(self, msg):
        self.log_box.configure(state="normal")
        self.log_box.insert("end", f"[{time.strftime('%H:%M:%S')}] {msg}\n")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def check_queue(self):
        try:
            while True:
                msg = self.msg_queue.get_nowait()
                if msg['type'] == 'log':
                    self.log_message(msg['text'])
                elif msg['type'] == 'progress':
                    self.update_progress(msg)
                elif msg['type'] == 'seed_complete':
                    # Only update if the currently selected file matches the one that just finished hashing
                    if self.vars_upload["path"].get() == msg['path']:
                        self.vars_upload["hash"].set(msg['hash'])
                        self.log_message(f"Seeding active. Hash: {msg['hash']}")
        except queue.Empty:
            pass
        self.after(100, self.check_queue)

    def select_file(self):
        picker = ModernFilePicker(self, selection_type="file", title="Select File to Share")
        if picker.result:
            path = picker.result
            p = Path(path)
            self.vars_upload["path"].set(str(p))
            size_mb = p.stat().st_size / (1024 * 1024)
            self.vars_upload["size"].set(f"{size_mb:.2f} MB")
            self.vars_upload["hash"].set("Pending Seeding...")

    def start_seeding(self):
        path_str = self.vars_upload["path"].get()
        if not os.path.exists(path_str):
            messagebox.showerror("Error", "Invalid file path")
            return
        try:
            # Run in thread to avoid freeze
            def seed_task():
                try:
                    manifest = self.fm.slice_file(path_str)
                    self.msg_queue.put({"type": "log", "text": f"Seeding started: {manifest['filename']}"})
                    self.msg_queue.put({"type": "seed_complete", "hash": manifest['file_hash'], "path": path_str})
                except Exception as e:
                    self.msg_queue.put({"type": "log", "text": f"Error seeding: {e}"})

            threading.Thread(target=seed_task, daemon=True).start()
            self.log_message("Hashing file... please wait.")
        except Exception as e:
            self.log_message(f"Error: {e}")

    def browse_dest(self):
        picker = ModernFilePicker(self, start_path=str(self.download_dest_path), selection_type="folder", title="Select Download Folder")
        if picker.result:
            path = picker.result
            self.entry_dest.delete(0, "end")
            self.entry_dest.insert(0, path)
            self.download_dest_path = Path(path)

    def initiate_download(self):
        ip_str = self.entry_ip.get().strip()
        try:
            port = int(self.entry_port.get())
        except ValueError:
            messagebox.showerror("Error", "Invalid Port")
            return
        f_hash = self.entry_hash.get().strip()
        
        if not f_hash:
            messagebox.showwarning("Warning", "Missing File Hash")
            return

        self.lbl_status.configure(text="Status: Initializing...")
        self.progress_bar.set(0)
        self.active_download = {"start_time": time.time(), "bytes": 0}
        
        if not ip_str:
            # Auto-Discovery Mode
            self.log_message("Auto-detecting peers via UDP...")
            self.lbl_status.configure(text="Status: Searching for peers...")
            
            def discovery_task():
                future = asyncio.run_coroutine_threadsafe(
                    self.client.discover_peers(f_hash), 
                    self.loop
                )
                try:
                    ips = future.result(timeout=5)
                    if ips:
                        self.msg_queue.put({"type": "log", "text": f"Found peers: {', '.join(ips)}"})
                        # Update UI
                        self.after(0, lambda: self.entry_ip.delete(0, "end"))
                        self.after(0, lambda: self.entry_ip.insert(0, ", ".join(ips)))
                        # Start Download
                        self._start_download_process(ips, port, f_hash)
                    else:
                        self.msg_queue.put({"type": "log", "text": "No peers found."})
                        self.after(0, lambda: self.lbl_status.configure(text="Status: No peers found"))
                except Exception as e:
                    self.msg_queue.put({"type": "log", "text": f"Discovery error: {e}"})

            threading.Thread(target=discovery_task, daemon=True).start()
        else:
            # Manual Mode
            ips = [ip.strip() for ip in ip_str.split(',') if ip.strip()]
            self._start_download_process(ips, port, f_hash)

    def _start_download_process(self, ips, port, f_hash):
        # Callback to bridge asyncio -> GUI
        def progress_callback(file_hash, filename, chunk_index, total_chunks, bytes_len):
            self.msg_queue.put({
                "type": "progress",
                "file_hash": file_hash,
                "filename": filename,
                "chunk_index": chunk_index,
                "total_chunks": total_chunks,
                "bytes": bytes_len
            })

        asyncio.run_coroutine_threadsafe(
            self.client.download_file(ips, port, f_hash, progress_callback), 
            self.loop
        )
        self.log_message(f"Requesting {f_hash} from peers: {ips}")

    def update_progress(self, msg):
        # Calculate speed
        now = time.time()
        if self.active_download:
            self.active_download["bytes"] += msg['bytes']
            elapsed = now - self.active_download["start_time"]
            if elapsed > 0:
                speed = (self.active_download["bytes"] / (1024*1024)) / elapsed
                self.lbl_speed.configure(text=f"Speed: {speed:.2f} MB/s")

        percent = msg['chunk_index'] / msg['total_chunks']
        self.progress_bar.set(percent)
        self.lbl_status.configure(text=f"Status: Downloading chunk {msg['chunk_index']}/{msg['total_chunks']}")
        
        if msg['chunk_index'] == msg['total_chunks']:
            self.lbl_status.configure(text="Status: Completed")
            self.log_message(f"Download finished: {msg['filename']}")
            self.finalize_download(msg['filename'])

    def finalize_download(self, filename):
        src = Path(self.fm.storage_dir) / filename
        dest_dir = Path(self.entry_dest.get())
        dest = dest_dir / filename
        try:
            if not dest_dir.exists(): dest_dir.mkdir(parents=True, exist_ok=True)
            if src.exists():
                shutil.copy(src, dest)
                self.log_message(f"File saved to: {dest}")
            else:
                self.log_message(f"Error: Source file {src} not found.")
        except Exception as e:
            self.log_message(f"Error moving file: {e}")

    def copy_hash(self):
        h = self.vars_upload["hash"].get()
        if h and h != "--" and h != "Pending Seeding...":
            self.clipboard_clear()
            self.clipboard_append(h)
            self.log_message("Hash copied to clipboard!")

    def paste_hash(self):
        try:
            text = self.clipboard_get()
            self.entry_hash.delete(0, "end")
            self.entry_hash.insert(0, text)
        except:
            pass

    def test_connection(self):
        ip_str = self.entry_ip.get().strip()
        try:
            port = int(self.entry_port.get())
        except ValueError:
            messagebox.showerror("Error", "Invalid Port")
            return
            
        if not ip_str:
            messagebox.showwarning("Warning", "Enter Peer IP to test")
            return

        ips = [ip.strip() for ip in ip_str.split(',') if ip.strip()]
        self.log_message(f"Testing TCP connection to {ips} on port {port}...")
        
        def ping_task():
            for ip in ips:
                try:
                    s = socket.create_connection((ip, port), timeout=3)
                    s.close()
                    self.msg_queue.put({"type": "log", "text": f"✅ Online: {ip}:{port} is reachable!"})
                except Exception as e:
                    self.msg_queue.put({"type": "log", "text": f"❌ Offline: {ip}:{port} ({e})"})

        threading.Thread(target=ping_task, daemon=True).start()

    def export_key(self):
        key_path = "secret.key"
        if os.path.exists(key_path):
            with open(key_path, "rb") as f:
                key_data = f.read()
            
            dest = filedialog.asksaveasfilename(defaultextension=".key", initialfile="secret.key", title="Save Security Key")
            if dest:
                with open(dest, "wb") as f:
                    f.write(key_data)
                self.log_message(f"Key exported to: {dest}")
        else:
            messagebox.showerror("Error", "Secret key not found!")

if __name__ == "__main__":
    app = P2PGUI()
    app.mainloop()