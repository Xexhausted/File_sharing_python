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

# Ensure project root is in path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.storage.chunker import FileManager
from src.security.encryptor import SecurityManager
from src.core.connection import P2PServer, P2PClient

# Configuration for CustomTkinter
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class P2PGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("P2P File Sharer - Pro Dashboard")
        self.geometry("900x750")

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
        self.sm = SecurityManager(key_path="secret.key")
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

        labels = ["File Path:", "Size:", "SHA-256 Hash:"]
        self.vars_upload = {
            "path": ctk.StringVar(value="No file selected"),
            "size": ctk.StringVar(value="--"),
            "hash": ctk.StringVar(value="--")
        }

        for i, label in enumerate(labels):
            ctk.CTkLabel(self.info_frame, text=label, font=self.font_bold).grid(row=i, column=0, padx=10, pady=10, sticky="w")
            entry = ctk.CTkEntry(self.info_frame, textvariable=list(self.vars_upload.values())[i], font=self.font_text, state="readonly")
            entry.grid(row=i, column=1, padx=10, pady=10, sticky="ew")

        # Start Seeding Button
        self.btn_seed = ctk.CTkButton(tab, text="Start Seeding", font=self.font_bold, height=50, fg_color="green", command=self.start_seeding)
        self.btn_seed.grid(row=2, column=0, padx=20, pady=30, sticky="ew")

    def _setup_download_tab(self):
        tab = self.tabview.tab("Download/Receive")
        tab.grid_columnconfigure(0, weight=1)

        # Destination Section
        dest_frame = ctk.CTkFrame(tab)
        dest_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
        dest_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(dest_frame, text="Destination:", font=self.font_bold).grid(row=0, column=0, padx=10, pady=10)
        self.entry_dest = ctk.CTkEntry(dest_frame, font=self.font_text)
        self.entry_dest.grid(row=0, column=1, padx=10, pady=10, sticky="ew")
        self.entry_dest.insert(0, str(self.download_dest_path))
        
        btn_browse = ctk.CTkButton(dest_frame, text="Browse Folder", font=self.font_text, command=self.browse_dest)
        btn_browse.grid(row=0, column=2, padx=10, pady=10)

        # Source Section
        src_frame = ctk.CTkFrame(tab)
        src_frame.grid(row=1, column=0, padx=10, pady=10, sticky="ew")
        src_frame.grid_columnconfigure(1, weight=1)

        # IP/Port
        conn_frame = ctk.CTkFrame(src_frame, fg_color="transparent")
        conn_frame.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 10))
        
        ctk.CTkLabel(conn_frame, text="Peer IP:", font=self.font_text).pack(side="left", padx=5)
        self.entry_ip = ctk.CTkEntry(conn_frame, width=150, font=self.font_text)
        self.entry_ip.pack(side="left", padx=5)
        self.entry_ip.insert(0, "127.0.0.1")

        ctk.CTkLabel(conn_frame, text="Port:", font=self.font_text).pack(side="left", padx=5)
        self.entry_port = ctk.CTkEntry(conn_frame, width=80, font=self.font_text)
        self.entry_port.pack(side="left", padx=5)
        self.entry_port.insert(0, "8888")

        # Hash
        ctk.CTkLabel(src_frame, text="Source File Hash:", font=self.font_bold).grid(row=1, column=0, padx=10, pady=10, sticky="w")
        self.entry_hash = ctk.CTkEntry(src_frame, font=self.font_text, placeholder_text="Paste SHA-256 Hash here...")
        self.entry_hash.grid(row=1, column=1, padx=10, pady=10, sticky="ew")

        # Initiate Button
        self.btn_connect = ctk.CTkButton(tab, text="Initiate Peer Connection", font=self.font_bold, height=50, command=self.initiate_download)
        self.btn_connect.grid(row=2, column=0, padx=20, pady=20, sticky="ew")

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
                    self.vars_upload["hash"].set(msg['hash'])
                    self.log_message(f"Seeding active. Hash: {msg['hash']}")
        except queue.Empty:
            pass
        self.after(100, self.check_queue)

    def select_file(self):
        path = filedialog.askopenfilename()
        if path:
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
                    self.msg_queue.put({"type": "seed_complete", "hash": manifest['file_hash']})
                except Exception as e:
                    self.msg_queue.put({"type": "log", "text": f"Error seeding: {e}"})

            threading.Thread(target=seed_task, daemon=True).start()
            self.log_message("Hashing file... please wait.")
        except Exception as e:
            self.log_message(f"Error: {e}")

    def browse_dest(self):
        path = filedialog.askdirectory()
        if path:
            self.entry_dest.delete(0, "end")
            self.entry_dest.insert(0, path)
            self.download_dest_path = Path(path)

    def initiate_download(self):
        ip = self.entry_ip.get()
        try:
            port = int(self.entry_port.get())
        except ValueError:
            messagebox.showerror("Error", "Invalid Port")
            return
        f_hash = self.entry_hash.get().strip()
        
        if not ip or not f_hash:
            messagebox.showwarning("Warning", "Missing IP or Hash")
            return

        self.lbl_status.configure(text="Status: Connecting...")
        self.progress_bar.set(0)
        self.active_download = {"start_time": time.time(), "bytes": 0}
        
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
            self.client.download_file([ip], port, f_hash, progress_callback), 
            self.loop
        )
        self.log_message(f"Requesting {f_hash} from {ip}:{port}")

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

if __name__ == "__main__":
    app = P2PGUI()
    app.mainloop()