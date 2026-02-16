import tkinter as tk
import customtkinter as ctk
from tkinter import filedialog, messagebox, ttk
import asyncio
import threading
import sys
import os
import logging
import queue
import time

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
        self.title("P2P File Sharer - Dashboard")
        self.geometry("1100x700")

        # --- Configuration ---
        self.port = 8888
        if len(sys.argv) > 1:
            try:
                self.port = int(sys.argv[1])
            except ValueError:
                pass
        
        # --- Internal Logic & State ---
        self.msg_queue = queue.Queue()
        self.active_downloads = {}  # hash -> {filename, total_chunks, downloaded_chunks, speed_history}
        self.start_time = time.time()
        
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

    def start_async_loop(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self.server.start())

    def _setup_ui(self):
        # Grid Layout
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # --- Sidebar ---
        self.sidebar = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar.grid(row=0, column=0, rowspan=2, sticky="nsew")
        self.sidebar.grid_rowconfigure(5, weight=1)

        ctk.CTkLabel(self.sidebar, text="P2P Node", font=ctk.CTkFont(size=20, weight="bold")).grid(row=0, column=0, padx=20, pady=(20, 10))
        ctk.CTkLabel(self.sidebar, text=f"Port: {self.port}", text_color="gray").grid(row=1, column=0, padx=20, pady=(0, 20))

        self.btn_all = ctk.CTkButton(self.sidebar, text="All Transfers", command=lambda: self.filter_view("all"), fg_color="transparent", border_width=2, text_color=("gray10", "#DCE4EE"))
        self.btn_all.grid(row=2, column=0, padx=20, pady=10)
        
        self.btn_dl = ctk.CTkButton(self.sidebar, text="Downloading", command=lambda: self.filter_view("downloading"), fg_color="transparent", border_width=2, text_color=("gray10", "#DCE4EE"))
        self.btn_dl.grid(row=3, column=0, padx=20, pady=10)

        # Action Buttons
        ctk.CTkButton(self.sidebar, text="＋ Share File", command=self.share_file).grid(row=6, column=0, padx=20, pady=10)
        ctk.CTkButton(self.sidebar, text="⬇ Download", command=self.open_download_dialog).grid(row=7, column=0, padx=20, pady=(10, 20))

        # --- Main Dashboard ---
        self.main_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        self.main_frame.grid_rowconfigure(1, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1)

        # Header
        ctk.CTkLabel(self.main_frame, text="Dashboard", font=ctk.CTkFont(size=24)).grid(row=0, column=0, sticky="w", pady=(0, 10))

        # Treeview (List of Files)
        # CustomTkinter doesn't have a Treeview, so we wrap a ttk.Treeview in a frame
        self.tree_frame = ctk.CTkFrame(self.main_frame)
        self.tree_frame.grid(row=1, column=0, sticky="nsew")
        self.tree_frame.grid_rowconfigure(0, weight=1)
        self.tree_frame.grid_columnconfigure(0, weight=1)

        self._setup_treeview_style()
        
        self.columns = ("filename", "size", "progress", "status", "speed")
        self.tree = ttk.Treeview(self.tree_frame, columns=self.columns, show="headings", selectmode="browse")
        
        self.tree.heading("filename", text="Filename")
        self.tree.heading("size", text="Size")
        self.tree.heading("progress", text="Progress")
        self.tree.heading("status", text="Status")
        self.tree.heading("speed", text="Down Speed")
        
        self.tree.column("filename", width=250)
        self.tree.column("size", width=80)
        self.tree.column("progress", width=100)
        self.tree.column("status", width=100)
        self.tree.column("speed", width=100)
        
        self.tree.grid(row=0, column=0, sticky="nsew", padx=2, pady=2)
        self.tree.bind("<<TreeviewSelect>>", self.on_tree_select)

        # --- Info Panel (Bottom) ---
        self.info_frame = ctk.CTkFrame(self.main_frame, height=150)
        self.info_frame.grid(row=2, column=0, sticky="ew", pady=(20, 0))
        self.info_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(self.info_frame, text="Selected File Details", font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, sticky="w", padx=10, pady=5)
        
        self.lbl_filename = ctk.CTkLabel(self.info_frame, text="No file selected")
        self.lbl_filename.grid(row=1, column=0, sticky="w", padx=10)

        self.progress_bar = ctk.CTkProgressBar(self.info_frame)
        self.progress_bar.grid(row=2, column=0, columnspan=2, sticky="ew", padx=10, pady=10)
        self.progress_bar.set(0)

        self.lbl_stats = ctk.CTkLabel(self.info_frame, text="ETA: -- | Peers: 0 | Hash: --")
        self.lbl_stats.grid(row=3, column=0, sticky="w", padx=10, pady=(0, 10))

        # --- Footer (Speed Stats) ---
        self.footer = ctk.CTkFrame(self, height=30, corner_radius=0)
        self.footer.grid(row=1, column=1, sticky="ew")
        
        self.lbl_total_down = ctk.CTkLabel(self.footer, text="Total Down: 0 KB/s", text_color="#4CC2FF")
        self.lbl_total_down.pack(side="right", padx=20)

    def _setup_treeview_style(self):
        style = ttk.Style()
        style.theme_use("clam")
        
        # Dark theme colors
        bg_color = "#2b2b2b"
        fg_color = "white"
        header_bg = "#343638"
        
        style.configure("Treeview", background=bg_color, foreground=fg_color, fieldbackground=bg_color, borderwidth=0, rowheight=25)
        style.map('Treeview', background=[('selected', '#1f538d')])
        
        style.configure("Treeview.Heading", background=header_bg, foreground=fg_color, relief="flat")
        style.map("Treeview.Heading", background=[('active', '#404244')])

    # --- Logic & Threading ---

    def check_queue(self):
        """Polls the queue for updates from the networking thread."""
        try:
            while True:
                msg = self.msg_queue.get_nowait()
                self.process_message(msg)
        except queue.Empty:
            pass
        
        self.update_speeds()
        self.after(100, self.check_queue)

    def process_message(self, msg):
        """Handles messages from the background thread."""
        if msg['type'] == 'progress':
            f_hash = msg['file_hash']
            filename = msg['filename']
            chunk_idx = msg['chunk_index']
            total = msg['total_chunks']
            bytes_received = msg['bytes']
            
            # Update State
            if f_hash not in self.active_downloads:
                # Create entry in Treeview if not exists
                if not self.tree.exists(f_hash):
                    self.tree.insert("", "end", iid=f_hash, values=(filename, "Calculating...", "0%", "Downloading", "0 KB/s"))
                self.active_downloads[f_hash] = {
                    "filename": filename,
                    "total": total,
                    "done": 0,
                    "speed_history": [] # (timestamp, bytes)
                }
            
            state = self.active_downloads[f_hash]
            state['done'] = chunk_idx
            state['speed_history'].append((time.time(), bytes_received))
            
            # Update Treeview
            percent = int((chunk_idx / total) * 100)
            self.tree.set(f_hash, "progress", f"{percent}%")
            
            # Update Detail Panel if selected
            selected = self.tree.selection()
            if selected and selected[0] == f_hash:
                self.progress_bar.set(chunk_idx / total)
                self.lbl_filename.configure(text=f"{filename} ({chunk_idx}/{total} chunks)")

    def update_speeds(self):
        """Calculates real-time speed based on recent history."""
        now = time.time()
        total_speed = 0
        
        for f_hash, state in self.active_downloads.items():
            # Filter history for last 1 second
            state['speed_history'] = [(t, b) for t, b in state['speed_history'] if now - t <= 1.0]
            
            # Sum bytes
            bytes_in_last_sec = sum(b for t, b in state['speed_history'])
            speed_kb = bytes_in_last_sec / 1024
            total_speed += speed_kb
            
            # Update Treeview Speed Column
            if self.tree.exists(f_hash):
                self.tree.set(f_hash, "speed", f"{speed_kb:.1f} KB/s")
                if state['done'] == state['total']:
                    self.tree.set(f_hash, "status", "Completed")
                    self.tree.set(f_hash, "speed", "0 KB/s")

        self.lbl_total_down.configure(text=f"Total Down: {total_speed:.1f} KB/s")

    def browse_file(self):
        filename = filedialog.askopenfilename()
        if filename:
            return filename
        return None

    def share_file(self):
        filepath = self.browse_file()
        if not filepath:
            return
        try:
            manifest = self.fm.slice_file(filepath)
            
            # Add to treeview as Seeding
            f_hash = manifest['file_hash']
            fname = manifest['filename']
            size_mb = manifest['size'] / (1024*1024)
            
            if not self.tree.exists(f_hash):
                self.tree.insert("", "end", iid=f_hash, values=(fname, f"{size_mb:.2f} MB", "100%", "Seeding", "0 KB/s"))
            
            # Show Hash
            dialog = ctk.CTkInputDialog(text="File Shared! Copy Hash:", title="Share Success")
            dialog.entry.insert(0, f_hash)
            dialog.wait_window()
            
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def open_download_dialog(self):
        dialog = ctk.CTkToplevel(self)
        dialog.title("Download File")
        dialog.geometry("400x300")
        
        ctk.CTkLabel(dialog, text="Peer IP:").pack(pady=5)
        entry_ip = ctk.CTkEntry(dialog)
        entry_ip.pack(pady=5)
        entry_ip.insert(0, "127.0.0.1")
        
        ctk.CTkLabel(dialog, text="Peer Port:").pack(pady=5)
        entry_port = ctk.CTkEntry(dialog)
        entry_port.pack(pady=5)
        entry_port.insert(0, "8888")
        
        ctk.CTkLabel(dialog, text="File Hash:").pack(pady=5)
        entry_hash = ctk.CTkEntry(dialog)
        entry_hash.pack(pady=5)
        
        def confirm():
            ip = entry_ip.get()
            try: port = int(entry_port.get())
            except: return
            f_hash = entry_hash.get()
            
            if ip and f_hash:
                self.start_download(ip, port, f_hash)
                dialog.destroy()
                
        ctk.CTkButton(dialog, text="Start Download", command=confirm).pack(pady=20)

    def start_download(self, ip, port, f_hash):
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

    def on_tree_select(self, event):
        selected = self.tree.selection()
        if not selected: return
        f_hash = selected[0]
        
        if f_hash in self.active_downloads:
            data = self.active_downloads[f_hash]
            self.lbl_filename.configure(text=data['filename'])
            self.lbl_stats.configure(text=f"Hash: {f_hash[:10]}...")
            if data['total'] > 0:
                self.progress_bar.set(data['done'] / data['total'])

    def filter_view(self, mode):
        # Simple filter implementation could hide/show tree items
        # For now, we just log it or could detach items
        pass

if __name__ == "__main__":
    app = P2PGUI()
    app.mainloop()