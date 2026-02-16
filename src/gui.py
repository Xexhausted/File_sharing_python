import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
import asyncio
import threading
import sys
import os
import logging

# Ensure project root is in path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.storage.chunker import FileManager
from src.security.encryptor import SecurityManager
from src.core.connection import P2PServer, P2PClient

class TextHandler(logging.Handler):
    """Redirect logging to a Tkinter Text widget."""
    def __init__(self, text_widget):
        super().__init__()
        self.text_widget = text_widget

    def emit(self, record):
        msg = self.format(record)
        def append():
            self.text_widget.configure(state='normal')
            self.text_widget.insert(tk.END, msg + '\n')
            self.text_widget.configure(state='disabled')
            self.text_widget.yview(tk.END)
        # Schedule update on main GUI thread
        self.text_widget.after(0, append)

class P2PGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("P2P File Sharer")
        self.root.geometry("700x600")

        # --- Configuration ---
        self.port = 8888
        if len(sys.argv) > 1:
            try:
                self.port = int(sys.argv[1])
            except ValueError:
                pass
        
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
        self._setup_logging()

    def start_async_loop(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self.server.start())

    def _setup_ui(self):
        # Header
        header = tk.Label(self.root, text=f"P2P Node Running on Port: {self.port}", font=("Arial", 14, "bold"))
        header.pack(pady=10)

        # Share Section
        share_frame = tk.LabelFrame(self.root, text="Share File", padx=10, pady=10)
        share_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.file_path_var = tk.StringVar()
        tk.Entry(share_frame, textvariable=self.file_path_var, width=50).pack(side=tk.LEFT, padx=5)
        tk.Button(share_frame, text="Browse...", command=self.browse_file).pack(side=tk.LEFT)
        tk.Button(share_frame, text="Share", command=self.share_file, bg="#dddddd").pack(side=tk.LEFT, padx=5)

        # Download Section
        dl_frame = tk.LabelFrame(self.root, text="Download File", padx=10, pady=10)
        dl_frame.pack(fill=tk.X, padx=10, pady=5)

        tk.Label(dl_frame, text="Peer IP:").grid(row=0, column=0, sticky=tk.W)
        self.peer_ip_var = tk.StringVar(value="127.0.0.1")
        tk.Entry(dl_frame, textvariable=self.peer_ip_var, width=15).grid(row=0, column=1, padx=5, sticky=tk.W)

        tk.Label(dl_frame, text="Peer Port:").grid(row=0, column=2, sticky=tk.W)
        self.peer_port_var = tk.StringVar(value="8888")
        tk.Entry(dl_frame, textvariable=self.peer_port_var, width=10).grid(row=0, column=3, padx=5, sticky=tk.W)

        tk.Label(dl_frame, text="File Hash:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.file_hash_var = tk.StringVar()
        tk.Entry(dl_frame, textvariable=self.file_hash_var, width=50).grid(row=1, column=1, columnspan=3, sticky=tk.W, padx=5)

        tk.Button(dl_frame, text="Start Download", command=self.start_download, bg="#dddddd").grid(row=2, column=1, pady=10, sticky=tk.W)

        # Logs Section
        log_frame = tk.LabelFrame(self.root, text="Activity Log", padx=10, pady=10)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.log_area = scrolledtext.ScrolledText(log_frame, state='disabled', height=10)
        self.log_area.pack(fill=tk.BOTH, expand=True)

    def _setup_logging(self):
        handler = TextHandler(self.log_area)
        formatter = logging.Formatter('%(asctime)s - %(message)s')
        handler.setFormatter(formatter)
        logging.getLogger().addHandler(handler)
        logging.getLogger().setLevel(logging.INFO)

    def browse_file(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.file_path_var.set(filename)

    def share_file(self):
        filepath = self.file_path_var.get()
        if not filepath:
            messagebox.showwarning("Warning", "Please select a file.")
            return
        try:
            manifest = self.fm.slice_file(filepath)
            logging.info(f"File Shared! Hash: {manifest['file_hash']}")
            self.file_hash_var.set(manifest['file_hash'])
        except Exception as e:
            logging.error(f"Share Error: {e}")
            messagebox.showerror("Error", str(e))

    def start_download(self):
        ip = self.peer_ip_var.get()
        try: port = int(self.peer_port_var.get())
        except ValueError: messagebox.showerror("Error", "Invalid Port"); return
        f_hash = self.file_hash_var.get()
        if not ip or not f_hash: messagebox.showwarning("Warning", "Missing IP or Hash"); return

        logging.info(f"Requesting {f_hash} from {ip}:{port}...")
        asyncio.run_coroutine_threadsafe(self.client.download_file([ip], port, f_hash), self.loop)

if __name__ == "__main__":
    root = tk.Tk()
    app = P2PGUI(root)
    root.mainloop()