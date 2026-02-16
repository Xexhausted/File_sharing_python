import asyncio
import sys
import logging
import os
from cryptography.fernet import Fernet

# Ensure src is in path if running from src directly
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.storage.chunker import FileManager
from src.security.encryptor import SecurityManager
from src.core.connection import P2PServer, P2PClient

# Configure Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

async def main():    # Parse port from command line args
    port = 8888
    if len(sys.argv) > 1:
        port = int(sys.argv[1])

    # 1. Setup Managers
    storage_dir = "./shared_files"
    fm = FileManager(storage_dir=storage_dir)
    
    key_path = os.path.join(storage_dir, "secret.key")
    if not os.path.exists(key_path):
        print("Generating new security key...")
        with open(key_path, "wb") as f:
            f.write(Fernet.generate_key())
            
    sm = SecurityManager(key_path=key_path)
    
    # 2. Start Server
    server = P2PServer("0.0.0.0", port, fm, sm)
    asyncio.create_task(server.start())
    
    # 3. Setup Client
    client = P2PClient(fm, sm)
    
    print("\n=== P2P Servent Started ===")
    print("Commands:")
    print("  share [filepath]               -> Slice and index a file")
    print("  download [peer_ip] [peer_port] [file_hash] -> Download a file")
    print("  ls                             -> List shared files")
    print("  exit                           -> Quit")
    print("===========================\n")
    
    # 4. CLI Loop
    loop = asyncio.get_running_loop()
    while True:
        try:
            line = await loop.run_in_executor(None, sys.stdin.readline)
            if not line: break
            parts = line.strip().split()
            if not parts: continue
            
            cmd = parts[0]
            
            if cmd == "share":
                if len(parts) < 2: print("Usage: share [filepath]"); continue
                try:
                    manifest = fm.slice_file(parts[1])
                    print(f"✅ File Shared. Hash: {manifest['file_hash']}")
                except Exception as e: print(f"❌ Error: {e}")
                    
            elif cmd == "download":
                if len(parts) < 4: print("Usage: download [peer_ip] [peer_port] [file_hash]"); continue
                asyncio.create_task(client.download_file([parts[1]], int(parts[2]), parts[3]))
                
            elif cmd == "ls":
                print(f"Files in {fm.storage_dir}:")
                for f in os.listdir(fm.storage_dir): print(f"  {f}")

            elif cmd == "exit": break
        except KeyboardInterrupt: break

if __name__ == "__main__":
    asyncio.run(main())