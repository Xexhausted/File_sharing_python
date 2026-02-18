"""
P2P File Sharing - CLI Interface
Secure peer-to-peer file sharing with asymmetric encryption
"""
import asyncio
import sys
import logging
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.storage.chunker import FileManager
from src.security.crypto import AsymmetricCrypto
from src.core.connection import P2PServer, P2PClient

# Configure Logging
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


async def main():
    """Main entry point for CLI interface."""
    # Parse port from command line args
    port = 8888
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            logger.error("Invalid port number")
            sys.exit(1)

    # Initialize components
    fm = FileManager(storage_dir="./shared_files")
    crypto = AsymmetricCrypto(keys_dir="./keys")
    
    # Start server
    server = P2PServer("0.0.0.0", port, fm, crypto)
    asyncio.create_task(server.start())
    
    # Setup client
    client = P2PClient(fm, crypto)
    
    print("\n" + "="*50)
    print("  P2P File Sharing System - Secure Edition")
    print("="*50)
    print(f"Server running on port: {port}")
    print(f"Public key location: {crypto.public_key_path}")
    print("\nCommands:")
    print("  share <filepath>                    - Share a file")
    print("  download <peer_ip> <port> <hash>    - Download a file")
    print("  ls                                  - List shared files")
    print("  exit                                - Quit")
    print("="*50 + "\n")
    
    # CLI Loop
    loop = asyncio.get_running_loop()
    while True:
        try:
            line = await loop.run_in_executor(None, sys.stdin.readline)
            if not line:
                break
            
            parts = line.strip().split()
            if not parts:
                continue
            
            cmd = parts[0].lower()
            
            if cmd == "share":
                if len(parts) < 2:
                    print("Usage: share <filepath>")
                    continue
                
                filepath = " ".join(parts[1:])  # Handle paths with spaces
                try:
                    manifest = fm.slice_file(filepath)
                    print(f"✅ File shared successfully!")
                    print(f"   Filename: {manifest['filename']}")
                    print(f"   Hash: {manifest['file_hash']}")
                    print(f"   Size: {manifest['size']} bytes")
                    print(f"   Chunks: {len(manifest['chunks'])}")
                except FileNotFoundError:
                    print(f"❌ Error: File not found: {filepath}")
                except Exception as e:
                    print(f"❌ Error: {e}")
                    
            elif cmd == "download":
                if len(parts) < 4:
                    print("Usage: download <peer_ip> <port> <file_hash>")
                    continue
                
                peer_ip = parts[1]
                try:
                    peer_port = int(parts[2])
                except ValueError:
                    print("❌ Error: Invalid port number")
                    continue
                
                file_hash = parts[3]
                print(f"Initiating download from {peer_ip}:{peer_port}...")
                asyncio.create_task(client.download_file([peer_ip], peer_port, file_hash))
                
            elif cmd == "ls":
                print(f"\nShared files in {fm.storage_dir}:")
                try:
                    files = os.listdir(fm.storage_dir)
                    if files:
                        for f in sorted(files):
                            path = os.path.join(fm.storage_dir, f)
                            size = os.path.getsize(path)
                            print(f"  📄 {f} ({size} bytes)")
                    else:
                        print("  (empty)")
                except Exception as e:
                    print(f"❌ Error: {e}")
                print()

            elif cmd == "exit" or cmd == "quit":
                print("Shutting down...")
                break
            
            else:
                print(f"Unknown command: {cmd}")
                print("Type 'help' or see available commands above")
                
        except KeyboardInterrupt:
            print("\nShutting down...")
            break
        except Exception as e:
            logger.error(f"Error: {e}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nGoodbye!")
