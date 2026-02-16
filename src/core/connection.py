import asyncio
import json
import logging
import base64
import hashlib
import socket
from typing import List

try:
    import uvloop
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
except ImportError:
    pass

from src.core.protocol import P2PProtocol
from src.storage.chunker import FileManager
from src.security.encryptor import SecurityManager

logger = logging.getLogger("P2PConnection")

MAX_MSG_SIZE = 1024 * 1024 * 1024  # 1 GB Limit
DISCOVERY_PORT = 9999

class DiscoveryProtocol(asyncio.DatagramProtocol):
    def __init__(self, file_manager, tcp_port):
        self.fm = file_manager
        self.tcp_port = tcp_port
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        try:
            msg = json.loads(data.decode())
            if msg.get('cmd') == 'DISCOVER':
                file_hash = msg.get('file_hash')
                # Check if we have the file manifest
                if file_hash in self.fm.manifests:
                    # Reply to the sender
                    response = json.dumps({
                        "cmd": "FOUND",
                        "file_hash": file_hash,
                        "tcp_port": self.tcp_port
                    }).encode()
                    self.transport.sendto(response, addr)
        except Exception:
            pass

class P2PServer:
    def __init__(self, host: str, port: int, file_manager: FileManager, security_manager: SecurityManager):
        self.host = host
        self.port = port
        self.fm = file_manager
        self.sm = security_manager

    async def start(self):
        server = await asyncio.start_server(self.handle_client, self.host, self.port)
        logger.info(f"Server listening on {self.host}:{self.port}")
        
        # Start UDP Discovery Service
        loop = asyncio.get_running_loop()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if hasattr(socket, 'SO_REUSEPORT'):
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            sock.bind(('0.0.0.0', DISCOVERY_PORT))
            
            await loop.create_datagram_endpoint(
                lambda: DiscoveryProtocol(self.fm, self.port), sock=sock
            )
            logger.info(f"Discovery service active on UDP {DISCOVERY_PORT}")
        except Exception as e:
            logger.warning(f"Discovery service failed to start: {e}")

        async with server:
            await server.serve_forever()

    async def handle_client(self, reader, writer):
        addr = writer.get_extra_info('peername')
        try:
            while True:
                # 1. Read Length Prefix (4 bytes)
                length_data = await reader.read(4)
                if not length_data: break
                length = int.from_bytes(length_data, 'big')
                
                if length > MAX_MSG_SIZE:
                    logger.warning(f"Blocked oversized message ({length} bytes) from {addr}")
                    break
                
                # 2. Read Encrypted Payload
                encrypted_msg = await reader.readexactly(length)
                
                # 3. Decrypt
                decrypted_bytes = self.sm.decrypt(encrypted_msg)
                if not decrypted_bytes:
                    logger.warning(f"Decryption failed from {addr}")
                    break
                
                msg = json.loads(decrypted_bytes.decode())
                response = await self.process_request(msg)
                
                if response:
                    resp_bytes = json.dumps(response).encode()
                    enc_resp = self.sm.encrypt(resp_bytes)
                    writer.write(len(enc_resp).to_bytes(4, 'big') + enc_resp)
                    await writer.drain()
        except Exception as e:
            logger.error(f"Error handling client {addr}: {e}")
        finally:
            writer.close()

    async def process_request(self, msg: dict):
        cmd = msg.get('cmd')
        payload = msg.get('payload', {})
        
        if cmd == P2PProtocol.HANDSHAKE:
            return {"cmd": P2PProtocol.HANDSHAKE_ACK, "payload": {"status": "OK"}}
        
        elif cmd == P2PProtocol.QUERY:
            file_hash = payload.get('file_hash')
            manifest = self.fm.manifests.get(file_hash)
            if manifest:
                return {"cmd": P2PProtocol.QUERY_HIT, "payload": manifest}
            return {"cmd": P2PProtocol.ERROR, "payload": "File not found"}
            
        elif cmd == P2PProtocol.GET_CHUNK:
            file_hash = payload.get('file_hash')
            index = payload.get('chunk_index')
            data = self.fm.get_chunk(file_hash, index)
            if data:
                return {
                    "cmd": P2PProtocol.CHUNK_DATA,
                    "payload": {
                        "chunk_index": index,
                        "data": base64.b64encode(data).decode()
                    }
                }
            return {"cmd": P2PProtocol.ERROR, "payload": "Chunk not found"}

class P2PClient:
    def __init__(self, file_manager: FileManager, security_manager: SecurityManager):
        self.fm = file_manager
        self.sm = security_manager

    async def discover_peers(self, file_hash: str, timeout=2.0) -> List[str]:
        found_peers = set()
        
        class DiscoveryClientProtocol(asyncio.DatagramProtocol):
            def __init__(self):
                self.transport = None
            def connection_made(self, transport):
                self.transport = transport
                msg = json.dumps({"cmd": "DISCOVER", "file_hash": file_hash}).encode()
                sock = self.transport.get_extra_info('socket')
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                self.transport.sendto(msg, ('255.255.255.255', DISCOVERY_PORT))
            def datagram_received(self, data, addr):
                try:
                    msg = json.loads(data.decode())
                    if msg.get('cmd') == 'FOUND' and msg.get('file_hash') == file_hash:
                        found_peers.add(addr[0])
                except: pass
            def error_received(self, exc): pass

        loop = asyncio.get_running_loop()
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: DiscoveryClientProtocol(), local_addr=('0.0.0.0', 0)
        )
        await asyncio.sleep(timeout)
        transport.close()
        return list(found_peers)

    async def download_file(self, peer_ips: List[str], port: int, file_hash: str, progress_callback=None):
        # Try each peer in the list until one works
        for peer_ip in peer_ips:
            try:
                logger.info(f"Connecting to peer: {peer_ip}...")
                reader, writer = await asyncio.open_connection(peer_ip, port)
                
                # Handshake
                await self._send_msg(writer, P2PProtocol.HANDSHAKE, {"id": "client"})
                resp = await self._recv_msg(reader)
                if not resp or resp.get('cmd') != P2PProtocol.HANDSHAKE_ACK:
                    logger.error(f"Handshake failed with {peer_ip}")
                    writer.close()
                    await writer.wait_closed()
                    continue

                # Get Manifest
                await self._send_msg(writer, P2PProtocol.QUERY, {"file_hash": file_hash})
                resp = await self._recv_msg(reader)
                
                if not resp or resp.get('cmd') != P2PProtocol.QUERY_HIT:
                    logger.error(f"File not found on peer {peer_ip}")
                    writer.close()
                    await writer.wait_closed()
                    continue
                
                manifest = resp['payload']
                total_chunks = len(manifest['chunks'])
                filename = manifest['filename']
                file_size = manifest['size']
                
                logger.info(f"Downloading {filename} ({total_chunks} chunks) from {peer_ip}...")

                # Sequential download
                for i in range(total_chunks):
                    await self._send_msg(writer, P2PProtocol.GET_CHUNK, {"file_hash": file_hash, "chunk_index": i})
                    chunk_resp = await self._recv_msg(reader)
                    
                    if chunk_resp and chunk_resp.get('cmd') == P2PProtocol.CHUNK_DATA:
                        b64_data = chunk_resp['payload']['data']
                        data = base64.b64decode(b64_data)
                        
                        # Verify Integrity
                        if hashlib.sha256(data).hexdigest() == manifest['chunks'][i]:
                            self.fm.write_chunk(file_hash, i, data, file_size, filename)
                            if progress_callback:
                                progress_callback(file_hash, filename, i + 1, total_chunks, len(data))
                            print(f"Downloaded chunk {i+1}/{total_chunks}")
                        else:
                            logger.error(f"Hash mismatch for chunk {i}")
                            break
                
                # Final Full File Verification
                if self.fm.verify_file_integrity(filename, file_hash):
                    logger.info(f"✅ Integrity Verified: {filename} matches hash {file_hash}")
                    print("Download complete.")
                else:
                    logger.error(f"❌ Integrity Check Failed: {filename} is corrupt.")

                writer.close()
                await writer.wait_closed()
                return  # Success, exit function

            except Exception as e:
                logger.error(f"Download failed from {peer_ip}: {e}")
                continue  # Try next peer

    async def _send_msg(self, writer, cmd, payload):
        msg = {"cmd": cmd, "payload": payload}
        json_bytes = json.dumps(msg).encode()
        enc_data = self.sm.encrypt(json_bytes)
        writer.write(len(enc_data).to_bytes(4, 'big') + enc_data)
        await writer.drain()

    async def _recv_msg(self, reader):
        try:
            len_data = await reader.read(4)
            if not len_data: return None
            length = int.from_bytes(len_data, 'big')
            if length > MAX_MSG_SIZE:
                return None
            enc_data = await reader.readexactly(length)
            dec_data = self.sm.decrypt(enc_data)
            return json.loads(dec_data.decode())
        except Exception:
            return None