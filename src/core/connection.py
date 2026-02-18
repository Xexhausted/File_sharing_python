"""
P2P Connection Module with Asymmetric Encryption
Handles server and client connections with RSA-based security
"""
import asyncio
import json
import logging
import base64
import hashlib
import socket
from typing import List, Optional

try:
    import uvloop
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
except ImportError:
    pass

from src.core.protocol import P2PProtocol
from src.storage.chunker import FileManager
from src.security.crypto import AsymmetricCrypto, HybridCrypto

logger = logging.getLogger("P2PConnection")

MAX_MSG_SIZE = 1024 * 1024 * 1024  # 1 GB Limit
DISCOVERY_PORT = 9999


class DiscoveryProtocol(asyncio.DatagramProtocol):
    """UDP-based peer discovery protocol."""
    
    def __init__(self, file_manager: FileManager, tcp_port: int):
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
                if file_hash and file_hash in self.fm.manifests:
                    response = json.dumps({
                        "cmd": "FOUND",
                        "file_hash": file_hash,
                        "tcp_port": self.tcp_port
                    }).encode()
                    self.transport.sendto(response, addr)
        except Exception as e:
            logger.debug(f"Discovery packet error: {e}")


class P2PServer:
    """
    P2P Server with asymmetric encryption.
    Handles incoming connections and serves file chunks.
    """
    
    def __init__(self, host: str, port: int, file_manager: FileManager, crypto: AsymmetricCrypto):
        self.host = host
        self.port = port
        self.fm = file_manager
        self.crypto = crypto
        self.hybrid = HybridCrypto(crypto)
        self.peer_public_keys = {}  # Store peer public keys by address

    async def start(self):
        """Start the server and discovery service."""
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
                lambda: DiscoveryProtocol(self.fm, self.port), 
                sock=sock
            )
            logger.info(f"Discovery service active on UDP {DISCOVERY_PORT}")
        except Exception as e:
            logger.warning(f"Discovery service failed to start: {e}")

        async with server:
            await server.serve_forever()

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle incoming client connection."""
        addr = writer.get_extra_info('peername')
        peer_public_key = None
        
        try:
            # First message must be handshake with public key exchange
            length_data = await reader.read(4)
            if not length_data:
                return
            
            length = int.from_bytes(length_data, 'big')
            if length > MAX_MSG_SIZE:
                logger.warning(f"Blocked oversized message ({length} bytes) from {addr}")
                return
            
            # Read initial handshake (unencrypted)
            msg_data = await reader.readexactly(length)
            msg = json.loads(msg_data.decode())
            
            if msg.get('cmd') != P2PProtocol.HANDSHAKE:
                logger.warning(f"Expected handshake from {addr}")
                return
            
            # Extract peer's public key
            peer_pubkey_pem = msg['payload'].get('public_key')
            if not peer_pubkey_pem:
                logger.warning(f"No public key in handshake from {addr}")
                return
            
            peer_public_key = self.crypto.load_peer_public_key(peer_pubkey_pem.encode())
            self.peer_public_keys[addr] = peer_public_key
            
            # Send handshake acknowledgment with our public key
            ack_msg = {
                "cmd": P2PProtocol.HANDSHAKE_ACK,
                "payload": {
                    "status": "OK",
                    "public_key": self.crypto.get_public_key_bytes().decode()
                }
            }
            ack_bytes = json.dumps(ack_msg).encode()
            writer.write(len(ack_bytes).to_bytes(4, 'big') + ack_bytes)
            await writer.drain()
            
            logger.info(f"Handshake completed with {addr}")
            
            # Now handle encrypted messages
            while True:
                length_data = await reader.read(4)
                if not length_data:
                    break
                
                length = int.from_bytes(length_data, 'big')
                if length > MAX_MSG_SIZE:
                    logger.warning(f"Blocked oversized message from {addr}")
                    break
                
                encrypted_data = await reader.readexactly(length)
                
                # Decrypt using hybrid encryption
                # Format: [4 bytes key_len][encrypted_key][encrypted_data]
                key_len = int.from_bytes(encrypted_data[:4], 'big')
                encrypted_key = encrypted_data[4:4+key_len]
                encrypted_payload = encrypted_data[4+key_len:]
                
                decrypted_bytes = self.hybrid.decrypt(encrypted_key, encrypted_payload)
                if not decrypted_bytes:
                    logger.warning(f"Decryption failed from {addr}")
                    break
                
                msg = json.loads(decrypted_bytes.decode())
                response = await self.process_request(msg)
                
                if response:
                    # Encrypt response
                    resp_bytes = json.dumps(response).encode()
                    enc_key, enc_data = self.hybrid.encrypt(resp_bytes, peer_public_key)
                    
                    # Send: [4 bytes total_len][4 bytes key_len][enc_key][enc_data]
                    key_len_bytes = len(enc_key).to_bytes(4, 'big')
                    payload = key_len_bytes + enc_key + enc_data
                    
                    writer.write(len(payload).to_bytes(4, 'big') + payload)
                    await writer.drain()
                    
        except asyncio.IncompleteReadError:
            logger.debug(f"Client {addr} disconnected")
        except Exception as e:
            logger.error(f"Error handling client {addr}: {e}")
        finally:
            writer.close()
            await writer.wait_closed()
            if addr in self.peer_public_keys:
                del self.peer_public_keys[addr]

    async def process_request(self, msg: dict) -> Optional[dict]:
        """Process client requests."""
        cmd = msg.get('cmd')
        payload = msg.get('payload', {})
        
        if cmd == P2PProtocol.QUERY:
            file_hash = payload.get('file_hash')
            if not file_hash:
                return {"cmd": P2PProtocol.ERROR, "payload": "Missing file_hash"}
            
            manifest = self.fm.manifests.get(file_hash)
            if manifest:
                return {"cmd": P2PProtocol.QUERY_HIT, "payload": manifest}
            return {"cmd": P2PProtocol.ERROR, "payload": "File not found"}
            
        elif cmd == P2PProtocol.GET_CHUNK:
            file_hash = payload.get('file_hash')
            index = payload.get('chunk_index')
            
            if file_hash is None or index is None:
                return {"cmd": P2PProtocol.ERROR, "payload": "Missing parameters"}
            
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
        
        return {"cmd": P2PProtocol.ERROR, "payload": "Unknown command"}


class P2PClient:
    """
    P2P Client with asymmetric encryption.
    Handles outgoing connections and file downloads.
    """
    
    def __init__(self, file_manager: FileManager, crypto: AsymmetricCrypto):
        self.fm = file_manager
        self.crypto = crypto
        self.hybrid = HybridCrypto(crypto)

    async def discover_peers(self, file_hash: str, timeout: float = 2.0) -> List[str]:
        """Discover peers that have a specific file via UDP broadcast."""
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
                except Exception:
                    pass
                    
            def error_received(self, exc):
                pass

        loop = asyncio.get_running_loop()
        try:
            transport, protocol = await loop.create_datagram_endpoint(
                lambda: DiscoveryClientProtocol(), 
                local_addr=('0.0.0.0', 0)
            )
            await asyncio.sleep(timeout)
            transport.close()
        except Exception as e:
            logger.error(f"Discovery error: {e}")
        
        return list(found_peers)

    async def download_file(self, peer_ips: List[str], port: int, file_hash: str, progress_callback=None):
        """Download a file from peers."""
        if not peer_ips:
            logger.error("No peer IPs provided")
            return
        
        for peer_ip in peer_ips:
            try:
                logger.info(f"Connecting to peer: {peer_ip}:{port}")
                reader, writer = await asyncio.open_connection(peer_ip, port)
                
                # Perform handshake with public key exchange
                handshake_msg = {
                    "cmd": P2PProtocol.HANDSHAKE,
                    "payload": {
                        "id": "client",
                        "public_key": self.crypto.get_public_key_bytes().decode()
                    }
                }
                handshake_bytes = json.dumps(handshake_msg).encode()
                writer.write(len(handshake_bytes).to_bytes(4, 'big') + handshake_bytes)
                await writer.drain()
                
                # Receive handshake acknowledgment
                resp = await self._recv_unencrypted(reader)
                if not resp or resp.get('cmd') != P2PProtocol.HANDSHAKE_ACK:
                    logger.error(f"Handshake failed with {peer_ip}")
                    writer.close()
                    await writer.wait_closed()
                    continue
                
                # Extract peer's public key
                peer_pubkey_pem = resp['payload'].get('public_key')
                if not peer_pubkey_pem:
                    logger.error(f"No public key from {peer_ip}")
                    writer.close()
                    await writer.wait_closed()
                    continue
                
                peer_public_key = self.crypto.load_peer_public_key(peer_pubkey_pem.encode())
                logger.info(f"Secure connection established with {peer_ip}")
                
                # Query for file manifest
                await self._send_encrypted(writer, P2PProtocol.QUERY, {"file_hash": file_hash}, peer_public_key)
                resp = await self._recv_encrypted(reader)
                
                if not resp or resp.get('cmd') != P2PProtocol.QUERY_HIT:
                    logger.error(f"File not found on peer {peer_ip}")
                    writer.close()
                    await writer.wait_closed()
                    continue
                
                manifest = resp['payload']
                total_chunks = len(manifest['chunks'])
                filename = manifest['filename']
                file_size = manifest['size']
                
                logger.info(f"Downloading {filename} ({total_chunks} chunks) from {peer_ip}")

                # Download chunks sequentially
                for i in range(total_chunks):
                    await self._send_encrypted(
                        writer, 
                        P2PProtocol.GET_CHUNK, 
                        {"file_hash": file_hash, "chunk_index": i},
                        peer_public_key
                    )
                    chunk_resp = await self._recv_encrypted(reader)
                    
                    if chunk_resp and chunk_resp.get('cmd') == P2PProtocol.CHUNK_DATA:
                        b64_data = chunk_resp['payload']['data']
                        data = base64.b64decode(b64_data)
                        
                        # Verify chunk integrity
                        if hashlib.sha256(data).hexdigest() == manifest['chunks'][i]:
                            self.fm.write_chunk(file_hash, i, data, file_size, filename)
                            if progress_callback:
                                progress_callback(file_hash, filename, i + 1, total_chunks, len(data))
                            logger.info(f"Downloaded chunk {i+1}/{total_chunks}")
                        else:
                            logger.error(f"Hash mismatch for chunk {i}")
                            break
                    else:
                        logger.error(f"Failed to get chunk {i}")
                        break
                
                # Verify complete file integrity
                if self.fm.verify_file_integrity(filename, file_hash):
                    logger.info(f"✅ Download complete and verified: {filename}")
                else:
                    logger.error(f"❌ File integrity check failed: {filename}")

                writer.close()
                await writer.wait_closed()
                return  # Success
                
            except Exception as e:
                logger.error(f"Download failed from {peer_ip}: {e}")
                continue

    async def _send_encrypted(self, writer: asyncio.StreamWriter, cmd: str, payload: dict, peer_public_key):
        """Send encrypted message to peer."""
        msg = {"cmd": cmd, "payload": payload}
        json_bytes = json.dumps(msg).encode()
        
        # Encrypt using hybrid encryption
        enc_key, enc_data = self.hybrid.encrypt(json_bytes, peer_public_key)
        
        # Format: [4 bytes total_len][4 bytes key_len][enc_key][enc_data]
        key_len_bytes = len(enc_key).to_bytes(4, 'big')
        payload_bytes = key_len_bytes + enc_key + enc_data
        
        writer.write(len(payload_bytes).to_bytes(4, 'big') + payload_bytes)
        await writer.drain()

    async def _recv_encrypted(self, reader: asyncio.StreamReader) -> Optional[dict]:
        """Receive encrypted message from peer."""
        try:
            len_data = await reader.read(4)
            if not len_data:
                return None
            
            length = int.from_bytes(len_data, 'big')
            if length > MAX_MSG_SIZE:
                return None
            
            encrypted_data = await reader.readexactly(length)
            
            # Parse: [4 bytes key_len][encrypted_key][encrypted_data]
            key_len = int.from_bytes(encrypted_data[:4], 'big')
            encrypted_key = encrypted_data[4:4+key_len]
            encrypted_payload = encrypted_data[4+key_len:]
            
            dec_data = self.hybrid.decrypt(encrypted_key, encrypted_payload)
            if not dec_data:
                return None
            
            return json.loads(dec_data.decode())
        except Exception as e:
            logger.error(f"Receive error: {e}")
            return None

    async def _recv_unencrypted(self, reader: asyncio.StreamReader) -> Optional[dict]:
        """Receive unencrypted message (for handshake only)."""
        try:
            len_data = await reader.read(4)
            if not len_data:
                return None
            
            length = int.from_bytes(len_data, 'big')
            if length > MAX_MSG_SIZE:
                return None
            
            msg_data = await reader.readexactly(length)
            return json.loads(msg_data.decode())
        except Exception as e:
            logger.error(f"Receive error: {e}")
            return None
