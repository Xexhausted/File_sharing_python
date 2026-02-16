import asyncio
import json
import logging
import base64
import hashlib
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

class P2PServer:
    def __init__(self, host: str, port: int, file_manager: FileManager, security_manager: SecurityManager):
        self.host = host
        self.port = port
        self.fm = file_manager
        self.sm = security_manager

    async def start(self):
        server = await asyncio.start_server(self.handle_client, self.host, self.port)
        logger.info(f"Server listening on {self.host}:{self.port}")
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

    async def download_file(self, peer_ips: List[str], port: int, file_hash: str):
        # For simplicity in this demo, we pick the first peer to get the manifest
        # In a full implementation, we would query all peers.
        primary_peer = peer_ips[0]
        
        try:
            reader, writer = await asyncio.open_connection(primary_peer, port)
            
            # Handshake
            await self._send_msg(writer, P2PProtocol.HANDSHAKE, {"id": "client"})
            resp = await self._recv_msg(reader)
            if not resp or resp.get('cmd') != P2PProtocol.HANDSHAKE_ACK:
                logger.error("Handshake failed")
                return

            # Get Manifest
            await self._send_msg(writer, P2PProtocol.QUERY, {"file_hash": file_hash})
            resp = await self._recv_msg(reader)
            
            if not resp or resp.get('cmd') != P2PProtocol.QUERY_HIT:
                logger.error("File not found on peer")
                return
            
            manifest = resp['payload']
            total_chunks = len(manifest['chunks'])
            filename = manifest['filename']
            file_size = manifest['size']
            
            logger.info(f"Downloading {filename} ({total_chunks} chunks)...")

            # Sequential download for robustness on single connection
            # (To do parallel, we would open multiple connections to peer_ips)
            for i in range(total_chunks):
                await self._send_msg(writer, P2PProtocol.GET_CHUNK, {"file_hash": file_hash, "chunk_index": i})
                chunk_resp = await self._recv_msg(reader)
                
                if chunk_resp and chunk_resp.get('cmd') == P2PProtocol.CHUNK_DATA:
                    b64_data = chunk_resp['payload']['data']
                    data = base64.b64decode(b64_data)
                    
                    # Verify Integrity
                    if hashlib.sha256(data).hexdigest() == manifest['chunks'][i]:
                        self.fm.write_chunk(file_hash, i, data, file_size, filename)
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

        except Exception as e:
            logger.error(f"Download failed: {e}")

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
            enc_data = await reader.readexactly(length)
            dec_data = self.sm.decrypt(enc_data)
            return json.loads(dec_data.decode())
        except Exception:
            return None