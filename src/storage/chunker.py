import os
import hashlib
import mmap
from typing import Dict, Optional

CHUNK_SIZE = 1024 * 1024  # 1MB

class FileManager:
    def __init__(self, storage_dir: str):
        self.storage_dir = storage_dir
        os.makedirs(self.storage_dir, exist_ok=True)
        # Cache for file paths: hash -> filepath
        self.file_map: Dict[str, str] = {}
        # Cache for manifests: hash -> manifest_dict
        self.manifests: Dict[str, Dict] = {}

    def _get_file_hash(self, filepath: str) -> str:
        sha256 = hashlib.sha256()
        with open(filepath, 'rb') as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()

    def slice_file(self, filepath: str) -> Dict:
        """Slices a file and generates a manifest."""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"{filepath} not found.")

        file_hash = self._get_file_hash(filepath)
        file_size = os.path.getsize(filepath)
        filename = os.path.basename(filepath)
        
        chunk_hashes = []
        with open(filepath, 'rb') as f:
            # Use mmap for efficient reading if file is not empty
            if file_size > 0:
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    for i in range(0, file_size, CHUNK_SIZE):
                        chunk = mm[i:i+CHUNK_SIZE]
                        chunk_hashes.append(hashlib.sha256(chunk).hexdigest())
            else:
                chunk_hashes = []

        manifest = {
            "filename": filename,
            "file_hash": file_hash,
            "size": file_size,
            "chunks": chunk_hashes
        }
        
        self.file_map[file_hash] = filepath
        self.manifests[file_hash] = manifest
        return manifest

    def get_chunk(self, file_hash: str, chunk_index: int) -> Optional[bytes]:
        if file_hash not in self.file_map:
            return None
        
        filepath = self.file_map[file_hash]
        try:
            with open(filepath, 'rb') as f:
                f.seek(chunk_index * CHUNK_SIZE)
                return f.read(CHUNK_SIZE)
        except Exception:
            return None

    def write_chunk(self, file_hash: str, chunk_index: int, data: bytes, total_size: int, filename: str):
        filepath = os.path.join(self.storage_dir, filename)
        
        # Create/Resize file if needed
        if not os.path.exists(filepath) or os.path.getsize(filepath) != total_size:
            with open(filepath, 'wb') as f:
                f.truncate(total_size)
        
        with open(filepath, 'r+b') as f:
            f.seek(chunk_index * CHUNK_SIZE)
            f.write(data)
            
        self.file_map[file_hash] = filepath

    def verify_file_integrity(self, filename: str, expected_hash: str) -> bool:
        filepath = os.path.join(self.storage_dir, filename)
        if not os.path.exists(filepath):
            return False
        return self._get_file_hash(filepath) == expected_hash