"""
Asymmetric Cryptography Module
Uses RSA for encryption/decryption and signing/verification
"""
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import os
from pathlib import Path
from typing import Tuple, Optional
import logging

logger = logging.getLogger(__name__)

# Security constants
RSA_KEY_SIZE = 2048
RSA_PUBLIC_EXPONENT = 65537


class AsymmetricCrypto:
    """
    Handles asymmetric encryption using RSA.
    - Public key: Used for encryption and signature verification
    - Private key: Used for decryption and signing
    """
    
    def __init__(self, keys_dir: str = "./keys"):
        self.keys_dir = Path(keys_dir)
        self.keys_dir.mkdir(exist_ok=True)
        
        self.private_key_path = self.keys_dir / "private_key.pem"
        self.public_key_path = self.keys_dir / "public_key.pem"
        
        self.private_key = None
        self.public_key = None
        
        self._load_or_generate_keys()
    
    def _load_or_generate_keys(self):
        """Load existing keys or generate new ones securely."""
        if self.private_key_path.exists() and self.public_key_path.exists():
            self._load_keys()
            logger.info("Loaded existing RSA key pair")
        else:
            self._generate_keys()
            logger.info("Generated new RSA key pair")
    
    def _generate_keys(self):
        """Generate a new RSA key pair securely."""
        # Generate private key
        self.private_key = rsa.generate_private_key(
            public_exponent=RSA_PUBLIC_EXPONENT,
            key_size=RSA_KEY_SIZE,
            backend=default_backend()
        )
        
        # Derive public key
        self.public_key = self.private_key.public_key()
        
        # Save keys to disk
        self._save_keys()
    
    def _save_keys(self):
        """Save keys to disk with appropriate permissions."""
        # Save private key (encrypted with no password for simplicity, but restricted permissions)
        private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Write with restricted permissions (owner read/write only)
        self.private_key_path.write_bytes(private_pem)
        os.chmod(self.private_key_path, 0o600)
        
        # Save public key
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.public_key_path.write_bytes(public_pem)
        
        logger.info(f"Keys saved to {self.keys_dir}")
    
    def _load_keys(self):
        """Load keys from disk."""
        # Load private key
        private_pem = self.private_key_path.read_bytes()
        self.private_key = serialization.load_pem_private_key(
            private_pem,
            password=None,
            backend=default_backend()
        )
        
        # Load public key
        public_pem = self.public_key_path.read_bytes()
        self.public_key = serialization.load_pem_public_key(
            public_pem,
            backend=default_backend()
        )
    
    def get_public_key_bytes(self) -> bytes:
        """Get public key in PEM format for sharing."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def load_peer_public_key(self, public_key_pem: bytes):
        """Load a peer's public key from PEM bytes."""
        return serialization.load_pem_public_key(
            public_key_pem,
            backend=default_backend()
        )
    
    def encrypt(self, data: bytes, peer_public_key) -> bytes:
        """
        Encrypt data using peer's public key.
        Note: RSA can only encrypt small amounts of data (up to key_size - padding).
        For larger data, use hybrid encryption (RSA + AES).
        """
        try:
            ciphertext = peer_public_key.encrypt(
                data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return ciphertext
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise
    
    def decrypt(self, ciphertext: bytes) -> Optional[bytes]:
        """Decrypt data using our private key."""
        try:
            plaintext = self.private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return plaintext
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            return None
    
    def sign(self, data: bytes) -> bytes:
        """Sign data using our private key."""
        try:
            signature = self.private_key.sign(
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return signature
        except Exception as e:
            logger.error(f"Signing failed: {e}")
            raise
    
    def verify(self, data: bytes, signature: bytes, peer_public_key) -> bool:
        """Verify signature using peer's public key."""
        try:
            peer_public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            logger.warning("Signature verification failed")
            return False
        except Exception as e:
            logger.error(f"Verification error: {e}")
            return False


class HybridCrypto:
    """
    Hybrid encryption combining RSA (asymmetric) and AES (symmetric).
    - Use AES for encrypting large data (fast)
    - Use RSA to encrypt the AES key (secure key exchange)
    """
    
    def __init__(self, asymmetric_crypto: AsymmetricCrypto):
        self.asym = asymmetric_crypto
    
    def encrypt(self, data: bytes, peer_public_key) -> Tuple[bytes, bytes]:
        """
        Encrypt data using hybrid encryption.
        Returns: (encrypted_aes_key, encrypted_data)
        """
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        
        # Generate random AES key
        aes_key = os.urandom(32)  # 256-bit key
        iv = os.urandom(16)  # 128-bit IV
        
        # Encrypt data with AES
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # Pad data to AES block size
        from cryptography.hazmat.primitives import padding as sym_padding
        padder = sym_padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # Encrypt AES key with RSA
        key_package = aes_key + iv  # Combine key and IV
        encrypted_key = self.asym.encrypt(key_package, peer_public_key)
        
        return encrypted_key, encrypted_data
    
    def decrypt(self, encrypted_key: bytes, encrypted_data: bytes) -> Optional[bytes]:
        """
        Decrypt data using hybrid encryption.
        """
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        
        try:
            # Decrypt AES key with RSA
            key_package = self.asym.decrypt(encrypted_key)
            if not key_package:
                return None
            
            aes_key = key_package[:32]
            iv = key_package[32:48]
            
            # Decrypt data with AES
            cipher = Cipher(
                algorithms.AES(aes_key),
                modes.CBC(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
            
            # Unpad data
            from cryptography.hazmat.primitives import padding as sym_padding
            unpadder = sym_padding.PKCS7(128).unpadder()
            data = unpadder.update(padded_data) + unpadder.finalize()
            
            return data
        except Exception as e:
            logger.error(f"Hybrid decryption failed: {e}")
            return None
