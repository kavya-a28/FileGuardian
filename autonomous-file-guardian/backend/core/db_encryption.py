import os
import hashlib
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken

def _derive_dek(master_key_str: str) -> bytes:
    """
    Derive Database Encryption Key (DEK) from the Master Key string.
    """
    # Use a fixed salt specific to DB metadata
    salt = b'db_vault_metadata_salt' 
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(master_key_str.encode())


def encrypt_data(plaintext_str: str, master_key_str: str) -> str:
    """
    Encrypts a string using AES-GCM and returns base64 encoded result.
    Format: 'aes:' + base64(nonce + ciphertext + tag)
    """
    if not plaintext_str:
        return ""
    
    dek = _derive_dek(master_key_str)

    try:
        aesgcm = AESGCM(dek)
        nonce = os.urandom(12)
        ciphertext_bytes = aesgcm.encrypt(nonce, plaintext_str.encode(), None)
        # Prefix with 'aes:' to identify encryption method
        encrypted = base64.b64encode(nonce + ciphertext_bytes).decode('utf-8')
        return f"aes:{encrypted}"
    except Exception as e:
        # print(f"❌ DB ENCRYPTION FAILED: {e}")
        return "!!!ENCRYPTION_FAILED!!!" 


def decrypt_data(ciphertext_str: str, master_key_str: str) -> str:
    """
    Decrypts data, supporting AES-GCM and gracefully handling vault-locked states.
    """
    if not ciphertext_str or ciphertext_str.startswith("!!!"):
        return ""
    
    dek = _derive_dek(master_key_str)
    
    try:
        # NEW FORMAT: AES-GCM (prefixed with 'aes:')
        if ciphertext_str.startswith('aes:'):
            encrypted_data = ciphertext_str[4:]  # Remove 'aes:' prefix
            data = base64.b64decode(encrypted_data)
            
            if len(data) < 12:
                raise ValueError("Insufficient data length")
                
            nonce = data[:12]
            ciphertext = data[12:]
            aesgcm = AESGCM(dek)
            plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext_bytes.decode('utf-8')
        
        # Plaintext or old format fallback (e.g. initial setup)
        else:
            return ciphertext_str
            
    except Exception as e:
        # print(f"❌ DB DECRYPTION ERROR: {e}")
        return "--- DECRYPTION_ERROR ---"