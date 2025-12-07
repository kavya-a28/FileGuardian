import os
import hashlib
import json
import requests
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

class FileEncryptor:
    def __init__(self, master_key: str, canary_token: str = None, requires_2fa: bool = False):
        """
        Initialize Encryptor
        :param master_key: The user's password/key
        :param canary_token: Optional URL for canary token
        :param requires_2fa: Boolean flag if file requires 2FA to decrypt
        """
        self.master_key = master_key.encode()
        self.canary_token = canary_token
        self.requires_2fa = requires_2fa
    
    def _derive_key(self, salt: bytes) -> bytes:
        """Derive encryption key from master key using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(self.master_key)
    
    def _embed_metadata(self, data: bytes) -> bytes:
        """
        Embed metadata (Canary Token + 2FA Flag) into the file header.
        Replaces the old _embed_canary_token method to be more generic.
        """
        # If no features are enabled, don't modify the data
        if not self.canary_token and not self.requires_2fa:
            return data
        
        # Create metadata dictionary
        metadata = {
            'embedded': True
        }
        
        if self.canary_token:
            metadata['canary_token'] = self.canary_token
            
        if self.requires_2fa:
            metadata['requires_2fa'] = True
            
        # Serialize to JSON bytes
        metadata_bytes = json.dumps(metadata).encode()
        metadata_length = len(metadata_bytes).to_bytes(4, 'big')
        
        # Prepend length + metadata + original data
        return metadata_length + metadata_bytes + data
    
    def _extract_metadata(self, data: bytes) -> tuple[bytes, dict]:
        """
        Extract metadata from file data.
        Replaces _extract_canary_token.
        """
        try:
            # Read metadata length (first 4 bytes)
            metadata_length = int.from_bytes(data[:4], 'big')
            
            # Safety check: Metadata shouldn't be unreasonably large (e.g., > 10KB)
            if metadata_length > 10240: 
                return data, {}

            # Extract metadata bytes
            metadata_bytes = data[4:4+metadata_length]
            
            # Parse JSON
            metadata = json.loads(metadata_bytes.decode())
            
            # Return data without metadata header, and the metadata dict
            return data[4+metadata_length:], metadata
        except Exception:
            # If parsing fails, assume it's an old file or raw data
            return data, {}
    
    def _trigger_canary_token(self, token_url: str) -> bool:
        """
        Actually trigger the canary token by making HTTP request
        This is what sends the alert!
        """
        try:
            print(f"🕵️ Triggering canary token: {token_url}")
            
            # Make HTTP GET request to trigger the token
            # Set timeout to avoid hanging
            response = requests.get(
                token_url,
                timeout=10,
                headers={
                    'User-Agent': 'FileGuardian/1.0 Unauthorized-Access-Detector'
                }
            )
            
            if response.status_code == 200:
                print(f"✅ Canary token triggered successfully!")
                return True
            else:
                print(f"⚠️ Canary token response: {response.status_code}")
                return False
                
        except requests.exceptions.Timeout:
            print(f"⚠️ Canary token request timed out")
            return False
        except Exception as e:
            print(f"❌ Failed to trigger canary token: {e}")
            return False
    
    def encrypt_file(self, file_path: str) -> tuple[str, bytes]:
        """Encrypt a file IN PLACE - replaces original with encrypted version"""
        try:
            # Generate random salt and nonce
            salt = os.urandom(16)
            nonce = os.urandom(12)
            
            # Derive encryption key
            key = self._derive_key(salt)
            aesgcm = AESGCM(key)
            
            # Read original file
            with open(file_path, 'rb') as f:
                plaintext = f.read()
            
            # Embed metadata (Canary + 2FA flag) using the new generic method
            plaintext = self._embed_metadata(plaintext)
            
            # Encrypt
            ciphertext = aesgcm.encrypt(nonce, plaintext, None)
            
            # Overwrite original file with encrypted content
            # Format: salt(16) + nonce(12) + ciphertext
            with open(file_path, 'wb') as f:
                f.write(salt)
                f.write(nonce)
                f.write(ciphertext)
            
            # Return path and salt
            return file_path, salt
        except Exception as e:
            raise Exception(f"Encryption failed: {str(e)}")
    
    def decrypt_file(self, encrypted_path: str, output_path: str, salt: bytes, trigger_canary: bool = True) -> tuple[str, dict]:
        """
        Decrypt a file to specified output location
        
        Args:
            encrypted_path: Path to encrypted file
            output_path: Where to save decrypted file
            salt: Salt used for encryption
            trigger_canary: If True, trigger canary token (for unauthorized access)
        """
        try:
            # Read encrypted file
            with open(encrypted_path, 'rb') as f:
                stored_salt = f.read(16)
                nonce = f.read(12)
                ciphertext = f.read()
            
            # Verify salt matches
            if stored_salt != salt:
                raise Exception("Salt mismatch - file may be corrupted or wrong key")
            
            # Derive key
            key = self._derive_key(salt)
            aesgcm = AESGCM(key)
            
            # Decrypt
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            
            # Extract metadata (Canary + 2FA info)
            clean_data, metadata = self._extract_metadata(plaintext)
            
            # IMPORTANT: Trigger canary token if requested (unauthorized access)
            if trigger_canary and metadata.get('canary_token'):
                canary_url = metadata.get('canary_token')
                print(f"\n🚨 UNAUTHORIZED ACCESS DETECTED!")
                print(f"📡 Triggering canary token to send alert...")
                
                # Actually make the HTTP request to trigger alert
                triggered = self._trigger_canary_token(canary_url)
                
                if triggered:
                    print(f"✅ Alert sent! You should receive email notification.")
                    metadata['canary_triggered'] = True
                else:
                    print(f"⚠️ Alert may not have sent properly")
                    metadata['canary_triggered'] = False
            
            # Write decrypted file
            with open(output_path, 'wb') as f:
                f.write(clean_data)
            
            return output_path, metadata
        except Exception as e:
            raise Exception(f"Decryption failed: {str(e)}")
    
    def encrypt_folder(self, folder_path: str) -> list:
        """Encrypt all files in a folder recursively, replacing originals"""
        encrypted_files = []
        folder_path = Path(folder_path)
        
        for file_path in folder_path.rglob('*'):
            if file_path.is_file():
                try:
                    # Update to match new encrypt_file return values
                    enc_path, salt = self.encrypt_file(str(file_path))
                    encrypted_files.append({
                        'original': str(file_path),
                        'encrypted': enc_path,
                        'salt': salt.hex(),
                    })
                except Exception as e:
                    print(f"Failed to encrypt {file_path}: {e}")
        
        return encrypted_files