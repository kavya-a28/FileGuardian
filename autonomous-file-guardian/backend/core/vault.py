import hashlib

class VaultManager:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(VaultManager, cls).__new__(cls)
            cls._instance.is_unlocked = False
            cls._instance.master_key_hash = None
            cls._instance._master_key_str = None
            cls._instance._initialized = False 
        return cls._instance

    def initialize_vault(self, stored_hash):
        """
        Called when server starts or settings loaded.
        This loads the hash from the database into RAM for verification.
        """
        if stored_hash:
            self.master_key_hash = stored_hash
            self._initialized = True
        else:
            # print("⚠️ No master key hash found in database - vault needs setup")
            pass

    def unlock(self, key_attempt):
        """Verify key and unlock vault"""
        if not self.master_key_hash:
            return False
            
        attempt_hash = hashlib.sha256(key_attempt.encode()).hexdigest()
        
        if attempt_hash == self.master_key_hash:
            self.is_unlocked = True
            self._master_key_str = key_attempt  # Store key in RAM
            return True
        else:
            return False

    def lock(self):
        """Clear RAM and lock vault"""
        self.is_unlocked = False
        self._master_key_str = None
        # print("🔒 Vault locked - master key cleared from RAM")

    def get_master_key_for_dek(self):
        """
        Provides the Master Key string for use by EncryptedTextField to derive DEK.
        Raises PermissionError if the vault is locked.
        """
        if not self.is_unlocked or not self._master_key_str:
            raise PermissionError("Vault is locked; Master Key access denied.")
        return self._master_key_str

    def is_active(self):
        """Returns True if vault is unlocked"""
        return self.is_unlocked
    
    def is_initialized(self):
        """Returns True if vault hash has been loaded from DB"""
        return self._initialized

# Create a global instance
vault = VaultManager()