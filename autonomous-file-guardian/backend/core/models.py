from django.db import models
from django.utils import timezone
from django.db.models import TextField
from django.core.exceptions import ImproperlyConfigured
from core.db_encryption import encrypt_data, decrypt_data
from core.vault import vault

# ====================================================================
# ENCRYPTED FIELD MIXIN
# ====================================================================
class EncryptedTextField(TextField):
    """
    Custom field that encrypts/decrypts data automatically using the DEK 
    derived from the Master Key currently in VaultManager's RAM.
    """
    def get_prep_value(self, value):
        """Encrypt value before sending to the database"""
        if not value:
            return value

        try:
            # Only encrypt if vault is active
            if vault.is_active():
                master_key_str = vault.get_master_key_for_dek()
                return encrypt_data(value, master_key_str)
            else:
                # If vault is locked, return as-is (happens during migrations or un-setup)
                # It's up to the view/model logic to ensure sensitive data isn't saved unencrypted
                return value 
        except Exception:
            # If vault is locked, or other error, return unencrypted (to prevent data loss)
            return value

    def from_db_value(self, value, expression, connection):
        """Decrypt value when reading from the database"""
        if not value or not isinstance(value, str):
            return value
        
        # If it's a marker, return as-is
        if value.startswith("---") or value.startswith("!!!"):
            return value
        
        try:
            if not vault.is_active():
                return "--- VAULT_LOCKED ---"
            
            master_key_str = vault.get_master_key_for_dek()
            decrypted_value = decrypt_data(value, master_key_str)
            return decrypted_value
        except PermissionError:
            return "--- VAULT_LOCKED ---"
        except Exception:
            # If decryption fails (e.g. wrong key was used, or tampering), return an error marker
            return "--- DECRYPTION_ERROR ---"

# ====================================================================
# MODELS
# ====================================================================

class BlockchainAccount(models.Model):
    """User's blockchain account/wallet"""
    user_email = EncryptedTextField()
    blockchain_address = models.CharField(max_length=42, unique=True)
    public_key = models.TextField()
    private_key_encrypted = EncryptedTextField() # Added encryption
    created_at = models.DateTimeField(default=timezone.now)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        db_table = 'blockchain_accounts'
    
    def __str__(self):
        return f"{self.blockchain_address}"

class CanaryToken(models.Model):
    # token_id and token_url remain non-encrypted as they are public/external identifiers
    token_id = models.CharField(max_length=500, unique=True)
    token_url = models.TextField() 
    description = EncryptedTextField(blank=True) # Now encrypted
    created_at = models.DateTimeField(default=timezone.now)
    is_active = models.BooleanField(default=True)
    trigger_count = models.IntegerField(default=0)
    last_triggered = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = 'canary_tokens'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.token_id} - {self.description[:50]}"

class EncryptedFile(models.Model):
    original_path = EncryptedTextField()
    encrypted_path = EncryptedTextField()
    file_name = EncryptedTextField(max_length=500)
    file_type = models.CharField(max_length=10, choices=[('file', 'File'), ('folder', 'Folder')])
    salt = models.CharField(max_length=500)
    
    ipfs_cid = models.CharField(max_length=255, blank=True, null=True) 
    requires_2fa = models.BooleanField(default=False)

    device_hash = models.CharField(max_length=500)
    mac_address = EncryptedTextField(max_length=100)
    ip_address = EncryptedTextField(max_length=50)
    wifi_ssid = EncryptedTextField(max_length=200, blank=True, null=True)
    latitude = models.FloatField(blank=True, null=True)
    longitude = models.FloatField(blank=True, null=True)
    canary_token = models.ForeignKey(CanaryToken, on_delete=models.SET_NULL, null=True, blank=True, related_name='encrypted_files')
    encrypted_at = models.DateTimeField(default=timezone.now)
    last_accessed = models.DateTimeField(blank=True, null=True)
    access_count = models.IntegerField(default=0)
    is_active = models.BooleanField(default=True)
    is_deleted_by_user = models.BooleanField(default=False)
    deleted_at = models.DateTimeField(null=True, blank=True)
    
    # Blockchain fields remain non-encrypted for external visibility
    blockchain_file_id = models.IntegerField(null=True, blank=True)
    blockchain_tx_hash = models.CharField(max_length=66, blank=True)
    blockchain_file_hash = models.CharField(max_length=66, blank=True)
    blockchain_registered = models.BooleanField(default=False)
    blockchain_owner = models.CharField(max_length=42, blank=True)
    
    class Meta:
        db_table = 'encrypted_files'
        ordering = ['-encrypted_at']
    
    def __str__(self):
        return f"{self.id} - File"

class ActivityLog(models.Model):
    # ... (ACTION_CHOICES and SEVERITY_CHOICES)
    ACTION_CHOICES = [
        ('encrypt', 'Encrypted'), ('decrypt', 'Decrypted'), ('access_denied', 'Access Denied'),
        ('file_moved', 'File Moved'), ('file_copied', 'File Copied'), ('file_renamed', 'File Renamed'),
        ('file_deleted', 'File Deleted'), ('file_restored', 'File Restored'), ('permission_changed', 'Permission Changed'),
        ('suspicious_activity', 'Suspicious Activity'), ('canary_triggered', 'Canary Token Triggered'),
        ('blockchain_registered', 'Blockchain Registered'), ('access_granted', 'Access Granted'),
        ('access_revoked', 'Access Revoked'), ('integrity_verified', 'Integrity Verified'),
        ('integrity_violation', 'Integrity Violation'), ('2fa_setup', '2FA Setup'), ('2fa_failed', '2FA Failed'),
    ]
    
    SEVERITY_CHOICES = [
        ('info', 'Info'), ('warning', 'Warning'), ('alert', 'Alert'), ('critical', 'Critical'),
    ]

    encrypted_file = models.ForeignKey(EncryptedFile, on_delete=models.CASCADE, related_name='logs', null=True, blank=True)
    
    action = models.CharField(max_length=50, choices=ACTION_CHOICES)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='info')
    description = EncryptedTextField()
    device_info = models.JSONField(default=dict)
    ip_address = EncryptedTextField(max_length=50, blank=True, null=True)
    location_info = models.JSONField(default=dict, blank=True)
    timestamp = models.DateTimeField(default=timezone.now)
    
    # Blockchain fields
    blockchain_logged = models.BooleanField(default=False)
    blockchain_tx_hash = models.CharField(max_length=66, blank=True)
    
    class Meta:
        db_table = 'activity_logs'
        ordering = ['-timestamp']
    
    def __str__(self):
        return f"{self.action} - {self.timestamp}"

class TrustedUser(models.Model):
    """Users who have been granted access to encrypted files"""
    encrypted_file = models.ForeignKey(EncryptedFile, on_delete=models.CASCADE, related_name='trusted_users')
    user_email = EncryptedTextField()
    blockchain_address = models.CharField(max_length=42)
    public_key = models.TextField() 
    granted_by = models.CharField(max_length=100)
    granted_at = models.DateTimeField(default=timezone.now)
    is_active = models.BooleanField(default=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    
    # Blockchain registration
    blockchain_tx_hash = models.CharField(max_length=66, blank=True)
    blockchain_registered = models.BooleanField(default=False)
    
    class Meta:
        db_table = 'trusted_users'
        unique_together = ['encrypted_file', 'blockchain_address']
    
    def __str__(self):
        return f"{self.blockchain_address}"

class CanaryTriggerLog(models.Model):
    """Log when canary tokens are triggered"""
    canary_token = models.ForeignKey(CanaryToken, on_delete=models.CASCADE, related_name='triggers')
    encrypted_file = models.ForeignKey(EncryptedFile, on_delete=models.SET_NULL, null=True, blank=True)
    triggered_at = models.DateTimeField(default=timezone.now)
    ip_address = EncryptedTextField(max_length=50, blank=True, null=True)
    user_agent = EncryptedTextField(blank=True)
    location_info = models.JSONField(default=dict, blank=True)
    additional_data = models.JSONField(default=dict, blank=True)
    
    class Meta:
        db_table = 'canary_trigger_logs'
        ordering = ['-triggered_at']

class DeviceAuthorization(models.Model):
    device_hash = models.CharField(max_length=500, unique=True)
    device_name = EncryptedTextField(max_length=200)
    mac_address = EncryptedTextField(max_length=100)
    ip_address = EncryptedTextField(max_length=50)
    wifi_ssid = EncryptedTextField(max_length=200, blank=True, null=True)
    latitude = models.FloatField(blank=True, null=True)
    longitude = models.FloatField(blank=True, null=True)
    is_authorized = models.BooleanField(default=True)
    first_seen = models.DateTimeField(default=timezone.now)
    last_seen = models.DateTimeField(default=timezone.now)
    
    class Meta:
        db_table = 'device_authorizations'

class AppSettings(models.Model):
    """
    Application settings.
    master_key_hash is non-encrypted (it's already a hash).
    Other sensitive values like totp_secret are encrypted.
    """
    setting_key = models.CharField(max_length=100, unique=True)
    setting_value = models.TextField()  # Plain text field
    description = models.TextField(blank=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'app_settings'

    def __str__(self):
        return self.setting_key
    
    def save(self, *args, **kwargs):
        """
        Custom save to conditionally encrypt based on setting_key.
        """
        non_encrypted_keys = ['master_key_hash']
        
        # Keys to encrypt using EncryptedTextField logic
        keys_to_encrypt = ['totp_secret'] 

        if self.setting_key in keys_to_encrypt:
            try:
                if vault.is_active():
                    master_key = vault.get_master_key_for_dek()
                    
                    # Only encrypt if not already encrypted
                    if self.setting_value and not self.setting_value.startswith('aes:'):
                        self.setting_value = encrypt_data(self.setting_value, master_key)
                    if self.description and not self.description.startswith('aes:'):
                        self.description = encrypt_data(self.description, master_key)
            except Exception:
                pass
        
        super().save(*args, **kwargs)
    
    def get_decrypted_value(self):
        """Helper method to get decrypted value"""
        non_encrypted_keys = ['master_key_hash']
        
        if self.setting_key in non_encrypted_keys:
            return self.setting_value
        
        try:
            if vault.is_active():
                master_key = vault.get_master_key_for_dek()
                return decrypt_data(self.setting_value, master_key)
            else:
                return "--- VAULT_LOCKED ---"
        except Exception:
            return self.setting_value # Return unencrypted value if decryption fails