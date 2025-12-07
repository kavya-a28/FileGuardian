import os
import subprocess
import tempfile
import pyotp
import qrcode
import base64
import requests 
import hashlib
import time
from io import BytesIO
from pathlib import Path
from django.views.decorators.csrf import csrf_exempt
from django.utils import timezone
from rest_framework.decorators import api_view
from rest_framework.response import Response
from core.models import (EncryptedFile, ActivityLog, DeviceAuthorization, 
                         CanaryToken, CanaryTriggerLog, AppSettings, TrustedUser)
from core.encryption import FileEncryptor
from core.device_auth import get_device_info, generate_device_hash, verify_device
from core.utils import send_alert_email
from core.vault import vault # Import the Vault Manager

# --- BLOCKCHAIN ERROR HANDLING IMPORTS ---
try:
    from web3.exceptions import BadFunctionCallOutput
    from eth_abi.exceptions import InsufficientDataBytes
except ImportError:
    pass
# -----------------------------------------

# Try to import blockchain service, but make it optional
try:
    from core.blockchain_service import get_blockchain_service
    BLOCKCHAIN_ENABLED = True
except ImportError:
    BLOCKCHAIN_ENABLED = False
    print("⚠️  Blockchain service not available - running without blockchain features")
except Exception as e:
    # This will catch other import errors
    print(f"❌ CRITICAL ERROR importing blockchain_service: {e}")
    print("   Is Ganache running? Is contract.json correct? Is the IPFS library installed?")
    BLOCKCHAIN_ENABLED = False

# ==============================================================================
#  VAULT ENDPOINTS (The Master Key Gatekeeper)
# ==============================================================================

# ==============================================================================
#  VAULT ENDPOINTS (The Master Key Gatekeeper)
# ==============================================================================

@csrf_exempt
@api_view(['GET'])
def get_vault_status(request):
    """
    Checks if vault is locked or unlocked, and ensures the stored hash is loaded 
    into the VaultManager's RAM on startup.
    """
    try:
        # Check if master key hash exists in DB
        key_setting = AppSettings.objects.filter(setting_key='master_key_hash').first()
        is_setup = key_setting is not None
        
        # CRITICAL FIX: Always reload hash from DB if not initialized
        if is_setup and not vault.is_initialized():
            vault.initialize_vault(key_setting.setting_value)
        
        return Response({
            'is_locked': not vault.is_active(),
            'is_setup': is_setup
        })
    except Exception as e:
        return Response({
            'is_locked': True, 
            'is_setup': False, 
            'error': str(e)
        })

@csrf_exempt
@api_view(['POST'])
def setup_vault(request):
    """First time setup: Set a Master Key"""
    password = request.data.get('password')
    if not password or len(password) < 8:
        return Response({'error': 'Password must be at least 8 chars'}, status=400)
    
    if AppSettings.objects.filter(setting_key='master_key_hash').exists():
        return Response({'error': 'Vault already setup'}, status=400)
    
    hashed = hashlib.sha256(password.encode()).hexdigest()
    
    # Store the hash of the master key for verification (not the raw key)
    AppSettings.objects.create(
        setting_key='master_key_hash',
        setting_value=hashed,  # Store as plain text since it's a hash
        description='Hash of the Master Vault Key'
    )
    
    # Initialize RAM vault and unlock it immediately after setup
    vault.initialize_vault(hashed)
    vault.unlock(password)
    
    return Response({'success': True, 'message': 'Vault Setup Complete'})

@csrf_exempt
@api_view(['POST'])
def unlock_vault(request):
    """Unlock the vault with password"""
    password = request.data.get('password')
    if not password:
        return Response({'error': 'Password required'}, status=400)
    
    # Ensure hash is loaded
    key_setting = AppSettings.objects.filter(setting_key='master_key_hash').first()
    if not key_setting:
        return Response({'error': 'Vault not setup'}, status=400)
    
    # Reload hash if not initialized
    if not vault.is_initialized():
        vault.initialize_vault(key_setting.setting_value)
    
    # Vault handles hash comparison and setting the key in RAM
    if vault.unlock(password):
        return Response({'success': True, 'message': 'Vault Unlocked'})
    else:
        time.sleep(1)  # Delay to prevent brute force
        return Response({'error': 'Invalid Password'}, status=401)

@csrf_exempt
@api_view(['POST'])
def lock_vault(request):
    """Lock the vault (clear RAM)"""
    vault.lock()
    return Response({'success': True, 'message': 'Vault Locked'})
# ==============================================================================
#  2FA HELPER FUNCTIONS
# ==============================================================================
def get_totp_secret():
    """Retrieve 2FA secret from DB"""
    try:
        setting = AppSettings.objects.get(setting_key='totp_secret')
        # DECRYPT the secret before returning
        return setting.get_decrypted_value()
    except AppSettings.DoesNotExist:
        return None

def verify_totp_code(code):
    """Verify a TOTP code"""
    secret = get_totp_secret()
    if not secret:
        return False # 2FA not set up
    # Provide a slight time window drift for usability
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)
# ----------------------------


@csrf_exempt
@api_view(['POST'])
def setup_2fa(request):
    """Generate a new 2FA secret and QR code"""
    try:
        # Generate random secret
        secret = pyotp.random_base32()
        
        # Create TOTP object
        totp = pyotp.TOTP(secret)
        # Label format: Issuer:AccountName
        provisioning_uri = totp.provisioning_uri(name="Guardian User", issuer_name="File Guardian")
        
        # Generate QR Code
        qr = qrcode.make(provisioning_uri)
        buffered = BytesIO()
        qr.save(buffered, format="PNG")
        qr_base64 = base64.b64encode(buffered.getvalue()).decode()
        
        return Response({
            'secret': secret,
            'qr_code': f"data:image/png;base64,{qr_base64}"
        })
    except Exception as e:
        return Response({'error': str(e)}, status=500)

@csrf_exempt
@api_view(['POST'])
def confirm_2fa_setup(request):
    """Confirm and save 2FA secret"""
    secret = request.data.get('secret')
    code = request.data.get('code')
    
    if not secret or not code:
        return Response({'error': 'Missing secret or code'}, status=400)
        
    totp = pyotp.TOTP(secret)
    if totp.verify(code, valid_window=1):
        # Save to DB
        AppSettings.objects.update_or_create(
            setting_key='totp_secret',
            defaults={
                'setting_value': secret,
                'description': 'TOTP 2FA Secret Key'
            }
        )
        
        device_info = get_device_info()
        ActivityLog.objects.create(
            action='2fa_setup',
            severity='info',
            description="✅ 2FA Globally Enabled",
            device_info=device_info
        )
        
        return Response({'success': True, 'message': '2FA enabled successfully'})
    else:
        return Response({'error': 'Invalid code. Please try scanning again.'}, status=400)


@csrf_exempt
@api_view(['POST'])
def encrypt_file_or_folder(request):
    """Encrypt a file or folder, upload to IPFS, and register on blockchain"""
    try:
        file_path = request.data.get('file_path')
        master_key = request.data.get('master_key')
        file_type = request.data.get('file_type', 'file')
        use_canary = request.data.get('use_canary', False)
        requires_2fa = request.data.get('requires_2fa', False) # NEW param
        register_on_blockchain = request.data.get('register_on_blockchain', True) and BLOCKCHAIN_ENABLED
        
        if not file_path or not master_key:
            return Response({'error': 'Missing file_path or master_key'}, status=400)
        
        if not os.path.exists(file_path):
            return Response({'error': 'File or folder does not exist'}, status=404)
        
        # Check if 2FA is requested but not set up globally
        if requires_2fa and not get_totp_secret():
            return Response({'error': 'Cannot require 2FA: Please enable 2FA in Settings first.'}, status=400)

        device_info = get_device_info()
        device_hash = generate_device_hash()
        
        # Get canary token if requested
        canary_token_obj = None
        canary_token_url = None
        if use_canary:
            try:
                canary_setting = AppSettings.objects.filter(setting_key='default_canary_token').first()
                if canary_setting and canary_setting.setting_value:
                    canary_token_obj = CanaryToken.objects.filter(token_url=canary_setting.setting_value).first()
                    if canary_token_obj:
                        canary_token_url = canary_token_obj.setting_value # Use setting_value for the URL
            except:
                pass
        
        # Initialize encryptor with metadata flags
        encryptor = FileEncryptor(master_key, canary_token_url, requires_2fa)
        file_name = Path(file_path).name
        
        if file_type == 'folder':
            print("⚠️ Folder encryption with IPFS is not fully implemented in this example.")
            return Response({'error': 'Folder encryption with IPFS is not yet supported.'}, status=501)
        
        else:
            encrypted_path, salt = encryptor.encrypt_file(file_path)
            
            encrypted_record = EncryptedFile.objects.create(
                original_path=file_path,
                encrypted_path=encrypted_path,
                file_name=file_name,
                file_type='file',
                salt=salt.hex(),
                device_hash=device_hash,
                mac_address=device_info['mac_address'],
                ip_address=device_info['ip_address'],
                wifi_ssid=device_info['wifi_ssid'],
                latitude=device_info['latitude'],
                longitude=device_info['longitude'],
                canary_token=canary_token_obj,
                requires_2fa=requires_2fa  # Save 2FA status to DB
            )
            message = "File encrypted at original location"

        # Register on blockchain
        blockchain_info = {'registered': False}
        if register_on_blockchain:
            try:
                blockchain = get_blockchain_service()
                
                result = blockchain.register_file(
                    encrypted_record.encrypted_path,
                    encrypted_record.file_name,
                    blockchain.default_account
                )
                
                if result['success']:
                    encrypted_record.ipfs_cid = result['ipfs_cid']
                    encrypted_record.blockchain_file_id = result['file_id']
                    encrypted_record.blockchain_tx_hash = result['tx_hash']
                    encrypted_record.blockchain_file_hash = result['file_hash']
                    encrypted_record.blockchain_registered = True
                    encrypted_record.blockchain_owner = blockchain.default_account
                    encrypted_record.save()
                    
                    blockchain_info = {
                        'registered': True,
                        'file_id': result['file_id'],
                        'tx_hash': result['tx_hash'],
                        'ipfs_cid': result['ipfs_cid'] 
                    }
                    
                    blockchain.log_activity(
                        result['file_id'],
                        'encrypt',
                        'info',
                        f"File encrypted: {file_name}"
                    )
                    message += f" and registered on blockchain (ID: {result['file_id']})"
            except Exception as e:
                print(f"⚠️ Blockchain registration failed: {e}")
                blockchain_info = {'registered': False, 'error': str(e)}
        
        log_desc = f"✅ Successfully encrypted {file_type}: {file_name}\n📍 Location: {file_path}\n🔐 Encrypted in place"
        if canary_token_url:
            log_desc += " [Canary Token Embedded]"
        if requires_2fa:
            log_desc += " [2FA Protected]"
        if blockchain_info.get('registered'):
            log_desc += f"\n🔗 Registered on blockchain (IPFS CID: {blockchain_info.get('ipfs_cid')})"
        
        ActivityLog.objects.create(
            encrypted_file=encrypted_record,
            action='encrypt',
            severity='info',
            description=log_desc,
            device_info=device_info,
            ip_address=device_info['ip_address']
        )
        
        DeviceAuthorization.objects.update_or_create(
            device_hash=device_hash,
            defaults={
                'device_name': device_info['hostname'],
                'mac_address': device_info['mac_address'],
                'ip_address': device_info['ip_address'],
                'wifi_ssid': device_info['wifi_ssid'],
                'latitude': device_info['latitude'],
                'longitude': device_info['longitude'],
                'last_seen': timezone.now()
            }
        )
        
        return Response({
            'success': True,
            'message': message,
            'encrypted_id': encrypted_record.id,
            'encrypted_path': encrypted_record.encrypted_path,
            'file_name': encrypted_record.file_name,
            'has_canary': canary_token_url is not None,
            'requires_2fa': requires_2fa,
            'blockchain': blockchain_info,
            'info': 'File encrypted, stored on IPFS, and monitored by Guardian'
        })
        
    except Exception as e:
        import traceback
        print(traceback.format_exc())
        return Response({'error': str(e)}, status=500)

@csrf_exempt
@api_view(['POST'])
def decrypt_file_or_folder(request):
    """Decrypt and open file by downloading from IPFS"""
    try:
        encrypted_id = request.data.get('encrypted_id')
        master_key = request.data.get('master_key')
        totp_code = request.data.get('totp_code') # User provided code
        
        if not encrypted_id or not master_key:
            return Response({'error': 'Missing encrypted_id or master_key'}, status=400)
        
        encrypted_record = EncryptedFile.objects.get(id=encrypted_id, is_active=True)
        device_info = get_device_info()
        
        if encrypted_record.is_deleted_by_user:
            return Response({
                'error': 'File was deleted from file system',
                'deleted_at': encrypted_record.deleted_at,
                'can_restore': True 
            }, status=404)
        
        # --- 2FA GATEKEEPER CHECK ---
        if encrypted_record.requires_2fa:
            if not totp_code:
                return Response({
                    'error': '2FA Code Required', 
                    'requires_2fa': True,
                    'file_name': encrypted_record.file_name
                }, status=401)
            
            # Verify code
            if not verify_totp_code(totp_code):
                # --- NEW LOGIC: Trigger Canary on 2FA Failure ---
                canary_triggered = False
                if encrypted_record.canary_token:
                    canary_url = encrypted_record.canary_token.token_url
                    try:
                        requests.get(
                            canary_url,
                            timeout=5,
                            headers={'User-Agent': f'FileGuardian-2FA-FAILED / {device_info["hostname"]}'}
                        )
                        CanaryTriggerLog.objects.create(
                            canary_token=encrypted_record.canary_token,
                            encrypted_file=encrypted_record,
                            ip_address=device_info['ip_address'],
                            user_agent=f'FileGuardian-2FA-Failed',
                            additional_data={'reason': 'Invalid 2FA Code', 'failed_attempt': True}
                        )
                        encrypted_record.canary_token.trigger_count += 1
                        encrypted_record.canary_token.last_triggered = timezone.now()
                        encrypted_record.canary_token.save()
                        canary_triggered = True
                        print(f"🚨 Canary triggered due to 2FA failure for {encrypted_record.file_name}")
                    except Exception as e:
                        print(f"❌ Error triggering canary on 2FA fail: {e}")

                # 4. SEND EMAIL ALERT (NEW)
                send_alert_email(
                    filename=encrypted_record.file_name,
                    reason="Invalid 2FA Code (Potential Brute Force)",
                    ip_address=device_info['ip_address'],
                    device_name=device_info['hostname']
                )

                # 5. Create Activity Log
                log_desc = f"⚠️ Invalid 2FA code attempt for {encrypted_record.file_name}"
                if canary_triggered:
                    log_desc += "\n🚨 Canary token triggered by this security failure!"

                ActivityLog.objects.create(
                    encrypted_file=encrypted_record,
                    action='2fa_failed',
                    severity='alert' if canary_triggered else 'warning',
                    description=log_desc,
                    device_info=device_info,
                    ip_address=device_info['ip_address']
                )

                return Response({'error': 'Invalid 2FA Code'}, status=403)
        # --- END 2FA CHECK ---

        # --- SECURITY CHECK (Device Verification) ---
        is_authorized, verification_message = verify_device(
            encrypted_record.device_hash,
            encrypted_record.mac_address,
            encrypted_record.ip_address,
            encrypted_record.wifi_ssid,
            encrypted_record.latitude,
            encrypted_record.longitude
        )
        
        # CRITICAL: Trigger canary for UNAUTHORIZED access (Device Mismatch)
        if not is_authorized and encrypted_record.canary_token:
            canary_url = encrypted_record.canary_token.token_url
            try:
                import requests
                response = requests.get(
                    canary_url,
                    timeout=10,
                    headers={'User-Agent': f'FileGuardian-Unauthorized-Access / Device: {device_info["hostname"]}'}
                )
                CanaryTriggerLog.objects.create(
                    canary_token=encrypted_record.canary_token,
                    encrypted_file=encrypted_record,
                    ip_address=device_info['ip_address'],
                    user_agent=f'FileGuardian / {device_info["hostname"]}',
                    additional_data={'unauthorized_attempt': True, 'reason': verification_message}
                )
                encrypted_record.canary_token.trigger_count += 1
                encrypted_record.canary_token.last_triggered = timezone.now()
                encrypted_record.canary_token.save()
            except Exception as e:
                print(f"❌ Error triggering canary: {e}")
    
        # If not authorized, block access
        if not is_authorized:
            # 1. SEND EMAIL ALERT (NEW)
            send_alert_email(
                filename=encrypted_record.file_name,
                reason=f"Unauthorized Device: {verification_message}",
                ip_address=device_info['ip_address'],
                device_name=device_info['hostname']
            )

            # 2. Log Activity
            ActivityLog.objects.create(
                encrypted_file=encrypted_record,
                action='access_denied',
                severity='critical',
                description=f"🚨 UNAUTHORIZED ACCESS BLOCKED!\n\nReason: {verification_message}\n\n📍 Device Info:\n• IP: {device_info['ip_address']}\n• Device: {device_info['hostname']}\n• MAC: {device_info['mac_address']}\n\n🕵️ Canary token triggered!",
                device_info=device_info,
                ip_address=device_info['ip_address']
            )
            
            return Response({
                'success': False,
                'error': 'Device verification failed - Unauthorized access blocked',
                'reason': verification_message,
                'canary_triggered': encrypted_record.canary_token is not None
            }, status=403)
        # --- END SECURITY CHECK ---
            
        if not encrypted_record.ipfs_cid:
            return Response({
                'error': 'File data not found. No IPFS record is associated with this file.',
                'path': encrypted_record.encrypted_path
            }, status=404)
        
        encryptor = FileEncryptor(master_key)
        
        print(f"⬇️ Downloading {encrypted_record.ipfs_cid} from IPFS...")
        blockchain = get_blockchain_service()
        encrypted_content = blockchain.download_from_ipfs(encrypted_record.ipfs_cid)
        
        temp_enc_file = tempfile.NamedTemporaryFile(delete=False, prefix='guardian_enc_')
        temp_enc_file.write(encrypted_content)
        temp_enc_file.close()
        encrypted_path_for_decryption = temp_enc_file.name
        print(f"⤵️ Downloaded to temporary file: {encrypted_path_for_decryption}")

        temp_dir = tempfile.mkdtemp(prefix='guardian_decrypt_')
        
        canary_detected = False
        
        if encrypted_record.file_type == 'folder':
            os.unlink(encrypted_path_for_decryption)
            return Response({'error': 'Folder decryption from IPFS not yet implemented'}, status=501)
        
        else:
            salt = bytes.fromhex(encrypted_record.salt)
            output_path = os.path.join(temp_dir, encrypted_record.file_name)
            
            decrypted_path, metadata = encryptor.decrypt_file(
                encrypted_path_for_decryption,
                output_path,
                salt,
                trigger_canary=False
            )
            
            os.unlink(encrypted_path_for_decryption)
            
            if metadata.get('canary_token'):
                canary_detected = True
            
            if os.name == 'nt':
                os.startfile(decrypted_path)
            elif os.name == 'posix':
                subprocess.call(['open' if os.uname().sysname == 'Darwin' else 'xdg-open', decrypted_path])
            
            encrypted_record.last_accessed = timezone.now()
            encrypted_record.access_count += 1
            encrypted_record.save()
            
            log_description = f"✅ Owner accessed {encrypted_record.file_type}: {encrypted_record.file_name}\n📍 Opened from: {temp_dir}"
            if canary_detected:
                log_description += "\n🔒 Canary token present (NOT triggered for owner)"
            if encrypted_record.requires_2fa:
                log_description += "\n🛡️ 2FA Verified"
            
            ActivityLog.objects.create(
                encrypted_file=encrypted_record,
                action='decrypt',
                severity='info',
                description=log_description,
                device_info=device_info,
                ip_address=device_info['ip_address']
            )
            
            return Response({
                'success': True,
                'message': "File decrypted and opened from IPFS",
                'decrypted_path': decrypted_path,
                'canary_detected': canary_detected,
                'is_owner': is_authorized,
                'requires_2fa': encrypted_record.requires_2fa
            })
            
    except EncryptedFile.DoesNotExist:
        return Response({'error': 'Encrypted file not found'}, status=404)
    except Exception as e:
        import traceback
        print(f"❌ Error: {e}")
        print(traceback.format_exc())
        return Response({'error': str(e)}, status=500)

@api_view(['POST'])
def restore_deleted_file(request, file_id):
    """Restore file from IPFS to its original encrypted location"""
    try:
        encrypted_file = EncryptedFile.objects.get(id=file_id, is_deleted_by_user=True)
        
        target_path = encrypted_file.original_path
        target_dir = os.path.dirname(target_path)
        
        if not os.path.exists(target_dir):
            os.makedirs(target_dir, exist_ok=True)
        
        if not encrypted_file.ipfs_cid:
            return Response({'error': 'Cannot restore: No IPFS backup found for this file.'}, status=404)

        print(f"♻️ Restoring {encrypted_file.ipfs_cid} from IPFS to {target_path}...")
        blockchain = get_blockchain_service()
        encrypted_content = blockchain.download_from_ipfs(encrypted_file.ipfs_cid)
        
        with open(target_path, 'wb') as f:
            f.write(encrypted_content)
        
        restored_path = target_path
        
        encrypted_file.is_deleted_by_user = False
        encrypted_file.deleted_at = None
        encrypted_file.save()
        
        device_info = get_device_info()
        ActivityLog.objects.create(
            encrypted_file=encrypted_file,
            action='file_restored',
            severity='info',
            description=f"✅ File restored from IPFS: {encrypted_file.file_name}\n📍 Restored to: {target_path}",
            device_info=device_info,
            ip_address=device_info['ip_address']
        )
        
        return Response({
            'success': True,
            'message': 'File restored successfully from IPFS',
            'restored_path': restored_path
        })
        
    except EncryptedFile.DoesNotExist:
        return Response({'error': 'File not found or not deleted'}, status=404)
    except Exception as e:
        return Response({'error': str(e)}, status=500)

# --- NEW RECOVERY FUNCTIONS ---

@api_view(['GET'])
def scan_recovery_status(request):
    """
    Compare Blockchain records vs Local Database
    to find files that were deleted locally (Disaster Recovery)
    """
    if not BLOCKCHAIN_ENABLED:
        return Response({'error': 'Blockchain not enabled'}, status=503)

    try:
        blockchain = get_blockchain_service()
        
        # --- HARDENED BLOCKCHAIN CALL ---
        # Catches the specific error when Contract address doesn't exist on current chain
        try:
            file_count = blockchain.contract.functions.fileCount().call()
        except (BadFunctionCallOutput, InsufficientDataBytes, ValueError):
            return Response({
                'error': 'Blockchain Connection Error',
                'details': 'Contract address mismatch. Did you restart Ganache? Please redeploy contract and update settings.'
            }, status=503)
        # ---------------------------------
        
        recovery_list = []
        
        for i in range(1, file_count + 1):
            file_data = blockchain.get_file_info(i)
            
            if not file_data['success']:
                continue
                
            local_exists = EncryptedFile.objects.filter(blockchain_file_id=i).exists()
            status = 'missing' if not local_exists else 'safe'
            
            recovery_list.append({
                'blockchain_id': i,
                'name': file_data['metadata'].get('name', 'Unknown'),
                'ipfs_cid': file_data['ipfs_cid'],
                'status': status,
                'timestamp': file_data['timestamp']
            })
            
        return Response({
            'success': True,
            'total_blockchain': file_count,
            'files': recovery_list
        })
        
    except Exception as e:
        import traceback
        print(traceback.format_exc())
        return Response({'error': 'Blockchain service failed to respond'}, status=503)

@api_view(['POST'])
def perform_full_recovery(request):
    """
    Download from IPFS and Re-create Database Record
    (Used when database is wiped/corrupted)
    """
    try:
        blockchain_id = request.data.get('blockchain_id')
        ipfs_cid = request.data.get('ipfs_cid')
        file_name = request.data.get('file_name')
        
        print(f"♻️ DISASTER RECOVERY: Downloading {ipfs_cid}...")
        blockchain = get_blockchain_service()
        encrypted_content = blockchain.download_from_ipfs(ipfs_cid)
        
        from django.conf import settings
        recovery_dir = os.path.join(settings.BASE_DIR, 'Recovered_Files')
        if not os.path.exists(recovery_dir):
            os.makedirs(recovery_dir)
            
        target_path = os.path.join(recovery_dir, file_name)
        
        with open(target_path, 'wb') as f:
            f.write(encrypted_content)
            
        with open(target_path, 'rb') as f:
            salt = f.read(16)
            
        device_info = get_device_info()
        device_hash = generate_device_hash()
        
        new_record = EncryptedFile.objects.create(
            original_path=target_path,
            encrypted_path=target_path,
            file_name=file_name,
            file_type='file',
            salt=salt.hex(), # Extracted from the file header!
            ipfs_cid=ipfs_cid,
            blockchain_file_id=blockchain_id,
            blockchain_registered=True,
            device_hash=device_hash,
            mac_address=device_info['mac_address'],
            ip_address=device_info['ip_address'],
            wifi_ssid=device_info['wifi_ssid'],
            latitude=device_info['latitude'],
            longitude=device_info['longitude'],
            is_active=True,
            encrypted_at=timezone.now()
        )
        
        return Response({
            'success': True,
            'message': f"File recovered to {target_path}",
            'new_id': new_record.id
        })
        
    except Exception as e:
        import traceback
        print(traceback.format_exc())
        return Response({'error': str(e)}, status=500)

@api_view(['POST'])
def restore_deleted_file(request, file_id):
    """Restore file from IPFS to its original encrypted location"""
    try:
        encrypted_file = EncryptedFile.objects.get(id=file_id, is_deleted_by_user=True)
        
        target_path = encrypted_file.original_path
        target_dir = os.path.dirname(target_path)
        
        if not os.path.exists(target_dir):
            os.makedirs(target_dir, exist_ok=True)
        
        if not encrypted_file.ipfs_cid:
            return Response({'error': 'Cannot restore: No IPFS backup found for this file.'}, status=404)

        print(f"♻️ Restoring {encrypted_file.ipfs_cid} from IPFS to {target_path}...")
        blockchain = get_blockchain_service()
        encrypted_content = blockchain.download_from_ipfs(encrypted_file.ipfs_cid)
        
        with open(target_path, 'wb') as f:
            f.write(encrypted_content)
        
        restored_path = target_path
        
        encrypted_file.is_deleted_by_user = False
        encrypted_file.deleted_at = None
        encrypted_file.save()
        
        device_info = get_device_info()
        ActivityLog.objects.create(
            encrypted_file=encrypted_file,
            action='file_restored',
            severity='info',
            description=f"✅ File restored from IPFS: {encrypted_file.file_name}\n📍 Restored to: {target_path}",
            device_info=device_info,
            ip_address=device_info['ip_address']
        )
        
        return Response({
            'success': True,
            'message': 'File restored successfully from IPFS',
            'restored_path': restored_path
        })
        
    except EncryptedFile.DoesNotExist:
        return Response({'error': 'File not found or not deleted'}, status=404)
    except Exception as e:
        return Response({'error': str(e)}, status=500)

@api_view(['GET'])
def list_encrypted_files(request):
    """List all encrypted files"""
    include_deleted = request.GET.get('include_deleted', 'false').lower() == 'true'
    
    if include_deleted:
        files = EncryptedFile.objects.filter(is_active=True)
    else:
        files = EncryptedFile.objects.filter(is_active=True, is_deleted_by_user=False)
    
    files_data = files.values(
        'id', 'file_name', 'file_type', 'encrypted_path', 'encrypted_at', 
        'last_accessed', 'access_count', 'is_deleted_by_user', 'deleted_at',
        'blockchain_registered', 'blockchain_file_id', 'ipfs_cid', 'requires_2fa'
    )
    
    files_list = list(files_data)
    for file in files_list:
        if not file['is_deleted_by_user']:
            file['exists'] = os.path.exists(file['encrypted_path'])
            file['location'] = os.path.dirname(file['encrypted_path'])
            if not file['exists'] and file['ipfs_cid']:
                file['location'] = "Backed up on IPFS (not found locally)"
        else:
            file['exists'] = False
            file['location'] = 'Deleted (backed up on IPFS)'
    
    return Response({'files': files_list})

@api_view(['GET'])
def get_activity_logs(request):
    """Get activity logs"""
    file_id = request.GET.get('file_id')
    severity = request.GET.get('severity')
    
    logs = ActivityLog.objects.all()
    
    if file_id:
        logs = logs.filter(encrypted_file_id=file_id)
    if severity:
        logs = logs.filter(severity=severity)
    
    logs = logs[:100]
    
    logs_data = logs.values(
        'id', 'action', 'severity', 'description', 
        'ip_address', 'timestamp', 'encrypted_file__file_name'
    )
    
    return Response({'logs': list(logs_data)})

@api_view(['DELETE'])
def delete_encrypted_file(request, file_id):
    """Delete encrypted file from monitoring"""
    try:
        encrypted_file = EncryptedFile.objects.get(id=file_id)
        file_name = encrypted_file.file_name
        
        device_info = get_device_info()
        ActivityLog.objects.create(
            encrypted_file=encrypted_file,
            action='file_deleted',
            severity='warning',
            description=f"🗑️ File removed from monitoring: {file_name}",
            device_info=device_info,
            ip_address=device_info['ip_address']
        )
        
        encrypted_file.is_active = False
        encrypted_file.save()
        
        return Response({
            'success': True,
            'message': 'File removed from monitoring',
        })
    except Exception as e:
        return Response({'error': str(e)}, status=500)

@api_view(['GET'])
def get_dashboard_stats(request):
    """Get dashboard statistics"""
    total_files = EncryptedFile.objects.filter(is_active=True, is_deleted_by_user=False).count()
    deleted_files = EncryptedFile.objects.filter(is_active=True, is_deleted_by_user=True).count()
    total_logs = ActivityLog.objects.count()
    
    critical_alerts = ActivityLog.objects.filter(severity='critical').count()
    alert_alerts = ActivityLog.objects.filter(severity='alert').count()
    alerts = critical_alerts + alert_alerts
    
    recent_activities = ActivityLog.objects.all()[:10].values(
        'action', 'severity', 'description', 'timestamp', 'encrypted_file__file_name'
    )
    
    suspicious = ActivityLog.objects.filter(
        severity__in=['critical', 'alert']
    ).count()
    
    active_canaries = CanaryToken.objects.filter(is_active=True).count()
    canary_triggers = CanaryTriggerLog.objects.count()
    
    return Response({
        'total_files': total_files,
        'deleted_files': deleted_files,
        'total_logs': total_logs,
        'alerts': alerts,
        'critical_alerts': critical_alerts,
        'suspicious_activities': suspicious,
        'active_canaries': active_canaries,
        'canary_triggers': canary_triggers,
        'recent_activities': list(recent_activities)
    })

@api_view(['GET'])
def get_file_location(request, file_id):
    """Get encrypted file location"""
    try:
        encrypted_file = EncryptedFile.objects.get(id=file_id, is_active=True)
        exists = os.path.exists(encrypted_file.encrypted_path) if not encrypted_file.is_deleted_by_user else False
        
        return Response({
            'success': True,
            'file_name': encrypted_file.file_name,
            'location': encrypted_file.encrypted_path,
            'exists': exists,
            'is_deleted': encrypted_file.is_deleted_by_user,
            'directory': os.path.dirname(encrypted_file.encrypted_path)
        })
    except EncryptedFile.DoesNotExist:
        return Response({'error': 'File not found'}, status=404)

# Canary Token Management
@api_view(['POST'])
def create_canary_token(request):
    """Create a new canary token"""
    try:
        token_url = request.data.get('token_url')
        description = request.data.get('description', '')
        
        if not token_url:
            return Response({'error': 'token_url is required'}, status=400)
        
        import hashlib
        token_id = hashlib.md5(token_url.encode()).hexdigest()[:16]
        
        canary = CanaryToken.objects.create(
            token_id=token_id,
            token_url=token_url,
            description=description
        )
        
        return Response({
            'success': True,
            'token_id': canary.token_id,
            'message': 'Canary token created successfully'
        })
    except Exception as e:
        return Response({'error': str(e)}, status=500)

@api_view(['GET'])
def list_canary_tokens(request):
    """List all canary tokens"""
    tokens = CanaryToken.objects.filter(is_active=True).values(
        'id', 'token_id', 'token_url', 'description', 'created_at',
        'trigger_count', 'last_triggered'
    )
    return Response({'tokens': list(tokens)})

@api_view(['POST'])
def set_default_canary_token(request):
    """Set default canary token"""
    try:
        token_url = request.data.get('token_url', '')
        
        AppSettings.objects.update_or_create(
            setting_key='default_canary_token',
            defaults={
                'setting_value': token_url,
                'description': 'Default canary token URL'
            }
        )
        
        return Response({
            'success': True,
            'message': 'Default canary token updated'
        })
    except Exception as e:
        return Response({'error': str(e)}, status=500)

@api_view(['GET'])
def get_app_settings(request):
    """Get application settings"""
    try:
        default_canary = AppSettings.objects.filter(setting_key='default_canary_token').first()
        totp_secret = AppSettings.objects.filter(setting_key='totp_secret').first()
        
        canary_url = default_canary.setting_value if default_canary else ''
        
        return Response({
            'default_canary_token': canary_url,
            'has_canary_configured': bool(canary_url),
            'has_2fa_configured': bool(totp_secret), # Check if 2FA secret exists
            'blockchain_enabled': BLOCKCHAIN_ENABLED
        })
    except Exception as e:
        return Response({'error': str(e)}, status=500)

# Blockchain endpoints (only if blockchain is enabled)
if BLOCKCHAIN_ENABLED:
    @api_view(['POST'])
    def grant_file_access(request, file_id):
        """Grant access to trusted user on blockchain"""
        try:
            # file_id from URL, not request.data
            encrypted_file = EncryptedFile.objects.get(id=file_id, is_active=True)
            
            user_email = request.data.get('user_email')
            user_address = request.data.get('blockchain_address')
            user_public_key = request.data.get('public_key')
            
            if not all([user_email, user_address, user_public_key]):
                return Response({'error': 'Missing required fields'}, status=400)
            
            if not encrypted_file.blockchain_registered:
                return Response({'error': 'File not registered on blockchain'}, status=400)
            
            blockchain = get_blockchain_service()
            result = blockchain.grant_access(
                encrypted_file.blockchain_file_id,
                user_address,
                user_public_key
            )
            
            if result['success']:
                TrustedUser.objects.create(
                    encrypted_file=encrypted_file,
                    user_email=user_email,
                    blockchain_address=user_address,
                    public_key=user_public_key,
                    granted_by=encrypted_file.blockchain_owner,
                    blockchain_tx_hash=result['tx_hash'],
                    blockchain_registered=True
                )
                
                device_info = get_device_info()
                ActivityLog.objects.create(
                    encrypted_file=encrypted_file,
                    action='access_granted',
                    severity='info',
                    description=f"✅ Access granted to {user_email}\n🔗 TX: {result['tx_hash'][:10]}...",
                    device_info=device_info,
                    ip_address=device_info['ip_address']
                )
                
                return Response({
                    'success': True,
                    'message': 'Access granted successfully',
                    'tx_hash': result['tx_hash']
                })
            else:
                return Response({'error': result.get('error')}, status=500)
                
        except EncryptedFile.DoesNotExist:
            return Response({'error': 'File not found'}, status=404)
        except Exception as e:
            return Response({'error': str(e)}, status=500)

    @api_view(['POST'])
    def revoke_file_access(request, file_id):
        """Revoke access from trusted user"""
        try:
            encrypted_file = EncryptedFile.objects.get(id=file_id, is_active=True)
            user_address = request.data.get('blockchain_address')

            if not user_address:
                 return Response({'error': 'Missing blockchain_address'}, status=400)
                 
            trusted_user = TrustedUser.objects.get(
                encrypted_file=encrypted_file,
                blockchain_address=user_address,
                is_active=True
            )
            
            blockchain = get_blockchain_service()
            result = blockchain.revoke_access(
                encrypted_file.blockchain_file_id,
                user_address
            )
            
            if result['success']:
                trusted_user.is_active = False
                trusted_user.revoked_at = timezone.now()
                trusted_user.save()
                
                device_info = get_device_info()
                ActivityLog.objects.create(
                    encrypted_file=encrypted_file,
                    action='access_revoked',
                    severity='warning',
                    description=f"⚠️ Access revoked from {trusted_user.user_email}",
                    device_info=device_info,
                    ip_address=device_info['ip_address']
                )
                
                return Response({
                    'success': True,
                    'message': 'Access revoked successfully'
                })
            else:
                return Response({'error': result.get('error')}, status=500)
                
        except EncryptedFile.DoesNotExist:
            return Response({'error': 'File not found'}, status=404)
        except TrustedUser.DoesNotExist:
            return Response({'error': 'Trusted user not found or already revoked'}, status=404)
        except Exception as e:
            return Response({'error': str(e)}, status=500)

    @api_view(['POST'])
    def verify_file_integrity(request, file_id):
        """Verify file integrity using blockchain"""
        try:
            encrypted_file = EncryptedFile.objects.get(id=file_id, is_active=True)
            
            if not encrypted_file.blockchain_registered:
                return Response({'error': 'File not registered on blockchain'}, status=400)
            
            if not os.path.exists(encrypted_file.encrypted_path):
                 return Response({
                    'success': False,
                    'error': 'File not found at original location. Cannot verify integrity.',
                    'is_valid': False,
                    'details': 'File is backed up on IPFS, but not present locally for verification.'
                }, status=404)

            blockchain = get_blockchain_service()
            
            # --- HARDENED BLOCKCHAIN CALL ---
            try:
                result = blockchain.verify_file_integrity(
                    encrypted_file.blockchain_file_id,
                    encrypted_file.encrypted_path
                )
            except (BadFunctionCallOutput, InsufficientDataBytes, ValueError):
                return Response({
                    'error': 'Blockchain Verification Failed',
                    'details': 'Cannot connect to contract. Ensure Ganache is running and contract address is correct.'
                }, status=503)
            # ---------------------------------
            
            if result['success']:
                device_info = get_device_info()
                
                if result['is_valid']:
                    ActivityLog.objects.create(
                        encrypted_file=encrypted_file,
                        action='integrity_verified',
                        severity='info',
                        description=f"✅ Integrity verified - No tampering",
                        device_info=device_info,
                        ip_address=device_info['ip_address']
                    )
                else:
                    ActivityLog.objects.create(
                        encrypted_file=encrypted_file,
                        action='integrity_violation',
                        severity='critical',
                        description=f"🚨 FILE TAMPERED!\nHash mismatch detected",
                        device_info=device_info,
                        ip_address=device_info['ip_address']
                    )
                
                return Response({
                    'success': True,
                    'is_valid': result['is_valid'],
                    'original_hash': result['original_hash'],
                    'current_hash': result['current_hash']
                })
            else:
                return Response({'error': result.get('error')}, status=500)
                
        except EncryptedFile.DoesNotExist:
            return Response({'error': 'File not found'}, status=404)
        except Exception as e:
            return Response({'error': str(e)}, status=500)

    @api_view(['GET'])
    def get_blockchain_logs(request, file_id):
        """Get activity logs from blockchain"""
        try:
            encrypted_file = EncryptedFile.objects.get(id=file_id, is_active=True)
            
            if not encrypted_file.blockchain_registered:
                return Response({'error': 'File not registered on blockchain'}, status=400)
            
            blockchain = get_blockchain_service()
            result = blockchain.get_file_logs(encrypted_file.blockchain_file_id)
            
            if result['success']:
                return Response({
                    'success': True,
                    'logs': result['logs']
                })
            else:
                return Response({'error': result.get('error')}, status=500)
                
        except EncryptedFile.DoesNotExist:
            return Response({'error': 'File not found'}, status=404)
        except Exception as e:
            return Response({'error': str(e)}, status=500)

    @api_view(['GET'])
    def get_trusted_users(request, file_id):
        """Get list of trusted users from blockchain"""
        try:
            encrypted_file = EncryptedFile.objects.get(id=file_id, is_active=True)
            
            if not encrypted_file.blockchain_registered:
                return Response({'error': 'File not registered on blockchain'}, status=400)
            
            blockchain = get_blockchain_service()
            result = blockchain.get_trusted_users(encrypted_file.blockchain_file_id)
            
            if result['success']:
                return Response({
                    'success': True,
                    'users': result['users']
                })
            else:
                return Response({'error': result.get('error')}, status=500)
                
        except EncryptedFile.DoesNotExist:
            return Response({'error': 'File not found'}, status=404)
        except Exception as e:
            return Response({'error': str(e)}, status=500)
else:
    # Stub functions when blockchain is disabled
    @api_view(['POST'])
    def grant_file_access(request, file_id):
        return Response({'error': 'Blockchain not enabled'}, status=503)
    
    @api_view(['POST'])
    def revoke_file_access(request, file_id):
        return Response({'error': 'Blockchain not enabled'}, status=503)
    
    @api_view(['POST'])
    def verify_file_integrity(request, file_id):
        return Response({'error': 'Blockchain not enabled'}, status=503)
    
    @api_view(['GET'])
    def get_blockchain_logs(request, file_id):
        return Response({'error': 'Blockchain not enabled'}, status=503)
    
    @api_view(['GET'])
    def get_trusted_users(request, file_id):
        return Response({'error': 'Blockchain not enabled'}, status=503)