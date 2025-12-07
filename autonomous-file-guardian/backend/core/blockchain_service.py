"""
Blockchain service for FileGuardian
Handles all interactions with the smart contract and IPFS
"""

import json
import hashlib
import requests
from pathlib import Path
from web3 import Web3
from web3.middleware import geth_poa_middleware
from django.conf import settings
import os
from dotenv import load_dotenv
import time
import traceback

load_dotenv()

class BlockchainService:
    def __init__(self):
        self.w3 = None
        self.contract = None
        self.default_account = None
        self.ipfs_available = False
        
        provider_url = os.getenv('BLOCKCHAIN_PROVIDER_URL', 'http://127.0.0.1:8545')
        self.contract_address = os.getenv('CONTRACT_ADDRESS')
        
        if not self.contract_address:
            print("❌ CONTRACT_ADDRESS not set in .env file.")
            raise Exception("CONTRACT_ADDRESS not set")
            
        # 1. Connect to Web3 provider
        try:
            self.w3 = Web3(Web3.HTTPProvider(provider_url, request_kwargs={'timeout': 5}))
            self.w3.middleware_onion.inject(geth_poa_middleware, layer=0)
            
            if not self.w3.is_connected():
                raise ConnectionError("Web3 provider is unreachable.")
            
            # 2. Load ABI
            contract_file = Path(__file__).parent / 'blockchain_data' / 'contract.json'
            with open(contract_file, 'r') as f:
                self.abi = json.load(f)['abi']
            
            # 3. Create Contract Instance
            self.contract = self.w3.eth.contract(
                address=self.contract_address,
                abi=self.abi
            )
            self.default_account = self.w3.eth.accounts[0]
            
            print(f"✅ Blockchain connected - Contract: {self.contract_address}")
            
        except ConnectionError:
            raise Exception(f"Failed to connect to Ethereum provider at {provider_url}")
        except FileNotFoundError:
            raise Exception(f"contract.json not found.")
        except Exception as e:
            # Catches issues like invalid contract address format, or no accounts available
            print(f"❌ Failed to initialize Web3 or Contract: {e}")
            raise Exception(f"Web3/Contract initialization failed: {e}")

        # 4. Check IPFS status
        self.ipfs_api_url = 'http://127.0.0.1:5001/api/v0'
        try:
            response = requests.post(f'{self.ipfs_api_url}/version', timeout=2)
            if response.status_code == 200:
                print(f"✅ IPFS connected")
                self.ipfs_available = True
            else:
                print(f"⚠️ IPFS responded with status {response.status_code}")
        except Exception as e:
            print(f"⚠️ IPFS connection failed: {e}")
            print("   Make sure IPFS Desktop is running")
            
    def calculate_file_hash(self, file_path):
        """Calculate SHA256 hash of file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return "0x" + sha256_hash.hexdigest()

    def upload_to_ipfs(self, file_path):
        """Upload file to IPFS using HTTP API"""
        if not self.ipfs_available:
            raise Exception("IPFS not connected. Make sure IPFS Desktop is running.")
        
        try:
            print(f"⬆️ Uploading {file_path} to IPFS...")
            with open(file_path, 'rb') as f:
                files = {'file': f}
                response = requests.post(
                    f'{self.ipfs_api_url}/add',
                    files=files,
                    timeout=30
                )
                
                if response.status_code == 200:
                    result = response.json()
                    cid = result['Hash']
                    size = result.get('Size', 0)
                    print(f"✅ File uploaded to IPFS. CID: {cid}")
                    return {'Hash': cid, 'Size': size}
                else:
                    raise Exception(f"IPFS upload failed with status {response.status_code}: {response.text}")
                    
        except Exception as e:
            print(f"❌ IPFS upload failed: {e}")
            raise Exception(f"IPFS upload failed: {e}")

    def download_from_ipfs(self, ipfs_cid):
        """Download file from IPFS using HTTP API"""
        if not self.ipfs_available:
            raise Exception("IPFS not connected")
        
        try:
            print(f"⬇️ Downloading {ipfs_cid} from IPFS...")
            response = requests.post(
                f'{self.ipfs_api_url}/cat',
                params={'arg': ipfs_cid},
                timeout=30
            )
            
            if response.status_code == 200:
                file_content = response.content
                print(f"✅ Downloaded {len(file_content)} bytes from IPFS")
                return file_content
            else:
                raise Exception(f"IPFS download failed with status {response.status_code}: {response.text}")
                
        except Exception as e:
            print(f"❌ IPFS download failed: {e}")
            raise Exception(f"IPFS download failed: {e}")

    def register_file(self, encrypted_file_path, file_name, owner_address=None):
        """
        Calculates hash, uploads to IPFS, and registers file on blockchain
        """
        try:
            file_hash = self.calculate_file_hash(encrypted_file_path)
            
            print("⬆️ Uploading to IPFS...")
            ipfs_result = self.upload_to_ipfs(encrypted_file_path)
            ipfs_cid = ipfs_result['Hash']
            
            file_size = os.path.getsize(encrypted_file_path)
            metadata = json.dumps({
                "name": file_name,
                "size": file_size,
                "path": encrypted_file_path
            })
            
            from_address = owner_address or self.default_account
            
            print("📝 Registering on blockchain...")
            tx_hash = self.contract.functions.registerFile(
                file_hash,
                metadata,
                ipfs_cid
            ).transact({'from': from_address})
            
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            
            file_id = self.contract.functions.fileCount().call()
            
            print(f"✅ File registered! ID: {file_id}, CID: {ipfs_cid}")
            
            return {
                'success': True,
                'file_id': file_id,
                'tx_hash': tx_hash.hex(),
                'file_hash': file_hash,
                'ipfs_cid': ipfs_cid,
                'gas_used': tx_receipt.gasUsed
            }
            
        except Exception as e:
            print(f"❌ Blockchain registration failed: {e}")
            import traceback
            traceback.print_exc()
            return {
                'success': False,
                'error': str(e)
            }
        
    def log_activity(self, file_id, action, severity, details, actor_address=None):
        try:
            from_address = actor_address or self.default_account
            tx_hash = self.contract.functions.logActivity(
                file_id, action, severity, details
            ).transact({'from': from_address})
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            return {'success': True, 'tx_hash': tx_hash.hex(), 'gas_used': tx_receipt.gasUsed}
        except Exception as e:
            print(f"❌ Activity logging failed: {e}")
            return {'success': False, 'error': str(e)}

    def grant_access(self, file_id, trusted_user_address, public_key, owner_address=None):
        try:
            from_address = owner_address or self.default_account
            tx_hash = self.contract.functions.grantAccess(
                file_id, trusted_user_address, public_key
            ).transact({'from': from_address})
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            return {'success': True, 'tx_hash': tx_hash.hex(), 'gas_used': tx_receipt.gasUsed}
        except Exception as e:
            print(f"❌ Access grant failed: {e}")
            return {'success': False, 'error': str(e)}

    def revoke_access(self, file_id, trusted_user_address, owner_address=None):
        try:
            from_address = owner_address or self.default_account
            tx_hash = self.contract.functions.revokeAccess(
                file_id, trusted_user_address
            ).transact({'from': from_address})
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            return {'success': True, 'tx_hash': tx_hash.hex()}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def verify_file_integrity(self, file_id, current_file_path, actor_address=None):
        try:
            current_hash = self.calculate_file_hash(current_file_path)
            
            # --- HARDENED CONTRACT CALL ---
            try:
                file_info = self.contract.functions.getFile(file_id).call()
            except Exception as e:
                 # Re-raise with specific message for views.py to handle 503
                 if isinstance(e, (BadFunctionCallOutput, InsufficientDataBytes, ValueError)):
                      raise ConnectionError("Contract call failed (Mismatch/Offline)") from e
                 raise e
            # ------------------------------
            
            original_hash = file_info[0] 
            from_address = actor_address or self.default_account
            
            tx_hash = self.contract.functions.verifyFileIntegrity(
                file_id, current_hash
            ).transact({'from': from_address})
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            
            is_valid = original_hash == current_hash
            
            return {
                'success': True, 'is_valid': is_valid,
                'original_hash': original_hash, 'current_hash': current_hash,
                'tx_hash': tx_hash.hex()
            }
        except ConnectionError as e:
            return {'success': False, 'error': str(e)}
        except Exception as e:
            print(f"❌ Integrity verification failed: {e}")
            return {'success': False, 'error': str(e)}

    def has_access(self, file_id, user_address):
        try:
            # --- HARDENED CONTRACT CALL ---
            try:
                 return self.contract.functions.hasAccess(file_id, user_address).call()
            except Exception as e:
                 if isinstance(e, (BadFunctionCallOutput, InsufficientDataBytes, ValueError)):
                      raise ConnectionError("Contract call failed (Mismatch/Offline)") from e
                 raise e
            # ------------------------------
        except ConnectionError as e:
             print(f"❌ Access check failed (Connection): {e}")
             return False
        except Exception as e:
            print(f"❌ Access check failed: {e}")
            return False
    
    def get_file_logs(self, file_id):
        try:
            # --- HARDENED CONTRACT CALL ---
            try:
                 logs = self.contract.functions.getFileLogs(file_id).call()
            except Exception as e:
                 if isinstance(e, (BadFunctionCallOutput, InsufficientDataBytes, ValueError)):
                      raise ConnectionError("Contract call failed (Mismatch/Offline)") from e
                 raise e
            # ------------------------------

            formatted_logs = [{
                'file_id': log[0], 'action': log[1], 'severity': log[2],
                'actor': log[3], 'details': log[4], 'timestamp': log[5]
            } for log in logs]
            return {'success': True, 'logs': formatted_logs}
        except ConnectionError as e:
             return {'success': False, 'error': str(e)}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def get_trusted_users(self, file_id):
        try:
            # --- HARDENED CONTRACT CALL ---
            try:
                users = self.contract.functions.getTrustedUsers(file_id).call()
            except Exception as e:
                 if isinstance(e, (BadFunctionCallOutput, InsufficientDataBytes, ValueError)):
                      raise ConnectionError("Contract call failed (Mismatch/Offline)") from e
                 raise e
            # ------------------------------

            user_details = []
            for user_address in users:
                details = self.contract.functions.getTrustedUserDetails(file_id, user_address).call()
                user_details.append({
                    'address': user_address, 'public_key': details[0],
                    'granted_at': details[1], 'is_active': details[2]
                })
            return {'success': True, 'users': user_details}
        except ConnectionError as e:
             return {'success': False, 'error': str(e)}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def get_file_info(self, file_id):
        try:
            # --- HARDENED CONTRACT CALL ---
            try:
                file_info = self.contract.functions.getFile(file_id).call()
            except Exception as e:
                 if isinstance(e, (BadFunctionCallOutput, InsufficientDataBytes, ValueError)):
                      raise ConnectionError("Contract call failed (Mismatch/Offline)") from e
                 raise e
            # ------------------------------

            metadata = json.loads(file_info[3])
            return {
                'success': True, 'file_hash': file_info[0], 'owner': file_info[1],
                'timestamp': file_info[2], 'metadata': metadata, 'ipfs_cid': file_info[4]
            }
        except ConnectionError as e:
             return {'success': False, 'error': str(e)}
        except Exception as e:
            return {'success': False, 'error': str(e)}

# Singleton instance
_blockchain_service = None

def get_blockchain_service():
    global _blockchain_service
    # --- HARDENED CONNECTION CHECK ---
    # Attempt to initialize service
    if _blockchain_service is None:
        try:
            _blockchain_service = BlockchainService()
        except Exception as e:
            # If initialization fails (e.g., CONTRACT_ADDRESS missing, web3 fails to connect),
            # this prevents the service from being set and will be caught by views.py.
            print(f"CRITICAL: Failed to load BlockchainService: {e}")
            _blockchain_service = None
            raise # Re-raise to alert views.py initialization block
    # ---------------------------------
    return _blockchain_service