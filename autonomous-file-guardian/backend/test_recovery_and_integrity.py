"""
FileGuardian Recovery and Integrity Testing Script

This script tests:
1. Database recovery from blockchain + IPFS
2. File integrity verification
3. Tamper detection
4. File restoration from IPFS

Usage:
    python test_recovery_and_integrity.py

Make sure Django, Ganache, and IPFS are running!
"""

import os
import sys
import django
import hashlib
from pathlib import Path

# Setup Django environment
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'guardian_api.settings')
django.setup()

from core.models import EncryptedFile
from core.blockchain_service import get_blockchain_service

class RecoveryTester:
    def __init__(self):
        self.blockchain = get_blockchain_service()
        print("\n" + "="*70)
        print("🔧 FileGuardian Recovery & Integrity Testing Tool")
        print("="*70 + "\n")
    
    def show_menu(self):
        """Display main menu"""
        print("\n📋 Available Tests:")
        print("  1. 🔍 List all files (Database vs Blockchain)")
        print("  2. ✅ Verify file integrity")
        print("  3. 🔨 Simulate database corruption")
        print("  4. ♻️  Full database recovery from blockchain")
        print("  5. 📥 Restore deleted file from IPFS")
        print("  6. 🧪 Detect tampering")
        print("  7. 📊 Compare database vs blockchain")
        print("  8. 🔐 Test file hash verification")
        print("  0. ❌ Exit")
        print()
    
    def list_all_files(self):
        """List all files from database and blockchain"""
        print("\n" + "="*70)
        print("📁 FILES IN DATABASE")
        print("="*70)
        
        db_files = EncryptedFile.objects.filter(is_active=True)
        
        if not db_files.exists():
            print("⚠️  No files in database")
        else:
            for f in db_files:
                print(f"\n🆔 DB ID: {f.id}")
                print(f"   📄 Name: {f.file_name}")
                print(f"   📍 Path: {f.encrypted_path}")
                print(f"   🔗 IPFS: {f.ipfs_cid}")
                print(f"   ⛓️  Blockchain ID: {f.blockchain_file_id}")
                print(f"   ✅ Exists locally: {os.path.exists(f.encrypted_path)}")
                print(f"   🗑️  Deleted: {f.is_deleted_by_user}")
        
        print("\n" + "="*70)
        print("⛓️  FILES ON BLOCKCHAIN")
        print("="*70)
        
        try:
            file_count = self.blockchain.contract.functions.fileCount().call()
            print(f"\n📊 Total files on blockchain: {file_count}\n")
            
            for file_id in range(1, file_count + 1):
                result = self.blockchain.get_file_info(file_id)
                if result['success']:
                    metadata = result['metadata']
                    print(f"🆔 Blockchain ID: {file_id}")
                    print(f"   📄 Name: {metadata.get('name', 'N/A')}")
                    print(f"   🔗 IPFS: {result['ipfs_cid']}")
                    print(f"   #️⃣  Hash: {result['file_hash'][:20]}...")
                    print(f"   👤 Owner: {result['owner']}")
                    print()
        except Exception as e:
            print(f"❌ Error reading blockchain: {e}")
    
    def verify_integrity(self):
        """Verify integrity of a specific file"""
        print("\n" + "="*70)
        print("🔍 FILE INTEGRITY VERIFICATION")
        print("="*70)
        
        # List files
        files = EncryptedFile.objects.filter(
            is_active=True, 
            blockchain_registered=True,
            is_deleted_by_user=False
        )
        
        if not files.exists():
            print("\n⚠️  No registered files to verify")
            return
        
        print("\nAvailable files:")
        for f in files:
            status = "✅" if os.path.exists(f.encrypted_path) else "❌"
            print(f"  {f.id}. {status} {f.file_name}")
        
        try:
            file_id = int(input("\nEnter file ID to verify: "))
            file_obj = EncryptedFile.objects.get(id=file_id)
            
            if not os.path.exists(file_obj.encrypted_path):
                print(f"\n❌ File not found locally: {file_obj.encrypted_path}")
                return
            
            print(f"\n🔍 Verifying: {file_obj.file_name}")
            print("⏳ Checking integrity...")
            
            result = self.blockchain.verify_file_integrity(
                file_obj.blockchain_file_id,
                file_obj.encrypted_path
            )
            
            if result['success']:
                if result['is_valid']:
                    print("\n✅ INTEGRITY VERIFIED - File is authentic!")
                    print(f"   Original hash: {result['original_hash'][:20]}...")
                    print(f"   Current hash:  {result['current_hash'][:20]}...")
                    print(f"   Transaction: {result['tx_hash'][:20]}...")
                else:
                    print("\n🚨 TAMPERING DETECTED!")
                    print(f"   ❌ Original hash: {result['original_hash'][:20]}...")
                    print(f"   ⚠️  Current hash:  {result['current_hash'][:20]}...")
                    print(f"   📝 Logged on blockchain: {result['tx_hash'][:20]}...")
            else:
                print(f"\n❌ Verification failed: {result.get('error')}")
                
        except EncryptedFile.DoesNotExist:
            print("\n❌ File not found in database")
        except ValueError:
            print("\n❌ Invalid input")
        except Exception as e:
            print(f"\n❌ Error: {e}")
    
    def simulate_corruption(self):
        """Simulate database corruption for testing"""
        print("\n" + "="*70)
        print("🔨 SIMULATE DATABASE CORRUPTION")
        print("="*70)
        
        files = EncryptedFile.objects.filter(is_active=True)
        
        if not files.exists():
            print("\n⚠️  No files to corrupt")
            return
        
        print("\nWarning: This will modify database records for testing!")
        print("Available files:")
        for f in files:
            print(f"  {f.id}. {f.file_name}")
        
        try:
            file_id = int(input("\nEnter file ID to corrupt: "))
            file_obj = EncryptedFile.objects.get(id=file_id)
            
            print("\nCorruption options:")
            print("  1. Change IPFS CID")
            print("  2. Change file hash")
            print("  3. Change blockchain ID")
            print("  4. Delete from database (simulate loss)")
             
            choice = input("\nChoice: ")
            
            if choice == '1':
                file_obj.ipfs_cid = "QmFAKECIDForTestingPurposes"
                file_obj.save()
                print("\n⚠️  Corrupted: Changed IPFS CID to fake value")
                
            elif choice == '2':
                file_obj.blockchain_file_hash = "0x" + "f" * 64
                file_obj.save()
                print("\n⚠️  Corrupted: Changed file hash")
                
            elif choice == '3':
                file_obj.blockchain_file_id = 99999
                file_obj.save()
                print("\n⚠️  Corrupted: Changed blockchain ID")
                
            elif choice == '4':
                file_name = file_obj.file_name
                file_obj.delete()
                print(f"\n⚠️  Deleted: {file_name} removed from database")
            
            print("\n💡 Now run option 7 to detect tampering!")
            
        except EncryptedFile.DoesNotExist:
            print("\n❌ File not found")
        except ValueError:
            print("\n❌ Invalid input")
    
    def full_recovery(self):
        """Recover entire database from blockchain"""
        print("\n" + "="*70)
        print("♻️  FULL DATABASE RECOVERY FROM BLOCKCHAIN")
        print("="*70)
        
        print("\n⚠️  WARNING: This will reset the database and rebuild from blockchain!")
        confirm = input("Are you sure? (yes/no): ")
        
        if confirm.lower() != 'yes':
            print("\n❌ Recovery cancelled")
            return
        
        try:
            # Backup current database state
            print("\n📦 Backing up current database state...")
            backup_file = Path(__file__).parent / 'db_backup.json'
            import json
            
            backup_data = []
            for f in EncryptedFile.objects.all():
                backup_data.append({
                    'id': f.id,
                    'file_name': f.file_name,
                    'ipfs_cid': f.ipfs_cid,
                    'blockchain_file_id': f.blockchain_file_id
                })
            
            with open(backup_file, 'w') as f:
                json.dump(backup_data, f, indent=2)
            print(f"✅ Backup saved to: {backup_file}")
            
            # Clear database
            print("\n🗑️  Clearing database...")
            deleted_count = EncryptedFile.objects.all().count()
            EncryptedFile.objects.all().delete()
            print(f"✅ Deleted {deleted_count} records")
            
            # Recover from blockchain
            print("\n♻️  Recovering from blockchain...")
            file_count = self.blockchain.contract.functions.fileCount().call()
            print(f"📊 Found {file_count} files on blockchain\n")
            
            recovered = 0
            for file_id in range(1, file_count + 1):
                result = self.blockchain.get_file_info(file_id)
                
                if result['success']:
                    metadata = result['metadata']
                    
                    # Check if file exists locally
                    file_path = metadata.get('path', '')
                    exists = os.path.exists(file_path)
                    
                    # Create database record
                    EncryptedFile.objects.create(
                        file_name=metadata.get('name', 'Unknown'),
                        original_path=file_path,
                        encrypted_path=file_path,
                        file_type='file',
                        salt='00' * 16,  # Placeholder - actual salt not on blockchain
                        ipfs_cid=result['ipfs_cid'],
                        blockchain_file_id=file_id,
                        blockchain_file_hash=result['file_hash'],
                        blockchain_registered=True,
                        blockchain_owner=result['owner'],
                        device_hash='recovered',
                        mac_address='recovered',
                        ip_address='recovered'
                    )
                    
                    status = "✅" if exists else "⚠️ (missing locally)"
                    print(f"  {file_id}. {status} {metadata.get('name', 'Unknown')}")
                    recovered += 1
            
            print(f"\n🎉 Recovery complete! Recovered {recovered} files from blockchain")
            print(f"💡 Backup saved to: {backup_file}")
            
        except Exception as e:
            print(f"\n❌ Recovery failed: {e}")
            import traceback
            traceback.print_exc()
    
    def restore_from_ipfs(self):
        """Restore a deleted file from IPFS"""
        print("\n" + "="*70)
        print("📥 RESTORE FILE FROM IPFS")
        print("="*70)
        
        # Show deleted files
        deleted_files = EncryptedFile.objects.filter(
            is_active=True,
            is_deleted_by_user=True
        )
        
        if not deleted_files.exists():
            print("\n⚠️  No deleted files to restore")
            return
        
        print("\nDeleted files available for restore:")
        for f in deleted_files:
            print(f"  {f.id}. {f.file_name} (deleted: {f.deleted_at})")
        
        try:
            file_id = int(input("\nEnter file ID to restore: "))
            file_obj = EncryptedFile.objects.get(id=file_id)
            
            if not file_obj.ipfs_cid:
                print("\n❌ No IPFS backup found for this file")
                return
            
            print(f"\n♻️  Restoring: {file_obj.file_name}")
            print(f"   IPFS CID: {file_obj.ipfs_cid}")
            print(f"   Target: {file_obj.encrypted_path}")
            
            # Download from IPFS
            print("\n⬇️  Downloading from IPFS...")
            encrypted_content = self.blockchain.download_from_ipfs(file_obj.ipfs_cid)
            
            # Create directory if needed
            target_dir = os.path.dirname(file_obj.encrypted_path)
            if not os.path.exists(target_dir):
                os.makedirs(target_dir, exist_ok=True)
            
            # Write file
            with open(file_obj.encrypted_path, 'wb') as f:
                f.write(encrypted_content)
            
            # Update database
            file_obj.is_deleted_by_user = False
            file_obj.deleted_at = None
            file_obj.save()
            
            print(f"\n✅ File restored successfully!")
            print(f"   📍 Location: {file_obj.encrypted_path}")
            print(f"   📦 Size: {len(encrypted_content)} bytes")
            
        except EncryptedFile.DoesNotExist:
            print("\n❌ File not found")
        except Exception as e:
            print(f"\n❌ Restore failed: {e}")
    
    def detect_tampering(self):
        """Compare database records with blockchain to detect tampering"""
        print("\n" + "="*70)
        print("🧪 TAMPERING DETECTION")
        print("="*70)
        
        files = EncryptedFile.objects.filter(
            is_active=True,
            blockchain_registered=True
        )
        
        if not files.exists():
            print("\n⚠️  No registered files to check")
            return
        
        print("\n🔍 Checking database records against blockchain...\n")
        
        tampering_found = False
        
        for file_obj in files:
            try:
                # Get blockchain record
                result = self.blockchain.get_file_info(file_obj.blockchain_file_id)
                
                if result['success']:
                    bc_cid = result['ipfs_cid']
                    bc_hash = result['file_hash']
                    
                    # Compare IPFS CID
                    if file_obj.ipfs_cid != bc_cid:
                        print(f"🚨 TAMPERING DETECTED: {file_obj.file_name}")
                        print(f"   Field: IPFS CID")
                        print(f"   ❌ Database: {file_obj.ipfs_cid}")
                        print(f"   ✅ Blockchain: {bc_cid}")
                        print(f"   💡 Fix: Update database to match blockchain")
                        tampering_found = True
                        print()
                    
                    # Compare file hash (if stored)
                    elif file_obj.blockchain_file_hash and file_obj.blockchain_file_hash != bc_hash:
                        print(f"🚨 TAMPERING DETECTED: {file_obj.file_name}")
                        print(f"   Field: File Hash")
                        print(f"   ❌ Database: {file_obj.blockchain_file_hash[:20]}...")
                        print(f"   ✅ Blockchain: {bc_hash[:20]}...")
                        tampering_found = True
                        print()
                    else:
                        print(f"✅ {file_obj.file_name} - Verified")
                        
            except Exception as e:
                print(f"⚠️  {file_obj.file_name} - Check failed: {e}")
        
        if not tampering_found:
            print("\n🎉 No tampering detected! All records match blockchain.")
        else:
            print("\n⚠️  Tampering detected in one or more files!")
    
    def compare_database_blockchain(self):
        """Detailed comparison between database and blockchain"""
        print("\n" + "="*70)
        print("📊 DATABASE vs BLOCKCHAIN COMPARISON")
        print("="*70)
        
        # Count files
        db_count = EncryptedFile.objects.filter(is_active=True).count()
        
        try:
            bc_count = self.blockchain.contract.functions.fileCount().call()
        except Exception as e:
            print(f"\n❌ Error reading blockchain: {e}")
            return
        
        print(f"\n📊 Statistics:")
        print(f"   Database files: {db_count}")
        print(f"   Blockchain files: {bc_count}")
        
        if db_count == bc_count:
            print("   ✅ Counts match")
        else:
            print(f"   ⚠️  Mismatch: {abs(db_count - bc_count)} file(s) difference")
        
        # Find discrepancies
        print("\n🔍 Checking for discrepancies...\n")
        
        db_blockchain_ids = set(
            EncryptedFile.objects.filter(
                is_active=True,
                blockchain_registered=True
            ).values_list('blockchain_file_id', flat=True)
        )
        
        bc_ids = set(range(1, bc_count + 1))
        
        missing_from_db = bc_ids - db_blockchain_ids
        orphaned_in_db = db_blockchain_ids - bc_ids
        
        if missing_from_db:
            print(f"⚠️  Files on blockchain but NOT in database:")
            for bc_id in missing_from_db:
                result = self.blockchain.get_file_info(bc_id)
                if result['success']:
                    print(f"   - Blockchain ID {bc_id}: {result['metadata'].get('name', 'Unknown')}")
        
        if orphaned_in_db:
            print(f"\n⚠️  Database records with invalid blockchain IDs:")
            for bc_id in orphaned_in_db:
                files = EncryptedFile.objects.filter(blockchain_file_id=bc_id)
                for f in files:
                    print(f"   - DB ID {f.id}: {f.file_name} (BC ID: {bc_id})")
        
        if not missing_from_db and not orphaned_in_db:
            print("✅ All records are in sync!")
    
    def test_hash_verification(self):
        """Test file hash verification"""
        print("\n" + "="*70)
        print("🔐 FILE HASH VERIFICATION TEST")
        print("="*70)
        
        files = EncryptedFile.objects.filter(
            is_active=True,
            is_deleted_by_user=False
        )
        
        if not files.exists():
            print("\n⚠️  No files to verify")
            return
        
        print("\nAvailable files:")
        for f in files:
            status = "✅" if os.path.exists(f.encrypted_path) else "❌"
            print(f"  {f.id}. {status} {f.file_name}")
        
        try:
            file_id = int(input("\nEnter file ID: "))
            file_obj = EncryptedFile.objects.get(id=file_id)
            
            if not os.path.exists(file_obj.encrypted_path):
                print(f"\n❌ File not found: {file_obj.encrypted_path}")
                return
            
            print(f"\n🔐 Computing hash for: {file_obj.file_name}")
            
            # Calculate current hash
            current_hash = self.blockchain.calculate_file_hash(file_obj.encrypted_path)
            print(f"   Current hash: {current_hash}")
            
            # Get blockchain hash
            if file_obj.blockchain_registered:
                result = self.blockchain.get_file_info(file_obj.blockchain_file_id)
                if result['success']:
                    bc_hash = result['file_hash']
                    print(f"   Blockchain hash: {bc_hash}")
                    
                    if current_hash == bc_hash:
                        print("\n   ✅ MATCH - File is authentic!")
                    else:
                        print("\n   🚨 MISMATCH - File has been modified!")
            else:
                print("\n   ⚠️  File not registered on blockchain")
                
        except EncryptedFile.DoesNotExist:
            print("\n❌ File not found")
        except Exception as e:
            print(f"\n❌ Error: {e}")
    
    def run(self):
        """Main loop"""
        while True:
            self.show_menu()
            choice = input("Select option: ").strip()
            
            if choice == '0':
                print("\n👋 Goodbye!\n")
                break
            elif choice == '1':
                self.list_all_files()
            elif choice == '2':
                self.verify_integrity()
            elif choice == '3':
                self.simulate_corruption()
            elif choice == '4':
                self.full_recovery()
            elif choice == '5':
                self.restore_from_ipfs()
            elif choice == '6':
                self.detect_tampering()
            elif choice == '7':
                self.compare_database_blockchain()
            elif choice == '8':
                self.test_hash_verification()
            else:
                print("\n❌ Invalid option")
            
            input("\nPress Enter to continue...")


if __name__ == '__main__':
    try:
        tester = RecoveryTester()
        tester.run()
    except KeyboardInterrupt:
        print("\n\n👋 Interrupted by user\n")
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        import traceback
        traceback.print_exc()