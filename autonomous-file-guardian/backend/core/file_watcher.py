import time
import os
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from django.utils import timezone
from django.apps import apps

class GuardianFileHandler(FileSystemEventHandler):
    def __init__(self):
        super().__init__()
        self.monitored_files = {} # Map: path -> file_id
        self.file_metadata = {}   # Map: path -> stats
        self.last_refresh = 0
        self.refresh_interval = 5
        
        # Debouncing Dictionary
        self.recent_alerts = {} 
        self.alert_cooldown = 5 # Seconds

    def _refresh_if_needed(self):
        if time.time() - self.last_refresh > self.refresh_interval:
            self.load_monitored_files()
            self.last_refresh = time.time()

    def _should_alert(self, file_path):
        """
        Check if we should alert (Debouncing logic).
        Includes path normalization to fix Windows double-alert bug.
        """
        # 1. Normalize path: lowercase and standard slashes
        norm_path = os.path.normpath(file_path).lower()
        
        now = time.time()
        last_time = self.recent_alerts.get(norm_path, 0)
        
        # 2. Check time difference
        if now - last_time > self.alert_cooldown:
            self.recent_alerts[norm_path] = now
            return True
            
        return False

    def load_monitored_files(self):
        try:
            EncryptedFile = apps.get_model('core', 'EncryptedFile')
            files = EncryptedFile.objects.filter(is_active=True, is_deleted_by_user=False)
            
            current_paths = set()
            for file in files:
                path = file.encrypted_path
                current_paths.add(path)
                if path not in self.monitored_files and os.path.exists(path):
                    self.monitored_files[path] = file.id
                    stat = os.stat(path)
                    self.file_metadata[path] = {
                        'size': stat.st_size,
                        'mtime': stat.st_mtime
                    }
                    print(f"👁️  WATCHING: {path}")

            # Cleanup
            for path in list(self.monitored_files.keys()):
                if path not in current_paths:
                    del self.monitored_files[path]
        except Exception as e:
            # Fail silently to keep thread alive
            pass

    def log_activity(self, file_id, action, description, severity='warning'):
        try:
            EncryptedFile = apps.get_model('core', 'EncryptedFile')
            ActivityLog = apps.get_model('core', 'ActivityLog')
            from core.device_auth import get_device_info
            
            encrypted_file = EncryptedFile.objects.get(id=file_id)
            device_info = get_device_info()
            
            ActivityLog.objects.create(
                encrypted_file=encrypted_file,
                action=action,
                severity=severity,
                description=description,
                device_info=device_info,
                ip_address=device_info['ip_address'],
                timestamp=timezone.now()
            )
            print(f"\n🚨 [ALERT TRIGGERED] {action}: {description}\n")
        except Exception as e:
            print(f"Failed to log: {e}")

    def backup_deleted_file(self, file_id):
        try:
            EncryptedFile = apps.get_model('core', 'EncryptedFile')
            f = EncryptedFile.objects.get(id=file_id)
            f.is_deleted_by_user = True
            f.deleted_at = timezone.now()
            f.save()
            print(f"✅ File marked deleted: {f.file_name}")
        except: pass

    # --- EVENT HANDLERS ---

    def on_moved(self, event):
        self._refresh_if_needed()
        if not event.is_directory and event.src_path in self.monitored_files:
            # Debounce check
            if not self._should_alert(event.src_path): return

            file_id = self.monitored_files[event.src_path]
            src_dir = os.path.dirname(event.src_path)
            dest_dir = os.path.dirname(event.dest_path)
            
            msg = f"⚠️ File moved!\nFrom: {event.src_path}\nTo: {event.dest_path}" if src_dir != dest_dir else \
                  f"⚠️ File renamed!\nFrom: {os.path.basename(event.src_path)}\nTo: {os.path.basename(event.dest_path)}"
            
            self.log_activity(file_id, 'file_moved', msg, 'alert')
            
            # Update internal state
            self.monitored_files[event.dest_path] = file_id
            del self.monitored_files[event.src_path]
            
            # Update DB
            try:
                EncryptedFile = apps.get_model('core', 'EncryptedFile')
                f = EncryptedFile.objects.get(id=file_id)
                f.encrypted_path = event.dest_path
                f.save()
            except: pass

    def on_deleted(self, event):
        self._refresh_if_needed()
        if not event.is_directory and event.src_path in self.monitored_files:
            # Debounce check
            if not self._should_alert(event.src_path): return

            file_id = self.monitored_files[event.src_path]
            self.log_activity(file_id, 'file_deleted', 
                f"🚨 CRITICAL: File deleted from disk!\nPath: {event.src_path}", 'critical')
            self.backup_deleted_file(file_id)
            del self.monitored_files[event.src_path]

    def on_created(self, event):
        """Detect copies based on Name Similarity OR File Size"""
        self._refresh_if_needed()
        if event.is_directory: return

        new_path = event.src_path
        new_filename = os.path.basename(new_path)
        
        # Debounce check (Normalized)
        if not self._should_alert(new_path): return

        # Wait a tiny bit for file write to complete
        time.sleep(0.2) 
        
        try:
            new_size = os.path.getsize(new_path)
        except:
            new_size = -1

        for path, fid in self.monitored_files.items():
            orig_name = os.path.basename(path)
            orig_meta = self.file_metadata.get(path, {})
            orig_size = orig_meta.get('size', -2)

            # 1. Name Check: "Test.txt" in "Test - Copy.txt"
            # Exclude the exact file itself (happens during some save operations)
            if path == new_path: continue

            name_match = (orig_name.rsplit('.', 1)[0] in new_filename)
            
            # 2. Size Check: Must be > 0 and match exactly
            size_match = (new_size == orig_size) and (new_size > 0)

            if name_match or size_match:
                reason = "Name similarity" if name_match else "Exact file size match"
                self.log_activity(fid, 'file_copied', 
                    f"⚠️ Possible Copy Detected ({reason})!\nOriginal: {orig_name}\nNew File: {new_filename}", 'warning')
                break # Stop checking other files

class FileWatcherService:
    def __init__(self):
        self.observer = Observer()
        self.handler = GuardianFileHandler()
        self.watched_paths = set()

    def start(self):
        print("🛡️  Starting Dynamic File Guardian Watcher...")
        self.update_watches()
        self.observer.start()
        
        import threading
        t = threading.Thread(target=self.keep_updating)
        t.daemon = True
        t.start()

    def update_watches(self):
        self.handler.load_monitored_files()
        needed_dirs = set()
        for path in self.handler.monitored_files.keys():
            parent = os.path.dirname(path)
            if os.path.exists(parent):
                needed_dirs.add(parent)
        
        for folder in needed_dirs:
            if folder not in self.watched_paths:
                try:
                    self.observer.schedule(self.handler, folder, recursive=False)
                    self.watched_paths.add(folder)
                    print(f"   ✓ Watching: {folder}")
                except: pass

    def keep_updating(self):
        while True:
            time.sleep(5)
            self.update_watches()

def start_file_watcher():
    FileWatcherService().start()