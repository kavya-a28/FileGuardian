
from django.apps import AppConfig
import sys
import threading

class CoreConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'core'

    def ready(self):
        # Prevent running twice (Django reloader)
        if 'runserver' in sys.argv:
            from .file_watcher import start_file_watcher
            # Run watcher in a separate background thread
            watcher_thread = threading.Thread(target=start_file_watcher, daemon=True)
            watcher_thread.start()
            print("👁️  File Watcher Service Started")