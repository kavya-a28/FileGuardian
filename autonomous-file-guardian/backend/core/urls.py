from django.urls import path
from core import views

urlpatterns = [
    # --- VAULT ENDPOINTS ---
    path('vault/status/', views.get_vault_status, name='vault_status'),
    path('vault/setup/', views.setup_vault, name='vault_setup'),
    path('vault/unlock/', views.unlock_vault, name='vault_unlock'),
    path('vault/lock/', views.lock_vault, name='vault_lock'),

    # --- Auth & 2FA ---
    path('auth/setup-2fa/', views.setup_2fa, name='setup_2fa'),
    path('auth/confirm-2fa/', views.confirm_2fa_setup, name='confirm_2fa'),

    # --- File Operations ---
    path('encrypt/', views.encrypt_file_or_folder, name='encrypt'),
    path('decrypt/', views.decrypt_file_or_folder, name='decrypt'),
    path('files/', views.list_encrypted_files, name='list_files'),
    path('files/<int:file_id>/location/', views.get_file_location, name='file_location'),
    path('files/<int:file_id>/delete/', views.delete_encrypted_file, name='delete_file'),
    path('files/<int:file_id>/restore/', views.restore_deleted_file, name='restore_file'),
    
    # --- Blockchain Operations (THESE WERE MISSING) ---
    path('files/<int:file_id>/verify-integrity/', views.verify_file_integrity, name='verify_integrity'),
    path('files/<int:file_id>/grant-access/', views.grant_file_access, name='grant_access'),
    path('files/<int:file_id>/revoke-access/', views.revoke_file_access, name='revoke_access'),
    path('files/<int:file_id>/blockchain-logs/', views.get_blockchain_logs, name='blockchain_logs'),
    path('files/<int:file_id>/trusted-users/', views.get_trusted_users, name='trusted_users'),
    
    # --- Activity Logs & Dashboard ---
    path('logs/', views.get_activity_logs, name='logs'),
    path('dashboard/stats/', views.get_dashboard_stats, name='dashboard_stats'),
    
    # --- Canary Tokens ---
    path('canary/create/', views.create_canary_token, name='create_canary'),
    path('canary/list/', views.list_canary_tokens, name='list_canary'),
    
    # --- Settings ---
    path('settings/', views.get_app_settings, name='app_settings'),
    path('settings/canary/', views.set_default_canary_token, name='set_default_canary'),
    
    # --- Recovery (Disaster Recovery) ---
    path('recovery/scan/', views.scan_recovery_status, name='scan_recovery'),
    path('recovery/restore/', views.perform_full_recovery, name='perform_recovery'),
]