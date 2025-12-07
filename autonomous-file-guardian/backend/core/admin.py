

from django.contrib import admin
from core.models import EncryptedFile, ActivityLog, DeviceAuthorization

@admin.register(EncryptedFile)
class EncryptedFileAdmin(admin.ModelAdmin):
    list_display = ('file_name', 'file_type', 'encrypted_at', 'last_accessed', 'access_count', 'is_active')
    list_filter = ('file_type', 'is_active', 'encrypted_at')
    search_fields = ('file_name', 'original_path', 'mac_address', 'ip_address')
    readonly_fields = ('encrypted_at', 'device_hash', 'salt')
     
    fieldsets = (
        ('File Information', {
            'fields': ('file_name', 'file_type', 'original_path', 'encrypted_path', 'is_active')
        }),
        ('Encryption Details', {
            'fields': ('salt', 'device_hash')
        }),
        ('Device Information', {
            'fields': ('mac_address', 'ip_address', 'wifi_ssid', 'latitude', 'longitude')
        }),
        ('Access Information', {
            'fields': ('encrypted_at', 'last_accessed', 'access_count')
        }),
    )

@admin.register(ActivityLog)
class ActivityLogAdmin(admin.ModelAdmin):
    list_display = ('encrypted_file', 'action', 'severity', 'ip_address', 'timestamp')
    list_filter = ('action', 'severity', 'timestamp')
    search_fields = ('encrypted_file__file_name', 'description', 'ip_address')
    readonly_fields = ('timestamp', 'device_info')
    date_hierarchy = 'timestamp'
    
    def has_add_permission(self, request):
        return False
    
    def has_change_permission(self, request, obj=None):
        return False

@admin.register(DeviceAuthorization)
class DeviceAuthorizationAdmin(admin.ModelAdmin):
    list_display = ('device_name', 'mac_address', 'ip_address', 'is_authorized', 'last_seen')
    list_filter = ('is_authorized', 'first_seen', 'last_seen')
    search_fields = ('device_name', 'mac_address', 'ip_address', 'wifi_ssid')
    readonly_fields = ('device_hash', 'first_seen', 'last_seen')
    
    fieldsets = (
        ('Device Information', {
            'fields': ('device_name', 'device_hash', 'mac_address')
        }),
        ('Network Information', {
            'fields': ('ip_address', 'wifi_ssid')
        }),
        ('Location', {
            'fields': ('latitude', 'longitude')
        }),
        ('Authorization', {
            'fields': ('is_authorized', 'first_seen', 'last_seen')
        }),
    )

    