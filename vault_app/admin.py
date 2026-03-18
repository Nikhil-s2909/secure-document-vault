"""
vault_app/admin.py
-------------------
Register models with the Django admin site so admins can view
documents and audit logs through the /admin/ interface.

Note: The admin panel should be access-controlled in production.
"""

from django.contrib import admin
from .models import EncryptedDocument, ActivityLog


@admin.register(EncryptedDocument)
class EncryptedDocumentAdmin(admin.ModelAdmin):
    list_display = ('original_name', 'owner', 'size_display', 'mime_type', 'uploaded_at')
    list_filter = ('owner', 'uploaded_at')
    search_fields = ('original_name', 'owner__username')
    readonly_fields = ('id', 'encrypted_path', 'encryption_salt', 'uploaded_at')
    ordering = ('-uploaded_at',)

    # Prevent admins from downloading/decrypting files — display only
    def has_add_permission(self, request):
        return False


@admin.register(ActivityLog)
class ActivityLogAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'user', 'action', 'document', 'ip_address')
    list_filter = ('action', 'user')
    search_fields = ('user__username', 'details')
    readonly_fields = ('user', 'action', 'document', 'details', 'ip_address', 'timestamp')
    ordering = ('-timestamp',)

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False  # Audit logs are immutable
