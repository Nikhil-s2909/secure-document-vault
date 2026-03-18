"""
vault_app/models.py
--------------------
Database models for the Secure Document Vault:

  EncryptedDocument  — stores metadata about each uploaded & encrypted file.
                       The actual file bytes are saved to disk as ciphertext;
                       only the per-file encryption key (itself encrypted with
                       the master key) is kept in the DB.

  ActivityLog        — append-only audit trail recording every upload, download,
                       delete, login, and logout event with timestamp and IP.
"""

import uuid
from django.db import models
from django.contrib.auth.models import User


class EncryptedDocument(models.Model):
    """
    Represents one user-uploaded file that has been encrypted and stored.

    Fields
    ------
    id              : UUID primary key (avoids sequential ID enumeration attacks).
    owner           : FK to the Django User who uploaded the file.
    original_name   : Original filename shown in the UI.
    encrypted_path  : Path on disk to the ciphertext blob (relative to MEDIA_ROOT).
    file_size       : Original (plaintext) size in bytes, stored for display.
    mime_type       : Detected MIME type of the original file.
    encryption_salt : Random 16-byte salt (hex) used when deriving the file key.
    uploaded_at     : UTC timestamp of upload.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    owner = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='documents'
    )
    original_name = models.CharField(max_length=255)
    encrypted_path = models.CharField(max_length=512)   # relative path on disk
    file_size = models.PositiveIntegerField(default=0)  # bytes (plaintext size)
    mime_type = models.CharField(max_length=100, default='application/octet-stream')
    encryption_salt = models.CharField(max_length=64)   # hex-encoded 32-byte salt
    uploaded_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-uploaded_at']

    def __str__(self):
        return f"{self.original_name} (owner: {self.owner.username})"

    @property
    def size_display(self):
        """Human-readable file size."""
        size = self.file_size
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"


class ActivityLog(models.Model):
    """
    Immutable audit log entry. One row per significant user action.

    Action Choices
    --------------
    UPLOAD   : User successfully uploaded and encrypted a file.
    DOWNLOAD : Owner decrypted and downloaded their file.
    DELETE   : Owner deleted a file from the vault.
    LOGIN    : User logged in.
    LOGOUT   : User logged out.
    FAILED   : A failed access attempt (wrong owner, etc.).
    """

    ACTION_CHOICES = [
        ('UPLOAD',   'File Uploaded'),
        ('DOWNLOAD', 'File Downloaded'),
        ('DELETE',   'File Deleted'),
        ('LOGIN',    'User Login'),
        ('LOGOUT',   'User Logout'),
        ('FAILED',   'Failed Access Attempt'),
    ]

    user = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, related_name='activity_logs'
    )
    action = models.CharField(max_length=20, choices=ACTION_CHOICES)
    document = models.ForeignKey(
        EncryptedDocument,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='logs'
    )
    details = models.TextField(blank=True)   # extra human-readable context
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"[{self.timestamp:%Y-%m-%d %H:%M}] {self.user} — {self.action}"
