"""
vault_app/views.py
-------------------
All HTTP request handlers for the Secure Document Vault.

View summary
------------
home_view            — landing page redirect.
register_view        — new user registration.
login_view           — authenticate and start session.
logout_view          — end session.
dashboard_view       — list the user's documents.
upload_view          — validate, encrypt, and store a file.
download_view        — authenticate ownership, decrypt, stream file.
delete_view          — remove encrypted file + DB record.
activity_log_view    — show the user's own audit log.
"""

import os
import mimetypes
import logging

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import HttpResponse, Http404
from django.conf import settings
from django.utils import timezone

from .models import EncryptedDocument, ActivityLog
from .forms import UserRegistrationForm, DocumentUploadForm
from .encryption import encrypt_file, decrypt_file
from .utils import get_client_ip, log_activity, safe_filename

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public views
# ---------------------------------------------------------------------------

def home_view(request):
    """Redirect authenticated users to dashboard; others to login."""
    if request.user.is_authenticated:
        return redirect('dashboard')
    return redirect('login')


def register_view(request):
    """
    Handle new user registration.
    GET  → render blank registration form.
    POST → validate, create user, log them in, redirect to dashboard.
    """
    if request.user.is_authenticated:
        return redirect('dashboard')

    if request.method == 'POST':
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            log_activity(user, 'LOGIN', details='Account created', request=request)
            messages.success(request, f'Welcome to the Vault, {user.username}!')
            return redirect('dashboard')
    else:
        form = UserRegistrationForm()

    return render(request, 'registration/register.html', {'form': form})


def login_view(request):
    """
    Handle user login.
    GET  → render login form.
    POST → authenticate credentials; log success/failure.
    """
    if request.user.is_authenticated:
        return redirect('dashboard')

    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '')
        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            log_activity(user, 'LOGIN', request=request)
            messages.success(request, f'Welcome back, {user.username}!')
            return redirect('dashboard')
        else:
            # Log failed attempt (user object is None, so pass username in details)
            log_activity(
                None, 'FAILED',
                details=f'Failed login for username: {username}',
                request=request
            )
            messages.error(request, 'Invalid username or password.')

    return render(request, 'registration/login.html')


def logout_view(request):
    """Log the logout event, end the session, redirect to login."""
    if request.user.is_authenticated:
        log_activity(request.user, 'LOGOUT', request=request)
        logout(request)
        messages.info(request, 'You have been securely logged out.')
    return redirect('login')


# ---------------------------------------------------------------------------
# Authenticated views
# ---------------------------------------------------------------------------

@login_required
def dashboard_view(request):
    """
    Main user dashboard — lists all documents belonging to the logged-in user.
    Also shows a summary count for the info cards.
    """
    documents = EncryptedDocument.objects.filter(owner=request.user)
    total_size = sum(d.file_size for d in documents)
    recent_logs = ActivityLog.objects.filter(user=request.user).order_by('-timestamp')[:5]

    context = {
        'documents': documents,
        'doc_count': documents.count(),
        'total_size': _human_size(total_size),
        'recent_logs': recent_logs,
    }
    return render(request, 'vault/dashboard.html', context)


@login_required
def upload_view(request):
    """
    Handle secure file upload.

    Flow
    ----
    1. Validate file via DocumentUploadForm (extension + size).
    2. Read raw bytes; pass to encrypt_file() → (ciphertext, salt_hex).
    3. Write ciphertext to ENCRYPTED_FILES_DIR under a UUID-based name.
    4. Create EncryptedDocument DB record.
    5. Write ActivityLog entry.
    6. Redirect to dashboard with success message.
    """
    if request.method == 'POST':
        form = DocumentUploadForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_file = form.cleaned_data['file']
            original_name = uploaded_file.name
            plaintext_size = uploaded_file.size
            mime_type, _ = mimetypes.guess_type(original_name)
            mime_type = mime_type or 'application/octet-stream'

            try:
                # 1. Encrypt
                ciphertext, salt_hex = encrypt_file(uploaded_file)

                # 2. Determine storage path (UUID-named to prevent filename leakage)
                enc_dir = settings.ENCRYPTED_FILES_DIR
                os.makedirs(enc_dir, exist_ok=True)

                # Import uuid here (already imported in models; keep views clean)
                import uuid
                stored_filename = f"{uuid.uuid4().hex}.enc"
                disk_path = os.path.join(enc_dir, stored_filename)
                relative_path = os.path.join('encrypted_files', stored_filename)

                # 3. Write ciphertext
                with open(disk_path, 'wb') as f:
                    f.write(ciphertext)

                # 4. DB record
                doc = EncryptedDocument.objects.create(
                    owner=request.user,
                    original_name=original_name,
                    encrypted_path=relative_path,
                    file_size=plaintext_size,
                    mime_type=mime_type,
                    encryption_salt=salt_hex,
                )

                # 5. Audit log
                log_activity(
                    request.user, 'UPLOAD', document=doc,
                    details=f'Uploaded "{original_name}" ({_human_size(plaintext_size)})',
                    request=request
                )

                messages.success(request, f'"{original_name}" encrypted and stored successfully.')
                return redirect('dashboard')

            except Exception as exc:
                logger.exception("Upload/encryption error: %s", exc)
                messages.error(request, 'An error occurred during encryption. Please try again.')
        else:
            messages.error(request, 'Invalid file. Please check the requirements.')
    else:
        form = DocumentUploadForm()

    return render(request, 'vault/upload.html', {'form': form})


@login_required
def download_view(request, doc_id):
    """
    Decrypt and stream a file to the owner.

    Security
    --------
    * Uses get_object_or_404 with owner=request.user — any other user gets 404.
    * Ciphertext is decrypted in memory; plaintext is never written to disk.
    * Fernet raises InvalidToken if ciphertext has been tampered with.
    """
    doc = get_object_or_404(EncryptedDocument, id=doc_id, owner=request.user)

    disk_path = os.path.join(settings.MEDIA_ROOT, doc.encrypted_path)
    if not os.path.exists(disk_path):
        messages.error(request, 'Encrypted file not found on disk.')
        return redirect('dashboard')

    try:
        with open(disk_path, 'rb') as f:
            ciphertext = f.read()

        plaintext = decrypt_file(ciphertext, doc.encryption_salt)

        log_activity(
            request.user, 'DOWNLOAD', document=doc,
            details=f'Downloaded "{doc.original_name}"',
            request=request
        )

        response = HttpResponse(plaintext, content_type=doc.mime_type)
        response['Content-Disposition'] = (
            f'attachment; filename="{doc.original_name}"'
        )
        response['Content-Length'] = len(plaintext)
        return response

    except Exception as exc:
        logger.exception("Decryption error for doc %s: %s", doc_id, exc)
        messages.error(request, 'Decryption failed. The file may be corrupted.')
        return redirect('dashboard')


@login_required
def delete_view(request, doc_id):
    """
    Delete an encrypted document (owner only, POST required for CSRF safety).
    Removes both the DB record and the ciphertext file from disk.
    """
    doc = get_object_or_404(EncryptedDocument, id=doc_id, owner=request.user)

    if request.method == 'POST':
        original_name = doc.original_name
        disk_path = os.path.join(settings.MEDIA_ROOT, doc.encrypted_path)

        # Remove from disk
        try:
            if os.path.exists(disk_path):
                os.remove(disk_path)
        except OSError as exc:
            logger.warning("Could not delete file from disk: %s", exc)

        log_activity(
            request.user, 'DELETE', document=doc,
            details=f'Deleted "{original_name}"',
            request=request
        )

        doc.delete()
        messages.success(request, f'"{original_name}" has been permanently deleted.')

    return redirect('dashboard')


@login_required
def activity_log_view(request):
    """Display the full activity log for the logged-in user."""
    logs = ActivityLog.objects.filter(user=request.user).select_related('document')
    return render(request, 'vault/activity_log.html', {'logs': logs})


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _human_size(size_bytes: int) -> str:
    """Convert bytes to a human-readable string."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"
