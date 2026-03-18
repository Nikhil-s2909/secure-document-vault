"""
vault_app/utils.py
-------------------
Helper utilities shared across views:

  get_client_ip(request)  — extract real IP even behind a reverse proxy.
  log_activity(...)       — create an ActivityLog row with one call.
  safe_filename(name)     — sanitise a filename for safe disk storage.
"""

import re
import os
import logging

logger = logging.getLogger(__name__)


def get_client_ip(request) -> str:
    """
    Return the client's real IP address.
    Checks X-Forwarded-For header first (set by Nginx / load balancers),
    then falls back to REMOTE_ADDR.
    """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        # The header may contain a comma-separated list; the first entry is
        # the original client IP.
        return x_forwarded_for.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', '0.0.0.0')


def log_activity(user, action: str, document=None, details: str = '', request=None):
    """
    Create one ActivityLog entry.

    Parameters
    ----------
    user     : Django User instance (or None for anonymous events).
    action   : One of ActivityLog.ACTION_CHOICES keys, e.g. 'UPLOAD'.
    document : EncryptedDocument instance or None.
    details  : Free-text context appended to the log entry.
    request  : HttpRequest — used to extract the client IP.
    """
    # Import here to avoid circular imports (models → utils → models)
    from vault_app.models import ActivityLog

    ip = get_client_ip(request) if request else None

    try:
        ActivityLog.objects.create(
            user=user,
            action=action,
            document=document,
            details=details,
            ip_address=ip,
        )
    except Exception as exc:  # Never crash the main request over a log failure
        logger.error("Failed to write ActivityLog: %s", exc)


def safe_filename(original_name: str) -> str:
    """
    Strip path components and replace unsafe characters so the filename can
    be stored on disk without risk.

    Examples
    --------
    '../../etc/passwd'  → 'etc_passwd'
    'My Report (v2).pdf' → 'My_Report__v2_.pdf'
    """
    # Take only the basename
    name = os.path.basename(original_name)
    # Replace anything that isn't alphanumeric, dot, dash, or underscore
    name = re.sub(r'[^\w.\-]', '_', name)
    # Collapse multiple consecutive underscores
    name = re.sub(r'_+', '_', name)
    return name or 'unnamed'
