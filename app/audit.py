"""
Audit Logger
============
Writes every significant action (UPLOAD, DOWNLOAD, DELETE, LOGIN, REGISTER)
to both the database (AuditLog table) and a rotating plaintext log file.

Having two sinks means:
  - Database: queryable, shown in the admin UI.
  - File: survives DB corruption, suitable for SIEM ingestion.
"""

import logging
import os
from datetime import datetime
from flask import request
from .extensions import db
from .models import AuditLog


def _get_file_logger(log_dir: str) -> logging.Logger:
    logger = logging.getLogger("vault.audit")
    if not logger.handlers:
        os.makedirs(log_dir, exist_ok=True)
        handler = logging.FileHandler(os.path.join(log_dir, "audit.log"))
        handler.setFormatter(
            logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
        )
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger


def log_action(user, action: str, document=None, details: str = "", log_dir: str = "logs"):
    """
    Record an action in both the DB and the audit log file.

    Parameters
    ----------
    user     : User ORM object
    action   : One of UPLOAD | DOWNLOAD | DELETE | LOGIN | REGISTER
    document : Document ORM object (optional)
    details  : Free-text annotation
    log_dir  : Directory for the log file
    """
    ip = request.remote_addr if request else "N/A"
    ua = (request.user_agent.string[:256] if request else "N/A")

    entry = AuditLog(
        user_id=user.id,
        document_id=document.id if document else None,
        action=action,
        ip_address=ip,
        user_agent=ua,
        details=details,
        timestamp=datetime.utcnow(),
    )
    db.session.add(entry)
    db.session.commit()

    file_logger = _get_file_logger(log_dir)
    doc_info = f" | doc={document.original_filename}" if document else ""
    file_logger.info(
        f"action={action} | user={user.username} | ip={ip}{doc_info} | {details}"
    )
