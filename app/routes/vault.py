"""
Vault Blueprint
===============
Core file-vault operations:
  - POST /vault/upload        : encrypt & store a file
  - GET  /vault/download/<id> : decrypt & stream to owner only
  - POST /vault/delete/<id>   : soft-delete (removes encrypted file + DB record)
  - GET  /vault/dashboard     : list user's documents
  - GET  /vault/logs          : view personal audit log
"""

import os
import mimetypes
from flask import (
    Blueprint, render_template, redirect, url_for,
    flash, request, current_app, send_file, abort,
)
from flask_login import login_required, current_user
from io import BytesIO

from ..extensions import db
from ..models import Document, AuditLog
from ..crypto import encrypt_file, decrypt_file
from ..audit import log_action

vault_bp = Blueprint("vault", __name__, url_prefix="/vault")


def _allowed_file(filename: str) -> bool:
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    return ext in current_app.config["ALLOWED_EXTENSIONS"]


def _secure_filename(filename: str) -> str:
    """Strip path separators; keep original name for display only."""
    return os.path.basename(filename).replace("..", "")


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@vault_bp.route("/dashboard")
@login_required
def dashboard():
    docs = (
        Document.query
        .filter_by(owner_id=current_user.id)
        .order_by(Document.uploaded_at.desc())
        .all()
    )
    return render_template("dashboard.html", documents=docs)


# ---------------------------------------------------------------------------
# Upload
# ---------------------------------------------------------------------------

@vault_bp.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    if request.method == "POST":
        file = request.files.get("file")
        description = request.form.get("description", "").strip()

        if not file or file.filename == "":
            flash("No file selected.", "warning")
            return redirect(request.url)

        original_name = _secure_filename(file.filename)

        if not _allowed_file(original_name):
            flash("File type not allowed.", "danger")
            return redirect(request.url)

        plaintext = file.read()
        master_key = current_app.config["MASTER_KEY"]

        # Encrypt
        ciphertext, salt_hex = encrypt_file(plaintext, master_key)

        # Persist record
        ext = original_name.rsplit(".", 1)[-1].lower() if "." in original_name else ""
        doc = Document(
            original_filename=original_name,
            file_extension=ext,
            encrypted_size=len(ciphertext),
            kdf_salt=salt_hex,
            owner_id=current_user.id,
            description=description,
        )
        db.session.add(doc)
        db.session.flush()   # get doc.id before writing file

        # Write encrypted bytes to disk using UUID filename
        enc_path = os.path.join(
            current_app.config["ENCRYPTED_FILES_DIR"],
            doc.stored_filename
        )
        with open(enc_path, "wb") as f:
            f.write(ciphertext)

        doc.encrypted_size = os.path.getsize(enc_path)
        db.session.commit()

        log_action(
            current_user, "UPLOAD", document=doc,
            details=f"Encrypted size: {doc.encrypted_size} bytes",
            log_dir=current_app.config["LOG_DIR"],
        )
        flash(f'"{original_name}" uploaded and encrypted successfully.', "success")
        return redirect(url_for("vault.dashboard"))

    return render_template("upload.html")


# ---------------------------------------------------------------------------
# Download  (owner-only)
# ---------------------------------------------------------------------------

@vault_bp.route("/download/<int:doc_id>")
@login_required
def download(doc_id):
    doc = Document.query.get_or_404(doc_id)

    # Ownership check — never serve another user's file
    if doc.owner_id != current_user.id:
        abort(403)

    enc_path = os.path.join(
        current_app.config["ENCRYPTED_FILES_DIR"],
        doc.stored_filename
    )
    if not os.path.exists(enc_path):
        flash("Encrypted file not found on disk.", "danger")
        return redirect(url_for("vault.dashboard"))

    with open(enc_path, "rb") as f:
        ciphertext = f.read()

    master_key = current_app.config["MASTER_KEY"]
    try:
        plaintext = decrypt_file(ciphertext, master_key, doc.kdf_salt)
    except Exception:
        flash("Decryption failed — file may be corrupted.", "danger")
        return redirect(url_for("vault.dashboard"))

    # Update stats
    from datetime import datetime
    doc.download_count += 1
    doc.last_downloaded_at = datetime.utcnow()
    db.session.commit()

    log_action(
        current_user, "DOWNLOAD", document=doc,
        details=f"Download #{doc.download_count}",
        log_dir=current_app.config["LOG_DIR"],
    )

    mime, _ = mimetypes.guess_type(doc.original_filename)
    mime = mime or "application/octet-stream"

    return send_file(
        BytesIO(plaintext),
        mimetype=mime,
        as_attachment=True,
        download_name=doc.original_filename,
    )


# ---------------------------------------------------------------------------
# Delete  (owner-only)
# ---------------------------------------------------------------------------

@vault_bp.route("/delete/<int:doc_id>", methods=["POST"])
@login_required
def delete(doc_id):
    doc = Document.query.get_or_404(doc_id)

    if doc.owner_id != current_user.id:
        abort(403)

    enc_path = os.path.join(
        current_app.config["ENCRYPTED_FILES_DIR"],
        doc.stored_filename
    )
    if os.path.exists(enc_path):
        os.remove(enc_path)

    log_action(
        current_user, "DELETE", document=doc,
        details=f"Deleted: {doc.original_filename}",
        log_dir=current_app.config["LOG_DIR"],
    )

    db.session.delete(doc)
    db.session.commit()

    flash(f'"{doc.original_filename}" permanently deleted.', "info")
    return redirect(url_for("vault.dashboard"))


# ---------------------------------------------------------------------------
# Audit log viewer
# ---------------------------------------------------------------------------

@vault_bp.route("/logs")
@login_required
def audit_logs():
    logs = (
        AuditLog.query
        .filter_by(user_id=current_user.id)
        .order_by(AuditLog.timestamp.desc())
        .limit(200)
        .all()
    )
    return render_template("audit_logs.html", logs=logs)
