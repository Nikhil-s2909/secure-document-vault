# 🔐 Secure Document Vault

A production-quality Django web application that lets users **upload, encrypt, store, and securely retrieve personal documents** — with every file protected by AES-256 encryption, per-file cryptographic keys, owner-only access control, and a full audit trail.

---

## ✨ Features

| Feature | Details |
|---|---|
| **User Auth** | Django session-based registration & login |
| **AES-256 Encryption** | Every file encrypted with Fernet (AES-128-CBC + HMAC-SHA256) before touching disk |
| **Per-file Keys** | PBKDF2-SHA256 with 600 000 iterations; random 32-byte salt per file |
| **Owner-only Access** | Download/delete views enforce `owner=request.user` at DB query level |
| **Audit Trail** | Append-only `ActivityLog` table records every upload, download, delete, login, and failed access — with IP address |
| **Safe File Names** | Stored files are renamed to UUID `.enc` blobs; original name kept only in DB |
| **Professional UI** | Dark cybersecurity theme, drag-and-drop upload, responsive design |
| **Admin Panel** | Read-only admin views for `EncryptedDocument` and `ActivityLog` |

---

## 📁 Project Structure

```
secure_document_vault/
│
├── manage.py                   # Django CLI entry point
├── requirements.txt            # Python dependencies
│
├── vault_project/              # Django project configuration
│   ├── __init__.py
│   ├── settings.py             # All Django settings (DB, auth, paths, limits)
│   ├── urls.py                 # Root URL dispatcher
│   └── wsgi.py                 # WSGI entry point for production
│
├── vault_app/                  # Main Django application
│   ├── __init__.py
│   ├── apps.py                 # AppConfig registration
│   ├── models.py               # EncryptedDocument + ActivityLog models
│   ├── views.py                # All HTTP request handlers
│   ├── urls.py                 # App-level URL patterns
│   ├── forms.py                # UserRegistrationForm + DocumentUploadForm
│   ├── encryption.py           # AES-256 encrypt/decrypt layer
│   ├── utils.py                # IP extraction, audit logging, filename sanitiser
│   └── admin.py                # Django admin registrations
│
├── templates/
│   ├── base.html               # Shared layout with navbar
│   ├── registration/
│   │   ├── login.html          # Login page
│   │   └── register.html       # Registration page
│   └── vault/
│       ├── dashboard.html      # Document list + stats
│       ├── upload.html         # Drag-and-drop upload form
│       └── activity_log.html   # Full audit log table
│
├── static/
│   ├── css/main.css            # Full dark-theme stylesheet
│   └── js/main.js              # Drop-zone, upload state, alert auto-dismiss
│
├── media/
│   └── encrypted_files/        # AES-256 ciphertext blobs (UUID-named .enc)
│                               # Never served directly by Django/Nginx
└── logs/                       # Reserved for server-side log files
```

---

## 🏗️ Architecture & Module Guide

### `vault_project/settings.py`
Central Django configuration. Key additions:
- `ENCRYPTED_FILES_DIR` — absolute path to the ciphertext storage folder
- `ALLOWED_UPLOAD_EXTENSIONS` — whitelist of permitted file types
- `FILE_UPLOAD_MAX_MEMORY_SIZE` — 10 MB cap on incoming files
- Auth redirect URLs wired to the vault's login/dashboard views

### `vault_app/models.py`
Two database tables:

**`EncryptedDocument`**
- UUID primary key prevents sequential ID enumeration
- `encrypted_path` — relative path on disk to the `.enc` blob
- `encryption_salt` — hex-encoded 32-byte random salt (stored; never the key)
- `file_size` — original plaintext size for UI display

**`ActivityLog`**
- Immutable append-only audit table
- Stores `action` (UPLOAD / DOWNLOAD / DELETE / LOGIN / LOGOUT / FAILED), `ip_address`, `timestamp`, and optional `document` FK
- Admin marks `has_change_permission = False` to enforce immutability

### `vault_app/encryption.py`
Cryptographic core. Pure Python, no external services.

```
Upload path
───────────
file bytes  →  os.urandom(32) salt
            →  PBKDF2-HMAC-SHA256(secret_key, salt, 600_000 iters) → 32-byte raw key
            →  base64url(key) → Fernet key
            →  Fernet.encrypt(plaintext) → ciphertext (.enc blob on disk)
            →  salt stored in DB

Download path
─────────────
salt from DB  →  same PBKDF2 derivation → Fernet key
ciphertext from disk  →  Fernet.decrypt(ciphertext)  →  plaintext bytes streamed to browser
```

Fernet provides authenticated encryption: any tampering with the ciphertext raises `InvalidToken` before a single byte of plaintext is returned.

### `vault_app/views.py`
All views decorated with `@login_required` except register/login/logout.

| View | Method | What it does |
|---|---|---|
| `upload_view` | POST | Validates → encrypts → writes `.enc` → creates DB record → logs |
| `download_view` | GET | Ownership check → reads `.enc` → decrypts in memory → `HttpResponse` stream |
| `delete_view` | POST | Ownership check → removes `.enc` from disk → deletes DB record → logs |
| `activity_log_view` | GET | Reads `ActivityLog` filtered to `request.user` |

### `vault_app/forms.py`
- `UserRegistrationForm` — extends `UserCreationForm` with email; checks uniqueness
- `DocumentUploadForm` — validates extension against whitelist and enforces 10 MB size cap before the file reaches the encryption layer

### `vault_app/utils.py`
- `get_client_ip` — respects `X-Forwarded-For` for reverse-proxy deployments
- `log_activity` — single call to create any `ActivityLog` entry; swallows exceptions so a logging failure never breaks the main request
- `safe_filename` — strips path traversal components, replaces unsafe characters

---

## 🚀 Quick Start

### 1. Clone & create virtualenv

```bash
git clone https://github.com/yourname/secure-document-vault.git
cd secure-document-vault
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Apply migrations

```bash
python manage.py makemigrations vault_app
python manage.py migrate
```

### 4. Create a superuser (optional, for /admin)

```bash
python manage.py createsuperuser
```

### 5. Run the development server

```bash
python manage.py runserver
```

Open **http://127.0.0.1:8000** — register an account and start uploading.

---

## 🔑 Security Notes

> These apply before deploying to a public server.

- **Change `SECRET_KEY`** — use `python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"` and store it in an environment variable, never in code.
- **Set `DEBUG = False`** and populate `ALLOWED_HOSTS` with your domain.
- **Serve behind Nginx/Apache** — configure it to block direct access to `media/encrypted_files/`. Django views are the only authorised decryption path.
- **Use PostgreSQL** in production instead of the default SQLite.
- **Enable HTTPS** — Fernet encrypts at rest, but HTTPS protects data in transit.
- **Rotate `SECRET_KEY` carefully** — changing it invalidates all existing ciphertext because the encryption keys are derived from it. Implement a re-encryption migration before rotating.

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Framework | Django 4.2 |
| Encryption | `cryptography` library — Fernet + PBKDF2 |
| Database | SQLite (dev) / PostgreSQL (prod) |
| Frontend | Vanilla HTML/CSS/JS — Space Mono + DM Sans fonts |
| Auth | Django built-in session authentication |

---

## 📄 License

MIT License — see `LICENSE` for details.
