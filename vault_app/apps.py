"""
vault_app/apps.py
------------------
AppConfig for vault_app.
Registers the application with Django's app registry.
"""

from django.apps import AppConfig


class VaultAppConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'vault_app'
    verbose_name = 'Secure Document Vault'
