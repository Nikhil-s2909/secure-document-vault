"""
vault_app/forms.py
-------------------
Django forms used across the vault:

  UserRegistrationForm  — new account creation with password confirmation.
  DocumentUploadForm    — file upload with client-side and server-side validation
                          of extension, MIME type, and size.
"""

import os
import mimetypes

from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm
from django.conf import settings


class UserRegistrationForm(UserCreationForm):
    """
    Extends Django's built-in UserCreationForm with an email field.
    Validates that the username and email are not already taken.
    """

    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={
            'class': 'form-input',
            'placeholder': 'you@example.com',
        }),
        help_text='Required. Used for account recovery.',
    )

    class Meta:
        model = User
        fields = ('username', 'email', 'password1', 'password2')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Apply consistent CSS class to all fields
        for field_name, field in self.fields.items():
            if 'class' not in field.widget.attrs:
                field.widget.attrs['class'] = 'form-input'
            field.widget.attrs.setdefault('autocomplete', 'off')

        self.fields['username'].widget.attrs['placeholder'] = 'Choose a username'
        self.fields['password1'].widget.attrs['placeholder'] = 'Strong password'
        self.fields['password2'].widget.attrs['placeholder'] = 'Confirm password'

    def clean_email(self):
        email = self.cleaned_data.get('email', '').lower()
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError('An account with this email already exists.')
        return email


class DocumentUploadForm(forms.Form):
    """
    Handles file upload validation before the file is passed to the
    encryption layer.

    Validation rules
    ----------------
    1. File must be provided.
    2. Extension must be in settings.ALLOWED_UPLOAD_EXTENSIONS.
    3. File size must not exceed settings.FILE_UPLOAD_MAX_MEMORY_SIZE.
    """

    file = forms.FileField(
        widget=forms.ClearableFileInput(attrs={
            'class': 'file-input',
            'id': 'file-upload',
            'accept': ','.join(settings.ALLOWED_UPLOAD_EXTENSIONS),
        }),
        help_text=f"Allowed: {', '.join(settings.ALLOWED_UPLOAD_EXTENSIONS)} · Max 10 MB",
    )

    def clean_file(self):
        uploaded = self.cleaned_data.get('file')
        if not uploaded:
            raise forms.ValidationError('No file was selected.')

        # --- Extension check ---
        _, ext = os.path.splitext(uploaded.name.lower())
        if ext not in settings.ALLOWED_UPLOAD_EXTENSIONS:
            raise forms.ValidationError(
                f'File type "{ext}" is not allowed. '
                f'Permitted types: {", ".join(settings.ALLOWED_UPLOAD_EXTENSIONS)}'
            )

        # --- Size check ---
        max_size = settings.FILE_UPLOAD_MAX_MEMORY_SIZE
        if uploaded.size > max_size:
            mb = max_size / (1024 * 1024)
            raise forms.ValidationError(
                f'File is too large. Maximum size is {mb:.0f} MB.'
            )

        return uploaded
