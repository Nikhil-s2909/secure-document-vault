"""
vault_project/urls.py
----------------------
Root URL configuration. Routes requests to:
  - vault_app views (main application)
  - Django admin panel
  - Authentication views (login/logout)
"""

from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('vault_app.urls')),
]

# Serve static and media files during development
if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    # Note: encrypted media files should NEVER be served directly
    # Downloads are handled through secure view functions only
