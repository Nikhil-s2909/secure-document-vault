"""
vault_app/urls.py
------------------
URL patterns for all vault_app views.

Pattern overview
----------------
/                   → home (redirects based on auth state)
/register/          → new user registration
/login/             → login form
/logout/            → end session
/dashboard/         → user's document list
/upload/            → file upload form + handler
/download/<uuid>/   → decrypt + stream file (owner only)
/delete/<uuid>/     → permanently delete file (owner only, POST)
/activity/          → user's full audit log
"""

from django.urls import path
from . import views

urlpatterns = [
    path('',                          views.home_view,         name='home'),
    path('register/',                 views.register_view,     name='register'),
    path('login/',                    views.login_view,        name='login'),
    path('logout/',                   views.logout_view,       name='logout'),
    path('dashboard/',                views.dashboard_view,    name='dashboard'),
    path('upload/',                   views.upload_view,       name='upload'),
    path('download/<uuid:doc_id>/',   views.download_view,     name='download'),
    path('delete/<uuid:doc_id>/',     views.delete_view,       name='delete'),
    path('activity/',                 views.activity_log_view, name='activity_log'),
]
